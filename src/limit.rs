//! Per-source rate limiting and per-token capture deduplication.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use crate::clock::since;

/// Bounds the memory a limiter can use. A flood from spoofed sources could
/// otherwise create a bucket per address; past this many keys, new sources
/// share one overflow bucket.
const LIMITER_MAX_KEYS: usize = 65536;

/// The least time a bucket can go unused before it is dropped; a limiter
/// waits longer when its bucket takes longer to refill (see `idle`).
const LIMITER_IDLE: Duration = Duration::from_secs(60);

/// A token-bucket rate limiter per key (a client address prefix). Code that
/// holds an `Option<Limiter>` treats `None` as "unlimited".
#[derive(Debug)]
pub struct Limiter {
    rate: f64,
    burst: f64,
    /// How long a bucket can go unused before it is dropped: at least
    /// burst/rate, so that a dropped bucket would have been full anyway.
    idle: Duration,
    inner: Mutex<Buckets>,
}

#[derive(Debug)]
struct Buckets {
    map: HashMap<String, Bucket>,
    last_sweep: SystemTime,
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    last: SystemTime,
}

impl Limiter {
    /// Allows `per_sec` events per key per second on average, and up to
    /// `burst` at once. Returns `None` (no limit) when `per_sec <= 0`.
    pub fn new(per_sec: f64, burst: u32) -> Option<Self> {
        (per_sec > 0.0).then(|| {
            let burst = f64::from(burst.max(1));
            Limiter {
                rate: per_sec,
                burst,
                idle: LIMITER_IDLE.max(Duration::from_secs_f64(burst / per_sec)),
                inner: Mutex::new(Buckets { map: HashMap::new(), last_sweep: SystemTime::UNIX_EPOCH }),
            }
        })
    }

    pub fn allow(&self, key: &str, now: SystemTime) -> bool {
        let mut b = self.inner.lock().unwrap();

        if since(now, b.last_sweep) > self.idle {
            let idle = self.idle;
            b.map.retain(|_, bucket| since(now, bucket.last) <= idle);
            b.last_sweep = now;
        }
        let key = if !b.map.contains_key(key) && b.map.len() >= LIMITER_MAX_KEYS { "overflow" } else { key };
        let burst = self.burst;
        let bucket = b.map.entry(key.to_string()).or_insert(Bucket { tokens: burst, last: now });

        // Refill for the time since this bucket was last used, then spend one.
        let elapsed = since(now, bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.rate).min(self.burst);
        bucket.last = bucket.last.max(now);
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Reduces an address to the network a single client (or resolver farm)
/// plausibly controls, so that one source can't dodge the limit by rotating
/// through adjacent addresses.
pub fn prefix_key(ip: IpAddr, v4_bits: u8, v6_bits: u8) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(v4_bits)).unwrap_or(0);
            format!("{}/{v4_bits}", std::net::Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(v6_bits)).unwrap_or(0);
            format!("{}/{v6_bits}", std::net::Ipv6Addr::from(u128::from(v6) & mask))
        }
    }
}

/// Bounds the guard's memory. When full it stops tracking new tokens (failing
/// open): the store still keeps only the first capture, and the per-source
/// DNS limit still applies.
const CAPTURE_GUARD_MAX_KEYS: usize = 100_000;

/// Remembers which tokens have already been captured, so repeat lookups
/// (resolver retries, prefetch, someone replaying a valid token to run up the
/// Redis bill) are dropped without a Redis command.
#[derive(Debug, Default)]
pub struct CaptureGuard {
    seen: Mutex<HashMap<String, SystemTime>>, // token -> expiry
}

impl CaptureGuard {
    /// Reports whether this is the first capture of `token`, which expires at
    /// `expires`, and marks it as captured.
    pub fn first(&self, token: &str, expires: SystemTime, now: SystemTime) -> bool {
        let mut seen = self.seen.lock().unwrap();
        if seen.contains_key(token) {
            return false;
        }
        if seen.len() >= CAPTURE_GUARD_MAX_KEYS {
            seen.retain(|_, exp| now < *exp);
            if seen.len() >= CAPTURE_GUARD_MAX_KEYS {
                return true;
            }
        }
        seen.insert(token.to_string(), expires);
        true
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_rate_disables() {
        assert!(Limiter::new(0.0, 10).is_none());
    }

    #[test]
    fn burst_then_refill() {
        let l = Limiter::new(1.0, 5).unwrap();
        let now = SystemTime::now();
        for i in 0..5 {
            assert!(l.allow("k", now), "request {i} within burst denied");
        }
        assert!(!l.allow("k", now), "over burst allowed");
        assert!(l.allow("other", now), "keys are independent");
        assert!(l.allow("k", now + Duration::from_secs(1)), "bucket did not refill");
    }

    #[test]
    fn sweeps_idle_and_overflows() {
        let l = Limiter::new(1.0, 5).unwrap();
        let now = SystemTime::now();
        for i in 0..LIMITER_MAX_KEYS {
            l.allow(&i.to_string(), now);
        }
        // Past the key cap, new sources share the overflow bucket (burst 5).
        for i in 0..5 {
            assert!(l.allow(&format!("new{i}"), now), "overflow request {i} denied within burst");
        }
        assert!(!l.allow("another", now), "overflow bucket was not shared");
        // Once idle buckets are swept, new sources get their own again.
        let later = now + 2 * LIMITER_IDLE;
        assert!(l.allow("another", later));
        assert_eq!(l.inner.lock().unwrap().map.len(), 1, "after sweep");
    }

    /// The leak test on upset.dev runs up to 50 lookups (100 HTTP requests)
    /// as fast as it can; the default HTTP burst must take a whole run, and
    /// refill in time for the next.
    #[test]
    fn burst_independent_of_rate() {
        let l = Limiter::new(5.0, 150).unwrap();
        let now = SystemTime::now();
        assert!((0..150).all(|_| l.allow("k", now)), "burst of 150 not honoured");
        assert!(!l.allow("k", now));
        assert!(l.allow("k", now + Duration::from_millis(200)), "5/s refill");
        // A slow-refilling bucket isn't swept (and so reset to full) early.
        assert_eq!(Limiter::new(1.0, 600).unwrap().idle, Duration::from_secs(600));
        assert_eq!(l.idle, LIMITER_IDLE);
    }

    #[test]
    fn prefix_keys() {
        let cases = [
            ("198.51.100.77", "198.51.100.0/24"),
            ("::ffff:198.51.100.77", "198.51.100.0/24"),
            ("2001:db8:1:2:3::1", "2001:db8:1::/56"),
        ];
        for (addr, want) in cases {
            assert_eq!(prefix_key(addr.parse().unwrap(), 24, 56), want, "{addr}");
        }
        assert_eq!(prefix_key("198.51.100.77".parse().unwrap(), 32, 64), "198.51.100.77/32");
    }

    #[test]
    fn capture_guard() {
        let g = CaptureGuard::default();
        let now = SystemTime::now();
        let exp = now + Duration::from_secs(3600);
        assert!(g.first("t", exp, now), "first capture denied");
        assert!(!g.first("t", exp, now), "repeat capture allowed");
        assert!(g.first("u", exp, now), "other token denied");
    }

    #[test]
    fn capture_guard_sweeps_when_full() {
        let g = CaptureGuard::default();
        let now = SystemTime::now();
        {
            let mut seen = g.seen.lock().unwrap();
            for i in 0..CAPTURE_GUARD_MAX_KEYS {
                seen.insert(i.to_string(), now + Duration::from_secs(60));
            }
        }
        // Full of live entries: fail open rather than drop a real capture.
        assert!(g.first("new", now + Duration::from_secs(3600), now));
        assert_eq!(g.len(), CAPTURE_GUARD_MAX_KEYS, "full guard tracked a new token");
        // Once those expire they are swept and tracking resumes.
        let later = now + Duration::from_secs(120);
        assert!(g.first("new", later + Duration::from_secs(3600), later));
        assert!(!g.first("new", later + Duration::from_secs(3600), later));
        assert_eq!(g.len(), 1, "after sweep");
    }
}
