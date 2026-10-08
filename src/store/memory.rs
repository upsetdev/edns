//! The in-memory store: state is lost on restart, which only affects lookups
//! in flight at that moment, and it cannot be shared between replicas.

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use super::{ACME_TXT_TTL, Capture, acme_key};
use crate::clock::{Clock, since};

/// Bounds the store (about 300 bytes per capture, so roughly 30 MB). Only
/// tokens we minted can create entries, and minting is rate-limited per
/// client, so reaching it takes a distributed effort; past it new captures
/// are refused while existing ones are kept.
const MAX_ENTRIES: usize = 100_000;

/// How often expired entries are dropped.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

pub struct MemStore {
    inner: Mutex<Inner>,
    clock: Clock,
    /// Calls made, so tests can assert a code path never touches the store.
    ops: AtomicUsize,
}

#[derive(Default)]
struct Inner {
    caps: HashMap<String, (Capture, SystemTime)>,
    txt: HashMap<String, HashMap<String, SystemTime>>, // acme key -> value -> expiry
    last_sweep: Option<SystemTime>,
}

impl Default for MemStore {
    fn default() -> Self {
        Self::with_clock(Clock::system())
    }
}

impl MemStore {
    pub fn with_clock(clock: Clock) -> Self {
        MemStore { inner: Mutex::default(), clock, ops: AtomicUsize::new(0) }
    }

    #[cfg(test)]
    pub fn ops(&self) -> usize {
        self.ops.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.ops.fetch_add(1, Ordering::Relaxed);
        self.inner.lock().unwrap()
    }

    pub fn record(&self, token: &str, c: &Capture, expires: SystemTime) -> bool {
        let now = self.clock.now();
        let mut m = self.lock();
        if now >= expires {
            return false;
        }
        // Sweep at most once per interval, piggybacking on writes so no
        // background task is needed.
        if m.last_sweep.is_none_or(|t| since(now, t) >= SWEEP_INTERVAL) {
            m.sweep(now);
        }
        if m.caps.get(token).is_some_and(|(_, exp)| now < *exp) {
            return false; // keep the first capture
        }
        if m.caps.len() >= MAX_ENTRIES {
            m.sweep(now);
            if m.caps.len() >= MAX_ENTRIES {
                return false;
            }
        }
        m.caps.insert(token.to_string(), (c.clone(), expires));
        true
    }

    pub fn get(&self, token: &str) -> Option<Capture> {
        let now = self.clock.now();
        let m = self.lock();
        m.caps.get(token).filter(|(_, exp)| now < *exp).map(|(c, _)| c.clone())
    }

    pub fn add_txt(&self, name: &str, value: &str) {
        let expires = self.clock.now() + ACME_TXT_TTL;
        self.lock().txt.entry(acme_key(name)).or_default().insert(value.to_string(), expires);
    }

    pub fn del_txt(&self, name: &str, value: &str) {
        let mut m = self.lock();
        let k = acme_key(name);
        if let Some(vals) = m.txt.get_mut(&k) {
            vals.remove(value);
            if vals.is_empty() {
                m.txt.remove(&k);
            }
        }
    }

    pub fn get_txt(&self, name: &str) -> Vec<String> {
        let now = self.clock.now();
        let m = self.lock();
        m.txt
            .get(&acme_key(name))
            .map(|vals| vals.iter().filter(|(_, exp)| now < **exp).map(|(v, _)| v.clone()).collect())
            .unwrap_or_default()
    }
}

impl Inner {
    fn sweep(&mut self, now: SystemTime) {
        self.caps.retain(|_, (_, exp)| now < *exp);
        self.txt.retain(|_, vals| {
            vals.retain(|_, exp| now < *exp);
            !vals.is_empty()
        });
        self.last_sweep = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sweeps_and_caps() {
        let clock = Clock::fixed(SystemTime::now());
        let m = MemStore::with_clock(clock.clone());
        let now = clock.now();
        {
            let mut inner = m.inner.lock().unwrap();
            inner.last_sweep = Some(now);
            for i in 0..MAX_ENTRIES {
                inner.caps.insert(i.to_string(), (Capture::default(), now + Duration::from_secs(60)));
            }
        }
        let hour = Duration::from_secs(3600);
        assert!(!m.record("tok", &Capture::default(), now + hour), "recorded past the cap with nothing expired");

        clock.advance(Duration::from_secs(120)); // everything stored has expired
        assert!(m.record("tok", &Capture::default(), clock.now() + hour), "expired entries were not swept");
        assert_eq!(m.inner.lock().unwrap().caps.len(), 1);
    }

    #[test]
    fn expired_capture_can_be_replaced() {
        let clock = Clock::fixed(SystemTime::now());
        let m = MemStore::with_clock(clock.clone());
        let c = |ip: &str| Capture { resolver_ip: ip.into(), ..Default::default() };
        assert!(m.record("t", &c("a"), clock.now() + Duration::from_secs(10)));
        clock.advance(Duration::from_secs(11));
        assert!(m.record("t", &c("b"), clock.now() + Duration::from_secs(10)));
        assert_eq!(m.get("t").unwrap().resolver_ip, "b");
    }
}
