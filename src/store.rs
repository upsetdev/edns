//! Captures and ACME challenge records.
//!
//! The memory backend suits a single instance; Redis lets several replicas
//! share state, since capture and report for one token may land on
//! different replicas.

mod memory;
mod redis;

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

pub use self::memory::MemStore;
pub use self::redis::{RedisStore, connect as redis_connect};

/// What we learned about the DNS path used to resolve a token. The JSON field
/// names are the Redis format, shared with the Go implementation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capture {
    pub token: String,
    /// Recursive resolver that queried us.
    pub resolver_ip: String,
    /// EDNS Client Subnet, e.g. "1.2.3.0/24", or "none".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ecs: String,
    /// "ipv4", "ipv6" or "none".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ecs_family: String,
    /// True once a DNS query landed.
    pub resolved: bool,
    /// Unix seconds.
    pub created_at: i64,
}

/// How long a challenge value outlives a missed cleanup.
pub const ACME_TXT_TTL: Duration = Duration::from_secs(300);

pub enum Store {
    Memory(MemStore),
    Redis(RedisStore),
}

impl Store {
    /// Stores the capture for `token` until `expires`, unless the token
    /// already has one: the first lookup is the client following the
    /// redirect, while later ones come from re-resolution elsewhere (other
    /// tools or devices, resolver prefetch, scanners) and would report the
    /// wrong resolver. Returns whether `c` was stored.
    pub async fn record(&self, token: &str, c: &Capture, expires: SystemTime) -> bool {
        match self {
            Store::Memory(m) => m.record(token, c, expires),
            Store::Redis(r) => r.record(token, c, expires).await,
        }
    }

    /// The capture for `token`, if present and unexpired.
    pub async fn get(&self, token: &str) -> Option<Capture> {
        match self {
            Store::Memory(m) => m.get(token),
            Store::Redis(r) => r.get(token).await,
        }
    }

    // ACME DNS-01 challenge records. The ACME client writes the TXT here and
    // the DNS server serves it when Let's Encrypt validates. Several values
    // can be live at once (apex + wildcard in one order).

    pub async fn add_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        match self {
            Store::Memory(m) => {
                m.add_txt(name, value);
                Ok(())
            }
            Store::Redis(r) => r.add_txt(name, value).await,
        }
    }

    pub async fn del_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        match self {
            Store::Memory(m) => {
                m.del_txt(name, value);
                Ok(())
            }
            Store::Redis(r) => r.del_txt(name, value).await,
        }
    }

    pub async fn get_txt(&self, name: &str) -> Vec<String> {
        match self {
            Store::Memory(m) => m.get_txt(name),
            Store::Redis(r) => r.get_txt(name).await,
        }
    }
}

/// The store key of an ACME challenge name, case- and trailing-dot-insensitive.
fn acme_key(name: &str) -> String {
    format!("acme:{}", name.trim_end_matches('.').to_lowercase())
}

#[cfg(test)]
pub(crate) mod tests {
    //! Behaviour shared by both backends. The Redis runs need a server:
    //! set EDNS_TEST_REDIS_URL (e.g. redis://127.0.0.1:6379) to include them.

    use super::*;
    use crate::clock::Clock;
    use crate::config::tests::test_config;
    use crate::token;

    pub fn test_redis_url() -> Option<String> {
        std::env::var("EDNS_TEST_REDIS_URL").ok().filter(|u| !u.is_empty())
    }

    /// The backends to run a shared test against. Expiry tests need a
    /// controllable clock, which only the memory store has; `None` means the
    /// test must use real (short) waits.
    pub fn backends() -> Vec<(&'static str, Store, Option<Clock>)> {
        let clock = Clock::fixed(SystemTime::now());
        let mut out = vec![("memory", Store::Memory(MemStore::with_clock(clock.clone())), Some(clock))];
        match test_redis_url() {
            Some(url) => out.push(("redis", Store::Redis(RedisStore::new(&url).unwrap()), None)),
            None => eprintln!("EDNS_TEST_REDIS_URL not set; skipping Redis backend"),
        }
        out
    }

    fn new_token() -> String {
        token::mint(&test_config(), SystemTime::now())
    }

    fn capture(tok: &str, ip: &str) -> Capture {
        Capture { token: tok.into(), resolver_ip: ip.into(), ..Default::default() }
    }

    #[tokio::test]
    async fn record_keeps_first_and_expires() {
        for (name, store, clock) in backends() {
            let tok = new_token();
            let now = clock.as_ref().map_or_else(SystemTime::now, Clock::now);
            // Redis expiry is real time, so give it a short life there.
            let life = if clock.is_some() { Duration::from_secs(3600) } else { Duration::from_millis(1500) };

            assert!(store.get(&tok).await.is_none(), "{name}: unrecorded token found");
            assert!(store.record(&tok, &capture(&tok, "198.51.100.7"), now + life).await, "{name}");
            assert!(
                !store.record(&tok, &capture(&tok, "198.51.100.8"), now + life).await,
                "{name}: second record replaced the first"
            );
            let got = store.get(&tok).await.unwrap();
            assert_eq!(got.resolver_ip, "198.51.100.7", "{name}: want the first capture");

            match &clock {
                Some(c) => c.advance(life + Duration::from_secs(1)),
                None => tokio::time::sleep(life + Duration::from_millis(500)).await,
            }
            assert!(store.get(&tok).await.is_none(), "{name}: capture outlived its token");
        }
    }

    #[tokio::test]
    async fn record_rejects_expired() {
        for (name, store, clock) in backends() {
            let tok = new_token();
            let now = clock.as_ref().map_or_else(SystemTime::now, Clock::now);
            assert!(!store.record(&tok, &capture(&tok, ""), now - Duration::from_secs(1)).await, "{name}");
            assert!(store.get(&tok).await.is_none(), "{name}: expired token was stored");
        }
    }

    #[tokio::test]
    async fn txt() {
        for (name, store, clock) in backends() {
            // Unique per run, since a Redis server may be shared.
            let txt_name = format!("_acme-challenge.{}.example.test.", new_token());
            for v in ["a", "b"] {
                store.add_txt(&txt_name, v).await.unwrap();
            }
            let mut got = store.get_txt(&txt_name.to_uppercase()).await;
            got.sort();
            assert_eq!(got, ["a", "b"], "{name}: lookups are case-insensitive");
            store.del_txt(&txt_name, "a").await.unwrap();
            assert_eq!(store.get_txt(&txt_name).await, ["b"], "{name}");
            // Expiry is 5 minutes: only checkable on the controllable clock.
            if let Some(c) = clock {
                c.advance(Duration::from_secs(360));
                assert!(store.get_txt(&txt_name).await.is_empty(), "{name}: expired values served");
            } else {
                store.del_txt(&txt_name, "b").await.unwrap();
                assert!(store.get_txt(&txt_name).await.is_empty(), "{name}");
            }
        }
    }

    #[test]
    fn capture_json_matches_go() {
        let c = Capture {
            token: "t".into(),
            resolver_ip: "198.51.100.7".into(),
            ecs: "203.0.113.0/24".into(),
            ecs_family: "ipv4".into(),
            resolved: true,
            created_at: 42,
        };
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"token":"t","resolver_ip":"198.51.100.7","ecs":"203.0.113.0/24","ecs_family":"ipv4","resolved":true,"created_at":42}"#
        );
        // Go omits empty ecs fields; both spellings must read back.
        let go: Capture =
            serde_json::from_str(r#"{"token":"t","resolver_ip":"","resolved":false,"created_at":0}"#).unwrap();
        assert_eq!(go.ecs, "");
    }
}
