//! The Redis store. Key names and values match the Go implementation.

use std::time::{Duration, SystemTime};

use anyhow::Context;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};

use super::{ACME_TXT_TTL, Capture, acme_key};
use crate::clock::since;

pub struct RedisStore {
    conn: ConnectionManager,
}

/// Opens a lazily connecting, auto-reconnecting client: like go-redis, the
/// server starts even while Redis is unreachable, and each command fails fast
/// instead of hanging the request that issued it.
pub fn connect(url: &str) -> anyhow::Result<ConnectionManager> {
    let client = redis::Client::open(url).context("redis url")?;
    let config = ConnectionManagerConfig::new()
        .set_connection_timeout(Some(Duration::from_secs(5)))
        .set_response_timeout(Some(Duration::from_secs(3)));
    ConnectionManager::new_lazy_with_config(client, config).context("redis client")
}

fn key(token: &str) -> String {
    format!("edns:{token}")
}

impl RedisStore {
    pub fn new(url: &str) -> anyhow::Result<Self> {
        Ok(RedisStore { conn: connect(url)? })
    }

    /// A single SET NX: tokens are self-validating, so there is nothing to
    /// read first, and NX keeps the first capture.
    pub async fn record(&self, token: &str, c: &Capture, expires: SystemTime) -> bool {
        let ttl = since(expires, SystemTime::now());
        if ttl.is_zero() {
            return false;
        }
        let data = serde_json::to_string(c).expect("Capture serializes");
        let res: redis::RedisResult<Option<String>> = redis::cmd("SET")
            .arg(key(token))
            .arg(data)
            .arg("NX")
            .arg("PX")
            .arg(ttl.as_millis().max(1) as u64)
            .query_async(&mut self.conn.clone())
            .await;
        match res {
            Ok(set) => set.is_some(),
            Err(e) => {
                tracing::error!("redis record {token}: {e}");
                false
            }
        }
    }

    pub async fn get(&self, token: &str) -> Option<Capture> {
        let res: redis::RedisResult<Option<String>> =
            redis::cmd("GET").arg(key(token)).query_async(&mut self.conn.clone()).await;
        match res {
            Ok(val) => serde_json::from_str(&val?).ok(),
            Err(e) => {
                tracing::error!("redis get {token}: {e}");
                None
            }
        }
    }

    pub async fn add_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let k = acme_key(name);
        let _: () = redis::pipe()
            .cmd("SADD")
            .arg(&k)
            .arg(value)
            .ignore()
            .cmd("EXPIRE")
            .arg(&k)
            .arg(ACME_TXT_TTL.as_secs())
            .ignore()
            .query_async(&mut self.conn.clone())
            .await?;
        Ok(())
    }

    pub async fn del_txt(&self, name: &str, value: &str) -> anyhow::Result<()> {
        let _: i64 = redis::cmd("SREM").arg(acme_key(name)).arg(value).query_async(&mut self.conn.clone()).await?;
        Ok(())
    }

    pub async fn get_txt(&self, name: &str) -> Vec<String> {
        let res: redis::RedisResult<Vec<String>> =
            redis::cmd("SMEMBERS").arg(acme_key(name)).query_async(&mut self.conn.clone()).await;
        res.unwrap_or_else(|e| {
            tracing::error!("redis txt {name}: {e}");
            Vec::new()
        })
    }
}
