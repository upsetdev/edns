//! Storage for certificates, keys and the ACME account: files for a single
//! instance, or Redis so replicas share one certificate. Either way it is only
//! read at startup and around renewals; handshakes are served from memory.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use redis::aio::ConnectionManager;
use tokio::sync::{Mutex, OwnedMutexGuard, oneshot};

pub enum CertStorage {
    File(FileStorage),
    Redis(RedisCertStorage),
}

impl CertStorage {
    pub fn file(dir: impl Into<PathBuf>) -> Self {
        CertStorage::File(FileStorage { root: dir.into(), lock: Arc::default() })
    }

    pub fn redis(url: &str) -> anyhow::Result<Self> {
        Ok(CertStorage::Redis(RedisCertStorage::new(crate::store::redis_connect(url)?, "edns-cert:")))
    }

    pub async fn load(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match self {
            CertStorage::File(f) => f.load(key).await,
            CertStorage::Redis(r) => r.load(key).await,
        }
    }

    pub async fn store(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        match self {
            CertStorage::File(f) => f.store(key, value).await,
            CertStorage::Redis(r) => r.store(key, value).await,
        }
    }

    /// Takes the named lock, waiting while someone else holds it. Used around
    /// ordering a certificate, so only one instance talks to the CA.
    pub async fn lock(&self, name: &str) -> anyhow::Result<CertLock> {
        match self {
            CertStorage::File(f) => Ok(CertLock::File(f.lock.clone().lock_owned().await)),
            CertStorage::Redis(r) => r.lock(name).await,
        }
    }
}

/// A held lock. Release it with [`CertLock::unlock`]; if it is dropped
/// instead (say the task panicked), a Redis lock stops being kept alive and
/// expires after its lease.
pub enum CertLock {
    File(#[allow(dead_code)] OwnedMutexGuard<()>),
    Redis { storage: RedisCertStorage, name: String, token: String, stop: Option<oneshot::Sender<()>> },
}

impl CertLock {
    pub async fn unlock(self) -> anyhow::Result<()> {
        match self {
            CertLock::File(_) => Ok(()),
            CertLock::Redis { storage, name, token, mut stop } => {
                stop.take();
                storage.unlock(&name, &token).await
            }
        }
    }
}

// --- Files ----------------------------------------------------------------

/// One file per key under `root`. Within a process the lock is a mutex; the
/// file backend is for a single instance, so that is all it needs.
pub struct FileStorage {
    root: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl FileStorage {
    fn path(&self, key: &str) -> anyhow::Result<PathBuf> {
        let rel = Path::new(key);
        if !rel.components().all(|c| matches!(c, Component::Normal(_))) {
            bail!("invalid storage key {key:?}");
        }
        Ok(self.root.join(rel))
    }

    async fn load(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match tokio::fs::read(self.path(key)?).await {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {key}")),
        }
    }

    /// Writes via a temporary file and a rename, so a reader never sees a
    /// half-written key; files are private to the owner (they hold keys).
    async fn store(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;

        let path = self.path(key)?;
        let dir = path.parent().expect("keys have a parent under root");
        tokio::fs::create_dir_all(dir).await.with_context(|| format!("mkdir {}", dir.display()))?;
        let tmp = path.with_extension("tmp");
        let mut f =
            tokio::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).await?;
        f.write_all(value).await?;
        f.sync_all().await?;
        tokio::fs::rename(&tmp, &path).await.with_context(|| format!("write {key}"))?;
        Ok(())
    }
}

// --- Redis ----------------------------------------------------------------

/// Keys live under `prefix`: values at `<prefix>file:<key>`, locks at
/// `<prefix>lock:<name>`.
///
/// A lock is SET NX PX with a random owner token. While held, a task keeps
/// extending it, so a long ACME order can't lose it; if the holder dies, the
/// lease runs out and another replica takes over. Unlock and extend only act
/// if the token still matches, so a replica can never release or extend a
/// lock that expired and was taken by someone else.
#[derive(Clone)]
pub struct RedisCertStorage {
    conn: ConnectionManager,
    prefix: String,
    lease: Duration,
    poll: Duration,
}

/// Deletes the lock only if we still own it.
const UNLOCK_SCRIPT: &str = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("DEL", KEYS[1])
end
return 0"#;

/// Resets the lease only if we still own the lock.
const EXTEND_SCRIPT: &str = r#"
if redis.call("GET", KEYS[1]) == ARGV[1] then
    return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0"#;

impl RedisCertStorage {
    pub fn new(conn: ConnectionManager, prefix: &str) -> Self {
        RedisCertStorage {
            conn,
            prefix: prefix.to_string(),
            lease: Duration::from_secs(60),
            poll: Duration::from_secs(1),
        }
    }

    fn file_key(&self, key: &str) -> String {
        format!("{}file:{key}", self.prefix)
    }

    fn lock_key(&self, name: &str) -> String {
        format!("{}lock:{name}", self.prefix)
    }

    async fn load(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(redis::cmd("GET").arg(self.file_key(key)).query_async(&mut self.conn.clone()).await?)
    }

    async fn store(&self, key: &str, value: &[u8]) -> anyhow::Result<()> {
        let _: () = redis::cmd("SET").arg(self.file_key(key)).arg(value).query_async(&mut self.conn.clone()).await?;
        Ok(())
    }

    async fn lock(&self, name: &str) -> anyhow::Result<CertLock> {
        let mut b = [0u8; 16];
        rand::fill(&mut b);
        let token = hex::encode(b);
        let key = self.lock_key(name);

        loop {
            let set: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg(&token)
                .arg("NX")
                .arg("PX")
                .arg(self.lease.as_millis() as u64)
                .query_async(&mut self.conn.clone())
                .await
                .with_context(|| format!("lock {name}"))?;
            if set.is_some() {
                break;
            }
            tokio::time::sleep(self.poll).await;
        }

        let (stop, mut stopped) = oneshot::channel::<()>();
        let (storage, keep_key, keep_token) = (self.clone(), key, token.clone());
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(storage.lease / 3);
            tick.tick().await; // the first tick is immediate
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let owned: redis::RedisResult<i64> = redis::Script::new(EXTEND_SCRIPT)
                            .key(&keep_key)
                            .arg(&keep_token)
                            .arg(storage.lease.as_millis() as u64)
                            .invoke_async(&mut storage.conn.clone())
                            .await;
                        if matches!(owned, Ok(0)) {
                            return; // lost the lock (expired and taken); nothing to extend
                        }
                    }
                    // Fires on unlock, and when the lock is dropped.
                    _ = &mut stopped => return,
                }
            }
        });
        Ok(CertLock::Redis { storage: self.clone(), name: name.to_string(), token, stop: Some(stop) })
    }

    async fn unlock(&self, name: &str, token: &str) -> anyhow::Result<()> {
        let _: i64 = redis::Script::new(UNLOCK_SCRIPT)
            .key(self.lock_key(name))
            .arg(token)
            .invoke_async(&mut self.conn.clone())
            .await
            .with_context(|| format!("unlock {name}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn temp_dir() -> PathBuf {
        let mut b = [0u8; 8];
        rand::fill(&mut b);
        std::env::temp_dir().join(format!("edns-test-{}", hex::encode(b)))
    }

    #[tokio::test]
    async fn file_round_trip() {
        let dir = temp_dir();
        let s = CertStorage::file(&dir);
        assert_eq!(s.load("certs/a/x.pem").await.unwrap(), None);
        s.store("certs/a/x.pem", b"one").await.unwrap();
        s.store("certs/a/x.pem", b"two").await.unwrap();
        assert_eq!(s.load("certs/a/x.pem").await.unwrap().as_deref(), Some(&b"two"[..]));

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("certs/a/x.pem")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key material must be private");

        for bad in ["../escape", "/abs", "a/../../b", ""] {
            assert!(s.store(bad, b"x").await.is_err(), "{bad:?} accepted");
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn file_lock_is_exclusive() {
        let s = CertStorage::file(temp_dir());
        let held = s.lock("l").await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(50), s.lock("l")).await.is_err());
        held.unlock().await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(1), s.lock("l")).await.is_ok());
    }

    /// A Redis storage under a unique prefix, with a short lease so expiry is
    /// testable in real time.
    fn redis_storage(lease: Duration) -> Option<RedisCertStorage> {
        let url = crate::store::tests::test_redis_url()?;
        let mut b = [0u8; 8];
        rand::fill(&mut b);
        let mut s =
            RedisCertStorage::new(crate::store::redis_connect(&url).unwrap(), &format!("test:{}:", hex::encode(b)));
        s.lease = lease;
        s.poll = Duration::from_millis(20);
        Some(s)
    }

    #[tokio::test]
    async fn redis_round_trip() {
        let Some(r) = redis_storage(Duration::from_secs(60)) else { return };
        let s = CertStorage::Redis(r);
        assert_eq!(s.load("k").await.unwrap(), None);
        s.store("k", b"\x00binary\xff").await.unwrap();
        assert_eq!(s.load("k").await.unwrap().as_deref(), Some(&b"\x00binary\xff"[..]));
    }

    #[tokio::test]
    async fn redis_lock_is_exclusive_and_kept_alive() {
        let Some(r) = redis_storage(Duration::from_millis(300)) else { return };
        let (a, b) = (CertStorage::Redis(r.clone()), CertStorage::Redis(r));

        let held = a.lock("l").await.unwrap();
        // Well past the 300ms lease, the keep-alive still holds it.
        assert!(tokio::time::timeout(Duration::from_secs(1), b.lock("l")).await.is_err(), "lock lost while held");
        held.unlock().await.unwrap();
        let other =
            tokio::time::timeout(Duration::from_secs(1), b.lock("l")).await.expect("lock after unlock").unwrap();
        other.unlock().await.unwrap();
    }

    #[tokio::test]
    async fn redis_expired_lock_is_not_released_by_old_holder() {
        let Some(r) = redis_storage(Duration::from_millis(300)) else { return };
        let mut conn = r.conn.clone();
        let key = r.lock_key("l");
        let a = CertStorage::Redis(r.clone());

        // The holder stalls (no keep-alive) past its lease, so another
        // replica takes the lock over.
        let CertLock::Redis { storage, name, token, mut stop } = a.lock("l").await.unwrap() else { unreachable!() };
        stop.take();
        tokio::time::sleep(Duration::from_millis(500)).await;
        let newer = CertStorage::Redis(r).lock("l").await.unwrap();
        let owner: String = redis::cmd("GET").arg(&key).query_async(&mut conn).await.unwrap();

        // The stale holder's unlock must not touch the new lock.
        storage.unlock(&name, &token).await.unwrap();
        let after: String = redis::cmd("GET").arg(&key).query_async(&mut conn).await.unwrap();
        assert_eq!(after, owner, "old holder released the new holder's lock");
        newer.unlock().await.unwrap();
        let gone: Option<String> = redis::cmd("GET").arg(&key).query_async(&mut conn).await.unwrap();
        assert_eq!(gone, None, "unlock left the lock in Redis");
    }
}
