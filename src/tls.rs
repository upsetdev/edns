//! HTTPS certificates: one Let's Encrypt certificate for the apex and the
//! wildcard (`<base>` + `*.<base>`), obtained and renewed with a DNS-01
//! challenge. This process is the zone's authoritative server, so publishing
//! the challenge only means writing a TXT value to the store; the DNS handler
//! then serves it to the CA's validators.

use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime};

use anyhow::{Context, bail};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use x509_parser::extensions::GeneralName;

use crate::certstore::CertStorage;
use crate::clock::since;
use crate::config::Config;
use crate::store::Store;

/// How often to check whether the certificate needs renewing (and whether
/// another replica already renewed it).
const CHECK_INTERVAL: Duration = Duration::from_secs(600);
/// Retry delays after a failed attempt double from the first to the last.
/// Starting at 2 minutes keeps us within Let's Encrypt's limit of 5 failed
/// validations per hostname per hour.
const RETRY_MIN: Duration = Duration::from_secs(120);
const RETRY_MAX: Duration = Duration::from_secs(3600);

/// A certificate in use, with what we need to decide when to renew it.
struct Installed {
    key: Arc<CertifiedKey>,
    /// The stored PEM it came from, to notice when storage holds a new one.
    pem: Vec<u8>,
    not_before: SystemTime,
    not_after: SystemTime,
    names: Vec<String>,
}

pub struct CertManager {
    cfg: Arc<Config>,
    /// Where challenge TXT values go (and the DNS handler reads them from).
    store: Arc<Store>,
    storage: CertStorage,
    directory_url: String,
    current: RwLock<Option<Installed>>,
}

impl CertManager {
    pub fn new(cfg: Arc<Config>, store: Arc<Store>, storage: CertStorage) -> Self {
        let ca = if cfg.acme_staging { LetsEncrypt::Staging } else { LetsEncrypt::Production };
        CertManager { cfg, store, storage, directory_url: ca.url().to_string(), current: RwLock::new(None) }
    }

    /// The names the certificate must cover.
    fn names(&self) -> [String; 2] {
        let apex = self.cfg.apex();
        [apex.to_string(), format!("*.{apex}")]
    }

    /// Storage keys are namespaced by CA, so staging and production
    /// certificates (and accounts) never mix.
    fn issuer(&self) -> &str {
        let url = self.directory_url.trim_start_matches("https://");
        url.split('/').next().unwrap_or(url)
    }

    fn cert_key(&self) -> String {
        format!("certs/{}/{}.pem", self.issuer(), self.cfg.apex())
    }

    fn account_key(&self) -> String {
        format!("acme/{}/account.json", self.issuer())
    }

    /// Keeps the certificate current, forever. Errors are logged and retried
    /// with backoff; meanwhile the last good certificate keeps serving.
    pub async fn run(self: Arc<Self>) {
        let mut retry = RETRY_MIN;
        loop {
            match self.maintain(SystemTime::now()).await {
                Ok(()) => {
                    retry = RETRY_MIN;
                    tokio::time::sleep(CHECK_INTERVAL).await;
                }
                Err(e) => {
                    tracing::error!("certificate: {e:#}; retrying in {}s", retry.as_secs());
                    tokio::time::sleep(retry).await;
                    retry = (retry * 2).min(RETRY_MAX);
                }
            }
        }
    }

    /// One maintenance pass: load what storage has, and obtain a new
    /// certificate if it's missing or due for renewal.
    async fn maintain(&self, now: SystemTime) -> anyhow::Result<()> {
        // Pick up a certificate stored by an earlier run or another replica.
        self.load_stored().await?;
        if !self.needs_renewal(now) {
            return Ok(());
        }

        let lock = self.storage.lock(&format!("issue_cert_{}", self.cfg.apex())).await?;
        let result = async {
            // Another replica may have renewed while we waited for the lock.
            self.load_stored().await?;
            if !self.needs_renewal(now) {
                return Ok(());
            }
            let [apex, wildcard] = self.names();
            tracing::info!("obtaining certificate for {apex} and {wildcard}");
            let (chain, key) = self.obtain().await?;
            let pem = format!("{key}{chain}").into_bytes();
            let installed = parse(&pem)?;
            self.storage.store(&self.cert_key(), &pem).await.context("store certificate")?;
            self.install(installed);
            Ok(())
        }
        .await;
        if let Err(e) = lock.unlock().await {
            tracing::warn!("certificate lock: {e:#}");
        }
        result
    }

    async fn load_stored(&self) -> anyhow::Result<()> {
        let Some(pem) = self.storage.load(&self.cert_key()).await.context("load certificate")? else {
            return Ok(());
        };
        if self.current.read().unwrap().as_ref().is_some_and(|c| c.pem == pem) {
            return Ok(());
        }
        match parse(&pem) {
            Ok(installed) => self.install(installed),
            // Don't let a bad stored value block obtaining a fresh one.
            Err(e) => tracing::warn!("ignoring stored certificate: {e:#}"),
        }
        Ok(())
    }

    fn install(&self, c: Installed) {
        let until = httpdate::fmt_http_date(c.not_after);
        let mut current = self.current.write().unwrap();
        // Never swap in an older certificate than the one being served.
        if current.as_ref().is_some_and(|old| old.not_after > c.not_after) {
            return;
        }
        tracing::info!("serving certificate for {} (valid until {until})", c.names.join(", "));
        *current = Some(c);
    }

    /// Whether the certificate is missing, doesn't cover our names, or has
    /// less than a third of its lifetime left (CertMagic's rule, which also
    /// suits shorter-lived certificates).
    fn needs_renewal(&self, now: SystemTime) -> bool {
        let current = self.current.read().unwrap();
        let Some(c) = current.as_ref() else { return true };
        if !self.names().iter().all(|n| c.names.contains(n)) {
            return true;
        }
        let lifetime = since(c.not_after, c.not_before);
        since(c.not_after, now) < lifetime / 3
    }

    async fn account(&self) -> anyhow::Result<Account> {
        let key = self.account_key();
        if let Some(raw) = self.storage.load(&key).await? {
            let creds: AccountCredentials = serde_json::from_slice(&raw).context("stored ACME account")?;
            return Ok(Account::builder()?.from_credentials(creds).await?);
        }
        let contact = self.cfg.acme_email.as_ref().map(|e| format!("mailto:{e}"));
        let contacts: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, creds) = Account::builder()?
            .create(
                &NewAccount { contact: &contacts, terms_of_service_agreed: true, only_return_existing: false },
                self.directory_url.clone(),
                None,
            )
            .await
            .context("create ACME account")?;
        self.storage.store(&key, &serde_json::to_vec(&creds)?).await?;
        Ok(account)
    }

    /// Runs one ACME order and returns (certificate chain PEM, key PEM).
    async fn obtain(&self) -> anyhow::Result<(String, String)> {
        let account = self.account().await?;
        let names = self.names();
        let identifiers: Vec<Identifier> = names.iter().map(|n| Identifier::Dns(n.clone())).collect();
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await.context("new order")?;

        // Both names validate through the same TXT name; the store keeps
        // both values at once.
        let txt_name = format!("_acme-challenge.{}", self.cfg.base_domain);
        let mut published = Vec::new();
        let validated = async {
            let mut authzs = order.authorizations();
            while let Some(authz) = authzs.next().await {
                let mut authz = authz?;
                match authz.status {
                    AuthorizationStatus::Pending => {}
                    AuthorizationStatus::Valid => continue,
                    other => bail!("authorization is {other:?}"),
                }
                let mut challenge = authz.challenge(ChallengeType::Dns01).context("no dns-01 challenge offered")?;
                let value = challenge.key_authorization().dns_value();
                self.store.add_txt(&txt_name, &value).await.context("publish challenge")?;
                published.push(value);
                challenge.set_ready().await?;
            }
            let policy =
                RetryPolicy::new().initial_delay(Duration::from_secs(1)).backoff(1.5).timeout(Duration::from_secs(180));
            match order.poll_ready(&policy).await? {
                OrderStatus::Ready => Ok(()),
                other => bail!("order is {other:?} (validation failed?)"),
            }
        }
        .await;
        for value in &published {
            if let Err(e) = self.store.del_txt(&txt_name, value).await {
                tracing::warn!("clean up challenge: {e:#}");
            }
        }
        validated?;

        let key = rcgen::KeyPair::generate()?; // ECDSA P-256
        let mut params = rcgen::CertificateParams::new(names.to_vec())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key)?;
        order.finalize_csr(csr.der()).await.context("finalize")?;
        let chain = order.poll_certificate(&RetryPolicy::new().timeout(Duration::from_secs(120))).await?;
        Ok((chain, key.serialize_pem()))
    }

    /// A rustls config serving the current certificate. Until the first one
    /// is obtained, handshakes fail (as with CertMagic's async management).
    pub fn server_config(self: Arc<Self>) -> anyhow::Result<Arc<ServerConfig>> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(self)));
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Ok(Arc::new(cfg))
    }
}

/// Parses a stored PEM (private key plus certificate chain, leaf first).
fn parse(pem: &[u8]) -> anyhow::Result<Installed> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(pem).collect::<Result<_, _>>().context("certificate PEM")?;
    let leaf = chain.first().context("no certificate in PEM")?;
    let key = PrivateKeyDer::from_pem_slice(pem).context("private key PEM")?;
    let provider = rustls::crypto::ring::default_provider();
    let certified = CertifiedKey::from_der(chain.clone(), key, &provider).context("certificate and key")?;

    let (_, x509) = x509_parser::parse_x509_certificate(leaf).context("parse certificate")?;
    let time =
        |t: x509_parser::time::ASN1Time| SystemTime::UNIX_EPOCH + Duration::from_secs(t.timestamp().max(0) as u64);
    let names = match x509.subject_alternative_name() {
        Ok(Some(san)) => san
            .value
            .general_names
            .iter()
            .filter_map(|n| match n {
                GeneralName::DNSName(d) => Some(d.to_lowercase()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    Ok(Installed {
        key: Arc::new(certified),
        pem: pem.to_vec(),
        not_before: time(x509.validity().not_before),
        not_after: time(x509.validity().not_after),
        names,
    })
}

struct Resolver(Arc<CertManager>);

impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Resolver")
    }
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.current.read().unwrap().as_ref().map(|c| c.key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::test_config;
    use crate::store::MemStore;
    use rustls::pki_types::ServerName;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A self-signed certificate valid from `from` for `days`, as stored PEM.
    fn self_signed(names: &[&str], from: SystemTime, days: u64) -> Vec<u8> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).unwrap();
        let start = time::OffsetDateTime::from(from);
        params.not_before = start;
        params.not_after = start + time::Duration::days(days as i64);
        let cert = params.self_signed(&key).unwrap();
        format!("{}{}", key.serialize_pem(), cert.pem()).into_bytes()
    }

    fn manager(dir: &std::path::Path) -> Arc<CertManager> {
        let store = Arc::new(Store::Memory(MemStore::default()));
        Arc::new(CertManager::new(Arc::new(test_config()), store, CertStorage::file(dir)))
    }

    fn temp_dir() -> std::path::PathBuf {
        let mut b = [0u8; 8];
        rand::fill(&mut b);
        std::env::temp_dir().join(format!("edns-tls-{}", hex::encode(b)))
    }

    const NAMES: &[&str] = &["example.test", "*.example.test"];
    const DAY: Duration = Duration::from_secs(86400);

    #[tokio::test]
    async fn renewal_window() {
        let dir = temp_dir();
        let m = manager(&dir);
        let now = SystemTime::now();
        assert!(m.needs_renewal(now), "no certificate yet");

        // 90-day certificate: renew once fewer than 30 days remain.
        m.install(parse(&self_signed(NAMES, now - 10 * DAY, 90)).unwrap());
        assert!(!m.needs_renewal(now), "80 days left");
        assert!(!m.needs_renewal(now + 49 * DAY), "31 days left");
        assert!(m.needs_renewal(now + 51 * DAY), "29 days left");

        // A certificate that doesn't cover both names is replaced.
        *m.current.write().unwrap() = None;
        m.install(parse(&self_signed(&["example.test"], now, 90)).unwrap());
        assert!(m.needs_renewal(now), "wildcard missing");
    }

    #[tokio::test]
    async fn loads_stored_certificate_without_ordering() {
        let dir = temp_dir();
        let m = manager(&dir);
        let now = SystemTime::now();
        m.storage.store(&m.cert_key(), &self_signed(NAMES, now, 90)).await.unwrap();

        // A valid stored certificate means no ACME traffic at all (there is
        // no network in this test, so ordering would fail).
        m.maintain(now).await.unwrap();
        assert!(m.current.read().unwrap().is_some());

        // A newer one stored by another replica is picked up on the next
        // pass; an older one is never swapped in.
        let newer = self_signed(NAMES, now + DAY, 90);
        m.storage.store(&m.cert_key(), &newer).await.unwrap();
        m.maintain(now).await.unwrap();
        assert_eq!(m.current.read().unwrap().as_ref().unwrap().pem, newer);
        m.storage.store(&m.cert_key(), &self_signed(NAMES, now - DAY, 90)).await.unwrap();
        m.maintain(now).await.unwrap();
        assert_eq!(m.current.read().unwrap().as_ref().unwrap().pem, newer);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_bad_pem() {
        assert!(parse(b"").is_err());
        let now = SystemTime::now();
        let a = self_signed(NAMES, now, 90);
        let b = self_signed(NAMES, now, 90);
        // Key from one pair, certificate from another.
        let key_end = a.windows(25).position(|w| w == b"-----END PRIVATE KEY-----").unwrap() + 26;
        let cert_start = b.windows(27).position(|w| w == b"-----BEGIN CERTIFICATE-----").unwrap();
        let mixed = [&a[..key_end], &b[cert_start..]].concat();
        assert!(parse(&mixed).is_err(), "mismatched key accepted");
    }

    /// The full HTTPS path: TLS handshake with the managed certificate, ALPN,
    /// then a request through the real HTTP handler.
    #[tokio::test]
    async fn https_serves_managed_certificate() {
        let dir = temp_dir();
        let m = manager(&dir);
        let pem = self_signed(NAMES, SystemTime::now(), 90);
        m.install(parse(&pem).unwrap());

        let mut cfg = test_config();
        cfg.enable_tls = true;
        let h = Arc::new(crate::http::HttpHandler::new(Arc::new(cfg), Arc::new(Store::Memory(MemStore::default()))));
        let ln = crate::net::Listener::bind("127.0.0.1:0", false, 4).await.unwrap();
        let addr = ln.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(m.clone().server_config().unwrap());
        tokio::spawn(crate::http::serve(h, ln, Some(acceptor)));

        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&pem) {
            roots.add(cert.unwrap()).unwrap();
        }
        let mut client =
            rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        client.alpn_protocols = vec![b"http/1.1".to_vec()];
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector.connect(ServerName::try_from("abc.example.test").unwrap(), tcp).await.unwrap();

        tls.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut resp = String::new();
        tls.read_to_string(&mut resp).await.unwrap();
        assert!(resp.starts_with("HTTP/1.1 302"), "{resp}");
        assert!(resp.to_lowercase().contains("location: https://"), "{resp}");
        assert!(resp.to_lowercase().contains("strict-transport-security"), "{resp}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
