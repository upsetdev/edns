//! Configuration, read from environment variables at startup.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use anyhow::{Context, bail};
use hickory_proto::rr::Name;

/// Where captures and ACME challenge records live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreKind {
    /// In process memory: a single instance only.
    Memory,
    /// Redis: shared between instances.
    Redis,
}

/// Where certificates, keys and the ACME account live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CertStoreKind {
    /// Files under `cert_dir`: a single instance only.
    File,
    /// Redis, with a distributed lock so only one instance orders or renews.
    Redis,
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Lower-case FQDN with a trailing dot, e.g. "edns.upset.dev.".
    pub base_domain: String,
    /// Public IPv4 of this server: the A record we hand out.
    pub http_ip: Ipv4Addr,
    /// Optional public IPv6 (AAAA).
    pub http_ipv6: Option<Ipv6Addr>,
    /// Authoritative nameservers (lower-case FQDNs), for NS/SOA answers.
    pub ns: Vec<String>,
    /// SOA RNAME, e.g. "hostmaster.upset.dev.".
    pub hostmaster: String,
    pub dns_addr: String,
    /// Separate UDP listen address (Fly.io: fly-global-services:53).
    pub dns_udp_addr: String,
    pub http_addr: String,
    pub https_addr: String,
    pub store: StoreKind,
    pub redis_addr: String,
    /// redis:// URL with credentials; overrides `redis_addr` when set.
    pub redis_url: Option<String>,
    /// Serve HTTPS with an ACME (DNS-01 wildcard) certificate.
    pub enable_tls: bool,
    pub acme_email: Option<String>,
    /// Use the Let's Encrypt staging CA.
    pub acme_staging: bool,
    pub cert_store: CertStoreKind,
    pub cert_dir: String,
    /// How long a token lives.
    pub ttl: Duration,
    /// HMAC key for tokens; must match across replicas.
    pub token_secret: Vec<u8>,
    /// Require a PROXY protocol header on TCP listeners.
    pub proxy_protocol: bool,
    /// DNS queries/s per source /24 (IPv4) or /56 (IPv6); 0 = off.
    pub dns_rate_limit: f64,
    /// HTTP requests/s per client IPv4 or /64; 0 = off.
    pub http_rate_limit: f64,
}

/// Ensures a trailing dot.
fn fqdn(s: &str) -> String {
    if s.ends_with('.') { s.to_string() } else { format!("{s}.") }
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Reads the configuration through `lookup` (the environment in
    /// production, a map in tests) and validates it. Empty values count as
    /// unset.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let get = |key: &str| lookup(key).filter(|v| !v.is_empty());
        let env = |key: &str, default: &str| get(key).unwrap_or_else(|| default.to_string());

        let base = fqdn(&env("BASE_DOMAIN", "edns.upset.dev").to_lowercase());
        let apex = base.trim_end_matches('.').to_string();

        let ns: Vec<String> = env("NS", &format!("ns1.{apex},ns2.{apex}"))
            .split(',')
            .map(str::trim)
            .filter(|n| !n.is_empty())
            .map(|n| fqdn(&n.to_lowercase()))
            .collect();
        if ns.is_empty() {
            bail!("NS must list at least one nameserver");
        }

        let store = match env("STORE", "memory").as_str() {
            "memory" => StoreKind::Memory,
            "redis" => StoreKind::Redis,
            other => bail!("STORE must be memory or redis, got {other:?}"),
        };
        let cert_store = match env("CERT_STORE", "file").as_str() {
            "file" => CertStoreKind::File,
            "redis" => CertStoreKind::Redis,
            other => bail!("CERT_STORE must be file or redis, got {other:?}"),
        };
        // Sharing certificates means several replicas answer DNS, and Let's
        // Encrypt's validation query may reach any of them, so the challenge
        // TXT must live in the shared store too.
        if cert_store == CertStoreKind::Redis && store != StoreKind::Redis {
            bail!("CERT_STORE=redis requires STORE=redis");
        }

        let rate = |key: &str, default: &str| -> anyhow::Result<f64> {
            let raw = env(key, default);
            match raw.parse::<f64>() {
                Ok(v) if v.is_finite() && v >= 0.0 => Ok(v),
                _ => bail!("{key} must be a non-negative number, got {raw:?}"),
            }
        };
        let dns_rate_limit = rate("DNS_RATE_LIMIT", "20")?;
        let http_rate_limit = rate("HTTP_RATE_LIMIT", "2")?;

        let token_secret = match get("TOKEN_SECRET") {
            Some(secret) if secret.len() < 32 => bail!("TOKEN_SECRET must be at least 32 characters"),
            Some(secret) => secret.into_bytes(),
            None => {
                // Fine for a single instance: a restart only invalidates
                // tokens minted in the seconds before it. Replicas must share
                // a TOKEN_SECRET.
                tracing::warn!("TOKEN_SECRET not set; using a random per-process secret");
                let mut secret = vec![0u8; 32];
                rand::fill(&mut secret[..]);
                secret
            }
        };

        // The A record we hand out is the whole point of the redirect; refuse
        // to start rather than answer with a wrong or empty address.
        let raw_ip = env("HTTP_IP", "");
        let http_ip: Ipv4Addr =
            raw_ip.parse().with_context(|| format!("HTTP_IP must be a public IPv4 address, got {raw_ip:?}"))?;
        let http_ipv6 = match get("HTTP_IPV6") {
            None => None,
            Some(raw) => Some(
                raw.parse::<Ipv6Addr>().with_context(|| format!("HTTP_IPV6 must be an IPv6 address, got {raw:?}"))?,
            ),
        };

        let hostmaster = fqdn(&env("HOSTMASTER", &format!("hostmaster.{apex}")).to_lowercase());
        // Every name ends up in a DNS answer, so reject ones that can't.
        for (key, name) in
            [("BASE_DOMAIN", &base), ("HOSTMASTER", &hostmaster)].into_iter().chain(ns.iter().map(|n| ("NS", n)))
        {
            Name::from_ascii(name).with_context(|| format!("{key}: invalid domain name {name:?}"))?;
        }

        let dns_addr = env("DNS_ADDR", ":53");
        Ok(Config {
            base_domain: base,
            http_ip,
            http_ipv6,
            ns,
            hostmaster,
            dns_udp_addr: env("DNS_UDP_ADDR", &dns_addr),
            dns_addr,
            http_addr: env("HTTP_ADDR", ":8080"),
            https_addr: env("HTTPS_ADDR", ":8443"),
            store,
            redis_addr: env("REDIS_ADDR", "redis:6379"),
            redis_url: get("REDIS_URL"),
            enable_tls: env("TLS", "true") == "true",
            acme_email: get("ACME_EMAIL"),
            acme_staging: env("ACME_STAGING", "false") == "true",
            cert_store,
            cert_dir: env("CERT_DIR", "/data"),
            ttl: Duration::from_secs(3600),
            token_secret,
            proxy_protocol: env("PROXY_PROTOCOL", "false") == "true",
            dns_rate_limit,
            http_rate_limit,
        })
    }

    /// The zone apex without the trailing dot, as it appears in Host headers.
    pub fn apex(&self) -> &str {
        self.base_domain.trim_end_matches('.')
    }

    /// The Redis connection URL.
    pub fn redis_conn_url(&self) -> String {
        self.redis_url.clone().unwrap_or_else(|| format!("redis://{}", self.redis_addr))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;

    /// A valid configuration for the example.test zone.
    pub fn test_config() -> Config {
        Config {
            base_domain: "example.test.".into(),
            http_ip: "192.0.2.10".parse().unwrap(),
            http_ipv6: Some("2001:db8::10".parse().unwrap()),
            ns: vec!["ns1.example.test.".into(), "ns2.example.test.".into()],
            hostmaster: "hostmaster.example.test.".into(),
            dns_addr: ":0".into(),
            dns_udp_addr: ":0".into(),
            http_addr: ":0".into(),
            https_addr: ":0".into(),
            store: StoreKind::Memory,
            redis_addr: String::new(),
            redis_url: None,
            enable_tls: false,
            acme_email: None,
            acme_staging: true,
            cert_store: CertStoreKind::File,
            cert_dir: String::new(),
            ttl: Duration::from_secs(3600),
            token_secret: b"test-secret-test-secret-test-secret".to_vec(),
            proxy_protocol: false,
            dns_rate_limit: 0.0,
            http_rate_limit: 0.0,
        }
    }

    fn load(vars: &[(&str, &str)]) -> anyhow::Result<Config> {
        let map: HashMap<String, String> = vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
        Config::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults() {
        let cfg = load(&[("BASE_DOMAIN", "Example.Test"), ("HTTP_IP", "192.0.2.10")]).unwrap();
        assert_eq!(cfg.base_domain, "example.test.", "lower-cased fqdn");
        assert_eq!(cfg.ns, ["ns1.example.test.", "ns2.example.test."]);
        assert_eq!(cfg.hostmaster, "hostmaster.example.test.");
        assert_eq!(cfg.dns_udp_addr, cfg.dns_addr, "UDP defaults to DNS_ADDR");
        assert!(cfg.enable_tls, "TLS defaults to on");
        assert_eq!(cfg.store, StoreKind::Memory);
        assert_eq!(cfg.cert_store, CertStoreKind::File);
        assert!(!cfg.proxy_protocol);
        assert_eq!((cfg.dns_rate_limit, cfg.http_rate_limit), (20.0, 2.0));
        assert_eq!(cfg.token_secret.len(), 32, "generated secret");
        assert_eq!(cfg.http_ipv6, None);
    }

    #[test]
    fn overrides() {
        let secret = "s".repeat(32);
        let cfg = load(&[
            ("HTTP_IP", "192.0.2.10"),
            ("NS", " a.example.net , b.example.net. ,"),
            ("HOSTMASTER", "dns.example.net"),
            ("DNS_ADDR", ":5353"),
            ("DNS_UDP_ADDR", "fly-global-services:53"),
            ("STORE", "redis"),
            ("CERT_STORE", "redis"),
            ("PROXY_PROTOCOL", "true"),
            ("DNS_RATE_LIMIT", "0"),
            ("HTTP_RATE_LIMIT", "0.5"),
            ("TOKEN_SECRET", &secret),
            ("HTTP_IPV6", "2001:db8::1"),
        ])
        .unwrap();
        assert_eq!(cfg.ns, ["a.example.net.", "b.example.net."]);
        assert_eq!(cfg.hostmaster, "dns.example.net.");
        assert_eq!((cfg.dns_addr.as_str(), cfg.dns_udp_addr.as_str()), (":5353", "fly-global-services:53"));
        assert_eq!((cfg.store, cfg.cert_store), (StoreKind::Redis, CertStoreKind::Redis));
        assert!(cfg.proxy_protocol);
        assert_eq!((cfg.dns_rate_limit, cfg.http_rate_limit), (0.0, 0.5));
        assert_eq!(cfg.token_secret, secret.as_bytes());
        assert_eq!(cfg.http_ipv6, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn rejects_invalid() {
        let cases = [
            ("missing HTTP_IP", "HTTP_IP", "", "HTTP_IP"),
            ("IPv6 as HTTP_IP", "HTTP_IP", "2001:db8::1", "HTTP_IP"),
            ("IPv4 as HTTP_IPV6", "HTTP_IPV6", "192.0.2.1", "HTTP_IPV6"),
            ("empty NS", "NS", " , ", "NS"),
            ("unknown STORE", "STORE", "memcached", "STORE"),
            ("unknown CERT_STORE", "CERT_STORE", "s3", "CERT_STORE"),
            ("CERT_STORE=redis without STORE=redis", "CERT_STORE", "redis", "STORE=redis"),
            ("bad DNS_RATE_LIMIT", "DNS_RATE_LIMIT", "fast", "DNS_RATE_LIMIT"),
            ("negative HTTP_RATE_LIMIT", "HTTP_RATE_LIMIT", "-1", "HTTP_RATE_LIMIT"),
            ("NaN rate", "DNS_RATE_LIMIT", "NaN", "DNS_RATE_LIMIT"),
            ("short TOKEN_SECRET", "TOKEN_SECRET", "short", "TOKEN_SECRET"),
            ("bad name", "BASE_DOMAIN", "a..b", "BASE_DOMAIN"),
        ];
        for (name, key, val, want) in cases {
            let mut vars = vec![("HTTP_IP", "192.0.2.10")];
            vars.retain(|(k, _)| *k != key);
            vars.push((key, val));
            let err = load(&vars).err().unwrap_or_else(|| panic!("{name}: want an error"));
            assert!(format!("{err:#}").contains(want), "{name}: err = {err:#}, want mention of {want}");
        }
    }
}
