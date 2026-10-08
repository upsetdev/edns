//! The authoritative DNS server: zone answers, token capture, ACME TXT.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use hickory_proto::op::{Edns, Message, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA, HINFO, NS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::clock::{Clock, unix_secs};
use crate::config::{Config, StoreKind};
use crate::limit::{CaptureGuard, Limiter, prefix_key};
use crate::net::{Accepted, Listener};
use crate::store::{Capture, Store};
use crate::token;

/// Caps concurrent DNS-over-TCP connections. Real resolvers only use TCP to
/// retry truncated answers, so this is generous.
pub const MAX_TCP_CONNS: usize = 512;
/// Queries handled concurrently over UDP; past this, packets are dropped
/// rather than queued, as a resolver retries anyway.
const UDP_MAX_INFLIGHT: usize = 2048;
/// DNS over TCP timeouts and per-connection query cap (miekg's defaults).
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_MAX_QUERIES: usize = 128;
/// Largest UDP reply to a query without EDNS.
const UDP_MAX_REPLY: usize = 512;
/// The UDP payload size we advertise and honour with EDNS: the DNS Flag Day
/// 2020 value, which avoids IP fragmentation on virtually every path.
const EDNS_MAX_PAYLOAD: u16 = 1232;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

pub struct DnsHandler {
    cfg: Arc<Config>,
    pub(crate) store: Arc<Store>,
    pub(crate) clock: Clock,
    /// Per source prefix; `None` = unlimited.
    pub(crate) udp_limit: Option<Limiter>,
    /// Separate, so spoofed UDP can't lock out the TCP retry.
    pub(crate) tcp_limit: Option<Limiter>,
    /// Skips Redis for already-captured tokens; `None` = off.
    pub(crate) guard: Option<CaptureGuard>,
    // Parsed once from the config, which validated them.
    base: Name,
    ns: Vec<Name>,
    hostmaster: Name,
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).expect("names are validated when the config loads")
}

impl DnsHandler {
    pub fn new(cfg: Arc<Config>, store: Arc<Store>) -> Self {
        DnsHandler {
            base: name(&cfg.base_domain),
            ns: cfg.ns.iter().map(|n| name(n)).collect(),
            hostmaster: name(&cfg.hostmaster),
            store,
            clock: Clock::system(),
            udp_limit: Limiter::new(cfg.dns_rate_limit, cfg.dns_rate_burst),
            tcp_limit: Limiter::new(cfg.dns_rate_limit, cfg.dns_rate_burst),
            // Captures cost money only in Redis; in memory a repeat is a
            // cheap map lookup in record itself.
            guard: (cfg.store == StoreKind::Redis).then(CaptureGuard::default),
            cfg,
        }
    }

    /// Answers one raw query, or returns `None` to stay silent. This is the
    /// server layer: it filters what reaches [`DnsHandler::handle`] the way
    /// miekg/dns's default accept function did.
    pub async fn respond(&self, packet: &[u8], peer: IpAddr, transport: Transport) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None;
        }
        // Never answer a response: two servers answering each other's
        // replies would loop forever, and it's a classic reflection trick.
        if packet[2] & 0x80 != 0 {
            return None;
        }
        let req = match Message::from_vec(packet) {
            Ok(m) => m,
            Err(_) => return Some(header_only_reply(packet, ResponseCode::FormErr)),
        };
        if req.metadata.op_code != OpCode::Query {
            return error_reply(&req, ResponseCode::NotImp);
        }
        if req.queries.len() != 1 {
            return error_reply(&req, ResponseCode::FormErr);
        }

        let resp = self.handle(&req, peer, transport).await;
        let bytes = resp.to_vec().ok()?;
        let max = match &req.edns {
            Some(e) => e.max_payload().clamp(UDP_MAX_REPLY as u16, EDNS_MAX_PAYLOAD).into(),
            None => UDP_MAX_REPLY,
        };
        if transport == Transport::Udp && bytes.len() > max {
            return resp.truncate().to_vec().ok();
        }
        Some(bytes)
    }

    pub async fn handle(&self, req: &Message, peer: IpAddr, transport: Transport) -> Message {
        let mut m = Message::response(req.metadata.id, req.metadata.op_code);
        m.metadata = Metadata::response_from_request(&req.metadata);
        m.metadata.authoritative = true;
        m.queries = req.queries.iter().take(1).cloned().collect();

        // Response rate limiting per source prefix, before any work. Over UDP
        // the reply is an empty truncated answer: no bigger than the query, so
        // useless for reflection, while a real resolver retries over TCP,
        // which a spoofed source cannot complete. TCP has its own buckets, so
        // a spoofed flood claiming a real resolver's prefix can't block that
        // retry; a TCP source is genuine, so over its own limit it is simply
        // refused.
        let limit = match transport {
            Transport::Udp => &self.udp_limit,
            Transport::Tcp => &self.tcp_limit,
        };
        if limit.as_ref().is_some_and(|l| !l.allow(&prefix_key(peer, 24, 56), self.clock.now())) {
            m.metadata.authoritative = false;
            match transport {
                Transport::Udp => m.metadata.truncation = true,
                Transport::Tcp => m.metadata.response_code = ResponseCode::Refused,
            }
            return m;
        }
        m.edns = edns_reply(req);

        let Some(q) = req.queries.first() else { return m };
        let qname = q.name.to_ascii().to_lowercase();
        let base = self.cfg.base_domain.as_str();

        // Serve glue for our own nameserver hostnames, which live outside the
        // primary zone (e.g. edns1.ns.upset.dev). A resolver that follows the
        // NS records may look these up directly, so we answer them with
        // HTTP_IP.
        if self.cfg.ns.contains(&qname) {
            match q.query_type {
                RecordType::A => m.answers.push(rr(&q.name, 3600, RData::A(A(self.cfg.http_ip)))),
                RecordType::AAAA => {
                    if let Some(ip) = self.cfg.http_ipv6 {
                        m.answers.push(rr(&q.name, 3600, RData::AAAA(AAAA(ip))));
                    }
                }
                _ => {}
            }
            return m;
        }

        // Only authoritative for our zone.
        if qname != base && !qname.ends_with(&format!(".{base}")) {
            m.metadata.response_code = ResponseCode::Refused;
            return m;
        }

        // ACME DNS-01 challenge: serve the TXT the ACME client published. The
        // challenge name is the same for the apex and the wildcard cert.
        if qname == format!("_acme-challenge.{base}") {
            if q.query_type == RecordType::TXT {
                for v in self.store.get_txt(&qname).await {
                    m.answers.push(rr(&q.name, 0, RData::TXT(TXT::new(vec![v]))));
                }
            }
            if m.answers.is_empty() {
                m.authorities.push(self.soa());
            }
            return m;
        }

        match q.query_type {
            RecordType::ANY => {
                // RFC 8482: answer ANY with a single small synthesized record
                // rather than everything we have, so it can't be used for
                // amplification.
                m.answers.push(rr(&q.name, 3600, RData::HINFO(HINFO::new("RFC8482".into(), String::new()))));
            }
            RecordType::SOA => m.answers.push(self.soa()),
            RecordType::NS => {
                for ns in &self.ns {
                    m.answers.push(rr(&self.base, 86400, RData::NS(NS(ns.clone()))));
                }
            }
            RecordType::A => {
                // A query for a token subdomain is the signal we care about:
                // it means a resolver looked the name up on behalf of a client.
                if let Some(label) = token_label(&qname, base)
                    && let Some(expires) = token::verify(&self.cfg, label, self.clock.now())
                {
                    self.capture(label, expires, peer, req).await;
                }
                m.answers.push(rr(&q.name, 5, RData::A(A(self.cfg.http_ip))));
            }
            RecordType::AAAA => match self.cfg.http_ipv6 {
                Some(ip) => m.answers.push(rr(&q.name, 5, RData::AAAA(AAAA(ip)))),
                // No AAAA configured: NOERROR/NODATA with SOA in authority.
                None => m.authorities.push(self.soa()),
            },
            // Known name, unsupported type: NODATA.
            _ => m.authorities.push(self.soa()),
        }
        m
    }

    /// Records the resolver IP and ECS for a verified token.
    async fn capture(&self, token: &str, expires: SystemTime, resolver: IpAddr, req: &Message) {
        let now = self.clock.now();
        if self.guard.as_ref().is_some_and(|g| !g.first(token, expires, now)) {
            return;
        }
        let (ecs, family) = extract_ecs(req);
        let c = Capture {
            token: token.to_string(),
            resolver_ip: resolver.to_string(),
            ecs: ecs.clone(),
            ecs_family: family.to_string(),
            resolved: true,
            created_at: unix_secs(expires - self.cfg.ttl) as i64,
        };
        if self.store.record(token, &c, expires).await {
            tracing::info!("dns resolve token={token} resolver={resolver} ecs={ecs}");
        }
    }

    fn soa(&self) -> Record {
        let mname = self.ns.first().cloned().unwrap_or_else(|| name(&format!("ns1.{}", self.cfg.base_domain)));
        let soa = SOA::new(mname, self.hostmaster.clone(), soa_serial(self.clock.now()), 7200, 3600, 1209600, 60);
        rr(&self.base, 60, RData::SOA(soa))
    }
}

fn rr(name: &Name, ttl: u32, data: RData) -> Record {
    Record::from_rdata(name.clone(), ttl, data)
}

/// The OPT record for a reply: present when the query had one (RFC 6891
/// requires it), echoing any client subnet with scope /0, which tells the
/// resolver our answer is the same for every subnet (RFC 7871). Resolvers
/// such as Google Public DNS only keep sending ECS to nameservers that echo
/// it, and the forwarded subnet is what this service reports.
fn edns_reply(req: &Message) -> Option<Edns> {
    let query = req.edns.as_ref()?;
    let mut e = Edns::new();
    e.set_max_payload(EDNS_MAX_PAYLOAD);
    if let Some(EdnsOption::Subnet(s)) = query.option(EdnsCode::Subnet) {
        e.options_mut().insert(EdnsOption::Subnet(ClientSubnet::new(s.addr(), s.source_prefix(), 0)));
    }
    Some(e)
}

/// A FORMERR/NOTIMP reply to a query we couldn't (or won't) process: header
/// only, so never larger than the query.
fn error_reply(req: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut m = Message::error_msg(req.metadata.id, req.metadata.op_code, code);
    m.metadata.recursion_desired = req.metadata.recursion_desired;
    m.to_vec().ok()
}

/// Like [`error_reply`] for a packet that didn't even parse: echoes the id,
/// opcode and RD bit from the raw header.
fn header_only_reply(packet: &[u8], code: ResponseCode) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out[..2].copy_from_slice(&packet[..2]);
    out[2] = 0x80 | (packet[2] & 0x79); // QR, opcode, RD
    out[3] = u16::from(code) as u8 & 0x0f;
    out
}

/// Derives the SOA serial from the clock. Serials compare with RFC 1982
/// sequence-space arithmetic, so truncating to 32 bits (wrapping in 2106)
/// stays monotonic as far as resolvers are concerned.
pub fn soa_serial(t: SystemTime) -> u32 {
    unix_secs(t) as u32
}

/// The left-most label of `qname` if it is a direct subdomain of `base`
/// (i.e. "<token>.base.").
pub fn token_label<'a>(qname: &'a str, base: &str) -> Option<&'a str> {
    let prefix = qname.strip_suffix(base)?.strip_suffix('.')?;
    (!prefix.is_empty() && !prefix.contains('.')).then_some(prefix)
}

/// Pulls the EDNS Client Subnet option from a query: (subnet, family), or
/// ("none", "none") when absent or zero-length.
pub fn extract_ecs(req: &Message) -> (String, &'static str) {
    let none = ("none".to_string(), "none");
    let Some(edns) = &req.edns else { return none };
    let Some(EdnsOption::Subnet(s)) = edns.option(EdnsCode::Subnet) else { return none };
    if s.source_prefix() == 0 {
        return none;
    }
    let family = if s.addr().is_ipv4() { "ipv4" } else { "ipv6" };
    (format!("{}/{}", s.addr(), s.source_prefix()), family)
}

pub async fn serve_udp(h: Arc<DnsHandler>, sock: UdpSocket) -> io::Result<()> {
    let sock = Arc::new(sock);
    let inflight = Arc::new(Semaphore::new(UDP_MAX_INFLIGHT));
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            // An ICMP error from an earlier reply surfaces here on some
            // systems; it says nothing about the socket itself.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => continue,
            Err(e) => return Err(e),
        };
        let Ok(permit) = inflight.clone().try_acquire_owned() else { continue };
        let packet = buf[..n].to_vec();
        let (h, sock) = (h.clone(), sock.clone());
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(reply) = h.respond(&packet, peer.ip().to_canonical(), Transport::Udp).await {
                let _ = sock.send_to(&reply, peer).await;
            }
        });
    }
}

pub async fn serve_tcp(h: Arc<DnsHandler>, ln: Listener) -> io::Result<()> {
    loop {
        let conn = ln.accept().await?;
        let h = h.clone();
        tokio::spawn(async move {
            let _ = serve_tcp_conn(&h, conn).await;
        });
    }
}

async fn serve_tcp_conn(h: &DnsHandler, conn: Accepted) -> io::Result<()> {
    let mut conn = conn.resolve().await?;
    let (s, peer) = (&mut conn.stream, conn.peer);
    for i in 0..TCP_MAX_QUERIES {
        let wait = if i == 0 { TCP_READ_TIMEOUT } else { TCP_IDLE_TIMEOUT };
        let Ok(Ok(len)) = timeout(wait, s.read_u16()).await else { return Ok(()) };
        let mut msg = vec![0u8; len.into()];
        timeout(TCP_READ_TIMEOUT, s.read_exact(&mut msg)).await??;
        let Some(reply) = h.respond(&msg, peer, Transport::Tcp).await else { return Ok(()) };
        let mut out = Vec::with_capacity(2 + reply.len());
        out.extend((reply.len() as u16).to_be_bytes());
        out.extend(reply);
        timeout(TCP_WRITE_TIMEOUT, s.write_all(&out)).await??;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::test_config;
    use crate::store::MemStore;
    use hickory_proto::op::{Edns, Query};
    use hickory_proto::rr::rdata::opt::ClientSubnet;

    fn handler() -> DnsHandler {
        DnsHandler::new(Arc::new(test_config()), Arc::new(Store::Memory(MemStore::default())))
    }

    fn mem(h: &DnsHandler) -> &MemStore {
        match &*h.store {
            Store::Memory(m) => m,
            Store::Redis(_) => panic!("not a memory store"),
        }
    }

    fn new_token() -> String {
        token::mint(&test_config(), SystemTime::now())
    }

    fn request(qname: &str, qtype: RecordType, ecs: Option<&str>) -> Vec<u8> {
        let mut req = Message::query();
        req.metadata.recursion_desired = true;
        req.add_query(Query::query(Name::from_ascii(qname).unwrap(), qtype));
        if let Some(ecs) = ecs {
            let mut edns = Edns::new();
            edns.set_max_payload(4096);
            edns.options_mut().insert(EdnsOption::Subnet(ecs.parse::<ClientSubnet>().unwrap()));
            req.set_edns(edns);
        }
        req.to_vec().unwrap()
    }

    /// Sends one question to `h` as if it came from `peer`, through the
    /// wire encoding both ways.
    async fn query_via(
        h: &DnsHandler,
        qname: &str,
        qtype: RecordType,
        peer: &str,
        ecs: Option<&str>,
        t: Transport,
    ) -> Message {
        let reply = h.respond(&request(qname, qtype, ecs), peer.parse().unwrap(), t).await.expect("no reply");
        Message::from_vec(&reply).unwrap()
    }

    async fn query(h: &DnsHandler, qname: &str, qtype: RecordType, peer: &str, ecs: Option<&str>) -> Message {
        query_via(h, qname, qtype, peer, ecs, Transport::Udp).await
    }

    fn first_answer(m: &Message) -> String {
        match &m.answers[0].data {
            RData::A(a) => a.0.to_string(),
            RData::AAAA(a) => a.0.to_string(),
            RData::NS(ns) => ns.0.to_ascii(),
            RData::SOA(soa) => soa.mname.to_ascii(),
            other => format!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn answers_zone_records() {
        let h = handler();
        let cases = [
            ("example.test.", RecordType::A, "192.0.2.10"),
            ("example.test.", RecordType::AAAA, "2001:db8::10"),
            ("example.test.", RecordType::NS, "ns1.example.test."),
            ("example.test.", RecordType::SOA, "ns1.example.test."),
            ("example.test.", RecordType::MX, ""),
            ("ns2.example.test.", RecordType::A, "192.0.2.10"),
            ("anything.example.test.", RecordType::A, "192.0.2.10"),
        ];
        for (name, qtype, want) in cases {
            let m = query(&h, name, qtype, "198.51.100.1", None).await;
            assert_eq!(m.metadata.response_code, ResponseCode::NoError, "{name}/{qtype}");
            assert!(m.metadata.authoritative, "{name}/{qtype}: not authoritative");
            if want.is_empty() {
                assert!(m.answers.is_empty() && !m.authorities.is_empty(), "{name}/{qtype}: want NODATA with SOA");
            } else {
                assert_eq!(first_answer(&m), want, "{name}/{qtype}");
            }
        }
    }

    #[tokio::test]
    async fn aaaa_without_ipv6_is_nodata() {
        let mut cfg = test_config();
        cfg.http_ipv6 = None;
        let h = DnsHandler::new(Arc::new(cfg), Arc::new(Store::Memory(MemStore::default())));
        let m = query(&h, "example.test.", RecordType::AAAA, "198.51.100.1", None).await;
        assert!(m.answers.is_empty() && !m.authorities.is_empty());
    }

    #[tokio::test]
    async fn refuses_out_of_zone() {
        let m = query(&handler(), "example.com.", RecordType::A, "198.51.100.1", None).await;
        assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn captures_resolver_and_ecs() {
        let cases = [
            ("no ecs", None, "none", "none"),
            ("ipv4 ecs", Some("203.0.113.0/24"), "203.0.113.0/24", "ipv4"),
            ("ipv6 ecs", Some("2001:db8:1::/56"), "2001:db8:1::/56", "ipv6"),
        ];
        for (name, ecs, want_ecs, want_family) in cases {
            let h = handler();
            let tok = new_token();
            query(&h, &format!("{tok}.example.test."), RecordType::A, "198.51.100.7", ecs).await;
            let c = h.store.get(&tok).await.unwrap_or_else(|| panic!("{name}: not captured"));
            assert!(c.resolved && c.resolver_ip == "198.51.100.7", "{name}: {c:?}");
            assert_eq!((c.ecs.as_str(), c.ecs_family.as_str()), (want_ecs, want_family), "{name}");
        }
    }

    #[tokio::test]
    async fn capture_ignores_forged_expired_and_junk() {
        let h = handler();
        let cfg = test_config();
        let mut other = cfg.clone();
        other.token_secret = b"some-other-secret-some-other-secret".to_vec();
        let expired = token::mint(&cfg, SystemTime::now() - 2 * cfg.ttl);
        let forged = token::mint(&other, SystemTime::now());

        // None of these may touch the store: forged and expired tokens fail
        // the MAC/expiry check in memory, and junk labels can't be tokens.
        for name in [
            format!("{forged}.example.test."),
            format!("{expired}.example.test."),
            "www.example.test.".into(),
            "a.b.example.test.".into(),
            "0123456789abcdef.example.test.".into(),
        ] {
            query(&h, &name, RecordType::A, "198.51.100.1", None).await;
        }
        assert_eq!(mem(&h).ops(), 0, "invalid lookups touched the store");
    }

    #[tokio::test]
    async fn capture_is_case_insensitive() {
        // Resolvers randomize query case (DNS 0x20), so the token must still match.
        let h = handler();
        let tok = new_token();
        query(&h, &format!("{}.Example.TEST.", tok.to_uppercase()), RecordType::A, "198.51.100.7", None).await;
        assert!(h.store.get(&tok).await.is_some_and(|c| c.resolved), "mixed-case lookup was not captured");
    }

    /// The first lookup is the client following the redirect; later lookups
    /// of the same token (another tool or device, resolver prefetch) must not
    /// replace it. Checked on both backends, since Redis relies on the guard
    /// plus SET NX and memory on record alone.
    #[tokio::test]
    async fn keeps_first_capture() {
        let mut handlers = vec![("memory", handler())];
        if let Some(url) = crate::store::tests::test_redis_url() {
            let mut cfg = test_config();
            cfg.store = StoreKind::Redis;
            let store = Store::Redis(crate::store::RedisStore::new(&url).unwrap());
            handlers.push(("redis", DnsHandler::new(Arc::new(cfg), Arc::new(store))));
        }
        for (name, h) in handlers {
            let tok = new_token();
            let qname = format!("{tok}.example.test.");
            query(&h, &qname, RecordType::A, "172.253.236.213", Some("203.0.113.0/24")).await;
            query(&h, &qname, RecordType::A, "185.40.106.78", None).await;
            let c = h.store.get(&tok).await.unwrap();
            assert_eq!(
                (c.resolver_ip.as_str(), c.ecs.as_str()),
                ("172.253.236.213", "203.0.113.0/24"),
                "{name}: want the first resolver and its ECS"
            );
        }
    }

    #[tokio::test]
    async fn guard_skips_store_on_repeats() {
        let mut h = handler();
        h.guard = Some(CaptureGuard::default());
        let tok = new_token();
        let qname = format!("{tok}.example.test.");
        query(&h, &qname, RecordType::A, "198.51.100.7", None).await;
        let base = mem(&h).ops();
        for i in 0..10 {
            query(&h, &qname, RecordType::A, &format!("198.51.100.{}", 10 + i), None).await;
        }
        assert_eq!(mem(&h).ops() - base, 0, "repeat captures touched the store");
    }

    #[test]
    fn memory_store_has_no_capture_guard() {
        assert!(handler().guard.is_none());
        let mut cfg = test_config();
        cfg.store = StoreKind::Redis;
        let h = DnsHandler::new(Arc::new(cfg), Arc::new(Store::Memory(MemStore::default())));
        assert!(h.guard.is_some(), "redis config should guard captures");
    }

    #[tokio::test]
    async fn rate_limit() {
        let mut h = handler();
        h.udp_limit = Limiter::new(1.0, 5);
        h.tcp_limit = Limiter::new(1.0, 5);
        h.clock = Clock::fixed(SystemTime::now());
        let tok = new_token();

        for i in 0..5 {
            let m = query(&h, "example.test.", RecordType::A, &format!("198.51.100.{i}"), None).await;
            assert!(!m.metadata.truncation && !m.answers.is_empty(), "query {i} within burst was limited");
        }
        // The whole /24 shares one bucket: the next UDP query gets an empty
        // truncated reply and does not capture.
        let m = query(&h, &format!("{tok}.example.test."), RecordType::A, "198.51.100.200", None).await;
        assert!(m.metadata.truncation && m.answers.is_empty() && m.authorities.is_empty(), "want empty TC reply");
        assert_eq!(mem(&h).ops(), 0, "a rate-limited query reached the store");

        // The truncated reply's TCP retry has its own bucket, so a spoofed
        // UDP flood can't lock the real resolver out. Past the TCP limit the
        // source is genuine, so the reply is REFUSED rather than TC.
        for i in 0..5 {
            let m = query_via(&h, "example.test.", RecordType::A, "198.51.100.1", None, Transport::Tcp).await;
            assert!(m.metadata.response_code == ResponseCode::NoError && !m.answers.is_empty(), "TCP query {i}");
        }
        let m = query_via(&h, "example.test.", RecordType::A, "198.51.100.1", None, Transport::Tcp).await;
        assert_eq!(m.metadata.response_code, ResponseCode::Refused);
        assert!(!m.metadata.truncation);

        // Another /24 is unaffected, and the bucket refills over time.
        assert!(!query(&h, "example.test.", RecordType::A, "198.51.101.1", None).await.metadata.truncation);
        h.clock.advance(Duration::from_secs(2));
        assert!(!query(&h, "example.test.", RecordType::A, "198.51.100.1", None).await.metadata.truncation);
    }

    /// Replies carry OPT exactly when the query did, and echo the client
    /// subnet with scope /0 (RFC 7871), so resolvers keep forwarding it.
    #[tokio::test]
    async fn echoes_edns_and_client_subnet() {
        let h = handler();
        let tok = new_token();

        let m = query(&h, &format!("{tok}.example.test."), RecordType::A, "198.51.100.7", Some("203.0.113.0/24")).await;
        let edns = m.edns.as_ref().expect("no OPT in reply to an EDNS query");
        assert_eq!(edns.max_payload(), EDNS_MAX_PAYLOAD);
        match edns.option(EdnsCode::Subnet) {
            Some(EdnsOption::Subnet(s)) => {
                assert_eq!((s.addr().to_string(), s.source_prefix(), s.scope_prefix()), ("203.0.113.0".into(), 24, 0));
            }
            other => panic!("ECS not echoed: {other:?}"),
        }

        let v6 = query(&h, "example.test.", RecordType::AAAA, "198.51.100.7", Some("2001:db8:1::/56")).await;
        match v6.edns.as_ref().and_then(|e| e.option(EdnsCode::Subnet)) {
            Some(EdnsOption::Subnet(s)) => assert_eq!((s.source_prefix(), s.scope_prefix()), (56, 0)),
            other => panic!("IPv6 ECS not echoed: {other:?}"),
        }

        // No EDNS in, no OPT out; out-of-zone refusals still carry it.
        let plain = Message::from_vec(
            &h.respond(&request("example.test.", RecordType::A, None), "198.51.100.7".parse().unwrap(), Transport::Udp)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(plain.edns.is_none(), "OPT added to a non-EDNS query");
        let refused = query(&h, "example.com.", RecordType::A, "198.51.100.7", Some("203.0.113.0/24")).await;
        assert_eq!(refused.metadata.response_code, ResponseCode::Refused);
        assert!(refused.edns.is_some());
    }

    #[tokio::test]
    async fn answers_any_minimally() {
        let m = query(&handler(), "example.test.", RecordType::ANY, "198.51.100.1", None).await;
        assert_eq!(m.answers.len(), 1);
        match &m.answers[0].data {
            RData::HINFO(h) => assert_eq!(&*h.cpu, b"RFC8482"),
            other => panic!("ANY answer = {other:?}, want RFC 8482 HINFO"),
        }
    }

    #[tokio::test]
    async fn serves_acme_challenge() {
        let h = handler();
        let name = "_acme-challenge.example.test.";
        assert!(query(&h, name, RecordType::TXT, "198.51.100.1", None).await.answers.is_empty());
        h.store.add_txt(name, "key-auth-1").await.unwrap();
        let m = query(&h, name, RecordType::TXT, "198.51.100.1", None).await;
        match m.answers.first().map(|r| &r.data) {
            Some(RData::TXT(t)) => assert_eq!(&*t.txt_data[0], b"key-auth-1"),
            other => panic!("answer = {other:?}, want key-auth-1"),
        }
        h.store.del_txt(name, "key-auth-1").await.unwrap();
        assert!(query(&h, name, RecordType::TXT, "198.51.100.1", None).await.answers.is_empty());
    }

    #[tokio::test]
    async fn server_layer_filters() {
        let h = handler();
        let peer: IpAddr = "198.51.100.1".parse().unwrap();

        // Responses are never answered.
        let mut resp = Message::from_vec(&request("example.test.", RecordType::A, None)).unwrap();
        resp.metadata.message_type = hickory_proto::op::MessageType::Response;
        assert!(h.respond(&resp.to_vec().unwrap(), peer, Transport::Udp).await.is_none());

        // Other opcodes get NOTIMP; garbage gets a header-only FORMERR.
        let mut notify = Message::from_vec(&request("example.test.", RecordType::A, None)).unwrap();
        notify.metadata.op_code = OpCode::Notify;
        let reply =
            Message::from_vec(&h.respond(&notify.to_vec().unwrap(), peer, Transport::Udp).await.unwrap()).unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);

        let garbage = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xff];
        let reply = h.respond(&garbage, peer, Transport::Udp).await.unwrap();
        assert_eq!(reply.len(), 12, "error reply must be header-only");
        assert_eq!(&reply[..2], &[0x12, 0x34], "id echoed");
        assert_eq!(reply[3] & 0x0f, 1, "FORMERR");

        assert!(h.respond(&[0u8; 5], peer, Transport::Udp).await.is_none(), "runt packet answered");
    }

    #[tokio::test]
    async fn udp_and_tcp_servers() {
        let h = Arc::new(handler());
        let udp = crate::net::bind_udp("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        tokio::spawn(serve_udp(h.clone(), udp));
        let ln = Listener::bind("127.0.0.1:0", false, 4).await.unwrap();
        let tcp_addr = ln.local_addr().unwrap();
        tokio::spawn(serve_tcp(h.clone(), ln));

        let tok = new_token();
        let req = request(&format!("{tok}.example.test."), RecordType::A, Some("203.0.113.0/24"));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&req, udp_addr).await.unwrap();
        let mut buf = [0u8; 512];
        let n = timeout(Duration::from_secs(2), client.recv(&mut buf)).await.unwrap().unwrap();
        assert_eq!(first_answer(&Message::from_vec(&buf[..n]).unwrap()), "192.0.2.10");
        let c = h.store.get(&tok).await.expect("captured over UDP");
        assert_eq!((c.resolver_ip.as_str(), c.ecs.as_str()), ("127.0.0.1", "203.0.113.0/24"));

        let mut s = tokio::net::TcpStream::connect(tcp_addr).await.unwrap();
        for _ in 0..2 {
            // Several queries on one connection.
            s.write_all(&(req.len() as u16).to_be_bytes()).await.unwrap();
            s.write_all(&req).await.unwrap();
            let len = s.read_u16().await.unwrap();
            let mut msg = vec![0u8; len.into()];
            s.read_exact(&mut msg).await.unwrap();
            assert_eq!(first_answer(&Message::from_vec(&msg).unwrap()), "192.0.2.10");
        }
    }

    #[test]
    fn token_labels() {
        let base = "example.test.";
        assert_eq!(token_label("abc.example.test.", base), Some("abc"));
        for q in ["example.test.", "a.b.example.test.", "abcexample.test.", "abc.other.test."] {
            assert_eq!(token_label(q, base), None, "{q}");
        }
    }

    #[test]
    fn soa_serials() {
        let t = |s: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(s);
        assert_eq!(soa_serial(t(1_700_000_000)), 1_700_000_000);
        // Past 2106 the serial wraps instead of panicking or saturating.
        assert_eq!(soa_serial(t((1 << 32) + 5)), 5);
    }
}
