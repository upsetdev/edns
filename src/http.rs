//! The HTTP(S) side: mint a token, report what the DNS side captured.

use std::convert::Infallible;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::header::{self, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_io_timeout::TimeoutStream;
use tokio_rustls::TlsAcceptor;

use crate::clock::Clock;
use crate::config::Config;
use crate::limit::{Limiter, prefix_key};
use crate::net::{Accepted, Listener};
use crate::store::{Capture, Store};
use crate::token;

pub type Resp = Response<Full<Bytes>>;

/// Caps concurrent connections per listener, so a connection flood queues in
/// the kernel instead of exhausting the VM's memory.
pub const MAX_CONNS: usize = 1024;

// Timeouts on every phase of a connection, so slow or idle clients can't
// hold it open indefinitely: headers must arrive within 5s, a read may stall
// at most 60s (which also bounds keep-alive idling), a write at most 10s.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const READ_TIMEOUT: Duration = Duration::from_secs(60);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// Request header budget (Go's 8 KiB MaxHeaderBytes plus its slack).
const MAX_HEADER_BYTES: usize = 12 << 10;

static FAVICON: &[u8] = include_bytes!("../public/favicon.ico");
/// The favicon's Last-Modified time: process start, so conditional requests work.
static FAVICON_MODIFIED: LazyLock<SystemTime> = LazyLock::new(SystemTime::now);

pub struct HttpHandler {
    cfg: Arc<Config>,
    store: Arc<Store>,
    /// Per client IPv4 or IPv6 /64; `None` = unlimited.
    limit: Option<Limiter>,
    clock: Clock,
}

impl HttpHandler {
    pub fn new(cfg: Arc<Config>, store: Arc<Store>) -> Self {
        LazyLock::force(&FAVICON_MODIFIED);
        HttpHandler {
            limit: Limiter::new(cfg.http_rate_limit, cfg.http_rate_burst),
            cfg,
            store,
            clock: Clock::system(),
        }
    }

    /// The complete handler chain. When TLS is on, every request is forced
    /// onto HTTPS: insecure ones are redirected, secure ones get HSTS so
    /// browsers stay on HTTPS thereafter.
    pub async fn serve<B>(&self, req: Request<B>, peer: IpAddr, tls: bool) -> Resp {
        // Secure when it reached us over TLS, directly (in-process) or via a
        // TLS-terminating proxy that set X-Forwarded-Proto.
        let secure = tls
            || req
                .headers()
                .get("x-forwarded-proto")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("https"));

        // Any other name or address pointed at us (the server's IP, the
        // fly.dev hostname, ...) has nothing to serve: send people to the
        // site itself. The target is fixed, so a forged Host header can't
        // make this an open redirect. No Host at all (HTTP/1.0) still mints.
        if !self.is_our_host(&request_host(&req)) {
            let scheme = if self.cfg.enable_tls { "https" } else { "http" };
            return redirect(req.method(), StatusCode::MOVED_PERMANENTLY, &format!("{scheme}://{}/", self.cfg.apex()));
        }

        if self.cfg.enable_tls && !secure {
            let target = format!("https://{}{}", host_only(&request_host(&req)), request_uri(&req));
            return redirect(req.method(), StatusCode::MOVED_PERMANENTLY, &target);
        }
        let mut resp = self.cors(req, peer, secure).await;
        if self.cfg.enable_tls {
            resp.headers_mut().insert(
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=63072000; includeSubDomains"),
            );
        }
        resp
    }

    /// Allows the JSON report to be fetched from any origin (the report is
    /// public, non-sensitive lookup data) and answers CORS preflight requests.
    async fn cors<B>(&self, req: Request<B>, peer: IpAddr, secure: bool) -> Resp {
        let mut resp = if req.method() == Method::OPTIONS {
            response(StatusCode::NO_CONTENT)
        } else if req.uri().path() == "/favicon.ico" {
            // Served on every host (apex and token subdomains) without
            // touching the store, so a browser's automatic favicon fetch
            // costs no Redis command.
            favicon(&req)
        } else {
            self.route(req, peer, secure).await
        };
        let h = resp.headers_mut();
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, OPTIONS"));
        h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("*"));
        h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
        resp
    }

    async fn route<B>(&self, req: Request<B>, peer: IpAddr, secure: bool) -> Resp {
        if self.limit.as_ref().is_some_and(|l| !l.allow(&prefix_key(peer, 32, 64), self.clock.now())) {
            let mut resp = text_error(StatusCode::TOO_MANY_REQUESTS, r#"{"error":"rate limited"}"#);
            resp.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
            return resp;
        }

        let host = host_only(&request_host(&req)).trim_end_matches('.').to_lowercase();
        let base = self.cfg.apex(); // compared without the trailing dot
        if host == base || host.is_empty() {
            return self.mint(req.method(), secure);
        }
        match host.strip_suffix(base).and_then(|p| p.strip_suffix('.')) {
            Some(token) if token::verify(&self.cfg, token, self.clock.now()).is_some() => self.report(token).await,
            Some(_) => text_error(StatusCode::NOT_FOUND, r#"{"error":"unknown or expired token"}"#),
            None => text_error(StatusCode::NOT_FOUND, "404 page not found"),
        }
    }

    /// Whether a Host header names our zone: the apex or a name under it, in
    /// any case, with or without a port (or empty, see `serve`).
    fn is_our_host(&self, host: &str) -> bool {
        let host = host_only(host).trim_end_matches('.').to_lowercase();
        let apex = self.cfg.apex();
        host.is_empty() || host == apex || host.strip_suffix(apex).is_some_and(|p| p.ends_with('.'))
    }

    /// Creates a fresh token and redirects the client to <token>.base so that
    /// resolving the new name forces a DNS lookup we can observe. Tokens are
    /// signed, so minting stores nothing.
    fn mint(&self, method: &Method, secure: bool) -> Resp {
        let token = token::mint(&self.cfg, self.clock.now());
        // Always hand out an HTTPS target when TLS is available; insecure
        // requests are upgraded before they ever reach here.
        let scheme = if self.cfg.enable_tls || secure { "https" } else { "http" };
        let mut resp = redirect(method, StatusCode::FOUND, &format!("{scheme}://{token}.{}/", self.cfg.apex()));
        resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }

    /// Returns the captured DNS data for a verified token. A token with no
    /// capture yet reports an empty resolver.
    async fn report(&self, token: &str) -> Resp {
        let c = self.store.get(token).await.unwrap_or_else(|| Capture { token: token.into(), ..Default::default() });

        #[derive(Serialize)]
        struct Ip<'a> {
            ip: &'a str,
        }
        #[derive(Serialize)]
        struct Report<'a> {
            dns: Ip<'a>,
            /// Only present when the resolver forwarded a client subnet.
            #[serde(skip_serializing_if = "Option::is_none")]
            edns: Option<Ip<'a>>,
        }
        let report = Report { dns: Ip { ip: &c.resolver_ip }, edns: c.ecs.split_once('/').map(|(ip, _)| Ip { ip }) };

        // Pretty-printed with a four-space indent and a trailing newline, as
        // the Go version's json.Encoder wrote it.
        let mut body = Vec::new();
        let mut ser =
            serde_json::Serializer::with_formatter(&mut body, serde_json::ser::PrettyFormatter::with_indent(b"    "));
        report.serialize(&mut ser).expect("report serializes");
        body.push(b'\n');

        let mut resp = Response::new(Full::new(Bytes::from(body)));
        let h = resp.headers_mut();
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        resp
    }
}

/// The request's host: the URL authority (HTTP/2 :authority, or an
/// absolute-form HTTP/1 target), else the Host header.
fn request_host<B>(req: &Request<B>) -> String {
    if let Some(a) = req.uri().authority() {
        return a.as_str().to_string();
    }
    req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("").to_string()
}

fn request_uri<B>(req: &Request<B>) -> &str {
    req.uri().path_and_query().map_or("/", |pq| pq.as_str())
}

/// Strips a port, the way Go's net.SplitHostPort does: "host:80" and
/// "[::1]:80" lose it; anything that isn't host:port stays as it is.
fn host_only(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((h, port)) if port.starts_with(':') => h,
            _ => host,
        };
    }
    match host.split_once(':') {
        Some((h, port)) if !port.contains(':') => h,
        _ => host,
    }
}

fn response(status: StatusCode) -> Resp {
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = status;
    resp
}

/// A plain-text error, like Go's http.Error.
fn text_error(status: StatusCode, msg: &str) -> Resp {
    let mut resp = Response::new(Full::new(Bytes::from(format!("{msg}\n"))));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    resp
}

/// A redirect with the small HTML body Go's http.Redirect writes for GET and
/// HEAD, so non-following clients still see where to go.
fn redirect(method: &Method, status: StatusCode, url: &str) -> Resp {
    let mut resp = response(status);
    if method == Method::GET || method == Method::HEAD {
        let reason = status.canonical_reason().unwrap_or("");
        *resp.body_mut() = Full::new(Bytes::from(format!("<a href=\"{}\">{reason}</a>.\n\n", html_escape(url))));
        resp.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    }
    if let Ok(loc) = HeaderValue::from_str(url) {
        resp.headers_mut().insert(header::LOCATION, loc);
    }
    resp
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

fn favicon<B>(req: &Request<B>) -> Resp {
    let modified = *FAVICON_MODIFIED;
    let not_modified = req
        .headers()
        .get(header::IF_MODIFIED_SINCE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| httpdate::parse_http_date(v).ok())
        // HTTP dates have whole seconds, so compare at that precision.
        .is_some_and(|since| crate::clock::unix_secs(modified) <= crate::clock::unix_secs(since));

    let mut resp = if not_modified {
        response(StatusCode::NOT_MODIFIED)
    } else {
        let mut r = Response::new(Full::new(Bytes::from_static(FAVICON)));
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("image/x-icon"));
        r
    };
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=86400"));
    if let Ok(v) = HeaderValue::from_str(&httpdate::fmt_http_date(modified)) {
        h.insert(header::LAST_MODIFIED, v);
    }
    resp
}

/// Accepts connections forever, serving each with HTTP/1.1 or HTTP/2, over
/// TLS when `tls` is set.
pub async fn serve(h: Arc<HttpHandler>, ln: Listener, tls: Option<TlsAcceptor>) -> io::Result<()> {
    loop {
        let conn = ln.accept().await?;
        let (h, tls) = (h.clone(), tls.clone());
        tokio::spawn(async move {
            if let Err(e) = serve_conn(h, conn, tls).await {
                tracing::debug!("http connection: {e:#}");
            }
        });
    }
}

async fn serve_conn(h: Arc<HttpHandler>, conn: Accepted, tls: Option<TlsAcceptor>) -> anyhow::Result<()> {
    let conn = conn.resolve().await?;
    let _permit = conn.permit;
    let mut io = TimeoutStream::new(conn.stream);
    io.set_read_timeout(Some(READ_TIMEOUT));
    io.set_write_timeout(Some(WRITE_TIMEOUT));
    let io = Box::pin(io);
    match tls {
        Some(acceptor) => {
            let stream = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(io)).await??;
            serve_http(h, stream, conn.peer, true).await
        }
        None => serve_http(h, io, conn.peer, false).await,
    }
}

async fn serve_http<S>(h: Arc<HttpHandler>, stream: S, peer: IpAddr, tls: bool) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let svc = service_fn(move |req| {
        let h = h.clone();
        async move { Ok::<_, Infallible>(h.serve(req, peer, tls).await) }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT).max_buf_size(MAX_HEADER_BYTES);
    builder.http2().timer(TokioTimer::new()).max_header_list_size(MAX_HEADER_BYTES as u32);
    builder.serve_connection(TokioIo::new(stream), svc).await.map_err(|e| anyhow::anyhow!(e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::test_config;
    use crate::dns::{DnsHandler, Transport};
    use crate::store::MemStore;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const PEER: &str = "198.51.100.1";

    fn new_store() -> Arc<Store> {
        Arc::new(Store::Memory(MemStore::default()))
    }

    fn ops(store: &Store) -> usize {
        match store {
            Store::Memory(m) => m.ops(),
            Store::Redis(_) => unreachable!(),
        }
    }

    async fn get_with(h: &HttpHandler, method: Method, url: &str, hdrs: &[(&str, &str)], peer: &str) -> (Resp, String) {
        let mut req = Request::builder().method(method).uri(url);
        for (k, v) in hdrs {
            req = req.header(*k, *v);
        }
        let resp = h.serve(req.body(()).unwrap(), peer.parse().unwrap(), false).await;
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (Response::from_parts(parts, Full::new(bytes)), text)
    }

    async fn get(h: &HttpHandler, url: &str) -> (Resp, String) {
        get_with(h, Method::GET, url, &[], PEER).await
    }

    fn hdr<'a>(resp: &'a Resp, name: &str) -> &'a str {
        resp.headers().get(name).map_or("", |v| v.to_str().unwrap())
    }

    #[tokio::test]
    async fn end_to_end_lookup() {
        let (cfg, store) = (Arc::new(test_config()), new_store());
        let h = HttpHandler::new(cfg.clone(), store.clone());
        let dns = DnsHandler::new(cfg.clone(), store);

        // 1. Mint: the apex redirects to a fresh token subdomain.
        let (resp, body) = get(&h, "http://example.test/").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = hdr(&resp, "location").to_string();
        let host = loc.strip_prefix("http://").unwrap().strip_suffix('/').unwrap();
        let token = host.strip_suffix(".example.test").unwrap();
        assert!(token::verify(&cfg, token, SystemTime::now()).is_some(), "redirect to {loc}");
        assert_eq!(body, format!("<a href=\"{loc}\">Found</a>.\n\n"), "Go-style redirect body");
        assert_eq!(hdr(&resp, "cache-control"), "no-store");

        // 2. Capture: the client's resolver looks the token up.
        let mut q = hickory_proto::op::Message::query();
        q.add_query(hickory_proto::op::Query::query(
            hickory_proto::rr::Name::from_ascii(format!("{host}.")).unwrap(),
            hickory_proto::rr::RecordType::A,
        ));
        let mut edns = hickory_proto::op::Edns::new();
        edns.options_mut().insert(hickory_proto::rr::rdata::opt::EdnsOption::Subnet("203.0.113.0/24".parse().unwrap()));
        q.set_edns(edns);
        dns.respond(&q.to_vec().unwrap(), "198.51.100.7".parse().unwrap(), Transport::Udp).await.unwrap();

        // 3. Report: the token host returns what the DNS side recorded.
        let (resp, body) = get(&h, &loc).await;
        assert_eq!(resp.status(), StatusCode::OK, "{body}");
        assert_eq!(
            body,
            "{\n    \"dns\": {\n        \"ip\": \"198.51.100.7\"\n    },\n    \"edns\": {\n        \"ip\": \"203.0.113.0\"\n    }\n}\n"
        );
        assert_eq!(hdr(&resp, "content-type"), "application/json");
        assert_eq!(hdr(&resp, "cache-control"), "no-store");
    }

    #[tokio::test]
    async fn mint_costs_no_store() {
        let store = new_store();
        let h = HttpHandler::new(Arc::new(test_config()), store.clone());
        assert_eq!(get(&h, "http://example.test/").await.0.status(), StatusCode::FOUND);
        assert_eq!(ops(&store), 0, "mint touched the store");
    }

    #[tokio::test]
    async fn report_omits_edns_without_subnet() {
        let store = new_store();
        let tok = token::mint(&test_config(), SystemTime::now());
        let c = Capture {
            token: tok.clone(),
            resolver_ip: "198.51.100.7".into(),
            ecs: "none".into(),
            resolved: true,
            ..Default::default()
        };
        store.record(&tok, &c, SystemTime::now() + Duration::from_secs(3600)).await;
        let h = HttpHandler::new(Arc::new(test_config()), store);
        let (_, body) = get(&h, &format!("http://{tok}.example.test/")).await;
        assert!(!body.contains("edns"), "edns present without a subnet: {body}");
    }

    #[tokio::test]
    async fn report_before_capture() {
        let h = HttpHandler::new(Arc::new(test_config()), new_store());
        let tok = token::mint(&test_config(), SystemTime::now());
        let (resp, body) = get(&h, &format!("http://{tok}.example.test/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body.contains(r#""ip": """#), "want an empty resolver: {body}");
    }

    #[tokio::test]
    async fn report_rejects_forged_expired_and_invalid() {
        let store = new_store();
        let cfg = test_config();
        let h = HttpHandler::new(Arc::new(cfg.clone()), store.clone());
        let mut other = cfg.clone();
        other.token_secret = b"some-other-secret-some-other-secret".to_vec();
        let hosts = [
            format!("{}.example.test", token::mint(&other, SystemTime::now())),
            format!("{}.example.test", token::mint(&cfg, SystemTime::now() - 2 * cfg.ttl)),
            "www.example.test".into(),
            "a.b.example.test".into(),
        ];
        for host in hosts {
            let (resp, _) = get(&h, &format!("http://{host}/")).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{host}");
            assert_eq!(hdr(&resp, "content-type"), "text/plain; charset=utf-8", "{host}");
        }
        assert_eq!(ops(&store), 0, "invalid hosts touched the store");
    }

    #[tokio::test]
    async fn rate_limit() {
        let mut cfg = test_config();
        cfg.http_rate_limit = 1.0;
        cfg.http_rate_burst = 5;
        let h = HttpHandler::new(Arc::new(cfg), new_store());
        let from = |peer: &'static str| {
            let h = &h;
            async move { get_with(h, Method::GET, "http://example.test/", &[], peer).await.0 }
        };
        for i in 0..5 {
            assert_eq!(from("198.51.100.1").await.status(), StatusCode::FOUND, "request {i} within burst");
        }
        let limited = from("198.51.100.1").await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(hdr(&limited, "retry-after"), "5");
        // Limits are per client: a neighbour in the same /24 is unaffected,
        // while IPv6 clients are grouped by /64.
        assert_eq!(from("198.51.100.2").await.status(), StatusCode::FOUND);
        for _ in 0..5 {
            from("2001:db8::1").await;
        }
        assert_eq!(from("2001:db8::2").await.status(), StatusCode::TOO_MANY_REQUESTS, "same /64");
        // Favicons cost nothing and stay available.
        let (fav, _) = get_with(&h, Method::GET, "http://example.test/favicon.ico", &[], "198.51.100.1").await;
        assert_eq!(fav.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn favicon_everywhere_without_store() {
        let store = new_store();
        let h = HttpHandler::new(Arc::new(test_config()), store.clone());
        let tok = token::mint(&test_config(), SystemTime::now());
        for host in ["example.test".to_string(), format!("{tok}.example.test")] {
            let (resp, _) = get(&h, &format!("http://{host}/favicon.ico")).await;
            assert_eq!((resp.status(), hdr(&resp, "content-type")), (StatusCode::OK, "image/x-icon"), "{host}");
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(&body[..], FAVICON, "{host}: body differs from the embedded favicon");
        }
        assert_eq!(ops(&store), 0, "favicon touched the store");

        let (first, _) = get(&h, "http://example.test/favicon.ico").await;
        let lm = hdr(&first, "last-modified").to_string();
        let (again, body) =
            get_with(&h, Method::GET, "http://example.test/favicon.ico", &[("if-modified-since", &lm)], PEER).await;
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn force_https() {
        let mut cfg = test_config();
        cfg.enable_tls = true;
        let h = HttpHandler::new(Arc::new(cfg), new_store());

        let (resp, _) = get_with(&h, Method::GET, "/path?q=1", &[("host", "example.test:80")], PEER).await;
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(hdr(&resp, "location"), "https://example.test/path?q=1");

        let (resp, _) =
            get_with(&h, Method::GET, "/", &[("host", "example.test"), ("x-forwarded-proto", "https")], PEER).await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert!(hdr(&resp, "location").starts_with("https://"));
        assert!(!hdr(&resp, "strict-transport-security").is_empty(), "missing HSTS on a secure response");
    }

    /// Requests for any host outside our zone (the server's IP, the
    /// fly.dev name, other domains) go to the site's apex, over HTTPS when
    /// TLS is on, without a detour via https://<that host>/ (whose
    /// certificate wouldn't match) and without touching the store.
    #[tokio::test]
    async fn foreign_hosts_redirect_to_apex() {
        let store = new_store();
        let mut cfg = test_config();
        cfg.enable_tls = true;
        let h = HttpHandler::new(Arc::new(cfg), store.clone());
        for host in [
            "192.0.2.10",
            "192.0.2.10:80",
            "[2001:db8::10]",
            "[2001:db8::10]:443",
            "edns-upset-dev.fly.dev",
            "example.com",
            "notexample.test",
            "example.test.attacker.example",
        ] {
            let (resp, body) = get_with(&h, Method::GET, "/some/path?q=1", &[("host", host)], PEER).await;
            assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY, "{host}");
            assert_eq!(hdr(&resp, "location"), "https://example.test/", "{host}");
            assert!(body.contains("https://example.test/"), "{host}: {body}");
        }
        assert_eq!(ops(&store), 0);

        // Without TLS the target is plain HTTP.
        let h = HttpHandler::new(Arc::new(test_config()), new_store());
        let (resp, _) = get_with(&h, Method::GET, "/", &[("host", "192.0.2.10")], PEER).await;
        assert_eq!(hdr(&resp, "location"), "http://example.test/");

        // Our own names are untouched, in any case, port or trailing dot.
        let tok = token::mint(&test_config(), SystemTime::now());
        for (host, want) in [
            ("example.test", StatusCode::FOUND),
            ("EXAMPLE.test:8080", StatusCode::FOUND),
            ("example.test.", StatusCode::FOUND),
            (&*format!("{tok}.example.test"), StatusCode::OK),
            ("a.b.example.test", StatusCode::NOT_FOUND),
        ] {
            let (resp, _) = get_with(&h, Method::GET, "/", &[("host", host)], PEER).await;
            assert_eq!(resp.status(), want, "{host}");
        }
    }

    #[tokio::test]
    async fn cors_preflight() {
        let h = HttpHandler::new(Arc::new(test_config()), new_store());
        let tok = token::mint(&test_config(), SystemTime::now());
        let (resp, _) = get_with(&h, Method::OPTIONS, &format!("http://{tok}.example.test/"), &[], PEER).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(hdr(&resp, "access-control-allow-origin"), "*");
    }

    #[test]
    fn host_ports() {
        for (input, want) in [
            ("example.test", "example.test"),
            ("example.test:8080", "example.test"),
            ("[::1]:80", "::1"),
            ("[::1]", "[::1]"),
            ("a:b:c", "a:b:c"),
            ("", ""),
        ] {
            assert_eq!(host_only(input), want, "{input}");
        }
    }

    /// The real server over a socket: HTTP/1.1 keep-alive and a
    /// PROXY-protocol client address.
    #[tokio::test]
    async fn server_over_socket() {
        let mut cfg = test_config();
        cfg.http_rate_limit = 1.0;
        cfg.http_rate_burst = 5;
        let h = Arc::new(HttpHandler::new(Arc::new(cfg), new_store()));
        let ln = Listener::bind("127.0.0.1:0", true, 4).await.unwrap();
        let addr = ln.local_addr().unwrap();
        tokio::spawn(serve(h, ln, None));

        let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
        s.write_all(b"PROXY TCP4 203.0.113.9 192.0.2.1 5555 80\r\n").await.unwrap();
        // Six requests on one connection from 203.0.113.9: the sixth is over
        // its burst of 5, which proves the PROXY address was used.
        let mut statuses = Vec::new();
        for _ in 0..6 {
            s.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n").await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = s.read(&mut buf).await.unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            statuses.push(head.split(' ').nth(1).unwrap().to_string());
        }
        assert_eq!(statuses, ["302", "302", "302", "302", "302", "429"]);
    }
}
