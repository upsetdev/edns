//! TCP listeners: connection caps, the PROXY protocol, and Go-style
//! listen addresses.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// How long a client gets to send its PROXY header.
const PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(5);

/// Binds like Go's `net.Listen`: a bare ":port" means every interface, as one
/// dual-stack socket with `IPV6_V6ONLY` cleared explicitly (so IPv4 clients
/// still arrive whatever the kernel default is), falling back to IPv4 where
/// IPv6 is unavailable. Anything else is resolved and bound as given.
async fn bind_socket(addr: &str, ty: socket2::Type) -> io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket};

    let proto = if ty == socket2::Type::STREAM { Protocol::TCP } else { Protocol::UDP };
    let open = |domain: Domain, addr: SocketAddr, dual: bool| -> io::Result<Socket> {
        let s = Socket::new(domain, ty, Some(proto))?;
        if dual {
            s.set_only_v6(false)?;
        }
        if ty == socket2::Type::STREAM {
            s.set_reuse_address(true)?;
        }
        s.set_nonblocking(true)?;
        s.bind(&addr.into())?;
        Ok(s)
    };

    if let Some(port) = addr.strip_prefix(':') {
        let port: u16 = port.parse().map_err(|_| io::Error::other(format!("bad port in {addr:?}")))?;
        return open(Domain::IPV6, (std::net::Ipv6Addr::UNSPECIFIED, port).into(), true)
            .or_else(|_| open(Domain::IPV4, (std::net::Ipv4Addr::UNSPECIFIED, port).into(), false));
    }
    let mut last = None;
    for a in tokio::net::lookup_host(addr).await? {
        match open(Domain::for_address(a), a, false) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other(format!("{addr:?} resolved to nothing"))))
}

pub async fn bind_udp(addr: &str) -> io::Result<UdpSocket> {
    let s = bind_socket(addr, socket2::Type::DGRAM).await?;
    UdpSocket::from_std(s.into())
}

/// A TCP listener that accepts at most `max_conns` connections at once and,
/// when `proxy` is set, requires a PROXY protocol header so that the peer
/// address is the real client rather than the load balancer (Fly.io).
pub struct Listener {
    inner: TcpListener,
    proxy: bool,
    permits: Arc<Semaphore>,
}

/// An accepted connection whose PROXY header (if required) is still unread.
/// Reading it happens in the connection's own task, via [`Accepted::resolve`],
/// so a slow client can't stall the accept loop.
pub struct Accepted {
    stream: TcpStream,
    peer: SocketAddr,
    proxy: bool,
    permit: OwnedSemaphorePermit,
}

/// A connection ready to serve, with the client's real address.
pub struct Conn {
    pub stream: TcpStream,
    pub peer: IpAddr,
    /// Holds this connection's slot until dropped.
    pub permit: OwnedSemaphorePermit,
}

impl Listener {
    pub async fn bind(addr: &str, proxy: bool, max_conns: usize) -> io::Result<Self> {
        let s = bind_socket(addr, socket2::Type::STREAM).await?;
        s.listen(1024)?;
        let inner = TcpListener::from_std(s.into())?;
        Ok(Listener { inner, proxy, permits: Arc::new(Semaphore::new(max_conns)) })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Waits for a free slot, then for a connection; at the cap, new
    /// connections queue in the kernel backlog instead of using memory.
    pub async fn accept(&self) -> io::Result<Accepted> {
        let permit = self.permits.clone().acquire_owned().await.expect("semaphore never closed");
        loop {
            match self.inner.accept().await {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(Accepted { stream, peer, proxy: self.proxy, permit });
                }
                // Per-connection failures (e.g. reset before accept) aren't
                // fatal to the listener.
                Err(e) if is_transient(&e) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

fn is_transient(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset | io::ErrorKind::Interrupted)
        || e.raw_os_error() == Some(24) // EMFILE: back off by retrying the next accept
}

impl Accepted {
    /// Finds the client's IP: from the PROXY header when required, else the
    /// socket peer. A connection without a valid header is an error, so it is
    /// dropped rather than trusted.
    pub async fn resolve(mut self) -> io::Result<Conn> {
        let mut src = self.peer;
        if self.proxy {
            let header = tokio::time::timeout(PROXY_HEADER_TIMEOUT, read_proxy_header(&mut self.stream))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "PROXY header timeout"))??;
            src = header.unwrap_or(self.peer);
        }
        Ok(Conn { stream: self.stream, peer: src.ip().to_canonical(), permit: self.permit })
    }
}

/// The 12-byte signature that starts a PROXY protocol v2 header.
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
/// The longest v1 header line allowed by the spec, CRLF included.
const V1_MAX_LEN: usize = 107;

/// Reads a PROXY protocol v1 or v2 header from `r`, consuming exactly the
/// header so the payload that follows is untouched. Returns the source
/// address it carries, or `None` for headers without one (v1 UNKNOWN, v2
/// LOCAL, or non-IP families), where the socket peer should be used.
pub async fn read_proxy_header<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<SocketAddr>> {
    let invalid = |msg: &str| io::Error::new(io::ErrorKind::InvalidData, format!("PROXY header: {msg}"));

    // Every valid header is at least 12 bytes long ("PROXY UNKNOWN\r\n" is
    // 15), so this never reads past a v1 line.
    let mut start = [0u8; 12];
    r.read_exact(&mut start).await?;

    if &start == V2_SIGNATURE {
        let mut hdr = [0u8; 4];
        r.read_exact(&mut hdr).await?;
        let (ver_cmd, family, len) = (hdr[0], hdr[1], u16::from_be_bytes([hdr[2], hdr[3]]) as usize);
        if ver_cmd >> 4 != 2 {
            return Err(invalid("unsupported version"));
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).await?;
        if ver_cmd & 0x0f == 0 {
            return Ok(None); // LOCAL: health checks from the proxy itself
        }
        if ver_cmd & 0x0f != 1 {
            return Err(invalid("unknown command"));
        }
        return match family >> 4 {
            1 if body.len() >= 12 => {
                let ip: [u8; 4] = body[0..4].try_into().unwrap();
                let port = u16::from_be_bytes([body[8], body[9]]);
                Ok(Some(SocketAddr::from((ip, port))))
            }
            2 if body.len() >= 36 => {
                let ip: [u8; 16] = body[0..16].try_into().unwrap();
                let port = u16::from_be_bytes([body[32], body[33]]);
                Ok(Some(SocketAddr::from((ip, port))))
            }
            1 | 2 => Err(invalid("short address block")),
            _ => Ok(None), // AF_UNSPEC or AF_UNIX
        };
    }

    if !start.starts_with(b"PROXY ") {
        return Err(invalid("missing"));
    }
    // v1: read the rest of the line a byte at a time, so nothing past the
    // CRLF is consumed.
    let mut line = start.to_vec();
    while !line.ends_with(b"\r\n") {
        if line.len() >= V1_MAX_LEN {
            return Err(invalid("v1 line too long"));
        }
        line.push(r.read_u8().await?);
    }
    let line = std::str::from_utf8(&line[..line.len() - 2]).map_err(|_| invalid("not ASCII"))?;
    let fields: Vec<&str> = line.split(' ').collect();
    match fields.as_slice() {
        ["PROXY", "UNKNOWN", ..] => Ok(None),
        ["PROXY", "TCP4" | "TCP6", src, _dst, sport, _dport] => {
            let ip: IpAddr = src.parse().map_err(|_| invalid("bad source address"))?;
            let port: u16 = sport.parse().map_err(|_| invalid("bad source port"))?;
            Ok(Some(SocketAddr::new(ip, port)))
        }
        _ => Err(invalid("malformed v1 line")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn parse(input: &[u8]) -> (io::Result<Option<SocketAddr>>, Vec<u8>) {
        let mut r = input;
        let res = read_proxy_header(&mut r).await;
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).await.unwrap();
        (res, rest)
    }

    #[tokio::test]
    async fn v1() {
        let (res, rest) = parse(b"PROXY TCP4 203.0.113.9 192.0.2.1 5555 443\r\nhello").await;
        assert_eq!(res.unwrap(), Some("203.0.113.9:5555".parse().unwrap()));
        assert_eq!(rest, b"hello", "payload after the header must be untouched");

        let (res, _) = parse(b"PROXY TCP6 2001:db8::9 2001:db8::1 5555 443\r\n").await;
        assert_eq!(res.unwrap(), Some("[2001:db8::9]:5555".parse().unwrap()));

        let (res, rest) = parse(b"PROXY UNKNOWN\r\nx").await;
        assert_eq!(res.unwrap(), None);
        assert_eq!(rest, b"x");
    }

    #[tokio::test]
    async fn v2() {
        let mut msg = V2_SIGNATURE.to_vec();
        msg.extend([0x21, 0x11, 0, 12]); // v2 PROXY, TCP over IPv4, 12 bytes
        msg.extend([203, 0, 113, 9, 192, 0, 2, 1]);
        msg.extend(5555u16.to_be_bytes());
        msg.extend(443u16.to_be_bytes());
        msg.extend(b"hello");
        let (res, rest) = parse(&msg).await;
        assert_eq!(res.unwrap(), Some("203.0.113.9:5555".parse().unwrap()));
        assert_eq!(rest, b"hello");

        let mut local = V2_SIGNATURE.to_vec();
        local.extend([0x20, 0x00, 0, 0]); // LOCAL
        assert_eq!(parse(&local).await.0.unwrap(), None);
    }

    #[tokio::test]
    async fn rejects_garbage() {
        for input in
            [&b"GET / HTTP/1.1\r\n\r\n"[..], b"PROXY TCP4 nope\r\n", b"PROXY TCP4 1.2.3.4 5.6.7.8 x 1\r\n", b"short"]
        {
            assert!(parse(input).await.0.is_err(), "{:?} accepted", String::from_utf8_lossy(input));
        }
        let mut long = b"PROXY ".to_vec();
        long.extend([b'a'; 200]);
        assert!(parse(&long).await.0.is_err(), "unterminated v1 line accepted");
    }

    /// With PROXY protocol on, the resolved peer is the client named in the
    /// header, and connections without one are rejected rather than trusted.
    #[tokio::test]
    async fn listener_requires_header() {
        let ln = Listener::bind("127.0.0.1:0", true, 4).await.unwrap();
        let addr = ln.local_addr().unwrap();

        let mut c = TcpStream::connect(addr).await.unwrap();
        c.write_all(b"PROXY TCP4 203.0.113.9 192.0.2.1 5555 443\r\nhello\n").await.unwrap();
        let mut a = ln.accept().await.unwrap().resolve().await.unwrap();
        assert_eq!(a.peer, "203.0.113.9".parse::<IpAddr>().unwrap());
        let mut buf = [0u8; 6];
        a.stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello\n");

        let mut c2 = TcpStream::connect(addr).await.unwrap();
        c2.write_all(b"hello, no header\n").await.unwrap();
        let a2 = ln.accept().await.unwrap();
        assert!(a2.resolve().await.is_err(), "connection without a header was trusted");
    }

    #[tokio::test]
    async fn listener_without_proxy_uses_peer() {
        let ln = Listener::bind("127.0.0.1:0", false, 4).await.unwrap();
        let _c = TcpStream::connect(ln.local_addr().unwrap()).await.unwrap();
        let a = ln.accept().await.unwrap().resolve().await.unwrap();
        assert_eq!(a.peer, "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn listener_caps_connections() {
        let ln = Listener::bind("127.0.0.1:0", false, 1).await.unwrap();
        let addr = ln.local_addr().unwrap();
        let _c1 = TcpStream::connect(addr).await.unwrap();
        let _c2 = TcpStream::connect(addr).await.unwrap();
        let first = ln.accept().await.unwrap();
        // The second connection waits in the backlog until the first's slot
        // is released.
        assert!(tokio::time::timeout(Duration::from_millis(100), ln.accept()).await.is_err());
        drop(first);
        assert!(tokio::time::timeout(Duration::from_secs(1), ln.accept()).await.is_ok());
    }

    /// ":port" binds one socket that accepts both IPv4 and IPv6 clients, and
    /// IPv4 peers come out as plain IPv4 rather than ::ffff:a.b.c.d.
    #[tokio::test]
    async fn go_style_address_is_dual_stack() {
        let ln = Listener::bind(":0", false, 4).await.unwrap();
        let port = ln.local_addr().unwrap().port();
        let _c = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let a = ln.accept().await.unwrap().resolve().await.unwrap();
        assert_eq!(a.peer, "127.0.0.1".parse::<IpAddr>().unwrap());
        if let Ok(_c6) = TcpStream::connect(("::1", port)).await {
            let a = ln.accept().await.unwrap().resolve().await.unwrap();
            assert_eq!(a.peer, "::1".parse::<IpAddr>().unwrap());
        }
    }
}
