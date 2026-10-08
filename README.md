# edns.upset.dev

[![CI](https://github.com/upsetdev/edns/actions/workflows/ci.yml/badge.svg)](https://github.com/upsetdev/edns/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A tiny authoritative DNS server + HTTP service that tells you **which recursive
resolver** your device actually uses, and whether that resolver forwards an
**EDNS Client Subnet (ECS)** option to authoritative servers.

Try it: **[edns.upset.dev](https://edns.upset.dev)**, or from a terminal:

```console
$ curl -sL https://edns.upset.dev/
{
    "dns": {
        "ip": "172.253.211.5"
    },
    "edns": {
        "ip": "203.0.113.0"
    }
}
```

- `dns.ip`: the recursive resolver that queried the authoritative server.
- `edns.ip`: the client subnet the resolver forwarded. Present only when the
  resolver sends ECS.

Useful for debugging DNS-based geo routing and CDN steering, checking which
resolver a VPN, DoH setting, or ISP is really using, and checking whether
a resolver leaks client subnets.

## How it works

The service is authoritative for its own zone and serves HTTP(S) on the same
host. A lookup takes three steps:

1. **Mint.** A request to the apex (`https://edns.upset.dev/`) creates a random,
   short-lived, signed token and redirects (`302`) to
   `https://<token>.edns.upset.dev/`.
2. **Capture.** To follow the redirect, the client resolves
   `<token>.edns.upset.dev`. The name is new, so no cache has it, and the query
   reaches this server. The resolver's source IP and any ECS subnet are recorded
   against the token. Only the first lookup counts: later ones (another tool or
   device opening the same link, resolver prefetch) would name a different
   resolver.
3. **Report.** The request to the token host returns what was recorded as JSON.

A token carries its own expiry and an HMAC, so the server can check it
without storing anything: minting writes nothing, and forged or expired tokens
are rejected before they reach the store. Only captures are stored, for the
rest of the token's one-hour life. The store is in memory by default. With
Redis, any instance can handle any step, as long as all instances share the
same Redis and `TOKEN_SECRET`.

HTTPS uses one Let's Encrypt certificate for `<base>` and `*.<base>`, obtained
and renewed automatically (when a third of its lifetime is left) using a
DNS-01 challenge, and stored on disk or, for several instances, in Redis. This
process is the zone's authoritative server, so publishing the challenge only
means writing a TXT value to the store. The DNS handler then serves it to the
ACME validator.

### DNS behaviour

- Answers `SOA`, `NS`, `A` and `AAAA` for the zone. Other types get `NODATA`
  (SOA in the authority section).
- Answers `A`/`AAAA` for its own nameserver hostnames (the `NS` list), even
  when they sit outside the zone.
- Refuses queries for names outside the zone.
- Answers `ANY` with a single `HINFO` record
  ([RFC 8482](https://www.rfc-editor.org/rfc/rfc8482)).
- `A` queries for `<token>.<base>` trigger the capture. Names that aren't
  valid, unexpired tokens are answered without touching the store.
- `TXT` queries for `_acme-challenge.<base>` return the current DNS-01 values.

### Abuse protection

- **Signed tokens.** Random-subdomain floods and forged or expired tokens are
  rejected in memory, so they cost no Redis commands. Only a token's first
  capture is written; later lookups of it are dropped without touching Redis.
- **DNS rate limiting**, per source `/24` (IPv4) or `/56` (IPv6), with UDP and
  TCP limited separately. Over the UDP limit the reply is an empty truncated
  answer (`TC`), no bigger than the query, so it's useless for reflection. A
  real resolver retries over TCP, which a spoofed source can't complete. Over
  the TCP limit the reply is `REFUSED`.
- **HTTP rate limiting** per client IPv4 address or IPv6 `/64` (`429` with
  `Retry-After`). Favicon requests aren't limited.
- **Connection limits and timeouts** on every TCP listener, so slow or idle
  clients can't exhaust the machine.

Rate limits need the real client address. Behind a TCP proxy, enable the PROXY
protocol on the proxy and set `PROXY_PROTOCOL=true` (the Fly.io setup does
this).

## Production deployment

[edns.upset.dev](https://edns.upset.dev) runs on **[Fly.io](https://fly.io)**:
a single Machine in Singapore (`sin`), with
[Upstash Redis](https://fly.io/docs/upstash/redis/) as the token store. Every
push to `main` that passes CI is deployed automatically with `fly deploy`
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)); the configuration is
in [`fly.toml`](fly.toml).

## Self-hosting

You need a domain where you can delegate a subdomain (for example
`edns.example.com`) to nameservers you control, and a host with a public IPv4
address that can receive UDP and TCP on port 53.

### 1. Delegate the zone

In the parent zone (`example.com`), add:

```dns
edns.example.com.       NS  ns1.edns.example.com.
edns.example.com.       NS  ns2.edns.example.com.
ns1.edns.example.com.   A   <your public IPv4>
ns2.edns.example.com.   A   <your public IPv4>
```

If your DNS provider proxies traffic (for example Cloudflare's orange cloud),
turn it off for these records.

### 2a. Deploy on Fly.io

```bash
fly apps create <app>
fly ips allocate-v4 -a <app>            # dedicated IPv4: Fly only routes UDP on one
fly ips allocate-v6 -a <app>
fly volumes create edns_certs -a <app> -r <region> -s 1
fly redis create --name <app>-redis --region <region> --plan Pay-as-you-go --no-replicas
fly secrets set -a <app> REDIS_URL='redis://default:...@fly-<app>-redis.upstash.io:6379'
fly secrets set -a <app> TOKEN_SECRET=$(openssl rand -hex 32)   # optional on one Machine
```

Redis is optional on a single Machine: drop the `fly redis create` and
`REDIS_URL` steps and set `STORE = "memory"` in `fly.toml`.

Copy `fly.toml`, then set `app`, `primary_region`, `BASE_DOMAIN`, `NS`, `HTTP_IP`
and `HTTP_IPV6` to your values, and deploy:

```bash
fly deploy --ha=false
```

Fly.io details to know:

- **UDP must bind `fly-global-services:53`.** Fly doesn't rewrite UDP
  destination ports, and replies have to leave from that address. `fly.toml`
  handles this with `DNS_UDP_ADDR`. The image grants `CAP_NET_BIND_SERVICE` so
  the non-root process can bind port 53.
- **Run a single Machine, or share certificates.** With the default
  `CERT_STORE=file`, each Machine has its own certificate volume and would
  request its own certificate. To run several, set `STORE=redis`,
  `CERT_STORE=redis` and a shared `TOKEN_SECRET`, and drop the volume. They
  then share one certificate, and a lock in Redis makes sure only one Machine
  orders or renews it. Certificates are served from memory, so this adds no
  Redis commands per TLS handshake.
- **TCP uses the PROXY protocol.** Fly's TCP proxy hides the client address,
  so the TCP services enable Fly's `proxy_proto` handler and the app requires
  the header (`PROXY_PROTOCOL=true`). Change both together.
- **Keep the Machine running.** Incoming UDP doesn't wake a stopped Machine,
  so `fly.toml` disables auto-stop.

### 2b. Deploy anywhere else (Docker)

```bash
docker build -t edns .
docker run -d --name edns \
  -p 53:53/udp -p 53:53/tcp -p 80:8080 -p 443:8443 \
  -v edns-certs:/data \
  -e BASE_DOMAIN=edns.example.com \
  -e HTTP_IP=<your public IPv4> \
  -e ACME_EMAIL=you@example.com \
  edns
```

This keeps state in memory. To run several instances, give them the same
`TOKEN_SECRET` and a shared Redis (`-e STORE=redis -e REDIS_ADDR=<host>:6379`).

Publish the ports so that the container sees the client's real source address.
A proxy or load balancer that rewrites source IPs (SNAT, or Docker Swarm's
ingress routing mesh, for example) makes every lookup report the proxy's IP.

### Configuration

All configuration is through environment variables.

| Variable          | Default                 | Description                                                                           |
| ----------------- | ----------------------- | ------------------------------------------------------------------------------------- |
| `HTTP_IP`         | **required**            | Public IPv4 returned in `A` answers for the zone.                                     |
| `HTTP_IPV6`       | _(empty)_               | Public IPv6 returned in `AAAA` answers.                                               |
| `BASE_DOMAIN`     | `edns.upset.dev`        | The zone this server is authoritative for.                                            |
| `NS`              | `ns1.<base>,ns2.<base>` | Comma-separated authoritative nameserver hostnames.                                   |
| `HOSTMASTER`      | `hostmaster.<base>`     | SOA RNAME (contact mailbox, `.` instead of `@`).                                      |
| `DNS_ADDR`        | `:53`                   | DNS listen address (UDP and TCP).                                                     |
| `DNS_UDP_ADDR`    | `$DNS_ADDR`             | Separate UDP listen address (Fly.io: `fly-global-services:53`).                       |
| `HTTP_ADDR`       | `:8080`                 | HTTP listen address.                                                                  |
| `HTTPS_ADDR`      | `:8443`                 | HTTPS listen address.                                                                 |
| `STORE`           | `memory`                | `memory` (single instance) or `redis` (shared between instances).                     |
| `REDIS_ADDR`      | `redis:6379`            | Redis `host:port`, with `STORE=redis`.                                                |
| `REDIS_URL`       | _(empty)_               | `redis://user:pass@host:port`. Overrides `REDIS_ADDR` when set.                       |
| `TOKEN_SECRET`    | _(random per process)_  | HMAC key for tokens, at least 32 characters. Must match across instances.             |
| `DNS_RATE_LIMIT`  | `20`                    | DNS queries per second per source `/24` or `/56`, bursting to 5×. `0` disables.       |
| `HTTP_RATE_LIMIT` | `2`                     | HTTP requests per second per client IPv4 or IPv6 `/64`, bursting to 5×. `0` disables. |
| `PROXY_PROTOCOL`  | `false`                 | Require a PROXY protocol header on TCP listeners (DNS, HTTP, HTTPS).                  |
| `TLS`             | `true`                  | Serve HTTPS with a Let's Encrypt certificate and redirect plain HTTP to it.           |
| `ACME_EMAIL`      | _(empty)_               | Let's Encrypt account contact.                                                        |
| `ACME_STAGING`    | `false`                 | Use the Let's Encrypt staging CA, for testing.                                        |
| `CERT_STORE`      | `file`                  | `file` (`CERT_DIR`) or `redis` (shared by instances; requires `STORE=redis`).         |
| `CERT_DIR`        | `/data`                 | Certificate storage directory, with `CERT_STORE=file`.                                |

The server refuses to start if the configuration is invalid, for example when
`HTTP_IP` is missing or isn't an IPv4 address.

### Redis cost

With `STORE=redis`, each lookup uses about 2 Redis commands: 1 to record the
capture and 1 to report. Minting, favicon requests, repeat lookups of a
captured token, and queries for invalid or expired tokens use none. On Upstash Pay-as-you-go ($0.20 per 100K commands),
10,000 lookups a day come to about $1.20 a month. Set a spending cap on the
database as well, so a sustained flood can't run up the bill.

## Development

Requires Rust (the version is pinned in
[`rust-toolchain.toml`](rust-toolchain.toml); rustup installs it on first use).
The tests need no external services. The Redis-backed tests run as well when
`EDNS_TEST_REDIS_URL` points at a Redis; `make test-redis` starts a throwaway
one in Docker.

```bash
make test        # unit + end-to-end tests
make test-redis  # the same, plus the Redis backend (needs Docker)
make lint        # rustfmt, clippy
make vuln        # cargo audit
make check       # lint, test and vuln, as run in CI (CI also runs Redis)
```

The code, in `src/`:

| Module         | What it does |
| -------------- | ------------ |
| `main.rs`      | Startup: binds the listeners and runs the servers. |
| `config.rs`    | Environment variables, validated. |
| `token.rs`     | Signed, self-expiring tokens. |
| `dns.rs`       | The authoritative DNS server and token capture. |
| `http.rs`      | Mint, report, favicon, HTTPS redirect, CORS. |
| `limit.rs`     | Per-source rate limits and the per-token capture guard. |
| `net.rs`       | TCP/UDP listeners: connection caps, PROXY protocol. |
| `store.rs`     | Captures and ACME challenge records, in memory (`store/memory.rs`) or Redis (`store/redis.rs`). |
| `tls.rs`       | The ACME client and certificate renewal loop. |
| `certstore.rs` | Certificate storage (files or Redis) and the distributed lock. |
| `clock.rs`     | A clock tests can freeze and advance. |

To run locally without TLS, on unprivileged ports (avoid 5353, which mDNS
usually holds):

```bash
cargo build --release
HTTP_IP=127.0.0.1 BASE_DOMAIN=edns.localhost TLS=false DNS_ADDR=:5300 ./target/release/edns
```

Your system resolver never queries this server for `*.localhost`, so do the
three steps by hand:

```bash
curl -si http://edns.localhost:8080/ | grep -i location     # 1. mint
dig @127.0.0.1 -p 5300 +subnet=203.0.113.0/24 <token>.edns.localhost   # 2. capture
curl -s http://<token>.edns.localhost:8080/                  # 3. report
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). To report a
security issue, follow [SECURITY.md](SECURITY.md) instead of opening a public
issue.

## License

[MIT](LICENSE)
