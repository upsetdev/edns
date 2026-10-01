# edns

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
   short-lived token and redirects (`302`) to `https://<token>.edns.upset.dev/`.
2. **Capture.** To follow the redirect, the client resolves
   `<token>.edns.upset.dev`. The name is new, so no cache has it, and the query
   reaches this server. The resolver's source IP and any ECS subnet are recorded
   against the token.
3. **Report.** The request to the token host returns what was recorded as JSON.

Tokens are kept in Redis for one hour. Each step can be handled by any
instance, as long as all instances share the same Redis.

HTTPS uses a wildcard certificate (`<base>` + `*.<base>`), obtained and renewed
automatically by [CertMagic](https://github.com/caddyserver/certmagic) using a
DNS-01 challenge. This process is the zone's authoritative server, so
publishing the challenge only means writing a TXT value to Redis. The DNS
handler then serves it to the ACME validator.

### DNS behaviour

- Answers `SOA`, `NS`, `A` and `AAAA` for the zone. Other types get `NODATA`
  (SOA in the authority section).
- Answers `A`/`AAAA` for its own nameserver hostnames (the `NS` list), even
  when they sit outside the zone.
- Refuses queries for names outside the zone.
- `A` queries for `<token>.<base>` trigger the capture. Names that can't be
  tokens are answered without touching Redis.
- `TXT` queries for `_acme-challenge.<base>` return the current DNS-01 values.

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
```

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
- **Run a single Machine.** Each Machine has its own certificate volume and
  would request its own certificate.
- **TCP hides the source IP.** Fly's proxy handles TCP, so lookups that fall
  back to DNS over TCP record a Fly address. Lookups over UDP, the normal case,
  are unaffected.
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
  -e REDIS_ADDR=<redis host>:6379 \
  -e ACME_EMAIL=you@example.com \
  edns
```

Publish the ports so that the container sees the client's real source address.
A proxy or load balancer that rewrites source IPs (SNAT, or Docker Swarm's
ingress routing mesh, for example) makes every lookup report the proxy's IP.

### Configuration

All configuration is through environment variables.

| Variable       | Default                  | Description |
|----------------|--------------------------|-------------|
| `HTTP_IP`      | **required**             | Public IPv4 returned in `A` answers for the zone. |
| `HTTP_IPV6`    | _(empty)_                | Public IPv6 returned in `AAAA` answers. |
| `BASE_DOMAIN`  | `edns.upset.dev`         | The zone this server is authoritative for. |
| `NS`           | `ns1.<base>,ns2.<base>`  | Comma-separated authoritative nameserver hostnames. |
| `HOSTMASTER`   | `hostmaster.<base>`      | SOA RNAME (contact mailbox, `.` instead of `@`). |
| `DNS_ADDR`     | `:53`                    | DNS listen address (UDP and TCP). |
| `DNS_UDP_ADDR` | `$DNS_ADDR`              | Separate UDP listen address (Fly.io: `fly-global-services:53`). |
| `HTTP_ADDR`    | `:8080`                  | HTTP listen address. |
| `HTTPS_ADDR`   | `:8443`                  | HTTPS listen address. |
| `REDIS_ADDR`   | `redis:6379`             | Redis `host:port`. |
| `REDIS_URL`    | _(empty)_                | `redis://user:pass@host:port`. Overrides `REDIS_ADDR` when set. |
| `TLS`          | `true`                   | Serve HTTPS with CertMagic and redirect plain HTTP to it. |
| `ACME_EMAIL`   | _(empty)_                | Let's Encrypt account contact. |
| `ACME_STAGING` | `false`                  | Use the Let's Encrypt staging CA, for testing. |
| `CERT_DIR`     | `/data`                  | Certificate storage directory. |

The server refuses to start if the configuration is invalid, for example when
`HTTP_IP` is missing or isn't an IPv4 address.

### Redis cost

Each lookup uses about 5 Redis commands: 1 to mint, 2 for each captured `A`
query, and 1 to report. Favicon requests and queries for names that can't be
tokens use none. On Upstash Pay-as-you-go ($0.20 per 100K commands), 10,000
lookups a day come to about $3 a month.

## Development

Requires Go (the version is in [`go.mod`](go.mod)). Tests use an in-memory Redis
([miniredis](https://github.com/alicebob/miniredis)), so they don't need any
external services.

```bash
make test     # unit + end-to-end tests with the race detector
make lint     # gofmt, go vet, staticcheck
make vuln     # govulncheck
make check    # all of the above, as run in CI
```

To run locally without TLS, on unprivileged ports (avoid 5353, which mDNS
usually holds):

```bash
docker run -d -p 6379:6379 redis:8-alpine
go build -o edns .
HTTP_IP=127.0.0.1 BASE_DOMAIN=edns.localhost TLS=false \
  REDIS_ADDR=localhost:6379 DNS_ADDR=:5300 ./edns
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
