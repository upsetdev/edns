package main

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pires/go-proxyproto"
	"golang.org/x/net/netutil"
	"golang.org/x/time/rate"
)

// limiterMaxKeys bounds the memory a limiter can use. A flood from spoofed
// sources could otherwise create a bucket per address; past this many keys,
// new sources share one overflow bucket.
const limiterMaxKeys = 65536

// limiterIdle is how long a bucket can go unused before it is dropped. It must
// be at least burst/rate, so that a dropped bucket would have been full anyway.
const limiterIdle = time.Minute

// limiter is a token-bucket rate limiter per key (a client address prefix).
// A nil *limiter allows everything.
type limiter struct {
	mu        sync.Mutex
	rate      rate.Limit
	burst     int
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// newLimiter allows perSec events per key per second, with bursts of up to
// five seconds' worth. It returns nil (no limit) when perSec <= 0.
func newLimiter(perSec float64) *limiter {
	if perSec <= 0 {
		return nil
	}
	return &limiter{
		rate:    rate.Limit(perSec),
		burst:   max(1, int(5*perSec)),
		buckets: map[string]*bucket{},
	}
}

func (l *limiter) allow(key string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.Sub(l.lastSweep) > limiterIdle {
		for k, b := range l.buckets {
			if now.Sub(b.seen) > limiterIdle {
				delete(l.buckets, k)
			}
		}
		l.lastSweep = now
	}
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= limiterMaxKeys {
			key = "overflow"
			b, ok = l.buckets[key]
		}
		if !ok {
			b = &bucket{lim: rate.NewLimiter(l.rate, l.burst)}
			l.buckets[key] = b
		}
	}
	b.seen = now
	return b.lim.AllowN(now, 1)
}

// prefixKey reduces an address to the network a single client (or resolver
// farm) plausibly controls, so that one source can't dodge the limit by
// rotating through adjacent addresses. Unparseable input is its own key.
func prefixKey(addr string, v4Bits, v6Bits int) string {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return addr
	}
	ip = ip.Unmap()
	bits := v6Bits
	if ip.Is4() {
		bits = v4Bits
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return addr
	}
	return p.String()
}

// captureGuardMaxKeys bounds the guard's memory. When full it stops tracking
// new tokens (failing open): the store still keeps only the first capture,
// and the per-source DNS limit still applies.
const captureGuardMaxKeys = 100000

// captureGuard remembers which tokens have already been captured, so repeat
// lookups (resolver retries, prefetch, someone replaying a valid token to run
// up the Redis bill) are dropped without a Redis command. A nil *captureGuard
// allows every capture.
type captureGuard struct {
	mu   sync.Mutex
	seen map[string]time.Time // token -> expiry
}

func newCaptureGuard() *captureGuard {
	return &captureGuard{seen: map[string]time.Time{}}
}

// first reports whether this is the first capture of token, which expires at
// expires, and marks it as captured.
func (g *captureGuard) first(token string, expires, now time.Time) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.seen[token]; ok {
		return false
	}
	if len(g.seen) >= captureGuardMaxKeys {
		for k, exp := range g.seen {
			if !now.Before(exp) {
				delete(g.seen, k)
			}
		}
		if len(g.seen) >= captureGuardMaxKeys {
			return true
		}
	}
	g.seen[token] = expires
	return true
}

// listen opens a TCP listener that accepts at most maxConns connections at
// once and, when proxy is set, requires a PROXY protocol header so that
// RemoteAddr is the real client rather than the load balancer (Fly.io).
func listen(addr string, proxy bool, maxConns int) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	ln = netutil.LimitListener(ln, maxConns)
	if proxy {
		ln = &proxyproto.Listener{
			Listener:          ln,
			ReadHeaderTimeout: 5 * time.Second,
			ConnPolicy: func(proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
				return proxyproto.REQUIRE, nil
			},
		}
	}
	return ln, nil
}
