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

// captureMaxWrites caps how many times one token's capture is written to
// Redis. Real lookups produce one or two A queries per token; anything beyond
// a handful is someone replaying a valid token to run up the Redis bill.
const captureMaxWrites = 4

// captureGuardMaxKeys bounds the guard's memory. When full it stops tracking
// new tokens (failing open), since the per-source DNS limit still applies.
const captureGuardMaxKeys = 100000

// captureGuard deduplicates capture writes per token. A nil *captureGuard
// allows every write.
type captureGuard struct {
	mu      sync.Mutex
	entries map[string]*captureEntry
}

type captureEntry struct {
	writes  int
	last    string // fingerprint of the last result written
	expires time.Time
}

func newCaptureGuard() *captureGuard {
	return &captureGuard{entries: map[string]*captureEntry{}}
}

// allow reports whether a capture with the given fingerprint should be
// written for token, which expires at expires.
func (g *captureGuard) allow(token, fingerprint string, expires, now time.Time) bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	e, ok := g.entries[token]
	if !ok {
		if len(g.entries) >= captureGuardMaxKeys {
			for k, e := range g.entries {
				if !now.Before(e.expires) {
					delete(g.entries, k)
				}
			}
			if len(g.entries) >= captureGuardMaxKeys {
				return true
			}
		}
		e = &captureEntry{expires: expires}
		g.entries[token] = e
	}
	if e.last == fingerprint || e.writes >= captureMaxWrites {
		return false
	}
	e.writes++
	e.last = fingerprint
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
