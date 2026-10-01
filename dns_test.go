package main

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSAnswersZoneRecords(t *testing.T) {
	store, _ := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store}

	tests := []struct {
		name  string
		qtype uint16
		want  string // expected first answer, "" for NODATA
	}{
		{"example.test", dns.TypeA, "192.0.2.10"},
		{"example.test", dns.TypeAAAA, "2001:db8::10"},
		{"example.test", dns.TypeNS, "ns1.example.test."},
		{"example.test", dns.TypeSOA, "ns1.example.test."},
		{"example.test", dns.TypeMX, ""},
		{"ns2.example.test", dns.TypeA, "192.0.2.10"},
		{"anything.example.test", dns.TypeA, "192.0.2.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name+"/"+dns.TypeToString[tt.qtype], func(t *testing.T) {
			m := query(t, h, tt.name, tt.qtype, "198.51.100.1", "")
			if m.Rcode != dns.RcodeSuccess || !m.Authoritative {
				t.Fatalf("rcode=%s aa=%v, want authoritative NOERROR", dns.RcodeToString[m.Rcode], m.Authoritative)
			}
			if tt.want == "" {
				if len(m.Answer) != 0 || len(m.Ns) == 0 {
					t.Fatalf("want NODATA with SOA in authority, got %v / %v", m.Answer, m.Ns)
				}
				return
			}
			if len(m.Answer) == 0 {
				t.Fatalf("no answer")
			}
			var got string
			switch rr := m.Answer[0].(type) {
			case *dns.A:
				got = rr.A.String()
			case *dns.AAAA:
				got = rr.AAAA.String()
			case *dns.NS:
				got = rr.Ns
			case *dns.SOA:
				got = rr.Ns
			}
			if got != tt.want {
				t.Fatalf("answer = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDNSRefusesOutOfZone(t *testing.T) {
	store, _ := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store}

	m := query(t, h, "example.com", dns.TypeA, "198.51.100.1", "")
	if m.Rcode != dns.RcodeRefused {
		t.Fatalf("rcode = %s, want REFUSED", dns.RcodeToString[m.Rcode])
	}
}

func TestDNSCapturesResolverAndECS(t *testing.T) {
	tests := []struct {
		name, ecs, wantECS, wantFamily string
	}{
		{"no ecs", "", "none", "none"},
		{"ipv4 ecs", "203.0.113.0/24", "203.0.113.0/24", "ipv4"},
		{"ipv6 ecs", "2001:db8:1::/56", "2001:db8:1::/56", "ipv6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _ := newTestStore(t)
			h := &dnsHandler{cfg: testConfig(), store: store}
			tok := newToken()

			query(t, h, tok+".example.test", dns.TypeA, "198.51.100.7", tt.ecs)

			res, ok := store.Get(tok)
			if !ok {
				t.Fatal("token vanished")
			}
			if !res.Resolved || res.ResolverIP != "198.51.100.7" {
				t.Errorf("resolved=%v resolver=%q", res.Resolved, res.ResolverIP)
			}
			if res.ECS != tt.wantECS || res.ECSFamily != tt.wantFamily {
				t.Errorf("ecs=%q/%q, want %q/%q", res.ECS, res.ECSFamily, tt.wantECS, tt.wantFamily)
			}
		})
	}
}

func TestDNSCaptureIgnoresForgedExpiredAndJunk(t *testing.T) {
	store, mr := newTestStore(t)
	cfg := testConfig()
	h := &dnsHandler{cfg: cfg, store: store}

	other := cfg
	other.TokenSecret = []byte("some-other-secret-some-other-secret")
	expired := mintToken(cfg, time.Now().Add(-2*cfg.TTL))
	forged := mintToken(other, time.Now())

	// None of these may cost a Redis command: forged and expired tokens fail
	// the MAC/expiry check in memory, and junk labels can't be tokens at all.
	for _, name := range []string{
		forged + ".example.test", expired + ".example.test",
		"www.example.test", "a.b.example.test", "0123456789abcdef.example.test",
	} {
		query(t, h, name, dns.TypeA, "198.51.100.1", "")
	}
	if n := mr.CommandCount(); n != 0 {
		t.Errorf("invalid lookups ran %d Redis commands, want 0", n)
	}
}

func TestDNSCaptureIsCaseInsensitive(t *testing.T) {
	// Resolvers randomize query case (DNS 0x20), so the token must still match.
	store, _ := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store}
	tok := newToken()

	query(t, h, strings.ToUpper(tok)+".Example.TEST", dns.TypeA, "198.51.100.7", "")
	if res, _ := store.Get(tok); res == nil || !res.Resolved {
		t.Fatal("mixed-case lookup was not captured")
	}
}

// TestDNSKeepsFirstCapture: the first lookup is the client following the
// redirect; later lookups of the same token (another tool or device, resolver
// prefetch) must not replace it. Checked on both backends, since Redis relies
// on the guard plus SET NX and memory on Record alone.
func TestDNSKeepsFirstCapture(t *testing.T) {
	redisStore, _ := newTestStore(t)
	memCfg := testConfig()
	memCfg.Store = "memory"
	for name, h := range map[string]*dnsHandler{
		"redis":  newDNSHandler(testConfig(), redisStore),
		"memory": newDNSHandler(memCfg, newMemStore()),
	} {
		t.Run(name, func(t *testing.T) {
			h.udpLimit = nil
			tok := newToken()
			query(t, h, tok+".example.test", dns.TypeA, "172.253.236.213", "203.0.113.0/24")
			query(t, h, tok+".example.test", dns.TypeA, "185.40.106.78", "")

			res, ok := h.store.Get(tok)
			if !ok || res.ResolverIP != "172.253.236.213" || res.ECS != "203.0.113.0/24" {
				t.Fatalf("capture = %+v, want the first resolver and its ECS", res)
			}
		})
	}
}

func TestDNSRepeatCapturesCostNoRedis(t *testing.T) {
	store, mr := newTestStore(t)
	h := newDNSHandler(testConfig(), store)
	h.udpLimit = nil
	tok := newToken()

	// The first capture is one SET (plus go-redis's connection handshake,
	// hence the baseline). Every later lookup of the token is free.
	query(t, h, tok+".example.test", dns.TypeA, "198.51.100.7", "")
	base := mr.CommandCount()
	for i := range 10 {
		query(t, h, tok+".example.test", dns.TypeA, "198.51.100."+strconv.Itoa(10+i), "")
	}
	if n := mr.CommandCount() - base; n != 0 {
		t.Fatalf("repeat captures ran %d Redis commands, want 0", n)
	}
}

func TestDNSMemoryStoreHasNoCaptureGuard(t *testing.T) {
	cfg := testConfig()
	cfg.Store = "memory"
	if h := newDNSHandler(cfg, newMemStore()); h.guard != nil {
		t.Error("memory store should not need a capture guard")
	}
}

func TestDNSRateLimit(t *testing.T) {
	store, mr := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store, udpLimit: newLimiter(1), tcpLimit: newLimiter(1)} // burst 5
	now := time.Now()
	h.now = func() time.Time { return now }
	tok := newToken()

	for i := range 5 {
		if m := query(t, h, "example.test", dns.TypeA, "198.51.100."+strconv.Itoa(i), ""); m.Truncated || len(m.Answer) == 0 {
			t.Fatalf("query %d within burst was limited", i)
		}
	}
	// The whole /24 shares one bucket: the next UDP query gets an empty
	// truncated reply and does not capture.
	m := query(t, h, tok+".example.test", dns.TypeA, "198.51.100.200", "")
	if !m.Truncated || len(m.Answer) != 0 || len(m.Ns) != 0 {
		t.Fatalf("over limit: tc=%v answer=%v ns=%v, want empty truncated reply", m.Truncated, m.Answer, m.Ns)
	}
	if mr.CommandCount() != 0 {
		t.Error("a rate-limited query reached Redis")
	}

	// The truncated reply's TCP retry has its own bucket, so a spoofed UDP
	// flood can't lock the real resolver out. Past the TCP limit the source
	// is genuine, so the reply is REFUSED rather than TC.
	tcp := func() *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("example.test.", dns.TypeA)
		w := &fakeDNSWriter{remote: &net.TCPAddr{IP: net.ParseIP("198.51.100.1"), Port: 40000}}
		h.handle(w, req)
		return w.msg
	}
	for i := range 5 {
		if m := tcp(); m.Rcode != dns.RcodeSuccess || len(m.Answer) == 0 {
			t.Fatalf("TCP query %d after UDP limit: rcode=%s, want an answer", i, dns.RcodeToString[m.Rcode])
		}
	}
	if m := tcp(); m.Rcode != dns.RcodeRefused || m.Truncated {
		t.Fatalf("TCP over limit: rcode=%s tc=%v, want REFUSED", dns.RcodeToString[m.Rcode], m.Truncated)
	}

	// Another /24 is unaffected, and the bucket refills over time.
	if m := query(t, h, "example.test", dns.TypeA, "198.51.101.1", ""); m.Truncated {
		t.Fatal("a different /24 was limited")
	}
	now = now.Add(2 * time.Second)
	if m := query(t, h, "example.test", dns.TypeA, "198.51.100.1", ""); m.Truncated {
		t.Fatal("bucket did not refill")
	}
}

func TestDNSAnswersANYMinimally(t *testing.T) {
	store, _ := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store}

	m := query(t, h, "example.test", dns.TypeANY, "198.51.100.1", "")
	if len(m.Answer) != 1 {
		t.Fatalf("ANY answer = %v, want a single record", m.Answer)
	}
	if hinfo, ok := m.Answer[0].(*dns.HINFO); !ok || hinfo.Cpu != "RFC8482" {
		t.Fatalf("ANY answer = %v, want RFC 8482 HINFO", m.Answer[0])
	}
}

func TestDNSServesACMEChallenge(t *testing.T) {
	store, _ := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store}
	name := "_acme-challenge.example.test."

	if m := query(t, h, name, dns.TypeTXT, "198.51.100.1", ""); len(m.Answer) != 0 {
		t.Fatalf("answer before Present: %v", m.Answer)
	}
	if err := store.AddTXT(name, "key-auth-1"); err != nil {
		t.Fatal(err)
	}
	m := query(t, h, name, dns.TypeTXT, "198.51.100.1", "")
	if len(m.Answer) != 1 || m.Answer[0].(*dns.TXT).Txt[0] != "key-auth-1" {
		t.Fatalf("answer = %v, want key-auth-1", m.Answer)
	}
	if err := store.DelTXT(name, "key-auth-1"); err != nil {
		t.Fatal(err)
	}
	if m := query(t, h, name, dns.TypeTXT, "198.51.100.1", ""); len(m.Answer) != 0 {
		t.Fatalf("answer after CleanUp: %v", m.Answer)
	}
}

func TestTokenLabel(t *testing.T) {
	base := "example.test."
	tests := []struct {
		qname, want string
		ok          bool
	}{
		{"abc.example.test.", "abc", true},
		{"example.test.", "", false},
		{"a.b.example.test.", "", false},
		{"abcexample.test.", "", false},
		{"abc.other.test.", "", false},
	}
	for _, tt := range tests {
		got, ok := tokenLabel(tt.qname, base)
		if got != tt.want || ok != tt.ok {
			t.Errorf("tokenLabel(%q) = %q, %v; want %q, %v", tt.qname, got, ok, tt.want, tt.ok)
		}
	}
}

func TestSOASerial(t *testing.T) {
	if got := soaSerial(time.Unix(1_700_000_000, 0)); got != 1_700_000_000 {
		t.Errorf("soaSerial = %d", got)
	}
	// Past 2106 the serial wraps instead of panicking or saturating.
	if got := soaSerial(time.Unix(1<<32+5, 0)); got != 5 {
		t.Errorf("soaSerial after wrap = %d, want 5", got)
	}
}
