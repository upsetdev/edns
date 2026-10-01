package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

const tok = "0123456789abcdef"

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
			store.Put(tok, &Result{Token: tok})

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

func TestDNSCaptureIgnoresUnknownAndJunk(t *testing.T) {
	store, mr := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store}

	// A well-formed but unminted token must not be created by a lookup.
	query(t, h, "fedcba9876543210.example.test", dns.TypeA, "198.51.100.1", "")
	if mr.Exists(key("fedcba9876543210")) {
		t.Error("lookup of an unminted token created it")
	}

	// Labels that cannot be tokens must not cost a Redis command.
	before := mr.CommandCount()
	for _, name := range []string{"www.example.test", "a.b.example.test", "0123456789abcdeg.example.test"} {
		query(t, h, name, dns.TypeA, "198.51.100.1", "")
	}
	if n := mr.CommandCount() - before; n != 0 {
		t.Errorf("junk lookups ran %d Redis commands, want 0", n)
	}
}

func TestDNSCaptureIsCaseInsensitive(t *testing.T) {
	// Resolvers randomize query case (DNS 0x20), so the token must still match.
	store, _ := newTestStore(t)
	h := &dnsHandler{cfg: testConfig(), store: store}
	store.Put(tok, &Result{Token: tok})

	query(t, h, "0123456789ABCDEF.Example.TEST", dns.TypeA, "198.51.100.7", "")
	if res, _ := store.Get(tok); res == nil || !res.Resolved {
		t.Fatal("mixed-case lookup was not captured")
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
