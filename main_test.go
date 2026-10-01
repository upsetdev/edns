package main

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("BASE_DOMAIN", "Example.Test")
	t.Setenv("HTTP_IP", "192.0.2.10")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BaseDomain != "example.test." {
		t.Errorf("BaseDomain = %q, want lower-cased fqdn", cfg.BaseDomain)
	}
	if want := []string{"ns1.example.test.", "ns2.example.test."}; !reflect.DeepEqual(cfg.NS, want) {
		t.Errorf("NS = %v, want %v", cfg.NS, want)
	}
	if cfg.HostmasterMail != "hostmaster.example.test." {
		t.Errorf("HostmasterMail = %q", cfg.HostmasterMail)
	}
	if cfg.DNSUDPAddr != cfg.DNSAddr {
		t.Errorf("DNSUDPAddr = %q, want it to default to DNSAddr %q", cfg.DNSUDPAddr, cfg.DNSAddr)
	}
	if !cfg.EnableTLS {
		t.Error("TLS should default to on")
	}
	if cfg.CertStore != "file" {
		t.Errorf("CertStore = %q, want file", cfg.CertStore)
	}
	if cfg.Store != "memory" || cfg.ProxyProtocol {
		t.Errorf("Store/ProxyProtocol = %q/%v, want memory/false", cfg.Store, cfg.ProxyProtocol)
	}
	if cfg.DNSRateLimit != 20 || cfg.HTTPRateLimit != 2 {
		t.Errorf("rate limits = %v/%v, want 20/2", cfg.DNSRateLimit, cfg.HTTPRateLimit)
	}
	if len(cfg.TokenSecret) != 32 {
		t.Errorf("generated TokenSecret has %d bytes, want 32", len(cfg.TokenSecret))
	}
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("HTTP_IP", "192.0.2.10")
	t.Setenv("NS", " a.example.net , b.example.net. ,")
	t.Setenv("HOSTMASTER", "dns.example.net")
	t.Setenv("DNS_ADDR", ":5353")
	t.Setenv("DNS_UDP_ADDR", "fly-global-services:53")
	t.Setenv("STORE", "redis")
	t.Setenv("CERT_STORE", "redis")
	t.Setenv("PROXY_PROTOCOL", "true")
	t.Setenv("DNS_RATE_LIMIT", "0")
	t.Setenv("HTTP_RATE_LIMIT", "0.5")
	t.Setenv("TOKEN_SECRET", strings.Repeat("s", 32))

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if want := []string{"a.example.net.", "b.example.net."}; !reflect.DeepEqual(cfg.NS, want) {
		t.Errorf("NS = %v, want %v", cfg.NS, want)
	}
	if cfg.HostmasterMail != "dns.example.net." {
		t.Errorf("HostmasterMail = %q", cfg.HostmasterMail)
	}
	if cfg.DNSAddr != ":5353" || cfg.DNSUDPAddr != "fly-global-services:53" {
		t.Errorf("DNSAddr/DNSUDPAddr = %q/%q", cfg.DNSAddr, cfg.DNSUDPAddr)
	}
	if cfg.CertStore != "redis" {
		t.Errorf("CertStore = %q, want redis", cfg.CertStore)
	}
	if cfg.Store != "redis" || !cfg.ProxyProtocol || cfg.DNSRateLimit != 0 || cfg.HTTPRateLimit != 0.5 {
		t.Errorf("Store=%q ProxyProtocol=%v rates=%v/%v", cfg.Store, cfg.ProxyProtocol, cfg.DNSRateLimit, cfg.HTTPRateLimit)
	}
	if string(cfg.TokenSecret) != strings.Repeat("s", 32) {
		t.Errorf("TokenSecret = %q", cfg.TokenSecret)
	}
}

func TestLoadConfigRejectsInvalid(t *testing.T) {
	tests := []struct {
		name, env, val, wantErr string
	}{
		{"missing HTTP_IP", "HTTP_IP", "", "HTTP_IP"},
		{"IPv6 as HTTP_IP", "HTTP_IP", "2001:db8::1", "HTTP_IP"},
		{"IPv4 as HTTP_IPV6", "HTTP_IPV6", "192.0.2.1", "HTTP_IPV6"},
		{"empty NS", "NS", " , ", "NS"},
		{"unknown STORE", "STORE", "memcached", "STORE"},
		{"unknown CERT_STORE", "CERT_STORE", "s3", "CERT_STORE"},
		{"CERT_STORE=redis without STORE=redis", "CERT_STORE", "redis", "STORE=redis"},
		{"bad DNS_RATE_LIMIT", "DNS_RATE_LIMIT", "fast", "DNS_RATE_LIMIT"},
		{"negative HTTP_RATE_LIMIT", "HTTP_RATE_LIMIT", "-1", "HTTP_RATE_LIMIT"},
		{"short TOKEN_SECRET", "TOKEN_SECRET", "short", "TOKEN_SECRET"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HTTP_IP", "192.0.2.10")
			t.Setenv(tt.env, tt.val)
			_, err := loadConfig()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want mention of %s", err, tt.wantErr)
			}
		})
	}
}

func TestMintedTokensVerify(t *testing.T) {
	cfg := testConfig()
	now := time.Now()
	seen := map[string]bool{}
	for range 100 {
		tok := mintToken(cfg, now)
		if len(tok) != tokenLen || len(tok) > 63 {
			t.Fatalf("token %q has length %d, want %d (and a valid DNS label)", tok, len(tok), tokenLen)
		}
		expires, ok := verifyToken(cfg, tok, now)
		if !ok {
			t.Fatalf("verifyToken rejected freshly minted %q", tok)
		}
		if want := now.Add(cfg.TTL).Truncate(time.Second); !expires.Equal(want) {
			t.Fatalf("expires = %v, want %v", expires, want)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

func TestVerifyTokenRejects(t *testing.T) {
	cfg := testConfig()
	now := time.Now()
	tok := mintToken(cfg, now)

	other := cfg
	other.TokenSecret = []byte("some-other-secret-some-other-secret")
	flipped := []byte(tok)
	flipped[10] ^= 1 // still hex: '0'<->'1', 'a'<->'`' is caught by the charset check

	tests := map[string]struct {
		label string
		at    time.Time
	}{
		"expired":      {tok, now.Add(cfg.TTL)},
		"other secret": {mintToken(other, now), now},
		"tampered":     {string(flipped), now},
		"upper case":   {strings.ToUpper(tok), now},
		"too short":    {tok[1:], now},
		"too long":     {tok + "0", now},
		"empty":        {"", now},
		"non-hex":      {strings.Repeat("g", tokenLen), now},
		"old format":   {"0123456789abcdef", now},
	}
	for name, tt := range tests {
		if _, ok := verifyToken(cfg, tt.label, tt.at); ok {
			t.Errorf("%s: verifyToken(%q) = true, want false", name, tt.label)
		}
	}
}
