package main

import (
	"reflect"
	"strings"
	"testing"
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
}

func TestLoadConfigOverrides(t *testing.T) {
	t.Setenv("HTTP_IP", "192.0.2.10")
	t.Setenv("NS", " a.example.net , b.example.net. ,")
	t.Setenv("HOSTMASTER", "dns.example.net")
	t.Setenv("DNS_ADDR", ":5353")
	t.Setenv("DNS_UDP_ADDR", "fly-global-services:53")

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
}

func TestLoadConfigRejectsInvalid(t *testing.T) {
	tests := []struct {
		name, env, val, wantErr string
	}{
		{"missing HTTP_IP", "HTTP_IP", "", "HTTP_IP"},
		{"IPv6 as HTTP_IP", "HTTP_IP", "2001:db8::1", "HTTP_IP"},
		{"IPv4 as HTTP_IPV6", "HTTP_IPV6", "192.0.2.1", "HTTP_IPV6"},
		{"empty NS", "NS", " , ", "NS"},
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

func TestRandTokenIsValidToken(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		tok := randToken(tokenLen)
		if !isToken(tok) {
			t.Fatalf("randToken produced %q, which isToken rejects", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

func TestIsToken(t *testing.T) {
	for _, tok := range []string{"0123456789abcdef", "ffffffffffffffff"} {
		if !isToken(tok) {
			t.Errorf("isToken(%q) = false, want true", tok)
		}
	}
	for _, tok := range []string{"", "www", "0123456789ABCDEF", "0123456789abcde", "0123456789abcdef0", "0123456789abcdeg", "_acme-challenge"} {
		if isToken(tok) {
			t.Errorf("isToken(%q) = true, want false", tok)
		}
	}
}
