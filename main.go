package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// Config is read from environment variables at startup.
type Config struct {
	BaseDomain     string        // fqdn with trailing dot, e.g. "edns.upset.dev."
	HTTPIP         string        // public IPv4 of this HTTP server (the A record we hand out)
	HTTPIPv6       string        // optional public IPv6 (AAAA)
	NS             []string      // authoritative nameservers (for NS/SOA answers)
	HostmasterMail string        // SOA RNAME, e.g. "hostmaster.upset.dev."
	DNSAddr        string        // listen addr for DNS, default ":53"
	DNSUDPAddr     string        // listen addr for DNS over UDP, default DNSAddr
	HTTPAddr       string        // listen addr for HTTP, default ":8080"
	HTTPSAddr      string        // listen addr for HTTPS, default ":8443"
	RedisAddr      string        // host:port of Redis, default "redis:6379"
	RedisURL       string        // redis:// URL (with credentials); overrides RedisAddr
	EnableTLS      bool          // serve HTTPS via CertMagic (DNS-01 wildcard), default true
	ACMEEmail      string        // contact email for Let's Encrypt
	ACMEStaging    bool          // use LE staging CA (for testing), default false
	CertDir        string        // CertMagic storage path, default "/data"
	TTL            time.Duration // how long a token lives
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// fqdn ensures a trailing dot.
func fqdn(s string) string {
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}

// tokenLen is the number of hex characters in a minted token.
const tokenLen = 16

// loadConfig reads the configuration from the environment and validates it.
func loadConfig() (Config, error) {
	base := fqdn(strings.ToLower(env("BASE_DOMAIN", "edns.upset.dev")))
	apex := strings.TrimSuffix(base, ".")

	var ns []string
	for _, n := range strings.Split(env("NS", "ns1."+apex+",ns2."+apex), ",") {
		if n = strings.TrimSpace(n); n != "" {
			ns = append(ns, fqdn(strings.ToLower(n)))
		}
	}

	dnsAddr := env("DNS_ADDR", ":53")
	cfg := Config{
		BaseDomain:     base,
		HTTPIP:         env("HTTP_IP", ""),
		HTTPIPv6:       env("HTTP_IPV6", ""),
		NS:             ns,
		HostmasterMail: fqdn(strings.ToLower(env("HOSTMASTER", "hostmaster."+apex))),
		DNSAddr:        dnsAddr,
		DNSUDPAddr:     env("DNS_UDP_ADDR", dnsAddr),
		HTTPAddr:       env("HTTP_ADDR", ":8080"),
		HTTPSAddr:      env("HTTPS_ADDR", ":8443"),
		RedisAddr:      env("REDIS_ADDR", "redis:6379"),
		RedisURL:       env("REDIS_URL", ""),
		EnableTLS:      env("TLS", "true") == "true",
		ACMEEmail:      env("ACME_EMAIL", ""),
		ACMEStaging:    env("ACME_STAGING", "false") == "true",
		CertDir:        env("CERT_DIR", "/data"),
		TTL:            time.Hour,
	}

	// The A record we hand out is the whole point of the redirect; refuse to
	// start rather than answer with a wrong or empty address.
	if ip := net.ParseIP(cfg.HTTPIP); ip == nil || ip.To4() == nil {
		return Config{}, fmt.Errorf("HTTP_IP must be a public IPv4 address, got %q", cfg.HTTPIP)
	}
	if cfg.HTTPIPv6 != "" {
		if ip := net.ParseIP(cfg.HTTPIPv6); ip == nil || ip.To4() != nil {
			return Config{}, fmt.Errorf("HTTP_IPV6 must be an IPv6 address, got %q", cfg.HTTPIPv6)
		}
	}
	if len(cfg.NS) == 0 {
		return Config{}, errors.New("NS must list at least one nameserver")
	}
	return cfg, nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	store := NewStore(cfg.RedisAddr, cfg.RedisURL, cfg.TTL)

	go serveDNS(cfg, store)
	serveHTTP(cfg, store) // blocks
}

// isToken reports whether label has the shape of a minted token, so junk
// lookups (scanners, typos) are rejected without a Redis round trip.
func isToken(label string) bool {
	if len(label) != tokenLen {
		return false
	}
	for _, c := range label {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// randToken returns a url/dns-safe random label of n hex chars.
func randToken(n int) string {
	b := make([]byte, (n+1)/2)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is fatal; we never want predictable tokens
		log.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)[:n]
}
