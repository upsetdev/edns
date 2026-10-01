package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
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
	Store          string        // "memory" (default) or "redis"
	RedisAddr      string        // host:port of Redis, default "redis:6379"
	RedisURL       string        // redis:// URL (with credentials); overrides RedisAddr
	EnableTLS      bool          // serve HTTPS via CertMagic (DNS-01 wildcard), default true
	ACMEEmail      string        // contact email for Let's Encrypt
	ACMEStaging    bool          // use LE staging CA (for testing), default false
	CertStore      string        // "file" (default, CertDir) or "redis" (shared by replicas)
	CertDir        string        // CertMagic storage path, default "/data"
	TTL            time.Duration // how long a token lives
	TokenSecret    []byte        // HMAC key for tokens; must match across replicas
	ProxyProtocol  bool          // require a PROXY protocol header on TCP listeners
	DNSRateLimit   float64       // DNS queries/s per source /24 (IPv4) or /56 (IPv6); 0 = off
	HTTPRateLimit  float64       // HTTP requests/s per client IPv4 or /64; 0 = off
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
		Store:          env("STORE", "memory"),
		RedisAddr:      env("REDIS_ADDR", "redis:6379"),
		RedisURL:       env("REDIS_URL", ""),
		EnableTLS:      env("TLS", "true") == "true",
		ACMEEmail:      env("ACME_EMAIL", ""),
		ACMEStaging:    env("ACME_STAGING", "false") == "true",
		CertStore:      env("CERT_STORE", "file"),
		CertDir:        env("CERT_DIR", "/data"),
		TTL:            time.Hour,
		ProxyProtocol:  env("PROXY_PROTOCOL", "false") == "true",
	}

	if cfg.Store != "memory" && cfg.Store != "redis" {
		return Config{}, fmt.Errorf("STORE must be memory or redis, got %q", cfg.Store)
	}
	if cfg.CertStore != "file" && cfg.CertStore != "redis" {
		return Config{}, fmt.Errorf("CERT_STORE must be file or redis, got %q", cfg.CertStore)
	}
	// Sharing certificates means several replicas answer DNS, and Let's
	// Encrypt's validation query may reach any of them, so the challenge TXT
	// must live in the shared store too.
	if cfg.CertStore == "redis" && cfg.Store != "redis" {
		return Config{}, errors.New("CERT_STORE=redis requires STORE=redis")
	}

	var err error
	if cfg.DNSRateLimit, err = strconv.ParseFloat(env("DNS_RATE_LIMIT", "20"), 64); err != nil || cfg.DNSRateLimit < 0 {
		return Config{}, fmt.Errorf("DNS_RATE_LIMIT must be a non-negative number, got %q", os.Getenv("DNS_RATE_LIMIT"))
	}
	if cfg.HTTPRateLimit, err = strconv.ParseFloat(env("HTTP_RATE_LIMIT", "2"), 64); err != nil || cfg.HTTPRateLimit < 0 {
		return Config{}, fmt.Errorf("HTTP_RATE_LIMIT must be a non-negative number, got %q", os.Getenv("HTTP_RATE_LIMIT"))
	}

	if secret := os.Getenv("TOKEN_SECRET"); secret != "" {
		if len(secret) < 32 {
			return Config{}, errors.New("TOKEN_SECRET must be at least 32 characters")
		}
		cfg.TokenSecret = []byte(secret)
	} else {
		// Fine for a single instance: a restart only invalidates tokens minted
		// in the seconds before it. Replicas must share a TOKEN_SECRET.
		cfg.TokenSecret = make([]byte, 32)
		if _, err := rand.Read(cfg.TokenSecret); err != nil {
			return Config{}, fmt.Errorf("token secret: %w", err)
		}
		log.Print("TOKEN_SECRET not set; using a random per-process secret")
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
	store := NewStore(cfg)

	go serveDNS(cfg, store)
	serveHTTP(cfg, store) // blocks
}
