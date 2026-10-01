package main

import (
	"bytes"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed public/favicon.ico
var favicon []byte

// faviconModTime is the process start time, so conditional requests work.
var faviconModTime = time.Now()

// newHTTPHandler builds the complete HTTP handler chain.
func newHTTPHandler(cfg Config, store Store) http.Handler {
	h := &httpHandler{cfg: cfg, store: store, limit: newLimiter(cfg.HTTPRateLimit)}
	mux := http.NewServeMux()
	// Served on every host (apex and token subdomains) without touching the
	// store, so a browser's automatic favicon fetch costs no Redis command.
	mux.HandleFunc("/favicon.ico", serveFavicon)
	mux.HandleFunc("/", h.handle)

	// When TLS is on, every request is forced onto HTTPS: insecure ones are
	// redirected, secure ones get HSTS so browsers stay on HTTPS thereafter.
	handler := cors(mux)
	if cfg.EnableTLS {
		handler = forceHTTPS(handler)
	}
	return handler
}

// httpMaxConns caps concurrent connections per listener, so a connection
// flood queues in the kernel instead of exhausting the VM's memory.
const httpMaxConns = 1024

// newHTTPServer returns a server with timeouts on every phase of a request,
// so slow or idle clients can't hold connections open indefinitely.
func newHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func serveHTTP(cfg Config, store Store) {
	handler := newHTTPHandler(cfg, store)

	// HTTPS: CertMagic obtains and auto-renews the wildcard cert via an
	// in-process DNS-01 solver (we are the authoritative server for the zone).
	if cfg.EnableTLS {
		tlsCfg, err := setupTLS(cfg, store)
		if err != nil {
			log.Fatalf("tls setup: %v", err)
		}
		ln, err := listen(cfg.HTTPSAddr, cfg.ProxyProtocol, httpMaxConns)
		if err != nil {
			log.Fatalf("https listen: %v", err)
		}
		go func() {
			log.Printf("HTTPS listening on %s", cfg.HTTPSAddr)
			log.Fatal(newHTTPServer(handler).Serve(tls.NewListener(ln, tlsCfg)))
		}()
	}

	ln, err := listen(cfg.HTTPAddr, cfg.ProxyProtocol, httpMaxConns)
	if err != nil {
		log.Fatalf("http listen: %v", err)
	}
	log.Printf("HTTP listening on %s (base=%s a=%s)", cfg.HTTPAddr, cfg.BaseDomain, cfg.HTTPIP)
	log.Fatal(newHTTPServer(handler).Serve(ln))
}

// isSecure reports whether the request reached us over HTTPS, either directly
// (in-process TLS) or via a TLS-terminating proxy that set X-Forwarded-Proto.
func isSecure(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// forceHTTPS redirects any plain-HTTP request to its HTTPS equivalent and sets
// HSTS on secure responses so clients keep using HTTPS.
func forceHTTPS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isSecure(r) {
			host := r.Host
			if hostOnly, _, err := net.SplitHostPort(host); err == nil {
				host = hostOnly
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

// cors allows the JSON report to be fetched from any origin (the report is
// public, non-sensitive lookup data) and answers CORS preflight requests.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func serveFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, "favicon.ico", faviconModTime, bytes.NewReader(favicon))
}

type httpHandler struct {
	cfg   Config
	store Store
	limit *limiter // per client IPv4 or IPv6 /64; nil = unlimited
}

func (h *httpHandler) handle(w http.ResponseWriter, r *http.Request) {
	clientIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		clientIP = r.RemoteAddr
	}
	if !h.limit.allow(prefixKey(clientIP, 32, 64), time.Now()) {
		w.Header().Set("Retry-After", "5")
		http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
		return
	}

	host := strings.ToLower(r.Host)
	if hostOnly, _, err := net.SplitHostPort(host); err == nil {
		host = hostOnly
	}
	base := strings.TrimSuffix(h.cfg.BaseDomain, ".") // host header has no trailing dot

	switch {
	case host == base || host == "":
		h.mint(w, r)
	case strings.HasSuffix(host, "."+base):
		token := strings.TrimSuffix(host, "."+base)
		if _, ok := verifyToken(h.cfg, token, time.Now()); !ok {
			http.Error(w, `{"error":"unknown or expired token"}`, http.StatusNotFound)
			return
		}
		h.report(w, token)
	default:
		http.NotFound(w, r)
	}
}

// mint creates a fresh token and redirects the client to <token>.base so that
// resolving the new name forces a DNS lookup we can observe. Tokens are
// signed, so minting stores nothing.
func (h *httpHandler) mint(w http.ResponseWriter, r *http.Request) {
	token := mintToken(h.cfg, time.Now())

	base := strings.TrimSuffix(h.cfg.BaseDomain, ".")
	// Always hand out an HTTPS target when TLS is available; insecure requests
	// are upgraded by forceHTTPS before they ever reach here.
	scheme := "http"
	if h.cfg.EnableTLS || isSecure(r) {
		scheme = "https"
	}
	loc := scheme + "://" + token + "." + base + "/"

	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, loc, http.StatusFound)
}

// report returns the captured DNS data for a verified token. A token with no
// capture yet reports an empty resolver.
func (h *httpHandler) report(w http.ResponseWriter, token string) {
	res, ok := h.store.Get(token)
	if !ok {
		res = &Result{Token: token}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	type ipObj struct {
		IP string `json:"ip"`
	}
	resp := struct {
		DNS  ipObj  `json:"dns"`
		EDNS *ipObj `json:"edns,omitempty"`
	}{
		DNS: ipObj{IP: res.ResolverIP},
	}
	// edns block is only present when the resolver forwarded a client subnet.
	if ip, _, ok := strings.Cut(res.ECS, "/"); ok {
		resp.EDNS = &ipObj{IP: ip}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "    ")
	_ = enc.Encode(resp)
}
