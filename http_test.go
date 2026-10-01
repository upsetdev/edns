package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// get performs a request against the full handler chain used in production.
func get(handler http.Handler, method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestEndToEndLookup(t *testing.T) {
	store, _ := newTestStore(t)
	cfg := testConfig()
	handler := newHTTPHandler(cfg, store)
	dnsH := &dnsHandler{cfg: cfg, store: store}

	// 1. Mint: the apex redirects to a fresh token subdomain.
	rec := get(handler, "GET", "http://example.test/", nil)
	if rec.Code != http.StatusFound {
		t.Fatalf("mint status = %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	token, _, _ := strings.Cut(loc.Host, ".")
	if _, ok := verifyToken(cfg, token, time.Now()); !ok || loc.Host != token+".example.test" {
		t.Fatalf("redirect to %q, want <token>.example.test", loc)
	}

	// 2. Capture: the client's resolver looks the token up.
	query(t, dnsH, loc.Host, dns.TypeA, "198.51.100.7", "203.0.113.0/24")

	// 3. Report: the token host returns what the DNS side recorded.
	rec = get(handler, "GET", loc.String(), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("report status = %d: %s", rec.Code, rec.Body)
	}
	var got struct {
		DNS  struct{ IP string }  `json:"dns"`
		EDNS *struct{ IP string } `json:"edns"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("report body %q: %v", rec.Body, err)
	}
	if got.DNS.IP != "198.51.100.7" || got.EDNS == nil || got.EDNS.IP != "203.0.113.0" {
		t.Fatalf("report = %s", rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestMintCostsNoRedis(t *testing.T) {
	store, mr := newTestStore(t)
	if rec := get(newHTTPHandler(testConfig(), store), "GET", "http://example.test/", nil); rec.Code != http.StatusFound {
		t.Fatalf("mint status = %d", rec.Code)
	}
	if n := mr.CommandCount(); n != 0 {
		t.Errorf("mint ran %d Redis commands, want 0", n)
	}
}

func TestReportOmitsEDNSWithoutSubnet(t *testing.T) {
	store, _ := newTestStore(t)
	tok := newToken()
	store.Record(tok, &Result{Token: tok, ResolverIP: "198.51.100.7", ECS: "none", Resolved: true}, time.Now().Add(time.Hour))

	rec := get(newHTTPHandler(testConfig(), store), "GET", "http://"+tok+".example.test/", nil)
	if strings.Contains(rec.Body.String(), "edns") {
		t.Fatalf("edns present without a subnet: %s", rec.Body)
	}
}

func TestReportBeforeCapture(t *testing.T) {
	store, _ := newTestStore(t)
	rec := get(newHTTPHandler(testConfig(), store), "GET", "http://"+newToken()+".example.test/", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ip": ""`) {
		t.Fatalf("uncaptured token: status=%d body=%s, want 200 with an empty resolver", rec.Code, rec.Body)
	}
}

func TestReportRejectsForgedExpiredAndInvalidTokens(t *testing.T) {
	store, mr := newTestStore(t)
	cfg := testConfig()
	handler := newHTTPHandler(cfg, store)

	other := cfg
	other.TokenSecret = []byte("some-other-secret-some-other-secret")
	for _, host := range []string{
		mintToken(other, time.Now()) + ".example.test",
		mintToken(cfg, time.Now().Add(-2*cfg.TTL)) + ".example.test",
		"www.example.test", "a.b.example.test", "example.com",
	} {
		if rec := get(handler, "GET", "http://"+host+"/", nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", host, rec.Code)
		}
	}
	if n := mr.CommandCount(); n != 0 {
		t.Errorf("invalid hosts ran %d Redis commands, want 0", n)
	}
}

func TestHTTPRateLimit(t *testing.T) {
	store, _ := newTestStore(t)
	cfg := testConfig()
	cfg.HTTPRateLimit = 1 // burst 5
	handler := newHTTPHandler(cfg, store)

	from := func(addr string) int {
		req := httptest.NewRequest("GET", "http://example.test/", nil)
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}
	for i := range 5 {
		if code := from("198.51.100.1:1234"); code != http.StatusFound {
			t.Fatalf("request %d within burst: status %d", i, code)
		}
	}
	if code := from("198.51.100.1:1234"); code != http.StatusTooManyRequests {
		t.Fatalf("over limit: status %d, want 429", code)
	}
	// Limits are per client: a neighbour in the same /24 is unaffected,
	// while IPv6 clients are grouped by /64.
	if code := from("198.51.100.2:1234"); code != http.StatusFound {
		t.Fatalf("other client: status %d", code)
	}
	for range 5 {
		from("[2001:db8::1]:1234")
	}
	if code := from("[2001:db8::2]:1234"); code != http.StatusTooManyRequests {
		t.Fatalf("same /64: status %d, want 429", code)
	}
	// Favicons cost nothing and stay available.
	req := httptest.NewRequest("GET", "http://example.test/favicon.ico", nil)
	req.RemoteAddr = "198.51.100.1:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("favicon while limited: status %d", rec.Code)
	}
}

func TestFavicon(t *testing.T) {
	store, mr := newTestStore(t)
	handler := newHTTPHandler(testConfig(), store)

	for _, host := range []string{"example.test", newToken() + ".example.test"} {
		rec := get(handler, "GET", "http://"+host+"/favicon.ico", nil)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "image/x-icon" {
			t.Fatalf("%s: status=%d type=%q", host, rec.Code, rec.Header().Get("Content-Type"))
		}
		if !bytes.Equal(rec.Body.Bytes(), favicon) {
			t.Fatalf("%s: body differs from embedded favicon", host)
		}
	}
	if mr.CommandCount() != 0 {
		t.Errorf("favicon ran %d Redis commands, want 0", mr.CommandCount())
	}
}

func TestForceHTTPS(t *testing.T) {
	store, _ := newTestStore(t)
	cfg := testConfig()
	cfg.EnableTLS = true
	handler := newHTTPHandler(cfg, store)

	rec := get(handler, "GET", "http://example.test:80/path?q=1", nil)
	if rec.Code != http.StatusMovedPermanently || rec.Header().Get("Location") != "https://example.test/path?q=1" {
		t.Fatalf("plain HTTP: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}

	rec = get(handler, "GET", "http://example.test/", map[string]string{"X-Forwarded-Proto": "https"})
	if rec.Code != http.StatusFound || !strings.HasPrefix(rec.Header().Get("Location"), "https://") {
		t.Fatalf("secure mint: status=%d location=%q", rec.Code, rec.Header().Get("Location"))
	}
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Error("missing HSTS on secure response")
	}
}

func TestCORSPreflight(t *testing.T) {
	store, _ := newTestStore(t)
	rec := get(newHTTPHandler(testConfig(), store), "OPTIONS", "http://"+newToken()+".example.test/", nil)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("preflight: status=%d acao=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}
