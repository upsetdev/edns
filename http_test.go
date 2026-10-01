package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

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
	if !isToken(token) || loc.Host != token+".example.test" {
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

func TestReportOmitsEDNSWithoutSubnet(t *testing.T) {
	store, _ := newTestStore(t)
	store.Put(tok, &Result{Token: tok, ResolverIP: "198.51.100.7", ECS: "none", Resolved: true})

	rec := get(newHTTPHandler(testConfig(), store), "GET", "http://"+tok+".example.test/", nil)
	if strings.Contains(rec.Body.String(), "edns") {
		t.Fatalf("edns present without a subnet: %s", rec.Body)
	}
}

func TestReportRejectsUnknownAndInvalidTokens(t *testing.T) {
	store, mr := newTestStore(t)
	handler := newHTTPHandler(testConfig(), store)

	if rec := get(handler, "GET", "http://fedcba9876543210.example.test/", nil); rec.Code != http.StatusNotFound {
		t.Errorf("unknown token status = %d, want 404", rec.Code)
	}

	before := mr.CommandCount()
	for _, host := range []string{"www.example.test", "a.b.example.test", "example.com"} {
		if rec := get(handler, "GET", "http://"+host+"/", nil); rec.Code != http.StatusNotFound {
			t.Errorf("%s status = %d, want 404", host, rec.Code)
		}
	}
	if n := mr.CommandCount() - before; n != 0 {
		t.Errorf("invalid hosts ran %d Redis commands, want 0", n)
	}
}

func TestFavicon(t *testing.T) {
	store, mr := newTestStore(t)
	handler := newHTTPHandler(testConfig(), store)

	for _, host := range []string{"example.test", tok + ".example.test"} {
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
	rec := get(newHTTPHandler(testConfig(), store), "OPTIONS", "http://"+tok+".example.test/", nil)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("preflight: status=%d acao=%q", rec.Code, rec.Header().Get("Access-Control-Allow-Origin"))
	}
}
