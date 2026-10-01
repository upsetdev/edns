package main

import (
	"bufio"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestLimiterNilAllowsEverything(t *testing.T) {
	l := newLimiter(0)
	if l != nil {
		t.Fatal("newLimiter(0) should disable limiting")
	}
	for range 1000 {
		if !l.allow("k", time.Now()) {
			t.Fatal("nil limiter denied")
		}
	}
}

func TestLimiterSweepsIdleAndOverflows(t *testing.T) {
	l := newLimiter(1)
	now := time.Now()
	for i := range limiterMaxKeys {
		l.allow(strconv.Itoa(i), now)
	}
	// Past the key cap, new sources share the overflow bucket (burst 5).
	for i := range 5 {
		if !l.allow("new"+strconv.Itoa(i), now) {
			t.Fatalf("overflow request %d denied within burst", i)
		}
	}
	if l.allow("another", now) {
		t.Fatal("overflow bucket was not shared")
	}
	// Once idle buckets are swept, new sources get their own again.
	now = now.Add(2 * limiterIdle)
	if !l.allow("another", now) || len(l.buckets) != 1 {
		t.Fatalf("after sweep: %d buckets, want 1", len(l.buckets))
	}
}

func TestPrefixKey(t *testing.T) {
	tests := []struct{ addr, want string }{
		{"198.51.100.77", "198.51.100.0/24"},
		{"::ffff:198.51.100.77", "198.51.100.0/24"},
		{"2001:db8:1:2:3::1", "2001:db8:1::/56"},
		{"not-an-ip", "not-an-ip"},
	}
	for _, tt := range tests {
		if got := prefixKey(tt.addr, 24, 56); got != tt.want {
			t.Errorf("prefixKey(%q) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}

func TestCaptureGuard(t *testing.T) {
	g := newCaptureGuard()
	now := time.Now()
	exp := now.Add(time.Hour)

	if !g.first("t", exp, now) {
		t.Fatal("first capture denied")
	}
	if g.first("t", exp, now) {
		t.Fatal("repeat capture allowed")
	}
	if !g.first("u", exp, now) {
		t.Fatal("other token denied")
	}
	var nilGuard *captureGuard
	for range 2 {
		if !nilGuard.first("t", exp, now) {
			t.Fatal("nil guard denied")
		}
	}
}

func TestCaptureGuardSweepsWhenFull(t *testing.T) {
	g := newCaptureGuard()
	now := time.Now()
	for i := range captureGuardMaxKeys {
		g.seen[strconv.Itoa(i)] = now.Add(time.Minute)
	}
	// Full of live entries: fail open rather than drop a real capture.
	if !g.first("new", now.Add(time.Hour), now) || len(g.seen) != captureGuardMaxKeys {
		t.Fatal("full guard should allow without tracking")
	}
	// Once those expire they are swept and tracking resumes.
	later := now.Add(2 * time.Minute)
	if !g.first("new", later.Add(time.Hour), later) || g.first("new", later.Add(time.Hour), later) {
		t.Fatal("guard did not resume tracking after sweep")
	}
	if len(g.seen) != 1 {
		t.Errorf("%d entries after sweep, want 1", len(g.seen))
	}
}

// TestListenProxyProtocol checks that with PROXY protocol on, RemoteAddr is
// the client named in the header, and that connections without one are
// rejected rather than trusted.
func TestListenProxyProtocol(t *testing.T) {
	ln, err := listen("127.0.0.1:0", true, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	got := make(chan string, 2)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err != nil {
					got <- "error"
					return
				}
				got <- c.RemoteAddr().String() + " " + line
			}(c)
		}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("PROXY TCP4 203.0.113.9 192.0.2.1 5555 443\r\nhello\n"))
	if g := <-got; g != "203.0.113.9:5555 hello\n" {
		t.Fatalf("with header: got %q", g)
	}

	c2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_, _ = c2.Write([]byte("hello\n"))
	if g := <-got; g != "error" {
		t.Fatalf("without header: got %q, want the read to fail", g)
	}
}
