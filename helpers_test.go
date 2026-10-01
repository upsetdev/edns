package main

import (
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/miekg/dns"
)

// testConfig returns a valid configuration for the example.test zone.
func testConfig() Config {
	return Config{
		BaseDomain:     "example.test.",
		HTTPIP:         "192.0.2.10",
		HTTPIPv6:       "2001:db8::10",
		NS:             []string{"ns1.example.test.", "ns2.example.test."},
		HostmasterMail: "hostmaster.example.test.",
		EnableTLS:      false,
		TTL:            time.Hour,
	}
}

// newTestStore starts an in-memory Redis and returns a Store backed by it.
func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	return NewStore(mr.Addr(), "", time.Hour), mr
}

// fakeDNSWriter captures the reply a dns handler writes.
type fakeDNSWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (w *fakeDNSWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(192, 0, 2, 53), Port: 53}
}
func (w *fakeDNSWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *fakeDNSWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *fakeDNSWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *fakeDNSWriter) Close() error                { return nil }
func (w *fakeDNSWriter) TsigStatus() error           { return nil }
func (w *fakeDNSWriter) TsigTimersOnly(bool)         {}
func (w *fakeDNSWriter) Hijack()                     {}

// query sends one question to h as if it came from resolverIP and returns the
// reply. ecs, when non-empty, is attached as an EDNS Client Subnet option.
func query(t *testing.T, h *dnsHandler, name string, qtype uint16, resolverIP, ecs string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	if ecs != "" {
		_, subnet, err := net.ParseCIDR(ecs)
		if err != nil {
			t.Fatalf("bad ecs %q: %v", ecs, err)
		}
		ones, _ := subnet.Mask.Size()
		opt := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, SourceNetmask: uint8(ones), Address: subnet.IP}
		opt.Family = 1
		if subnet.IP.To4() == nil {
			opt.Family = 2
		}
		req.SetEdns0(4096, false)
		req.IsEdns0().Option = append(req.IsEdns0().Option, opt)
	}
	w := &fakeDNSWriter{remote: &net.UDPAddr{IP: net.ParseIP(resolverIP), Port: 40000}}
	h.handle(w, req)
	if w.msg == nil {
		t.Fatalf("no reply for %s", name)
	}
	return w.msg
}
