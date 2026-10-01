package main

import (
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

func serveDNS(cfg Config, store *Store) {
	h := &dnsHandler{cfg: cfg, store: store}
	dns.HandleFunc(".", h.handle)

	// UDP and TCP (large answers / retries fall back to TCP).
	// UDP may need its own bind address: on Fly.io it must listen on
	// fly-global-services so replies leave from the anycast IP.
	addrs := map[string]string{"udp": cfg.DNSUDPAddr, "tcp": cfg.DNSAddr}
	for _, net_ := range []string{"udp", "tcp"} {
		srv := &dns.Server{Addr: addrs[net_], Net: net_}
		go func(s *dns.Server) {
			log.Printf("DNS listening on %s/%s", s.Addr, s.Net)
			if err := s.ListenAndServe(); err != nil {
				log.Fatalf("dns %s: %v", s.Net, err)
			}
		}(srv)
	}
	select {} // keep goroutine alive
}

type dnsHandler struct {
	cfg   Config
	store *Store
}

func (h *dnsHandler) handle(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	if len(r.Question) == 0 {
		_ = w.WriteMsg(m)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)
	base := h.cfg.BaseDomain

	// Serve glue for our own nameserver hostnames, which live outside the
	// primary zone (e.g. edns1.ns.upset.dev). A resolver that follows the NS
	// records may look these up directly, so we answer them with HTTP_IP.
	if h.isNSName(qname) {
		switch q.Qtype {
		case dns.TypeA:
			if ip := net.ParseIP(h.cfg.HTTPIP); ip != nil {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
					A:   ip,
				})
			}
		case dns.TypeAAAA:
			if h.cfg.HTTPIPv6 != "" {
				if ip := net.ParseIP(h.cfg.HTTPIPv6); ip != nil {
					m.Answer = append(m.Answer, &dns.AAAA{
						Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 3600},
						AAAA: ip,
					})
				}
			}
		}
		_ = w.WriteMsg(m)
		return
	}

	// Only authoritative for our zone.
	if qname != base && !strings.HasSuffix(qname, "."+base) {
		m.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(m)
		return
	}

	// ACME DNS-01 challenge: serve the TXT that CertMagic's solver published.
	// The challenge name is the same for the apex and the wildcard cert.
	if qname == "_acme-challenge."+base {
		if q.Qtype == dns.TypeTXT {
			for _, v := range h.store.GetTXT(qname) {
				m.Answer = append(m.Answer, &dns.TXT{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
					Txt: []string{v},
				})
			}
		}
		if len(m.Answer) == 0 {
			m.Ns = append(m.Ns, h.soa(base))
		}
		_ = w.WriteMsg(m)
		return
	}

	switch q.Qtype {
	case dns.TypeSOA:
		m.Answer = append(m.Answer, h.soa(base))
	case dns.TypeNS:
		m.Answer = append(m.Answer, h.nsRecords(base)...)
	case dns.TypeA:
		// A query for a token subdomain is the signal we care about:
		// it means a resolver looked the name up on behalf of a client.
		if label, ok := tokenLabel(qname, base); ok && isToken(label) {
			h.capture(label, w, r)
		}
		if ip := net.ParseIP(h.cfg.HTTPIP); ip != nil {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 5},
				A:   ip,
			})
		}
	case dns.TypeAAAA:
		if h.cfg.HTTPIPv6 != "" {
			if ip := net.ParseIP(h.cfg.HTTPIPv6); ip != nil {
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 5},
					AAAA: ip,
				})
			}
		}
		// no AAAA configured -> NOERROR/NODATA with SOA in authority
		if len(m.Answer) == 0 {
			m.Ns = append(m.Ns, h.soa(base))
		}
	default:
		// Known name, unsupported type -> NODATA.
		m.Ns = append(m.Ns, h.soa(base))
	}

	_ = w.WriteMsg(m)
}

// capture records the resolver IP and ECS for a token. It only updates an
// existing token (minted by the HTTP redirect); unknown tokens are ignored.
func (h *dnsHandler) capture(token string, w dns.ResponseWriter, r *dns.Msg) {
	resolverIP := addrIP(w.RemoteAddr())
	ecs, family := extractECS(r)

	updated := h.store.Update(token, func(res *Result) {
		res.ResolverIP = resolverIP
		res.ECS = ecs
		res.ECSFamily = family
		res.Resolved = true
	})
	if updated {
		log.Printf("dns resolve token=%s resolver=%s ecs=%s", token, resolverIP, ecs)
	}
}

func (h *dnsHandler) soa(base string) *dns.SOA {
	ns := "ns1." + base
	if len(h.cfg.NS) > 0 {
		ns = h.cfg.NS[0]
	}
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: base, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      ns,
		Mbox:    h.cfg.HostmasterMail,
		Serial:  soaSerial(time.Now()),
		Refresh: 7200,
		Retry:   3600,
		Expire:  1209600,
		Minttl:  60,
	}
}

// soaSerial derives the SOA serial from the clock. Serials compare with RFC
// 1982 sequence-space arithmetic, so truncating to 32 bits (wrapping in 2106)
// stays monotonic as far as resolvers are concerned.
func soaSerial(t time.Time) uint32 {
	return uint32(t.Unix() & 0xffffffff) // #nosec G115 -- intentional wrap, see above
}

// isNSName reports whether qname is one of our configured nameserver hostnames.
func (h *dnsHandler) isNSName(qname string) bool {
	for _, ns := range h.cfg.NS {
		if strings.EqualFold(qname, ns) {
			return true
		}
	}
	return false
}

func (h *dnsHandler) nsRecords(base string) []dns.RR {
	var out []dns.RR
	for _, ns := range h.cfg.NS {
		out = append(out, &dns.NS{
			Hdr: dns.RR_Header{Name: base, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400},
			Ns:  ns,
		})
	}
	return out
}

// tokenLabel returns the left-most label of qname if it is a direct
// subdomain of base (i.e. "<token>.base."), else ok=false.
func tokenLabel(qname, base string) (string, bool) {
	if !strings.HasSuffix(qname, "."+base) {
		return "", false
	}
	prefix := strings.TrimSuffix(qname, "."+base)
	if prefix == "" || strings.Contains(prefix, ".") {
		return "", false
	}
	return prefix, true
}

func addrIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// extractECS pulls the EDNS Client Subnet option from a query, if present.
func extractECS(r *dns.Msg) (subnet, family string) {
	opt := r.IsEdns0()
	if opt == nil {
		return "none", "none"
	}
	for _, o := range opt.Option {
		s, ok := o.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		if s.SourceNetmask == 0 {
			return "none", "none"
		}
		cidr := s.Address.String() + "/" + strconv.Itoa(int(s.SourceNetmask))
		switch s.Family {
		case 1:
			return cidr, "ipv4"
		case 2:
			return cidr, "ipv6"
		}
	}
	return "none", "none"
}
