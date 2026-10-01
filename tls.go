package main

import (
	"context"
	"crypto/tls"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez/v3/acme"
)

// setupTLS configures CertMagic to obtain and auto-renew a wildcard
// certificate (edns.upset.dev + *.edns.upset.dev) using a DNS-01 challenge
// solved in-process, then returns a *tls.Config for our HTTPS listener.
func setupTLS(cfg Config, store Store) (*tls.Config, error) {
	base := strings.TrimSuffix(cfg.BaseDomain, ".")

	// Certificates, keys and the ACME account live on disk (one instance) or
	// in Redis (shared by replicas, with a distributed lock so only one of
	// them orders or renews). Either way CertMagic serves handshakes from its
	// in-memory cache, not from storage.
	if cfg.CertStore == "redis" {
		certmagic.Default.Storage = newRedisCertStorage(newRedisClient(cfg.RedisAddr, cfg.RedisURL))
	} else {
		certmagic.Default.Storage = &certmagic.FileStorage{Path: cfg.CertDir}
	}

	acmeIssuer := certmagic.DefaultACME
	acmeIssuer.Agreed = true
	acmeIssuer.Email = cfg.ACMEEmail
	acmeIssuer.DNS01Solver = &dnsSolver{store: store}
	// A wildcard can only be validated via DNS-01; disable the others.
	acmeIssuer.DisableHTTPChallenge = true
	acmeIssuer.DisableTLSALPNChallenge = true
	if cfg.ACMEStaging {
		acmeIssuer.CA = certmagic.LetsEncryptStagingCA
	} else {
		acmeIssuer.CA = certmagic.LetsEncryptProductionCA
	}
	certmagic.DefaultACME = acmeIssuer

	magic := certmagic.NewDefault()
	domains := []string{base, "*." + base}
	// Async so a transient ACME failure doesn't crash startup; certs are
	// obtained/renewed in the background and served once ready.
	if err := magic.ManageAsync(context.Background(), domains); err != nil {
		return nil, err
	}

	tlsCfg := magic.TLSConfig()
	tlsCfg.NextProtos = append([]string{"h2", "http/1.1"}, tlsCfg.NextProtos...)
	return tlsCfg, nil
}

// dnsSolver implements acmez.Solver. Because this process is the authoritative
// DNS server for the zone, "publishing" the challenge record is just a write
// to the shared store; the DNS handler serves it back to the ACME validator.
type dnsSolver struct{ store Store }

func (s *dnsSolver) Present(_ context.Context, ch acme.Challenge) error {
	return s.store.AddTXT(ch.DNS01TXTRecordName(), ch.DNS01KeyAuthorization())
}

func (s *dnsSolver) CleanUp(_ context.Context, ch acme.Challenge) error {
	return s.store.DelTXT(ch.DNS01TXTRecordName(), ch.DNS01KeyAuthorization())
}

// Wait lets the record settle (and propagate to all replicas via Redis)
// before we ask the ACME server to validate. Implements acmez.Waiter.
func (s *dnsSolver) Wait(ctx context.Context, _ acme.Challenge) error {
	select {
	case <-time.After(2 * time.Second):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
