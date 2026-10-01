package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"log"
	"time"
)

// A token is hex(expiry ‖ nonce ‖ mac), where expiry is a big-endian uint32 of
// unix seconds and mac is HMAC-SHA256(secret, expiry ‖ nonce) truncated. The
// MAC makes tokens self-validating: forged or expired labels are rejected in
// memory, so random-subdomain floods never reach Redis, and minting needs no
// store write at all.
const (
	tokenExpiryBytes = 4
	tokenNonceBytes  = 8
	tokenMACBytes    = 8
	tokenBytes       = tokenExpiryBytes + tokenNonceBytes + tokenMACBytes

	// tokenLen is the number of hex characters in a minted token.
	tokenLen = 2 * tokenBytes
)

// mintToken returns a fresh token that expires cfg.TTL after now.
func mintToken(cfg Config, now time.Time) string {
	var b [tokenBytes]byte
	binary.BigEndian.PutUint32(b[:tokenExpiryBytes], uint32(now.Add(cfg.TTL).Unix())) // #nosec G115 -- fits until 2106
	if _, err := rand.Read(b[tokenExpiryBytes : tokenExpiryBytes+tokenNonceBytes]); err != nil {
		// crypto/rand failing is fatal; we never want predictable tokens
		log.Fatalf("rand: %v", err)
	}
	copy(b[tokenExpiryBytes+tokenNonceBytes:], tokenMAC(cfg.TokenSecret, b[:tokenExpiryBytes+tokenNonceBytes]))
	return hex.EncodeToString(b[:])
}

// verifyToken reports whether label is a token we minted that has not yet
// expired at now, and returns its expiry.
func verifyToken(cfg Config, label string, now time.Time) (time.Time, bool) {
	if len(label) != tokenLen {
		return time.Time{}, false
	}
	var b [tokenBytes]byte
	for i := range tokenLen {
		// Lower-case only: callers lower-case DNS names and Host headers, and
		// this keeps one canonical spelling (and Redis key) per token.
		if c := label[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return time.Time{}, false
		}
	}
	if _, err := hex.Decode(b[:], []byte(label)); err != nil {
		return time.Time{}, false
	}
	signed := b[:tokenExpiryBytes+tokenNonceBytes]
	if !hmac.Equal(b[len(signed):], tokenMAC(cfg.TokenSecret, signed)) {
		return time.Time{}, false
	}
	expires := time.Unix(int64(binary.BigEndian.Uint32(b[:tokenExpiryBytes])), 0)
	if !now.Before(expires) {
		return time.Time{}, false
	}
	return expires, true
}

func tokenMAC(secret, msg []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(msg)
	return m.Sum(nil)[:tokenMACBytes]
}
