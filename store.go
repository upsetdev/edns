package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var ctx = context.Background()

// Result holds what we learned about the DNS path used to resolve a token.
type Result struct {
	Token      string `json:"token"`
	ResolverIP string `json:"resolver_ip"`          // recursive resolver that queried us
	ECS        string `json:"ecs,omitempty"`        // EDNS Client Subnet, e.g. 1.2.3.0/24
	ECSFamily  string `json:"ecs_family,omitempty"` // ipv4 | ipv6 | none
	Resolved   bool   `json:"resolved"`             // true once a DNS query landed
	CreatedAt  int64  `json:"created_at"`           // unix seconds
}

// Store persists short-lived tokens in Redis so that any replica can mint,
// capture, and report on the same token (the three steps may hit different
// replicas behind the Swarm load balancer).
type Store struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewStore connects to Redis at url (redis://user:pass@host:port) if set,
// otherwise at the plain host:port addr.
func NewStore(addr, url string, ttl time.Duration) *Store {
	opts := &redis.Options{Addr: addr}
	if url != "" {
		var err error
		if opts, err = redis.ParseURL(url); err != nil {
			log.Fatalf("redis url: %v", err)
		}
	}
	return &Store{
		rdb: redis.NewClient(opts),
		ttl: ttl,
	}
}

func key(token string) string { return "edns:" + token }

// Put stores a fresh token with the configured TTL.
func (s *Store) Put(token string, r *Result) {
	data, _ := json.Marshal(r)
	if err := s.rdb.Set(ctx, key(token), data, s.ttl).Err(); err != nil {
		log.Printf("redis put %s: %v", token, err)
	}
}

// Update mutates an existing token in place, preserving its original TTL.
// Returns false if the token is unknown or expired.
//
// This is a plain GET + SET XX KEEPTTL rather than a WATCH transaction: it is
// two commands instead of ~6 (cheaper on per-command Redis like Upstash), and
// XX guarantees we never resurrect a token that expired in between. Concurrent
// captures for one token may race, but they write the same fields, so the
// last writer winning is harmless.
func (s *Store) Update(token string, fn func(*Result)) bool {
	k := key(token)
	val, err := s.rdb.Get(ctx, k).Result()
	if errors.Is(err, redis.Nil) {
		return false
	}
	if err != nil {
		log.Printf("redis update %s: %v", token, err)
		return false
	}
	var res Result
	if err := json.Unmarshal([]byte(val), &res); err != nil {
		return false
	}
	fn(&res)
	data, _ := json.Marshal(&res)
	err = s.rdb.SetArgs(ctx, k, data, redis.SetArgs{Mode: "XX", KeepTTL: true}).Err()
	if errors.Is(err, redis.Nil) {
		return false // expired between GET and SET
	}
	if err != nil {
		log.Printf("redis update %s: %v", token, err)
		return false
	}
	return true
}

// --- ACME DNS-01 challenge records ---------------------------------------
//
// CertMagic's solver writes the challenge TXT here; the DNS server reads it
// when Let's Encrypt validates. They live in Redis so the value is visible no
// matter which replica answers the validating query. Multiple values can be
// live at once (apex + wildcard in one order), so we use a set.

func acmeKey(name string) string {
	return "acme:" + strings.ToLower(strings.TrimSuffix(name, "."))
}

func (s *Store) AddTXT(name, value string) error {
	k := acmeKey(name)
	if err := s.rdb.SAdd(ctx, k, value).Err(); err != nil {
		return err
	}
	return s.rdb.Expire(ctx, k, 5*time.Minute).Err()
}

func (s *Store) DelTXT(name, value string) error {
	return s.rdb.SRem(ctx, acmeKey(name), value).Err()
}

func (s *Store) GetTXT(name string) []string {
	vals, err := s.rdb.SMembers(ctx, acmeKey(name)).Result()
	if err != nil {
		log.Printf("redis txt %s: %v", name, err)
		return nil
	}
	return vals
}

// Get returns a copy of the stored result, or ok=false if absent/expired.
func (s *Store) Get(token string) (*Result, bool) {
	val, err := s.rdb.Get(ctx, key(token)).Result()
	if errors.Is(err, redis.Nil) {
		return nil, false
	}
	if err != nil {
		log.Printf("redis get %s: %v", token, err)
		return nil, false
	}
	var res Result
	if err := json.Unmarshal([]byte(val), &res); err != nil {
		return nil, false
	}
	return &res, true
}
