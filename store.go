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

// Store holds captures and ACME challenge records. The memory backend suits a
// single instance; Redis lets several replicas share state, since capture and
// report for one token may land on different replicas.
type Store interface {
	// Record stores the capture for token until expires, replacing any
	// earlier capture (the last resolver to ask wins).
	Record(token string, r *Result, expires time.Time) bool
	// Get returns the capture for token, or ok=false if absent or expired.
	Get(token string) (*Result, bool)

	// ACME DNS-01 challenge records. CertMagic's solver writes the TXT here
	// and the DNS server serves it when Let's Encrypt validates. Several
	// values can be live at once (apex + wildcard in one order).
	AddTXT(name, value string) error
	DelTXT(name, value string) error
	GetTXT(name string) []string
}

// acmeTXTTTL bounds how long a challenge value outlives a missed CleanUp.
const acmeTXTTTL = 5 * time.Minute

// NewStore returns the backend named by cfg.Store.
func NewStore(cfg Config) Store {
	if cfg.Store == "redis" {
		return newRedisStore(cfg.RedisAddr, cfg.RedisURL)
	}
	return newMemStore()
}

type redisStore struct {
	rdb *redis.Client
}

// newRedisClient connects to Redis at url (redis://user:pass@host:port) if
// set, otherwise at the plain host:port addr.
func newRedisClient(addr, url string) *redis.Client {
	opts := &redis.Options{Addr: addr}
	if url != "" {
		var err error
		if opts, err = redis.ParseURL(url); err != nil {
			log.Fatalf("redis url: %v", err)
		}
	}
	return redis.NewClient(opts)
}

func newRedisStore(addr, url string) *redisStore {
	return &redisStore{rdb: newRedisClient(addr, url)}
}

func key(token string) string { return "edns:" + token }

// Record is a single SET: tokens are self-validating, so there is nothing to
// read first.
func (s *redisStore) Record(token string, r *Result, expires time.Time) bool {
	ttl := time.Until(expires)
	if ttl <= 0 {
		return false
	}
	data, _ := json.Marshal(r)
	if err := s.rdb.Set(ctx, key(token), data, ttl).Err(); err != nil {
		log.Printf("redis record %s: %v", token, err)
		return false
	}
	return true
}

func (s *redisStore) Get(token string) (*Result, bool) {
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

func acmeKey(name string) string {
	return "acme:" + strings.ToLower(strings.TrimSuffix(name, "."))
}

func (s *redisStore) AddTXT(name, value string) error {
	k := acmeKey(name)
	if err := s.rdb.SAdd(ctx, k, value).Err(); err != nil {
		return err
	}
	return s.rdb.Expire(ctx, k, acmeTXTTTL).Err()
}

func (s *redisStore) DelTXT(name, value string) error {
	return s.rdb.SRem(ctx, acmeKey(name), value).Err()
}

func (s *redisStore) GetTXT(name string) []string {
	vals, err := s.rdb.SMembers(ctx, acmeKey(name)).Result()
	if err != nil {
		log.Printf("redis txt %s: %v", name, err)
		return nil
	}
	return vals
}
