package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/redis/go-redis/v9"
)

// redisCertStorage implements certmagic.Storage on Redis, so that replicas
// share one certificate (and one ACME account) instead of each ordering its
// own. CertMagic keeps loaded certificates in its in-memory cache and only
// touches storage at startup, on renewal, and when checking whether another
// instance renewed, so TLS handshakes never reach Redis.
//
// Each file is a hash {v: value, m: modified unix nanos} at certFileKey(key).
// Directories are implicit, as in the Storage contract: certIndexKey is a set
// of every file key, which List/Exists/Delete filter by prefix. CertMagic
// stores a few dozen keys at most, so scanning the set is cheap.
type redisCertStorage struct {
	rdb   *redis.Client
	lease time.Duration // lock TTL; refreshed while held

	mu    sync.Mutex
	locks map[string]*certLock
}

type certLock struct {
	token string
	stop  chan struct{}
}

const (
	certIndexKey  = "certmagic:index"
	certLockLease = time.Minute
	certLockPoll  = time.Second
)

func certFileKey(key string) string  { return "certmagic:file:" + key }
func certLockKey(name string) string { return "certmagic:lock:" + name }

var _ certmagic.Storage = (*redisCertStorage)(nil)
var _ certmagic.LockLeaseRenewer = (*redisCertStorage)(nil)

func newRedisCertStorage(rdb *redis.Client) *redisCertStorage {
	return &redisCertStorage{rdb: rdb, lease: certLockLease, locks: map[string]*certLock{}}
}

func (s *redisCertStorage) Store(ctx context.Context, key string, value []byte) error {
	_, err := s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		p.HSet(ctx, certFileKey(key), "v", value, "m", time.Now().UnixNano())
		p.SAdd(ctx, certIndexKey, key)
		return nil
	})
	return err
}

func (s *redisCertStorage) Load(ctx context.Context, key string) ([]byte, error) {
	v, err := s.rdb.HGet(ctx, certFileKey(key), "v").Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, fs.ErrNotExist
	}
	return v, err
}

func (s *redisCertStorage) Delete(ctx context.Context, key string) error {
	keys, err := s.matching(ctx, key)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil // already gone, like os.RemoveAll
	}
	_, err = s.rdb.TxPipelined(ctx, func(p redis.Pipeliner) error {
		for _, k := range keys {
			p.Del(ctx, certFileKey(k))
			p.SRem(ctx, certIndexKey, k)
		}
		return nil
	})
	return err
}

func (s *redisCertStorage) Exists(ctx context.Context, key string) bool {
	keys, err := s.matching(ctx, key)
	return err == nil && len(keys) > 0
}

func (s *redisCertStorage) List(ctx context.Context, dir string, recursive bool) ([]string, error) {
	dir = cleanCertKey(dir)
	keys, err := s.matching(ctx, dir)
	if err != nil {
		return nil, err
	}
	prefix := dir + "/"
	if dir == "" {
		prefix = ""
	}
	seen := map[string]bool{}
	var out []string
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, k := range keys {
		rest, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue // k is dir itself, a file, which has no children
		}
		parts := strings.Split(rest, "/")
		if !recursive {
			add(prefix + parts[0])
			continue
		}
		// Recursive listings include the intermediate directories too, as
		// FileStorage's walk does.
		for i := range parts {
			add(prefix + strings.Join(parts[:i+1], "/"))
		}
	}
	if len(out) == 0 {
		return nil, fs.ErrNotExist
	}
	return out, nil
}

func (s *redisCertStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	vals, err := s.rdb.HMGet(ctx, certFileKey(key), "m").Result()
	if err != nil {
		return certmagic.KeyInfo{}, err
	}
	if m, ok := vals[0].(string); ok {
		nanos, err := strconv.ParseInt(m, 10, 64)
		if err != nil {
			return certmagic.KeyInfo{}, fmt.Errorf("stat %s: bad mtime %q", key, m)
		}
		size, err := s.rdb.HStrLen(ctx, certFileKey(key), "v").Result()
		if err != nil {
			return certmagic.KeyInfo{}, err
		}
		return certmagic.KeyInfo{Key: key, Modified: time.Unix(0, nanos), Size: size, IsTerminal: true}, nil
	}
	if s.Exists(ctx, key) {
		return certmagic.KeyInfo{Key: key}, nil
	}
	return certmagic.KeyInfo{}, fs.ErrNotExist
}

// matching returns the file keys equal to key or below it as a directory.
func (s *redisCertStorage) matching(ctx context.Context, key string) ([]string, error) {
	all, err := s.rdb.SMembers(ctx, certIndexKey).Result()
	if err != nil {
		return nil, err
	}
	key = cleanCertKey(key)
	var out []string
	for _, k := range all {
		if key == "" || k == key || strings.HasPrefix(k, key+"/") {
			out = append(out, k)
		}
	}
	return out, nil
}

// cleanCertKey normalizes a key to have no leading, trailing or doubled
// slashes; the root is "".
func cleanCertKey(key string) string {
	return strings.Trim(path.Clean("/"+key), "/")
}

// --- Locking -------------------------------------------------------------
//
// A lock is SET NX PX with a random owner token. While held, a goroutine
// keeps extending it, so a long ACME order can't lose it; if the holder dies,
// the lease runs out and another replica takes over. Unlock and renewal only
// act if the token still matches, so a replica can never release or extend a
// lock that expired and was taken by someone else.

var (
	// unlockScript deletes the lock only if we still own it.
	unlockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0`)
	// extendScript makes the lease at least ARGV[2] ms, only if we still own
	// the lock. It never shortens a longer lease set by RenewLockLease.
	extendScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) ~= ARGV[1] then
	return 0
end
if redis.call("PTTL", KEYS[1]) < tonumber(ARGV[2]) then
	redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 1`)
)

func (s *redisCertStorage) Lock(ctx context.Context, name string) error {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	token := hex.EncodeToString(b)

	for {
		ok, err := s.rdb.SetNX(ctx, certLockKey(name), token, s.lease).Result()
		if err != nil {
			return fmt.Errorf("lock %s: %w", name, err)
		}
		if ok {
			break
		}
		select {
		case <-time.After(certLockPoll):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	l := &certLock{token: token, stop: make(chan struct{})}
	s.mu.Lock()
	s.locks[name] = l
	s.mu.Unlock()
	go s.keepAlive(name, l)
	return nil
}

func (s *redisCertStorage) keepAlive(name string, l *certLock) {
	t := time.NewTicker(s.lease / 3)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			n, err := extendScript.Run(context.Background(), s.rdb,
				[]string{certLockKey(name)}, l.token, s.lease.Milliseconds()).Int()
			if err == nil && n == 0 {
				return // lost the lock (expired and taken); nothing to extend
			}
		case <-l.stop:
			return
		}
	}
}

func (s *redisCertStorage) Unlock(ctx context.Context, name string) error {
	s.mu.Lock()
	l, ok := s.locks[name]
	delete(s.locks, name)
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("unlock %s: not held", name)
	}
	close(l.stop)
	return unlockScript.Run(ctx, s.rdb, []string{certLockKey(name)}, l.token).Err()
}

// RenewLockLease extends a held lock to at least leaseDuration, for ACME
// retries that may outlast the regular keep-alive lease.
func (s *redisCertStorage) RenewLockLease(ctx context.Context, name string, leaseDuration time.Duration) error {
	s.mu.Lock()
	l, ok := s.locks[name]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("renew %s: not held", name)
	}
	n, err := extendScript.Run(ctx, s.rdb, []string{certLockKey(name)}, l.token,
		max(leaseDuration, s.lease).Milliseconds()).Int()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("renew %s: lock lost", name)
	}
	return nil
}
