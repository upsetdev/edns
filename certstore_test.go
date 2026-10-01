package main

import (
	"context"
	"errors"
	"io/fs"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestCertStorage(t *testing.T) (*redisCertStorage, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	return newRedisCertStorage(redis.NewClient(&redis.Options{Addr: mr.Addr()})), mr
}

func TestCertStorageFiles(t *testing.T) {
	s, _ := newTestCertStorage(t)
	c := context.Background()

	if _, err := s.Load(c, "certs/a/a.crt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Load of missing key: err = %v, want fs.ErrNotExist", err)
	}
	if _, err := s.Stat(c, "certs/a/a.crt"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Stat of missing key: err = %v, want fs.ErrNotExist", err)
	}

	before := time.Now()
	for _, k := range []string{"certs/a/a.crt", "certs/a/a.key", "certs/b/b.crt", "acme/account.json"} {
		if err := s.Store(c, k, []byte("data:"+k)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Store(c, "certs/a/a.crt", []byte("new")); err != nil {
		t.Fatal(err)
	}
	if v, err := s.Load(c, "certs/a/a.crt"); err != nil || string(v) != "new" {
		t.Fatalf("Load = %q, %v; want the overwritten value", v, err)
	}

	info, err := s.Stat(c, "certs/a/a.crt")
	if err != nil || !info.IsTerminal || info.Size != 3 || info.Modified.Before(before) {
		t.Fatalf("Stat file = %+v, %v", info, err)
	}
	if info, err := s.Stat(c, "certs/a"); err != nil || info.IsTerminal {
		t.Fatalf("Stat dir = %+v, %v; want a non-terminal key", info, err)
	}

	for k, want := range map[string]bool{
		"certs/a/a.crt": true, "certs/a": true, "certs": true, "/certs/": true,
		"cert": false, "certs/a/a": false, "certs/c": false,
	} {
		if got := s.Exists(c, k); got != want {
			t.Errorf("Exists(%q) = %v, want %v", k, got, want)
		}
	}

	list := func(dir string, recursive bool) []string {
		t.Helper()
		got, err := s.List(c, dir, recursive)
		if err != nil {
			t.Fatalf("List(%q, %v): %v", dir, recursive, err)
		}
		slices.Sort(got)
		return got
	}
	if got, want := list("certs", false), []string{"certs/a", "certs/b"}; !slices.Equal(got, want) {
		t.Errorf("List(certs) = %v, want %v", got, want)
	}
	if got, want := list("certs", true), []string{"certs/a", "certs/a/a.crt", "certs/a/a.key", "certs/b", "certs/b/b.crt"}; !slices.Equal(got, want) {
		t.Errorf("List(certs, recursive) = %v, want %v", got, want)
	}
	if got, want := list("", false), []string{"acme", "certs"}; !slices.Equal(got, want) {
		t.Errorf("List(root) = %v, want %v", got, want)
	}
	if _, err := s.List(c, "nope", false); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("List of missing dir: err = %v, want fs.ErrNotExist", err)
	}

	// Deleting a directory removes everything under it, and nothing else.
	if err := s.Delete(c, "certs/a"); err != nil {
		t.Fatal(err)
	}
	if s.Exists(c, "certs/a") || s.Exists(c, "certs/a/a.key") || !s.Exists(c, "certs/b/b.crt") {
		t.Fatal("Delete(dir) removed the wrong keys")
	}
	if err := s.Delete(c, "certs/a"); err != nil {
		t.Errorf("Delete of an already-deleted key: %v, want nil", err)
	}
}

func TestCertStorageLockIsExclusive(t *testing.T) {
	s, _ := newTestCertStorage(t)
	c := context.Background()

	if err := s.Lock(c, "issue_cert_example.test"); err != nil {
		t.Fatal(err)
	}
	// A second holder (another replica) waits until the context gives up.
	other := newRedisCertStorage(s.rdb)
	short, cancel := context.WithTimeout(c, 50*time.Millisecond)
	defer cancel()
	if err := other.Lock(short, "issue_cert_example.test"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("second Lock: err = %v, want it to block until the deadline", err)
	}
	// Different names don't contend.
	if err := other.Lock(c, "issue_cert_other.test"); err != nil {
		t.Fatal(err)
	}

	if err := s.Unlock(c, "issue_cert_example.test"); err != nil {
		t.Fatal(err)
	}
	if err := other.Lock(c, "issue_cert_example.test"); err != nil {
		t.Fatalf("Lock after Unlock: %v", err)
	}
	if err := s.Unlock(c, "never-locked"); err == nil {
		t.Error("Unlock of a lock we don't hold succeeded")
	}
}

func TestCertStorageExpiredLockIsNotReleasedByOldHolder(t *testing.T) {
	s, mr := newTestCertStorage(t)
	c := context.Background()

	// The holder stalls past its lease (no keep-alive tick in this window),
	// so another replica takes the lock over.
	if err := s.Lock(c, "l"); err != nil {
		t.Fatal(err)
	}
	mr.FastForward(certLockLease + time.Second)
	other := newRedisCertStorage(s.rdb)
	if err := other.Lock(c, "l"); err != nil {
		t.Fatalf("Lock after the lease expired: %v", err)
	}
	newOwner, _ := mr.Get(certLockKey("l"))

	// The stale holder's Unlock and renewal must not touch the new lock.
	if err := s.RenewLockLease(c, "l", time.Hour); err == nil {
		t.Error("RenewLockLease of a lost lock succeeded")
	}
	_ = s.Unlock(c, "l")
	if owner, _ := mr.Get(certLockKey("l")); owner != newOwner {
		t.Fatalf("old holder released or replaced the new holder's lock")
	}
}

func TestCertStorageLeaseOnlyGrows(t *testing.T) {
	s, mr := newTestCertStorage(t)
	c := context.Background()

	if err := s.Lock(c, "l"); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewLockLease(c, "l", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(certLockKey("l")); ttl != 10*time.Minute {
		t.Fatalf("TTL after RenewLockLease = %v, want 10m", ttl)
	}
	// The keep-alive extends to the regular lease; it must not cut the
	// longer one RenewLockLease set.
	tok := s.locks["l"].token
	if err := extendScript.Run(c, s.rdb, []string{certLockKey("l")}, tok, certLockLease.Milliseconds()).Err(); err != nil {
		t.Fatal(err)
	}
	if ttl := mr.TTL(certLockKey("l")); ttl != 10*time.Minute {
		t.Fatalf("TTL after keep-alive = %v, want it left at 10m", ttl)
	}
	if err := s.Unlock(c, "l"); err != nil {
		t.Fatal(err)
	}
	if mr.Exists(certLockKey("l")) {
		t.Fatal("Unlock left the lock in Redis")
	}
}
