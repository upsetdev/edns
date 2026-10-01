package main

import (
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// storeBackend builds a fresh store plus a way to advance its clock.
type storeBackend struct {
	name string
	new  func(t *testing.T) (Store, func(time.Duration))
}

var storeBackends = []storeBackend{
	{"memory", func(t *testing.T) (Store, func(time.Duration)) {
		m := newMemStore()
		now := time.Now()
		m.now = func() time.Time { return now }
		return m, func(d time.Duration) { now = now.Add(d) }
	}},
	{"redis", func(t *testing.T) (Store, func(time.Duration)) {
		mr := miniredis.RunT(t)
		return newRedisStore(mr.Addr(), ""), mr.FastForward
	}},
}

func TestStoreRecordAndExpire(t *testing.T) {
	for _, b := range storeBackends {
		t.Run(b.name, func(t *testing.T) {
			store, advance := b.new(t)
			tok := newToken()

			if _, ok := store.Get(tok); ok {
				t.Fatal("Get of an unrecorded token returned ok")
			}
			if !store.Record(tok, &Result{Token: tok, ResolverIP: "198.51.100.7"}, time.Now().Add(time.Hour)) {
				t.Fatal("Record returned false")
			}
			if !store.Record(tok, &Result{Token: tok, ResolverIP: "198.51.100.8"}, time.Now().Add(time.Hour)) {
				t.Fatal("second Record returned false")
			}
			if res, ok := store.Get(tok); !ok || res.ResolverIP != "198.51.100.8" {
				t.Fatalf("Get = %+v, %v; want the last capture", res, ok)
			}

			advance(time.Hour + time.Second)
			if _, ok := store.Get(tok); ok {
				t.Fatal("capture outlived its token")
			}
		})
	}
}

func TestStoreRecordRejectsExpired(t *testing.T) {
	for _, b := range storeBackends {
		t.Run(b.name, func(t *testing.T) {
			store, _ := b.new(t)
			tok := newToken()
			if store.Record(tok, &Result{Token: tok}, time.Now().Add(-time.Second)) {
				t.Error("Record of an already-expired token returned true")
			}
			if _, ok := store.Get(tok); ok {
				t.Error("expired token was stored")
			}
		})
	}
}

func TestStoreTXT(t *testing.T) {
	for _, b := range storeBackends {
		t.Run(b.name, func(t *testing.T) {
			store, advance := b.new(t)
			name := "_acme-challenge.example.test."

			for _, v := range []string{"a", "b"} {
				if err := store.AddTXT(name, v); err != nil {
					t.Fatal(err)
				}
			}
			if got := store.GetTXT("_ACME-challenge.example.test"); len(got) != 2 {
				t.Fatalf("GetTXT = %v, want two values", got)
			}
			if err := store.DelTXT(name, "a"); err != nil {
				t.Fatal(err)
			}
			if got := store.GetTXT(name); len(got) != 1 || got[0] != "b" {
				t.Fatalf("GetTXT after DelTXT = %v, want [b]", got)
			}
			advance(6 * time.Minute)
			if got := store.GetTXT(name); len(got) != 0 {
				t.Fatalf("GetTXT after expiry = %v, want none", got)
			}
		})
	}
}

func TestMemStoreSweepsAndCaps(t *testing.T) {
	m := newMemStore()
	now := time.Now()
	m.now = func() time.Time { return now }

	for i := range memMaxEntries {
		m.caps[strconv.Itoa(i)] = memEntry{expires: now.Add(time.Minute)}
	}
	tok := newToken()
	if m.Record(tok, &Result{}, now.Add(time.Hour)) {
		t.Fatal("Record succeeded past the cap with nothing expired")
	}

	now = now.Add(2 * time.Minute) // everything already stored has expired
	if !m.Record(tok, &Result{}, now.Add(time.Hour)) {
		t.Fatal("Record failed after expired entries could be swept")
	}
	if len(m.caps) != 1 {
		t.Errorf("%d entries after sweep, want 1", len(m.caps))
	}
}
