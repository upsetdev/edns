package main

import (
	"testing"
	"time"
)

func TestStoreUpdateKeepsTTL(t *testing.T) {
	store, mr := newTestStore(t)
	store.Put(tok, &Result{Token: tok, CreatedAt: 42})
	mr.FastForward(10 * time.Minute)

	if !store.Update(tok, func(r *Result) { r.ResolverIP = "198.51.100.7" }) {
		t.Fatal("Update of a live token returned false")
	}
	res, ok := store.Get(tok)
	if !ok || res.ResolverIP != "198.51.100.7" || res.CreatedAt != 42 {
		t.Fatalf("after Update: %+v, ok=%v", res, ok)
	}
	if ttl := mr.TTL(key(tok)); ttl != 50*time.Minute {
		t.Errorf("TTL after Update = %v, want the original 50m remaining", ttl)
	}
}

func TestStoreUpdateDoesNotResurrect(t *testing.T) {
	store, mr := newTestStore(t)

	if store.Update(tok, func(*Result) {}) {
		t.Error("Update of a missing token returned true")
	}

	store.Put(tok, &Result{Token: tok})
	mr.FastForward(time.Hour + time.Second)
	if store.Update(tok, func(*Result) {}) {
		t.Error("Update of an expired token returned true")
	}
	if mr.Exists(key(tok)) {
		t.Error("Update recreated an expired token")
	}
}

func TestStoreTXTExpires(t *testing.T) {
	store, mr := newTestStore(t)
	name := "_acme-challenge.example.test."

	if err := store.AddTXT(name, "a"); err != nil {
		t.Fatal(err)
	}
	if err := store.AddTXT(name, "b"); err != nil {
		t.Fatal(err)
	}
	if got := store.GetTXT(name); len(got) != 2 {
		t.Fatalf("GetTXT = %v, want two values", got)
	}
	mr.FastForward(6 * time.Minute)
	if got := store.GetTXT(name); len(got) != 0 {
		t.Fatalf("GetTXT after expiry = %v, want none", got)
	}
}
