package main

import (
	"sync"
	"time"
)

// memMaxEntries bounds the memory store (about 300 bytes per capture, so
// roughly 30 MB). Only tokens we minted can create entries, and minting is
// rate-limited per client, so reaching it takes a distributed effort; past it
// new captures are refused while existing ones are kept.
const memMaxEntries = 100000

// memSweepInterval is how often expired entries are dropped.
const memSweepInterval = time.Minute

// memStore keeps everything in process memory. State is lost on restart,
// which only affects lookups in flight at that moment. It cannot be shared
// between replicas; use Redis for that.
type memStore struct {
	mu        sync.Mutex
	caps      map[string]memEntry
	txt       map[string]map[string]time.Time // acme name -> value -> expiry
	now       func() time.Time
	lastSweep time.Time
}

type memEntry struct {
	res     Result
	expires time.Time
}

func newMemStore() *memStore {
	return &memStore{
		caps: map[string]memEntry{},
		txt:  map[string]map[string]time.Time{},
		now:  time.Now,
	}
}

func (m *memStore) Record(token string, r *Result, expires time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if !now.Before(expires) {
		return false
	}
	m.maybeSweepLocked(now)
	if e, ok := m.caps[token]; ok && now.Before(e.expires) {
		return false // keep the first capture
	}
	if len(m.caps) >= memMaxEntries {
		m.sweepLocked(now)
		if len(m.caps) >= memMaxEntries {
			return false
		}
	}
	m.caps[token] = memEntry{res: *r, expires: expires}
	return true
}

func (m *memStore) Get(token string) (*Result, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.caps[token]
	if !ok || !m.now().Before(e.expires) {
		return nil, false
	}
	res := e.res
	return &res, true
}

func (m *memStore) AddTXT(name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := acmeKey(name)
	if m.txt[k] == nil {
		m.txt[k] = map[string]time.Time{}
	}
	m.txt[k][value] = m.now().Add(acmeTXTTTL)
	return nil
}

func (m *memStore) DelTXT(name, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := acmeKey(name)
	delete(m.txt[k], value)
	if len(m.txt[k]) == 0 {
		delete(m.txt, k)
	}
	return nil
}

func (m *memStore) GetTXT(name string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	var out []string
	for v, exp := range m.txt[acmeKey(name)] {
		if now.Before(exp) {
			out = append(out, v)
		}
	}
	return out
}

// maybeSweepLocked drops expired entries at most once per memSweepInterval,
// piggybacking on writes so no background goroutine is needed.
func (m *memStore) maybeSweepLocked(now time.Time) {
	if now.Sub(m.lastSweep) >= memSweepInterval {
		m.sweepLocked(now)
	}
}

func (m *memStore) sweepLocked(now time.Time) {
	for k, e := range m.caps {
		if !now.Before(e.expires) {
			delete(m.caps, k)
		}
	}
	for k, vals := range m.txt {
		for v, exp := range vals {
			if !now.Before(exp) {
				delete(vals, v)
			}
		}
		if len(vals) == 0 {
			delete(m.txt, k)
		}
	}
	m.lastSweep = now
}
