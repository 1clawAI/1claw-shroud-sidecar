package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// JWKSLOCK-L1. `refresh()` used to hold the cache's write lock across the
// whole network fetch. With a fallback URL and two attempts each at a 20s
// timeout that is up to ~80s, during which every chat and terminal JWT check
// blocks on `RLock` — which defeats the stale-serving behaviour it was added
// alongside: the keys were sitting there and nobody could read them.
//
// The property is that a reader gets served *while* a slow fetch is in
// flight, so the test makes the fetch slow and reads during it.
func TestSlowJWKSFetchDoesNotBlockReaders(t *testing.T) {
	release := make(chan struct{})
	var hits int32
	var hitsMu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsMu.Lock()
		hits++
		hitsMu.Unlock()
		<-release // Hold the request open, standing in for a hairpin timeout.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"keys":[]}`)
	}))
	defer srv.Close()

	cache := NewJWKSCache(srv.URL, 50*time.Millisecond)
	// Seed usable keys and let them go stale, so refresh() will fetch.
	cache.mu.Lock()
	cache.edKeys["seeded"] = make([]byte, 32)
	cache.fetchedAt = time.Now().Add(-time.Hour)
	cache.lastGoodAt = time.Now().Add(-time.Minute)
	cache.mu.Unlock()

	fetchDone := make(chan struct{})
	go func() {
		_ = cache.refresh()
		close(fetchDone)
	}()

	// Give the fetch time to be in flight.
	time.Sleep(100 * time.Millisecond)

	read := make(chan struct{})
	go func() {
		cache.mu.RLock()
		_ = cache.hasAnyKeysLocked()
		cache.mu.RUnlock()
		close(read)
	}()

	select {
	case <-read:
		// Good: a reader got the lock while the fetch was outstanding.
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("a JWT check blocked on the cache lock while a fetch was in flight — " +
			"refresh() is holding mu across the network call")
	}

	close(release)
	<-fetchDone
}

// A burst arriving at TTL expiry must make one upstream request, not one per
// connection: `fetchMu` serialises them without holding the read lock.
func TestConcurrentRefreshesMakeOneFetch(t *testing.T) {
	var hits int
	var hitsMu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitsMu.Lock()
		hits++
		hitsMu.Unlock()
		time.Sleep(80 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		// A real Ed25519 JWK so the refresh succeeds and marks the cache fresh.
		fmt.Fprint(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA",`+
			`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`)
	}))
	defer srv.Close()

	cache := NewJWKSCache(srv.URL, time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = cache.refresh()
		}()
	}
	wg.Wait()

	hitsMu.Lock()
	defer hitsMu.Unlock()
	if hits != 1 {
		t.Fatalf("8 concurrent refreshes made %d upstream fetches, want 1", hits)
	}
}

// Serving stale keys through a short outage is deliberate. Serving them
// forever is not: a key removed upstream would keep verifying tokens for as
// long as the fetch kept failing.
func TestStaleKeysAreNotServedForever(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cache := NewJWKSCache(srv.URL, 50*time.Millisecond)
	cache.mu.Lock()
	cache.edKeys["seeded"] = make([]byte, 32)
	cache.fetchedAt = time.Now().Add(-time.Hour)
	cache.mu.Unlock()

	// Within the stale window: keep serving.
	cache.mu.Lock()
	cache.lastGoodAt = time.Now().Add(-time.Minute)
	cache.mu.Unlock()
	if err := cache.refresh(); err != nil {
		t.Fatalf("a brief outage should serve stale keys, got %v", err)
	}

	// Beyond it: fail closed.
	cache.mu.Lock()
	cache.lastGoodAt = time.Now().Add(-2 * jwksMaxStale)
	cache.fetchedAt = time.Now().Add(-time.Hour)
	cache.mu.Unlock()
	if err := cache.refresh(); err == nil {
		t.Fatalf("keys stale beyond %v must stop being served", jwksMaxStale)
	}
}
