package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A runtime JWT with the given expiry. Only the payload is read here.
func jwtExpiring(at time.Time) string {
	payload := fmt.Sprintf(`{"sub":"agent:test","exp":%d}`, at.Unix())
	return "eyJhbGciOiJFZERTQSJ9." +
		base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

// The sidecar used to hand back an expired runtime JWT with a comment saying a
// refresh "requires Vault/chat to push a new one". Every call the agent made
// through it — memory, intents, execute, secrets — therefore 401'd about two
// hours into a runtime's life unless somebody happened to open dashboard chat,
// whose proxy pushes a fresh token. The only remedy the user had was to
// restart the runtime.
func TestExpiringRuntimeTokenIsRenewed(t *testing.T) {
	fresh := jwtExpiring(time.Now().Add(2 * time.Hour))
	var gotAuth, gotRuntimeHeader, gotPath string

	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotRuntimeHeader = r.Header.Get("X-1Claw-Runtime-Id")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fresh, "expires_in": 7200,
		})
	}))
	defer vault.Close()

	stale := jwtExpiring(time.Now().Add(10 * time.Second)) // inside the 60s skew
	tm := NewTokenManager(vault.URL, "agent-1", "", stale, "runtime-abc")

	tok, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if tok != fresh {
		t.Fatalf("still handing back the old token; renewal did not happen")
	}
	if gotPath != "/v1/runtimes/runtime-abc/agent-token/renew" {
		t.Fatalf("renewed against %q", gotPath)
	}
	// Renewal is authenticated by the credential it replaces.
	if gotAuth != "Bearer "+stale {
		t.Fatalf("renew was not authenticated with the current token: %q", gotAuth)
	}
	// Vault requires this to match for runtime-bound tokens; without it the
	// renewal 401s and the expiry is back.
	if gotRuntimeHeader != "runtime-abc" {
		t.Fatalf("X-1Claw-Runtime-Id was %q", gotRuntimeHeader)
	}

	// And it is cached, not re-fetched on every call.
	again, _ := tm.GetToken()
	if again != fresh {
		t.Fatalf("second GetToken returned %q", again)
	}
}

func TestHealthyTokenIsNotRenewed(t *testing.T) {
	hit := false
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(500)
	}))
	defer vault.Close()

	good := jwtExpiring(time.Now().Add(90 * time.Minute))
	tm := NewTokenManager(vault.URL, "agent-1", "", good, "runtime-abc")
	tok, err := tm.GetToken()
	if err != nil || tok != good {
		t.Fatalf("got %q, %v", tok, err)
	}
	if hit {
		t.Fatal("renewed a token with 90 minutes left — that is per-call load on Vault for nothing")
	}
}

// A failed renewal must not make things worse than they were.
func TestRenewalFailureFallsBackToTheExistingToken(t *testing.T) {
	vault := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"nope"}`, http.StatusForbidden)
	}))
	defer vault.Close()

	stale := jwtExpiring(time.Now().Add(10 * time.Second))
	tm := NewTokenManager(vault.URL, "agent-1", "", stale, "runtime-abc")
	tok, err := tm.GetToken()
	if err != nil {
		t.Fatalf("a failed renewal must not turn into an error: %v", err)
	}
	if tok != stale {
		t.Fatalf("expected the existing token back, got %q", tok)
	}
}

// Without a runtime id there is nothing to renew against; it must degrade to
// the old behaviour rather than calling a nonsense URL.
func TestNoRuntimeIdDegradesQuietly(t *testing.T) {
	stale := jwtExpiring(time.Now().Add(10 * time.Second))
	tm := NewTokenManager("https://api.invalid", "agent-1", "", stale, "")
	tok, err := tm.GetToken()
	if err != nil || tok != stale {
		t.Fatalf("got %q, %v", tok, err)
	}
	_, rerr := tm.renewRuntimeToken(stale)
	if rerr == nil || !strings.Contains(rerr.Error(), "runtime id") {
		t.Fatalf("expected a clear 'no runtime id' error, got %v", rerr)
	}
}
