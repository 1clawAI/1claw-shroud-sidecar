package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

func TestApplyAgentJWTFromRequestPrefersIncomingJWT(t *testing.T) {
	stale := makeTestJWT(time.Now().Add(-time.Hour))
	fresh := makeTestJWT(time.Now().Add(time.Hour))

	tm := NewTokenManager("https://api.1claw.co", "agent-id", "", stale, "")
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+fresh)

	got := applyAgentJWTFromRequest(req, tm, stale)
	if got != fresh {
		t.Fatalf("got %q, want fresh request JWT %q", got, fresh)
	}

	tok, err := tm.GetToken()
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if tok != fresh {
		t.Fatalf("TokenManager not hot-swapped, got %q", tok)
	}
}

func TestApplyAgentJWTFromRequestPrefersRefreshedHeader(t *testing.T) {
	stale := makeTestJWT(time.Now().Add(-time.Hour))
	fresh := makeTestJWT(time.Now().Add(2 * time.Hour))

	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	req.Header.Set("X-Refreshed-Agent-Token", fresh)
	req.Header.Set("Authorization", "Bearer "+stale)

	got := applyAgentJWTFromRequest(req, nil, stale)
	if got != fresh {
		t.Fatalf("got %q, want X-Refreshed-Agent-Token %q", got, fresh)
	}
}

func makeTestJWT(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payloadBytes, _ := json.Marshal(map[string]int64{"exp": exp.Unix()})
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".sig"
}
