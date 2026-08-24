package main

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Scratch LRU Tests
// ============================================================

func TestScratchLRU_InsertAndGet(t *testing.T) {
	lru := NewScratchLRU(100, 1024*1024)

	lru.Put("ns1", "key1", json.RawMessage(`"hello"`), nil)

	entry, ok := lru.Get("ns1", "key1")
	if !ok {
		t.Fatal("expected entry to be found")
	}
	if string(entry.value) != `"hello"` {
		t.Errorf("value = %s, want %q", string(entry.value), `"hello"`)
	}
	if lru.Len() != 1 {
		t.Errorf("Len() = %d, want 1", lru.Len())
	}
}

func TestScratchLRU_GetMiss(t *testing.T) {
	lru := NewScratchLRU(100, 1024*1024)

	_, ok := lru.Get("ns1", "missing")
	if ok {
		t.Error("expected miss for non-existent key")
	}
}

func TestScratchLRU_Update(t *testing.T) {
	lru := NewScratchLRU(100, 1024*1024)

	lru.Put("ns1", "key1", json.RawMessage(`"v1"`), nil)
	lru.Put("ns1", "key1", json.RawMessage(`"v2"`), nil)

	entry, ok := lru.Get("ns1", "key1")
	if !ok {
		t.Fatal("expected entry")
	}
	if string(entry.value) != `"v2"` {
		t.Errorf("value = %s, want %q", string(entry.value), `"v2"`)
	}
	if lru.Len() != 1 {
		t.Errorf("Len() = %d, want 1 (update shouldn't add)", lru.Len())
	}
}

func TestScratchLRU_Delete(t *testing.T) {
	lru := NewScratchLRU(100, 1024*1024)
	lru.Put("ns1", "key1", json.RawMessage(`"v"`), nil)

	deleted := lru.Delete("ns1", "key1")
	if !deleted {
		t.Error("expected delete to return true")
	}
	if lru.Len() != 0 {
		t.Errorf("Len() = %d after delete", lru.Len())
	}

	_, ok := lru.Get("ns1", "key1")
	if ok {
		t.Error("expected miss after delete")
	}

	if lru.Delete("ns1", "key1") {
		t.Error("deleting non-existent should return false")
	}
}

func TestScratchLRU_EvictionByCount(t *testing.T) {
	lru := NewScratchLRU(3, 1024*1024)

	lru.Put("ns", "a", json.RawMessage(`"1"`), nil)
	lru.Put("ns", "b", json.RawMessage(`"2"`), nil)
	lru.Put("ns", "c", json.RawMessage(`"3"`), nil)
	lru.Put("ns", "d", json.RawMessage(`"4"`), nil) // evicts "a"

	if lru.Len() != 3 {
		t.Errorf("Len() = %d, want 3", lru.Len())
	}

	if _, ok := lru.Get("ns", "a"); ok {
		t.Error("'a' should have been evicted")
	}
	if _, ok := lru.Get("ns", "d"); !ok {
		t.Error("'d' should be present")
	}
}

func TestScratchLRU_EvictionBySize(t *testing.T) {
	lru := NewScratchLRU(1000, 50) // 50 bytes max

	lru.Put("ns", "a", json.RawMessage(`"aaaaaaaaaa"`), nil)                       // ~15 bytes
	lru.Put("ns", "b", json.RawMessage(`"bbbbbbbbbb"`), nil)                       // ~15 bytes
	lru.Put("ns", "c", json.RawMessage(`"cccccccccccccccccccccccccccccc"`), nil)   // ~35 bytes, evicts a and b

	if lru.TotalBytes() > 50 {
		t.Errorf("TotalBytes() = %d, should be <= 50", lru.TotalBytes())
	}
}

func TestScratchLRU_LRUOrder(t *testing.T) {
	lru := NewScratchLRU(3, 1024*1024)

	lru.Put("ns", "a", json.RawMessage(`"1"`), nil)
	lru.Put("ns", "b", json.RawMessage(`"2"`), nil)
	lru.Put("ns", "c", json.RawMessage(`"3"`), nil)

	// Access "a" to make it recently used
	lru.Get("ns", "a")

	// Insert "d" — should evict "b" (least recently used)
	lru.Put("ns", "d", json.RawMessage(`"4"`), nil)

	if _, ok := lru.Get("ns", "b"); ok {
		t.Error("'b' should have been evicted (LRU)")
	}
	if _, ok := lru.Get("ns", "a"); !ok {
		t.Error("'a' should be present (was accessed recently)")
	}
}

func TestScratchLRU_TTLExpiry(t *testing.T) {
	lru := NewScratchLRU(100, 1024*1024)

	ttl := 50 * time.Millisecond
	lru.Put("ns", "ephemeral", json.RawMessage(`"temp"`), &ttl)

	entry, ok := lru.Get("ns", "ephemeral")
	if !ok || entry == nil {
		t.Fatal("expected entry before TTL expires")
	}

	time.Sleep(60 * time.Millisecond)

	_, ok = lru.Get("ns", "ephemeral")
	if ok {
		t.Error("expected miss after TTL expired")
	}
}

func TestScratchLRU_ListKeys(t *testing.T) {
	lru := NewScratchLRU(100, 1024*1024)

	lru.Put("ns1", "a", json.RawMessage(`"1"`), nil)
	lru.Put("ns1", "b", json.RawMessage(`"2"`), nil)
	lru.Put("ns2", "c", json.RawMessage(`"3"`), nil)

	keys := lru.ListKeys("ns1")
	if len(keys) != 2 {
		t.Errorf("ListKeys(ns1) returned %d keys, want 2", len(keys))
	}

	keys2 := lru.ListKeys("ns2")
	if len(keys2) != 1 {
		t.Errorf("ListKeys(ns2) returned %d keys, want 1", len(keys2))
	}

	keys3 := lru.ListKeys("ns3")
	if len(keys3) != 0 {
		t.Errorf("ListKeys(ns3) returned %d keys, want 0", len(keys3))
	}
}

func TestScratchLRU_NamespaceIsolation(t *testing.T) {
	lru := NewScratchLRU(100, 1024*1024)

	lru.Put("ns1", "key", json.RawMessage(`"val1"`), nil)
	lru.Put("ns2", "key", json.RawMessage(`"val2"`), nil)

	e1, ok1 := lru.Get("ns1", "key")
	e2, ok2 := lru.Get("ns2", "key")
	if !ok1 || !ok2 {
		t.Fatal("both entries should exist")
	}
	if string(e1.value) != `"val1"` || string(e2.value) != `"val2"` {
		t.Error("namespaces should be isolated")
	}
}

// ============================================================
// Inbound Auth Tests
// ============================================================

func TestInboundAuth_Public(t *testing.T) {
	auth := NewInboundAuth("public", "", "https://api.1claw.xyz")

	req := httptest.NewRequest("GET", "/test", nil)
	ok, reason := auth.Authenticate(req)
	if !ok {
		t.Errorf("public auth should pass, got reason: %s", reason)
	}
}

func TestInboundAuth_APIKey_Valid(t *testing.T) {
	key := "rk_test_secret_key_12345"
	hash := HashAPIKey(key)
	auth := NewInboundAuth("api_key", hash, "https://api.1claw.xyz")

	// Via Authorization header
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	ok, reason := auth.Authenticate(req)
	if !ok {
		t.Errorf("valid API key via Bearer should pass, got reason: %s", reason)
	}

	// Via X-API-Key header
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("X-API-Key", key)
	ok2, reason2 := auth.Authenticate(req2)
	if !ok2 {
		t.Errorf("valid API key via X-API-Key should pass, got reason: %s", reason2)
	}
}

func TestInboundAuth_APIKey_Invalid(t *testing.T) {
	hash := HashAPIKey("correct_key")
	auth := NewInboundAuth("api_key", hash, "https://api.1claw.xyz")

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer wrong_key")
	ok, _ := auth.Authenticate(req)
	if ok {
		t.Error("invalid API key should fail")
	}
}

func TestInboundAuth_APIKey_Missing(t *testing.T) {
	hash := HashAPIKey("some_key")
	auth := NewInboundAuth("api_key", hash, "https://api.1claw.xyz")

	req := httptest.NewRequest("GET", "/test", nil)
	ok, reason := auth.Authenticate(req)
	if ok {
		t.Error("missing API key should fail")
	}
	if reason != "missing API key" {
		t.Errorf("reason = %q", reason)
	}
}

func TestInboundAuth_APIKey_EmptyHashFailsClosed(t *testing.T) {
	auth := NewInboundAuth("api_key", "", "https://api.1claw.xyz")

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer any_key")
	ok, reason := auth.Authenticate(req)
	if ok {
		t.Fatal("api_key mode with empty hash must fail closed")
	}
	if reason != "inbound API key not provisioned" {
		t.Errorf("reason = %q", reason)
	}
}

func TestInboundAuth_JWT_RejectsUnsigned(t *testing.T) {
	auth := NewInboundAuth("jwt", "", "https://api.1claw.xyz")
	// Inject empty cache that will fail refresh (fail-closed).
	auth.jwksCache = &JWKSCache{
		keys:   map[string]*rsa.PublicKey{},
		edKeys: map[string]ed25519.PublicKey{},
		url:    "http://127.0.0.1:1/jwks", // unreachable
		ttl:    time.Hour,
		client: &http.Client{Timeout: 50 * time.Millisecond},
	}

	// Structurally valid but unsigned/forged JWT must be rejected.
	forged := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.c2lnbmF0dXJl"
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	ok, reason := auth.Authenticate(req)
	if ok {
		t.Errorf("forged JWT must be rejected, got ok with reason %q", reason)
	}
}

func TestInboundAuth_JWT_ValidSigned(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	cache := &JWKSCache{
		keys:      map[string]*rsa.PublicKey{"test": &priv.PublicKey},
		edKeys:    map[string]ed25519.PublicKey{},
		fetchedAt: time.Now(),
		ttl:       time.Hour,
		url:       "inline",
		client:    &http.Client{},
	}
	auth := NewInboundAuth("jwt", "", "https://api.1claw.xyz").WithJWKSCache(cache)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"test"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"sub":"user:test","exp":%d,"iss":"https://api.1claw.xyz"}`,
		time.Now().Add(time.Hour).Unix(),
	)))
	signingInput := header + "." + payload
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	token := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	ok, reason := auth.Authenticate(req)
	if !ok {
		t.Fatalf("valid signed JWT should pass, got reason: %s", reason)
	}
}

func TestInboundAuth_JWT_Invalid(t *testing.T) {
	auth := NewInboundAuth("jwt", "", "https://api.1claw.xyz")

	// Missing Bearer
	req := httptest.NewRequest("GET", "/test", nil)
	ok, _ := auth.Authenticate(req)
	if ok {
		t.Error("missing token should fail")
	}

	// Malformed JWT (not 3 parts)
	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("Authorization", "Bearer not-a-jwt")
	ok2, _ := auth.Authenticate(req2)
	if ok2 {
		t.Error("malformed JWT should fail")
	}
}

func TestLoadConfigListenAddrLoopback(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "")
	cfg := loadConfig()
	if cfg.ListenAddr != "127.0.0.1:8080" {
		t.Fatalf("default LISTEN_ADDR must be loopback, got %q", cfg.ListenAddr)
	}
}

// ============================================================
// Route Separation Tests
// ============================================================

func TestRouteSeparation_MemoryBlockedOnInbound(t *testing.T) {
	innerHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	})

	mux := BuildInboundMux(innerHandler)

	blockedPaths := []string{"/memory/ns1", "/memory/ns1/key1", "/intents/transactions", "/execute", "/healthz"}
	for _, path := range blockedPaths {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("path %s should be blocked on :8081, got %d", path, w.Code)
		}
	}

	// Non-blocked paths should pass through
	allowedPaths := []string{"/", "/some-api", "/.well-known/agent.json"}
	for _, path := range allowedPaths {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("path %s should be allowed on :8081, got %d", path, w.Code)
		}
	}
}

// ============================================================
// Header Stripping Tests
// ============================================================

func TestHeaderStripping(t *testing.T) {
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("X-Forwarded-Host", "evil.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Real-Ip", "5.6.7.8")
	req.Header.Set("X-Shroud-Agent-Key", "agent:key")
	req.Header.Set("X-Shroud-Api-Key", "sk-secret")
	req.Header.Set("X-Custom-Header", "keep-me")
	req.Header.Set("Content-Type", "application/json")

	StripSensitiveHeaders(req)

	stripped := []string{
		"Authorization",
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-Ip",
		"X-Shroud-Agent-Key",
		"X-Shroud-Api-Key",
	}
	for _, h := range stripped {
		if req.Header.Get(h) != "" {
			t.Errorf("header %s should be stripped, got %q", h, req.Header.Get(h))
		}
	}

	kept := []string{"X-Custom-Header", "Content-Type"}
	for _, h := range kept {
		if req.Header.Get(h) == "" {
			t.Errorf("header %s should be kept", h)
		}
	}
}

// ============================================================
// Rate Limiter Tests
// ============================================================

func TestRateLimiter_AllowsWithinLimit(t *testing.T) {
	rl := NewRateLimiter(10, 10)

	for i := 0; i < 10; i++ {
		if !rl.Allow("1.2.3.4") {
			t.Errorf("request %d should be allowed within burst", i)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := NewRateLimiter(10, 5)

	for i := 0; i < 5; i++ {
		rl.Allow("1.2.3.4")
	}

	if rl.Allow("1.2.3.4") {
		t.Error("6th request should be blocked after exhausting burst")
	}
}

func TestRateLimiter_DifferentIPs(t *testing.T) {
	rl := NewRateLimiter(10, 2)

	rl.Allow("1.1.1.1")
	rl.Allow("1.1.1.1")

	if !rl.Allow("2.2.2.2") {
		t.Error("different IP should have its own bucket")
	}
}

// ============================================================
// Memory Handler Tests (with mock upstream)
// ============================================================

func TestMemoryHandler_ScratchPutAndGet(t *testing.T) {
	activity := NewActivityTracker()
	scratch := NewScratchLRU(100, 1024*1024)
	tm := NewTokenManager("http://localhost", "agent-1", "key-1", "static-token", "")

	handler := NewMemoryHandler(tm, "http://localhost", "agent-1", scratch, activity)

	// PUT scratch entry
	putBody := `{"value":"test-value","tier":"scratch","ttl_seconds":300}`
	putReq := httptest.NewRequest("PUT", "/memory/ns1/key1", strings.NewReader(putBody))
	putW := httptest.NewRecorder()
	handler.ServeHTTP(putW, putReq)

	if putW.Code != 200 {
		t.Errorf("PUT scratch: status = %d, body = %s", putW.Code, putW.Body.String())
	}

	var putResp map[string]string
	json.Unmarshal(putW.Body.Bytes(), &putResp)
	if putResp["tier"] != "scratch" {
		t.Errorf("PUT response tier = %q", putResp["tier"])
	}

	// GET should return from scratch
	getReq := httptest.NewRequest("GET", "/memory/ns1/key1", nil)
	getW := httptest.NewRecorder()
	handler.ServeHTTP(getW, getReq)

	if getW.Code != 200 {
		t.Errorf("GET scratch: status = %d", getW.Code)
	}
	if getW.Header().Get("X-1Claw-Tier") != "scratch" {
		t.Errorf("expected X-1Claw-Tier: scratch header")
	}

	var getResp map[string]interface{}
	json.Unmarshal(getW.Body.Bytes(), &getResp)
	if getResp["tier"] != "scratch" {
		t.Errorf("GET response tier = %v", getResp["tier"])
	}
}

func TestMemoryHandler_DeleteScratch(t *testing.T) {
	activity := NewActivityTracker()
	scratch := NewScratchLRU(100, 1024*1024)
	tm := NewTokenManager("http://localhost", "agent-1", "key-1", "static-token", "")

	handler := NewMemoryHandler(tm, "http://localhost", "agent-1", scratch, activity)

	// PUT entry
	putReq := httptest.NewRequest("PUT", "/memory/ns1/key1", strings.NewReader(`{"value":"test","tier":"scratch"}`))
	handler.ServeHTTP(httptest.NewRecorder(), putReq)

	// Verify it exists
	if scratch.Len() != 1 {
		t.Fatal("expected 1 entry in scratch")
	}

	// DELETE — this also tries to proxy to Vault (which will fail), but scratch entry should be removed
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	handler2 := NewMemoryHandler(tm, upstream.URL, "agent-1", scratch, activity)
	delReq := httptest.NewRequest("DELETE", "/memory/ns1/key1", nil)
	delW := httptest.NewRecorder()
	handler2.ServeHTTP(delW, delReq)

	// Scratch entry should be gone
	if _, ok := scratch.Get("ns1", "key1"); ok {
		t.Error("scratch entry should be deleted")
	}
}

// ============================================================
// Activity Tracker Tests
// ============================================================

func TestActivityTracker(t *testing.T) {
	tracker := NewActivityTracker()

	before := tracker.LastActivity()
	time.Sleep(10 * time.Millisecond)
	tracker.Touch()
	after := tracker.LastActivity()

	if !after.After(before) {
		t.Error("Touch() should update last activity")
	}

	idle := tracker.IdleDuration()
	if idle > time.Second {
		t.Errorf("idle duration should be small, got %v", idle)
	}
}

// ============================================================
// Secret Mounts Parse Tests
// ============================================================

func TestParseSecretMounts_Valid(t *testing.T) {
	raw := `[{"path":"api-keys/openai","mount":"/run/secrets/openai"},{"path":"db/password","mount":"/run/secrets/db"}]`
	mounts, err := ParseSecretMounts(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mounts) != 2 {
		t.Fatalf("expected 2 mounts, got %d", len(mounts))
	}
	if mounts[0].Path != "api-keys/openai" || mounts[0].Mount != "/run/secrets/openai" {
		t.Errorf("mount[0] = %+v", mounts[0])
	}
}

func TestParseSecretMounts_Empty(t *testing.T) {
	mounts, err := ParseSecretMounts("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if mounts != nil {
		t.Errorf("expected nil for empty string, got %v", mounts)
	}
}

func TestParseSecretMounts_InvalidJSON(t *testing.T) {
	_, err := ParseSecretMounts("not json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseSecretMounts_MissingFields(t *testing.T) {
	_, err := ParseSecretMounts(`[{"path":"foo"}]`)
	if err == nil {
		t.Error("expected error when mount field missing")
	}
}

// ============================================================
// Token Manager Tests
// ============================================================

func TestTokenManager_StaticToken(t *testing.T) {
	tm := NewTokenManager("http://localhost", "agent-1", "", "my-static-jwt", "")

	token, err := tm.GetToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "my-static-jwt" {
		t.Errorf("token = %q, want %q", token, "my-static-jwt")
	}
}

func TestTokenManager_Exchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/auth/agent-token" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "jwt-from-exchange",
			"expires_in":   3600,
			"agent_id":     "agent-1",
		})
	}))
	defer server.Close()

	tm := NewTokenManager(server.URL, "agent-1", "ocv_test_key", "", "")

	token, err := tm.GetToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "jwt-from-exchange" {
		t.Errorf("token = %q, want %q", token, "jwt-from-exchange")
	}
}

// ============================================================
// Agent Card Cache Tests
// ============================================================

func TestAgentCardCache(t *testing.T) {
	cache := &agentCardCache{}

	_, ok := cache.Get()
	if ok {
		t.Error("empty cache should return false")
	}

	cache.Set([]byte(`{"name":"test-agent"}`))

	data, ok := cache.Get()
	if !ok {
		t.Error("cache should return data after Set")
	}
	if string(data) != `{"name":"test-agent"}` {
		t.Errorf("cache data = %s", string(data))
	}

	cache.Clear()
	_, ok = cache.Get()
	if ok {
		t.Error("cache should be empty after Clear")
	}
}

// ============================================================
// Config Loading Tests (extended)
// ============================================================

func TestLoadConfigRuntimeFields(t *testing.T) {
	t.Setenv("LISTEN_ADDR", ":9090")
	t.Setenv("INBOUND_ADDR", ":9091")
	t.Setenv("ONECLAW_BASE_URL", "https://api.test.xyz")
	t.Setenv("ONECLAW_AGENT_ID", "agent-test")
	t.Setenv("ONECLAW_AGENT_TOKEN", "jwt-static")
	t.Setenv("ONECLAW_RUNTIME_ID", "rt-123")
	t.Setenv("IDLE_TIMEOUT_SECS", "900")
	t.Setenv("INBOUND_AUTH", "api_key")
	t.Setenv("INBOUND_API_KEY_HASH", "abc123")
	t.Setenv("USER_PORT", "3000")
	t.Setenv("SCRATCH_MAX_ENTRIES", "500")
	t.Setenv("SCRATCH_MAX_BYTES", "5242880")

	// Clear other env vars
	t.Setenv("ONECLAW_SHROUD_URL", "")
	t.Setenv("ONECLAW_AGENT_API_KEY", "")
	t.Setenv("ONECLAW_DEFAULT_PROVIDER", "")
	t.Setenv("ONECLAW_DEFAULT_MODEL", "")
	t.Setenv("ONECLAW_VAULT_ID", "")
	t.Setenv("CODER_WORKSPACE_ID", "")

	cfg := loadConfig()

	if cfg.InboundAddr != ":9091" {
		t.Errorf("InboundAddr = %q", cfg.InboundAddr)
	}
	if cfg.BaseURL != "https://api.test.xyz" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.AgentToken != "jwt-static" {
		t.Errorf("AgentToken = %q", cfg.AgentToken)
	}
	if cfg.RuntimeID != "rt-123" {
		t.Errorf("RuntimeID = %q", cfg.RuntimeID)
	}
	if cfg.IdleTimeoutSecs != 900 {
		t.Errorf("IdleTimeoutSecs = %d", cfg.IdleTimeoutSecs)
	}
	if cfg.InboundAuth != "api_key" {
		t.Errorf("InboundAuth = %q", cfg.InboundAuth)
	}
	if cfg.InboundKeyHash != "abc123" {
		t.Errorf("InboundKeyHash = %q", cfg.InboundKeyHash)
	}
	if cfg.UserPort != "3000" {
		t.Errorf("UserPort = %q", cfg.UserPort)
	}
	if cfg.ScratchMax != 500 {
		t.Errorf("ScratchMax = %d", cfg.ScratchMax)
	}
	if cfg.ScratchMaxBytes != 5242880 {
		t.Errorf("ScratchMaxBytes = %d", cfg.ScratchMaxBytes)
	}
}

// ============================================================
// Intents Handler Route Tests
// ============================================================

func TestIntentsHandler_RoutesCorrectly(t *testing.T) {
	activity := NewActivityTracker()

	tests := []struct {
		method string
		path   string
		expect string
	}{
		{"POST", "/intents/transactions", "/v1/agents/agent-1/transactions"},
		{"POST", "/intents/transactions/sign", "/v1/agents/agent-1/transactions/sign"},
		{"POST", "/intents/sign", "/v1/agents/agent-1/sign"},
		{"GET", "/intents/transactions", "/v1/agents/agent-1/transactions"},
		{"GET", "/intents/transactions/tx-123", "/v1/agents/agent-1/transactions/tx-123"},
		{"POST", "/intents/simulate", "/v1/agents/agent-1/transactions/simulate"},
		{"POST", "/intents/simulate-bundle", "/v1/agents/agent-1/transactions/simulate-bundle"},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var receivedPath string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				if r.Header.Get("Authorization") == "" {
					t.Error("expected Authorization header")
				}
				w.WriteHeader(200)
				w.Write([]byte(`{"ok":true}`))
			}))
			defer upstream.Close()

			tm := NewTokenManager(upstream.URL, "agent-1", "key-1", "static-token", "")
			handler := NewIntentsHandler(tm, upstream.URL, upstream.URL, "agent-1", activity)

			var body *strings.Reader
			if tt.method == "POST" {
				body = strings.NewReader(`{"test":true}`)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != 200 {
				t.Errorf("status = %d, body = %s", w.Code, w.Body.String())
			}
			if receivedPath != tt.expect {
				t.Errorf("upstream path = %q, want %q", receivedPath, tt.expect)
			}
		})
	}
}

// ============================================================
// Execute Handler Route Tests
// ============================================================

func TestExecuteHandler_Routes(t *testing.T) {
	activity := NewActivityTracker()

	tests := []struct {
		method     string
		path       string
		expectPath string
		expectCode int
	}{
		{"POST", "/execute", "/v1/agents/agent-1/execute", 200},
		{"GET", "/execute/bindings", "/v1/agents/agent-1/bindings", 200},
		{"GET", "/execute/unknown", "", 404},
		{"GET", "/execute", "", 405},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			var receivedPath string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedPath = r.URL.Path
				w.WriteHeader(200)
				w.Write([]byte(`{"ok":true}`))
			}))
			defer upstream.Close()

			tm := NewTokenManager(upstream.URL, "agent-1", "key-1", "static-token", "")
			handler := NewExecuteHandler(tm, upstream.URL, "agent-1", activity)

			var body *strings.Reader
			if tt.method == "POST" {
				body = strings.NewReader(`{"binding":"test"}`)
			} else {
				body = strings.NewReader("")
			}
			req := httptest.NewRequest(tt.method, tt.path, body)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)

			if w.Code != tt.expectCode {
				t.Errorf("status = %d, want %d, body = %s", w.Code, tt.expectCode, w.Body.String())
			}
			if tt.expectPath != "" && receivedPath != tt.expectPath {
				t.Errorf("upstream path = %q, want %q", receivedPath, tt.expectPath)
			}
		})
	}
}

// ============================================================
// Hash API Key Tests
// ============================================================

func TestHashAPIKey(t *testing.T) {
	hash1 := HashAPIKey("test-key")
	hash2 := HashAPIKey("test-key")
	hash3 := HashAPIKey("different-key")

	if hash1 != hash2 {
		t.Error("same key should produce same hash")
	}
	if hash1 == hash3 {
		t.Error("different keys should produce different hashes")
	}
	if len(hash1) != 64 {
		t.Errorf("SHA-256 hex should be 64 chars, got %d", len(hash1))
	}
}
