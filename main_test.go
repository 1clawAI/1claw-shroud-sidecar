package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Provider detection ---

func TestDetectProviderFromPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/v1/chat/completions", "openai"},
		{"/chat/completions", "openai"},
		{"/v1/messages", "anthropic"},
		{"/messages", "anthropic"},
		{"/v1/models/gemini-pro:generateContent", "google"},
		{"/unknown/path", ""},
		{"/", ""},
	}
	for _, tt := range tests {
		got := detectProviderFromPath(tt.path)
		if got != tt.want {
			t.Errorf("detectProviderFromPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestResolveProvider(t *testing.T) {
	cfg := Config{Provider: "anthropic"}

	// Header takes priority
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	r.Header.Set("X-Shroud-Provider", "google")
	if got := resolveProvider(cfg, r); got != "google" {
		t.Errorf("header override: got %q, want %q", got, "google")
	}

	// Config fallback
	r2 := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	if got := resolveProvider(cfg, r2); got != "anthropic" {
		t.Errorf("config fallback: got %q, want %q", got, "anthropic")
	}

	// Path auto-detect
	cfg2 := Config{}
	r3 := httptest.NewRequest("POST", "/v1/messages", nil)
	if got := resolveProvider(cfg2, r3); got != "anthropic" {
		t.Errorf("path detect: got %q, want %q", got, "anthropic")
	}
}

// --- Model resolution ---

func TestResolveModel(t *testing.T) {
	cfg := Config{Model: "gpt-4o"}

	// Header takes priority
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"model":"gpt-3.5-turbo"}`))
	r.Header.Set("X-Shroud-Model", "claude-3")
	if got := resolveModel(cfg, r, []byte(`{"model":"gpt-3.5-turbo"}`)); got != "claude-3" {
		t.Errorf("header override: got %q, want %q", got, "claude-3")
	}

	// Body fallback
	body := []byte(`{"model":"gpt-3.5-turbo","messages":[]}`)
	r2 := httptest.NewRequest("POST", "/", nil)
	if got := resolveModel(cfg, r2, body); got != "gpt-3.5-turbo" {
		t.Errorf("body parse: got %q, want %q", got, "gpt-3.5-turbo")
	}

	// Config default
	r3 := httptest.NewRequest("POST", "/", nil)
	if got := resolveModel(cfg, r3, []byte(`{}`)); got != "gpt-4o" {
		t.Errorf("config default: got %q, want %q", got, "gpt-4o")
	}

	// Empty body → config default
	r4 := httptest.NewRequest("POST", "/", nil)
	if got := resolveModel(cfg, r4, []byte("")); got != "gpt-4o" {
		t.Errorf("empty body: got %q, want %q", got, "gpt-4o")
	}
}

// --- Usage extraction ---

func TestExtractUsage(t *testing.T) {
	t.Run("valid usage", func(t *testing.T) {
		body := []byte(`{"id":"chatcmpl-1","usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`)
		u := extractUsage(body)
		if u == nil {
			t.Fatal("expected non-nil usage")
		}
		if *u.PromptTokens != 10 {
			t.Errorf("prompt_tokens = %d, want 10", *u.PromptTokens)
		}
		if *u.CompletionTokens != 20 {
			t.Errorf("completion_tokens = %d, want 20", *u.CompletionTokens)
		}
	})

	t.Run("no usage field", func(t *testing.T) {
		body := []byte(`{"id":"chatcmpl-1","choices":[]}`)
		if u := extractUsage(body); u != nil {
			t.Error("expected nil for response without usage")
		}
	})

	t.Run("empty body", func(t *testing.T) {
		if u := extractUsage([]byte("")); u != nil {
			t.Error("expected nil for empty body")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		if u := extractUsage([]byte("not json")); u != nil {
			t.Error("expected nil for invalid JSON")
		}
	})

	t.Run("null usage values", func(t *testing.T) {
		body := []byte(`{"usage":{"prompt_tokens":null,"completion_tokens":null}}`)
		if u := extractUsage(body); u != nil {
			t.Error("expected nil when both token counts are null")
		}
	})
}

// --- Audit log format ---

func TestAuditEntryJSON(t *testing.T) {
	prompt := 10
	completion := 20
	entry := AuditEntry{
		Timestamp:        "2026-04-12T00:00:00Z",
		WorkspaceID:      "ws-123",
		AgentID:          "agent-456",
		Provider:         "openai",
		Model:            "gpt-4o",
		Method:           "POST",
		Path:             "/v1/chat/completions",
		StatusCode:       200,
		LatencyMs:        150,
		ReqBytes:         100,
		RespBytes:        500,
		PromptTokens:     &prompt,
		CompletionTokens: &completion,
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	checks := map[string]interface{}{
		"timestamp":            "2026-04-12T00:00:00Z",
		"workspace_id":        "ws-123",
		"agent_id":            "agent-456",
		"provider":            "openai",
		"model":               "gpt-4o",
		"method":              "POST",
		"path":                "/v1/chat/completions",
		"status_code":         float64(200),
		"latency_ms":          float64(150),
		"request_bytes":       float64(100),
		"response_bytes":      float64(500),
		"prompt_token_count":  float64(10),
		"completion_token_count": float64(20),
	}

	for k, want := range checks {
		got, ok := parsed[k]
		if !ok {
			t.Errorf("missing key %q", k)
			continue
		}
		if got != want {
			t.Errorf("%q = %v (%T), want %v (%T)", k, got, got, want, want)
		}
	}

	// error should be omitted when empty
	if _, ok := parsed["error"]; ok {
		t.Error("error field should be omitted when empty")
	}
}

func TestAuditEntryOmitsEmpty(t *testing.T) {
	entry := AuditEntry{
		AgentID:    "agent-1",
		Provider:   "openai",
		Method:     "POST",
		Path:       "/v1/chat/completions",
		StatusCode: 200,
	}

	data, _ := json.Marshal(entry)
	var parsed map[string]interface{}
	json.Unmarshal(data, &parsed)

	// workspace_id, model, error, token counts should be omitted
	for _, key := range []string{"workspace_id", "model", "error", "prompt_token_count", "completion_token_count"} {
		if _, ok := parsed[key]; ok {
			t.Errorf("%q should be omitted when empty/nil", key)
		}
	}
}

// --- State file operations ---

func TestStateFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "state.json")

	state := &ProvisionState{
		VaultID:     "vault-123",
		AgentID:     "agent-456",
		AgentAPIKey: "ocv_test_key",
		VaultName:   "test-vault",
		AgentName:   "test-agent",
		CreatedAt:   "2026-04-12T00:00:00Z",
	}

	if err := saveStateFile(path, state); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Verify file permissions
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode = %o, want 0600", perm)
	}

	loaded, err := loadStateFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.VaultID != state.VaultID {
		t.Errorf("VaultID = %q, want %q", loaded.VaultID, state.VaultID)
	}
	if loaded.AgentID != state.AgentID {
		t.Errorf("AgentID = %q, want %q", loaded.AgentID, state.AgentID)
	}
	if loaded.AgentAPIKey != state.AgentAPIKey {
		t.Errorf("AgentAPIKey = %q, want %q", loaded.AgentAPIKey, state.AgentAPIKey)
	}
}

func TestLoadStateFileMissing(t *testing.T) {
	_, err := loadStateFile("/nonexistent/path/state.json")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestLoadStateFileInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	os.WriteFile(path, []byte("not valid json"), 0600)

	_, err := loadStateFile(path)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestLoadStateFileMissingFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	os.WriteFile(path, []byte(`{"vault_id":"v1"}`), 0600)

	_, err := loadStateFile(path)
	if err == nil {
		t.Error("expected error when agent_id and agent_api_key missing")
	}
}

// --- Config loading ---

func TestLoadConfigDefaults(t *testing.T) {
	// Clear relevant env vars
	for _, k := range []string{"LISTEN_ADDR", "ONECLAW_SHROUD_URL", "ONECLAW_AGENT_ID", "ONECLAW_AGENT_API_KEY", "ONECLAW_DEFAULT_PROVIDER", "ONECLAW_DEFAULT_MODEL", "ONECLAW_VAULT_ID", "CODER_WORKSPACE_ID"} {
		t.Setenv(k, "")
	}

	cfg := loadConfig()
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8080")
	}
	if cfg.ShroudURL != "https://shroud.1claw.xyz" {
		t.Errorf("ShroudURL = %q, want %q", cfg.ShroudURL, "https://shroud.1claw.xyz")
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv("LISTEN_ADDR", ":9090")
	t.Setenv("ONECLAW_SHROUD_URL", "https://custom.shroud.example.com/")
	t.Setenv("ONECLAW_AGENT_ID", "test-agent")
	t.Setenv("ONECLAW_AGENT_API_KEY", "ocv_test")
	t.Setenv("ONECLAW_DEFAULT_PROVIDER", "anthropic")
	t.Setenv("ONECLAW_DEFAULT_MODEL", "claude-3")
	t.Setenv("ONECLAW_VAULT_ID", "vault-1")
	t.Setenv("CODER_WORKSPACE_ID", "ws-1")

	cfg := loadConfig()
	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.ShroudURL != "https://custom.shroud.example.com" {
		t.Errorf("ShroudURL = %q (trailing slash should be trimmed)", cfg.ShroudURL)
	}
	if cfg.AgentID != "test-agent" {
		t.Errorf("AgentID = %q", cfg.AgentID)
	}
	if cfg.Provider != "anthropic" {
		t.Errorf("Provider = %q", cfg.Provider)
	}
}

// --- Bootstrap config ---

func TestLoadBootstrapConfigNil(t *testing.T) {
	t.Setenv("ONECLAW_MASTER_API_KEY", "")
	if cfg := loadBootstrapConfig(); cfg != nil {
		t.Error("expected nil when ONECLAW_MASTER_API_KEY is empty")
	}
}

func TestLoadBootstrapConfigDefaults(t *testing.T) {
	t.Setenv("ONECLAW_MASTER_API_KEY", "1ck_test")
	t.Setenv("ONECLAW_BASE_URL", "")
	t.Setenv("ONECLAW_VAULT_NAME", "")
	t.Setenv("ONECLAW_AGENT_NAME", "")
	t.Setenv("ONECLAW_POLICY_PATH", "")
	t.Setenv("ONECLAW_STATE_FILE", "")

	cfg := loadBootstrapConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}
	if cfg.MasterAPIKey != "1ck_test" {
		t.Errorf("MasterAPIKey = %q", cfg.MasterAPIKey)
	}
	if cfg.BaseURL != "https://api.1claw.xyz" {
		t.Errorf("BaseURL = %q", cfg.BaseURL)
	}
	if cfg.VaultName != "shroud-sidecar" {
		t.Errorf("VaultName = %q", cfg.VaultName)
	}
	if cfg.AgentName != "shroud-sidecar-agent" {
		t.Errorf("AgentName = %q", cfg.AgentName)
	}
	if cfg.PolicyPath != "**" {
		t.Errorf("PolicyPath = %q", cfg.PolicyPath)
	}
	if !cfg.ShroudEnable {
		t.Error("ShroudEnable should be true")
	}
}

func TestLoadBootstrapConfigCustom(t *testing.T) {
	t.Setenv("ONECLAW_MASTER_API_KEY", "1ck_custom")
	t.Setenv("ONECLAW_BASE_URL", "https://api.custom.xyz/")
	t.Setenv("ONECLAW_VAULT_NAME", "my-vault")
	t.Setenv("ONECLAW_AGENT_NAME", "my-agent")
	t.Setenv("ONECLAW_POLICY_PATH", "keys/*")
	t.Setenv("ONECLAW_STATE_FILE", "/tmp/custom-state.json")

	cfg := loadBootstrapConfig()
	if cfg.BaseURL != "https://api.custom.xyz" {
		t.Errorf("BaseURL = %q (trailing slash should be trimmed)", cfg.BaseURL)
	}
	if cfg.VaultName != "my-vault" {
		t.Errorf("VaultName = %q", cfg.VaultName)
	}
	if cfg.AgentName != "my-agent" {
		t.Errorf("AgentName = %q", cfg.AgentName)
	}
	if cfg.PolicyPath != "keys/*" {
		t.Errorf("PolicyPath = %q", cfg.PolicyPath)
	}
	if cfg.StateFile != "/tmp/custom-state.json" {
		t.Errorf("StateFile = %q", cfg.StateFile)
	}
}

// --- Health endpoint ---

func TestHealthEndpoint(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	req := httptest.NewRequest("GET", "/healthz", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want %q", resp["status"], "ok")
	}
}

// --- Proxy handler (with mock upstream) ---

func TestProxyHandlerForwardsToUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers were set
		if r.Header.Get("X-Shroud-Agent-Key") != "agent-1:key-1" {
			t.Errorf("X-Shroud-Agent-Key = %q", r.Header.Get("X-Shroud-Agent-Key"))
		}
		if r.Header.Get("X-Shroud-Provider") != "openai" {
			t.Errorf("X-Shroud-Provider = %q", r.Header.Get("X-Shroud-Provider"))
		}
		if r.Header.Get("X-Shroud-Model") != "gpt-4o" {
			t.Errorf("X-Shroud-Model = %q", r.Header.Get("X-Shroud-Model"))
		}

		// Host and Connection should be stripped
		if r.Header.Get("X-Custom") != "kept" {
			t.Errorf("X-Custom header should be forwarded")
		}

		// Verify body was forwarded
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]interface{}
		json.Unmarshal(body, &parsed)
		if parsed["model"] != "gpt-4o" {
			t.Errorf("body model = %v", parsed["model"])
		}

		w.Header().Set("X-Upstream-Header", "present")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "chatcmpl-test",
			"choices": []map[string]interface{}{
				{"message": map[string]string{"content": "Hello!"}},
			},
			"usage": map[string]int{"prompt_tokens": 5, "completion_tokens": 8},
		})
	}))
	defer upstream.Close()

	cfg := Config{
		ShroudURL:   upstream.URL,
		AgentID:     "agent-1",
		AgentAPIKey: "key-1",
		Provider:    "openai",
	}

	handler := proxyHandler(cfg)

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`
	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Custom", "kept")

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}

	// Upstream response headers forwarded
	if w.Header().Get("X-Upstream-Header") != "present" {
		t.Error("upstream response header not forwarded")
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["id"] != "chatcmpl-test" {
		t.Errorf("response id = %v", resp["id"])
	}
}

func TestProxyHandlerBYOK(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-Shroud-Api-Key"); got != "sk-user-key" {
			t.Errorf("X-Shroud-Api-Key = %q, want %q", got, "sk-user-key")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	cfg := Config{ShroudURL: upstream.URL, AgentID: "agent-1", AgentAPIKey: "key-1"}
	handler := proxyHandler(cfg)

	req := httptest.NewRequest("POST", "/v1/chat/completions", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer sk-user-key")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != 200 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestProxyHandlerStripsIncomingShroudHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The sidecar sets its own X-Shroud-Agent-Key — the caller's shouldn't leak through
		if r.Header.Get("X-Shroud-Agent-Key") != "agent-1:key-1" {
			t.Errorf("X-Shroud-Agent-Key = %q, expected sidecar's own key", r.Header.Get("X-Shroud-Agent-Key"))
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	cfg := Config{ShroudURL: upstream.URL, AgentID: "agent-1", AgentAPIKey: "key-1"}
	handler := proxyHandler(cfg)

	req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	req.Header.Set("X-Shroud-Agent-Key", "malicious:attacker")
	req.Header.Set("X-Shroud-Evil", "should-be-stripped")
	w := httptest.NewRecorder()
	handler(w, req)
}

func TestProxyHandlerQueryParams(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "stream=true" {
			t.Errorf("query = %q, want %q", r.URL.RawQuery, "stream=true")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{}`))
	}))
	defer upstream.Close()

	cfg := Config{ShroudURL: upstream.URL, AgentID: "agent-1", AgentAPIKey: "key-1"}
	handler := proxyHandler(cfg)

	req := httptest.NewRequest("POST", "/v1/chat/completions?stream=true", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	handler(w, req)
}

// --- Error handler ---

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, 502, "upstream failed")

	if w.Code != 502 {
		t.Errorf("code = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "upstream failed" {
		t.Errorf("error = %q", resp["error"])
	}
}

// AuditEntry must never gain fields that could echo BYOK or vault material.
func TestAuditEntryJSONHasNoCredentialFields(t *testing.T) {
	p := 1
	c := 2
	entry := AuditEntry{
		AgentID:          "agent-uuid",
		Provider:         "openai",
		Model:            "gpt-4o-mini",
		Method:           "POST",
		Path:             "/v1/chat/completions",
		StatusCode:       403,
		PromptTokens:     &p,
		CompletionTokens: &c,
	}
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	for _, forbidden := range []string{"authorization", "api_key", "bearer", "sk-", "x-shroud-api-key"} {
		if strings.Contains(strings.ToLower(s), forbidden) {
			t.Errorf("audit JSON must not contain credential-like substring %q: %s", forbidden, s)
		}
	}
}
