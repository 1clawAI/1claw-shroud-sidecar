package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	ListenAddr  string
	ShroudURL   string
	AgentID     string
	AgentAPIKey string
	Provider    string
	Model       string
	VaultID     string
	WorkspaceID string
}

type AuditEntry struct {
	Timestamp        string `json:"timestamp"`
	WorkspaceID      string `json:"workspace_id,omitempty"`
	AgentID          string `json:"agent_id"`
	Provider         string `json:"provider"`
	Model            string `json:"model,omitempty"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	StatusCode       int    `json:"status_code"`
	LatencyMs        int64  `json:"latency_ms"`
	ReqBytes         int64  `json:"request_bytes"`
	RespBytes        int64  `json:"response_bytes"`
	PromptTokens     *int   `json:"prompt_token_count,omitempty"`
	CompletionTokens *int   `json:"completion_token_count,omitempty"`
	Error            string `json:"error,omitempty"`
}

func loadConfig() Config {
	return Config{
		ListenAddr:  envOr("LISTEN_ADDR", ":8080"),
		ShroudURL:   strings.TrimRight(envOr("ONECLAW_SHROUD_URL", "https://shroud.1claw.xyz"), "/"),
		AgentID:     os.Getenv("ONECLAW_AGENT_ID"),
		AgentAPIKey: os.Getenv("ONECLAW_AGENT_API_KEY"),
		Provider:    envOr("ONECLAW_DEFAULT_PROVIDER", ""),
		Model:       os.Getenv("ONECLAW_DEFAULT_MODEL"),
		VaultID:     os.Getenv("ONECLAW_VAULT_ID"),
		WorkspaceID: os.Getenv("CODER_WORKSPACE_ID"),
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "teardown" {
		runTeardown()
		return
	}

	cfg := loadConfig()

	if cfg.AgentID == "" || cfg.AgentAPIKey == "" {
		bcfg := loadBootstrapConfig()
		if bcfg == nil {
			log.Fatal("Set ONECLAW_AGENT_ID + ONECLAW_AGENT_API_KEY (manual mode), or ONECLAW_MASTER_API_KEY (bootstrap mode)")
		}

		state, err := bootstrap(bcfg)
		if err != nil {
			log.Fatalf("[bootstrap] %v", err)
		}

		cfg.AgentID = state.AgentID
		cfg.AgentAPIKey = state.AgentAPIKey
		if cfg.VaultID == "" {
			cfg.VaultID = state.VaultID
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/", proxyHandler(cfg))

	log.Printf("1claw-shroud-sidecar listening on %s → %s (agent %s)", cfg.ListenAddr, cfg.ShroudURL, cfg.AgentID[:8]+"...")
	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func runTeardown() {
	bcfg := loadBootstrapConfig()
	if bcfg == nil {
		log.Fatal("ONECLAW_MASTER_API_KEY is required for teardown")
	}
	if err := teardown(bcfg); err != nil {
		log.Fatalf("[teardown] %v", err)
	}
}

func proxyHandler(cfg Config) http.HandlerFunc {
	client := &http.Client{Timeout: 120 * time.Second}
	agentKey := cfg.AgentID + ":" + cfg.AgentAPIKey

	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		provider := resolveProvider(cfg, r)
		model := resolveModel(cfg, r, body)

		targetURL := cfg.ShroudURL + r.URL.Path
		if r.URL.RawQuery != "" {
			targetURL += "?" + r.URL.RawQuery
		}

		proxyReq, err := http.NewRequestWithContext(r.Context(), r.Method, targetURL, strings.NewReader(string(body)))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to build upstream request")
			return
		}

		for key, vals := range r.Header {
			lower := strings.ToLower(key)
			if lower == "host" || lower == "connection" || strings.HasPrefix(lower, "x-shroud-") {
				continue
			}
			for _, v := range vals {
				proxyReq.Header.Add(key, v)
			}
		}

		proxyReq.Header.Set("X-Shroud-Agent-Key", agentKey)
		proxyReq.Header.Set("Content-Type", "application/json")
		if provider != "" {
			proxyReq.Header.Set("X-Shroud-Provider", provider)
		}
		if model != "" {
			proxyReq.Header.Set("X-Shroud-Model", model)
		}

		// BYOK: forward the caller's provider API key if present.
		if apiKey := r.Header.Get("Authorization"); apiKey != "" && strings.HasPrefix(apiKey, "Bearer ") {
			proxyReq.Header.Set("X-Shroud-Api-Key", strings.TrimPrefix(apiKey, "Bearer "))
		}

		resp, err := client.Do(proxyReq)
		if err != nil {
			emitAudit(cfg, provider, model, r, int64(len(body)), 0, 502, start, nil, err.Error())
			writeError(w, http.StatusBadGateway, "upstream request failed: "+err.Error())
			return
		}
		defer resp.Body.Close()

		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			emitAudit(cfg, provider, model, r, int64(len(body)), 0, 502, start, nil, "failed to read upstream response")
			writeError(w, http.StatusBadGateway, "failed to read upstream response")
			return
		}

		for key, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(key, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)

		usage := extractUsage(respBody)
		emitAudit(cfg, provider, model, r, int64(len(body)), int64(len(respBody)), resp.StatusCode, start, usage, "")
	}
}

func resolveProvider(cfg Config, r *http.Request) string {
	if p := r.Header.Get("X-Shroud-Provider"); p != "" {
		return p
	}
	if cfg.Provider != "" {
		return cfg.Provider
	}
	return detectProviderFromPath(r.URL.Path)
}

func resolveModel(cfg Config, r *http.Request, body []byte) string {
	if m := r.Header.Get("X-Shroud-Model"); m != "" {
		return m
	}

	var parsed struct {
		Model string `json:"model"`
	}
	if json.Unmarshal(body, &parsed) == nil && parsed.Model != "" {
		return parsed.Model
	}

	return cfg.Model
}

func detectProviderFromPath(path string) string {
	p := strings.ToLower(path)
	switch {
	case strings.Contains(p, "/chat/completions"):
		return "openai"
	case strings.Contains(p, "/messages"):
		return "anthropic"
	case strings.Contains(p, "generatecontent"):
		return "google"
	default:
		return ""
	}
}

type usageInfo struct {
	PromptTokens     *int
	CompletionTokens *int
}

func extractUsage(body []byte) *usageInfo {
	var parsed struct {
		Usage struct {
			PromptTokens     *int `json:"prompt_tokens"`
			CompletionTokens *int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return nil
	}
	if parsed.Usage.PromptTokens == nil && parsed.Usage.CompletionTokens == nil {
		return nil
	}
	return &usageInfo{
		PromptTokens:     parsed.Usage.PromptTokens,
		CompletionTokens: parsed.Usage.CompletionTokens,
	}
}

func emitAudit(cfg Config, provider, model string, r *http.Request, reqBytes, respBytes int64, status int, start time.Time, usage *usageInfo, errMsg string) {
	entry := AuditEntry{
		Timestamp:   time.Now().UTC().Format(time.RFC3339Nano),
		WorkspaceID: cfg.WorkspaceID,
		AgentID:     cfg.AgentID,
		Provider:    provider,
		Model:       model,
		Method:      r.Method,
		Path:        r.URL.Path,
		StatusCode:  status,
		LatencyMs:   time.Since(start).Milliseconds(),
		ReqBytes:    reqBytes,
		RespBytes:   respBytes,
		Error:       errMsg,
	}
	if usage != nil {
		entry.PromptTokens = usage.PromptTokens
		entry.CompletionTokens = usage.CompletionTokens
	}

	line, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stdout, string(line))
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
