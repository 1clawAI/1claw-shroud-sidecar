package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Set at link time: go build -ldflags="-X main.version=v1.2.3"
var version = "dev"

type Config struct {
	ListenAddr      string
	InboundAddr     string
	ShroudURL       string
	BaseURL         string
	AgentID         string
	AgentAPIKey     string
	AgentToken      string
	Provider        string
	Model           string
	VaultID         string
	WorkspaceID     string
	RuntimeID       string
	IdleTimeoutSecs int
	InboundAuth     string
	InboundKeyHash  string
	UserPort        string
	ScratchMax      int
	ScratchMaxBytes int
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
	scratchMax, _ := strconv.Atoi(envOr("SCRATCH_MAX_ENTRIES", "1000"))
	scratchBytes, _ := strconv.Atoi(envOr("SCRATCH_MAX_BYTES", "10485760"))
	idleTimeout, _ := strconv.Atoi(envOr("IDLE_TIMEOUT_SECS", "1800"))

	return Config{
		ListenAddr:      envOr("LISTEN_ADDR", ":8080"),
		InboundAddr:     envOr("INBOUND_ADDR", ":8081"),
		ShroudURL:       strings.TrimRight(envOr("ONECLAW_SHROUD_URL", "https://shroud.1claw.xyz"), "/"),
		BaseURL:         strings.TrimRight(envOr("ONECLAW_BASE_URL", "https://api.1claw.xyz"), "/"),
		AgentID:         os.Getenv("ONECLAW_AGENT_ID"),
		AgentAPIKey:     os.Getenv("ONECLAW_AGENT_API_KEY"),
		AgentToken:      os.Getenv("ONECLAW_AGENT_TOKEN"),
		Provider:        envOr("ONECLAW_DEFAULT_PROVIDER", ""),
		Model:           os.Getenv("ONECLAW_DEFAULT_MODEL"),
		VaultID:         os.Getenv("ONECLAW_VAULT_ID"),
		WorkspaceID:     os.Getenv("CODER_WORKSPACE_ID"),
		RuntimeID:       os.Getenv("ONECLAW_RUNTIME_ID"),
		IdleTimeoutSecs: idleTimeout,
		InboundAuth:     envOr("INBOUND_AUTH", "public"),
		InboundKeyHash:  os.Getenv("INBOUND_API_KEY_HASH"),
		UserPort:        envOr("USER_PORT", "8000"),
		ScratchMax:      scratchMax,
		ScratchMaxBytes: scratchBytes,
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": version,
	})
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h", "--help", "help":
			fmt.Fprintln(os.Stderr, "usage: shroud-sidecar [-version] [teardown]")
			os.Exit(0)
		case "-V", "-version", "--version", "version":
			fmt.Println(version)
			os.Exit(0)
		case "teardown":
			runTeardown()
			return
		}
	}

	cfg := loadConfig()
	shellOnly := envOr("ONECLAW_SHELL_ONLY", "0") == "1"

	if !shellOnly && (cfg.AgentID == "" || (cfg.AgentAPIKey == "" && cfg.AgentToken == "")) {
		bcfg := loadBootstrapConfig()
		if bcfg == nil {
			log.Fatal("Set ONECLAW_AGENT_ID + ONECLAW_AGENT_API_KEY/ONECLAW_AGENT_TOKEN (manual mode), or ONECLAW_MASTER_API_KEY (bootstrap mode), or ONECLAW_SHELL_ONLY=1")
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

	if shellOnly {
		log.Printf("shell-only mode: inbound proxy + /terminal (memory/intents/execute disabled)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Token manager for Vault API auth
	tm := NewTokenManager(cfg.BaseURL, cfg.AgentID, cfg.AgentAPIKey, cfg.AgentToken)

	// Activity tracker for idle detection
	activity := NewActivityTracker()

	// Scratch LRU cache
	scratch := NewScratchLRU(cfg.ScratchMax, cfg.ScratchMaxBytes)

	// Internal API mux (:8080)
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)

	// Memory API
	memHandler := NewMemoryHandler(tm, cfg.BaseURL, cfg.AgentID, scratch, activity)
	mux.Handle("/memory/", memHandler)
	mux.Handle("/memory", memHandler)

	// Intents proxy
	intentsHandler := NewIntentsHandler(tm, cfg.ShroudURL, cfg.BaseURL, cfg.AgentID, activity)
	mux.Handle("/intents/", intentsHandler)
	mux.Handle("/intents", intentsHandler)

	// Execution proxy
	execHandler := NewExecuteHandler(tm, cfg.BaseURL, cfg.AgentID, activity)
	mux.Handle("/execute/", execHandler)
	mux.Handle("/execute", execHandler)

	// Interactive terminal (WebSocket PTY)
	shellMaxMin, _ := strconv.Atoi(envOr("SHELL_MAX_SESSION_MINUTES", "30"))
	shellIdleMin, _ := strconv.Atoi(envOr("SHELL_IDLE_TIMEOUT_MINUTES", "10"))
	shellMaxSessions, _ := strconv.Atoi(envOr("SHELL_MAX_SESSIONS", "2"))
	termHandler := &TerminalHandler{
		maxSessions:    shellMaxSessions,
		sessionTimeout: time.Duration(shellMaxMin) * time.Minute,
		idleTimeout:    time.Duration(shellIdleMin) * time.Minute,
		jwksURL:        envOr("ONECLAW_JWKS_URL", "https://api.1claw.xyz/.well-known/jwks.json"),
		jwksCache:      NewJWKSCache(envOr("ONECLAW_JWKS_URL", "https://api.1claw.xyz/.well-known/jwks.json"), 5*time.Minute),
		runtimeID:      cfg.RuntimeID,
	}
	mux.Handle("/terminal", termHandler)

	// Existing LLM proxy (catch-all)
	mux.HandleFunc("/", proxyHandler(cfg, activity))

	// Secret file mounts
	mounts, err := ParseSecretMountsFromEnv()
	if err != nil {
		log.Fatalf("[secret-mounts] %v", err)
	}
	var secretMounter *SecretMounter
	if len(mounts) > 0 {
		if cfg.VaultID == "" {
			log.Fatal("[secret-mounts] ONECLAW_VAULT_ID required for SECRET_MOUNTS")
		}
		secretMounter = NewSecretMounter(tm, cfg.BaseURL, cfg.VaultID, mounts)
		if err := secretMounter.MountAll(ctx); err != nil {
			log.Fatalf("[secret-mounts] initial mount failed: %v", err)
		}
		go secretMounter.RefreshLoop(ctx)
	}

	// Idle reporter
	idleReporter := NewIdleReporter(tm, cfg.BaseURL, cfg.RuntimeID, cfg.IdleTimeoutSecs, activity)
	go idleReporter.Run(ctx)

	// Inbound security proxy (:8081, or :$PORT when used as Cloud Run ingress)
	inboundAuth := NewInboundAuth(cfg.InboundAuth, cfg.InboundKeyHash, cfg.BaseURL)
	inbound := NewInboundProxy(cfg.InboundAddr, cfg.UserPort, inboundAuth, tm, cfg.BaseURL, cfg.AgentID, activity).
		WithTerminal(termHandler)
	go func() {
		if err := inbound.Start(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[inbound-proxy] error: %v", err)
		}
	}()

	// SIGTERM handler
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: ActivityMiddleware(activity, mux),
	}

	go func() {
		sig := <-sigCh
		log.Printf("[shutdown] received %s, shutting down...", sig)
		cancel()

		// Flush scratch entries to Vault (best-effort, 5s timeout)
		flushCtx, flushCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer flushCancel()
		if n := scratch.Len(); n > 0 {
			log.Printf("[shutdown] flushing %d scratch entries to Vault...", n)
			flushed := scratch.FlushToVault(flushCtx, tm, cfg.BaseURL, cfg.AgentID)
			log.Printf("[shutdown] flushed %d/%d scratch entries", flushed, n)
		}

		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		server.Shutdown(shutCtx)
	}()

	agentLabel := "none"
	if cfg.AgentID != "" {
		agentLabel = cfg.AgentID[:min(8, len(cfg.AgentID))] + "..."
	}
	log.Printf("1claw-shroud-sidecar %s listening on %s → %s (agent %s)", version, cfg.ListenAddr, cfg.ShroudURL, agentLabel)
	log.Printf("  runtime APIs: memory, intents, execute, terminal on %s", cfg.ListenAddr)
	log.Printf("  inbound proxy on %s → localhost:%s (auth: %s)", cfg.InboundAddr, cfg.UserPort, cfg.InboundAuth)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
	log.Println("[shutdown] complete")
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

func proxyHandler(cfg Config, activity *ActivityTracker) http.HandlerFunc {
	client := &http.Client{Timeout: 120 * time.Second}
	agentKey := cfg.AgentID + ":" + cfg.AgentAPIKey

	return func(w http.ResponseWriter, r *http.Request) {
		activity.Touch()
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

		// Count upstream response bytes toward runtime egress metering
		activity.AddEgress(int64(len(body) + len(respBody)))

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
