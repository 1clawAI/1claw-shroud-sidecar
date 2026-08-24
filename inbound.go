package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	inboundMaxBodySize      = 5 * 1024 * 1024
	inboundMaxHeaders       = 50
	inboundMaxHeaderSize    = 8 * 1024
	inboundMaxConns         = 1000
	inboundRateLimit        = 100 // req/s per IP
	agentCardCacheTTL       = 60 * time.Second
)

// --- Token Bucket Rate Limiter ---

type tokenBucket struct {
	tokens    float64
	lastFill  time.Time
	rate      float64
	burst     float64
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64
	burst   float64
}

func NewRateLimiter(rate, burst float64) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    rate,
		burst:   burst,
	}
	go rl.cleanup()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	b, ok := rl.buckets[ip]
	if !ok {
		b = &tokenBucket{tokens: rl.burst, lastFill: time.Now(), rate: rl.rate, burst: rl.burst}
		rl.buckets[ip] = b
	}

	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *RateLimiter) cleanup() {
	for {
		time.Sleep(5 * time.Minute)
		rl.mu.Lock()
		cutoff := time.Now().Add(-10 * time.Minute)
		for ip, b := range rl.buckets {
			if b.lastFill.Before(cutoff) {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// --- Connection Limiter ---

type connLimiter struct {
	active int64
	max    int64
}

func (cl *connLimiter) acquire() bool {
	return atomic.AddInt64(&cl.active, 1) <= cl.max
}

func (cl *connLimiter) release() {
	atomic.AddInt64(&cl.active, -1)
}

// --- Agent Card Cache ---

type agentCardCache struct {
	mu      sync.RWMutex
	data    []byte
	fetched time.Time
}

func (c *agentCardCache) Get() ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.data != nil && time.Since(c.fetched) < agentCardCacheTTL {
		return c.data, true
	}
	return nil, false
}

func (c *agentCardCache) Set(data []byte) {
	c.mu.Lock()
	c.data = data
	c.fetched = time.Now()
	c.mu.Unlock()
}

func (c *agentCardCache) Clear() {
	c.mu.Lock()
	c.data = nil
	c.mu.Unlock()
}

// --- Inbound Auth ---

type InboundAuth struct {
	mode      string // "api_key", "jwt", "public"
	keyHash   string // SHA-256 hex of the expected API key
	jwksURL   string
	jwksCache *JWKSCache
	orgID     string
	agentID   string
}

func NewInboundAuth(mode, keyHash, baseURL string) *InboundAuth {
	jwksURL := ""
	var cache *JWKSCache
	if mode == "jwt" {
		jwksURL = strings.TrimRight(baseURL, "/") + "/.well-known/jwks.json"
		cache = NewJWKSCache(jwksURL, 5*time.Minute)
	}
	return &InboundAuth{
		mode:      mode,
		keyHash:   keyHash,
		jwksURL:   jwksURL,
		jwksCache: cache,
	}
}

// WithJWKSCache injects a shared JWKS cache (e.g. the terminal handler's).
func (ia *InboundAuth) WithJWKSCache(cache *JWKSCache) *InboundAuth {
	if cache != nil {
		ia.jwksCache = cache
		ia.jwksURL = cache.url
	}
	return ia
}

func (ia *InboundAuth) Authenticate(r *http.Request) (bool, string) {
	switch ia.mode {
	case "public":
		return true, ""
	case "api_key":
		return ia.checkAPIKey(r)
	case "jwt":
		return ia.checkJWT(r)
	default:
		return false, "unknown auth mode"
	}
}

func (ia *InboundAuth) checkAPIKey(r *http.Request) (bool, string) {
	// Fail closed: api_key mode without a provisioned hash is an auth bypass.
	if ia.keyHash == "" {
		return false, "inbound API key not provisioned"
	}

	key := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		key = strings.TrimPrefix(auth, "Bearer ")
	}
	if key == "" {
		key = r.Header.Get("X-API-Key")
	}
	if key == "" {
		return false, "missing API key"
	}

	hash := sha256.Sum256([]byte(key))
	if hex.EncodeToString(hash[:]) != ia.keyHash {
		return false, "invalid API key"
	}
	return true, ""
}

// WithTenantBinding scopes jwt inbound auth to this runtime's org (and agent when sub is agent:*).
func (ia *InboundAuth) WithTenantBinding(orgID, agentID string) *InboundAuth {
	ia.orgID = orgID
	ia.agentID = agentID
	return ia
}

func (ia *InboundAuth) checkJWT(r *http.Request) (bool, string) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		return false, "missing Bearer token"
	}
	token := strings.TrimPrefix(auth, "Bearer ")

	// Fail closed: jwt mode requires a JWKS cache and cryptographic verification.
	// The inbound proxy forwards to the user container (not Vault), so structural
	// checks alone are an auth bypass.
	if ia.jwksCache == nil {
		return false, "JWKS unavailable"
	}
	if err := verifyInboundHostedJWT(ia.jwksCache, token, ia.orgID, ia.agentID); err != nil {
		return false, "invalid JWT: " + err.Error()
	}
	return true, ""
}

// --- Inbound Proxy Server ---

type InboundProxy struct {
	listenAddr string
	userPort   string
	auth       *InboundAuth
	limiter    *RateLimiter
	connLimit  *connLimiter
	agentCard  *agentCardCache
	tm         *TokenManager
	baseURL    string
	agentID    string
	activity   *ActivityTracker
	terminal   *TerminalHandler
	runtimeID  string
	jwksCache  *JWKSCache
}

func NewInboundProxy(listenAddr, userPort string, auth *InboundAuth, tm *TokenManager, baseURL, agentID string, activity *ActivityTracker) *InboundProxy {
	return &InboundProxy{
		listenAddr: listenAddr,
		userPort:   userPort,
		auth:       auth,
		limiter:    NewRateLimiter(inboundRateLimit, inboundRateLimit),
		connLimit:  &connLimiter{max: inboundMaxConns},
		agentCard:  &agentCardCache{},
		tm:         tm,
		baseURL:    baseURL,
		agentID:    agentID,
		activity:   activity,
	}
}

// WithTerminal attaches the interactive shell WebSocket handler to the inbound mux
// so /terminal is reachable on the public Cloud Run port (JWT-auth'd, not inbound API key).
func (ip *InboundProxy) WithTerminal(th *TerminalHandler) *InboundProxy {
	ip.terminal = th
	if th != nil {
		ip.jwksCache = th.jwksCache
		ip.runtimeID = th.runtimeID
	}
	return ip
}

// runtimeChatTokenFromRequest reads the Vault-minted aud=runtime-chat JWT.
// Prefer the dedicated header so Authorization can carry a refreshed agent JWT.
func runtimeChatTokenFromRequest(r *http.Request) string {
	if tok := strings.TrimSpace(r.Header.Get("X-1Claw-Runtime-Chat-Token")); looksLikeJWT(tok) {
		return tok
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if looksLikeJWT(token) {
			return token
		}
	}
	return ""
}

// authenticateRuntimeChatJWT validates a short-lived Vault-issued JWT
// (aud=runtime-chat) used by POST /v1/runtimes/{id}/chat to reach the user app.
func (ip *InboundProxy) authenticateRuntimeChatJWT(r *http.Request) (bool, string) {
	// Chat ingress is JWT-only — never fall back to inbound_auth (api_key/public).
	if ip.jwksCache == nil {
		return false, "JWKS cache unavailable"
	}
	if ip.runtimeID == "" {
		return false, "ONECLAW_RUNTIME_ID not configured — stop and start the runtime"
	}
	token := runtimeChatTokenFromRequest(r)
	if token == "" {
		return false, "runtime-chat JWT required"
	}
	claims, err := verifyRuntimeAudienceJWT(ip.jwksCache, token, "runtime-chat", ip.runtimeID)
	if err != nil {
		return false, err.Error()
	}
	_ = claims
	return true, ""
}

func (ip *InboundProxy) Start(ctx context.Context) error {
	target, _ := url.Parse(fmt.Sprintf("http://localhost:%s", ip.userPort))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		writeError(w, http.StatusBadGateway, "user container unreachable: "+err.Error())
	}

	mux := http.NewServeMux()
	// Shell WebSocket — JWT-authenticated by TerminalHandler (skip inbound API key).
	if ip.terminal != nil {
		mux.Handle("/terminal", ip.terminal)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ip.activity.Touch()

		clientIP := extractIP(r)

		if !ip.limiter.Allow(clientIP) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}

		if len(r.Header) > inboundMaxHeaders {
			writeError(w, http.StatusRequestHeaderFieldsTooLarge, "too many headers")
			return
		}
		for key, vals := range r.Header {
			for _, v := range vals {
				if len(key)+len(v) > inboundMaxHeaderSize {
					writeError(w, http.StatusRequestHeaderFieldsTooLarge, "header too large")
					return
				}
			}
		}

		// Agent card endpoint — exempt from auth, GET only
		if r.URL.Path == "/.well-known/agent.json" {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", "GET")
				writeError(w, http.StatusMethodNotAllowed, "GET only")
				return
			}
			ip.serveAgentCard(w, r)
			return
		}

		// Vault dashboard chat: require short-lived aud=runtime-chat JWT bound to this runtime.
		isChatCompletions := r.Method == http.MethodPost &&
			(r.URL.Path == "/v1/chat/completions" || strings.HasPrefix(r.URL.Path, "/v1/chat/completions/"))
		if isChatCompletions {
			ok, reason := ip.authenticateRuntimeChatJWT(r)
			if !ok {
				msg := "runtime-chat JWT required"
				if reason != "" && reason != msg {
					msg = msg + ": " + reason
				}
				writeError(w, http.StatusUnauthorized, msg)
				return
			}
			if fresh := strings.TrimSpace(r.Header.Get("X-Refreshed-Agent-Token")); looksLikeJWT(fresh) && ip.tm != nil {
				ip.tm.UpdateStaticJWT(fresh)
			}
		} else {
			ok, reason := ip.auth.Authenticate(r)
			if !ok {
				writeError(w, http.StatusUnauthorized, reason)
				return
			}
		}

		r.Body = http.MaxBytesReader(w, r.Body, inboundMaxBodySize)

		stripSensitiveHeaders(r)

		cw := &countingResponseWriter{ResponseWriter: w}
		proxy.ServeHTTP(cw, r)
		if cw.n > 0 {
			ip.activity.AddEgress(cw.n)
		}
	})

	listener, err := net.Listen("tcp", ip.listenAddr)
	if err != nil {
		return fmt.Errorf("inbound listen: %w", err)
	}

	limitedListener := &limitedNetListener{
		Listener:  listener,
		connLimit: ip.connLimit,
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Allow long-lived SSE chat streams through the inbound proxy.
		WriteTimeout: 5 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(shutCtx)
	}()

	log.Printf("[inbound-proxy] listening on %s → localhost:%s (auth: %s)", ip.listenAddr, ip.userPort, ip.auth.mode)
	return server.Serve(limitedListener)
}

func (ip *InboundProxy) serveAgentCard(w http.ResponseWriter, _ *http.Request) {
	if data, ok := ip.agentCard.Get(); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	url := fmt.Sprintf("%s/v1/agents/%s/card", ip.baseURL, ip.agentID)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to build card request")
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to fetch agent card")
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		writeError(w, http.StatusNotFound, "agent not discoverable")
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusBadGateway, "failed to read agent card")
		return
	}

	if resp.StatusCode/100 != 2 {
		writeError(w, resp.StatusCode, "agent card fetch failed")
		return
	}

	ip.agentCard.Set(body)
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// countingResponseWriter tracks bytes written toward egress metering.
type countingResponseWriter struct {
	http.ResponseWriter
	n int64
}

func (c *countingResponseWriter) Write(b []byte) (int, error) {
	n, err := c.ResponseWriter.Write(b)
	c.n += int64(n)
	return n, err
}

func (c *countingResponseWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func stripSensitiveHeaders(r *http.Request) {
	headersToStrip := []string{
		"X-Forwarded-For",
		"X-Forwarded-Host",
		"X-Forwarded-Proto",
		"X-Real-Ip",
		"Authorization",
	}
	for key := range r.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-shroud-") {
			r.Header.Del(key)
		}
	}
	for _, h := range headersToStrip {
		r.Header.Del(h)
	}
}

func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// StripSensitiveHeaders is exported for testing.
func StripSensitiveHeaders(r *http.Request) {
	stripSensitiveHeaders(r)
}

// --- Connection-limited listener ---

type limitedNetListener struct {
	net.Listener
	connLimit *connLimiter
}

func (l *limitedNetListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !l.connLimit.acquire() {
			conn.Close()
			continue
		}
		return &limitedConn{Conn: conn, limiter: l.connLimit}, nil
	}
}

type limitedConn struct {
	net.Conn
	limiter  *connLimiter
	released sync.Once
}

func (c *limitedConn) Close() error {
	c.released.Do(func() { c.limiter.release() })
	return c.Conn.Close()
}

// --- Helpers for auth used in tests ---

func HashAPIKey(key string) string {
	h := sha256.Sum256([]byte(key))
	return hex.EncodeToString(h[:])
}

// ValidateInboundAuth performs authentication for a request. Exported for tests.
func ValidateInboundAuth(auth *InboundAuth, r *http.Request) (bool, string) {
	return auth.Authenticate(r)
}

// BuildInboundMux creates a handler that blocks non-inbound routes.
// Memory/intents/execute must not be reachable on :8081.
func BuildInboundMux(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/memory") ||
			strings.HasPrefix(path, "/intents") ||
			strings.HasPrefix(path, "/execute") ||
			path == "/healthz" {
			writeError(w, http.StatusNotFound, "not found on this port")
			return
		}
		handler.ServeHTTP(w, r)
	})
}

// InboundMuxForJSON serializes response as JSON.
func InboundMuxForJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}
