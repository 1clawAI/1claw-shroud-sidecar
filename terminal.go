package main

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// TerminalHandler serves interactive PTY sessions over WebSocket.
type TerminalHandler struct {
	maxSessions    int
	activeSessions int32
	sessionTimeout time.Duration
	idleTimeout    time.Duration
	jwksURL        string
	jwksCache      *JWKSCache
	runtimeID      string
	ptyRegistry    *ptyRegistry
}

// JWKSCache caches RSA (RS256) and Ed25519 (EdDSA) public keys from JWKS, keyed by kid.
type JWKSCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	edKeys    map[string]ed25519.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
	url       string
	client    *http.Client
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

type shellSessionClaims struct {
	Sub       string `json:"sub"`
	RuntimeID string `json:"runtime_id"`
	OrgID     string `json:"org_id"`
	Aud       string `json:"aud"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	Jti       string `json:"jti"`
	SessionID string `json:"session_id"`
}

type terminalMessage struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

func NewJWKSCache(url string, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		keys:   make(map[string]*rsa.PublicKey),
		edKeys: make(map[string]ed25519.PublicKey),
		url:    url,
		ttl:    ttl,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *JWKSCache) hasAnyKeysLocked() bool {
	return len(c.keys) > 0 || len(c.edKeys) > 0
}

func (c *JWKSCache) GetKeyByKid(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	fresh := c.hasAnyKeysLocked() && time.Since(c.fetchedAt) < c.ttl
	if fresh {
		if kid != "" {
			if k, ok := c.keys[kid]; ok {
				c.mu.RUnlock()
				return k, nil
			}
		} else {
			// No kid — return any cached RSA key (single-key deployments).
			for _, k := range c.keys {
				c.mu.RUnlock()
				return k, nil
			}
		}
	}
	c.mu.RUnlock()

	if err := c.refresh(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if kid != "" {
		if k, ok := c.keys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("kid %q not found in JWKS", kid)
	}
	for _, k := range c.keys {
		return k, nil
	}
	return nil, fmt.Errorf("no suitable RS256 key found in JWKS")
}

func (c *JWKSCache) GetEdKeyByKid(kid string) (ed25519.PublicKey, error) {
	c.mu.RLock()
	fresh := c.hasAnyKeysLocked() && time.Since(c.fetchedAt) < c.ttl
	if fresh {
		if kid != "" {
			if k, ok := c.edKeys[kid]; ok {
				c.mu.RUnlock()
				return k, nil
			}
		} else {
			for _, k := range c.edKeys {
				c.mu.RUnlock()
				return k, nil
			}
		}
	}
	c.mu.RUnlock()

	if err := c.refresh(); err != nil {
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	if kid != "" {
		if k, ok := c.edKeys[kid]; ok {
			return k, nil
		}
		return nil, fmt.Errorf("EdDSA kid %q not found in JWKS", kid)
	}
	for _, k := range c.edKeys {
		return k, nil
	}
	return nil, fmt.Errorf("no suitable EdDSA key found in JWKS")
}

func (c *JWKSCache) refresh() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.hasAnyKeysLocked() && time.Since(c.fetchedAt) < c.ttl {
		return nil
	}

	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("jwks fetch failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks fetch HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("jwks read body: %w", err)
	}

	var jwks jwksResponse
	if err := json.Unmarshal(body, &jwks); err != nil {
		return fmt.Errorf("jwks parse: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey)
	edKeys := make(map[string]ed25519.PublicKey)
	for _, k := range jwks.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = "_default"
		}

		switch k.Kty {
		case "RSA":
			if k.Alg != "" && k.Alg != "RS256" {
				continue
			}
			pubKey, err := parseRSAPublicKey(k.N, k.E)
			if err != nil {
				continue
			}
			keys[kid] = pubKey
		case "OKP":
			if k.Crv != "Ed25519" {
				continue
			}
			if k.Alg != "" && k.Alg != "EdDSA" {
				continue
			}
			xBytes, err := base64URLDecode(k.X)
			if err != nil || len(xBytes) != ed25519.PublicKeySize {
				continue
			}
			edKeys[kid] = ed25519.PublicKey(xBytes)
		}
	}

	if len(keys) == 0 && len(edKeys) == 0 {
		return fmt.Errorf("no suitable RS256/EdDSA keys found in JWKS")
	}

	c.keys = keys
	c.edKeys = edKeys
	c.fetchedAt = time.Now()
	return nil
}

// verifyInboundAPIJWT verifies a Vault-issued API JWT (EdDSA or RS256) against JWKS.
// Fail-closed: missing JWKS cache, fetch failure, bad sig, or expired → error.
func verifyInboundAPIJWT(cache *JWKSCache, tokenStr string) error {
	if cache == nil {
		return fmt.Errorf("JWKS unavailable")
	}
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("invalid token format")
	}

	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return fmt.Errorf("decode header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return fmt.Errorf("parse header: %w", err)
	}

	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}
	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	signed := []byte(parts[0] + "." + parts[1])
	switch header.Alg {
	case "RS256":
		pubKey, err := cache.GetKeyByKid(header.Kid)
		if err != nil {
			return fmt.Errorf("get JWKS RSA key: %w", err)
		}
		hash := sha256.Sum256(signed)
		if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature); err != nil {
			return fmt.Errorf("signature verification failed")
		}
	case "EdDSA":
		pubKey, err := cache.GetEdKeyByKid(header.Kid)
		if err != nil {
			return fmt.Errorf("get JWKS EdDSA key: %w", err)
		}
		if !ed25519.Verify(pubKey, signed, signature) {
			return fmt.Errorf("signature verification failed")
		}
	default:
		return fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	var claims struct {
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return fmt.Errorf("parse claims: %w", err)
	}
	if claims.Exp <= time.Now().Unix() {
		return fmt.Errorf("token expired")
	}
	return nil
}

func parseRSAPublicKey(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64URLDecode(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64URLDecode(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func base64URLDecode(s string) ([]byte, error) {
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.StdEncoding.DecodeString(s)
}

// verifyRuntimeAudienceJWT validates an RS256 JWT from Vault JWKS for a given
// audience (runtime-shell, runtime-chat) and optional runtime_id binding.
func verifyRuntimeAudienceJWT(cache *JWKSCache, tokenStr, audience, runtimeID string) (*shellSessionClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parse header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	signature, err := base64URLDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	pubKey, err := cache.GetKeyByKid(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("get JWKS key: %w", err)
	}

	signed := []byte(parts[0] + "." + parts[1])
	hash := sha256.Sum256(signed)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], signature); err != nil {
		return nil, fmt.Errorf("signature verification failed")
	}

	var claims shellSessionClaims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	now := time.Now().Unix()
	if claims.Exp <= now {
		return nil, fmt.Errorf("token expired")
	}

	if claims.Aud != audience {
		return nil, fmt.Errorf("invalid audience: %s", claims.Aud)
	}

	if runtimeID != "" && claims.RuntimeID != runtimeID {
		return nil, fmt.Errorf("runtime_id mismatch")
	}

	return &claims, nil
}

func (h *TerminalHandler) validateToken(tokenStr string) (*shellSessionClaims, error) {
	return verifyRuntimeAudienceJWT(h.jwksCache, tokenStr, "runtime-shell", h.runtimeID)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		return origin == "https://1claw.xyz" ||
			origin == "http://1claw.xyz" ||
			strings.HasSuffix(origin, ".1claw.xyz") ||
			strings.HasSuffix(origin, ".vercel.app") ||
			strings.Contains(origin, "localhost:") ||
			strings.Contains(origin, "127.0.0.1:")
	},
}

func (h *TerminalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		writeError(w, http.StatusUnauthorized, "missing token parameter")
		return
	}

	claims, err := h.validateToken(tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token: "+err.Error())
		return
	}

	current := atomic.LoadInt32(&h.activeSessions)
	if current >= int32(h.maxSessions) {
		writeError(w, http.StatusTooManyRequests, "max terminal sessions reached")
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[terminal] websocket upgrade failed: %v", err)
		return
	}

	atomic.AddInt32(&h.activeSessions, 1)
	go h.handleSession(conn, claims)
}

func (h *TerminalHandler) handleSession(conn *websocket.Conn, claims *shellSessionClaims) {
	defer atomic.AddInt32(&h.activeSessions, -1)
	defer conn.Close()

	sessionStart := time.Now()
	emitTerminalEvent("shell_session_start", claims.Sub, h.runtimeID, 0)

	defer func() {
		duration := time.Since(sessionStart).Seconds()
		emitTerminalEvent("shell_session_end", claims.Sub, h.runtimeID, duration)
	}()

	// Prefer bash so PS1 color/cwd escapes work in the dashboard xterm.
	shell := "/bin/sh"
	ps1 := "\033[1;36mruntime\033[0m:\033[1;34m$USER\033[0m$ "
	if _, err := exec.LookPath("bash"); err == nil {
		shell = "bash"
		ps1 = `\[\e[1;36m\]runtime\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ `
	}

	if h.ptyRegistry == nil {
		h.ptyRegistry = newPtyRegistry()
		go func(reg *ptyRegistry, idle time.Duration) {
			ticker := time.NewTicker(idle)
			defer ticker.Stop()
			for range ticker.C {
				reg.reapIdle(idle)
			}
		}(h.ptyRegistry, h.idleTimeout)
	}

	live, reattached, err := h.ptyRegistry.getOrCreate(claims.SessionID, shell, ps1)
	if err != nil {
		log.Printf("[terminal] failed to start/reattach pty: %v", err)
		msg := "failed to start shell"
		if err == errSessionBusy {
			msg = "session already attached elsewhere"
		}
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, msg))
		return
	}
	if reattached {
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte("\r\n\x1b[36m[Reattached to shell session]\x1b[0m\r\n"))
	}

	ptmx := live.ptmx
	cmd := live.cmd
	sessionID := claims.SessionID

	// On WS close: detach (keep PTY) if session_id present; otherwise destroy.
	defer func() {
		if sessionID != "" {
			h.ptyRegistry.detach(sessionID)
		} else {
			cleanup(cmd, ptmx)
		}
	}()

	sessionDeadline := live.createdAt.Add(h.sessionTimeout)
	sessionCtx, sessionCancel := context.WithDeadline(context.Background(), sessionDeadline)
	defer sessionCancel()

	idleTimer := time.NewTimer(h.idleTimeout)
	defer idleTimer.Stop()

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	go func() {
		defer closeDone()
		pumpPtyToWS(ptmx, conn, done)
	}()

	go func() {
		defer closeDone()
		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}

			idleTimer.Reset(h.idleTimeout)
			live.mu.Lock()
			live.lastActive = time.Now()
			live.mu.Unlock()

			if msgType == websocket.TextMessage {
				var tmsg terminalMessage
				if json.Unmarshal(msg, &tmsg) == nil && tmsg.Type == "resize" {
					if tmsg.Cols > 0 && tmsg.Rows > 0 {
						_ = pty.Setsize(ptmx, &pty.Winsize{
							Rows: tmsg.Rows,
							Cols: tmsg.Cols,
						})
					}
					continue
				}
			}

			if _, err := ptmx.Write(msg); err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-sessionCtx.Done():
		log.Printf("[terminal] session timeout for user %s", claims.Sub)
		if sessionID != "" {
			h.ptyRegistry.destroy(sessionID)
		}
	case <-idleTimer.C:
		log.Printf("[terminal] idle timeout for user %s", claims.Sub)
		if sessionID != "" {
			h.ptyRegistry.destroy(sessionID)
		}
	}
}

func cleanup(cmd *exec.Cmd, ptmx *os.File) {
	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)

		exited := make(chan struct{})
		go func() {
			cmd.Wait()
			close(exited)
		}()

		select {
		case <-exited:
		case <-time.After(3 * time.Second):
			_ = cmd.Process.Signal(syscall.SIGKILL)
			<-exited
		}
	}

	ptmx.Close()
}

func emitTerminalEvent(event, userID, runtimeID string, durationSecs float64) {
	entry := map[string]interface{}{
		"event":      event,
		"user_id":    userID,
		"runtime_id": runtimeID,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	if durationSecs > 0 {
		entry["duration_secs"] = int(durationSecs)
	}
	line, _ := json.Marshal(entry)
	fmt.Fprintln(os.Stdout, string(line))
}
