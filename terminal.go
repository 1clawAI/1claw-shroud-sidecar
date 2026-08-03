package main

import (
	"context"
	"crypto"
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
}

// JWKSCache caches RSA public keys from the JWKS endpoint, keyed by kid.
type JWKSCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
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
}

type shellSessionClaims struct {
	Sub       string `json:"sub"`
	RuntimeID string `json:"runtime_id"`
	OrgID     string `json:"org_id"`
	Aud       string `json:"aud"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	Jti       string `json:"jti"`
}

type terminalMessage struct {
	Type string `json:"type"`
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

func NewJWKSCache(url string, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		keys:   make(map[string]*rsa.PublicKey),
		url:    url,
		ttl:    ttl,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *JWKSCache) GetKeyByKid(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	fresh := c.keys != nil && len(c.keys) > 0 && time.Since(c.fetchedAt) < c.ttl
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

func (c *JWKSCache) refresh() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.keys) > 0 && time.Since(c.fetchedAt) < c.ttl {
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
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}

		pubKey, err := parseRSAPublicKey(k.N, k.E)
		if err != nil {
			continue
		}
		kid := k.Kid
		if kid == "" {
			kid = "_default"
		}
		keys[kid] = pubKey
	}

	if len(keys) == 0 {
		return fmt.Errorf("no suitable RS256 key found in JWKS")
	}

	c.keys = keys
	c.fetchedAt = time.Now()
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

func (h *TerminalHandler) validateToken(tokenStr string) (*shellSessionClaims, error) {
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

	pubKey, err := h.jwksCache.GetKeyByKid(header.Kid)
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

	if claims.Aud != "runtime-shell" {
		return nil, fmt.Errorf("invalid audience: %s", claims.Aud)
	}

	if h.runtimeID != "" && claims.RuntimeID != h.runtimeID {
		return nil, fmt.Errorf("runtime_id mismatch")
	}

	return &claims, nil
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
	// Fall back to /bin/sh with a plain ANSI prompt (dash ignores \[\]/\w).
	shell := "/bin/sh"
	ps1 := "\033[1;36mruntime\033[0m:\033[1;34m$USER\033[0m$ "
	if _, err := exec.LookPath("bash"); err == nil {
		shell = "bash"
		ps1 = `\[\e[1;36m\]runtime\[\e[0m\]:\[\e[1;34m\]\w\[\e[0m\]\$ `
	}
	cmd := exec.Command(shell, "-i")
	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"PS1="+ps1,
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("[terminal] failed to start pty: %v", err)
		conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "failed to start shell"))
		return
	}

	sessionCtx, sessionCancel := context.WithTimeout(context.Background(), h.sessionTimeout)
	defer sessionCancel()

	idleTimer := time.NewTimer(h.idleTimeout)
	defer idleTimer.Stop()

	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }

	// PTY → WebSocket
	go func() {
		defer closeDone()
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("[terminal] pty read error: %v", err)
				}
				return
			}
			if err := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				return
			}
		}
	}()

	// WebSocket → PTY
	go func() {
		defer closeDone()
		for {
			msgType, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}

			idleTimer.Reset(h.idleTimeout)

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
	case <-idleTimer.C:
		log.Printf("[terminal] idle timeout for user %s", claims.Sub)
	}

	cleanup(cmd, ptmx)
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
