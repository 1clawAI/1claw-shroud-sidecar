package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

// parseJWTExp returns the JWT exp claim as UTC time when present and valid.
func parseJWTExp(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, false
	}
	expInt, err := claims.Exp.Int64()
	if err != nil || expInt <= 0 {
		return time.Time{}, false
	}
	return time.Unix(expInt, 0).UTC(), true
}

func jwtExpiryFromToken(token string) time.Time {
	if exp, ok := parseJWTExp(token); ok {
		return exp
	}
	// Fallback when exp is missing — conservative default.
	return time.Now().Add(55 * time.Minute)
}

// extractAgentJWT prefers Vault-injected refresh headers, then Authorization Bearer JWT.
func extractAgentJWT(r *http.Request) string {
	if fresh := strings.TrimSpace(r.Header.Get("X-Refreshed-Agent-Token")); looksLikeJWT(fresh) {
		return fresh
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if looksLikeJWT(token) {
			return token
		}
	}
	return ""
}

// applyAgentJWTFromRequest hot-swaps the sidecar TokenManager when Vault/chat-bridge
// sends a fresher agent JWT, and returns the JWT to use for Shroud upstream auth.
func applyAgentJWTFromRequest(r *http.Request, tm *TokenManager, fallback string) string {
	if jwt := extractAgentJWT(r); jwt != "" {
		if tm != nil {
			tm.UpdateStaticJWT(jwt)
		}
		return jwt
	}
	if fallback != "" {
		return fallback
	}
	if tm != nil {
		if tok, err := tm.GetToken(); err == nil && tok != "" {
			return tok
		}
	}
	return ""
}
