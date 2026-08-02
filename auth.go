package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// TokenManager handles JWT acquisition and auto-refresh for Vault API calls.
type TokenManager struct {
	baseURL  string
	agentID  string
	apiKey   string
	token    string
	staticJWT bool
	mu       sync.RWMutex
	expiry   time.Time
	client   *http.Client
}

func NewTokenManager(baseURL, agentID, apiKey, staticToken string) *TokenManager {
	tm := &TokenManager{
		baseURL: baseURL,
		agentID: agentID,
		apiKey:  apiKey,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
	if staticToken != "" {
		tm.token = staticToken
		tm.staticJWT = true
		tm.expiry = time.Now().Add(365 * 24 * time.Hour) // assume long-lived
	}
	return tm
}

func (tm *TokenManager) GetToken() (string, error) {
	tm.mu.RLock()
	if tm.token != "" && time.Now().Before(tm.expiry.Add(-60*time.Second)) {
		tok := tm.token
		tm.mu.RUnlock()
		return tok, nil
	}
	tm.mu.RUnlock()

	if tm.staticJWT {
		tm.mu.RLock()
		tok := tm.token
		tm.mu.RUnlock()
		return tok, nil
	}

	return tm.refresh()
}

func (tm *TokenManager) refresh() (string, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Double-check after lock acquisition
	if tm.token != "" && time.Now().Before(tm.expiry.Add(-60*time.Second)) {
		return tm.token, nil
	}

	payload := map[string]string{"api_key": tm.apiKey}
	if tm.agentID != "" {
		payload["agent_id"] = tm.agentID
	}
	body, _ := json.Marshal(payload)

	resp, err := tm.client.Post(tm.baseURL+"/v1/auth/agent-token", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, string(data))
	}

	var result struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
		AgentID     string `json:"agent_id"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("token exchange parse: %w", err)
	}

	tm.token = result.AccessToken
	if result.ExpiresIn > 0 {
		tm.expiry = time.Now().Add(time.Duration(result.ExpiresIn) * time.Second)
	} else {
		tm.expiry = time.Now().Add(55 * time.Minute)
	}

	if tm.agentID == "" && result.AgentID != "" {
		tm.agentID = result.AgentID
	}

	return tm.token, nil
}

// AuthedRequest creates an HTTP request with the Bearer token injected.
func (tm *TokenManager) AuthedRequest(method, url string, body io.Reader) (*http.Request, error) {
	token, err := tm.GetToken()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}
