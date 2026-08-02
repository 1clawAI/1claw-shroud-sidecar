package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// IntentsHandler proxies Intents API calls to Vault or Shroud.
type IntentsHandler struct {
	tm        *TokenManager
	targetURL string
	agentID   string
	client    *http.Client
	activity  *ActivityTracker
}

func NewIntentsHandler(tm *TokenManager, shroudURL, baseURL, agentID string, activity *ActivityTracker) *IntentsHandler {
	target := shroudURL
	if target == "" {
		target = baseURL
	}
	return &IntentsHandler{
		tm:        tm,
		targetURL: target,
		agentID:   agentID,
		client:    &http.Client{Timeout: 120 * time.Second},
		activity:  activity,
	}
}

func (h *IntentsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.activity.Touch()

	path := strings.TrimPrefix(r.URL.Path, "/intents")
	path = strings.TrimPrefix(path, "/")

	var upstream string
	switch {
	case r.Method == http.MethodPost && (path == "transactions" || path == "transactions/"):
		upstream = fmt.Sprintf("/v1/agents/%s/transactions", h.agentID)
	case r.Method == http.MethodPost && (path == "transactions/sign" || path == "transactions/sign/"):
		upstream = fmt.Sprintf("/v1/agents/%s/transactions/sign", h.agentID)
	case r.Method == http.MethodPost && (path == "sign" || path == "sign/"):
		upstream = fmt.Sprintf("/v1/agents/%s/sign", h.agentID)
	case r.Method == http.MethodGet && (path == "transactions" || path == "transactions/"):
		upstream = fmt.Sprintf("/v1/agents/%s/transactions", h.agentID)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "transactions/"):
		txID := strings.TrimPrefix(path, "transactions/")
		txID = strings.TrimSuffix(txID, "/")
		upstream = fmt.Sprintf("/v1/agents/%s/transactions/%s", h.agentID, txID)
	case r.Method == http.MethodPost && (path == "simulate" || path == "simulate/"):
		upstream = fmt.Sprintf("/v1/agents/%s/transactions/simulate", h.agentID)
	case r.Method == http.MethodPost && (path == "simulate-bundle" || path == "simulate-bundle/"):
		upstream = fmt.Sprintf("/v1/agents/%s/transactions/simulate-bundle", h.agentID)
	default:
		writeError(w, http.StatusNotFound, "unknown intents endpoint")
		return
	}

	url := h.targetURL + upstream
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}

	var body io.Reader
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		body = io.LimitReader(r.Body, 5*1024*1024)
	}

	req, err := h.tm.AuthedRequest(r.Method, url, body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth error: "+err.Error())
		return
	}

	if idempKey := r.Header.Get("Idempotency-Key"); idempKey != "" {
		req.Header.Set("Idempotency-Key", idempKey)
	}

	resp, err := h.client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}
