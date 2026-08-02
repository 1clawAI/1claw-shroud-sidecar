package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ExecuteHandler proxies Execution Intents API calls to Vault.
type ExecuteHandler struct {
	tm       *TokenManager
	baseURL  string
	agentID  string
	client   *http.Client
	activity *ActivityTracker
}

func NewExecuteHandler(tm *TokenManager, baseURL, agentID string, activity *ActivityTracker) *ExecuteHandler {
	return &ExecuteHandler{
		tm:       tm,
		baseURL:  baseURL,
		agentID:  agentID,
		client:   &http.Client{Timeout: 60 * time.Second},
		activity: activity,
	}
}

func (h *ExecuteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.activity.Touch()

	path := strings.TrimPrefix(r.URL.Path, "/execute")
	path = strings.TrimPrefix(path, "/")

	var upstream string
	var method string

	switch {
	case path == "" || path == "/":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "POST only")
			return
		}
		upstream = fmt.Sprintf("/v1/agents/%s/execute", h.agentID)
		method = http.MethodPost
	case path == "bindings" || path == "bindings/":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		upstream = fmt.Sprintf("/v1/agents/%s/bindings", h.agentID)
		method = http.MethodGet
	default:
		writeError(w, http.StatusNotFound, "unknown execute endpoint")
		return
	}

	url := h.baseURL + upstream
	if r.URL.RawQuery != "" {
		url += "?" + r.URL.RawQuery
	}

	var body io.Reader
	if method == http.MethodPost {
		body = io.LimitReader(r.Body, 5*1024*1024)
	}

	req, err := h.tm.AuthedRequest(method, url, body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "auth error: "+err.Error())
		return
	}

	resp, err := h.client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream error: "+err.Error())
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}
