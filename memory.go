package main

import (
	"container/list"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- Scratch LRU Cache ---

type scratchEntry struct {
	namespace string
	key       string
	value     json.RawMessage
	ttl       *time.Duration
	createdAt time.Time
	size      int
}

type ScratchLRU struct {
	mu         sync.Mutex
	maxEntries int
	maxBytes   int
	items      map[string]*list.Element
	evictList  *list.List
	totalBytes int
}

func NewScratchLRU(maxEntries, maxBytes int) *ScratchLRU {
	return &ScratchLRU{
		maxEntries: maxEntries,
		maxBytes:   maxBytes,
		items:      make(map[string]*list.Element),
		evictList:  list.New(),
	}
}

func scratchKey(ns, key string) string {
	return ns + "\x00" + key
}

func (c *ScratchLRU) Get(namespace, key string) (*scratchEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := scratchKey(namespace, key)
	elem, ok := c.items[k]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*scratchEntry)

	if entry.ttl != nil && time.Since(entry.createdAt) > *entry.ttl {
		c.removeElement(elem)
		return nil, false
	}

	c.evictList.MoveToFront(elem)
	return entry, true
}

func (c *ScratchLRU) Put(namespace, key string, value json.RawMessage, ttl *time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := scratchKey(namespace, key)
	entrySize := len(value) + len(namespace) + len(key)

	if elem, ok := c.items[k]; ok {
		old := elem.Value.(*scratchEntry)
		c.totalBytes -= old.size
		old.value = value
		old.size = entrySize
		old.ttl = ttl
		old.createdAt = time.Now()
		c.totalBytes += entrySize
		c.evictList.MoveToFront(elem)
	} else {
		entry := &scratchEntry{
			namespace: namespace,
			key:       key,
			value:     value,
			ttl:       ttl,
			createdAt: time.Now(),
			size:      entrySize,
		}
		elem := c.evictList.PushFront(entry)
		c.items[k] = elem
		c.totalBytes += entrySize
	}

	for c.evictList.Len() > c.maxEntries || c.totalBytes > c.maxBytes {
		c.removeOldest()
	}
}

func (c *ScratchLRU) Delete(namespace, key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	k := scratchKey(namespace, key)
	elem, ok := c.items[k]
	if !ok {
		return false
	}
	c.removeElement(elem)
	return true
}

func (c *ScratchLRU) ListKeys(namespace string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()

	var keys []string
	prefix := namespace + "\x00"
	for k, elem := range c.items {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		entry := elem.Value.(*scratchEntry)
		if entry.ttl != nil && time.Since(entry.createdAt) > *entry.ttl {
			c.removeElement(elem)
			continue
		}
		keys = append(keys, entry.key)
	}
	return keys
}

// FlushToVault writes all non-expired scratch entries to the durable tier (best-effort).
func (c *ScratchLRU) FlushToVault(ctx context.Context, tm *TokenManager, baseURL, agentID string) int {
	c.mu.Lock()
	var entries []*scratchEntry
	for _, elem := range c.items {
		entry := elem.Value.(*scratchEntry)
		if entry.ttl != nil && time.Since(entry.createdAt) > *entry.ttl {
			continue
		}
		entries = append(entries, entry)
	}
	c.mu.Unlock()

	client := &http.Client{Timeout: 5 * time.Second}
	flushed := 0
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return flushed
		default:
		}
		body, _ := json.Marshal(map[string]interface{}{
			"value": string(entry.value),
			"tier":  "durable",
		})
		url := fmt.Sprintf("%s/v1/agents/%s/memory/%s/%s", baseURL, agentID, entry.namespace, entry.key)
		req, err := tm.AuthedRequest("PUT", url, strings.NewReader(string(body)))
		if err != nil {
			log.Printf("[scratch-flush] auth error: %v", err)
			continue
		}
		req = req.WithContext(ctx)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("[scratch-flush] %s/%s: %v", entry.namespace, entry.key, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode/100 == 2 {
			flushed++
		} else {
			log.Printf("[scratch-flush] %s/%s: HTTP %d", entry.namespace, entry.key, resp.StatusCode)
		}
	}
	return flushed
}

func (c *ScratchLRU) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evictList.Len()
}

func (c *ScratchLRU) TotalBytes() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.totalBytes
}

func (c *ScratchLRU) removeOldest() {
	elem := c.evictList.Back()
	if elem == nil {
		return
	}
	c.removeElement(elem)
}

func (c *ScratchLRU) removeElement(elem *list.Element) {
	c.evictList.Remove(elem)
	entry := elem.Value.(*scratchEntry)
	k := scratchKey(entry.namespace, entry.key)
	delete(c.items, k)
	c.totalBytes -= entry.size
}

// --- Memory API Handlers ---

type MemoryHandler struct {
	tm       *TokenManager
	baseURL  string
	agentID  string
	scratch  *ScratchLRU
	client   *http.Client
	activity *ActivityTracker
}

func NewMemoryHandler(tm *TokenManager, baseURL, agentID string, scratch *ScratchLRU, activity *ActivityTracker) *MemoryHandler {
	return &MemoryHandler{
		tm:       tm,
		baseURL:  baseURL,
		agentID:  agentID,
		scratch:  scratch,
		client:   &http.Client{Timeout: 30 * time.Second},
		activity: activity,
	}
}

func (h *MemoryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.activity.Touch()

	path := strings.TrimPrefix(r.URL.Path, "/memory")
	path = strings.TrimPrefix(path, "/")

	if r.Method == http.MethodPost && (path == "search" || path == "search/") {
		h.handleSearch(w, r)
		return
	}

	parts := strings.SplitN(path, "/", 2)

	switch {
	case len(parts) == 1 && parts[0] != "":
		// /memory/{namespace}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "GET only")
			return
		}
		h.handleListKeys(w, r, parts[0])

	case len(parts) == 2 && parts[0] != "" && parts[1] != "":
		namespace, key := parts[0], parts[1]
		switch r.Method {
		case http.MethodGet:
			h.handleGet(w, r, namespace, key)
		case http.MethodPut:
			h.handlePut(w, r, namespace, key)
		case http.MethodDelete:
			h.handleDelete(w, r, namespace, key)
		default:
			writeError(w, http.StatusMethodNotAllowed, "GET, PUT, DELETE only")
		}

	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (h *MemoryHandler) handleListKeys(w http.ResponseWriter, r *http.Request, namespace string) {
	url := fmt.Sprintf("%s/v1/agents/%s/memory/%s", h.baseURL, h.agentID, namespace)
	h.proxyGET(w, r, url)
}

func (h *MemoryHandler) handleGet(w http.ResponseWriter, r *http.Request, namespace, key string) {
	if entry, ok := h.scratch.Get(namespace, key); ok {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-1Claw-Tier", "scratch")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"key":   key,
			"value": json.RawMessage(entry.value),
			"tier":  "scratch",
		})
		return
	}

	url := fmt.Sprintf("%s/v1/agents/%s/memory/%s/%s", h.baseURL, h.agentID, namespace, key)
	h.proxyGET(w, r, url)
}

func (h *MemoryHandler) handlePut(w http.ResponseWriter, r *http.Request, namespace, key string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}

	var req struct {
		Value      json.RawMessage `json:"value"`
		Tier       string          `json:"tier"`
		TTLSeconds *int            `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Tier == "scratch" {
		var ttl *time.Duration
		if req.TTLSeconds != nil {
			d := time.Duration(*req.TTLSeconds) * time.Second
			ttl = &d
		}
		h.scratch.Put(namespace, key, req.Value, ttl)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "tier": "scratch"})
		return
	}

	url := fmt.Sprintf("%s/v1/agents/%s/memory/%s/%s", h.baseURL, h.agentID, namespace, key)
	h.proxyBody(w, r, "PUT", url, body)
}

func (h *MemoryHandler) handleDelete(w http.ResponseWriter, r *http.Request, namespace, key string) {
	h.scratch.Delete(namespace, key)
	url := fmt.Sprintf("%s/v1/agents/%s/memory/%s/%s", h.baseURL, h.agentID, namespace, key)
	h.proxyMethod(w, r, "DELETE", url)
}

func (h *MemoryHandler) handleSearch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 65536))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	url := fmt.Sprintf("%s/v1/agents/%s/memory/search", h.baseURL, h.agentID)
	h.proxyBody(w, r, "POST", url, body)
}

func (h *MemoryHandler) proxyGET(w http.ResponseWriter, _ *http.Request, url string) {
	req, err := h.tm.AuthedRequest("GET", url, nil)
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

func (h *MemoryHandler) proxyBody(w http.ResponseWriter, _ *http.Request, method, url string, body []byte) {
	req, err := h.tm.AuthedRequest(method, url, strings.NewReader(string(body)))
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

func (h *MemoryHandler) proxyMethod(w http.ResponseWriter, _ *http.Request, method, url string) {
	req, err := h.tm.AuthedRequest(method, url, nil)
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

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for key, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
