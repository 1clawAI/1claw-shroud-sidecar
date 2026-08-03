package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ActivityTracker records the last time any request was handled.
type ActivityTracker struct {
	mu             sync.Mutex
	lastActivityAt time.Time
	egressBytes    atomic.Int64
}

func NewActivityTracker() *ActivityTracker {
	return &ActivityTracker{lastActivityAt: time.Now()}
}

func (a *ActivityTracker) Touch() {
	a.mu.Lock()
	a.lastActivityAt = time.Now()
	a.mu.Unlock()
}

func (a *ActivityTracker) LastActivity() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastActivityAt
}

func (a *ActivityTracker) IdleDuration() time.Duration {
	return time.Since(a.LastActivity())
}

// AddEgress records outbound bytes (LLM proxy / inbound reverse-proxy responses).
func (a *ActivityTracker) AddEgress(n int64) {
	if n > 0 {
		a.egressBytes.Add(n)
	}
}

// TakeEgressDelta returns and resets the accumulated egress byte counter.
func (a *ActivityTracker) TakeEgressDelta() int64 {
	return a.egressBytes.Swap(0)
}

// IdleReporter periodically PATCHes /v1/runtimes/{id} with the last activity
// timestamp and egress byte delta for billing/enforcement.
type IdleReporter struct {
	tm          *TokenManager
	baseURL     string
	runtimeID   string
	idleTimeout time.Duration
	activity    *ActivityTracker
	client      *http.Client
	warnedIdle  bool
}

func NewIdleReporter(tm *TokenManager, baseURL, runtimeID string, idleTimeoutSecs int, activity *ActivityTracker) *IdleReporter {
	return &IdleReporter{
		tm:          tm,
		baseURL:     baseURL,
		runtimeID:   runtimeID,
		idleTimeout: time.Duration(idleTimeoutSecs) * time.Second,
		activity:    activity,
		client:      &http.Client{Timeout: 10 * time.Second},
	}
}

func (ir *IdleReporter) Run(ctx context.Context) {
	if ir.runtimeID == "" {
		log.Println("[idle-reporter] ONECLAW_RUNTIME_ID not set, idle reporting disabled")
		return
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	log.Printf("[idle-reporter] reporting to runtime %s every 30s (idle timeout: %s)", ir.runtimeID, ir.idleTimeout)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ir.report(ctx)
		}
	}
}

func (ir *IdleReporter) report(ctx context.Context) {
	lastActivity := ir.activity.LastActivity()
	idle := time.Since(lastActivity)
	egressDelta := ir.activity.TakeEgressDelta()

	if idle > ir.idleTimeout && !ir.warnedIdle {
		log.Printf("[idle-reporter] WARNING: runtime %s idle for %s (threshold: %s)", ir.runtimeID, idle.Round(time.Second), ir.idleTimeout)
		ir.warnedIdle = true
	} else if idle <= ir.idleTimeout {
		ir.warnedIdle = false
	}

	url := fmt.Sprintf("%s/v1/runtimes/%s", ir.baseURL, ir.runtimeID)
	body := fmt.Sprintf(
		`{"last_activity_at":"%s","egress_bytes_delta":%d}`,
		lastActivity.UTC().Format(time.RFC3339),
		egressDelta,
	)

	req, err := ir.tm.AuthedRequest("PATCH", url, strings.NewReader(body))
	if err != nil {
		log.Printf("[idle-reporter] auth error: %v", err)
		// Put delta back so we don't lose metering on auth blips
		ir.activity.AddEgress(egressDelta)
		return
	}
	req = req.WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ir.client.Do(req)
	if err != nil {
		log.Printf("[idle-reporter] PATCH error: %v", err)
		ir.activity.AddEgress(egressDelta)
		return
	}
	resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		log.Printf("[idle-reporter] PATCH returned %d", resp.StatusCode)
		ir.activity.AddEgress(egressDelta)
	}
}

// ActivityMiddleware wraps a handler to track activity on every request.
func ActivityMiddleware(activity *ActivityTracker, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		activity.Touch()
		next.ServeHTTP(w, r)
	})
}
