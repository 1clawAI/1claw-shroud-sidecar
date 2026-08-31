package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The dashboard opens this socket directly from the browser, so the browser
// sets Origin to whatever domain the dashboard is served from. When the
// dashboard moved to 1claw.co and this allowlist did not, the upgrade was
// refused and the interactive terminal stopped working from the canonical
// domain — silently, because a rejected upgrade looks like a network problem.
//
// Nothing covered this function before, which is why the move went unnoticed.
func TestTerminalCheckOrigin(t *testing.T) {
	allowed := []string{
		"https://1claw.co",
		"http://1claw.co",
		"https://app.1claw.co",
		"https://run.1claw.co",
		"https://1claw.xyz",
		"https://app.1claw.xyz",
		"https://preview-abc.vercel.app",
		"http://localhost:3000",
		"http://127.0.0.1:3000",
	}
	for _, origin := range allowed {
		t.Run("allow "+origin, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/terminal", nil)
			r.Header.Set("Origin", origin)
			if !terminalCheckOrigin(r) {
				t.Fatalf("origin %q should be allowed", origin)
			}
		})
	}

	// A lookalike must not pass on a suffix match: 1claw.co.evil.com ends with
	// neither ".1claw.co" nor ".vercel.app", and evil-1claw.co is a different
	// registrable domain that a careless Contains() check would admit.
	denied := []string{
		"https://evil.example",
		"https://1claw.co.evil.example",
		"https://evil-1claw.co",
		"https://notvercel.app",
	}
	for _, origin := range denied {
		t.Run("deny "+origin, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/terminal", nil)
			r.Header.Set("Origin", origin)
			if terminalCheckOrigin(r) {
				t.Fatalf("origin %q should be refused", origin)
			}
		})
	}

	// A non-browser client sends no Origin at all, and the CLI is one.
	t.Run("absent origin is allowed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/terminal", nil)
		if !terminalCheckOrigin(r) {
			t.Fatal("a request with no Origin should be allowed")
		}
	})
}
