package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCORSOnlyAllowsExplicitlyConfiguredOrigins(t *testing.T) {
	t.Setenv("CONTROL_ALLOWED_ORIGINS", "https://console.example.com")
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, origin := range []string{
		"https://console.example.com",
	} {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/login", nil)
		req.Header.Set("Origin", origin)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Fatalf("origin %s: expected 204 for preflight, got %d", origin, rr.Code)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != origin {
			t.Fatalf("origin %s: expected allow-origin %q, got %q", origin, origin, got)
		}
	}
}

func TestWithCORSRejectsLocalDevAndUnknownOrigins(t *testing.T) {
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// The deleted React/Vite dev server origins are no longer trusted, and
	// unknown origins are rejected the same way.
	for _, origin := range []string{
		"http://localhost:1420",
		"http://127.0.0.1:1420",
		"http://localhost:5173",
		"https://example.invalid",
	} {
		req := httptest.NewRequest(http.MethodOptions, "/api/v1/login", nil)
		req.Header.Set("Origin", origin)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != http.StatusNoContent {
			t.Fatalf("origin %s: expected 204 for preflight, got %d", origin, rr.Code)
		}
		if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("origin %s: unexpected allow-origin header: %q", origin, got)
		}
	}
}
