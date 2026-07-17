package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWithCORSAllowsDesktopAndLocalDevOrigins(t *testing.T) {
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, origin := range []string{
		"http://localhost:1420",
		"http://127.0.0.1:1420",
		"tauri://localhost",
		"http://tauri.localhost",
		"https://tauri.localhost",
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

func TestWithCORSRejectsUnknownOriginHeader(t *testing.T) {
	handler := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/login", nil)
	req.Header.Set("Origin", "https://example.invalid")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for preflight, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected allow-origin header: %q", got)
	}
}
