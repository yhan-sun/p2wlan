package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

	// Browser development origins are no longer trusted, and
	// unknown origins are rejected the same way.
	for _, origin := range []string{
		"http://legacy.invalid",
		"http://legacy-loopback.invalid",
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

func TestRateLimitIgnoresForwardedForFromUntrustedClient(t *testing.T) {
	t.Setenv("CONTROL_TRUSTED_PROXY_CIDRS", "")
	handler := rateLimit(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}, 1, time.Minute)

	for attempt, spoofed := range []string{"198.51.100.1", "198.51.100.2"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.RemoteAddr = "203.0.113.10:43210"
		req.Header.Set("X-Forwarded-For", spoofed)
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		if attempt == 0 && recorder.Code != http.StatusNoContent {
			t.Fatalf("first request: got %d", recorder.Code)
		}
		if attempt == 1 && recorder.Code != http.StatusTooManyRequests {
			t.Fatalf("spoofed forwarded-for bypassed limiter: got %d", recorder.Code)
		}
	}
}

func TestRateLimitUsesForwardedForOnlyFromTrustedProxy(t *testing.T) {
	t.Setenv("CONTROL_TRUSTED_PROXY_CIDRS", "127.0.0.0/8")
	handler := rateLimit(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}, 1, time.Minute)

	for _, clientIP := range []string{"198.51.100.1", "198.51.100.2"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/login", nil)
		req.RemoteAddr = "127.0.0.1:43210"
		req.Header.Set("X-Forwarded-For", clientIP)
		recorder := httptest.NewRecorder()
		handler(recorder, req)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("independent client %s was merged at proxy: got %d", clientIP, recorder.Code)
		}
	}
}
