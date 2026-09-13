package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRelayPartialTLSNeverFallsBackToPlaintext(t *testing.T) {
	for _, certOnly := range []bool{true, false} {
		cfg := testConfig()
		cfg.AllowInsecurePlaintext = true
		if certOnly {
			cfg.TLSCertChainPath = "missing.crt"
		} else {
			cfg.TLSPrivateKeyPath = "missing.key"
		}
		server, err := NewRelayServer(cfg)
		if server != nil {
			server.Close()
		}
		if err == nil {
			t.Fatal("partial TLS configuration downgraded to plaintext")
		}
	}
}

func TestRelayReadinessMatchesRevocationAdmission(t *testing.T) {
	s := &RelayServer{config: &RelayConfig{RevocationFeedURL: "http://127.0.0.1/feed", RevocationPollInterval: time.Second}}
	check := func(want int) {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleReadiness(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if w.Code != want {
			t.Fatalf("got %d want %d", w.Code, want)
		}
	}
	check(503)
	s.revocationLastSuccess = time.Now()
	check(200)
	s.revocationLastSuccess = time.Now().Add(-14 * time.Second)
	check(503)
	s.revocationLastSuccess = time.Now()
	s.closing = true
	check(503)
	w := httptest.NewRecorder()
	s.handleReadiness(w, httptest.NewRequest(http.MethodPost, "/readyz", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
