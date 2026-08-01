package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func TestAuthFailuresAreRateLimitedBySource(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-rate-limit"
	keyringJSON, err := json.Marshal(map[string]string{kid: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatalf("Marshal keyring: %v", err)
	}

	config := testConfig()
	config.Bind = "127.0.0.1:0"
	config.RequireAuthentication = true
	config.AllowLegacyUnauthenticated = false
	config.TicketKeyringJSON = string(keyringJSON)
	config.RelayAudience = "relay-test"
	config.RelayRegion = "test-region"
	config.AuthFailureLimit = 2
	config.AuthFailureWindow = time.Minute
	server, addr, cleanup := startTestServerWithInstance(t, config)
	defer cleanup()

	for i := 0; i < 2; i++ {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial failure %d: %v", i, err)
		}
		_, _ = conn.Write(makeFrame(msgRegister, []byte("legacy-node")))
		typ, payload := readTestFrame(t, conn)
		_ = conn.Close()
		if typ != msgError {
			t.Fatalf("expected auth error frame, got type=%d payload=%v", typ, payload)
		}
		if got := binary.BigEndian.Uint16(payload[:2]); got != errAuthRequired {
			t.Fatalf("expected auth-required code %d, got %d", errAuthRequired, got)
		}
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial rate-limited source: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	typ, payload := readTestFrame(t, conn)
	if typ != msgError {
		t.Fatalf("expected rate-limit error frame, got type=%d payload=%v", typ, payload)
	}
	if got := binary.BigEndian.Uint16(payload[:2]); got != errAuthRateLimited {
		t.Fatalf("expected auth-rate-limited code %d, got %d", errAuthRateLimited, got)
	}

	stats := server.Stats()
	if stats.AuthFailuresTotal != 3 || stats.AuthRateLimitedTotal != 1 {
		t.Fatalf("unexpected auth failure stats: %+v", stats)
	}
	if len(stats.AuthFailureSources) != 1 {
		t.Fatalf("expected one auth failure source snapshot, got %+v", stats.AuthFailureSources)
	}
	source := stats.AuthFailureSources[0]
	if source.Failures != 2 || source.RateLimited != 1 {
		t.Fatalf("unexpected source counters: %+v", source)
	}
	if len(source.SourceKey) != 16 || strings.ContainsAny(source.SourceKey, ".:") {
		t.Fatalf("source key should be a short hash, got %q", source.SourceKey)
	}
	if source.WindowResetUnix <= time.Now().Unix() {
		t.Fatalf("expected future window reset, got %+v", source)
	}
}
