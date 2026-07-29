package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// testConfig returns a RelayConfig suitable for local testing (plaintext enabled).
func testConfig() *RelayConfig {
	return &RelayConfig{
		SendQueueCapacity:      10,
		RegisterTimeout:        1 * time.Second,
		IdleTimeout:            5 * time.Second,
		MaxConnections:         10,
		MaxFramePayload:        65535,
		AllowInsecurePlaintext: true,
		RequireAuthentication:  false,
	}
}

func startTestServer(t *testing.T, config *RelayConfig) (string, func()) {
	t.Helper()
	_, addr, cleanup := startTestServerWithInstance(t, config)
	return addr, cleanup
}

func startTestServerWithInstance(t *testing.T, config *RelayConfig) (*RelayServer, string, func()) {
	t.Helper()
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to start relay server: %v", err)
	}

	go server.Serve()

	cleanup := func() {
		_ = server.Close()
	}

	return server, server.Addr().String(), cleanup
}

func readTestFrame(t *testing.T, conn net.Conn) (byte, []byte) {
	t.Helper()
	header := make([]byte, frameHeader)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatalf("read frame header: %v", err)
	}
	if string(header[:4]) != string(magic) {
		t.Fatalf("unexpected frame magic: %q", string(header[:4]))
	}
	length := int(binary.BigEndian.Uint16(header[6:8]))
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(conn, payload); err != nil {
			t.Fatalf("read frame payload: %v", err)
		}
	}
	return header[5], payload
}

func TestEnvValidation(t *testing.T) {
	t.Setenv("RELAY_MAX_CONNECTIONS", "abc")
	_, err := parseConfig(nil)
	if err == nil {
		t.Error("expected error for invalid RELAY_MAX_CONNECTIONS env value, got nil")
	}
}

func TestRevocationPollIntervalEnvValidation(t *testing.T) {
	t.Setenv("RELAY_REVOCATION_POLL_INTERVAL", "not-a-duration")
	_, err := parseConfig([]string{"-require-auth=false"})
	if err == nil {
		t.Fatal("expected error for invalid RELAY_REVOCATION_POLL_INTERVAL env value")
	}
}

func TestConfigValidation(t *testing.T) {
	// Test invalid config values reject on parseConfig
	_, err := parseConfig([]string{"-send-queue=0"})
	if err == nil {
		t.Error("expected error for 0 send queue capacity")
	}

	// Test valid configuration parsing (with auth disabled for test)
	cfg, err := parseConfig([]string{"-send-queue=64", "-register-timeout=10s", "-require-auth=false"})
	if err != nil {
		t.Fatalf("unexpected parsing error: %v", err)
	}
	if cfg.SendQueueCapacity != 64 {
		t.Errorf("expected SendQueueCapacity 64, got %d", cfg.SendQueueCapacity)
	}
	if cfg.RegisterTimeout != 10*time.Second {
		t.Errorf("expected RegisterTimeout 10s, got %v", cfg.RegisterTimeout)
	}

	_, err = parseConfig([]string{"-require-auth=false", "-revocation-feed-url=https://control.example.test/api/v1/relay/revocations"})
	if err == nil {
		t.Fatal("expected error when revocation feed URL is configured without token")
	}
}

func TestAuthFailureRateLimitConfigValidation(t *testing.T) {
	cfg, err := parseConfig([]string{"-require-auth=false", "-auth-failure-limit=7", "-auth-failure-window=2m"})
	if err != nil {
		t.Fatalf("unexpected parsing error: %v", err)
	}
	if cfg.AuthFailureLimit != 7 || cfg.AuthFailureWindow != 2*time.Minute {
		t.Fatalf("unexpected auth failure limit config: %+v", cfg)
	}

	if _, err := parseConfig([]string{"-require-auth=false", "-auth-failure-limit=-1"}); err == nil {
		t.Fatal("expected error for negative auth failure limit")
	}
	if _, err := parseConfig([]string{"-require-auth=false", "-auth-failure-limit=1", "-auth-failure-window=0s"}); err == nil {
		t.Fatal("expected error for enabled auth failure limit with zero window")
	}

	cfg, err = parseConfig([]string{"-require-auth=false", "-auth-failure-limit=0", "-auth-failure-window=0s"})
	if err != nil {
		t.Fatalf("disabled auth failure limiter should allow zero window: %v", err)
	}
	if cfg.AuthFailureLimit != 0 {
		t.Fatalf("expected disabled auth failure limiter, got %d", cfg.AuthFailureLimit)
	}
}

func TestVerifyTicketRejectsRevokedJTIAndDevice(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-test"
	const jti = "jti-revoked"
	const deviceID = "device-revoked"
	ticket := signRelayTicketForTest(t, priv, kid, jti, deviceID)

	baseConfig := &RelayConfig{
		RelayAudience:      "relay-test",
		RelayRegion:        "test-region",
		TicketMaxClockSkew: time.Second,
	}
	baseKeyring := map[string]ed25519.PublicKey{kid: pub}

	server := &RelayServer{config: baseConfig, ticketKeyring: baseKeyring}
	if _, err := server.verifyTicket(ticket); err != nil {
		t.Fatalf("valid ticket rejected: %v", err)
	}

	server.revokedTicketJTIs = map[string]struct{}{jti: {}}
	if _, err := server.verifyTicket(ticket); err == nil {
		t.Fatal("ticket with revoked jti should be rejected")
	}

	server.revokedTicketJTIs = nil
	server.revokedDeviceIDs = map[string]struct{}{deviceID: {}}
	if _, err := server.verifyTicket(ticket); err == nil {
		t.Fatal("ticket for revoked device should be rejected")
	}
}

func TestVerifyTicketAllowsLegacyTicketWithoutCredentialIDButKeepsDenylists(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-test"
	const jti = "jti-legacy"
	const deviceID = "device-legacy"
	legacyTicket := signRelayTicketForTest(t, priv, kid, jti, deviceID, "")

	server := newAuthTestRelayServer(pub, kid)
	server.applyRevocationSnapshot(relayRevocationFeedSnapshot{
		Version:              1,
		RevokedCredentialIDs: []string{"credential-revoked-only"},
	})
	if _, err := server.verifyTicket(legacyTicket); err != nil {
		t.Fatalf("legacy ticket without credential_id should remain valid: %v", err)
	}

	server.applyRevocationSnapshot(relayRevocationFeedSnapshot{
		Version:     2,
		RevokedJTIs: []string{jti},
	})
	if _, err := server.verifyTicket(legacyTicket); err == nil {
		t.Fatal("legacy ticket should still be rejected by revoked jti")
	}

	server = newAuthTestRelayServer(pub, kid)
	server.revokedDeviceIDs = map[string]struct{}{deviceID: {}}
	if _, err := server.verifyTicket(legacyTicket); err == nil {
		t.Fatal("legacy ticket should still be rejected by local device denylist")
	}
}

func TestRevocationFeedRejectsRevokedDeviceAndCredential(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-test"
	const revokedDeviceID = "device-revoked-by-feed"
	const revokedCredentialID = "credential-revoked-by-feed"
	deviceTicket := signRelayTicketForTest(t, priv, kid, "jti-device-feed", revokedDeviceID, "credential-ok")
	credentialTicket := signRelayTicketForTest(t, priv, kid, "jti-credential-feed", "device-ok", revokedCredentialID)

	server := newAuthTestRelayServer(pub, kid)
	if _, err := server.verifyTicket(deviceTicket); err != nil {
		t.Fatalf("valid device ticket rejected before feed refresh: %v", err)
	}
	if _, err := server.verifyTicket(credentialTicket); err != nil {
		t.Fatalf("valid credential ticket rejected before feed refresh: %v", err)
	}

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer feed-token" {
			t.Fatalf("unexpected Authorization header: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(relayRevocationFeedSnapshot{
			GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
			Version:              1,
			RevokedDeviceIDs:     []string{revokedDeviceID},
			RevokedCredentialIDs: []string{revokedCredentialID},
		})
	}))
	defer feed.Close()

	server.config.RevocationFeedURL = feed.URL
	server.config.RevocationFeedToken = "feed-token"
	if err := server.refreshRevocationFeed(context.Background()); err != nil {
		t.Fatalf("refreshRevocationFeed: %v", err)
	}
	if _, err := server.verifyTicket(deviceTicket); err == nil {
		t.Fatal("ticket for feed-revoked device should be rejected")
	}
	if _, err := server.verifyTicket(credentialTicket); err == nil {
		t.Fatal("ticket for feed-revoked credential should be rejected")
	}
}

func TestRevocationFeedRejectsRevokedJTI(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-test"
	const jti = "jti-revoked-by-feed"
	ticket := signRelayTicketForTest(t, priv, kid, jti, "device-ok", "credential-ok")

	server := newAuthTestRelayServer(pub, kid)
	if _, err := server.verifyTicket(ticket); err != nil {
		t.Fatalf("valid ticket rejected before feed refresh: %v", err)
	}

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer feed-token" {
			t.Fatalf("unexpected Authorization header: %q", r.Header.Get("Authorization"))
		}
		_ = json.NewEncoder(w).Encode(relayRevocationFeedSnapshot{
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
			Version:     1,
			RevokedJTIs: []string{jti},
		})
	}))
	defer feed.Close()

	server.config.RevocationFeedURL = feed.URL
	server.config.RevocationFeedToken = "feed-token"
	if err := server.refreshRevocationFeed(context.Background()); err != nil {
		t.Fatalf("refreshRevocationFeed: %v", err)
	}
	if _, err := server.verifyTicket(ticket); err == nil {
		t.Fatal("ticket for feed-revoked jti should be rejected")
	}
}

func TestRevocationFeedFailurePreservesExistingSnapshot(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-test"
	const deviceID = "device-revoked-before-failure"
	ticket := signRelayTicketForTest(t, priv, kid, "jti-preserve", deviceID, "credential-preserve")

	server := newAuthTestRelayServer(pub, kid)
	server.applyRevocationSnapshot(relayRevocationFeedSnapshot{
		Version:          1,
		RevokedDeviceIDs: []string{deviceID},
	})

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "feed unavailable", http.StatusServiceUnavailable)
	}))
	defer feed.Close()

	server.config.RevocationFeedURL = feed.URL
	server.config.RevocationFeedToken = "feed-token"
	if err := server.refreshRevocationFeed(context.Background()); err == nil {
		t.Fatal("expected refreshRevocationFeed to fail")
	}
	if _, err := server.verifyTicket(ticket); err == nil {
		t.Fatal("existing revocation snapshot should remain active after feed failure")
	}
}

func TestRevocationFeedEmptySnapshotReplacesOnlineButKeepsLocalDenylist(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-test"
	const onlineDeviceID = "device-online-cleared"
	const localDeviceID = "device-local-static"
	onlineTicket := signRelayTicketForTest(t, priv, kid, "jti-online-cleared", onlineDeviceID, "credential-online")
	localTicket := signRelayTicketForTest(t, priv, kid, "jti-local-static", localDeviceID, "credential-local")

	server := newAuthTestRelayServer(pub, kid)
	server.revokedDeviceIDs = map[string]struct{}{localDeviceID: {}}
	server.applyRevocationSnapshot(relayRevocationFeedSnapshot{
		Version:          1,
		RevokedDeviceIDs: []string{onlineDeviceID},
	})
	if _, err := server.verifyTicket(onlineTicket); err == nil {
		t.Fatal("online snapshot should initially reject online-revoked device")
	}

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(relayRevocationFeedSnapshot{
			GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
			Version:              2,
			RevokedDeviceIDs:     []string{},
			RevokedCredentialIDs: []string{},
			RevokedJTIs:          []string{},
		})
	}))
	defer feed.Close()

	server.config.RevocationFeedURL = feed.URL
	server.config.RevocationFeedToken = "feed-token"
	if err := server.refreshRevocationFeed(context.Background()); err != nil {
		t.Fatalf("refreshRevocationFeed: %v", err)
	}
	if _, err := server.verifyTicket(onlineTicket); err != nil {
		t.Fatalf("empty feed snapshot should clear prior online revocation: %v", err)
	}
	if _, err := server.verifyTicket(localTicket); err == nil {
		t.Fatal("local static denylist should remain active after empty online snapshot")
	}
}

func TestRevocationFeedRejectsOversizedJSON(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	server := newAuthTestRelayServer(pub, "kid-test")

	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"generated_at":"2026-07-25T00:00:00Z","version":1,"revoked_device_ids":[],"revoked_credential_ids":[],"revoked_jtis":[]}`))
		_, _ = w.Write(bytes.Repeat([]byte(" "), maxRevocationFeedJSONBytes))
	}))
	defer feed.Close()

	server.config.RevocationFeedURL = feed.URL
	server.config.RevocationFeedToken = "feed-token"
	if err := server.refreshRevocationFeed(context.Background()); err == nil {
		t.Fatal("expected oversized revocation feed to be rejected")
	}
}

func TestRevocationPollingStopsOnClose(t *testing.T) {
	var startedOnce sync.Once
	feedStarted := make(chan struct{})
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedOnce.Do(func() { close(feedStarted) })
		<-r.Context().Done()
	}))
	defer feed.Close()

	config := testConfig()
	config.Bind = "127.0.0.1:0"
	config.RevocationFeedURL = feed.URL
	config.RevocationFeedToken = "feed-token"
	config.RevocationPollInterval = time.Hour
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("NewRelayServer: %v", err)
	}

	select {
	case <-feedStarted:
	case <-time.After(time.Second):
		_ = server.Close()
		t.Fatal("revocation feed request did not start")
	}

	closed := make(chan struct{})
	go func() {
		_ = server.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("server Close should cancel in-flight revocation poll")
	}
}

func TestLocalJSONDenylistStillRejectsTickets(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	const kid = "kid-test"
	const deviceID = "device-local-json"
	ticket := signRelayTicketForTest(t, priv, kid, "jti-local-json", deviceID, "credential-local-json")

	config := testConfig()
	config.Bind = "127.0.0.1:0"
	config.RelayAudience = "relay-test"
	config.RelayRegion = "test-region"
	config.TicketKeyringJSON = `{"` + kid + `":"` + hex.EncodeToString(pub) + `"}`
	config.TicketRevokedDevicesJSON = `["` + deviceID + `"]`
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("NewRelayServer: %v", err)
	}
	defer server.Close()

	if _, err := server.verifyTicket(ticket); err == nil {
		t.Fatal("local JSON device denylist should reject ticket")
	}
}

func newAuthTestRelayServer(pub ed25519.PublicKey, kid string) *RelayServer {
	return &RelayServer{
		config: &RelayConfig{
			RelayAudience:      "relay-test",
			RelayRegion:        "test-region",
			TicketMaxClockSkew: time.Second,
		},
		ticketKeyring: map[string]ed25519.PublicKey{kid: pub},
	}
}

func signRelayTicketForTest(t *testing.T, privateKey ed25519.PrivateKey, kid, jti, deviceID string, credentialID ...string) string {
	t.Helper()
	now := time.Now()
	credID := "credential-test"
	if len(credentialID) > 0 {
		credID = credentialID[0]
	}
	claims := relayTicketClaims{
		DeviceID:      deviceID,
		CredentialID:  credID,
		NetworkID:     "network-test",
		NodeID:        deviceID,
		RelayRegion:   "test-region",
		RelayProtocol: 1,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "p2wlan-control",
			Subject:   deviceID,
			Audience:  jwt.ClaimStrings{"relay-test"},
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Second)),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = kid
	token.Header["typ"] = "p2wlan-relay+jwt"
	signed, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return signed
}

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

func TestSendQueueFullBackpressure(t *testing.T) {
	config := testConfig()
	config.SendQueueCapacity = 1
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	bob, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial bob: %v", err)
	}
	defer bob.Close()
	_, _ = bob.Write(makeFrame(msgRegister, []byte("bob")))

	buf := make([]byte, 1024)
	_, err = io.ReadAtLeast(bob, buf, frameHeader)
	if err != nil {
		t.Fatalf("read bob registered: %v", err)
	}
	if buf[5] != msgRegistered {
		t.Fatalf("expected registered, got %d", buf[5])
	}

	alice, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial alice: %v", err)
	}
	defer alice.Close()
	_, _ = alice.Write(makeFrame(msgRegister, []byte("alice")))
	_, _ = io.ReadAtLeast(alice, buf, frameHeader)

	payload := make([]byte, 60000)
	payload[0] = byte(len("bob"))
	copy(payload[1:], "bob")

	gotBackpressure := false
	for i := 0; i < 150; i++ {
		_, err = alice.Write(makeFrame(msgForward, payload))
		if err != nil {
			break
		}
		_ = alice.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, err := alice.Read(buf)
		if err == nil && n >= frameHeader && buf[5] == msgError {
			code := binary.BigEndian.Uint16(buf[8:10])
			if code == 4008 {
				gotBackpressure = true
				break
			}
		}
	}
	if !gotBackpressure {
		t.Error("expected backpressure error 4008")
	}
}

func TestRegisterTimeout(t *testing.T) {
	config := testConfig()
	config.RegisterTimeout = 100 * time.Millisecond
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	time.Sleep(200 * time.Millisecond)

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	if buf[5] != msgError {
		t.Fatalf("expected error msg, got %d", buf[5])
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4003 {
		t.Errorf("expected code 4003 (register timeout), got %d", code)
	}
}

func TestIdleTimeout(t *testing.T) {
	config := testConfig()
	config.IdleTimeout = 100 * time.Millisecond
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write(makeFrame(msgRegister, []byte("idle-client")))

	buf := make([]byte, 100)
	_, _ = io.ReadAtLeast(conn, buf, frameHeader)

	time.Sleep(200 * time.Millisecond)

	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	if buf[5] != msgError {
		t.Fatalf("expected error msg, got %d", buf[5])
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4009 {
		t.Errorf("expected code 4009 (idle timeout), got %d", code)
	}
}

func TestMaxConnections(t *testing.T) {
	config := testConfig()
	config.MaxConnections = 1
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer conn1.Close()

	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()

	buf := make([]byte, 100)
	n, err := conn2.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4005 {
		t.Errorf("expected code 4005 (max connections), got %d", code)
	}
}

func TestFrameSizeBoundary(t *testing.T) {
	config := testConfig()
	config.MaxFramePayload = 10
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	largePayload := make([]byte, 100)
	_, _ = conn.Write(makeFrame(msgRegister, largePayload))

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4006 {
		t.Errorf("expected code 4006 (frame too large), got %d", code)
	}
}

func TestOutboundFrameSizeBoundary(t *testing.T) {
	config := testConfig()
	config.MaxFramePayload = 30
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	bob, _ := net.Dial("tcp", addr)
	defer bob.Close()
	_, _ = bob.Write(makeFrame(msgRegister, []byte("bob")))
	buf := make([]byte, 1024)
	_, _ = io.ReadAtLeast(bob, buf, frameHeader)

	alice, _ := net.Dial("tcp", addr)
	defer alice.Close()
	_, _ = alice.Write(makeFrame(msgRegister, []byte("alice")))
	_, _ = io.ReadAtLeast(alice, buf, frameHeader)

	// Received payload: 1 + len("alice") + len(data) = 1 + 5 + 25 = 31 bytes (exceeds 30)
	data := make([]byte, 25)
	payload := make([]byte, 1+len("bob")+len(data))
	payload[0] = byte(len("bob"))
	copy(payload[1:], "bob")
	copy(payload[1+len("bob"):], data)

	_, _ = alice.Write(makeFrame(msgForward, payload))

	_ = alice.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := alice.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	if buf[5] != msgError {
		t.Fatalf("expected error frame type, got %d", buf[5])
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4006 {
		t.Errorf("expected 4006, got %d", code)
	}
}

func TestRelayStatsTrackRegistrationLimitsAndForwarding(t *testing.T) {
	config := testConfig()
	config.MaxConnections = 2
	server, addr, cleanup := startTestServerWithInstance(t, config)
	defer cleanup()

	bob, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial bob: %v", err)
	}
	defer bob.Close()
	_, _ = bob.Write(makeFrame(msgRegister, []byte("bob")))
	typ, payload := readTestFrame(t, bob)
	if typ != msgRegistered || string(payload) != "bob" {
		t.Fatalf("unexpected bob registration frame: type=%d payload=%q", typ, string(payload))
	}

	alice, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial alice: %v", err)
	}
	defer alice.Close()
	_, _ = alice.Write(makeFrame(msgRegister, []byte("alice")))
	typ, payload = readTestFrame(t, alice)
	if typ != msgRegistered || string(payload) != "alice" {
		t.Fatalf("unexpected alice registration frame: type=%d payload=%q", typ, string(payload))
	}

	extra, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	defer extra.Close()
	typ, payload = readTestFrame(t, extra)
	if typ != msgError || binary.BigEndian.Uint16(payload[:2]) != 4005 {
		t.Fatalf("expected connection-limit error, got type=%d payload=%v", typ, payload)
	}

	forward := func(dst string, data []byte) []byte {
		payload := make([]byte, 1+len(dst)+len(data))
		payload[0] = byte(len(dst))
		copy(payload[1:], dst)
		copy(payload[1+len(dst):], data)
		return payload
	}

	_, _ = alice.Write(makeFrame(msgForward, forward("bob", []byte("hello"))))
	typ, payload = readTestFrame(t, bob)
	if typ != msgReceived {
		t.Fatalf("expected received frame for bob, got type=%d payload=%v", typ, payload)
	}
	_, _ = alice.Write(makeFrame(msgForward, forward("missing", []byte("hello"))))
	typ, payload = readTestFrame(t, alice)
	if typ != msgError || binary.BigEndian.Uint16(payload[:2]) != 404 {
		t.Fatalf("expected peer-not-found error, got type=%d payload=%v", typ, payload)
	}

	stats := server.Stats()
	if stats.AcceptedConnectionsTotal != 2 || stats.RejectedConnectionsTotal != 1 {
		t.Fatalf("unexpected connection stats: %+v", stats)
	}
	if stats.LegacyRegistrationsTotal != 2 || stats.RegisteredPeers != 2 {
		t.Fatalf("unexpected registration stats: %+v", stats)
	}
	if stats.ForwardedFramesTotal != 1 || stats.ForwardErrorsTotal != 1 {
		t.Fatalf("unexpected forwarding stats: %+v", stats)
	}
}

func TestDuplicateRegistration(t *testing.T) {
	config := testConfig()
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn1, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer conn1.Close()
	_, _ = conn1.Write(makeFrame(msgRegister, []byte("dup")))
	buf := make([]byte, 100)
	_, _ = io.ReadAtLeast(conn1, buf, frameHeader)

	conn2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer conn2.Close()
	_, _ = conn2.Write(makeFrame(msgRegister, []byte("dup")))
	_, _ = io.ReadAtLeast(conn2, buf, frameHeader)

	_ = conn1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn1.Read(buf)
	if err == nil {
		t.Error("expected conn1 to be closed by server")
	}

	_, _ = conn2.Write(makeFrame(msgRegister, []byte("other")))
	n, err := conn2.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4004 {
		t.Errorf("expected duplicate registration error 4004, got %d", code)
	}
}

func TestRustGoErrorCodesCompatibility(t *testing.T) {
	// 1. peer-backpressure (4008)
	err4008 := errorFrame(4008, "backpressure")
	expected4008 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 14,
		15, 168,
		'b', 'a', 'c', 'k', 'p', 'r', 'e', 's', 's', 'u', 'r', 'e',
	}
	if !bytes.Equal(err4008, expected4008) {
		t.Errorf("errorFrame 4008 mismatch\ngot:  %v\nwant: %v", err4008, expected4008)
	}

	// 2. peer-not-found (404)
	err404 := errorFrame(404, "peer not found")
	expected404 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 16,
		1, 148,
		'p', 'e', 'e', 'r', ' ', 'n', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd',
	}
	if !bytes.Equal(err404, expected404) {
		t.Errorf("errorFrame 404 mismatch\ngot:  %v\nwant: %v", err404, expected404)
	}

	// 3. registered (msgRegistered 0x02)
	registered := makeFrame(msgRegistered, []byte("nodeA"))
	expectedRegistered := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgRegistered,
		0, 5,
		'n', 'o', 'd', 'e', 'A',
	}
	if !bytes.Equal(registered, expectedRegistered) {
		t.Errorf("registered frame mismatch\ngot:  %v\nwant: %v", registered, expectedRegistered)
	}

	// 4. frame-too-large (4006)
	err4006 := errorFrame(4006, "frame too large")
	expected4006 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 17,
		15, 166,
		'f', 'r', 'a', 'm', 'e', ' ', 't', 'o', 'o', ' ', 'l', 'a', 'r', 'g', 'e',
	}
	if !bytes.Equal(err4006, expected4006) {
		t.Errorf("errorFrame 4006 mismatch\ngot:  %v\nwant: %v", err4006, expected4006)
	}

	// 5. unknown error code (9999)
	err9999 := errorFrame(9999, "unknown")
	expected9999 := []byte{
		'D', 'E', 'R', 'P',
		1,
		msgError,
		0, 9,
		39, 15,
		'u', 'n', 'k', 'n', 'o', 'w', 'n',
	}
	if !bytes.Equal(err9999, expected9999) {
		t.Errorf("errorFrame 9999 mismatch\ngot:  %v\nwant: %v", err9999, expected9999)
	}
}

func TestServerCloseReclaimsImmediately(t *testing.T) {
	config := testConfig()
	config.RegisterTimeout = 10 * time.Second
	config.IdleTimeout = 1 * time.Hour
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	go server.Serve()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write(makeFrame(msgRegister, []byte("nodeA")))

	buf := make([]byte, 100)
	_, _ = io.ReadAtLeast(conn, buf, frameHeader)

	start := time.Now()
	err = server.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
	duration := time.Since(start)

	if duration > 200*time.Millisecond {
		t.Errorf("Close took too long to reclaim connection: %v (expected < 200ms)", duration)
	}
}

func TestIllegalUTF8NodeID(t *testing.T) {
	config := testConfig()
	addr, cleanup := startTestServer(t, config)
	defer cleanup()

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	illegalBytes := []byte{0xff, 0xfe, 0xfd}
	_, _ = conn.Write(makeFrame(msgRegister, illegalBytes))

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	if n < frameHeader {
		t.Fatalf("expected error frame, got %d bytes", n)
	}
	code := binary.BigEndian.Uint16(buf[8:10])
	if code != 4000 {
		t.Errorf("expected 4000 (invalid node ID), got %d", code)
	}
}

func TestServerCloseConcurrentAccept(t *testing.T) {
	config := testConfig()
	server, err := NewRelayServer(config)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	go server.Serve()

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					conn, err := net.Dial("tcp", server.Addr().String())
					if err == nil {
						_ = conn.Close()
					}
				}
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	_ = server.Close()
	duration := time.Since(start)

	close(stop)
	wg.Wait()

	if duration > 200*time.Millisecond {
		t.Errorf("Close took too long to complete during concurrent accepts: %v", duration)
	}
}
