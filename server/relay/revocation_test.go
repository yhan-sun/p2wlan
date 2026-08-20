package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

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

func TestRevocationFeedEmptySnapshotCannotResurrectRevokedIdentity(t *testing.T) {
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
	if _, err := server.verifyTicket(onlineTicket); err == nil {
		t.Fatal("empty feed snapshot must not resurrect a previously revoked device")
	}
	if _, err := server.verifyTicket(localTicket); err == nil {
		t.Fatal("local static denylist should remain active after empty online snapshot")
	}
}

func TestRevocationSnapshotRejectsRollbackAndMergesEqualVersion(t *testing.T) {
	server := &RelayServer{}
	if err := server.applyRevocationSnapshot(relayRevocationFeedSnapshot{
		Version:          7,
		RevokedDeviceIDs: []string{"device-a"},
	}); err != nil {
		t.Fatalf("apply initial snapshot: %v", err)
	}
	if err := server.applyRevocationSnapshot(relayRevocationFeedSnapshot{
		Version:              7,
		RevokedCredentialIDs: []string{"credential-b"},
	}); err != nil {
		t.Fatalf("equal-version additions must be merged: %v", err)
	}
	if !server.isDeviceRevoked("device-a") || !server.isCredentialRevoked("credential-b") {
		t.Fatal("equal-version snapshot lost an already observed tombstone")
	}
	if err := server.applyRevocationSnapshot(relayRevocationFeedSnapshot{
		Version:          6,
		RevokedDeviceIDs: []string{},
	}); err == nil {
		t.Fatal("older revocation snapshot must be rejected")
	}
	if !server.isDeviceRevoked("device-a") || !server.isCredentialRevoked("credential-b") {
		t.Fatal("rollback attempt changed the active revocation set")
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
