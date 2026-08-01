package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

func TestCreateSignalWakesAuthenticatedWebSocketAndRemainsDurable(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("ws-signal@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "ws-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "ws-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}
	_, targetToken, err := db.CreateDeviceCredential(target.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}

	hub := signaling.NewHub()
	defer hub.Close()
	wsServer := httptest.NewServer(auth.RequireDeviceAuth(db)(signaling.ServeWS(hub)))
	defer wsServer.Close()
	dialer := websocket.Dialer{
		HandshakeTimeout: 2 * time.Second,
		Subprotocols:     []string{signaling.ProtocolName},
	}
	header := http.Header{"Authorization": []string{"Bearer " + targetToken}}
	conn, response, err := dialer.Dial("ws"+strings.TrimPrefix(wsServer.URL, "http"), header)
	if err != nil {
		if response != nil {
			t.Fatalf("websocket dial: %v (HTTP %d)", err, response.StatusCode)
		}
		t.Fatalf("websocket dial: %v", err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatalf("read ready: %v", err)
	}

	apiServer := NewServer(nil, hub, db)
	const probeEphemeralPublicKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	body := strings.NewReader(`{"to_node_id":"` + target.ID + `","type":"peer_offer","candidates":["203.0.113.10:51820"],"session_id":"sess-api-1","probe_ephemeral_public_key":"` + probeEphemeralPublicKey + `","handshake":"abcd"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  source.ID,
		NetworkID: source.NetworkID,
		UserID:    source.UserID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	recorder := httptest.NewRecorder()
	apiServer.CreateSignal(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("CreateSignal: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	var created struct {
		Success         bool            `json:"success"`
		ProtocolVersion int64           `json:"protocol_version"`
		Signal          database.Signal `json:"signal"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created signal: %v", err)
	}
	if !created.Success || created.ProtocolVersion != database.SignalProtocolVersion || created.Signal.ProtocolVersion != database.SignalProtocolVersion {
		t.Fatalf("unexpected created signal version: %+v", created)
	}

	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read signal notification: %v", err)
	}
	var notification struct {
		Type     string `json:"type"`
		Sequence uint64 `json:"sequence"`
	}
	if err := json.Unmarshal(payload, &notification); err != nil {
		t.Fatalf("decode notification: %v", err)
	}
	if notification.Type != "signals_available" || notification.Sequence != 1 {
		t.Fatalf("unexpected notification: %+v", notification)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/v1/signals", nil)
	listReq = listReq.WithContext(context.WithValue(listReq.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  target.ID,
		NetworkID: target.NetworkID,
		UserID:    target.UserID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	listRecorder := httptest.NewRecorder()
	apiServer.ListSignals(listRecorder, listReq)
	if listRecorder.Code != http.StatusOK {
		t.Fatalf("ListSignals: HTTP %d %s", listRecorder.Code, listRecorder.Body.String())
	}
	var listed struct {
		Signals         []database.Signal `json:"signals"`
		ProtocolVersion int64             `json:"protocol_version"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode listed signals: %v", err)
	}
	if len(listed.Signals) != 1 || listed.Signals[0].FromNodeID != source.ID {
		t.Fatalf("durable signal missing after WebSocket wake: %+v", listed.Signals)
	}
	if listed.ProtocolVersion != database.SignalProtocolVersion || listed.Signals[0].ProtocolVersion != database.SignalProtocolVersion {
		t.Fatalf("unexpected listed signal version: %+v", listed)
	}
	if listed.Signals[0].SessionID != "sess-api-1" || listed.Signals[0].ProbeEphemeralPublicKey != probeEphemeralPublicKey {
		t.Fatalf("expected session key material to round trip, got %+v", listed.Signals[0])
	}
}

func TestCreateSignalRejectsUnsupportedProtocolVersion(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-version@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-version-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-version-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}

	apiServer := NewServer(nil, nil, db)
	body := strings.NewReader(`{"to_node_id":"` + target.ID + `","type":"peer_offer","protocol_version":99,"candidates":["203.0.113.10:51820"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  source.ID,
		NetworkID: source.NetworkID,
		UserID:    source.UserID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	recorder := httptest.NewRecorder()
	apiServer.CreateSignal(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("CreateSignal: got HTTP %d, want %d: %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
	}
	var response struct {
		Error                    string `json:"error"`
		ErrorCode                string `json:"error_code"`
		SupportedProtocolVersion int64  `json:"supported_protocol_version"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if response.ErrorCode != "unsupported_signal_protocol_version" || response.SupportedProtocolVersion != database.SignalProtocolVersion {
		t.Fatalf("unexpected error response: %+v", response)
	}
	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals: %v", err)
	}
	if len(signals) != 0 {
		t.Fatalf("unsupported signal version should not be persisted: %+v", signals)
	}
}

func TestCreateSignalCandidateLimitAllowsLinearPredictionWindow(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-candidate-limit@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "candidate-limit-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "candidate-limit-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}
	apiServer := NewServer(nil, nil, db)
	claims := &auth.DeviceClaims{
		DeviceID:  source.ID,
		NetworkID: source.NetworkID,
		UserID:    source.UserID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	candidates := make([]string, maxSignalCandidates)
	for i := range candidates {
		candidates[i] = "203.0.113.10:" + strconv.Itoa(41000+i)
	}

	body, err := json.Marshal(map[string]interface{}{
		"to_node_id": target.ID,
		"type":       "peer_offer",
		"candidates": candidates,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(string(body)))
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, claims))
	recorder := httptest.NewRecorder()
	apiServer.CreateSignal(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("CreateSignal with max candidates: HTTP %d %s", recorder.Code, recorder.Body.String())
	}

	candidates = append(candidates, "203.0.113.10:42000")
	body, err = json.Marshal(map[string]interface{}{
		"to_node_id": target.ID,
		"type":       "peer_offer",
		"candidates": candidates,
	})
	if err != nil {
		t.Fatalf("marshal oversized request: %v", err)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(string(body)))
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, claims))
	recorder = httptest.NewRecorder()
	apiServer.CreateSignal(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("CreateSignal with too many candidates: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "max 32") {
		t.Fatalf("expected max 32 error, got %s", recorder.Body.String())
	}
}

func TestCreateSignalVerifiesProbeEphemeralSignature(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("probe-sig@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "probe-sig-source-key", "source", "macos", hex.EncodeToString(edPub))
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "probe-sig-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}

	apiServer := NewServer(nil, nil, db)
	const sessionID = "sess-probe-sig"
	const probeEphemeralPublicKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	transcript := probeEphemeralTranscript("peer_offer", source.ID, target.ID, sessionID, probeEphemeralPublicKey, 7, 42_000)
	validSignature := hex.EncodeToString(ed25519.Sign(edPriv, transcript))

	for _, tc := range []struct {
		name      string
		signature string
		wantCode  int
	}{
		{name: "valid", signature: validSignature, wantCode: http.StatusOK},
		{name: "invalid", signature: hex.EncodeToString(make([]byte, ed25519.SignatureSize)), wantCode: http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.NewReader(`{"to_node_id":"` + target.ID + `","type":"peer_offer","candidates":["203.0.113.10:51820"],"candidate_generation":7,"candidates_expires_at_ms":42000,"session_id":"` + sessionID + `","probe_ephemeral_public_key":"` + probeEphemeralPublicKey + `","probe_ephemeral_signature":"` + tc.signature + `","handshake":"abcd","client_time_ms":1}`)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
			req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
				DeviceID:  source.ID,
				NetworkID: source.NetworkID,
				UserID:    source.UserID,
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			}))
			recorder := httptest.NewRecorder()
			apiServer.CreateSignal(recorder, req)
			if recorder.Code != tc.wantCode {
				t.Fatalf("CreateSignal: got HTTP %d, want %d: %s", recorder.Code, tc.wantCode, recorder.Body.String())
			}
		})
	}
}

func TestRevokeCurrentDeviceCredentialInvalidatesToken(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("revoke-current@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "revoke-current-key", "device", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	cred, token, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}

	apiServer := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/credential", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:     device.ID,
		NetworkID:    device.NetworkID,
		UserID:       device.UserID,
		CredentialID: cred.ID,
		ExpiresAt:    cred.ExpiresAt,
	}))
	recorder := httptest.NewRecorder()
	apiServer.RevokeCurrentDeviceCredential(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("RevokeCurrentDeviceCredential: HTTP %d %s", recorder.Code, recorder.Body.String())
	}
	if _, _, err := db.ValidateDeviceCredential(token); err == nil {
		t.Fatal("revoked current credential should no longer validate")
	}
}

func TestRelayRevocationFeedRequiresBearerAndReturnsSnapshot(t *testing.T) {
	t.Setenv("RELAY_REVOCATION_FEED_TOKEN", "relay-feed-token")
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("relay-feed@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "relay-feed-key", "device", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	credA, _, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential A: %v", err)
	}
	credB, _, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential B: %v", err)
	}

	apiServer := NewServer(nil, nil, db)
	revokeReq := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/credential", nil)
	revokeReq = revokeReq.WithContext(context.WithValue(revokeReq.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:     device.ID,
		NetworkID:    device.NetworkID,
		UserID:       device.UserID,
		CredentialID: credA.ID,
		ExpiresAt:    credA.ExpiresAt,
	}))
	revokeRecorder := httptest.NewRecorder()
	apiServer.RevokeCurrentDeviceCredential(revokeRecorder, revokeReq)
	if revokeRecorder.Code != http.StatusOK {
		t.Fatalf("RevokeCurrentDeviceCredential: HTTP %d %s", revokeRecorder.Code, revokeRecorder.Body.String())
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+device.ID, nil)
	deleteReq.SetPathValue("id", device.ID)
	deleteReq = deleteReq.WithContext(context.WithValue(deleteReq.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:     device.ID,
		NetworkID:    device.NetworkID,
		UserID:       device.UserID,
		CredentialID: credB.ID,
		ExpiresAt:    credB.ExpiresAt,
	}))
	deleteRecorder := httptest.NewRecorder()
	apiServer.DeleteDevice(deleteRecorder, deleteReq)
	if deleteRecorder.Code != http.StatusOK {
		t.Fatalf("DeleteDevice: HTTP %d %s", deleteRecorder.Code, deleteRecorder.Body.String())
	}

	unauthorizedReq := httptest.NewRequest(http.MethodGet, "/api/v1/relay/revocations", nil)
	unauthorizedRecorder := httptest.NewRecorder()
	apiServer.RelayRevocations(unauthorizedRecorder, unauthorizedReq)
	if unauthorizedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("RelayRevocations without token: HTTP %d", unauthorizedRecorder.Code)
	}

	feedReq := httptest.NewRequest(http.MethodGet, "/api/v1/relay/revocations", nil)
	feedReq.Header.Set("Authorization", "Bearer relay-feed-token")
	feedRecorder := httptest.NewRecorder()
	apiServer.RelayRevocations(feedRecorder, feedReq)
	if feedRecorder.Code != http.StatusOK {
		t.Fatalf("RelayRevocations: HTTP %d %s", feedRecorder.Code, feedRecorder.Body.String())
	}
	var snapshot database.RelayRevocationSnapshot
	if err := json.Unmarshal(feedRecorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("unmarshal snapshot: %v", err)
	}
	if !apiStringSliceContains(snapshot.RevokedCredentialIDs, credA.ID) {
		t.Fatalf("snapshot missing revoked credential %s: %+v", credA.ID, snapshot)
	}
	if !apiStringSliceContains(snapshot.RevokedCredentialIDs, credB.ID) {
		t.Fatalf("snapshot missing deleted device credential %s: %+v", credB.ID, snapshot)
	}
	if !apiStringSliceContains(snapshot.RevokedDeviceIDs, device.ID) {
		t.Fatalf("snapshot missing deleted device %s: %+v", device.ID, snapshot)
	}
	if snapshot.GeneratedAt == "" || snapshot.Version == 0 {
		t.Fatalf("snapshot should include generated_at and version: %+v", snapshot)
	}
}

func apiStringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestParseRelayServersReturnsEmptySliceWhenUnset(t *testing.T) {
	t.Setenv("RELAY_SERVERS", "")

	servers := parseRelayServers()
	if servers == nil {
		t.Fatal("expected an empty slice, got nil")
	}
	if len(servers) != 0 {
		t.Fatalf("expected no relay servers, got %v", servers)
	}

	encoded, err := json.Marshal(map[string][]string{"relay_servers": servers})
	if err != nil {
		t.Fatalf("marshal relay servers: %v", err)
	}
	if string(encoded) != `{"relay_servers":[]}` {
		t.Fatalf("expected empty JSON array, got %s", encoded)
	}
}

func TestParseRelayServersTrimsAndSkipsEmptyItems(t *testing.T) {
	t.Setenv("RELAY_SERVERS", " default@control.example.com:18081, ,backup@example.com:18081 ")

	servers := parseRelayServers()
	want := []string{"default@control.example.com:18081", "backup@example.com:18081"}
	if len(servers) != len(want) {
		t.Fatalf("expected %d relay servers, got %d: %v", len(want), len(servers), servers)
	}
	for i := range want {
		if servers[i] != want[i] {
			t.Fatalf("server %d: expected %q, got %q", i, want[i], servers[i])
		}
	}
}

func TestUpdateDeviceRenamesOwnedDevice(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("owner@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "rename-key", "old-name", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/devices/"+device.ID, strings.NewReader(`{"device_name":"  Studio Mac  "}`))
	req.SetPathValue("id", device.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	recorder := httptest.NewRecorder()

	server.UpdateDevice(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	updated, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if updated.DeviceName != "Studio Mac" {
		t.Fatalf("expected trimmed device name, got %q", updated.DeviceName)
	}
}

func TestRegisterDeviceStoresRequestedIPAndVersion(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("register-version@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	server := NewServer(nil, nil, db)
	body := strings.NewReader(`{"public_key":"register-version-key","device_name":"Studio","platform":"macos","network_id":"default","virtual_ip":"10.20.0.44","app_version":"0.1.68"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	recorder := httptest.NewRecorder()

	server.RegisterDevice(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Success   bool   `json:"success"`
		NodeID    string `json:"node_id"`
		VirtualIP string `json:"virtual_ip"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.Success || response.VirtualIP != "10.20.0.44" || response.NodeID == "" {
		t.Fatalf("unexpected register response: %+v", response)
	}
	device, err := db.GetDeviceByPublicKey("default", "register-version-key")
	if err != nil {
		t.Fatalf("GetDeviceByPublicKey: %v", err)
	}
	if device.AppVersion != "0.1.68" {
		t.Fatalf("expected stored app version, got %q", device.AppVersion)
	}
}

func TestUpdateDeviceChangesVirtualIP(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("update-ip@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "update-ip-key", "old-name", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/devices/"+device.ID, strings.NewReader(`{"device_name":"Studio Mac","virtual_ip":"10.20.0.66"}`))
	req.SetPathValue("id", device.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	recorder := httptest.NewRecorder()

	server.UpdateDevice(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		DeviceName string `json:"device_name"`
		VirtualIP  string `json:"virtual_ip"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.DeviceName != "Studio Mac" || response.VirtualIP != "10.20.0.66" {
		t.Fatalf("unexpected update response: %+v", response)
	}
	updated, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if updated.DeviceName != "Studio Mac" || updated.VirtualIP != "10.20.0.66" {
		t.Fatalf("unexpected updated device: %+v", updated)
	}
}

func TestUpdateDeviceEndpointStoresRelayRTT(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("relay-rtt@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "relay-rtt-key", "relay-device", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(
		http.MethodPatch,
		"/api/v1/devices/"+device.ID+"/endpoint",
		strings.NewReader(`{"endpoint":"198.51.100.10:52100","nat_type":"symmetric","relay_rtt_ms":42}`),
	)
	req.SetPathValue("id", device.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	recorder := httptest.NewRecorder()

	server.UpdateDeviceEndpoint(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	updated, err := db.GetDevice(device.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if updated.RelayRTTMS == nil || *updated.RelayRTTMS != 42 {
		t.Fatalf("expected relay RTT 42, got %+v", updated.RelayRTTMS)
	}

	nodesReq := httptest.NewRequest(http.MethodGet, "/api/v1/nodes?network_id=default", nil)
	nodesReq = nodesReq.WithContext(context.WithValue(nodesReq.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	nodesRecorder := httptest.NewRecorder()
	server.ListNodes(nodesRecorder, nodesReq)
	if nodesRecorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", nodesRecorder.Code, nodesRecorder.Body.String())
	}
	var response struct {
		Nodes []database.Device `json:"nodes"`
	}
	if err := json.Unmarshal(nodesRecorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(response.Nodes) != 1 || response.Nodes[0].RelayRTTMS == nil || *response.Nodes[0].RelayRTTMS != 42 {
		t.Fatalf("expected listed relay RTT 42, got %+v", response.Nodes)
	}
}

func TestUpdateDeviceRejectsDuplicateVirtualIP(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("update-ip-duplicate@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	first, err := db.CreateDeviceWithOptions(user.ID, "default", "update-ip-dup-a", "first", "macos", "", "10.20.0.70", "")
	if err != nil {
		t.Fatalf("CreateDevice first: %v", err)
	}
	second, err := db.CreateDevice(user.ID, "default", "update-ip-dup-b", "second", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice second: %v", err)
	}

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/devices/"+second.ID, strings.NewReader(`{"virtual_ip":"`+first.VirtualIP+`"}`))
	req.SetPathValue("id", second.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	recorder := httptest.NewRecorder()

	server.UpdateDevice(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "already assigned") {
		t.Fatalf("expected duplicate IP error, got %s", recorder.Body.String())
	}
}

func TestUpdateDeviceRejectsAnotherUser(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	owner, _ := db.CreateUser("owner@example.com", "hash")
	other, _ := db.CreateUser("other@example.com", "hash")
	device, _ := db.CreateDevice(owner.ID, "default", "owner-key", "owner-device", "macos", "")

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/devices/"+device.ID, strings.NewReader(`{"device_name":"hijacked"}`))
	req.SetPathValue("id", device.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: other.ID}))
	recorder := httptest.NewRecorder()

	server.UpdateDevice(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestDeleteDeviceAcceptsUserTokenForOwnedDevice(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, _ := db.CreateUser("owner-delete@example.com", "hash")
	device, _ := db.CreateDevice(user.ID, "default", "delete-key", "delete-me", "macos", "")

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+device.ID, nil)
	req.SetPathValue("id", device.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	recorder := httptest.NewRecorder()

	server.DeleteDevice(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := db.GetDevice(device.ID); err == nil {
		t.Fatal("expected deleted device to be unavailable")
	}
}

func TestDeleteDeviceAcceptsNetworkMember(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	owner, _ := db.CreateUser("owner-delete-member@example.com", "hash")
	member, _ := db.CreateUser("member-delete-member@example.com", "hash")
	device, _ := db.CreateDevice(owner.ID, "default", "delete-member-key", "remove-me", "macos", "")

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+device.ID, nil)
	req.SetPathValue("id", device.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: member.ID}))
	recorder := httptest.NewRecorder()

	server.DeleteDevice(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := db.GetDevice(device.ID); err == nil {
		t.Fatal("expected network-member delete to remove the device")
	}
}

func TestDeleteDeviceRejectsUserWithoutNetworkAccess(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	owner, _ := db.CreateUser("owner-delete-private@example.com", "hash")
	outsider, _ := db.CreateUser("outsider-delete-private@example.com", "hash")
	privateNetwork, err := db.CreateNetwork(owner.ID, "owner-private-delete", "10.77.0.0/24")
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	device, _ := db.CreateDevice(owner.ID, privateNetwork.ID, "delete-private-key", "keep-me", "macos", "")

	server := NewServer(nil, nil, db)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/"+device.ID, nil)
	req.SetPathValue("id", device.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: outsider.ID}))
	recorder := httptest.NewRecorder()

	server.DeleteDevice(recorder, req)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if _, err := db.GetDevice(device.ID); err != nil {
		t.Fatal("private-network device should not be deleted by an outsider")
	}
}

func TestCreateSignalAcceptsPeerReflexiveWithPunchWindow(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-owner@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-source-key", "signal-source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-target-key", "signal-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}

	punchAtMS := time.Now().Add(1500 * time.Millisecond).UnixMilli()
	body := strings.NewReader(`{
		"to_node_id":"` + target.ID + `",
		"type":"peer_reflexive",
		"candidates":["203.0.113.10:51820"],
		"candidate_sources":{"203.0.113.10:51820":"peer_reflexive"},
		"punch_at_ms":` + fmtInt64(punchAtMS) + `
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  source.ID,
		NetworkID: source.NetworkID,
		UserID:    user.ID,
	}))
	recorder := httptest.NewRecorder()

	NewServer(nil, nil, db).CreateSignal(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %d", len(signals))
	}
	if signals[0].Type != "peer_reflexive" {
		t.Fatalf("expected peer_reflexive, got %q", signals[0].Type)
	}
	if signals[0].PunchAtMS != punchAtMS {
		t.Fatalf("expected punch_at_ms %d, got %d", punchAtMS, signals[0].PunchAtMS)
	}
}

func TestCreateSignalNormalizesPunchWindowWithClientTime(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-normalize@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-normalize-source-key", "signal-source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-normalize-target-key", "signal-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}

	beforeMS := time.Now().UnixMilli()
	body := strings.NewReader(`{
		"to_node_id":"` + target.ID + `",
		"type":"peer_offer",
		"candidates":["203.0.113.10:51820"],
		"client_time_ms":1000000,
		"punch_at_ms":1001500
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  source.ID,
		NetworkID: source.NetworkID,
		UserID:    user.ID,
	}))
	recorder := httptest.NewRecorder()

	NewServer(nil, nil, db).CreateSignal(recorder, req)
	afterMS := time.Now().UnixMilli()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %d", len(signals))
	}
	if signals[0].PunchAtMS < beforeMS+1500 || signals[0].PunchAtMS > afterMS+1500 {
		t.Fatalf("expected server-normalized punch_at_ms around now+1500ms, got %d before=%d after=%d", signals[0].PunchAtMS, beforeMS, afterMS)
	}
}

func TestCreateSignalNormalizesCandidateExpiryWithClientClockSkew(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-expiry@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-expiry-source-key", "signal-source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-expiry-target-key", "signal-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}

	// The sender is five minutes behind the control-plane clock.  Its 45 second
	// candidate lifetime must still be accepted and stored relative to server time.
	clientTimeMS := int64(1_000_000)
	beforeMS := time.Now().UnixMilli()
	body := strings.NewReader(`{
		"to_node_id":"` + target.ID + `",
		"type":"peer_offer",
		"candidates":["203.0.113.10:51820"],
		"candidate_generation":17,
		"client_time_ms":` + fmtInt64(clientTimeMS) + `,
		"candidates_expires_at_ms":` + fmtInt64(clientTimeMS+45_000) + `
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID: source.ID, NetworkID: source.NetworkID, UserID: user.ID,
	}))
	recorder := httptest.NewRecorder()
	NewServer(nil, nil, db).CreateSignal(recorder, req)
	afterMS := time.Now().UnixMilli()
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %d", len(signals))
	}
	if signals[0].CandidatesExpiresAtMS < beforeMS+45_000 || signals[0].CandidatesExpiresAtMS > afterMS+45_000 {
		t.Fatalf("expected server-normalized expiry around now+45s, got %d before=%d after=%d", signals[0].CandidatesExpiresAtMS, beforeMS, afterMS)
	}
}

func TestCreateSignalRejectsInvalidPeerReflexive(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, _ := db.CreateUser("signal-invalid@example.com", "hash")
	source, _ := db.CreateDevice(user.ID, "default", "signal-invalid-source-key", "source", "macos", "")
	target, _ := db.CreateDevice(user.ID, "default", "signal-invalid-target-key", "target", "linux", "")
	server := NewServer(nil, nil, db)

	for _, tc := range []struct {
		name string
		body string
	}{
		{
			name: "missing candidate",
			body: `{"to_node_id":"` + target.ID + `","type":"peer_reflexive"}`,
		},
		{
			name: "distant punch window",
			body: `{"to_node_id":"` + target.ID + `","type":"peer_reflexive","candidates":["203.0.113.10:51820"],"punch_at_ms":` + fmtInt64(time.Now().Add(11*time.Minute).UnixMilli()) + `}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(tc.body))
			req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
				DeviceID:  source.ID,
				NetworkID: source.NetworkID,
				UserID:    user.ID,
			}))
			recorder := httptest.NewRecorder()

			server.CreateSignal(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestListSignalsLongPollReturnsWhenSignalArrives(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-long-poll@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-long-poll-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-long-poll-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}
	server := NewServer(nil, nil, db)

	errCh := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, err := db.CreateSignalWithPunchAt(
			source.ID,
			target.ID,
			"peer_offer",
			[]string{"203.0.113.10:51820"},
			map[string]string{"203.0.113.10:51820": "stun_observed"},
			"",
			time.Now().Add(1500*time.Millisecond).UnixMilli(),
		)
		errCh <- err
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals?wait_ms=500", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  target.ID,
		NetworkID: target.NetworkID,
		UserID:    user.ID,
	}))
	recorder := httptest.NewRecorder()
	started := time.Now()

	server.ListSignals(recorder, req)
	if err := <-errCh; err != nil {
		t.Fatalf("CreateSignalWithPunchAt: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("long poll should return when the signal arrives, elapsed=%s", elapsed)
	}

	var body struct {
		Signals      []database.Signal `json:"signals"`
		ServerTimeMS int64             `json:"server_time_ms"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ServerTimeMS <= 0 {
		t.Fatalf("expected server_time_ms in response: %s", recorder.Body.String())
	}
	if len(body.Signals) != 1 {
		t.Fatalf("expected one signal, got %d: %s", len(body.Signals), recorder.Body.String())
	}
	if body.Signals[0].FromNodeID != source.ID || body.Signals[0].ToNodeID != target.ID {
		t.Fatalf("unexpected signal endpoints: %+v", body.Signals[0])
	}
}

func TestListSignalsLongPollWakesImmediatelyWhenSignalCreatedViaAPI(t *testing.T) {
	previousFallback := signalLongPollFallbackInterval
	signalLongPollFallbackInterval = 750 * time.Millisecond
	defer func() {
		signalLongPollFallbackInterval = previousFallback
	}()

	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-notify@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-notify-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-notify-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}
	server := NewServer(nil, nil, db)

	errCh := make(chan error, 1)
	go func() {
		time.Sleep(25 * time.Millisecond)
		body := strings.NewReader(`{
			"to_node_id":"` + target.ID + `",
			"type":"peer_offer",
			"candidates":["203.0.113.10:51820"],
			"candidate_sources":{"203.0.113.10:51820":"stun_observed"},
			"punch_at_ms":` + fmtInt64(time.Now().Add(1500*time.Millisecond).UnixMilli()) + `
		}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
		req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
			DeviceID:  source.ID,
			NetworkID: source.NetworkID,
			UserID:    user.ID,
		}))
		recorder := httptest.NewRecorder()

		server.CreateSignal(recorder, req)
		if recorder.Code != http.StatusOK {
			errCh <- errors.New(recorder.Body.String())
			return
		}
		errCh <- nil
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals?wait_ms=1000", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  target.ID,
		NetworkID: target.NetworkID,
		UserID:    user.ID,
	}))
	recorder := httptest.NewRecorder()
	started := time.Now()

	server.ListSignals(recorder, req)
	if err := <-errCh; err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if elapsed := time.Since(started); elapsed >= signalLongPollFallbackInterval {
		t.Fatalf("long poll should wake before fallback polling interval, elapsed=%s", elapsed)
	}

	var body struct {
		Signals []database.Signal `json:"signals"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Signals) != 1 {
		t.Fatalf("expected one signal, got %d: %s", len(body.Signals), recorder.Body.String())
	}
	if body.Signals[0].FromNodeID != source.ID || body.Signals[0].ToNodeID != target.ID {
		t.Fatalf("unexpected signal endpoints: %+v", body.Signals[0])
	}
}

func fmtInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
