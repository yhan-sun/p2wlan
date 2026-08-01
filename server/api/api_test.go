package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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
