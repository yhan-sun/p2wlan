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
	if !strings.Contains(recorder.Body.String(), "max 96") {
		t.Fatalf("expected max 96 error, got %s", recorder.Body.String())
	}
}

// Full HTTP integration for the fresh-mapping queue contract:
//  1. A fresh prediction (peer_offer_fresh) is accepted through the API.
//  2. G2 is queued first, then a stale G1 arrives late: the server keeps both
//     and delivers them in send order (G2 first), never last-write-wins.
//  3. An ordinary peer_offer queued after a fresh signal never overwrites it.
func TestCreateSignalFreshQueueKeyAndSendOrder(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-fresh-order@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-fresh-order-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-fresh-order-target-key", "target", "linux", "")
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
	post := func(t *testing.T, payload map[string]interface{}) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(string(body)))
		req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, claims))
		recorder := httptest.NewRecorder()
		apiServer.CreateSignal(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("CreateSignal: HTTP %d %s", recorder.Code, recorder.Body.String())
		}
	}

	// 1. G2 fresh prediction is queued first (independent queue key).
	post(t, map[string]interface{}{
		"to_node_id": target.ID,
		"type":       "peer_offer_fresh",
		"candidates": []string{"203.0.113.10:45393", "203.0.113.10:45394"},
		"candidate_sources": map[string]string{
			"203.0.113.10:45393": "predicted_fresh:1742987654321:7",
			"203.0.113.10:45394": "predicted_fresh:1742987654321:7",
		},
		"candidate_generation": 2,
		"handshake":            "01020304",
	})
	// 2. G1 (older generation) arrives late on the ordinary queue.
	post(t, map[string]interface{}{
		"to_node_id":           target.ID,
		"type":                 "peer_offer",
		"candidates":           []string{"203.0.113.10:41000"},
		"candidate_sources":    map[string]string{"203.0.113.10:41000": "stun_observed"},
		"candidate_generation": 1,
		"handshake":            "01020305",
	})
	// 3. An ordinary refresh arrives after the fresh signal.
	post(t, map[string]interface{}{
		"to_node_id":           target.ID,
		"type":                 "peer_offer",
		"candidates":           []string{"203.0.113.10:42000"},
		"candidate_sources":    map[string]string{"203.0.113.10:42000": "stun_observed"},
		"candidate_generation": 3,
		"handshake":            "01020306",
	})

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
		Signals []database.Signal `json:"signals"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode listed signals: %v", err)
	}
	if len(listed.Signals) != 3 {
		t.Fatalf("all three signals must be delivered in send order, got %d: %+v", len(listed.Signals), listed.Signals)
	}
	first := listed.Signals[0]
	if first.Type != "peer_offer_fresh" || first.CandidateGeneration != 2 ||
		first.CandidateSources["203.0.113.10:45393"] != "predicted_fresh:1742987654321:7" {
		t.Fatalf("expected the fresh prediction first with its label intact, got %+v", first)
	}
	if listed.Signals[1].Handshake != "01020305" || listed.Signals[1].CandidateGeneration != 1 {
		t.Fatalf("expected the late G1 second (G2 must not be deleted), got %+v", listed.Signals[1])
	}
	if listed.Signals[2].Handshake != "01020306" || listed.Signals[2].CandidateGeneration != 3 {
		t.Fatalf("expected the ordinary refresh third, got %+v", listed.Signals[2])
	}
	for i := 1; i < len(listed.Signals); i++ {
		if listed.Signals[i-1].SignalSeq >= listed.Signals[i].SignalSeq {
			t.Fatalf("signal sequences must be strictly increasing in delivery order")
		}
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

// Mixed-version compatibility matrix:
//   - Old clients send fresh predictions on the independent `peer_offer_fresh`
//     wire type: a NEW server must keep accepting it (never 400).
//   - New clients send fresh predictions on the ordinary `peer_offer` wire
//     type with a `predicted_fresh:*` candidate label: an OLD server (and the
//     new one) accepts that payload unchanged, and the fresh identity is
//     carried by the label, not the wire type.
func TestMixedVersionSignalWireTypes(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("mixed-version@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "mixed-version-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "mixed-version-target-key", "target", "linux", "")
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
	post := func(payload map[string]interface{}) *httptest.ResponseRecorder {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(string(body)))
		req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, claims))
		recorder := httptest.NewRecorder()
		apiServer.CreateSignal(recorder, req)
		return recorder
	}

	// Old client wire type against the new server.
	oldClient := post(map[string]interface{}{
		"to_node_id": target.ID,
		"type":       "peer_offer_fresh",
		"candidates": []string{"203.0.113.10:45393"},
		"candidate_sources": map[string]string{
			"203.0.113.10:45393": "predicted_fresh:1742987654321:7",
		},
		"handshake": "0102",
	})
	if oldClient.Code != http.StatusOK {
		t.Fatalf("old-client peer_offer_fresh must be accepted by the new server, got HTTP %d %s", oldClient.Code, oldClient.Body.String())
	}

	// New client wire type (plain peer_offer carrying the fresh label).
	newClient := post(map[string]interface{}{
		"to_node_id": target.ID,
		"type":       "peer_offer",
		"candidates": []string{"203.0.113.10:45394"},
		"candidate_sources": map[string]string{
			"203.0.113.10:45394": "predicted_fresh:1742987654322:9",
		},
		"handshake": "0103",
	})
	if newClient.Code != http.StatusOK {
		t.Fatalf("new-client fresh offer on the peer_offer wire type must be accepted, got HTTP %d %s", newClient.Code, newClient.Body.String())
	}

	// The receiver sees both, in send order, with their labels intact.
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
		Signals []database.Signal `json:"signals"`
	}
	if err := json.Unmarshal(listRecorder.Body.Bytes(), &listed); err != nil {
		t.Fatalf("decode listed signals: %v", err)
	}
	if len(listed.Signals) != 2 {
		t.Fatalf("expected both mixed-version signals, got %d", len(listed.Signals))
	}
	if listed.Signals[0].Type != "peer_offer_fresh" {
		t.Fatalf("expected the old-client fresh signal first, got %+v", listed.Signals[0])
	}
	if listed.Signals[1].Type != "peer_offer" || listed.Signals[1].CandidateSources["203.0.113.10:45394"] != "predicted_fresh:1742987654322:9" {
		t.Fatalf("expected the new-client fresh label intact on the peer_offer wire type, got %+v", listed.Signals[1])
	}
}

func TestCreateSignalRejectsBadHandshakeHex(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("bad-hex@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "bad-hex-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "bad-hex-target-key", "target", "linux", "")
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
	post := func(handshake string) int {
		body, err := json.Marshal(map[string]interface{}{
			"to_node_id": target.ID,
			"type":       "peer_offer",
			"candidates": []string{"203.0.113.10:51820"},
			"handshake":  handshake,
		})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(string(body)))
		req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, claims))
		recorder := httptest.NewRecorder()
		apiServer.CreateSignal(recorder, req)
		return recorder.Code
	}
	for _, bad := range []string{"abc", "zz", "01zz", "0x0102"} {
		if code := post(bad); code != http.StatusBadRequest {
			t.Fatalf("handshake %q must be rejected with 400, got %d", bad, code)
		}
	}
	if code := post("0102"); code != http.StatusOK {
		t.Fatalf("valid hex handshake must be accepted, got %d", code)
	}
}

func TestCreateSignalFloodReturns429(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("flood@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "flood-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "flood-target-key", "target", "linux", "")
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
	post := func() *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]interface{}{
			"to_node_id": target.ID,
			"type":       "peer_offer",
			"candidates": []string{"203.0.113.10:51820"},
			"handshake":  "0102",
		})
		if err != nil {
			t.Fatalf("marshal request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(string(body)))
		req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, claims))
		recorder := httptest.NewRecorder()
		apiServer.CreateSignal(recorder, req)
		return recorder
	}
	for i := 0; i < database.MaxSignalsPerPair; i++ {
		if recorder := post(); recorder.Code != http.StatusOK {
			t.Fatalf("CreateSignal %d: HTTP %d %s", i, recorder.Code, recorder.Body.String())
		}
	}
	recorder := post()
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 429 for the flood, got %d %s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "signal_queue_limit") {
		t.Fatalf("expected a machine-readable queue-limit error code, got %s", recorder.Body.String())
	}
}
