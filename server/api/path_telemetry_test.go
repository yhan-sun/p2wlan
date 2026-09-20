package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

func TestRegisterDeviceAdvertisesPathTelemetryCapability(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()

	user, _ := db.CreateUser("telemetry-cap@example.com", "hash")
	server := NewServer(nil, nil, db)

	body := strings.NewReader(`{"public_key":"telemetry-pubkey","device_name":"MyDevice","platform":"linux","network_id":"default","app_version":"0.1.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: user.ID}))
	rec := httptest.NewRecorder()

	server.RegisterDevice(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success      bool     `json:"success"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !resp.Success {
		t.Fatalf("registration not success: %s", rec.Body.String())
	}
	found := false
	for _, cap := range resp.Capabilities {
		if cap == "path_telemetry_v1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected path_telemetry_v1 in capabilities, got %v", resp.Capabilities)
	}
}

func TestSubmitPathTelemetryHTTP(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()

	user, _ := db.CreateUser("user-telemetry@example.com", "hash")
	net, _ := db.CreateNetwork(user.ID, "Net 1", "10.20.0.0/16")
	devA, _ := db.CreateDevice(user.ID, net.ID, "pub-a", "Device A", "linux", "10.20.0.2")
	devB, _ := db.CreateDevice(user.ID, net.ID, "pub-b", "Device B", "linux", "10.20.0.3")

	server := NewServer(nil, nil, db)

	// Build batch payload
	path := "direct"
	batch := database.PathTelemetryBatch{
		ProtocolVersion: 1,
		Observations: []database.PathObservation{
			{
				SchemaVersion:       1,
				RemoteDeviceID:      devB.ID,
				NetworkID:           net.ID,
				ObservationRevision: 1,
				Lifecycle:           "online",
				CurrentPath:         &path,
				TransitionReason:    "direct_committed",
				ObservedAt:          time.Now().Unix(),
			},
		},
	}
	bodyBytes, _ := json.Marshal(batch)

	// 1. Unauthenticated request -> 401
	unauthReq := httptest.NewRequest(http.MethodPost, "/api/v1/telemetry/paths", bytes.NewReader(bodyBytes))
	unauthRec := httptest.NewRecorder()
	server.SubmitPathTelemetry(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", unauthRec.Code)
	}

	// 2. Authenticated as devA (scenario 11 & scenario 12: claims decide reporting device)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/telemetry/paths", bytes.NewReader(bodyBytes))
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  devA.ID,
		NetworkID: net.ID,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}))
	req = req.WithContext(context.WithValue(req.Context(), registrationSessionContextKey{}, int64(1)))
	rec := httptest.NewRecorder()

	server.SubmitPathTelemetry(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Success  bool `json:"success"`
		Accepted int  `json:"accepted"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Success || resp.Accepted != 1 {
		t.Fatalf("expected accepted=1, got %+v", resp)
	}

	// Check DB
	page, err := db.AdminConnections(database.AdminConnectionFilter{ReportingDeviceID: devA.ID}, 10, 0)
	if err != nil || len(page.Items) != 1 || page.Items[0].RemoteDeviceID != devB.ID {
		t.Fatalf("expected observation persisted in DB: %v", err)
	}
}

func TestWebSocketPathTelemetryChannel(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()

	user, _ := db.CreateUser("user-ws-telemetry@example.com", "hash")
	net, _ := db.CreateNetwork(user.ID, "Net 1", "10.20.0.0/16")
	devA, _ := db.CreateDevice(user.ID, net.ID, "pub-a", "Device A", "linux", "10.20.0.2")
	devB, _ := db.CreateDevice(user.ID, net.ID, "pub-b", "Device B", "linux", "10.20.0.3")

	hub := signaling.NewHub()
	defer hub.Close()

	authService := auth.NewService("test-secret-32-bytes-long-123456", db)
	server := NewServer(authService, hub, db)

	// Create device credential token for devA
	_, token, err := db.CreateDeviceCredential(devA.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}

	// Setup test HTTP server with WebSocket handler
	mux := http.NewServeMux()
	deviceAuth := auth.RequireDeviceAuth(db)
	wsHandler := deviceAuth(signaling.ServeWS(hub, server.WebSocketRegistrationSessionGuard()))
	mux.HandleFunc("/api/v1/signals/ws", wsHandler)

	httpServer := httptest.NewServer(mux)
	defer httpServer.Close()

	wsURL := "ws" + strings.TrimPrefix(httpServer.URL, "http") + "/api/v1/signals/ws"

	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	header.Set("Sec-WebSocket-Protocol", signaling.ProtocolName)
	header.Set("X-P2WLAN-Registration-Seq", "1")

	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("Dial WebSocket failed: %v", err)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101, got %d", resp.StatusCode)
	}

	// 1. Read ready message, verify capabilities include path_telemetry_v1
	_, readyBytes, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read ready failed: %v", err)
	}
	var ready struct {
		Type         string   `json:"type"`
		NodeID       string   `json:"node_id"`
		Capabilities []string `json:"capabilities"`
	}
	if err := json.Unmarshal(readyBytes, &ready); err != nil {
		t.Fatalf("unmarshal ready: %v", err)
	}
	if ready.Type != "ready" || ready.NodeID != devA.ID {
		t.Fatalf("unexpected ready message: %+v", ready)
	}
	hasCap := false
	for _, cap := range ready.Capabilities {
		if cap == "path_telemetry_v1" {
			hasCap = true
			break
		}
	}
	if !hasCap {
		t.Fatalf("expected path_telemetry_v1 in ready capabilities: %v", ready.Capabilities)
	}

	// 2. Send path_telemetry message over WebSocket
	path := "relay"
	msg := map[string]interface{}{
		"type":             "path_telemetry",
		"protocol_version": 1,
		"observations": []database.PathObservation{
			{
				SchemaVersion:       1,
				RemoteDeviceID:      devB.ID,
				NetworkID:           net.ID,
				ObservationRevision: 1,
				Lifecycle:           "online",
				CurrentPath:         &path,
				TransitionReason:    "relay_peer_confirmed",
				ObservedAt:          time.Now().Unix(),
			},
		},
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("write telemetry json: %v", err)
	}

	// 3. Read ack message back
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, ackBytes, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read ack message failed: %v", err)
	}
	var ack struct {
		Accepted int `json:"accepted"`
	}
	if err := json.Unmarshal(ackBytes, &ack); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	if ack.Accepted != 1 {
		t.Fatalf("expected accepted=1 in ack, got %d: %s", ack.Accepted, string(ackBytes))
	}

	// 4. Verify DB has Relay connection
	page, err := db.AdminConnections(database.AdminConnectionFilter{ReportingDeviceID: devA.ID}, 10, 0)
	if err != nil || len(page.Items) != 1 || page.Items[0].CurrentPath == nil || *page.Items[0].CurrentPath != "relay" {
		t.Fatalf("expected relay connection in DB: %+v, err: %v", page, err)
	}
}
