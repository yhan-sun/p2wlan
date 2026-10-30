package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

	if _, err := db.Exec(`UPDATE devices SET registration_seq = 1 WHERE id = ?`, devA.ID); err != nil {
		t.Fatal(err)
	}
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

	if _, err := db.Exec(`UPDATE devices SET registration_seq = 1 WHERE id = ?`, devA.ID); err != nil {
		t.Fatal(err)
	}
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
	msg = map[string]interface{}{"type": "path_telemetry", "payload": msg}
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

func TestRustPathTelemetrySharedFixture(t *testing.T) {
	payload, err := os.ReadFile("testdata/path_telemetry_rust_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	batch, err := decodePathTelemetryBatch(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Observations) != 1 || batch.Observations[0].Lifecycle != "online" || batch.Observations[0].ObservedAt != 1700000000 {
		t.Fatalf("Rust snapshot fields lost: %+v", batch)
	}
	f := newRegistrationSessionFixture(t)
	// The envelope's reporter/network are untrusted. Only claims supplied to
	// ingestion establish identity, even when the Rust payload names another.
	payload = bytes.ReplaceAll(payload, []byte("rust-remote"), []byte(f.peer.ID))
	// Re-encode only observation.network_id to the fixture's actual network.
	var envelope struct {
		Type    string                 `json:"type"`
		Payload map[string]interface{} `json:"payload"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload["observations"].([]interface{})[0].(map[string]interface{})["network_id"] = f.device.NetworkID
	payload, err = json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := f.server.IngestPathTelemetryPayload(f.device.ID, f.device.NetworkID, f.device.RegistrationSeq, payload)
	if err != nil || summary.Accepted != 1 {
		t.Fatalf("Rust frame ingestion: %+v %v", summary, err)
	}
	var lifecycle string
	var observedAt int64
	if err := f.db.QueryRow(`SELECT lifecycle, observed_at FROM peer_path_observations WHERE reporting_device_id=?`, f.device.ID).Scan(&lifecycle, &observedAt); err != nil {
		t.Fatal(err)
	}
	if lifecycle != "online" || observedAt != 1700000000 {
		t.Fatalf("persisted lifecycle/time = %s/%d", lifecycle, observedAt)
	}
}

func TestPathTelemetryMalformedAndOversizedBatches(t *testing.T) {
	for _, payload := range []string{
		`{}`, `{"type":"path_telemetry","payload":null}`, `{"type":"other","payload":{"observations":[]}}`,
		`{"observations":[],"protocol_version":99}`, `{"type":"path_telemetry","payload":{"sent_at":1}}`,
	} {
		if _, err := decodePathTelemetryBatch([]byte(payload)); err == nil {
			t.Errorf("malformed batch accepted: %s", payload)
		}
	}
	f := newRegistrationSessionFixture(t)
	request := f.request(http.MethodPost, "/api/v1/telemetry/paths", strings.Repeat(" ", signaling.MaxClientMessageBytes+1))
	request.Header.Set(auth.RegistrationSequenceHeader, strconv.FormatInt(f.device.RegistrationSeq, 10))
	recorder := httptest.NewRecorder()
	f.deviceSession(f.server.SubmitPathTelemetry)(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized HTTP telemetry = %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestWebSocketInFlightTelemetryCannotCommitAfterReregistration(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	hub := signaling.NewHub()
	t.Cleanup(hub.Close)
	f.server.hub = hub
	entered := make(chan struct{})
	resume := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(resume) }) }
	defer release()
	finished := make(chan error, 1)
	hub.SetTelemetryHandler(func(id, network string, sequence int64, data []byte) (interface{}, error) {
		close(entered)
		<-resume
		summary, err := f.server.IngestPathTelemetryPayload(id, network, sequence, data)
		finished <- err
		return summary, err
	})
	web := httptest.NewServer(f.deviceWebSocketSession(hub))
	defer web.Close()
	headers := http.Header{"Authorization": {"Bearer " + f.credential}, auth.RegistrationSequenceHeader: {strconv.FormatInt(f.device.RegistrationSeq, 10)}}
	dialer := websocket.Dialer{Subprotocols: []string{signaling.ProtocolName}, HandshakeTimeout: time.Second}
	conn, _, err := dialer.Dial("ws"+strings.TrimPrefix(web.URL, "http"), headers)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	path := "direct"
	frame := map[string]interface{}{"type": "path_telemetry", "payload": database.PathTelemetryBatch{Observations: []database.PathObservation{{RemoteDeviceID: f.peer.ID, NetworkID: f.device.NetworkID, ObservationRevision: 1, Lifecycle: "online", CurrentPath: &path}}}}
	if err := conn.WriteJSON(frame); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("callback did not enter")
	}
	request := f.request(http.MethodPost, "/api/v1/devices", `{"public_key":"`+f.device.PublicKey+`","device_name":"new daemon","platform":"linux","network_id":"default","registration_incarnation":9002}`)
	recorder := httptest.NewRecorder()
	auth.RequireAnyAuth(f.service, f.db)(f.server.RegisterDevice)(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("reregistration: %d %s", recorder.Code, recorder.Body.String())
	}
	release()
	select {
	case err := <-finished:
		var conflict *database.RegistrationSessionConflictError
		if !errors.As(err, &conflict) || conflict.CurrentSequence <= f.device.RegistrationSeq {
			t.Fatalf("old callback must conflict: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("callback did not finish")
	}
	var count int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM peer_path_observations WHERE reporting_device_id=?`, f.device.ID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("old session persisted %d observations", count)
	}
}

func TestGoAndRustSharePathTelemetryResourceContract(t *testing.T) {
	payload, err := os.ReadFile("testdata/path_telemetry_limits.json")
	if err != nil {
		t.Fatal(err)
	}
	var limits struct {
		MaxFrameBytes   int `json:"max_frame_bytes"`
		MaxObservations int `json:"max_observations"`
	}
	if err := json.Unmarshal(payload, &limits); err != nil {
		t.Fatal(err)
	}
	if limits.MaxFrameBytes != signaling.MaxClientMessageBytes || limits.MaxObservations != database.MaxPathTelemetryBatchObservations {
		t.Fatalf("Go limits diverged from shared Rust contract: %+v", limits)
	}
}
