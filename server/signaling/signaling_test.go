package signaling

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

type websocketFixture struct {
	db       *database.DB
	hub      *Hub
	server   *httptest.Server
	token    string
	deviceID string
}

func newWebSocketFixture(t *testing.T) *websocketFixture {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	user, err := db.CreateUser("ws@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "ws-public-key", "ws-device", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	_, token, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}
	hub := NewHubWithLimit(8)
	handler := auth.RequireDeviceAuth(db)(ServeWS(hub))
	server := httptest.NewServer(handler)
	fixture := &websocketFixture{
		db:       db,
		hub:      hub,
		server:   server,
		token:    token,
		deviceID: device.ID,
	}
	t.Cleanup(func() {
		hub.Close()
		server.Close()
		db.Close()
	})
	return fixture
}

func (f *websocketFixture) dial(t *testing.T, origin string) *websocket.Conn {
	t.Helper()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+f.token)
	if origin != "" {
		header.Set("Origin", origin)
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 2 * time.Second,
		Subprotocols:     []string{ProtocolName},
	}
	url := "ws" + strings.TrimPrefix(f.server.URL, "http")
	conn, response, err := dialer.Dial(url, header)
	if err != nil {
		if response != nil {
			t.Fatalf("websocket dial: %v (HTTP %d)", err, response.StatusCode)
		}
		t.Fatalf("websocket dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func readServerMessage(t *testing.T, conn *websocket.Conn) serverMessage {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	var message serverMessage
	if err := json.Unmarshal(payload, &message); err != nil {
		t.Fatalf("decode server message: %v", err)
	}
	return message
}

func TestWebSocketBindsIdentityAndDeliversSequencedWakeups(t *testing.T) {
	fixture := newWebSocketFixture(t)
	conn := fixture.dial(t, "")

	ready := readServerMessage(t, conn)
	if ready.Type != "ready" || ready.ProtocolVersion != ProtocolVersion {
		t.Fatalf("unexpected ready message: %+v", ready)
	}
	if ready.NodeID != fixture.deviceID || ready.NetworkID != "default" {
		t.Fatalf("identity was not bound from credential: %+v", ready)
	}
	if conn.Subprotocol() != ProtocolName {
		t.Fatalf("expected subprotocol %q, got %q", ProtocolName, conn.Subprotocol())
	}

	if !fixture.hub.Notify(fixture.deviceID) || !fixture.hub.Notify(fixture.deviceID) {
		t.Fatal("expected connected device notifications to enqueue")
	}
	first := readServerMessage(t, conn)
	second := readServerMessage(t, conn)
	if first.Type != "signals_available" || first.Sequence != 1 {
		t.Fatalf("unexpected first notification: %+v", first)
	}
	if second.Sequence != 2 || second.ServerTimeMS < first.ServerTimeMS {
		t.Fatalf("unexpected second notification: %+v", second)
	}
}

func TestWebSocketRejectsMissingDeviceCredentialAndSubprotocol(t *testing.T) {
	fixture := newWebSocketFixture(t)
	url := "ws" + strings.TrimPrefix(fixture.server.URL, "http")
	dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second}

	_, response, err := dialer.Dial(url+"?token="+fixture.token, nil)
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query credential must be rejected, err=%v response=%v", err, response)
	}

	header := http.Header{"Authorization": []string{"Bearer " + fixture.token}}
	_, response, err = dialer.Dial(url, header)
	if err == nil || response == nil || response.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("missing subprotocol must be rejected, err=%v response=%v", err, response)
	}
}

func TestWebSocketRejectsUntrustedOrigin(t *testing.T) {
	fixture := newWebSocketFixture(t)
	url := "ws" + strings.TrimPrefix(fixture.server.URL, "http")
	header := http.Header{
		"Authorization": []string{"Bearer " + fixture.token},
		"Origin":        []string{"https://attacker.invalid"},
	}
	dialer := websocket.Dialer{
		HandshakeTimeout: 2 * time.Second,
		Subprotocols:     []string{ProtocolName},
	}
	_, response, err := dialer.Dial(url, header)
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("untrusted origin must be rejected, err=%v response=%v", err, response)
	}
}

func TestWebSocketClientCannotSelfDeclareIdentity(t *testing.T) {
	fixture := newWebSocketFixture(t)
	conn := fixture.dial(t, "")
	_ = readServerMessage(t, conn)

	if err := conn.WriteJSON(map[string]any{
		"type": "register",
		"data": map[string]string{"node_id": "forged", "network_id": "other"},
	}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err := conn.ReadMessage()
	if err == nil {
		t.Fatal("application messages must close the notification-only channel")
	}

	fixture.hub.mu.RLock()
	_, forged := fixture.hub.clients["forged"]
	fixture.hub.mu.RUnlock()
	if forged {
		t.Fatal("client self-declared identity was registered")
	}
}

func TestHubConnectionLimitAndPointerSafeReplacement(t *testing.T) {
	hub := NewHubWithLimit(2)
	first := &Client{nodeID: "node-a", done: make(chan struct{}), send: make(chan []byte, 1), closeReq: make(chan closeRequest, 1)}
	second := &Client{nodeID: "node-a", done: make(chan struct{}), send: make(chan []byte, 1), closeReq: make(chan closeRequest, 1)}
	other := &Client{nodeID: "node-b", done: make(chan struct{}), send: make(chan []byte, 1), closeReq: make(chan closeRequest, 1)}

	if previous, err := hub.register(first); err != nil || previous != nil {
		t.Fatalf("register first: previous=%v err=%v", previous, err)
	}
	if previous, err := hub.register(second); err != nil || previous != first {
		t.Fatalf("replace first: previous=%v err=%v", previous, err)
	}
	hub.unregister(first)
	hub.mu.RLock()
	current := hub.clients["node-a"]
	hub.mu.RUnlock()
	if current != second {
		t.Fatal("old connection unregistered the replacement")
	}
	if _, err := hub.register(other); !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("expected connection limit, got %v", err)
	}
	if hub.activeClients != 2 {
		t.Fatalf("expected both still-active generations to consume capacity, got %d", hub.activeClients)
	}
}

func TestHubBackpressureIsBounded(t *testing.T) {
	hub := NewHubWithLimit(1)
	client := &Client{
		nodeID:   "node-a",
		done:     make(chan struct{}),
		send:     make(chan []byte, 1),
		closeReq: make(chan closeRequest, 1),
	}
	if _, err := hub.register(client); err != nil {
		t.Fatalf("register: %v", err)
	}
	if !hub.Notify("node-a") {
		t.Fatal("first notification should fit")
	}
	if hub.Notify("node-a") {
		t.Fatal("second notification should hit bounded backpressure")
	}
	select {
	case request := <-client.closeReq:
		if request.code != websocket.ClosePolicyViolation {
			t.Fatalf("unexpected close code %d", request.code)
		}
	default:
		t.Fatal("backpressured client was not scheduled for close")
	}
}

func TestHubCloseWaitsForConnectionTasksAndRejectsRegistration(t *testing.T) {
	fixture := newWebSocketFixture(t)
	conn := fixture.dial(t, "")
	_ = readServerMessage(t, conn)

	closed := make(chan struct{})
	go func() {
		fixture.hub.Close()
		close(closed)
	}()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("expected server shutdown to close the websocket")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("hub close did not reclaim connection tasks")
	}

	fixture.hub.mu.RLock()
	clientCount := len(fixture.hub.clients)
	fixture.hub.mu.RUnlock()
	if clientCount != 0 {
		t.Fatalf("expected no registered clients after close, got %d", clientCount)
	}
	client := &Client{nodeID: "late-client"}
	if _, err := fixture.hub.register(client); !errors.Is(err, ErrHubClosed) {
		t.Fatalf("expected ErrHubClosed after shutdown, got %v", err)
	}
}

func TestNewHubFromEnvRejectsInvalidConnectionLimit(t *testing.T) {
	t.Setenv("SIGNAL_WS_MAX_CONNECTIONS", "not-a-number")
	if _, err := NewHubFromEnv(); err == nil {
		t.Fatal("expected invalid connection limit to fail")
	}
	t.Setenv("SIGNAL_WS_MAX_CONNECTIONS", "0")
	if _, err := NewHubFromEnv(); err == nil {
		t.Fatal("expected zero connection limit to fail")
	}
	t.Setenv("SIGNAL_WS_MAX_CONNECTIONS", "17")
	hub, err := NewHubFromEnv()
	if err != nil {
		t.Fatalf("NewHubFromEnv: %v", err)
	}
	if hub.maxConnections != 17 {
		t.Fatalf("expected configured limit 17, got %d", hub.maxConnections)
	}
}
