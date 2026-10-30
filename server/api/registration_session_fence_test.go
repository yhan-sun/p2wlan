package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

type registrationSessionFixture struct {
	db         *database.DB
	server     *Server
	service    *auth.Service
	device     *database.Device
	peer       *database.Device
	credential string
}

type observedRegistrationSessionLocker struct {
	serial        sync.Mutex
	mu            sync.Mutex
	calls         int
	firstAcquired chan struct{}
	secondAttempt chan struct{}
}

func (l *observedRegistrationSessionLocker) Lock(_ string) func() {
	l.mu.Lock()
	l.calls++
	call := l.calls
	if call == 1 {
		close(l.firstAcquired)
	}
	if call == 2 {
		close(l.secondAttempt)
	}
	l.mu.Unlock()
	l.serial.Lock()
	return l.serial.Unlock
}

func (l *observedRegistrationSessionLocker) LockContext(_ context.Context, deviceID string) (func(), error) {
	return l.Lock(deviceID), nil
}

func newRegistrationSessionFixture(t *testing.T) *registrationSessionFixture {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateUser("registration-fence@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "registration-fence-device", "daemon", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	peer, err := db.CreateDevice(user.ID, "default", "registration-fence-peer", "peer", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice peer: %v", err)
	}
	_, credential, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}
	incarnation := int64(9001)
	device, err = db.RegisterDeviceWithOptions(
		user.ID, device.NetworkID, device.PublicKey, "daemon", "macos", "", "", "",
		database.DeviceRegistrationAttempt{Incarnation: &incarnation, EnforceIncarnation: true},
	)
	if err != nil {
		t.Fatalf("RegisterDeviceWithOptions: %v", err)
	}
	if device.RegistrationIncarnation != incarnation || device.RegistrationSeq < 2 {
		t.Fatalf("expected incarnation-aware device, got %+v", device)
	}
	return &registrationSessionFixture{
		db:         db,
		server:     NewServer(auth.NewService("registration-fence", db), nil, db),
		service:    auth.NewService("registration-fence", db),
		device:     device,
		peer:       peer,
		credential: credential,
	}
}

func (f *registrationSessionFixture) anySession(handler http.HandlerFunc) http.HandlerFunc {
	return auth.RequireAnyAuth(f.service, f.db)(f.server.RequireCurrentDeviceRegistrationSession(handler))
}

func (f *registrationSessionFixture) deviceSession(handler http.HandlerFunc) http.HandlerFunc {
	return auth.RequireDeviceAuth(f.db)(f.server.RequireCurrentDeviceRegistrationSession(handler))
}

func (f *registrationSessionFixture) deviceWebSocketSession(hub *signaling.Hub) http.HandlerFunc {
	return auth.RequireDeviceAuth(f.db)(signaling.ServeWS(hub, f.server.WebSocketRegistrationSessionGuard()))
}

func (f *registrationSessionFixture) request(method, path, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.credential)
	return req
}

func assertRegistrationLifecycleConflict(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	if recorder.Code != http.StatusConflict {
		t.Fatalf("expected HTTP 409, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode conflict response: %v (%s)", err, recorder.Body.String())
	}
	if response.ErrorCode != auth.RegistrationLifecycleConflictCode {
		t.Fatalf("error_code = %q, want %q", response.ErrorCode, auth.RegistrationLifecycleConflictCode)
	}
}

func TestDeviceRegistrationSessionFenceStopsRESTControlActions(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	// These values make any accidental action observable even if the test runs
	// within a single wall-clock second.
	if _, err := f.db.Exec(`UPDATE devices SET endpoint = ?, nat_type = ?, relay_rtt_ms = ?, last_seen = ?, online = 1 WHERE id = ?`,
		"198.51.100.10:51820", "p2v2:m=endpoint_independent;g=4;l="+strconv.FormatInt(f.device.RegistrationSeq, 10), 17, 123, f.device.ID); err != nil {
		t.Fatalf("prepare device state: %v", err)
	}
	if _, err := f.db.CreateSignal(f.peer.ID, f.device.ID, "peer_offer", []string{"203.0.113.10:51820"}, nil, ""); err != nil {
		t.Fatalf("queue signal: %v", err)
	}

	type endpointCase struct {
		name    string
		handler http.HandlerFunc
		method  string
		path    string
		body    string
		pathID  string
	}
	cases := []endpointCase{
		{
			name:    "list nodes",
			handler: f.anySession(f.server.ListNodes),
			method:  http.MethodGet,
			path:    "/api/v1/nodes",
		},
		{
			name:    "endpoint heartbeat",
			handler: f.anySession(f.server.UpdateDeviceEndpoint),
			method:  http.MethodPatch,
			path:    "/api/v1/devices/" + f.device.ID + "/endpoint",
			pathID:  f.device.ID,
			body:    `{"endpoint":"198.51.100.99:51820","nat_type":"p2v2:m=endpoint_independent;g=5;l=2"}`,
		},
		{
			name:    "offline presence",
			handler: f.anySession(f.server.ReleaseDevicePresence),
			method:  http.MethodPost,
			path:    "/api/v1/devices/" + f.device.ID + "/offline",
			pathID:  f.device.ID,
		},
		{
			name:    "create signal",
			handler: f.anySession(f.server.CreateSignal),
			method:  http.MethodPost,
			path:    "/api/v1/signals",
			body:    `{"to_node_id":"` + f.peer.ID + `","type":"peer_reflexive","candidates":["203.0.113.20:51820"]}`,
		},
		{
			name:    "list signals",
			handler: f.anySession(f.server.ListSignals),
			method:  http.MethodGet,
			path:    "/api/v1/signals",
		},
		{
			name:    "ack signals",
			handler: f.anySession(f.server.AckSignals),
			method:  http.MethodPost,
			path:    "/api/v1/signals/ack",
			body:    `{"signals":[]}`,
		},
		{
			name:    "relay ticket",
			handler: f.deviceSession(f.server.CreateRelayTicket),
			method:  http.MethodPost,
			path:    "/api/v1/relay/tickets",
			body:    `{"audience":"not-reached"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := f.request(tc.method, tc.path, tc.body)
			if tc.pathID != "" {
				req.SetPathValue("id", tc.pathID)
			}
			recorder := httptest.NewRecorder()
			tc.handler(recorder, req)
			assertRegistrationLifecycleConflict(t, recorder)
		})
	}

	stored, err := f.db.GetDevice(f.device.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if stored.Endpoint != "198.51.100.10:51820" || stored.NATType != "p2v2:m=endpoint_independent;g=4;l="+strconv.FormatInt(f.device.RegistrationSeq, 10) || stored.LastSeen != 123 || !stored.Online {
		t.Fatalf("stale session changed endpoint or lease: %+v", stored)
	}
	if stored.RelayRTTMS == nil || *stored.RelayRTTMS != 17 {
		t.Fatalf("stale session changed relay RTT: %+v", stored)
	}
	var queued int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM signals WHERE to_node_id = ?`, f.device.ID).Scan(&queued); err != nil {
		t.Fatalf("count queued signals: %v", err)
	}
	if queued != 1 {
		t.Fatalf("stale session created, consumed, or acknowledged signals: count=%d", queued)
	}

	// The exact current header retains the device-token-only path.
	validReq := f.request(http.MethodGet, "/api/v1/nodes", "")
	validReq.Header.Set(auth.RegistrationSequenceHeader, strconv.FormatInt(f.device.RegistrationSeq, 10))
	validRecorder := httptest.NewRecorder()
	f.anySession(f.server.ListNodes)(validRecorder, validReq)
	if validRecorder.Code != http.StatusOK {
		t.Fatalf("current session rejected: HTTP %d %s", validRecorder.Code, validRecorder.Body.String())
	}
}

func TestDeviceRegistrationSessionFenceRejectsStaleWebSocketBeforeUpgrade(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	hub := signaling.NewHub()
	t.Cleanup(hub.Close)
	f.server.hub = hub
	server := httptest.NewServer(f.deviceWebSocketSession(hub))
	t.Cleanup(server.Close)

	dialer := websocket.Dialer{
		HandshakeTimeout: time.Second,
		Subprotocols:     []string{signaling.ProtocolName},
	}
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	staleHeaders := http.Header{"Authorization": []string{"Bearer " + f.credential}}
	connection, response, err := dialer.Dial(endpoint, staleHeaders)
	if connection != nil {
		_ = connection.Close()
		t.Fatal("stale registration session unexpectedly upgraded WebSocket")
	}
	if err == nil || response == nil {
		t.Fatalf("expected failed WebSocket upgrade, err=%v response=%v", err, response)
	}
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("stale WebSocket status = %d, want 409", response.StatusCode)
	}

	currentHeaders := http.Header{
		"Authorization":                 []string{"Bearer " + f.credential},
		auth.RegistrationSequenceHeader: []string{strconv.FormatInt(f.device.RegistrationSeq, 10)},
	}
	connection, response, err = dialer.Dial(endpoint, currentHeaders)
	if err != nil {
		if response != nil {
			t.Fatalf("current WebSocket upgrade: %v (HTTP %d)", err, response.StatusCode)
		}
		t.Fatalf("current WebSocket upgrade: %v", err)
	}
	defer connection.Close()
	if _, _, err := connection.ReadMessage(); err != nil {
		t.Fatalf("read current-session ready message: %v", err)
	}

	// A newer registration must evict a socket that was valid for the prior
	// sequence.  Otherwise an already-upgraded old daemon could keep receiving
	// wakeups even though its next REST control request would be fenced.
	register := auth.RequireAnyAuth(f.service, f.db)(f.server.RegisterDevice)
	registrationReq := f.request(
		http.MethodPost,
		"/api/v1/devices",
		`{"public_key":"`+f.device.PublicKey+`","device_name":"new daemon","platform":"macos","network_id":"default","registration_incarnation":9002}`,
	)
	registrationRecorder := httptest.NewRecorder()
	register(registrationRecorder, registrationReq)
	if registrationRecorder.Code != http.StatusOK {
		t.Fatalf("new registration: HTTP %d %s", registrationRecorder.Code, registrationRecorder.Body.String())
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("old WebSocket remained usable after newer registration")
	}
}

func TestWebSocketRegistrationGuardSerializesUpgradeAndNewRegistration(t *testing.T) {
	f := newRegistrationSessionFixture(t)
	hub := signaling.NewHub()
	t.Cleanup(hub.Close)
	f.server.hub = hub
	locker := &observedRegistrationSessionLocker{
		firstAcquired: make(chan struct{}),
		secondAttempt: make(chan struct{}),
	}
	f.server.registrationSessionLocks = locker

	allowUpgrade := make(chan struct{})
	guardEntered := make(chan struct{})
	releaseRegistered := make(chan bool, 1)
	baseGuard := f.server.WebSocketRegistrationSessionGuard()
	guard := func(w http.ResponseWriter, r *http.Request) (func(), bool) {
		release, ok := baseGuard(w, r)
		if !ok {
			return nil, false
		}
		close(guardEntered)
		<-allowUpgrade
		return func() {
			// signaling.ServeWS invokes this only after Hub.register.  A live
			// enqueue proves the registration happened before the session lock
			// became available to the concurrent newer registration below.
			releaseRegistered <- hub.Notify(f.device.ID)
			release()
		}, true
	}
	server := httptest.NewServer(auth.RequireDeviceAuth(f.db)(signaling.ServeWS(hub, guard)))
	t.Cleanup(server.Close)

	dialResult := make(chan struct {
		connection *websocket.Conn
		response   *http.Response
		err        error
	}, 1)
	go func() {
		dialer := websocket.Dialer{HandshakeTimeout: 2 * time.Second, Subprotocols: []string{signaling.ProtocolName}}
		connection, response, err := dialer.Dial(
			"ws"+strings.TrimPrefix(server.URL, "http"),
			http.Header{
				"Authorization":                 []string{"Bearer " + f.credential},
				auth.RegistrationSequenceHeader: []string{strconv.FormatInt(f.device.RegistrationSeq, 10)},
			},
		)
		dialResult <- struct {
			connection *websocket.Conn
			response   *http.Response
			err        error
		}{connection, response, err}
	}()

	select {
	case <-guardEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket guard did not acquire the registration lock")
	}
	select {
	case <-locker.firstAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("first registration-session lock acquisition was not observed")
	}

	registrationDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		register := auth.RequireAnyAuth(f.service, f.db)(f.server.RegisterDevice)
		req := f.request(
			http.MethodPost,
			"/api/v1/devices",
			`{"public_key":"`+f.device.PublicKey+`","device_name":"new daemon","platform":"macos","network_id":"default","registration_incarnation":9002}`,
		)
		recorder := httptest.NewRecorder()
		register(recorder, req)
		registrationDone <- recorder
	}()
	select {
	case <-locker.secondAttempt:
		// The second call has reached the exact same lock, but cannot acquire
		// it until signaling registers the first socket and releases the guard.
	case <-time.After(2 * time.Second):
		t.Fatal("new registration did not contend for the WebSocket session lock")
	}
	select {
	case recorder := <-registrationDone:
		t.Fatalf("new registration completed before guarded Hub.register: HTTP %d %s", recorder.Code, recorder.Body.String())
	default:
	}

	close(allowUpgrade)
	select {
	case registered := <-releaseRegistered:
		if !registered {
			t.Fatal("session lock was released before WebSocket entered the Hub")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WebSocket did not reach Hub.register")
	}
	select {
	case recorder := <-registrationDone:
		if recorder.Code != http.StatusOK {
			t.Fatalf("new registration after WebSocket registration: HTTP %d %s", recorder.Code, recorder.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("new registration remained blocked after Hub.register")
	}
	select {
	case result := <-dialResult:
		if result.connection != nil {
			_ = result.connection.Close()
		}
		if result.err != nil && result.response == nil {
			t.Fatalf("guarded WebSocket failed before registration: %v", result.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("guarded WebSocket dial did not finish")
	}
}

func TestLegacyDeviceCredentialControlRequestRemainsHeaderFree(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := db.CreateUser("registration-fence-legacy@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "registration-fence-legacy", "legacy", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	_, credential, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatalf("CreateDeviceCredential: %v", err)
	}
	server := NewServer(nil, nil, db)
	handler := auth.RequireDeviceAuth(db)(server.RequireCurrentDeviceRegistrationSession(server.ListNodes))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+credential)
	recorder := httptest.NewRecorder()
	handler(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("legacy header-free request: HTTP %d %s", recorder.Code, recorder.Body.String())
	}

	var incarnation sql.NullInt64
	if err := db.QueryRow(`SELECT registration_incarnation FROM devices WHERE id = ?`, device.ID).Scan(&incarnation); err != nil || !incarnation.Valid || incarnation.Int64 != 0 {
		t.Fatalf("legacy fixture was not legacy: incarnation=%+v err=%v", incarnation, err)
	}
}
