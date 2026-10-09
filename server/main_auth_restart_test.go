package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/api"
	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

type restartControl struct {
	db     *database.DB
	server *httptest.Server
}

func startRestartControl(t *testing.T, dbPath, address string) restartControl {
	t.Helper()
	db, err := database.New(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	service := auth.NewService("persistent-restart-test-secret", db)
	hub := signaling.NewHub()
	t.Cleanup(hub.Close)
	apiServer := api.NewServer(service, hub, db)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/register", apiServer.Register)
	mux.HandleFunc("GET /api/v1/profile", service.RequireAuth(apiServer.Profile))
	registerDeviceControlRoutes(mux, service, db, apiServer, hub)
	server := httptest.NewUnstartedServer(mux)
	if address != "" {
		_ = server.Listener.Close()
		server.Listener, err = net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
	}
	server.Start()
	t.Cleanup(server.Close)
	return restartControl{db: db, server: server}
}

func TestProductionAccountAndDeviceLoginSurviveControlRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "control.db")
	control := startRestartControl(t, dbPath, "")
	baseURL := control.server.URL
	address := control.server.Listener.Addr().String()
	transport := &http.Transport{DisableKeepAlives: true}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	request := func(method, path, token, sequence string, payload any, expected int) map[string]any {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(method, baseURL+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		if sequence != "" {
			req.Header.Set(auth.RegistrationSequenceHeader, sequence)
		}
		response, err := client.Do(req)
		if err != nil {
			t.Fatalf("HTTP %s %s: %v", method, path, err)
		}
		defer response.Body.Close()
		if response.StatusCode != expected {
			t.Fatalf("HTTP %s %s: got %d, want %d", method, path, response.StatusCode, expected)
		}
		var result map[string]any
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}

	session := request(http.MethodPost, "/api/v1/register", "", "", map[string]string{
		"email": "restart-account@example.test", "password": "test-password123",
	}, http.StatusOK)
	userToken, ok := session["token"].(string)
	if !ok || userToken == "" {
		t.Fatal("registration did not return an account token")
	}
	registration := map[string]any{
		"public_key": "restart-device-key", "device_name": "restart-test", "platform": "windows",
		"network_id": "default", "registration_incarnation": 4101,
	}
	registered := request(http.MethodPost, "/api/v1/devices", userToken, "", registration, http.StatusOK)
	deviceID, ok := registered["node_id"].(string)
	if !ok || deviceID == "" {
		t.Fatal("registration did not return a device identity")
	}
	sequence := strconv.FormatInt(int64(registered["registration_seq"].(float64)), 10)
	_, deviceToken, err := control.db.CreateDeviceCredential(deviceID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	revoked, revokedToken, err := control.db.CreateDeviceCredential(deviceID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := control.db.RevokeDeviceCredential(revoked.ID); err != nil {
		t.Fatal(err)
	}
	_, expiredToken, err := control.db.CreateDeviceCredential(deviceID, -1)
	if err != nil {
		t.Fatal(err)
	}
	request(http.MethodGet, "/api/v1/profile", userToken, "", nil, http.StatusOK)
	request(http.MethodGet, "/api/v1/nodes", deviceToken, sequence, nil, http.StatusOK)

	// A storage outage cannot prove that the device lost its authorization.
	// The production middleware must keep this on the daemon's retry path.
	if err := control.db.Close(); err != nil {
		t.Fatal(err)
	}
	unavailable := request(http.MethodGet, "/api/v1/nodes", deviceToken, sequence, nil, http.StatusServiceUnavailable)
	if unavailable["error_code"] != "authentication_unavailable" {
		t.Fatal("temporary outage was not classified as retryable")
	}
	control.server.Close()

	// Recreate the HTTP/API/auth owners and reopen SQLite at the same address.
	// Neither password login nor device credential enrollment runs again.
	control = startRestartControl(t, dbPath, address)
	if control.server.URL != baseURL {
		t.Fatal("restart changed the control address")
	}
	request(http.MethodGet, "/api/v1/profile", userToken, "", nil, http.StatusOK)
	request(http.MethodGet, "/api/v1/nodes", deviceToken, sequence, nil, http.StatusOK)
	reconnected := request(http.MethodPost, "/api/v1/devices", deviceToken, "", registration, http.StatusOK)
	if reconnected["node_id"] != registered["node_id"] || reconnected["virtual_ip"] != registered["virtual_ip"] || reconnected["registration_seq"] != registered["registration_seq"] {
		t.Fatal("same daemon did not recover its durable registration")
	}
	for _, rejected := range []string{revokedToken, expiredToken, "dc-unknown"} {
		request(http.MethodGet, "/api/v1/nodes", rejected, sequence, nil, http.StatusUnauthorized)
	}

	// A genuinely newer daemon still fences the old registration, while the
	// original device credential remains usable to establish the new session.
	registration["registration_incarnation"] = 4102
	newSession := request(http.MethodPost, "/api/v1/devices", deviceToken, "", registration, http.StatusOK)
	conflict := request(http.MethodGet, "/api/v1/nodes", deviceToken, sequence, nil, http.StatusConflict)
	if conflict["error_code"] != auth.RegistrationLifecycleConflictCode {
		t.Fatal("obsolete daemon was not fenced")
	}
	newSequence := strconv.FormatInt(int64(newSession["registration_seq"].(float64)), 10)
	request(http.MethodGet, "/api/v1/nodes", deviceToken, newSequence, nil, http.StatusOK)
}
