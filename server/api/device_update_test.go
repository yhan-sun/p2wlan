package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

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

// newEndpointUpdateTestServer sets up a server, user, and device owned by that
// user, ready to exercise UpdateDeviceEndpoint.
func newEndpointUpdateTestServer(t *testing.T) (*Server, string, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	user, err := db.CreateUser("endpoint-cap@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	device, err := db.CreateDevice(user.ID, "default", "endpoint-cap-key", "endpoint-cap-device", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	return NewServer(nil, nil, db), device.ID, user.ID
}

// patchEndpoint sends an endpoint update with the given nat_type and returns
// the recorded response.
func patchEndpoint(t *testing.T, server *Server, deviceID string, userID string, natType string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"endpoint":"198.51.100.10:52100","nat_type":%q}`, natType)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/devices/"+deviceID+"/endpoint", strings.NewReader(body))
	req.SetPathValue("id", deviceID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: userID}))
	recorder := httptest.NewRecorder()
	server.UpdateDeviceEndpoint(recorder, req)
	return recorder
}

// R1 widens the nat_type cap from 64 to 128: a full-width `p2v2:` fingerprint
// label (worst case ~97 bytes) must now be accepted.
func TestUpdateEndpointAcceptsNatTypeWithin128(t *testing.T) {
	server, deviceID, userID := newEndpointUpdateTestServer(t)
	// A label shaped like the R1 control label, padded to exactly 128 bytes.
	prefix := "p2v2:m=address_or_port_dependent;a=random;d=32;c=90;f=likely_endpoint_independent;h=not_applicable"
	natType := prefix + strings.Repeat("x", 128-len(prefix))
	if len(natType) != 128 {
		t.Fatalf("test bug: nat_type must be 128 bytes, got %d", len(natType))
	}
	recorder := patchEndpoint(t, server, deviceID, userID, natType)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for 128-byte nat_type, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

// A nat_type over the new 128-byte cap must still be rejected with 400.
func TestUpdateEndpointRejectsNatTypeOver128(t *testing.T) {
	server, deviceID, userID := newEndpointUpdateTestServer(t)
	natType := strings.Repeat("y", 129)
	if len(natType) != 129 {
		t.Fatalf("test bug: nat_type must be 129 bytes, got %d", len(natType))
	}
	recorder := patchEndpoint(t, server, deviceID, userID, natType)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 129-byte nat_type, got %d: %s", recorder.Code, recorder.Body.String())
	}
}
