package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestWakeClaimTerminalBlockIsJobConflict(t *testing.T) {
	recorder := httptest.NewRecorder()
	wakeError(recorder, &database.WakeError{Code: "target_blocked", Terminal: true})
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "target_blocked") {
		t.Fatalf("terminal claim result = HTTP %d, %s", recorder.Code, recorder.Body.String())
	}
	recorder = httptest.NewRecorder()
	wakeError(recorder, &database.WakeError{Code: "target_blocked"})
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("blocked authorization = HTTP %d, %s", recorder.Code, recorder.Body.String())
	}
}

func TestWakeRoutesAuthorizeCredentialsAndKeepMACPrivate(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := auth.NewService("wake-routes-test-secret", db)
	jwt, owner, err := service.Register("owner@example.com", "account-password")
	if err != nil {
		t.Fatal(err)
	}
	control := NewServer(service, nil, db)
	mux := http.NewServeMux()
	control.RegisterWakeRoutes(mux)
	mux.HandleFunc("POST /api/v1/devices", auth.RequireAnyAuth(service, db)(control.RegisterDevice))
	mux.HandleFunc("GET /api/v1/nodes", auth.RequireAnyAuth(service, db)(control.ListNodes))
	mux.HandleFunc("POST /api/v1/telemetry/paths", auth.RequireDeviceAuth(db)(control.RequireCurrentDeviceRegistrationSession(control.SubmitPathTelemetry)))

	const mac = "02:11:22:33:44:55"
	request := func(method, path, bearer string, sequence int64, body string, want int, claim bool) map[string]any {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		if sequence > 0 {
			req.Header.Set(auth.RegistrationSequenceHeader, strconv.FormatInt(sequence, 10))
		}
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != want {
			t.Fatalf("%s %s returned %d, want %d: %s", method, path, res.Code, want, res.Body.String())
		}
		if strings.Contains(res.Body.String(), mac) != claim {
			t.Fatalf("%s %s violated MAC response visibility", method, path)
		}
		if want == http.StatusNoContent {
			return nil
		}
		var result map[string]any
		if err := json.Unmarshal(res.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}

	registration := `{"network_id":"default","public_key":"wake-proxy-key","device_name":"LAN Proxy","platform":"linux","registration_incarnation":500,"capabilities":{"wake_proxy_v1":true}}`
	agent := request("POST", "/api/v1/devices", jwt, 0, registration, 200, false)
	id := agent["node_id"].(string)
	seq := int64(agent["registration_seq"].(float64))
	if agent["accepted_peer_capabilities"].(map[string]any)["wake_proxy_v1"] == true {
		t.Fatal("JWT activated a wake proxy")
	}
	_, credential, err := db.CreateDeviceCredential(id, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if code := request("GET", "/api/v1/wake/jobs", credential, seq, "", 403, false)["error_code"]; code != "wake_proxy_required" {
		t.Fatalf("wrong denial: %v", code)
	}
	activation := request("POST", "/api/v1/devices", credential, 0, registration, 200, false)
	if activation["accepted_peer_capabilities"].(map[string]any)["wake_proxy_v1"] != true ||
		activation["registration_seq"] != agent["registration_seq"] {
		t.Fatal("fenced proxy activation did not preserve bootstrap sequence")
	}

	devicePath := "/api/v1/devices/" + id + "/wake"
	macBody := `{"mac":"` + mac + `","nic":"Ethernet"}`
	request("PUT", devicePath, jwt, seq, macBody, 401, false)
	request("PUT", devicePath, credential, 0, macBody, 409, false)
	request("PUT", devicePath, credential, seq, macBody, 204, false)
	request("PUT", "/api/v1/devices/another/wake", credential, seq, macBody, 403, false)
	status := request("GET", devicePath, jwt, 0, "", 200, false)
	if status["has_mac"] != true || status["online"] != true {
		t.Fatal("device wake status missing online/MAC flags")
	}
	request("GET", "/api/v1/nodes?network_id=default", jwt, 0, "", 200, false)
	peer, err := db.CreateDevice(owner.ID, "default", "wake-telemetry-peer", "Peer", "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	direct := "direct"
	batch, err := json.Marshal(database.PathTelemetryBatch{
		ProtocolVersion: 1,
		Observations: []database.PathObservation{{
			SchemaVersion: 1, NetworkID: "default", RemoteDeviceID: peer.ID, ObservationRevision: 1,
			Lifecycle: "online", CurrentPath: &direct, TransitionReason: "direct_committed", ObservedAt: time.Now().Unix(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	telemetry := request("POST", "/api/v1/telemetry/paths", credential, seq, string(batch), 200, false)
	if telemetry["accepted"] != float64(1) {
		t.Fatalf("valid path telemetry was not accepted: %v", telemetry)
	}
	connections, err := db.AdminConnections(database.AdminConnectionFilter{ReportingDeviceID: id}, 10, 0)
	if err != nil || len(connections.Items) != 1 {
		t.Fatalf("telemetry observation missing: %v", err)
	}
	encoded, err := json.Marshal(connections)
	if err != nil || strings.Contains(string(encoded), mac) {
		t.Fatalf("path telemetry exposed the local wake MAC: %v", err)
	}

	const manualList = "/api/v1/networks/default/wake-targets"
	target := request("POST", manualList, jwt, 0, `{"name":"Desk PC","mac":"`+mac+`"}`, 201, false)
	request("GET", manualList, jwt, 0, "", 200, false)
	manualWake := "/api/v1/wake-targets/" + target["id"].(string) + "/wake"
	request("GET", manualWake, jwt, 0, "", 200, false)
	job := request("POST", manualWake, jwt, 0, "", 202, false)
	jobPath := "/api/v1/wake/jobs/" + job["id"].(string)
	request("GET", "/api/v1/wake/jobs?state=queued&limit=4", credential, seq, "", 200, false)
	request("POST", jobPath+"/claim", jwt, seq, "", 401, false)
	claim := request("POST", jobPath+"/claim", credential, seq, "", 200, true)
	request("GET", jobPath, jwt, 0, "", 200, false)
	request("GET", jobPath, credential, seq, "", 200, false)
	result := `{"state":"sent","claim_token":"` + claim["claim_token"].(string) + `"}`
	request("POST", jobPath+"/result", credential, seq, result, 200, false)
	request("POST", jobPath+"/result", credential, seq, result, 200, false)
	request("DELETE", devicePath, credential, seq, "", 204, false)
	request("DELETE", devicePath, credential, seq, "", 204, false)
}
