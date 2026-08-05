package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

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

func TestCreateSignalAcceptsExpandedCandidateWindow(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-expanded-candidates@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-expanded-source-key", "signal-source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-expanded-target-key", "signal-target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}

	candidateArrayJSON := func(count int) string {
		var b strings.Builder
		for i := 0; i < count; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('"')
			b.WriteString("203.0.113.10:")
			b.WriteString(fmtInt64(int64(40000 + i)))
			b.WriteByte('"')
		}
		return b.String()
	}

	server := NewServer(nil, nil, db)
	body := strings.NewReader(`{"to_node_id":"` + target.ID + `","type":"peer_offer","candidates":[` + candidateArrayJSON(96) + `]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID: source.ID, NetworkID: source.NetworkID, UserID: user.ID,
	}))
	recorder := httptest.NewRecorder()
	server.CreateSignal(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 for 96 candidates, got %d: %s", recorder.Code, recorder.Body.String())
	}
	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals: %v", err)
	}
	if len(signals) != 1 || len(signals[0].Candidates) != 96 {
		t.Fatalf("expected one signal with 96 candidates, got %#v", signals)
	}

	body = strings.NewReader(`{"to_node_id":"` + target.ID + `","type":"peer_offer","candidates":[` + candidateArrayJSON(97) + `]}`)
	req = httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID: source.ID, NetworkID: source.NetworkID, UserID: user.ID,
	}))
	recorder = httptest.NewRecorder()
	server.CreateSignal(recorder, req)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for 97 candidates, got %d: %s", recorder.Code, recorder.Body.String())
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

// The client's fresh-mapping prediction window must pass the real control
// plane validation: every candidate_sources key is a real candidate, values
// stay under 64 bytes, and the map size never exceeds the candidate count.
// This locks the client contract used by
// p2wlan_daemon::build_fresh_mapping_signal_payload so a predicted-window
// offer can never be rejected with HTTP 400.
func TestCreateSignalAcceptsPredictedCandidateWindow(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-predicted@example.com", "hash")
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

	// Exact payload shape produced by the daemon: ranked predicted window
	// first, then the peer's own host/stun candidates, all real endpoints.
	body := strings.NewReader(`{
		"to_node_id":"` + target.ID + `",
		"type":"peer_offer",
		"candidates":[
			"220.163.6.190:45393",
			"220.163.6.190:45394",
			"220.163.6.190:45395",
			"220.163.6.190:45388",
			"192.168.0.239:58980"
		],
		"candidate_sources":{
			"220.163.6.190:45393":"predicted",
			"220.163.6.190:45394":"predicted",
			"220.163.6.190:45395":"predicted",
			"220.163.6.190:45388":"stun_observed",
			"192.168.0.239:58980":"host"
		}
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
		t.Fatalf("expected 200 for ranked predicted window, got %d: %s", recorder.Code, recorder.Body.String())
	}

	signals, err := db.ListAndDeleteSignals(target.ID)
	if err != nil {
		t.Fatalf("ListAndDeleteSignals: %v", err)
	}
	if len(signals) != 1 {
		t.Fatalf("expected one signal, got %d", len(signals))
	}
	if len(signals[0].Candidates) != 5 {
		t.Fatalf("expected 5 candidates, got %d", len(signals[0].Candidates))
	}
	if len(signals[0].CandidateSources) != 5 {
		t.Fatalf("expected 5 candidate sources, got %d", len(signals[0].CandidateSources))
	}
}

// Reserved metadata keys embedded in candidate_sources must stay rejected:
// the map must not carry keys that are not real candidates.
func TestCreateSignalRejectsReservedMetadataKeysInCandidateSources(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-reserved@example.com", "hash")
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

	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown key",
			body: `{
				"to_node_id":"` + target.ID + `",
				"type":"peer_offer",
				"candidates":["220.163.6.190:45393"],
				"candidate_sources":{
					"220.163.6.190:45393":"predicted",
					"__p2wlan_mapping_model_v1":"{\"model\":\"fixed_step\"}"
				}
			}`,
		},
		{
			name: "more sources than candidates",
			body: `{
				"to_node_id":"` + target.ID + `",
				"type":"peer_offer",
				"candidates":["220.163.6.190:45393"],
				"candidate_sources":{
					"220.163.6.190:45393":"predicted",
					"220.163.6.190:45394":"predicted"
				}
			}`,
		},
		{
			name: "source value too long",
			body: `{
				"to_node_id":"` + target.ID + `",
				"type":"peer_offer",
				"candidates":["220.163.6.190:45393"],
				"candidate_sources":{"220.163.6.190:45393":"` + strings.Repeat("x", 65) + `"}
			}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", strings.NewReader(tc.body))
			req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
				DeviceID:  source.ID,
				NetworkID: source.NetworkID,
				UserID:    user.ID,
			}))
			recorder := httptest.NewRecorder()
			NewServer(nil, nil, db).CreateSignal(recorder, req)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d: %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
