package api

import (
	"context"
	"encoding/json"
	"errors"
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
	t.Setenv("RELAY_SERVERS", " default@47.109.40.237:18081, ,backup@example.com:18081 ")

	servers := parseRelayServers()
	want := []string{"default@47.109.40.237:18081", "backup@example.com:18081"}
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

func TestListSignalsLongPollReturnsWhenSignalArrives(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-long-poll@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-long-poll-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-long-poll-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}
	server := NewServer(nil, nil, db)

	errCh := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		_, err := db.CreateSignalWithPunchAt(
			source.ID,
			target.ID,
			"peer_offer",
			[]string{"203.0.113.10:51820"},
			map[string]string{"203.0.113.10:51820": "stun_observed"},
			"",
			time.Now().Add(1500*time.Millisecond).UnixMilli(),
		)
		errCh <- err
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals?wait_ms=500", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  target.ID,
		NetworkID: target.NetworkID,
		UserID:    user.ID,
	}))
	recorder := httptest.NewRecorder()
	started := time.Now()

	server.ListSignals(recorder, req)
	if err := <-errCh; err != nil {
		t.Fatalf("CreateSignalWithPunchAt: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if elapsed := time.Since(started); elapsed >= 500*time.Millisecond {
		t.Fatalf("long poll should return when the signal arrives, elapsed=%s", elapsed)
	}

	var body struct {
		Signals []database.Signal `json:"signals"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Signals) != 1 {
		t.Fatalf("expected one signal, got %d: %s", len(body.Signals), recorder.Body.String())
	}
	if body.Signals[0].FromNodeID != source.ID || body.Signals[0].ToNodeID != target.ID {
		t.Fatalf("unexpected signal endpoints: %+v", body.Signals[0])
	}
}

func TestListSignalsLongPollWakesImmediatelyWhenSignalCreatedViaAPI(t *testing.T) {
	previousFallback := signalLongPollFallbackInterval
	signalLongPollFallbackInterval = 750 * time.Millisecond
	defer func() {
		signalLongPollFallbackInterval = previousFallback
	}()

	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	defer db.Close()
	user, err := db.CreateUser("signal-notify@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	source, err := db.CreateDevice(user.ID, "default", "signal-notify-source-key", "source", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice source: %v", err)
	}
	target, err := db.CreateDevice(user.ID, "default", "signal-notify-target-key", "target", "linux", "")
	if err != nil {
		t.Fatalf("CreateDevice target: %v", err)
	}
	server := NewServer(nil, nil, db)

	errCh := make(chan error, 1)
	go func() {
		time.Sleep(25 * time.Millisecond)
		body := strings.NewReader(`{
			"to_node_id":"` + target.ID + `",
			"type":"peer_offer",
			"candidates":["203.0.113.10:51820"],
			"candidate_sources":{"203.0.113.10:51820":"stun_observed"},
			"punch_at_ms":` + fmtInt64(time.Now().Add(1500*time.Millisecond).UnixMilli()) + `
		}`)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/signals", body)
		req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
			DeviceID:  source.ID,
			NetworkID: source.NetworkID,
			UserID:    user.ID,
		}))
		recorder := httptest.NewRecorder()

		server.CreateSignal(recorder, req)
		if recorder.Code != http.StatusOK {
			errCh <- errors.New(recorder.Body.String())
			return
		}
		errCh <- nil
	}()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/signals?wait_ms=1000", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{
		DeviceID:  target.ID,
		NetworkID: target.NetworkID,
		UserID:    user.ID,
	}))
	recorder := httptest.NewRecorder()
	started := time.Now()

	server.ListSignals(recorder, req)
	if err := <-errCh; err != nil {
		t.Fatalf("CreateSignal: %v", err)
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if elapsed := time.Since(started); elapsed >= signalLongPollFallbackInterval {
		t.Fatalf("long poll should wake before fallback polling interval, elapsed=%s", elapsed)
	}

	var body struct {
		Signals []database.Signal `json:"signals"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(body.Signals) != 1 {
		t.Fatalf("expected one signal, got %d: %s", len(body.Signals), recorder.Body.String())
	}
	if body.Signals[0].FromNodeID != source.ID || body.Signals[0].ToNodeID != target.ID {
		t.Fatalf("unexpected signal endpoints: %+v", body.Signals[0])
	}
}

func fmtInt64(value int64) string {
	return strconv.FormatInt(value, 10)
}
