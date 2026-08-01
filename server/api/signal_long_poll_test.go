package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

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
		Signals      []database.Signal `json:"signals"`
		ServerTimeMS int64             `json:"server_time_ms"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ServerTimeMS <= 0 {
		t.Fatalf("expected server_time_ms in response: %s", recorder.Body.String())
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
