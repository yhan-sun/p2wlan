package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

type leaseServer struct {
	db   *database.DB
	srv  *Server
	user *database.User
	from *database.Device
	to   *database.Device
}

func newLeaseServer(t *testing.T) *leaseServer {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "control.db"))
	if err != nil {
		t.Fatalf("database.New: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	user, err := db.CreateUser("ack-owner@example.com", "hash")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	from, err := db.CreateDevice(user.ID, "default", "ack-from-key", "ack-from", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice from: %v", err)
	}
	to, err := db.CreateDevice(user.ID, "default", "ack-to-key", "ack-to", "macos", "")
	if err != nil {
		t.Fatalf("CreateDevice to: %v", err)
	}
	return &leaseServer{
		db:   db,
		srv:  NewServer(nil, nil, db),
		user: user,
		from: from,
		to:   to,
	}
}

func (ls *leaseServer) userRequest(method, path, body string) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: ls.user.ID}))
	return httptest.NewRecorder(), req
}

func (ls *leaseServer) createSignal(t *testing.T, typ string, candidate string, generation int64) {
	t.Helper()
	body := `{"from_node_id":"` + ls.from.ID + `","to_node_id":"` + ls.to.ID + `","type":"` + typ +
		`","candidates":["` + candidate + `"],"candidate_generation":` + fmtInt64(generation) + `}`
	recorder, req := ls.userRequest(http.MethodPost, "/api/v1/signals", body)
	ls.srv.CreateSignal(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("create signal: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestListSignalsLeaseModeDeliversWithoutDeletingAndAcks(t *testing.T) {
	ls := newLeaseServer(t)
	ls.createSignal(t, "peer_offer", "203.0.113.10:44001", 1)
	ls.createSignal(t, "peer_offer", "203.0.113.10:44002", 2)

	// ACK-mode GET leases the batch (no deletion).
	recorder, req := ls.userRequest(http.MethodGet, "/api/v1/signals?node_id="+ls.to.ID+"&ack=1", "")
	ls.srv.ListSignals(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("lease GET: %d %s", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Signals []struct {
			ID            string `json:"id"`
			DeliveryToken string `json:"delivery_token"`
		} `json:"signals"`
		Delivery struct {
			BatchToken       string `json:"batch_token"`
			LeaseExpiresAtMS int64  `json:"lease_expires_at_ms"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode lease response: %v", err)
	}
	if len(response.Signals) != 2 {
		t.Fatalf("expected 2 leased signals, got %d", len(response.Signals))
	}
	if response.Delivery.BatchToken == "" {
		t.Fatalf("batch token must be present")
	}
	if response.Delivery.LeaseExpiresAtMS <= time.Now().UnixMilli() {
		t.Fatalf("lease deadline must be in the future")
	}
	for _, signal := range response.Signals {
		if signal.DeliveryToken == "" {
			t.Fatalf("delivery token must be present")
		}
	}

	// The rows still exist (the GET did not delete them): a legacy GET (no
	// ack) must NOT see or steal leased rows.
	legacy, legacyReq := ls.userRequest(http.MethodGet, "/api/v1/signals?node_id="+ls.to.ID, "")
	ls.srv.ListSignals(legacy, legacyReq)
	if legacy.Code != http.StatusOK {
		t.Fatalf("legacy GET: %d %s", legacy.Code, legacy.Body.String())
	}
	var legacyResponse struct {
		Signals []json.RawMessage `json:"signals"`
	}
	if err := json.Unmarshal(legacy.Body.Bytes(), &legacyResponse); err != nil {
		t.Fatalf("decode legacy response: %v", err)
	}
	if len(legacyResponse.Signals) != 0 {
		t.Fatalf("legacy GET must not steal leased rows, got %d", len(legacyResponse.Signals))
	}

	// ACK one row per-row with its token: exactly that row disappears.
	ackBody := `{"signals":[{"id":"` + response.Signals[0].ID + `","delivery_token":"` + response.Signals[0].DeliveryToken + `"}]}`
	ackRec, ackReq := ls.userRequest(http.MethodPost, "/api/v1/signals/ack?node_id="+ls.to.ID, ackBody)
	ls.srv.AckSignals(ackRec, ackReq)
	if ackRec.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", ackRec.Code, ackRec.Body.String())
	}

	// A repeated ACK is a no-op.
	ackRec2, ackReq2 := ls.userRequest(http.MethodPost, "/api/v1/signals/ack?node_id="+ls.to.ID, ackBody)
	ls.srv.AckSignals(ackRec2, ackReq2)
	if ackRec2.Code != http.StatusOK {
		t.Fatalf("repeat ack: %d %s", ackRec2.Code, ackRec2.Body.String())
	}

	// The other row is still held by its lease; after expiry it redelivers.
	second, secondReq := ls.userRequest(http.MethodGet, "/api/v1/signals?node_id="+ls.to.ID+"&ack=1", "")
	ls.srv.ListSignals(second, secondReq)
	var secondResponse struct {
		Signals []json.RawMessage `json:"signals"`
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondResponse); err != nil {
		t.Fatalf("decode second lease response: %v", err)
	}
	if len(secondResponse.Signals) != 0 {
		t.Fatalf("un-acked rows must stay leased, got %d", len(secondResponse.Signals))
	}
	// Expire the remaining lease in the DB, then redelivery happens.
	ls.db.Exec(`UPDATE signals SET lease_expires_at = ? WHERE to_node_id = ?`, time.Now().Unix()-1, ls.to.ID)
	redelivered, redeliveredReq := ls.userRequest(http.MethodGet, "/api/v1/signals?node_id="+ls.to.ID+"&ack=1", "")
	ls.srv.ListSignals(redelivered, redeliveredReq)
	var redeliveredResponse struct {
		Signals []json.RawMessage `json:"signals"`
	}
	if err := json.Unmarshal(redelivered.Body.Bytes(), &redeliveredResponse); err != nil {
		t.Fatalf("decode redelivery response: %v", err)
	}
	if len(redeliveredResponse.Signals) != 1 {
		t.Fatalf("expired lease must redeliver the remaining row, got %d", len(redeliveredResponse.Signals))
	}
}

func TestListSignalsLegacyModeStillDeletesOnGet(t *testing.T) {
	ls := newLeaseServer(t)
	ls.createSignal(t, "peer_answer", "203.0.113.10:44010", 1)

	// A legacy client (no ack param) keeps the delete-on-GET contract.
	legacy, legacyReq := ls.userRequest(http.MethodGet, "/api/v1/signals?node_id="+ls.to.ID, "")
	ls.srv.ListSignals(legacy, legacyReq)
	if legacy.Code != http.StatusOK {
		t.Fatalf("legacy GET: %d %s", legacy.Code, legacy.Body.String())
	}
	var response struct {
		Signals []json.RawMessage `json:"signals"`
	}
	if err := json.Unmarshal(legacy.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(response.Signals) != 1 {
		t.Fatalf("legacy GET must deliver the row, got %d", len(response.Signals))
	}
	// The row is gone: no infinite redelivery for old clients.
	again, againReq := ls.userRequest(http.MethodGet, "/api/v1/signals?node_id="+ls.to.ID, "")
	ls.srv.ListSignals(again, againReq)
	var againResponse struct {
		Signals []json.RawMessage `json:"signals"`
	}
	if err := json.Unmarshal(again.Body.Bytes(), &againResponse); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(againResponse.Signals) != 0 {
		t.Fatalf("legacy delete-on-GET must not redeliver, got %d", len(againResponse.Signals))
	}
}
