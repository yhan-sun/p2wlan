package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestUnchangedRoomIPResponseDoesNotRequireReconnect(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	owner, err := db.CreateUser("ip@api.test", "unused")
	if err != nil {
		t.Fatal(err)
	}
	room, err := db.CreateRoom(owner.ID, "room", "safe-password")
	if err != nil {
		t.Fatal(err)
	}
	d, err := db.CreateDevice(owner.ID, room.ID, "api-ip-key", "device", "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	_, credential, err := db.CreateDeviceCredential(d.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(auth.NewService("fixture-secret", db), nil, db)
	req := httptest.NewRequest("PATCH", "/", strings.NewReader(`{"virtual_ip":"`+d.VirtualIP+`"}`))
	req.SetPathValue("room", room.ID)
	req.SetPathValue("device", d.ID)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserClaimsKey, &auth.Claims{UserID: owner.ID}))
	w := httptest.NewRecorder()
	s.AssignRoomDeviceIP(w, req)
	var response map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || response["changed"] != false || response["reconnect_required"] != false {
		t.Fatalf("incorrect no-op response: %s", w.Body.String())
	}
	if _, _, err := db.ValidateDeviceCredential(credential); err != nil {
		t.Fatal("no-op revoked credential", err)
	}
}

func TestRoomConflictCodesDescribeActualOperation(t *testing.T) {
	for _, tt := range []struct {
		err  error
		code string
	}{
		{database.ErrRoomIPConflict, "room_ip_conflict"},
		{database.ErrRoomDeviceStateConflict, "room_device_state_conflict"},
		{database.ErrRoomInviteLimit, "room_invite_limit"},
		{database.ErrRoomConflict, "room_conflict"},
	} {
		w := httptest.NewRecorder()
		roomError(w, tt.err)
		var body map[string]any
		json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != 409 || body["error_code"] != tt.code {
			t.Fatalf("wrong error for %v: %s", tt.err, w.Body.String())
		}
	}
}

func TestRevocationCursorHTTPContract(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "feed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewServer(auth.NewService("fixture-secret", db), nil, db)
	s.relayRevocationFeedToken = "fixture-feed"
	for _, tt := range []struct {
		query  string
		status int
	}{
		{"?protocol=2&after=0", 200}, {"?protocol=2&after=-1", 400},
		{"?protocol=2&after=01", 400}, {"?protocol=2&after=0&after=0", 400},
		{"?protocol=2&after=999", 409}, {"?protocol=3", 400},
	} {
		req := httptest.NewRequest("GET", "/"+tt.query, nil)
		req.Header.Set("Authorization", "Bearer fixture-feed")
		w := httptest.NewRecorder()
		s.RelayRevocations(w, req)
		if w.Code != tt.status {
			t.Fatalf("%s: %d %s", tt.query, w.Code, w.Body.String())
		}
		if w.Code == 200 && !strings.Contains(w.Body.String(), `"protocol_version":2`) {
			t.Fatal("no v2 response")
		}
	}
}

func TestIssuedRelayTicketsBindAuthoritativeForwardingScope(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signerJSON, _ := json.Marshal(map[string]any{"active": map[string]string{"kid": "scope-fixture", "private_key": hex.EncodeToString(priv.Seed())}})
	t.Setenv("RELAY_TICKET_SIGNER_JSON", string(signerJSON))
	t.Setenv("RELAY_CATALOG_JSON", `[{"region":"test","audience":"test-relay","endpoint":"tls://relay.example:443"}]`)
	db, err := database.New(filepath.Join(t.TempDir(), "tickets.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	a, err := db.CreateUser("ticket-a@test.invalid", "unused")
	if err != nil {
		t.Fatal(err)
	}
	b, err := db.CreateUser("ticket-b@test.invalid", "unused")
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(auth.NewService("fixture-secret", db), nil, db)
	verifier := auth.NewRelayTicketVerifier(map[string]ed25519.PublicKey{"scope-fixture": pub}, time.Second)
	issue := func(user, network, key string) *auth.RelayTicketClaims {
		t.Helper()
		d, err := db.CreateDevice(user, network, key, key, "linux", "")
		if err != nil {
			t.Fatal(err)
		}
		cred, _, err := db.CreateDeviceCredential(d.ID, 3600)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"audience":"test-relay"}`))
		req = req.WithContext(context.WithValue(req.Context(), auth.DeviceClaimsKey, &auth.DeviceClaims{UserID: user, NetworkID: network, DeviceID: d.ID, CredentialID: cred.ID}))
		w := httptest.NewRecorder()
		s.CreateRelayTicket(w, req)
		if w.Code != 200 {
			t.Fatalf("ticket issuance: %d %s", w.Code, w.Body.String())
		}
		var body struct {
			Ticket string `json:"ticket"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		claims, err := verifier.Verify(body.Ticket)
		if err != nil {
			t.Fatal(err)
		}
		if claims.DeviceID != d.ID || claims.NodeID != d.ID || claims.CredentialID != cred.ID {
			t.Fatal("scope change altered device identity")
		}
		return claims
	}
	first := issue(a.ID, "default", "ticket-personal-a")
	same := issue(a.ID, "default", "ticket-personal-a2")
	other := issue(b.ID, "default", "ticket-personal-b")
	if first.NetworkID != same.NetworkID || first.NetworkID == other.NetworkID {
		t.Fatal("issued personal scopes violate account isolation")
	}
	room, err := db.CreateRoom(a.ID, "test room", "safe-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.JoinRoom(b.ID, room.Code, "safe-password", ""); err != nil {
		t.Fatal(err)
	}
	if issue(a.ID, room.ID, "ticket-room-a").NetworkID != issue(b.ID, room.ID, "ticket-room-b").NetworkID {
		t.Fatal("issued room scopes block members")
	}
}
