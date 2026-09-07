package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestRoomRoutesEnforceAccountAndDeviceBoundaries(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "rooms.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := auth.NewService("room-route-test-secret", db)
	tokenA, userA, err := service.Register("a@rooms.example", "account-password")
	if err != nil {
		t.Fatal(err)
	}
	tokenB, _, err := service.Register("b@rooms.example", "account-password")
	if err != nil {
		t.Fatal(err)
	}
	device, err := db.CreateDevice(userA.ID, "default", "room-route-key", "owner device", "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	_, deviceToken, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(service, nil, db)
	mux := http.NewServeMux()
	server.RegisterRoomRoutes(mux, func(next http.HandlerFunc) http.HandlerFunc { return next })
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, req)
		return response
	}
	for _, token := range []string{"", deviceToken} {
		response := request(http.MethodGet, "/api/v1/rooms", token, "")
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("room management accepted non-account credential: %d", response.Code)
		}
	}
	if response := request(http.MethodGet, "/api/v1/room-roster", tokenA, ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("room roster accepted account bearer: %d", response.Code)
	}
	for _, body := range []string{
		`{"name":"room","password":"room-password","owner_id":"foreign"}`,
		`{"name":"room","password":"room-password","cidr":"20.21.1.0/24"}`,
		`{"name":"room","password":"room-password"} {}`,
		`{"name":"`+strings.Repeat("x", 9000)+`","password":"room-password"}`,
	} {
		if response := request(http.MethodPost, "/api/v1/rooms", tokenA, body); response.Code != http.StatusBadRequest {
			t.Fatalf("invalid create accepted: %d %s", response.Code, response.Body.String())
		}
	}
	created := request(http.MethodPost, "/api/v1/rooms", tokenA, `{"name":"周末联机","password":"room-password"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var payload struct { Room database.Room `json:"room"` }
	if err := json.Unmarshal(created.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/rooms/"+payload.Room.ID
	if response := request(http.MethodGet, path, tokenB, ""); response.Code != http.StatusForbidden {
		t.Fatalf("unrelated account read detail: %d", response.Code)
	}
	if response := request(http.MethodDelete, path, tokenB, ""); response.Code != http.StatusForbidden {
		t.Fatalf("nonowner deleted room: %d", response.Code)
	}
	joined := request(http.MethodPost, "/api/v1/rooms/join", tokenB, `{"number":"`+payload.Room.Number+`","password":"room-password"}`)
	if joined.Code != http.StatusOK {
		t.Fatalf("join: %d %s", joined.Code, joined.Body.String())
	}
	if response := request(http.MethodPost, path+"/devices", tokenA, `{"device_id":"`+device.ID+`"}`); response.Code != http.StatusOK {
		t.Fatalf("enable owner device: %d %s", response.Code, response.Body.String())
	}
	roster := request(http.MethodGet, "/api/v1/room-roster", deviceToken, "")
	if roster.Code != http.StatusOK || !strings.Contains(roster.Body.String(), "10.21.1.1") || roster.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("device roster: %d %s", roster.Code, roster.Body.String())
	}
	if response := request(http.MethodPost, path+"/invitation", tokenB, `{}`); response.Code != http.StatusForbidden {
		t.Fatalf("member issued invitation: %d", response.Code)
	}
	invited := request(http.MethodPost, path+"/invitation", tokenA, `{}`)
	if invited.Code != http.StatusOK || invited.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invite: %d %s", invited.Code, invited.Body.String())
	}
	var invitation struct { Invitation string `json:"invitation"` }
	if err := json.Unmarshal(invited.Body.Bytes(), &invitation); err != nil || invitation.Invitation == "" {
		t.Fatalf("invite response: %v", err)
	}
	for _, endpoint := range []string{"/api/v1/rooms", path} {
		response := request(http.MethodGet, endpoint, tokenA, "")
		for _, secret := range []string{"room-password", "password_hash", "invite_hash", invitation.Invitation} {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatalf("GET %s leaked a room secret", endpoint)
			}
		}
	}
}
