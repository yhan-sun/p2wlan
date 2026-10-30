package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func TestLoginAcceptsEmailAndAccountUsername(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "auth-handlers.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	service := auth.NewService("auth-handler-secret", db)
	_, user, err := service.Register("pyu@example.test", "password123")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpdateUsername(user.ID, "pyu"); err != nil {
		t.Fatal(err)
	}
	s := NewServer(service, nil, db)

	login := func(payload map[string]string) (int, map[string]any) {
		body, _ := json.Marshal(payload)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewReader(body))
		w := httptest.NewRecorder()
		s.Login(w, r)
		var decoded map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &decoded)
		return w.Code, decoded
	}

	if code, body := login(map[string]string{"email": "pyu@example.test", "password": "password123"}); code != http.StatusOK || body["token"] == "" {
		t.Fatalf("email login failed: code=%d body=%v", code, body)
	}
	if code, body := login(map[string]string{"email": "pyu", "password": "password123"}); code != http.StatusOK || body["token"] == "" {
		t.Fatalf("username login failed: code=%d body=%v", code, body)
	}
	if code, body := login(map[string]string{"identifier": "pyu", "password": "password123"}); code != http.StatusOK || body["token"] == "" {
		t.Fatalf("identifier login failed: code=%d body=%v", code, body)
	}
	if code, body := login(map[string]string{"email": "PYU@EXAMPLE.TEST", "password": "password123"}); code != http.StatusOK || body["token"] == "" {
		t.Fatalf("uppercase email login failed: code=%d body=%v", code, body)
	}
	if _, err := db.UpdateUsername(user.ID, "My@Name"); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"email", "identifier"} {
		if code, body := login(map[string]string{key: "My@Name", "password": "password123"}); code != http.StatusOK || body["token"] == "" {
			t.Fatalf("case-sensitive username containing @ failed: key=%s code=%d body=%v", key, code, body)
		}
	}
}

func TestLoginStorageFailureDoesNotReportInvalidPassword(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "login-unavailable.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(auth.NewService("test-login-secret", db), nil, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(`{"email":"account@example.test","password":"password123"}`))
	w := httptest.NewRecorder()
	s.Login(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("storage outage must be retryable, got HTTP %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error_code"] != "authentication_unavailable" {
		t.Fatal("storage outage missing stable reason code")
	}
}

func TestRegisterValidatesBcryptPasswordByteLimit(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "password-limit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewServer(auth.NewService("test-secret", db), nil, db)
	for _, tc := range []struct {
		name, password string
		status         int
	}{
		{"ascii-limit", strings.Repeat("a", 72), http.StatusOK},
		{"ascii-too-long", strings.Repeat("a", 73), http.StatusBadRequest},
		{"unicode-limit", strings.Repeat("密", 24), http.StatusOK},
		{"unicode-too-long", strings.Repeat("密", 25), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]string{"email": tc.name + "@example.test", "password": tc.password})
			w := httptest.NewRecorder()
			s.Register(w, httptest.NewRequest(http.MethodPost, "/api/v1/register", bytes.NewReader(body)))
			if w.Code != tc.status {
				t.Fatalf("HTTP %d, want %d: %s", w.Code, tc.status, w.Body.String())
			}
			if tc.status == http.StatusBadRequest && !strings.Contains(w.Body.String(), "72") {
				t.Fatalf("password boundary missing from error: %s", w.Body.String())
			}
		})
	}
}
