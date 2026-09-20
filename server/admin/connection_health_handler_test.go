package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/database"
)

type connectionHealthFilterStore struct {
	fakeStore
	filter database.AdminConnectionHealthFilter
}

func (s *connectionHealthFilterStore) AdminConnectionHealth(filter database.AdminConnectionHealthFilter) (*database.AdminConnectionHealth, error) {
	s.filter = filter
	if filter.WindowSeconds != 0 && (filter.WindowSeconds < database.MinConnectionHealthWindowSeconds || filter.WindowSeconds > database.MaxConnectionHealthWindowSeconds) {
		return nil, database.ErrInvalidConnectionHealthWindow
	}
	if filter.AlertLimit != 0 && (filter.AlertLimit < 1 || filter.AlertLimit > database.MaxConnectionHealthAlertLimit) {
		return nil, database.ErrInvalidConnectionHealthLimit
	}
	return s.fakeStore.AdminConnectionHealth(filter)
}

func TestAdminConnectionHealthPassesScopeWindowAndLimit(t *testing.T) {
	token := strings.Repeat("h", 32)
	store := &connectionHealthFilterStore{}
	server, err := New(store, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(
		http.MethodGet,
		"/admin/api/v1/connection-health?network_id=n1&account_id=u1&device_id=d1&window_seconds=900&limit=17",
		nil,
	)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if store.filter.NetworkID != "n1" || store.filter.AccountID != "u1" || store.filter.DeviceID != "d1" || store.filter.WindowSeconds != 900 || store.filter.AlertLimit != 17 {
		t.Fatalf("unexpected connection health filter: %+v", store.filter)
	}
	for _, expected := range []string{
		`"schema_version":1`,
		`"window_seconds":900`,
		`"history_limit_per_direction":50`,
		`"alerts_limit":17`,
	} {
		if !strings.Contains(rec.Body.String(), expected) {
			t.Fatalf("response missing %s: %s", expected, rec.Body.String())
		}
	}
}

func TestAdminConnectionHealthAcceptsUserIDAlias(t *testing.T) {
	token := strings.Repeat("i", 32)
	store := &connectionHealthFilterStore{}
	server, err := New(store, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/connection-health?user_id=u2", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if store.filter.AccountID != "u2" {
		t.Fatalf("expected user_id alias to populate account filter, got %+v", store.filter)
	}
}

func TestAdminConnectionHealthRejectsInvalidWindowAndLimit(t *testing.T) {
	token := strings.Repeat("j", 32)
	store := &connectionHealthFilterStore{}
	server, err := New(store, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, path := range []string{
		"/admin/api/v1/connection-health?window_seconds=nope",
		"/admin/api/v1/connection-health?window_seconds=59",
		"/admin/api/v1/connection-health?window_seconds=86401",
		"/admin/api/v1/connection-health?limit=nope",
		"/admin/api/v1/connection-health?limit=101",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}
}
