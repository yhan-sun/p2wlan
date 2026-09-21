package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/database"
)

type connectionTrendsFilterStore struct {
	fakeStore
	filter database.AdminConnectionTrendsFilter
}

func (s *connectionTrendsFilterStore) AdminConnectionTrends(filter database.AdminConnectionTrendsFilter) (*database.AdminConnectionTrends, error) {
	s.filter = filter
	if filter.WindowHours != 0 && (filter.WindowHours < 1 || filter.WindowHours > database.MaxConnectionTrendsWindowHours) {
		return nil, database.ErrInvalidConnectionTrendsWindow
	}
	return s.fakeStore.AdminConnectionTrends(filter)
}

func TestAdminConnectionTrendsPassesNetworkAndWindow(t *testing.T) {
	token := strings.Repeat("t", 32)
	store := &connectionTrendsFilterStore{}
	server, err := New(store, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(
		http.MethodGet,
		"/admin/api/v1/connection-trends?network_id=n1&window_hours=168",
		nil,
	)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if store.filter.NetworkID != "n1" || store.filter.WindowHours != 168 {
		t.Fatalf("unexpected trends filter: %+v", store.filter)
	}
	for _, expected := range []string{
		`"schema_version":1`,
		`"bucket_seconds":3600`,
		`"window_hours":168`,
		`"retention_hours":720`,
		`"network_id":"n1"`,
		`"sample_semantics":"accepted_non_resync_committed_observation_samples"`,
		`"percentile_semantics":"fixed_histogram_upper_bound"`,
	} {
		if !strings.Contains(rec.Body.String(), expected) {
			t.Fatalf("response missing %s: %s", expected, rec.Body.String())
		}
	}
}

func TestAdminConnectionTrendsDefaultsWindow(t *testing.T) {
	token := strings.Repeat("u", 32)
	store := &connectionTrendsFilterStore{}
	server, err := New(store, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/connection-trends", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if store.filter.WindowHours != 0 {
		t.Fatalf("handler should leave missing window at zero for store normalization, got %+v", store.filter)
	}
	if !strings.Contains(rec.Body.String(), `"window_hours":24`) {
		t.Fatalf("expected default 24h response: %s", rec.Body.String())
	}
}

func TestAdminConnectionTrendsRejectsInvalidWindow(t *testing.T) {
	token := strings.Repeat("v", 32)
	store := &connectionTrendsFilterStore{}
	server, err := New(store, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, path := range []string{
		"/admin/api/v1/connection-trends?window_hours=nope",
		"/admin/api/v1/connection-trends?window_hours=-1",
		"/admin/api/v1/connection-trends?window_hours=721",
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
