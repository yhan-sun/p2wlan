package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/database"
)

type fakeStore struct{}

func (fakeStore) AdminOverviewSnapshot() (*database.AdminOverview, error) {
	return &database.AdminOverview{
		GeneratedAt:    10,
		Users:          3,
		Networks:       2,
		Rooms:          1,
		Devices:        4,
		OnlineDevices:  2,
		ActiveTunnels:  1,
		PendingSignals: 5,
		RecentDevices:  []database.AdminDeviceSummary{{ID: "d1", DeviceName: "desktop", Online: true}},
	}, nil
}

func (fakeStore) AdminAccounts(_ string, limit, offset int) (*database.AdminAccountPage, error) {
	return &database.AdminAccountPage{Total: 1, Limit: limit, Offset: offset, Items: []database.AdminAccountSummary{{ID: "u1", Username: "alice", DeviceCount: 2, OnlineDevices: 1}}}, nil
}

func (fakeStore) AdminAccountsCursor(_ string, _ string, limit int) (*database.AdminAccountCursorPage, error) {
	return &database.AdminAccountCursorPage{Total: 1, Limit: limit, Items: []database.AdminAccountSummary{{ID: "u1", Username: "alice", DeviceCount: 2, OnlineDevices: 1}}}, nil
}

func (fakeStore) AdminAccount(accountID string) (*database.AdminAccountDetail, error) {
	if accountID == "missing" {
		return nil, database.ErrAdminAccountNotFound
	}
	return &database.AdminAccountDetail{Account: database.AdminAccountSummary{ID: accountID, Username: "alice"}, Devices: []database.AdminDeviceSummary{}, Networks: []database.AdminNetworkSummary{}, Rooms: []database.AdminRoomSummary{}}, nil
}

func (fakeStore) AdminTopology(accountID string) (*database.AdminTopology, error) {
	if accountID == "missing" {
		return nil, database.ErrAdminAccountNotFound
	}
	scope := "global"
	if accountID != "" {
		scope = "account"
	}
	return &database.AdminTopology{
		GeneratedAt:              10,
		Scope:                    scope,
		FocusAccountID:           accountID,
		PathObservationAvailable: false,
		PathObservationNote:      "path telemetry unavailable",
		Nodes:                    []database.AdminTopologyNode{{ID: "account:u1", Kind: "account", AccountID: "u1", Label: "alice"}},
		Edges:                    []database.AdminTopologyEdge{},
	}, nil
}

func (fakeStore) AdminTopologyPage(after string, accountLimit, nodeBudget int) (*database.AdminTopologyPage, error) {
	return &database.AdminTopologyPage{
		AdminTopology: database.AdminTopology{
			GeneratedAt:              10,
			Scope:                    "global",
			PathObservationAvailable: false,
			PathObservationNote:      "path telemetry unavailable",
			Nodes:                    []database.AdminTopologyNode{{ID: "account:u1", Kind: "account", AccountID: "u1", Label: "alice"}},
			Edges:                    []database.AdminTopologyEdge{},
		},
		NextCursor:     "",
		Complete:       true,
		LoadedAccounts: 1,
		TotalAccounts:  1,
		NodeBudget:     nodeBudget,
		EdgeBudget:     4000,
	}, nil
}

func (fakeStore) AdminDevices(_ string, _ string, limit, offset int) (*database.AdminDevicePage, error) {
	return &database.AdminDevicePage{Total: 1, Limit: limit, Offset: offset, Items: []database.AdminDeviceSummary{{ID: "d1", DeviceName: "desktop"}}}, nil
}

func (fakeStore) AdminNetworks(limit, offset int) (*database.AdminNetworkPage, error) {
	return &database.AdminNetworkPage{Total: 1, Limit: limit, Offset: offset, Items: []database.AdminNetworkSummary{{ID: "n1", Name: "home"}}}, nil
}

func (fakeStore) AdminRooms(limit, offset int) (*database.AdminRoomPage, error) {
	return &database.AdminRoomPage{Total: 1, Limit: limit, Offset: offset, Items: []database.AdminRoomSummary{{ID: "r1", Name: "friends"}}}, nil
}

func (fakeStore) AdminConnections(_ database.AdminConnectionFilter, limit, offset int) (*database.AdminConnectionPage, error) {
	return &database.AdminConnectionPage{Total: 1, Limit: limit, Offset: offset, Items: []database.AdminConnectionSummary{{ReportingDeviceID: "d1", RemoteDeviceID: "d2"}}}, nil
}

func (fakeStore) AdminConnectionTransitions(_ database.AdminConnectionTransitionFilter, limit int, _ string) (*database.AdminConnectionTransitionPage, error) {
	return &database.AdminConnectionTransitionPage{Limit: limit, Items: []database.AdminConnectionTransitionSummary{{ReportingDeviceID: "d1", RemoteDeviceID: "d2"}}}, nil
}

func (fakeStore) AdminConnectionHealth(filter database.AdminConnectionHealthFilter) (*database.AdminConnectionHealth, error) {
	window := filter.WindowSeconds
	if window == 0 {
		window = database.DefaultConnectionHealthWindowSeconds
	}
	limit := filter.AlertLimit
	if limit == 0 {
		limit = database.DefaultConnectionHealthAlertLimit
	}
	return &database.AdminConnectionHealth{
		SchemaVersion:            database.AdminConnectionHealthSchemaVersion,
		GeneratedAt:              10,
		WindowSeconds:            window,
		HistoryLimitPerDirection: database.MaxTransitionsPerPair,
		Thresholds: database.AdminConnectionHealthThresholds{
			FrequentPathSwitches: database.ConnectionHealthFrequentSwitchThreshold,
			RepeatedPathFailures: database.ConnectionHealthRepeatedFailureThreshold,
		},
		AlertsLimit: limit,
		Alerts:      []database.AdminConnectionHealthAlert{},
	}, nil
}

type connectionFilterStore struct {
	fakeStore
	filter database.AdminConnectionFilter
}

func (s *connectionFilterStore) AdminConnections(filter database.AdminConnectionFilter, limit, offset int) (*database.AdminConnectionPage, error) {
	s.filter = filter
	return s.fakeStore.AdminConnections(filter, limit, offset)
}

func testServer(t *testing.T, token string) *Server {
	t.Helper()
	server, err := New(fakeStore{}, Config{
		Token:        token,
		BuildVersion: "server-v1.2.3",
		BuildCommit:  "0123456789abcdef",
		StartedAt:    time.Now().Add(-90 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestNewRejectsWeakAdminToken(t *testing.T) {
	if _, err := New(fakeStore{}, Config{Token: "short"}); err == nil {
		t.Fatal("expected short admin token to be rejected")
	}
}

func TestDisabledConsoleIsNotDiscoverable(t *testing.T) {
	server := testServer(t, "")
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	paths := []string{"/admin", "/admin/", "/admin/accounts/u1", "/admin/connections", "/admin/health", "/admin/api/v1/runtime", "/admin/api/v1/accounts", "/admin/api/v1/topology", "/admin/api/v1/connections", "/admin/api/v1/connection-transitions", "/admin/api/v1/connection-health", "/admin/api/v1/connection-health", "/admin/app.js", "/admin/index.html"}
	methods := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions}
	for _, path := range paths {
		for _, method := range methods {
			req := httptest.NewRequest(method, path, nil)
			res := httptest.NewRecorder()
			mux.ServeHTTP(res, req)
			// 405 would confirm that the route is registered even though the
			// console is disabled, so the disabled surface must be 404 for
			// every method, not only for GET.
			if res.Code != http.StatusNotFound {
				t.Fatalf("%s %s: expected 404, got %d", method, path, res.Code)
			}
		}
	}
}

func TestConsoleServesEmbeddedUIWithSecurityHeaders(t *testing.T) {
	server := testServer(t, strings.Repeat("a", 32))
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, path := range []string{"/admin/", "/admin/accounts/u1", "/admin/topology", "/admin/connections", "/admin/health"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("%s: expected 200, got %d", path, res.Code)
		}
		if !strings.Contains(res.Body.String(), "P2WLAN") {
			t.Fatalf("%s: expected embedded console HTML", path)
		}
		if got := res.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
			t.Fatalf("%s: missing restrictive CSP: %q", path, got)
		}
		if got := res.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s: expected no-store, got %q", path, got)
		}
	}

	asset := httptest.NewRecorder()
	mux.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/admin/missing.js", nil))
	if asset.Code != http.StatusNotFound {
		t.Fatalf("unknown admin asset: expected 404, got %d", asset.Code)
	}
}

func TestAdminAPIRequiresBearerToken(t *testing.T) {
	token := strings.Repeat("b", 32)
	server := testServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, path := range []string{"/admin/api/v1/overview", "/admin/api/v1/accounts", "/admin/api/v1/topology", "/admin/api/v1/connections", "/admin/api/v1/connection-transitions"} {
		unauthorized := httptest.NewRecorder()
		mux.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, path, nil))
		if unauthorized.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", path, unauthorized.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/overview", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", res.Code, res.Body.String())
	}
	if !strings.Contains(res.Body.String(), `"online_devices":2`) {
		t.Fatalf("unexpected overview payload: %s", res.Body.String())
	}
	if strings.Contains(res.Body.String(), token) {
		t.Fatal("admin token leaked into response")
	}
}

func TestAdminAccountCursorRoute(t *testing.T) {
	token := strings.Repeat("g", 32)
	server := testServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts/cursor?limit=25", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"username":"alice"`) {
		t.Fatalf("unexpected account cursor response %d: %s", res.Code, res.Body.String())
	}

	bad := httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts/cursor?cursor="+strings.Repeat("x", 129), nil)
	bad.Header.Set("Authorization", "Bearer "+token)
	badRes := httptest.NewRecorder()
	mux.ServeHTTP(badRes, bad)
	if badRes.Code != http.StatusBadRequest {
		t.Fatalf("expected oversized cursor to fail, got %d", badRes.Code)
	}
}

func TestAdminAccountAndTopologyRoutes(t *testing.T) {
	token := strings.Repeat("e", 32)
	server := testServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, tc := range []struct {
		path     string
		contains string
	}{
		{path: "/admin/api/v1/accounts", contains: `"username":"alice"`},
		{path: "/admin/api/v1/accounts/u1", contains: `"id":"u1"`},
		{path: "/admin/api/v1/topology", contains: `"scope":"global"`},
		{path: "/admin/api/v1/accounts/u1/topology", contains: `"scope":"account"`},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), tc.contains) {
			t.Fatalf("%s: unexpected response %d: %s", tc.path, res.Code, res.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/accounts/missing/topology", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("expected missing account topology to return 404, got %d", res.Code)
	}
}

func TestAdminTopologyPaginationValidation(t *testing.T) {
	token := strings.Repeat("f", 32)
	server := testServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, path := range []string{
		"/admin/api/v1/topology?limit=0",
		"/admin/api/v1/topology?limit=51",
		"/admin/api/v1/topology?node_limit=2001",
		"/admin/api/v1/topology?limit=12&node_limit=5",
		"/admin/api/v1/topology?cursor=" + strings.Repeat("x", 129),
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d: %s", path, res.Code, res.Body.String())
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/topology?limit=12&node_limit=600", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `"complete":true`) {
		t.Fatalf("unexpected topology page response %d: %s", res.Code, res.Body.String())
	}
}

func TestAdminConnectionsPassesSearchAndDirectionalFilters(t *testing.T) {
	token := strings.Repeat("q", 32)
	store := &connectionFilterStore{}
	server, err := New(store, Config{
		Token:        token,
		BuildVersion: "server-v1.2.3",
		BuildCommit:  "0123456789abcdef",
		StartedAt:    time.Now().Add(-90 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/connections?q=%20Alice%20Laptop%20&network_id=n1&reporting_device_id=d1&remote_device_id=d2&path=direct&freshness=fresh&limit=25&offset=0", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected connections response %d: %s", res.Code, res.Body.String())
	}
	if store.filter.Query != "Alice Laptop" || store.filter.NetworkID != "n1" || store.filter.ReportingDeviceID != "d1" || store.filter.RemoteDeviceID != "d2" || store.filter.Path != "direct" || store.filter.Freshness != "fresh" {
		t.Fatalf("unexpected connection filter: %+v", store.filter)
	}
}

func TestAdminPaginationRejectsOutOfRangeLimit(t *testing.T) {
	token := strings.Repeat("c", 32)
	server := testServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/devices?limit=201", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", res.Code)
	}
}

func TestRuntimeUsesBuildIdentity(t *testing.T) {
	token := strings.Repeat("d", 32)
	server := testServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/runtime", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res := httptest.NewRecorder()
	mux.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	body := res.Body.String()
	for _, expected := range []string{`"build_version":"server-v1.2.3"`, `"build_commit":"0123456789abcdef"`, `"admin_mode":"read-only"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("runtime response missing %s: %s", expected, body)
		}
	}
}
