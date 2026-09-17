package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yhan-sun/p2wlan/server/database"
)

type scaledFakeStore struct{ fakeStore }

func (scaledFakeStore) AdminAccountsCursor(_ string, cursor string, limit int) (*database.AdminAccountCursorPage, error) {
	if cursor == "bad" {
		return nil, database.ErrInvalidAdminCursor
	}
	return &database.AdminAccountCursorPage{
		Total:      2,
		Limit:      limit,
		SnapshotAt: 10,
		NextCursor: "next-account-page",
		Items:      []database.AdminAccountSummary{{ID: "u1", Username: "alice"}},
	}, nil
}

func (scaledFakeStore) AdminDevicesCursor(_, _, cursor string, limit int) (*database.AdminDeviceCursorPage, error) {
	if cursor == "bad" {
		return nil, database.ErrInvalidAdminCursor
	}
	return &database.AdminDeviceCursorPage{Total: 1, Limit: limit, SnapshotAt: 10, Items: []database.AdminDeviceSummary{{ID: "d1", DeviceName: "desktop"}}}, nil
}

func (scaledFakeStore) AdminNetworksCursor(cursor string, limit int) (*database.AdminNetworkCursorPage, error) {
	if cursor == "bad" {
		return nil, database.ErrInvalidAdminCursor
	}
	return &database.AdminNetworkCursorPage{Total: 1, Limit: limit, SnapshotAt: 10, Items: []database.AdminNetworkSummary{{ID: "n1", Name: "home"}}}, nil
}

func (scaledFakeStore) AdminRoomsCursor(cursor string, limit int) (*database.AdminRoomCursorPage, error) {
	if cursor == "bad" {
		return nil, database.ErrInvalidAdminCursor
	}
	return &database.AdminRoomCursorPage{Total: 1, Limit: limit, SnapshotAt: 10, Items: []database.AdminRoomSummary{{ID: "r1", Name: "friends"}}}, nil
}

func (scaledFakeStore) AdminTopologyPage(accountID, view, cursor string, _ int) (*database.AdminTopologyPage, error) {
	if cursor == "bad" {
		return nil, database.ErrInvalidAdminCursor
	}
	if view != "summary" && view != "full" {
		return nil, database.ErrInvalidAdminTopologyView
	}
	if accountID == "missing" {
		return nil, database.ErrAdminAccountNotFound
	}
	scope := "global"
	if accountID != "" {
		scope = "account"
	}
	return &database.AdminTopologyPage{
		GeneratedAt:              10,
		SnapshotAt:               9,
		Scope:                    scope,
		View:                     view,
		Phase:                    "accounts",
		FocusAccountID:           accountID,
		PathObservationAvailable: false,
		PathObservationNote:      "unavailable",
		Complete:                 true,
		Nodes:                    []database.AdminTopologyNode{{ID: "account:u1", Kind: "account", AccountID: "u1", Label: "alice"}},
		Edges:                    []database.AdminTopologyEdge{},
	}, nil
}

func scaledTestServer(t *testing.T, token string) *Server {
	t.Helper()
	server, err := New(scaledFakeStore{}, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestCursorAndTopologyPageHTTPContracts(t *testing.T) {
	token := strings.Repeat("z", 32)
	server := scaledTestServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, tc := range []struct {
		path     string
		contains string
	}{
		{path: "/admin/api/v1/accounts?pagination=cursor&limit=25", contains: `"next_cursor":"next-account-page"`},
		{path: "/admin/api/v1/devices?pagination=cursor&status=all&limit=25", contains: `"device_name":"desktop"`},
		{path: "/admin/api/v1/networks?pagination=cursor&limit=25", contains: `"name":"home"`},
		{path: "/admin/api/v1/rooms?pagination=cursor&limit=25", contains: `"name":"friends"`},
		{path: "/admin/api/v1/topology?view=summary&limit=50", contains: `"view":"summary"`},
		{path: "/admin/api/v1/accounts/u1/topology?view=full&limit=50", contains: `"scope":"account"`},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), tc.contains) {
			t.Fatalf("%s: unexpected response %d: %s", tc.path, res.Code, res.Body.String())
		}
	}
}

func TestScaledHTTPRejectsBadCursorAndLimit(t *testing.T) {
	token := strings.Repeat("y", 32)
	server := scaledTestServer(t, token)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	for _, path := range []string{
		"/admin/api/v1/accounts?pagination=cursor&cursor=bad",
		"/admin/api/v1/topology?view=summary&cursor=bad",
		"/admin/api/v1/devices?pagination=cursor&limit=201",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		res := httptest.NewRecorder()
		mux.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d: %s", path, res.Code, res.Body.String())
		}
	}
}
