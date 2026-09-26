package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yhan-sun/p2wlan/server/database"
)

func adminDeviceCursorHandlerFixture(t *testing.T) (*http.ServeMux, string) {
	t.Helper()
	db, err := database.New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id,email,password_hash,created_at,username) VALUES ('cursor-owner','cursor@example.test','secret-hash',1,'cursor-owner')`); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		id := fmt.Sprintf("d%d", i)
		if _, err := db.Exec(`INSERT INTO devices (id,user_id,network_id,public_key,device_name,platform,virtual_ip,nat_type,last_seen,online,created_at) VALUES (?,'cursor-owner','default',?,?,'linux',?,'unknown',?,1,1)`, id, "secret-key-"+id, "Desktop "+id, "ip-"+id, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	token := strings.Repeat("admin-only-", 4)
	server, err := New(db, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	return mux, token
}

func requestAdminDeviceCursor(mux *http.ServeMux, token string, params url.Values) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/admin/api/v1/devices/cursor?"+params.Encode(), nil)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	return response
}

func TestAdminDeviceCursorHTTPPagesAndOwnerLinks(t *testing.T) {
	mux, token := adminDeviceCursorHandlerFixture(t)
	params := url.Values{"q": {"Desktop"}, "status": {"online"}, "limit": {"2"}}
	first := requestAdminDeviceCursor(mux, token, params)
	if first.Code != http.StatusOK {
		t.Fatalf("first page: %d %s", first.Code, first.Body)
	}
	var page database.AdminDeviceCursorPage
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Total != 3 || page.Limit != 2 || len(page.Items) != 2 || page.NextCursor == "" || page.GeneratedAt <= 0 || page.Items[0].OwnerID != "cursor-owner" {
		t.Fatalf("unexpected cursor payload: %+v", page)
	}
	if first.Header().Get("Cache-Control") != "no-store" || !strings.Contains(first.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unsafe response headers: %v", first.Header())
	}
	for _, secret := range []string{token, "secret-hash", "secret-key-"} {
		if strings.Contains(first.Body.String(), secret) {
			t.Fatalf("cursor response leaked credential material")
		}
	}
	params.Set("cursor", page.NextCursor)
	second := requestAdminDeviceCursor(mux, token, params)
	page = database.AdminDeviceCursorPage{}
	if second.Code != http.StatusOK || json.Unmarshal(second.Body.Bytes(), &page) != nil {
		t.Fatalf("second page: %d %s", second.Code, second.Body)
	}
	if len(page.Items) != 1 || page.Items[0].ID != "d3" || page.NextCursor != "" {
		t.Fatalf("wrong next-page boundary: %+v", page)
	}
	// The old offset API remains available with the same schema plus owner_id.
	request := httptest.NewRequest(http.MethodGet, "/admin/api/v1/devices?limit=2&offset=1", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	legacy := httptest.NewRecorder()
	mux.ServeHTTP(legacy, request)
	var old database.AdminDevicePage
	if legacy.Code != http.StatusOK || json.Unmarshal(legacy.Body.Bytes(), &old) != nil || old.Offset != 1 || len(old.Items) != 2 || old.Items[0].OwnerID != "cursor-owner" {
		t.Fatalf("legacy device API changed: %d %s", legacy.Code, legacy.Body)
	}
}

func TestAdminDeviceCursorHTTPRejectsInvalidFiltersAndCursorReuse(t *testing.T) {
	mux, token := adminDeviceCursorHandlerFixture(t)
	first := requestAdminDeviceCursor(mux, token, url.Values{"q": {"Desktop"}, "limit": {"1"}})
	var page database.AdminDeviceCursorPage
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &page) != nil || page.NextCursor == "" {
		t.Fatalf("could not obtain cursor: %d %s", first.Code, first.Body)
	}
	for _, params := range []url.Values{
		{"limit": {"0"}}, {"limit": {"201"}}, {"limit": {"invalid"}}, {"status": {"maybe"}},
		{"cursor": {"invalid"}}, {"cursor": {strings.Repeat("x", database.MaxAdminDeviceCursorLength+1)}},
		{"cursor": {page.NextCursor}, "q": {"other"}},
		{"cursor": {page.NextCursor}, "q": {"Desktop"}, "status": {"online"}},
	} {
		response := requestAdminDeviceCursor(mux, token, params)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d %s", params.Encode(), response.Code, response.Body)
		}
	}
}

func TestAdminDeviceCursorDoesNotGrantAdminAuthority(t *testing.T) {
	mux, token := adminDeviceCursorHandlerFixture(t)
	first := requestAdminDeviceCursor(mux, token, url.Values{"limit": {"1"}})
	var page database.AdminDeviceCursorPage
	if first.Code != http.StatusOK || json.Unmarshal(first.Body.Bytes(), &page) != nil || page.NextCursor == "" {
		t.Fatalf("could not obtain cursor: %d %s", first.Code, first.Body)
	}
	for _, credential := range []string{"", "ordinary-user-jwt", "device-credential", page.NextCursor} {
		response := requestAdminDeviceCursor(mux, credential, url.Values{"cursor": {page.NextCursor}})
		if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "owner_id") {
			t.Fatalf("non-admin credential gained device access: %d %s", response.Code, response.Body)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		request := httptest.NewRequest(method, "/admin/api/v1/devices/cursor", nil)
		request.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Fatalf("write method %s accepted: %d", method, response.Code)
		}
	}
	disabled := http.NewServeMux()
	testServer(t, "").RegisterRoutes(disabled)
	if response := requestAdminDeviceCursor(disabled, token, nil); response.Code != http.StatusNotFound {
		t.Fatalf("disabled cursor route is discoverable: %d", response.Code)
	}
}

type failingAdminDeviceCursorStore struct{ fakeStore }

func (failingAdminDeviceCursorStore) AdminDevicesCursor(string, string, string, int) (*database.AdminDeviceCursorPage, error) {
	return nil, errors.New("private database failure")
}

func TestAdminDeviceCursorHTTPDatabaseFailure(t *testing.T) {
	token := strings.Repeat("a", 32)
	server, err := New(failingAdminDeviceCursorStore{}, Config{Token: token})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)
	response := requestAdminDeviceCursor(mux, token, nil)
	if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "private") {
		t.Fatalf("incorrect failure response: %d %s", response.Code, response.Body)
	}
}
