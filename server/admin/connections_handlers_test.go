package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminConnectionsHTTPHandlers(t *testing.T) {
	const validToken = "0123456789abcdef0123456789abcdef"
	server := testServer(t, validToken)
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	// 1. Unauthenticated request -> 401
	unauthReq := httptest.NewRequest(http.MethodGet, "/admin/api/v1/connections", nil)
	unauthRec := httptest.NewRecorder()
	mux.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", unauthRec.Code)
	}

	// 2. Authenticated request -> 200
	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/connections?path=direct&freshness=fresh", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var connPage struct {
		Total int                      `json:"total"`
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&connPage); err != nil {
		t.Fatalf("decode connections response failed: %v", err)
	}
	if connPage.Total != 1 || len(connPage.Items) != 1 {
		t.Fatalf("expected 1 connection item, got total=%d items=%d", connPage.Total, len(connPage.Items))
	}

	// 3. Transitions authenticated request -> 200
	transReq := httptest.NewRequest(http.MethodGet, "/admin/api/v1/connection-transitions?reporting_device=d1", nil)
	transReq.Header.Set("Authorization", "Bearer "+validToken)
	transRec := httptest.NewRecorder()
	mux.ServeHTTP(transRec, transReq)
	if transRec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", transRec.Code, transRec.Body.String())
	}

	var transPage struct {
		Items []map[string]interface{} `json:"items"`
	}
	if err := json.NewDecoder(transRec.Body).Decode(&transPage); err != nil {
		t.Fatalf("decode transitions response failed: %v", err)
	}
	if len(transPage.Items) != 1 {
		t.Fatalf("expected 1 transition item, got %d", len(transPage.Items))
	}
}

func TestAdminConnectionsDisabledConsole(t *testing.T) {
	// When token is empty, console is disabled -> 404
	server, err := New(nil, Config{Token: ""})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/connections", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when admin console is disabled, got %d", rec.Code)
	}
}
