package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yhan-sun/p2wlan/server/database"
)

func assertAuthenticationUnavailable(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("temporary storage failure: HTTP %d, expected 503", response.Code)
	}
	var body struct {
		ErrorCode string `json:"error_code"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ErrorCode != "authentication_unavailable" || response.Header().Get("Retry-After") == "" {
		t.Fatal("temporary authentication failure must identify a retryable response")
	}
}

func TestDeviceAuthenticationStorageFailureIsRetryable(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService("availability-test-secret", db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	for name, middleware := range map[string]func(http.HandlerFunc) http.HandlerFunc{
		"device": RequireDeviceAuth(db),
		"dual":   RequireAnyAuth(service, db),
	} {
		t.Run(name, func(t *testing.T) {
			handler := middleware(func(http.ResponseWriter, *http.Request) {
				t.Fatal("unverified credential reached the protected handler")
			})
			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			req.Header.Set("Authorization", "Bearer dc-test-credential")
			response := httptest.NewRecorder()
			handler(response, req)
			assertAuthenticationUnavailable(t, response)
		})
	}

	// A valid account JWT needs no device lookup, even if that storage is
	// temporarily unavailable. Its protected handler still owns data access.
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request.Header.Set("Authorization", "Bearer "+signedUserToken(t, "availability-test-secret", "p2pnet", jwt.SigningMethodHS256))
	response := httptest.NewRecorder()
	RequireAnyAuth(service, db)(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("valid account JWT rejected: HTTP %d", response.Code)
	}
}

func TestRegistrationStorageFailureIsNotALifecycleConflict(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "registration.db"))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/protected", nil)
	request = request.WithContext(context.WithValue(request.Context(), DeviceClaimsKey, &DeviceClaims{DeviceID: "missing-device"}))
	handler := RequireCurrentDeviceRegistrationSession(db)(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unknown registration reached the protected handler")
	})
	missing := httptest.NewRecorder()
	handler(missing, request)
	if missing.Code != http.StatusConflict {
		t.Fatalf("missing device must still be fenced: HTTP %d", missing.Code)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	unavailable := httptest.NewRecorder()
	handler(unavailable, request)
	assertAuthenticationUnavailable(t, unavailable)
}
