package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yhan-sun/p2wlan/server/database"
)

func credentialRejected(err error) bool {
	return errors.Is(err, database.ErrInvalidDeviceCredential) || errors.Is(err, database.ErrRoomAccess)
}

// WriteAuthenticationUnavailable denies a request whose authentication state
// could not be read. It is a retryable outage, not proof of credential revocation
// or an obsolete registration. Never expose storage errors or token contents.
func WriteAuthenticationUnavailable(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", "2")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":      "authentication temporarily unavailable",
		"error_code": "authentication_unavailable",
	})
}

// RequireAnyAuth is middleware that accepts either a user JWT or a device credential.
func RequireAnyAuth(authService *Service, db interface {
	ValidateDeviceCredential(token string) (*database.DeviceCredential, *database.Device, error)
}) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenStr == authHeader {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			// Try device credential first
			cred, device, err := db.ValidateDeviceCredential(tokenStr)
			if err == nil {
				claims := &DeviceClaims{
					DeviceID:     device.ID,
					NetworkID:    device.NetworkID,
					UserID:       device.UserID,
					CredentialID: cred.ID,
					ExpiresAt:    cred.ExpiresAt,
				}
				ctx := context.WithValue(r.Context(), DeviceClaimsKey, claims)
				next(w, r.WithContext(ctx))
				return
			}

			// Fall back to user JWT without making it depend on device storage.
			credentialErr := err
			userClaims, err := authService.ValidateToken(tokenStr)
			if err == nil {
				ctx := context.WithValue(r.Context(), UserClaimsKey, userClaims)
				next(w, r.WithContext(ctx))
				return
			}

			if !credentialRejected(credentialErr) {
				WriteAuthenticationUnavailable(w)
				return
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		}
	}
}

// RequireDeviceAuth is middleware that requires a valid device credential token.
func RequireDeviceAuth(db interface {
	ValidateDeviceCredential(token string) (*database.DeviceCredential, *database.Device, error)
}) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"missing authorization header"}`, http.StatusUnauthorized)
				return
			}

			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
			if tokenStr == authHeader {
				http.Error(w, `{"error":"invalid authorization format"}`, http.StatusUnauthorized)
				return
			}

			cred, device, err := db.ValidateDeviceCredential(tokenStr)
			if err != nil {
				if !credentialRejected(err) {
					WriteAuthenticationUnavailable(w)
					return
				}
				http.Error(w, `{"error":"invalid device credential"}`, http.StatusUnauthorized)
				return
			}

			claims := &DeviceClaims{
				DeviceID:     device.ID,
				NetworkID:    device.NetworkID,
				UserID:       device.UserID,
				CredentialID: cred.ID,
				ExpiresAt:    cred.ExpiresAt,
			}

			ctx := context.WithValue(r.Context(), DeviceClaimsKey, claims)
			next(w, r.WithContext(ctx))
		}
	}
}
