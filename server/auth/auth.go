// Package auth provides JWT-based authentication.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/yhan-sun/p2wlan/server/database"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrUnauthorized       = errors.New("unauthorized")
)

// Service provides authentication operations.
type Service struct {
	jwtSecret []byte
	db        *database.DB
}

// NewService creates a new auth service.
func NewService(secret string, db *database.DB) *Service {
	return &Service{
		jwtSecret: []byte(secret),
		db:        db,
	}
}

// Claims represents JWT claims.
type Claims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// Login authenticates a user and returns a JWT token.
func (s *Service) Login(email, password string) (string, *database.User, error) {
	user, err := s.db.GetUserByEmail(email)
	if err != nil {
		return "", nil, ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return "", nil, ErrInvalidCredentials
	}

	token, err := s.generateToken(user)
	if err != nil {
		return "", nil, err
	}

	return token, user, nil
}

// Register creates a new user account.
func (s *Service) Register(email, password string) (string, *database.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}

	user, err := s.db.CreateUser(email, string(hash))
	if err != nil {
		return "", nil, err
	}

	token, err := s.generateToken(user)
	if err != nil {
		return "", nil, err
	}

	return token, user, nil
}

// ValidateToken validates a JWT token and returns the claims.
func (s *Service) ValidateToken(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		return s.jwtSecret, nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// DeviceClaims represents device credential claims extracted from a device token.
type DeviceClaims struct {
	DeviceID     string `json:"device_id"`
	NetworkID    string `json:"network_id"`
	UserID       string `json:"user_id"`
	CredentialID string `json:"credential_id"`
	ExpiresAt    int64  `json:"expires_at"`
}

type contextKey string

func (k contextKey) String() string { return "auth." + string(k) }

const (
	UserClaimsKey   contextKey = "user_claims"
	DeviceClaimsKey contextKey = "device_claims"
)

// RequireAuth is middleware that requires a valid JWT token.
func (s *Service) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
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

		claims, err := s.ValidateToken(tokenStr)
		if err != nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), UserClaimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

// GetDeviceClaims extracts device claims from the request context.
func GetDeviceClaims(ctx context.Context) (*DeviceClaims, error) {
	claims, ok := ctx.Value(DeviceClaimsKey).(*DeviceClaims)
	if !ok {
		return nil, ErrUnauthorized
	}
	return claims, nil
}

// GetClaims extracts user claims from the request context.
func GetClaims(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(UserClaimsKey).(*Claims)
	if !ok {
		return nil, ErrUnauthorized
	}
	return claims, nil
}

func (s *Service) generateToken(user *database.User) (string, error) {
	claims := &Claims{
		UserID: user.ID,
		Email:  user.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)), // 7 days
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "p2pnet",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// GenerateNodeToken creates a device-specific token for WebSocket connections.
func GenerateNodeToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
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

			// Fall back to user JWT
			userClaims, err := authService.ValidateToken(tokenStr)
			if err == nil {
				ctx := context.WithValue(r.Context(), UserClaimsKey, userClaims)
				next(w, r.WithContext(ctx))
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