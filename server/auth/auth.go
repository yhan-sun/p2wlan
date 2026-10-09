// Package auth provides JWT-based authentication.
package auth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
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

// Login authenticates a user by email or display username and returns a JWT token.
func (s *Service) Login(identifier, password string) (string, *database.User, error) {
	user, err := s.db.GetUserByLoginIdentifier(identifier)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, ErrInvalidCredentials
		}
		return "", nil, fmt.Errorf("read login account: %w", err)
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
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer("p2pnet"),
	)
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

	// RegistrationSequenceHeader is the current daemon registration session
	// proof.  It is deliberately a request header rather than NAT metadata so
	// every device-token control-plane operation can be fenced, including
	// operations that do not publish an endpoint.
	RegistrationSequenceHeader = "X-P2WLAN-Registration-Seq"
	// RegistrationLifecycleConflictCode is returned when a device credential is
	// valid but belongs to an older daemon registration session.
	RegistrationLifecycleConflictCode = "registration_lifecycle_conflict"
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

// RequireCurrentDeviceRegistrationSession fences device-token requests to the
// currently registered daemon process.  A device credential remains valid
// across daemon restarts so a dropped registration response cannot strand the
// daemon, but that alone must not let the old process keep renewing its lease,
// consume durable signals, or replace the new process's WebSocket.
//
// Rows with registration_incarnation = 0 predate the fencing protocol and
// intentionally retain their header-free compatibility path.  For every
// incarnation-aware row, the caller must supply exactly one canonical decimal
// X-P2WLAN-Registration-Seq header whose value is the current server sequence.
// User-JWT requests pass through unchanged.
func RequireCurrentDeviceRegistrationSession(db interface {
	GetDevice(deviceID string) (*database.Device, error)
}) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetDeviceClaims(r.Context())
			if err != nil {
				// This is a user-JWT request authenticated by RequireAnyAuth, or a
				// handler wired without device auth.  The session proof applies only
				// to the durable device credential flow.
				next(w, r)
				return
			}

			device, err := db.GetDevice(claims.DeviceID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					writeRegistrationLifecycleConflict(w, nil)
				} else {
					WriteAuthenticationUnavailable(w)
				}
				return
			}
			if device.RegistrationIncarnation <= 0 {
				next(w, r)
				return
			}

			if !hasCurrentRegistrationSequence(r, device.RegistrationSeq) {
				writeRegistrationLifecycleConflict(w, device)
				return
			}
			next(w, r)
		}
	}
}

func hasCurrentRegistrationSequence(r *http.Request, expected int64) bool {
	values := r.Header.Values(RegistrationSequenceHeader)
	if len(values) != 1 {
		return false
	}
	raw := values[0]
	// Reject whitespace, leading plus signs, leading zeroes, and non-decimal
	// forms.  This makes the proof deterministic through proxies and prevents
	// ambiguous duplicate-value handling.
	if raw == "" || strings.TrimSpace(raw) != raw {
		return false
	}
	sequence, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || sequence <= 0 || strconv.FormatInt(sequence, 10) != raw {
		return false
	}
	return sequence == expected
}

func writeRegistrationLifecycleConflict(w http.ResponseWriter, device *database.Device) {
	response := map[string]interface{}{
		"error":      "device registration session is no longer current",
		"error_code": RegistrationLifecycleConflictCode,
	}
	if device != nil {
		response["registration_seq"] = device.RegistrationSeq
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(response)
}
