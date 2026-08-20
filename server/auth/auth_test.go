package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func signedUserToken(t *testing.T, secret, issuer string, method jwt.SigningMethod) string {
	t.Helper()
	claims := &Claims{
		UserID: "user-1",
		Email:  "user@example.com",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token, err := jwt.NewWithClaims(method, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func TestValidateTokenRequiresHS256AndExpectedIssuer(t *testing.T) {
	const secret = "test-secret"
	service := NewService(secret, nil)

	valid := signedUserToken(t, secret, "p2pnet", jwt.SigningMethodHS256)
	claims, err := service.ValidateToken(valid)
	if err != nil || claims.UserID != "user-1" {
		t.Fatalf("valid token rejected: claims=%+v err=%v", claims, err)
	}

	wrongMethod := signedUserToken(t, secret, "p2pnet", jwt.SigningMethodHS384)
	if _, err := service.ValidateToken(wrongMethod); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("HS384 token must be rejected, got %v", err)
	}

	wrongIssuer := signedUserToken(t, secret, "other-service", jwt.SigningMethodHS256)
	if _, err := service.ValidateToken(wrongIssuer); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong issuer token must be rejected, got %v", err)
	}

	missingIssuer := signedUserToken(t, secret, "", jwt.SigningMethodHS256)
	if _, err := service.ValidateToken(missingIssuer); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("missing issuer token must be rejected, got %v", err)
	}
}
