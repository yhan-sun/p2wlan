package auth

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/yhan-sun/p2wlan/server/database"
)

func TestDummyLoginHashMatchesRegistrationCost(t *testing.T) {
	cost, err := bcrypt.Cost([]byte(dummyLoginPasswordHash))
	if err != nil || cost != bcrypt.DefaultCost {
		t.Fatalf("dummy bcrypt hash must match registration cost: cost=%d err=%v", cost, err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(dummyLoginPasswordHash), []byte("p2wlan-login-dummy-credential")); err != nil {
		t.Fatalf("dummy hash must perform a complete bcrypt comparison: %v", err)
	}
}

func TestLoginUnknownAccountAlwaysRejectsDummyPassword(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "login.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service := NewService("login-privacy-test-secret", db)
	if _, _, err := service.Register("existing@example.test", "existing-test-password"); err != nil {
		t.Fatal(err)
	}
	for _, identifier := range []string{"missing@example.test", "missing-user", "existing@example.test"} {
		t.Run(identifier, func(t *testing.T) {
			token, user, err := service.Login(identifier, "p2wlan-login-dummy-credential")
			if token != "" || user != nil || !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("incorrect credentials must not authenticate: token_present=%t user_present=%t err=%v", token != "", user != nil, err)
			}
		})
	}
	if token, user, err := service.Login("existing@example.test", "existing-test-password"); err != nil || token == "" || user == nil {
		t.Fatalf("valid credentials rejected: token_present=%t user_present=%t err=%v", token != "", user != nil, err)
	}
}

func TestLoginStorageFailureRemainsAnAvailabilityError(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "unavailable.db"))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService("login-privacy-test-secret", db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	token, user, err := service.Login("missing@example.test", "p2wlan-login-dummy-credential")
	if token != "" || user != nil || err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("storage failure must remain distinct from invalid credentials: token_present=%t user_present=%t err=%v", token != "", user != nil, err)
	}
}
