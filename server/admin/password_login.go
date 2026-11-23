package admin

import (
	"crypto/rand"
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yhan-sun/p2wlan/server/internal/admincredential"
	"golang.org/x/crypto/bcrypt"
)

const adminAudience = "p2wlan-admin-console"
const adminSessionLifetime = time.Hour

type passwordLogin struct {
	username string
	hash     []byte
	key      [32]byte
	checks   chan struct{}
}

func newPasswordLogin(username, encoded string) (*passwordLogin, error) {
	if username == "" && encoded == "" {
		return nil, nil
	}
	if !admincredential.ValidUsername(username) {
		return nil, errors.New("invalid CONTROL_ADMIN_USERNAME")
	}
	hash, err := admincredential.DecodeHash(encoded)
	if err != nil {
		return nil, err
	}
	login := &passwordLogin{username: username, hash: hash, checks: make(chan struct{}, 2)}
	if _, err := rand.Read(login.key[:]); err != nil {
		return nil, err
	}
	return login, nil
}

func (s *Server) PasswordLoginEnabled() bool {
	return s.enabled && s.password != nil
}

func (s *Server) loginMethods(w http.ResponseWriter, _ *http.Request) {
	setBrowserSecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]bool{"password": s.PasswordLoginEnabled()})
}

func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	setBrowserSecurityHeaders(w)
	w.Header().Set("Cache-Control", "no-store")
	if !s.PasswordLoginEnabled() {
		http.NotFound(w, r)
		return
	}
	username, password, ok := r.BasicAuth()
	if !ok || len(username) > 64 || len(password) == 0 || len(password) > 72 {
		s.writeUnauthorized(w)
		return
	}
	login := s.password
	select {
	case login.checks <- struct{}{}:
		defer func() { <-login.checks }()
	default:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many login attempts"})
		return
	}
	if err := bcrypt.CompareHashAndPassword(login.hash, []byte(password)); err != nil || username != login.username {
		s.writeUnauthorized(w)
		return
	}
	claims := jwt.RegisteredClaims{
		Subject: login.username, Audience: jwt.ClaimStrings{adminAudience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(adminSessionLifetime)),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(login.key[:])
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to start admin session"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"access_token": token})
}

func (l *passwordLogin) accepts(token string) bool {
	if l == nil || len(token) > 1024 {
		return false
	}
	_, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(*jwt.Token) (any, error) {
		return l.key[:], nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithAudience(adminAudience), jwt.WithSubject(l.username), jwt.WithExpirationRequired())
	return err == nil
}
