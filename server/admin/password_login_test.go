package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/yhan-sun/p2wlan/server/internal/admincredential"
)

func TestOperatorPasswordSessionAndLegacyToken(t *testing.T) {
	const password = "test operator 密码"
	hash, err := admincredential.EncodePassword([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	config := Config{Token: strings.Repeat("t", 48), Username: "ops", PasswordHash: hash}
	s, err := New(fakeStore{}, config)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	mux.HandleFunc("POST /admin/api/v1/session", s.Login)
	login := func(user, secret string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/v1/session", nil)
		req.SetBasicAuth(user, secret)
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		return out
	}
	for _, wrong := range [][2]string{{"guest", password}, {"ops", "incorrect"}} {
		if res := login(wrong[0], wrong[1]); res.Code != http.StatusUnauthorized {
			t.Fatalf("unexpected failed-login status %d", res.Code)
		}
	}
	reply := login("ops", password)
	if reply.Code != http.StatusOK || reply.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("login status %d", reply.Code)
	}
	var session struct {
		Token string `json:"access_token"`
	}
	if err := json.Unmarshal(reply.Body.Bytes(), &session); err != nil {
		t.Fatal(err)
	}
	if session.Token == "" || strings.Contains(reply.Body.String(), config.Token) || strings.Contains(reply.Body.String(), password) {
		t.Fatal("login must return only a scoped session")
	}
	for _, item := range []struct {
		bearer string
		want   int
	}{
		{session.Token, 200}, {config.Token, 200}, {password, 401}, {"ordinary-user-token", 401},
	} {
		req := httptest.NewRequest(http.MethodGet, "/admin/api/v1/runtime", nil)
		req.Header.Set("Authorization", "Bearer "+item.bearer)
		out := httptest.NewRecorder()
		mux.ServeHTTP(out, req)
		if out.Code != item.want {
			t.Fatalf("runtime status %d, want %d", out.Code, item.want)
		}
	}
	expired := jwt.RegisteredClaims{Subject: "ops", Audience: jwt.ClaimStrings{adminAudience}, ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute))}
	old, err := jwt.NewWithClaims(jwt.SigningMethodHS256, expired).SignedString(s.password.key[:])
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(fakeStore{}, config)
	if err != nil {
		t.Fatal(err)
	}
	if s.password.accepts(old) || restarted.password.accepts(session.Token) {
		t.Fatal("expired or previous-process session accepted")
	}
	for _, cfg := range []Config{{Token: config.Token}, {Username: "ops", PasswordHash: hash}} {
		server, err := New(fakeStore{}, cfg)
		if err != nil || server.PasswordLoginEnabled() {
			t.Fatal("unexpected password login configuration", err)
		}
	}
	for _, cfg := range []Config{{Token: config.Token, Username: "ops"}, {Token: config.Token, PasswordHash: hash}, {Token: config.Token, Username: "two\nlines", PasswordHash: hash}} {
		if _, err := New(fakeStore{}, cfg); err == nil {
			t.Fatal("invalid configured account accepted")
		}
	}
}
