package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

// ---- Auth endpoints ----

// Login handles POST /api/v1/login.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email      string `json:"email"`
		Identifier string `json:"identifier"`
		Password   string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	identifier := strings.TrimSpace(req.Identifier)
	if identifier == "" {
		identifier = strings.TrimSpace(req.Email)
	}
	if isValidEmail(identifier) {
		identifier = strings.ToLower(identifier)
	}
	if !isValidLoginIdentifier(identifier) {
		http.Error(w, `{"error":"invalid email or username"}`, http.StatusBadRequest)
		return
	}
	if !isValidPassword(req.Password) {
		http.Error(w, `{"error":"invalid password"}`, http.StatusBadRequest)
		return
	}

	token, user, err := s.auth.Login(identifier, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
		} else {
			auth.WriteAuthenticationUnavailable(w)
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"token":   token,
		"user":    user,
	})
}

// Register handles POST /api/v1/register.
func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	req.Email = strings.ToLower(req.Email)
	if !isValidEmail(req.Email) {
		http.Error(w, `{"error":"invalid email"}`, http.StatusBadRequest)
		return
	}
	if !isValidPassword(req.Password) {
		http.Error(w, `{"error":"invalid password (min 6 characters)"}`, http.StatusBadRequest)
		return
	}

	token, user, err := s.auth.Register(req.Email, req.Password)
	if err != nil {
		http.Error(w, `{"error":"registration failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"token":   token,
		"user":    user,
	})
}

// Profile uses an account JWT; device credentials cannot edit an account.
func (s *Server) Profile(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodPatch {
		var req struct {
			Username string `json:"username"`
		}
		if !roomBody(w, r, &req) {
			return
		}
		user, err := s.db.UpdateUsername(actor, req.Username)
		if errors.Is(err, database.ErrInvalidUsername) {
			http.Error(w, `{"error":"invalid username"}`, 400)
			return
		}
		if err != nil {
			http.Error(w, `{"error":"profile update failed"}`, 500)
			return
		}
		writeJSON(w, 200, map[string]any{"user": user})
		return
	}
	user, err := s.db.GetUserByID(actor)
	if err != nil {
		http.Error(w, `{"error":"account not found"}`, 404)
		return
	}
	writeJSON(w, 200, map[string]any{"user": user})
}
