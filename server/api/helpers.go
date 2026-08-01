package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// ---- Helpers ----

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func isValidEmail(email string) bool {
	if len(email) < 3 || len(email) > 255 {
		return false
	}
	if !strings.Contains(email, "@") {
		return false
	}
	return true
}

func isValidPassword(password string) bool {
	return len(password) >= 6
}
