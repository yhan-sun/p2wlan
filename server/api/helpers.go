package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// ---- Helpers ----

// writeJSON encodes `data` into a buffer BEFORE any byte is written, so an
// encode error can never leave a half-written 200 response, and logs every
// write error instead of silently dropping a failed response body (a signal
// batch whose body write failed must never be treated as delivered — the
// lease layer owns that guarantee, but the failure must be visible).
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	encoded, err := json.Marshal(data)
	if err != nil {
		log.Printf("writeJSON encode failed (status %d): %v", status, err)
		http.Error(w, `{"error":"response encoding failed"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(status)
	if _, err := w.Write(encoded); err != nil {
		log.Printf("writeJSON write failed (status %d, %d bytes): %v", status, len(encoded), err)
	}
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
