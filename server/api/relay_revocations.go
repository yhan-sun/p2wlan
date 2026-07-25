package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

// RelayRevocations handles GET /api/v1/relay/revocations.
//
// This endpoint is relay-facing and uses a dedicated bearer token instead of
// user JWT or device credential auth. It returns a full snapshot so relays can
// safely retain the previous snapshot if polling fails.
func (s *Server) RelayRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	expected := strings.TrimSpace(s.relayRevocationFeedToken)
	if expected == "" {
		http.Error(w, `{"error":"revocation feed not configured"}`, http.StatusServiceUnavailable)
		return
	}
	if !validRelayRevocationFeedToken(r.Header.Get("Authorization"), expected) {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	snapshot, err := s.db.RelayRevocationSnapshot()
	if err != nil {
		http.Error(w, `{"error":"revocation feed unavailable"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, snapshot)
}

func validRelayRevocationFeedToken(authHeader, expected string) bool {
	authHeader = strings.TrimSpace(authHeader)
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return false
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) != len(expected) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}
