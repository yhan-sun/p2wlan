package api

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/yhan-sun/p2wlan/server/database"
	"net/http"
	"strconv"
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

	w.Header().Set("Cache-Control", "no-store")
	if protocol := r.URL.Query().Get("protocol"); protocol != "" {
		if protocol != "2" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported revocation protocol"})
			return
		}
		parseCursor := func(name string) (int64, error) {
			values, exists := r.URL.Query()[name]
			if !exists {
				return 0, nil
			}
			if len(values) != 1 {
				return 0, fmt.Errorf("duplicate cursor")
			}
			value, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil || value < 0 || strconv.FormatInt(value, 10) != values[0] {
				return 0, fmt.Errorf("invalid cursor")
			}
			return value, nil
		}
		after, err := parseCursor("after")
		through, throughErr := parseCursor("through")
		if err != nil || throughErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid revocation cursor"})
			return
		}
		page, err := s.db.RelayRevocationPage(after, through)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, database.ErrRevocationCursor) {
				status = http.StatusConflict
			}
			writeJSON(w, status, map[string]any{"error": "revocation feed unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, page)
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
