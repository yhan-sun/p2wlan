package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/yhan-sun/p2wlan/server/database"
)

func parseOptionalAdminInt(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	return strconv.Atoi(raw)
}

// connectionHealth handles GET /admin/api/v1/connection-health.
func (s *Server) connectionHealth(w http.ResponseWriter, r *http.Request) {
	windowSeconds, err := parseOptionalAdminInt(r.URL.Query().Get("window_seconds"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid window_seconds"})
		return
	}
	limit, err := parseOptionalAdminInt(r.URL.Query().Get("limit"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid limit"})
		return
	}

	filter := database.AdminConnectionHealthFilter{
		NetworkID:     strings.TrimSpace(r.URL.Query().Get("network_id")),
		AccountID:     strings.TrimSpace(r.URL.Query().Get("account_id")),
		DeviceID:      strings.TrimSpace(r.URL.Query().Get("device_id")),
		WindowSeconds: windowSeconds,
		AlertLimit:    limit,
	}
	if filter.AccountID == "" {
		filter.AccountID = strings.TrimSpace(r.URL.Query().Get("user_id"))
	}

	value, err := s.store.AdminConnectionHealth(filter)
	if err != nil {
		switch {
		case errors.Is(err, database.ErrInvalidConnectionHealthWindow):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "window_seconds must be between 60 and 86400"})
		case errors.Is(err, database.ErrInvalidConnectionHealthLimit):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 100"})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query connection health"})
		}
		return
	}
	writeJSON(w, http.StatusOK, value)
}
