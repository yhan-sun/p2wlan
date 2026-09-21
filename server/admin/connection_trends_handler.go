package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yhan-sun/p2wlan/server/database"
)

// connectionTrends handles GET /admin/api/v1/connection-trends.
func (s *Server) connectionTrends(w http.ResponseWriter, r *http.Request) {
	windowHours, err := parseOptionalAdminInt(r.URL.Query().Get("window_hours"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid window_hours"})
		return
	}

	value, err := s.store.AdminConnectionTrends(database.AdminConnectionTrendsFilter{
		NetworkID:   strings.TrimSpace(r.URL.Query().Get("network_id")),
		WindowHours: windowHours,
	})
	if err != nil {
		if errors.Is(err, database.ErrInvalidConnectionTrendsWindow) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "window_hours must be between 1 and 720"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query connection trends"})
		return
	}

	writeJSON(w, http.StatusOK, value)
}
