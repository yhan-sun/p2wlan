package admin

import (
	"errors"
	"net/http"

	"github.com/yhan-sun/p2wlan/server/database"
)

func (s *Server) devicesCursor(w http.ResponseWriter, r *http.Request) {
	limit, err := parseBoundedInt(r.URL.Query().Get("limit"), 25, 1, 200)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 200"})
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if len(cursor) > database.MaxAdminDeviceCursorLength {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device cursor; restart pagination"})
		return
	}
	page, err := s.store.AdminDevicesCursor(r.URL.Query().Get("q"), r.URL.Query().Get("status"), cursor, limit)
	switch {
	case errors.Is(err, database.ErrInvalidAdminDeviceCursor):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid device cursor; restart pagination"})
	case errors.Is(err, database.ErrInvalidAdminDeviceStatus):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid status filter"})
	case err != nil:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "unable to load devices"})
	default:
		writeJSON(w, http.StatusOK, page)
	}
}
