package admin

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/yhan-sun/p2wlan/server/database"
)

// connections handles GET /admin/api/v1/connections.
func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))

	filter := database.AdminConnectionFilter{
		Query:             strings.TrimSpace(r.URL.Query().Get("q")),
		NetworkID:         strings.TrimSpace(r.URL.Query().Get("network_id")),
		AccountID:         strings.TrimSpace(r.URL.Query().Get("account_id")),
		DeviceID:          strings.TrimSpace(r.URL.Query().Get("device_id")),
		ReportingDeviceID: strings.TrimSpace(r.URL.Query().Get("reporting_device_id")),
		RemoteDeviceID:    strings.TrimSpace(r.URL.Query().Get("remote_device_id")),
		Path:              strings.TrimSpace(r.URL.Query().Get("path")),
		Freshness:         strings.TrimSpace(r.URL.Query().Get("freshness")),
	}

	// Support user_id as an alias for account_id
	if filter.AccountID == "" {
		filter.AccountID = strings.TrimSpace(r.URL.Query().Get("user_id"))
	}

	page, err := s.store.AdminConnections(filter, limit, offset)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query connections"})
		return
	}

	writeJSON(w, http.StatusOK, page)
}

// connectionTransitions handles GET /admin/api/v1/connection-transitions.
func (s *Server) connectionTransitions(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))

	filter := database.AdminConnectionTransitionFilter{
		ReportingDeviceID: strings.TrimSpace(r.URL.Query().Get("reporting_device")),
		RemoteDeviceID:    strings.TrimSpace(r.URL.Query().Get("remote_device")),
		NetworkID:         strings.TrimSpace(r.URL.Query().Get("network")),
	}

	// Also allow underscore forms
	if filter.ReportingDeviceID == "" {
		filter.ReportingDeviceID = strings.TrimSpace(r.URL.Query().Get("reporting_device_id"))
	}
	if filter.RemoteDeviceID == "" {
		filter.RemoteDeviceID = strings.TrimSpace(r.URL.Query().Get("remote_device_id"))
	}
	if filter.NetworkID == "" {
		filter.NetworkID = strings.TrimSpace(r.URL.Query().Get("network_id"))
	}

	page, err := s.store.AdminConnectionTransitions(filter, limit, cursor)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to query connection transitions"})
		return
	}

	writeJSON(w, http.StatusOK, page)
}
