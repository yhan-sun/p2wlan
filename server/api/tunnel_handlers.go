package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

// ---- Tunnel endpoints ----

// CreateTunnel handles POST /api/v1/tunnels.
func (s *Server) CreateTunnel(w http.ResponseWriter, r *http.Request) {
	var deviceID string
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		deviceID = deviceClaims.DeviceID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		deviceID = strings.TrimSpace(r.URL.Query().Get("device_id"))
		if deviceID == "" {
			http.Error(w, `{"error":"device_id is required"}`, http.StatusBadRequest)
			return
		}
		belongs, err := s.db.DeviceBelongsToUser(deviceID, userClaims.UserID)
		if err != nil || !belongs {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
	} else {
		http.Error(w, `{"error":"device credential required"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Protocol   string `json:"protocol"`
		LocalPort  int    `json:"local_port"`
		RemotePort int    `json:"remote_port"`
		LocalAddr  string `json:"local_address"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	if req.LocalAddr == "" {
		req.LocalAddr = "127.0.0.1"
	}
	req.Protocol = strings.ToLower(strings.TrimSpace(req.Protocol))
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		http.Error(w, `{"error":"protocol must be tcp or udp"}`, http.StatusBadRequest)
		return
	}
	if req.LocalPort < 1 || req.LocalPort > 65535 || req.RemotePort < 0 || req.RemotePort > 65535 {
		http.Error(w, `{"error":"invalid port range"}`, http.StatusBadRequest)
		return
	}

	tunnel, err := s.db.CreateTunnel(deviceID, req.Protocol, req.LocalPort, req.RemotePort, req.LocalAddr)
	if err != nil {
		if errors.Is(err, database.ErrTunnelPortInUse) {
			http.Error(w, `{"error":"remote port already allocated"}`, http.StatusConflict)
			return
		}
		if errors.Is(err, database.ErrTunnelPortExhausted) {
			http.Error(w, `{"error":"remote port pool exhausted"}`, http.StatusServiceUnavailable)
			return
		}
		http.Error(w, `{"error":"tunnel creation failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"tunnel_id":       tunnel.ID,
		"remote_port":     tunnel.RemotePort,
		"public_endpoint": tunnel.PublicEndpoint,
	})
}

// ListTunnels handles GET /api/v1/tunnels.
func (s *Server) ListTunnels(w http.ResponseWriter, r *http.Request) {
	var deviceID string
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		deviceID = deviceClaims.DeviceID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		deviceID = strings.TrimSpace(r.URL.Query().Get("device_id"))
		if deviceID == "" {
			http.Error(w, `{"error":"device_id is required"}`, http.StatusBadRequest)
			return
		}
		belongs, err := s.db.DeviceBelongsToUser(deviceID, userClaims.UserID)
		if err != nil || !belongs {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
	} else {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	tunnels, err := s.db.ListTunnelsByDevice(deviceID)
	if err != nil {
		http.Error(w, `{"error":"failed to list tunnels"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"tunnels": tunnels})
}

// DeleteTunnel handles DELETE /api/v1/tunnels/{id}.
func (s *Server) DeleteTunnel(w http.ResponseWriter, r *http.Request) {
	deviceClaims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"device credential required"}`, http.StatusUnauthorized)
		return
	}

	tunnelID := r.PathValue("id")
	if tunnelID == "" {
		http.Error(w, `{"error":"missing tunnel id"}`, http.StatusBadRequest)
		return
	}

	tunnel, err := s.db.GetTunnel(tunnelID)
	if err != nil {
		http.Error(w, `{"error":"tunnel not found"}`, http.StatusNotFound)
		return
	}
	if tunnel.DeviceID != deviceClaims.DeviceID {
		http.Error(w, `{"error":"tunnel does not belong to this device"}`, http.StatusForbidden)
		return
	}

	if err := s.db.DeleteTunnel(tunnelID); err != nil {
		http.Error(w, `{"error":"delete failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}
