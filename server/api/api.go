// Package api provides the HTTP REST API for the control server.
package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

// Server handles API requests.
type Server struct {
	auth *auth.Service
	hub  *signaling.Hub
	db   *database.DB
}

// NewServer creates a new API server.
func NewServer(auth *auth.Service, hub *signaling.Hub, db *database.DB) *Server {
	return &Server{auth: auth, hub: hub, db: db}
}

// ---- Auth endpoints ----

// Login handles POST /api/v1/login.
func (s *Server) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	token, user, err := s.auth.Login(req.Email, req.Password)
	if err != nil {
		http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
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

// ---- Device endpoints ----

// RegisterDevice handles POST /api/v1/devices.
func (s *Server) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.GetClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		PublicKey  string `json:"public_key"`
		DeviceName string `json:"device_name"`
		Platform   string `json:"platform"`
		NetworkID  string `json:"network_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	device, err := s.db.CreateDevice(claims.UserID, req.NetworkID, req.PublicKey, req.DeviceName, req.Platform)
	if err != nil {
		http.Error(w, `{"error":"device registration failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"node_id":    device.ID,
		"virtual_ip": device.VirtualIP,
	})
}

// ListNodes handles GET /api/v1/nodes.
func (s *Server) ListNodes(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.GetClaims(r.Context())
	networkID := r.URL.Query().Get("network_id")
	if networkID == "" {
		networkID = "default"
	}

	_ = claims
	devices, err := s.db.ListDevicesByNetwork(networkID)
	if err != nil {
		http.Error(w, `{"error":"failed to list nodes"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"nodes": devices,
	})
}

// ListNetworks handles GET /api/v1/networks.
func (s *Server) ListNetworks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"networks": []map[string]interface{}{
			{"id": "default", "name": "Default Network", "cidr": "10.20.0.0/16"},
		},
	})
}

// UpdateDeviceEndpoint handles PATCH /api/v1/devices/{id}/endpoint.
func (s *Server) UpdateDeviceEndpoint(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if strings.TrimSpace(deviceID) == "" {
		http.Error(w, `{"error":"missing device id"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Endpoint string `json:"endpoint"`
		NATType  string `json:"nat_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.NATType = strings.TrimSpace(req.NATType)
	if req.Endpoint == "" {
		http.Error(w, `{"error":"endpoint is required"}`, http.StatusBadRequest)
		return
	}
	if req.NATType == "" {
		req.NATType = "unknown"
	}

	if err := s.db.UpdateDeviceEndpoint(deviceID, req.Endpoint, req.NATType); err != nil {
		http.Error(w, `{"error":"endpoint update failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// DeleteDevice handles DELETE /api/v1/devices/{id}.
func (s *Server) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceID := r.PathValue("id")
	if err := s.db.DeleteDevice(deviceID); err != nil {
		http.Error(w, `{"error":"delete failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ---- Signaling endpoints ----

// CreateSignal handles POST /api/v1/signals.
func (s *Server) CreateSignal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromNodeID string   `json:"from_node_id"`
		ToNodeID   string   `json:"to_node_id"`
		Type       string   `json:"type"`
		Candidates []string `json:"candidates"`
		Handshake  string   `json:"handshake"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.FromNodeID = strings.TrimSpace(req.FromNodeID)
	req.ToNodeID = strings.TrimSpace(req.ToNodeID)
	req.Type = strings.TrimSpace(req.Type)
	req.Handshake = strings.TrimSpace(req.Handshake)
	if req.FromNodeID == "" || req.ToNodeID == "" || req.Type == "" {
		http.Error(w, `{"error":"from_node_id, to_node_id, and type are required"}`, http.StatusBadRequest)
		return
	}
	if req.Type != "peer_offer" && req.Type != "peer_answer" {
		http.Error(w, `{"error":"unsupported signal type"}`, http.StatusBadRequest)
		return
	}

	signal, err := s.db.CreateSignal(req.FromNodeID, req.ToNodeID, req.Type, req.Candidates, req.Handshake)
	if err != nil {
		http.Error(w, `{"error":"signal creation failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "signal": signal})
}

// ListSignals handles GET /api/v1/signals.
func (s *Server) ListSignals(w http.ResponseWriter, r *http.Request) {
	nodeID := strings.TrimSpace(r.URL.Query().Get("node_id"))
	if nodeID == "" {
		http.Error(w, `{"error":"node_id is required"}`, http.StatusBadRequest)
		return
	}

	signals, err := s.db.ListAndDeleteSignals(nodeID)
	if err != nil {
		http.Error(w, `{"error":"failed to list signals"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"signals": signals})
}

// ---- Tunnel endpoints ----

// CreateTunnel handles POST /api/v1/tunnels.
func (s *Server) CreateTunnel(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.GetClaims(r.Context())

	var req struct {
		DeviceID   string `json:"device_id"`
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

	_ = claims
	tunnel, err := s.db.CreateTunnel(req.DeviceID, req.Protocol, req.LocalPort, req.RemotePort, req.LocalAddr)
	if err != nil {
		http.Error(w, `{"error":"tunnel creation failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":         true,
		"tunnel_id":       tunnel.ID,
		"public_endpoint": tunnel.PublicEndpoint,
	})
}

// ListTunnels handles GET /api/v1/tunnels.
func (s *Server) ListTunnels(w http.ResponseWriter, r *http.Request) {
	claims, _ := auth.GetClaims(r.Context())
	deviceID := r.URL.Query().Get("device_id")

	_ = claims
	tunnels, err := s.db.ListTunnelsByDevice(deviceID)
	if err != nil {
		http.Error(w, `{"error":"failed to list tunnels"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"tunnels": tunnels})
}

// DeleteTunnel handles DELETE /api/v1/tunnels/{id}.
func (s *Server) DeleteTunnel(w http.ResponseWriter, r *http.Request) {
	tunnelID := r.PathValue("id")
	if err := s.db.DeleteTunnel(tunnelID); err != nil {
		http.Error(w, `{"error":"delete failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ---- Helpers ----

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
