package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
)

// ---- Device endpoints ----

// RegisterDevice handles POST /api/v1/devices.
func (s *Server) RegisterDevice(w http.ResponseWriter, r *http.Request) {
	var req struct {
		PublicKey          string `json:"public_key"`
		DeviceName         string `json:"device_name"`
		Platform           string `json:"platform"`
		NetworkID          string `json:"network_id"`
		VirtualIP          string `json:"virtual_ip"`
		AppVersion         string `json:"app_version"`
		Ed25519PublicKey   string `json:"ed25519_public_key"`
		ChallengeID        string `json:"challenge_id"`
		ChallengeSignature string `json:"challenge_signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.PublicKey = strings.TrimSpace(req.PublicKey)
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	req.Platform = strings.TrimSpace(req.Platform)
	req.NetworkID = strings.TrimSpace(req.NetworkID)
	req.VirtualIP = strings.TrimSpace(req.VirtualIP)
	req.AppVersion = strings.TrimSpace(req.AppVersion)
	if req.NetworkID == "" {
		req.NetworkID = "default"
	}

	if req.PublicKey == "" {
		http.Error(w, `{"error":"public_key is required"}`, http.StatusBadRequest)
		return
	}
	if len(req.PublicKey) > 128 {
		http.Error(w, `{"error":"public_key too long"}`, http.StatusBadRequest)
		return
	}
	if req.DeviceName == "" {
		http.Error(w, `{"error":"device_name is required"}`, http.StatusBadRequest)
		return
	}
	if len(req.DeviceName) > 128 {
		http.Error(w, `{"error":"device_name too long"}`, http.StatusBadRequest)
		return
	}
	if len(req.NetworkID) > 64 {
		http.Error(w, `{"error":"network_id too long"}`, http.StatusBadRequest)
		return
	}
	if len(req.VirtualIP) > 64 {
		http.Error(w, `{"error":"virtual_ip too long"}`, http.StatusBadRequest)
		return
	}
	if len(req.AppVersion) > 64 {
		http.Error(w, `{"error":"app_version too long"}`, http.StatusBadRequest)
		return
	}

	userID := ""
	networkID := req.NetworkID
	deviceCredentialAuth := false

	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		deviceCredentialAuth = true
		device, err := s.db.GetDevice(deviceClaims.DeviceID)
		if err != nil {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
		if req.PublicKey != device.PublicKey {
			http.Error(w, `{"error":"device credential cannot register a different public key"}`, http.StatusForbidden)
			return
		}
		if req.NetworkID != deviceClaims.NetworkID {
			http.Error(w, `{"error":"device credential cannot change networks"}`, http.StatusForbidden)
			return
		}
		userID = deviceClaims.UserID
		networkID = deviceClaims.NetworkID
	} else if claims, err := auth.GetClaims(r.Context()); err == nil {
		userID = claims.UserID
		// Verify user has access to the network.
		hasAccess, err := s.db.UserHasNetworkAccess(userID, networkID)
		if err != nil {
			http.Error(w, `{"error":"network access check failed"}`, http.StatusInternalServerError)
			return
		}
		if !hasAccess {
			http.Error(w, `{"error":"user does not have access to this network"}`, http.StatusForbidden)
			return
		}
	} else {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	ed25519PubKey := strings.TrimSpace(req.Ed25519PublicKey)

	// If Ed25519 challenge is provided, verify it
	if req.ChallengeID != "" && req.ChallengeSignature != "" && ed25519PubKey != "" {
		existingDevice, err := s.db.GetDeviceByPublicKey(networkID, req.PublicKey)
		if err != nil || existingDevice.UserID != userID {
			http.Error(w, `{"error":"challenge verification failed"}`, http.StatusUnauthorized)
			return
		}
		if verifyChallenge(s.db, req.ChallengeID, existingDevice.ID, ed25519PubKey, req.ChallengeSignature) != nil {
			http.Error(w, `{"error":"challenge verification failed"}`, http.StatusUnauthorized)
			return
		}
	}

	device, err := s.db.CreateDeviceWithOptions(userID, networkID, req.PublicKey, req.DeviceName, req.Platform, ed25519PubKey, req.VirtualIP, req.AppVersion)
	if err != nil {
		writeDeviceMutationError(w, err, "device registration failed")
		return
	}

	var cidr string
	err = s.db.QueryRow(`SELECT cidr FROM networks WHERE id = ?`, networkID).Scan(&cidr)
	if err != nil {
		cidr = "10.20.0.0/16"
	}

	response := map[string]interface{}{
		"success":       true,
		"node_id":       device.ID,
		"virtual_ip":    device.VirtualIP,
		"cidr":          cidr,
		"relay_servers": s.relayServers,
	}

	// Include relay catalog for new clients that support it
	if s.relayCatalog != nil {
		response["relay_catalog"] = s.relayCatalog.Entries()
	}

	// Issue device credential if Ed25519 identity was verified
	if !deviceCredentialAuth && ed25519PubKey != "" && req.ChallengeID != "" && req.ChallengeSignature != "" {
		cred, token, err := s.db.CreateDeviceCredential(device.ID, 30*24*3600) // 30-day TTL
		if err == nil {
			response["device_credential"] = token
			response["credential_expires_at"] = cred.ExpiresAt
		}
	}

	writeJSON(w, http.StatusOK, response)
}

// ListNodes handles GET /api/v1/nodes.
func (s *Server) ListNodes(w http.ResponseWriter, r *http.Request) {
	// Try device claims first, then user claims
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		// Device credentials are used by the daemon to build its peer roster.
		// The current account-scoped product model keeps that roster private to
		// the account that owns the credential, even when the legacy `default`
		// network is shared by multiple accounts.
		devices, err := s.db.ListDevicesByUserAndNetwork(deviceClaims.UserID, deviceClaims.NetworkID)
		if err != nil {
			http.Error(w, `{"error":"failed to list nodes"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": devices})
		return
	}

	if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		networkID := strings.TrimSpace(r.URL.Query().Get("network_id"))
		if networkID == "" {
			http.Error(w, `{"error":"network_id is required"}`, http.StatusBadRequest)
			return
		}
		if len(networkID) > 64 {
			http.Error(w, `{"error":"network_id too long"}`, http.StatusBadRequest)
			return
		}
		hasAccess, err := s.db.UserHasNetworkAccess(userClaims.UserID, networkID)
		if err != nil {
			http.Error(w, `{"error":"failed to check network access"}`, http.StatusInternalServerError)
			return
		}
		if !hasAccess {
			http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
			return
		}
		devices, err := s.db.ListDevicesByUserAndNetwork(userClaims.UserID, networkID)
		if err != nil {
			http.Error(w, `{"error":"failed to list nodes"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": devices})
		return
	}

	http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
}

// ListNetworks handles GET /api/v1/networks.
func (s *Server) ListNetworks(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.GetClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	networks, err := s.db.GetUserNetworks(claims.UserID)
	if err != nil {
		http.Error(w, `{"error":"failed to list networks"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"networks": networks,
	})
}

// UpdateDeviceEndpoint handles PATCH /api/v1/devices/{id}/endpoint.
func (s *Server) UpdateDeviceEndpoint(w http.ResponseWriter, r *http.Request) {
	pathDeviceID := r.PathValue("id")
	if strings.TrimSpace(pathDeviceID) == "" {
		http.Error(w, `{"error":"missing device id"}`, http.StatusBadRequest)
		return
	}

	// Accept either device credential or user JWT
	authorized := false
	deviceAuthenticated := false
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		authorized = pathDeviceID == deviceClaims.DeviceID
		deviceAuthenticated = authorized
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		belongs, err := s.db.DeviceBelongsToUser(pathDeviceID, userClaims.UserID)
		authorized = err == nil && belongs
	}

	if !authorized {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		Endpoint   string `json:"endpoint"`
		NATType    string `json:"nat_type"`
		RelayRTTMS *int64 `json:"relay_rtt_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.Endpoint = strings.TrimSpace(req.Endpoint)
	req.NATType = strings.TrimSpace(req.NATType)
	if len(req.Endpoint) > 256 {
		http.Error(w, `{"error":"endpoint too long"}`, http.StatusBadRequest)
		return
	}
	if req.NATType == "" {
		req.NATType = "unknown"
	}
	if len(req.NATType) > 128 {
		http.Error(w, `{"error":"nat_type too long"}`, http.StatusBadRequest)
		return
	}
	if req.RelayRTTMS != nil && (*req.RelayRTTMS < 0 || *req.RelayRTTMS > 600000) {
		http.Error(w, `{"error":"relay_rtt_ms out of range"}`, http.StatusBadRequest)
		return
	}

	refreshLease := deviceAuthenticated
	if !deviceAuthenticated {
		hasActiveCredential, err := s.db.HasActiveDeviceCredential(pathDeviceID, time.Now().Unix())
		if err != nil {
			http.Error(w, `{"error":"device credential lookup failed"}`, http.StatusInternalServerError)
			return
		}
		// Preserve user-JWT heartbeat compatibility only for legacy devices
		// that do not yet have a usable device credential.
		refreshLease = !hasActiveCredential
	}
	var updateErr error
	if refreshLease {
		updateErr = s.db.UpdateDeviceEndpoint(pathDeviceID, req.Endpoint, req.NATType, req.RelayRTTMS)
	} else {
		updateErr = s.db.UpdateDeviceEndpointMetadata(pathDeviceID, req.Endpoint, req.NATType, req.RelayRTTMS)
	}
	if updateErr != nil {
		http.Error(w, `{"error":"endpoint update failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ReleaseDevicePresence handles POST /api/v1/devices/{id}/offline.
// A daemon may release only its own lease; an owning user JWT is retained for
// legacy clients that have not obtained a device credential yet.
func (s *Server) ReleaseDevicePresence(w http.ResponseWriter, r *http.Request) {
	pathDeviceID := strings.TrimSpace(r.PathValue("id"))
	if pathDeviceID == "" {
		http.Error(w, `{"error":"missing device id"}`, http.StatusBadRequest)
		return
	}

	authorized := false
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		authorized = pathDeviceID == deviceClaims.DeviceID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		belongs, err := s.db.DeviceBelongsToUser(pathDeviceID, userClaims.UserID)
		authorized = err == nil && belongs
	}
	if !authorized {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	if err := s.db.ReleaseDevicePresence(pathDeviceID); err != nil {
		http.Error(w, `{"error":"presence release failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// UpdateDevice handles PATCH /api/v1/devices/{id}.
func (s *Server) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	pathDeviceID := strings.TrimSpace(r.PathValue("id"))
	if pathDeviceID == "" {
		http.Error(w, `{"error":"missing device id"}`, http.StatusBadRequest)
		return
	}

	authorized := false
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		authorized = pathDeviceID == deviceClaims.DeviceID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		belongs, err := s.db.DeviceBelongsToUser(pathDeviceID, userClaims.UserID)
		authorized = err == nil && belongs
	}
	if !authorized {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		DeviceName string `json:"device_name"`
		VirtualIP  string `json:"virtual_ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	req.VirtualIP = strings.TrimSpace(req.VirtualIP)
	if req.DeviceName == "" && req.VirtualIP == "" {
		http.Error(w, `{"error":"device_name or virtual_ip is required"}`, http.StatusBadRequest)
		return
	}
	if req.DeviceName != "" && len([]rune(req.DeviceName)) > 128 {
		http.Error(w, `{"error":"device_name too long"}`, http.StatusBadRequest)
		return
	}
	if len(req.VirtualIP) > 64 {
		http.Error(w, `{"error":"virtual_ip too long"}`, http.StatusBadRequest)
		return
	}

	if req.DeviceName != "" {
		if err := s.db.UpdateDeviceName(pathDeviceID, req.DeviceName); err != nil {
			writeDeviceMutationError(w, err, "device update failed")
			return
		}
	}
	if req.VirtualIP != "" {
		if err := s.db.UpdateDeviceVirtualIP(pathDeviceID, req.VirtualIP); err != nil {
			writeDeviceMutationError(w, err, "virtual_ip update failed")
			return
		}
	}
	device, err := s.db.GetDevice(pathDeviceID)
	if err != nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "device": device, "device_name": device.DeviceName, "virtual_ip": device.VirtualIP})
}

func writeDeviceMutationError(w http.ResponseWriter, err error, fallback string) {
	message := strings.TrimSpace(err.Error())
	if message == "" {
		message = fallback
	}
	status := http.StatusInternalServerError
	if strings.Contains(message, "virtual_ip") || strings.Contains(message, "public key") || strings.Contains(message, "UNIQUE constraint") {
		status = http.StatusBadRequest
	}
	writeJSON(w, status, map[string]interface{}{"error": message})
}

// DeleteDevice handles DELETE /api/v1/devices/{id}.
func (s *Server) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	pathDeviceID := strings.TrimSpace(r.PathValue("id"))
	if pathDeviceID == "" {
		http.Error(w, `{"error":"missing device id"}`, http.StatusBadRequest)
		return
	}
	authorized := false
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		authorized = pathDeviceID == deviceClaims.DeviceID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		owned, err := s.db.DeviceBelongsToUser(pathDeviceID, userClaims.UserID)
		authorized = err == nil && owned
	}
	if !authorized {
		http.Error(w, `{"error":"device not found or access denied"}`, http.StatusForbidden)
		return
	}

	if err := s.db.DeleteDevice(pathDeviceID); err != nil {
		http.Error(w, `{"error":"delete failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}
