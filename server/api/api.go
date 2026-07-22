// Package api provides the HTTP REST API for the control server.
package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

var signalLongPollFallbackInterval = 100 * time.Millisecond

// Server handles API requests.
type Server struct {
	auth              *auth.Service
	hub               *signaling.Hub
	db                *database.DB
	relayServers      []string
	relayCatalog      *RelayCatalog
	relayTicketSigner *auth.RelayTicketSigner
	signalNotifier    *signalNotifier
}

// NewServer creates a new API server.
// Catalog and signer configuration errors are fatal in production mode
// (when RELAY_TICKET_SIGNER_KEY_FILE is set), but warnings in dev mode.
func NewServer(authService *auth.Service, hub *signaling.Hub, db *database.DB) *Server {
	catalog, catalogErr := LoadRelayCatalog()
	if catalogErr != nil {
		log.Printf("WARNING: failed to load relay catalog: %v", catalogErr)
		catalog = nil
	}

	signer, signerErr := auth.LoadSignerFromEnv()
	if signerErr != nil {
		// If a signer key file was explicitly configured, errors are fatal
		if os.Getenv("RELAY_TICKET_SIGNER_KEY_FILE") != "" || os.Getenv("RELAY_TICKET_SIGNER_JSON") != "" {
			log.Fatalf("FATAL: relay ticket signer configuration error: %v", signerErr)
		}
		log.Printf("WARNING: relay ticket signer not configured: %v", signerErr)
		signer = nil
	}

	// Fail fast: signer configured but no catalog
	if signer != nil && catalog == nil {
		log.Fatalf("FATAL: relay ticket signer is configured but no relay catalog is available. Set RELAY_CATALOG_JSON or RELAY_SERVERS.")
	}

	if signer != nil {
		log.Printf("Relay ticket signer active: kid=%s fingerprint=%s", signer.ActiveKid(), signer.Fingerprint())
	}

	return &Server{
		auth:              authService,
		hub:               hub,
		db:                db,
		relayServers:      parseRelayServers(),
		relayCatalog:      catalog,
		relayTicketSigner: signer,
		signalNotifier:    newSignalNotifier(),
	}
}

func parseRelayServers() []string {
	raw := strings.TrimSpace(os.Getenv("RELAY_SERVERS"))
	if raw == "" {
		return []string{}
	}
	servers := []string{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			servers = append(servers, part)
		}
	}
	return servers
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

	req.Email = strings.TrimSpace(req.Email)
	req.Email = strings.ToLower(req.Email)
	if !isValidEmail(req.Email) {
		http.Error(w, `{"error":"invalid email"}`, http.StatusBadRequest)
		return
	}
	if !isValidPassword(req.Password) {
		http.Error(w, `{"error":"invalid password"}`, http.StatusBadRequest)
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

	req.Email = strings.TrimSpace(req.Email)
	req.Email = strings.ToLower(req.Email)
	if !isValidEmail(req.Email) {
		http.Error(w, `{"error":"invalid email"}`, http.StatusBadRequest)
		return
	}
	if !isValidPassword(req.Password) {
		http.Error(w, `{"error":"invalid password (min 6 characters)"}`, http.StatusBadRequest)
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
	var req struct {
		PublicKey          string `json:"public_key"`
		DeviceName         string `json:"device_name"`
		Platform           string `json:"platform"`
		NetworkID          string `json:"network_id"`
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
	req.NetworkID = strings.TrimSpace(req.NetworkID)
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
		if verifyChallenge(s.db, req.ChallengeID, ed25519PubKey, req.ChallengeSignature) != nil {
			http.Error(w, `{"error":"challenge verification failed"}`, http.StatusUnauthorized)
			return
		}
	}

	device, err := s.db.CreateDevice(userID, networkID, req.PublicKey, req.DeviceName, req.Platform, ed25519PubKey)
	if err != nil {
		http.Error(w, `{"error":"device registration failed"}`, http.StatusInternalServerError)
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

// CreateChallenge handles POST /api/v1/challenges.
func (s *Server) CreateChallenge(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.GetClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.DeviceID = strings.TrimSpace(req.DeviceID)
	if req.DeviceID == "" {
		http.Error(w, `{"error":"device_id is required"}`, http.StatusBadRequest)
		return
	}

	// Verify the device belongs to the authenticated user
	belongs, err := s.db.DeviceBelongsToUser(req.DeviceID, claims.UserID)
	if err != nil {
		http.Error(w, `{"error":"device lookup failed"}`, http.StatusInternalServerError)
		return
	}
	if !belongs {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}

	// Generate 32-byte random challenge
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		http.Error(w, `{"error":"challenge generation failed"}`, http.StatusInternalServerError)
		return
	}

	expiresAt := time.Now().Add(5 * time.Minute).Unix()
	dc, err := s.db.CreateChallenge(req.DeviceID, challenge, expiresAt)
	if err != nil {
		http.Error(w, `{"error":"challenge creation failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"challenge_id": dc.ID,
		"challenge":    hex.EncodeToString(dc.Challenge),
		"expires_at":   dc.ExpiresAt,
	})
}

// SubmitDeviceCredential handles POST /api/v1/devices/credential.
func (s *Server) SubmitDeviceCredential(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.GetClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	var req struct {
		DeviceID           string `json:"device_id"`
		Ed25519PublicKey   string `json:"ed25519_public_key"`
		ChallengeID        string `json:"challenge_id"`
		ChallengeSignature string `json:"challenge_signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.Ed25519PublicKey = strings.TrimSpace(req.Ed25519PublicKey)
	req.ChallengeID = strings.TrimSpace(req.ChallengeID)
	req.ChallengeSignature = strings.TrimSpace(req.ChallengeSignature)

	if req.DeviceID == "" || req.Ed25519PublicKey == "" || req.ChallengeID == "" || req.ChallengeSignature == "" {
		http.Error(w, `{"error":"device_id, ed25519_public_key, challenge_id, and challenge_signature are required"}`, http.StatusBadRequest)
		return
	}

	// Verify the device belongs to the authenticated user
	belongs, err := s.db.DeviceBelongsToUser(req.DeviceID, claims.UserID)
	if err != nil {
		http.Error(w, `{"error":"device lookup failed"}`, http.StatusInternalServerError)
		return
	}
	if !belongs {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}

	// Verify the Ed25519 signature
	if err := verifyChallenge(s.db, req.ChallengeID, req.Ed25519PublicKey, req.ChallengeSignature); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	// Issue device credential with 30-day TTL
	cred, token, err := s.db.CreateDeviceCredential(req.DeviceID, 30*24*3600)
	if err != nil {
		http.Error(w, `{"error":"credential creation failed"}`, http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":           true,
		"device_credential": token,
		"credential_id":     cred.ID,
		"expires_at":        cred.ExpiresAt,
	})
}

// verifyChallenge checks the Ed25519 signature of a challenge.
func verifyChallenge(db *database.DB, challengeID, ed25519PubKeyHex, signatureHex string) error {
	challengeRecord, err := db.GetChallenge(challengeID)
	if err != nil {
		return fmt.Errorf("challenge not found: %w", err)
	}

	if challengeRecord.Consumed {
		return fmt.Errorf("challenge already consumed")
	}

	if time.Now().Unix() > challengeRecord.ExpiresAt {
		return fmt.Errorf("challenge expired")
	}

	// Mark consumed (one-time use; even if verification fails, don't replay)
	defer db.ConsumeChallenge(challengeID)

	pubKey, err := hex.DecodeString(ed25519PubKeyHex)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key")
	}

	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature")
	}

	if !ed25519.Verify(pubKey, challengeRecord.Challenge, sig) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

// ListNodes handles GET /api/v1/nodes.
func (s *Server) ListNodes(w http.ResponseWriter, r *http.Request) {
	// Try device claims first, then user claims
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		devices, err := s.db.ListDevicesByNetwork(deviceClaims.NetworkID)
		if err != nil {
			http.Error(w, `{"error":"failed to list nodes"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": devices})
		return
	}

	if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		networkID := r.URL.Query().Get("network_id")
		if networkID == "" {
			http.Error(w, `{"error":"network_id is required"}`, http.StatusBadRequest)
			return
		}
		if len(networkID) > 64 {
			http.Error(w, `{"error":"network_id too long"}`, http.StatusBadRequest)
			return
		}
		hasAccess, _ := s.db.UserHasNetworkAccess(userClaims.UserID, networkID)
		if !hasAccess {
			http.Error(w, `{"error":"access denied"}`, http.StatusForbidden)
			return
		}
		devices, err := s.db.ListDevicesByNetwork(networkID)
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
		Endpoint string `json:"endpoint"`
		NATType  string `json:"nat_type"`
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
	if len(req.NATType) > 64 {
		http.Error(w, `{"error":"nat_type too long"}`, http.StatusBadRequest)
		return
	}

	if err := s.db.UpdateDeviceEndpoint(pathDeviceID, req.Endpoint, req.NATType); err != nil {
		http.Error(w, `{"error":"endpoint update failed"}`, http.StatusInternalServerError)
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	req.DeviceName = strings.TrimSpace(req.DeviceName)
	if req.DeviceName == "" {
		http.Error(w, `{"error":"device_name is required"}`, http.StatusBadRequest)
		return
	}
	if len([]rune(req.DeviceName)) > 128 {
		http.Error(w, `{"error":"device_name too long"}`, http.StatusBadRequest)
		return
	}

	if err := s.db.UpdateDeviceName(pathDeviceID, req.DeviceName); err != nil {
		http.Error(w, `{"error":"device update failed"}`, http.StatusInternalServerError)
		return
	}
	device, err := s.db.GetDevice(pathDeviceID)
	if err != nil {
		http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "device": device})
}

// DeleteDevice handles DELETE /api/v1/devices/{id}.
func (s *Server) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	deviceClaims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	pathDeviceID := r.PathValue("id")
	if pathDeviceID != deviceClaims.DeviceID {
		http.Error(w, `{"error":"device mismatch"}`, http.StatusForbidden)
		return
	}

	if err := s.db.DeleteDevice(pathDeviceID); err != nil {
		http.Error(w, `{"error":"delete failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ---- Signaling endpoints ----

// CreateSignal handles POST /api/v1/signals.
func (s *Server) CreateSignal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromNodeID       string            `json:"from_node_id"`
		ToNodeID         string            `json:"to_node_id"`
		Type             string            `json:"type"`
		Candidates       []string          `json:"candidates"`
		CandidateSources map[string]string `json:"candidate_sources"`
		Handshake        string            `json:"handshake"`
		PunchAtMS        int64             `json:"punch_at_ms"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	req.ToNodeID = strings.TrimSpace(req.ToNodeID)
	req.Type = strings.TrimSpace(req.Type)
	if req.ToNodeID == "" || req.Type == "" {
		http.Error(w, `{"error":"to_node_id and type are required"}`, http.StatusBadRequest)
		return
	}
	if req.Type != "peer_offer" && req.Type != "peer_answer" && req.Type != "peer_reflexive" {
		http.Error(w, `{"error":"unsupported signal type"}`, http.StatusBadRequest)
		return
	}
	if len(req.ToNodeID) > 64 {
		http.Error(w, `{"error":"to_node_id too long"}`, http.StatusBadRequest)
		return
	}

	if len(req.Candidates) > 20 {
		http.Error(w, `{"error":"too many candidates (max 20)"}`, http.StatusBadRequest)
		return
	}
	if req.Type == "peer_reflexive" && len(req.Candidates) == 0 {
		http.Error(w, `{"error":"peer_reflexive requires an observed candidate"}`, http.StatusBadRequest)
		return
	}
	candidateSet := make(map[string]struct{}, len(req.Candidates))
	for i, c := range req.Candidates {
		if len(c) > 256 {
			http.Error(w, fmt.Sprintf(`{"error":"candidate %d too long"}`, i), http.StatusBadRequest)
			return
		}
		candidateSet[c] = struct{}{}
	}
	if len(req.CandidateSources) > len(req.Candidates) {
		http.Error(w, `{"error":"too many candidate sources"}`, http.StatusBadRequest)
		return
	}
	for endpoint, source := range req.CandidateSources {
		if len(endpoint) > 256 || len(source) > 64 {
			http.Error(w, `{"error":"candidate source too long"}`, http.StatusBadRequest)
			return
		}
		if _, ok := candidateSet[endpoint]; !ok {
			http.Error(w, `{"error":"candidate source references unknown candidate"}`, http.StatusBadRequest)
			return
		}
	}
	if len(req.Handshake) > 4096 {
		http.Error(w, `{"error":"handshake too long"}`, http.StatusBadRequest)
		return
	}
	if req.PunchAtMS < 0 {
		http.Error(w, `{"error":"punch_at_ms must be non-negative"}`, http.StatusBadRequest)
		return
	}
	if req.PunchAtMS > 0 {
		nowMS := time.Now().UnixMilli()
		if req.PunchAtMS < nowMS-10*60*1000 || req.PunchAtMS > nowMS+10*60*1000 {
			http.Error(w, `{"error":"punch_at_ms outside allowed clock-skew window"}`, http.StatusBadRequest)
			return
		}
	}

	// Determine from_node_id and network_id from auth context
	fromNodeID := ""
	var networkID string

	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		fromNodeID = deviceClaims.DeviceID
		networkID = deviceClaims.NetworkID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		// User JWT: from_node_id is provided by the client, validate it
		req.FromNodeID = strings.TrimSpace(req.FromNodeID)
		if req.FromNodeID == "" {
			http.Error(w, `{"error":"from_node_id is required"}`, http.StatusBadRequest)
			return
		}
		if len(req.FromNodeID) > 64 {
			http.Error(w, `{"error":"from_node_id too long"}`, http.StatusBadRequest)
			return
		}
		// Only accept IDs the user owns
		belongs, err := s.db.DeviceBelongsToUser(req.FromNodeID, userClaims.UserID)
		if err != nil || !belongs {
			http.Error(w, `{"error":"device not found or access denied"}`, http.StatusNotFound)
			return
		}
		fromNodeID = req.FromNodeID
		device, err := s.db.GetDevice(fromNodeID)
		if err != nil {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
		networkID = device.NetworkID
	} else {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Verify target device exists in the same network
	targetDevice, err := s.db.GetDevice(req.ToNodeID)
	if err != nil {
		http.Error(w, `{"error":"target device not found"}`, http.StatusNotFound)
		return
	}
	if targetDevice.NetworkID != networkID {
		http.Error(w, `{"error":"target device is in a different network"}`, http.StatusForbidden)
		return
	}

	signal, err := s.db.CreateSignalWithPunchAt(fromNodeID, req.ToNodeID, req.Type, req.Candidates, req.CandidateSources, req.Handshake, req.PunchAtMS)
	if err != nil {
		http.Error(w, `{"error":"signal creation failed"}`, http.StatusInternalServerError)
		return
	}
	s.signalNotifier.notify(req.ToNodeID)

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "signal": signal})
}

// ListSignals handles GET /api/v1/signals.
func (s *Server) ListSignals(w http.ResponseWriter, r *http.Request) {
	var nodeID string

	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		nodeID = deviceClaims.DeviceID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		nodeID = strings.TrimSpace(r.URL.Query().Get("node_id"))
		if nodeID == "" {
			http.Error(w, `{"error":"node_id is required"}`, http.StatusBadRequest)
			return
		}
		if len(nodeID) > 64 {
			http.Error(w, `{"error":"node_id too long"}`, http.StatusBadRequest)
			return
		}
		belongs, err := s.db.DeviceBelongsToUser(nodeID, userClaims.UserID)
		if err != nil || !belongs {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
	} else {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	waitMS := boundedSignalWaitMS(r)
	deadline := time.Now().Add(time.Duration(waitMS) * time.Millisecond)
	for {
		version := s.signalNotifier.version(nodeID)
		signals, err := s.db.ListAndDeleteSignals(nodeID)
		if err != nil {
			http.Error(w, `{"error":"failed to list signals"}`, http.StatusInternalServerError)
			return
		}
		if len(signals) > 0 || waitMS == 0 || !time.Now().Before(deadline) {
			writeJSON(w, http.StatusOK, map[string]interface{}{"signals": signals})
			return
		}

		wait := time.Until(deadline)
		if wait > signalLongPollFallbackInterval {
			wait = signalLongPollFallbackInterval
		}
		if wait <= 0 {
			writeJSON(w, http.StatusOK, map[string]interface{}{"signals": signals})
			return
		}
		s.signalNotifier.wait(r.Context(), nodeID, version, wait)
		if r.Context().Err() != nil {
			return
		}
	}
}

func boundedSignalWaitMS(r *http.Request) int {
	raw := strings.TrimSpace(r.URL.Query().Get("wait_ms"))
	if raw == "" {
		return 0
	}
	waitMS, err := strconv.Atoi(raw)
	if err != nil || waitMS <= 0 {
		return 0
	}
	if waitMS > 1000 {
		return 1000
	}
	return waitMS
}

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

// ---- Helpers ----

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
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
