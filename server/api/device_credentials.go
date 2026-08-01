package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

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
	if err := s.db.UpdateDeviceEd25519PublicKey(req.DeviceID, req.Ed25519PublicKey); err != nil {
		http.Error(w, `{"error":"device identity update failed"}`, http.StatusInternalServerError)
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

// RevokeCurrentDeviceCredential handles DELETE /api/v1/devices/credential.
func (s *Server) RevokeCurrentDeviceCredential(w http.ResponseWriter, r *http.Request) {
	deviceClaims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"device credential required"}`, http.StatusUnauthorized)
		return
	}
	if err := s.db.RevokeDeviceCredential(deviceClaims.CredentialID); err != nil {
		http.Error(w, `{"error":"credential revocation failed"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true})
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
