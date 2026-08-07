package api

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

var signalLongPollFallbackInterval = 100 * time.Millisecond

const maxSignalCandidates = 96

// senderIdentityFingerprint is the sender's identity fingerprint bound to a
// queued signal row at send time.
//
// The WireGuard public key is the identity the receiver tracks (its
// fresh-prediction high-water is bound to the peer's public key): a queued
// signal from an OLD identity key must never enter the NEW identity's
// high-water space after the sender's key changed.  Devices without one fall
// back to the Ed25519 identity key so every signal still carries a sender
// identity the receiver can compare against the peer's current key.
func senderIdentityFingerprint(sender *database.Device) string {
	if sender == nil {
		return ""
	}
	if strings.TrimSpace(sender.PublicKey) != "" {
		return sender.PublicKey
	}
	return strings.TrimSpace(sender.Ed25519PublicKey)
}

func probeEphemeralTranscript(signalType, fromNodeID, toNodeID, sessionID, probeEphemeralPublicKey string, candidateGeneration, candidatesExpiresAtMS int64) []byte {
	var b strings.Builder
	b.WriteString("p2wlan signal probe ephemeral v1\n")
	b.WriteString("type=")
	b.WriteString(signalType)
	b.WriteByte('\n')
	b.WriteString("from=")
	b.WriteString(fromNodeID)
	b.WriteByte('\n')
	b.WriteString("to=")
	b.WriteString(toNodeID)
	b.WriteByte('\n')
	b.WriteString("session_id=")
	b.WriteString(sessionID)
	b.WriteByte('\n')
	b.WriteString("probe_ephemeral_public_key=")
	b.WriteString(strings.ToLower(probeEphemeralPublicKey))
	b.WriteByte('\n')
	b.WriteString("candidate_generation=")
	b.WriteString(strconv.FormatInt(candidateGeneration, 10))
	b.WriteByte('\n')
	b.WriteString("candidates_expires_at_ms=")
	b.WriteString(strconv.FormatInt(candidatesExpiresAtMS, 10))
	b.WriteByte('\n')
	return []byte(b.String())
}

func verifyProbeEphemeralSignature(sender *database.Device, signalType, fromNodeID, toNodeID, sessionID, probeEphemeralPublicKey, signatureHex string, candidateGeneration, candidatesExpiresAtMS int64) error {
	if strings.TrimSpace(probeEphemeralPublicKey) == "" {
		return nil
	}
	if strings.TrimSpace(sender.Ed25519PublicKey) == "" {
		return nil // legacy/unverified device identity; keep compatibility while rollout completes
	}
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("session_id required for signed probe ephemeral key")
	}
	if strings.TrimSpace(signatureHex) == "" {
		return fmt.Errorf("probe_ephemeral_signature required")
	}
	pubKey, err := hex.DecodeString(sender.Ed25519PublicKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("sender ed25519 public key invalid")
	}
	signature, err := hex.DecodeString(signatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("probe_ephemeral_signature must be 64-byte hex")
	}
	transcript := probeEphemeralTranscript(signalType, fromNodeID, toNodeID, sessionID, probeEphemeralPublicKey, candidateGeneration, candidatesExpiresAtMS)
	if !ed25519.Verify(ed25519.PublicKey(pubKey), transcript, signature) {
		return fmt.Errorf("probe_ephemeral_signature mismatch")
	}
	return nil
}

// ---- Signaling endpoints ----

// CreateSignal handles POST /api/v1/signals.
func (s *Server) CreateSignal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromNodeID              string            `json:"from_node_id"`
		ToNodeID                string            `json:"to_node_id"`
		Type                    string            `json:"type"`
		ProtocolVersion         int64             `json:"protocol_version"`
		Candidates              []string          `json:"candidates"`
		CandidateSources        map[string]string `json:"candidate_sources"`
		CandidateGeneration     int64             `json:"candidate_generation"`
		CandidatesExpiresAtMS   int64             `json:"candidates_expires_at_ms"`
		SessionID               string            `json:"session_id"`
		ProbeEphemeralPublicKey string            `json:"probe_ephemeral_public_key"`
		ProbeEphemeralSignature string            `json:"probe_ephemeral_signature"`
		Handshake               string            `json:"handshake"`
		PunchAtMS               int64             `json:"punch_at_ms"`
		// PunchAtServerMS echoes an already normalized server deadline from
		// an offer. It lets the answer join the same synchronized punch window
		// instead of scheduling a second one after the round trip.
		PunchAtServerMS int64 `json:"punch_at_server_ms"`
		ClientTimeMS    int64 `json:"client_time_ms"`
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
	if req.Type != "peer_offer" && req.Type != "peer_offer_fresh" && req.Type != "peer_answer" && req.Type != "peer_reflexive" {
		http.Error(w, `{"error":"unsupported signal type"}`, http.StatusBadRequest)
		return
	}
	protocolVersion := req.ProtocolVersion
	if protocolVersion == 0 {
		protocolVersion = database.SignalProtocolVersion
	}
	if protocolVersion != database.SignalProtocolVersion {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":                      "unsupported signal protocol_version",
			"error_code":                 "unsupported_signal_protocol_version",
			"supported_protocol_version": database.SignalProtocolVersion,
		})
		return
	}
	if len(req.ToNodeID) > 64 {
		http.Error(w, `{"error":"to_node_id too long"}`, http.StatusBadRequest)
		return
	}

	if len(req.Candidates) > maxSignalCandidates {
		http.Error(w, fmt.Sprintf(`{"error":"too many candidates (max %d)"}`, maxSignalCandidates), http.StatusBadRequest)
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
	req.SessionID = strings.TrimSpace(req.SessionID)
	if len(req.SessionID) > 128 {
		http.Error(w, `{"error":"session_id too long"}`, http.StatusBadRequest)
		return
	}
	req.ProbeEphemeralPublicKey = strings.TrimSpace(req.ProbeEphemeralPublicKey)
	if req.ProbeEphemeralPublicKey != "" {
		decoded, err := hex.DecodeString(req.ProbeEphemeralPublicKey)
		if err != nil || len(decoded) != 32 {
			http.Error(w, `{"error":"probe_ephemeral_public_key must be 32-byte hex"}`, http.StatusBadRequest)
			return
		}
	}
	req.ProbeEphemeralSignature = strings.TrimSpace(req.ProbeEphemeralSignature)
	if req.ProbeEphemeralSignature != "" {
		decoded, err := hex.DecodeString(req.ProbeEphemeralSignature)
		if err != nil || len(decoded) != ed25519.SignatureSize {
			http.Error(w, `{"error":"probe_ephemeral_signature must be 64-byte hex"}`, http.StatusBadRequest)
			return
		}
	}
	if len(req.Handshake) > 4096 {
		http.Error(w, `{"error":"handshake too long"}`, http.StatusBadRequest)
		return
	}
	// The handshake must be well-formed hex of a plausible WireGuard
	// handshake-initiation length when non-empty: a bad handshake must be
	// rejected at creation time instead of poisoning the receiver's poll
	// batch (the client skips malformed rows, but the server should not queue
	// garbage that a mixed-version fleet then has to survive).
	if req.Handshake != "" {
		trimmed := strings.TrimSpace(req.Handshake)
		if len(trimmed)%2 != 0 {
			http.Error(w, `{"error":"handshake must be even-length hex"}`, http.StatusBadRequest)
			return
		}
		if _, err := hex.DecodeString(trimmed); err != nil {
			http.Error(w, `{"error":"handshake must be valid hex"}`, http.StatusBadRequest)
			return
		}
		if len(trimmed) > 2*4096 {
			http.Error(w, `{"error":"handshake too long"}`, http.StatusBadRequest)
			return
		}
	}
	if req.PunchAtMS < 0 {
		http.Error(w, `{"error":"punch_at_ms must be non-negative"}`, http.StatusBadRequest)
		return
	}
	if req.ClientTimeMS < 0 {
		http.Error(w, `{"error":"client_time_ms must be non-negative"}`, http.StatusBadRequest)
		return
	}
	nowMS := time.Now().UnixMilli()
	if req.CandidateGeneration < 0 || req.CandidatesExpiresAtMS < 0 {
		http.Error(w, `{"error":"candidate metadata must be non-negative"}`, http.StatusBadRequest)
		return
	}
	candidatesExpiresAtMS := req.CandidatesExpiresAtMS
	if req.CandidatesExpiresAtMS > 0 {
		if req.ClientTimeMS <= 0 {
			http.Error(w, `{"error":"candidate expiry requires client_time_ms"}`, http.StatusBadRequest)
			return
		}
		candidateLifetimeMS := req.CandidatesExpiresAtMS - req.ClientTimeMS
		if candidateLifetimeMS <= 0 || candidateLifetimeMS > 2*60*1000 {
			http.Error(w, `{"error":"candidate lifetime outside allowed window"}`, http.StatusBadRequest)
			return
		}
		// Persist a server-clock deadline.  Candidate expiry must not depend on
		// the sender's wall clock, since a skewed clock would otherwise make a
		// newly sent candidate set look expired to a healthy peer.
		candidatesExpiresAtMS = nowMS + candidateLifetimeMS
	}
	normalizedPunchAtMS := req.PunchAtMS
	if req.PunchAtServerMS > 0 {
		if req.PunchAtServerMS < nowMS-10*60*1000 || req.PunchAtServerMS > nowMS+10*60*1000 {
			http.Error(w, `{"error":"punch_at_server_ms outside allowed window"}`, http.StatusBadRequest)
			return
		}
		normalizedPunchAtMS = req.PunchAtServerMS
	} else if req.PunchAtMS > 0 && req.ClientTimeMS > 0 {
		delayMS := req.PunchAtMS - req.ClientTimeMS
		if delayMS < 0 {
			delayMS = 0
		}
		if delayMS > 10*60*1000 {
			http.Error(w, `{"error":"punch delay outside allowed window"}`, http.StatusBadRequest)
			return
		}
		normalizedPunchAtMS = nowMS + delayMS
	} else if req.PunchAtMS > 0 {
		if req.PunchAtMS < nowMS-10*60*1000 || req.PunchAtMS > nowMS+10*60*1000 {
			http.Error(w, `{"error":"punch_at_ms outside allowed clock-skew window"}`, http.StatusBadRequest)
			return
		}
	}

	// Determine from_node_id and network_id from auth context
	fromNodeID := ""
	var networkID string
	var senderDevice *database.Device

	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		fromNodeID = deviceClaims.DeviceID
		networkID = deviceClaims.NetworkID
		device, err := s.db.GetDevice(fromNodeID)
		if err != nil {
			http.Error(w, `{"error":"device not found"}`, http.StatusNotFound)
			return
		}
		senderDevice = device
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
		senderDevice = device
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
	if err := verifyProbeEphemeralSignature(senderDevice, req.Type, fromNodeID, req.ToNodeID, req.SessionID, req.ProbeEphemeralPublicKey, req.ProbeEphemeralSignature, req.CandidateGeneration, req.CandidatesExpiresAtMS); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}

	signal, err := s.db.CreateSignalWithTraversalSession(fromNodeID, req.ToNodeID, req.Type, protocolVersion, req.Candidates, req.CandidateSources, req.Handshake, normalizedPunchAtMS, req.CandidateGeneration, candidatesExpiresAtMS, req.SessionID, req.ProbeEphemeralPublicKey, senderIdentityFingerprint(senderDevice))
	if err != nil {
		if errors.Is(err, database.ErrSignalQueueLimit) {
			// A clear degradable signal: the queue bound (pair rows/bytes,
			// global rows, or sender frequency) is exceeded.  The sender
			// falls back to a later retry instead of unbounded growth.
			writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
				"error":      err.Error(),
				"error_code": "signal_queue_limit",
				"retryable":  true,
			})
			return
		}
		http.Error(w, `{"error":"signal creation failed"}`, http.StatusInternalServerError)
		return
	}
	s.signalNotifier.notify(req.ToNodeID)
	if s.hub != nil {
		s.hub.Notify(req.ToNodeID)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "signal": signal, "protocol_version": database.SignalProtocolVersion, "server_time_ms": time.Now().UnixMilli()})
}

// ListSignals handles GET /api/v1/signals.
//
// Clients that opt into ACK mode (`ack=1`) receive a DELIVERY LEASE instead
// of a deletion: the rows are not removed at GET time, every signal carries
// its delivery token, and the batch carries a batch token plus the lease
// deadline.  The client must ACK the batch (or individual signals) once it
// has decoded and enqueued everything; an expired lease re-delivers the
// batch, so a client that dies mid-processing or a connection that breaks
// mid-body can never lose a signal.  Legacy clients (no `ack=1`) keep the
// delete-on-GET semantics, and they can never steal rows a lease-mode client
// already holds.
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

	ackMode := strings.TrimSpace(r.URL.Query().Get("ack")) == "1"
	waitMS := boundedSignalWaitMS(r)
	deadline := time.Now().Add(time.Duration(waitMS) * time.Millisecond)
	for {
		version := s.signalNotifier.version(nodeID)
		var signals []database.Signal
		var err error
		leaseExpiresAtMS := int64(0)
		if ackMode {
			signals, leaseExpiresAtMS, err = s.db.ListSignalsWithLease(nodeID)
		} else {
			signals, err = s.db.ListAndDeleteSignals(nodeID)
		}
		if err != nil {
			http.Error(w, `{"error":"failed to list signals"}`, http.StatusInternalServerError)
			return
		}
		if len(signals) > 0 || waitMS == 0 || !time.Now().Before(deadline) {
			response := map[string]interface{}{
				"signals":          signals,
				"protocol_version": database.SignalProtocolVersion,
				"server_time_ms":   time.Now().UnixMilli(),
			}
			if ackMode && len(signals) > 0 {
				// The batch token lets a client ACK the whole batch at once;
				// per-row delivery tokens remain the reliable path.
				entries := make([]struct{ ID, Token string }, 0, len(signals))
				for _, signal := range signals {
					entries = append(entries, struct{ ID, Token string }{signal.ID, signal.DeliveryToken})
				}
				response["delivery"] = map[string]interface{}{
					"batch_token":         database.BatchTokenFor(entries),
					"lease_expires_at_ms": leaseExpiresAtMS,
				}
			}
			writeJSON(w, http.StatusOK, response)
			return
		}

		wait := time.Until(deadline)
		if wait > signalLongPollFallbackInterval {
			wait = signalLongPollFallbackInterval
		}
		if wait <= 0 {
			writeJSON(w, http.StatusOK, map[string]interface{}{"signals": signals, "protocol_version": database.SignalProtocolVersion, "server_time_ms": time.Now().UnixMilli()})
			return
		}
		s.signalNotifier.wait(r.Context(), nodeID, version, wait)
		if r.Context().Err() != nil {
			return
		}
	}
}

// AckSignals handles POST /api/v1/signals/ack.
//
// Idempotent: deleting an already-ACKed signal is a no-op, and a repeated
// ACK of the same batch is harmless.  Each signal is only deleted when its
// delivery token still matches the token the client received, so a client can
// only ever confirm the delivery it actually got.  The optional batch token
// acknowledges a whole batch in one call (validated against the current
// lease state; on a changed batch the client retries per-row).
func (s *Server) AckSignals(w http.ResponseWriter, r *http.Request) {
	var nodeID string
	if deviceClaims, err := auth.GetDeviceClaims(r.Context()); err == nil {
		nodeID = deviceClaims.DeviceID
	} else if userClaims, err := auth.GetClaims(r.Context()); err == nil {
		nodeID = strings.TrimSpace(r.URL.Query().Get("node_id"))
		if nodeID == "" {
			http.Error(w, `{"error":"node_id is required"}`, http.StatusBadRequest)
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

	var req struct {
		Signals    []database.SignalAck `json:"signals"`
		BatchToken string               `json:"batch_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}
	if len(req.Signals) > database.MaxSignalBatch {
		http.Error(w, `{"error":"too many signal acks"}`, http.StatusBadRequest)
		return
	}
	for _, ack := range req.Signals {
		if strings.TrimSpace(ack.ID) == "" || strings.TrimSpace(ack.DeliveryToken) == "" {
			http.Error(w, `{"error":"each ack needs id and delivery_token"}`, http.StatusBadRequest)
			return
		}
	}

	deleted := int64(0)
	var err error
	if len(req.Signals) > 0 {
		deleted, err = s.db.AckSignals(nodeID, req.Signals)
	} else if strings.TrimSpace(req.BatchToken) != "" {
		deleted, err = s.db.AckSignalBatch(nodeID, req.BatchToken)
	}
	if err != nil {
		http.Error(w, `{"error":"failed to ack signals"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"success": true, "deleted": deleted})
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
