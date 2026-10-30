package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

// SubmitPathTelemetry handles POST /api/v1/telemetry/paths.
func (s *Server) SubmitPathTelemetry(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"device authentication required"}`, http.StatusUnauthorized)
		return
	}

	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, signaling.MaxClientMessageBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, `{"error":"telemetry payload exceeds byte limit"}`, http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, `{"error":"invalid telemetry payload"}`, http.StatusBadRequest)
		}
		return
	}
	batch, err := decodePathTelemetryBatch(payload)
	if err != nil {
		http.Error(w, `{"error":"invalid telemetry payload"}`, http.StatusBadRequest)
		return
	}

	regSeq, _ := currentRequestRegistrationSequence(r)

	summary, err := s.db.RecordPathObservations(claims.DeviceID, claims.NetworkID, regSeq, batch.Observations, batch.IsResync)
	if err != nil {
		if writeRegistrationSessionConflict(w, err) {
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"total":     summary.Total,
		"accepted":  summary.Accepted,
		"duplicate": summary.Duplicate,
		"rejected":  summary.Rejected,
	})
}

// IngestPathTelemetryPayload processes an incoming JSON telemetry payload from the WebSocket channel.
func (s *Server) IngestPathTelemetryPayload(reportingDeviceID, networkID string, registrationSeq int64, payload []byte) (*database.PathTelemetryIngestSummary, error) {
	batch, err := decodePathTelemetryBatch(payload)
	if err != nil {
		return nil, err
	}
	return s.db.RecordPathObservations(reportingDeviceID, networkID, registrationSeq, batch.Observations, batch.IsResync)
}

// decodePathTelemetryBatch accepts the current Rust envelope and the original
// flat batch format. Authentication supplies the reporter/network/session;
// client-declared envelope IDs never establish authority.
func decodePathTelemetryBatch(payload []byte) (*database.PathTelemetryBatch, error) {
	if len(payload) > signaling.MaxClientMessageBytes {
		return nil, errors.New("path telemetry payload exceeds byte limit")
	}
	var envelope struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, err
	}
	if envelope.Payload != nil {
		if envelope.Type != "path_telemetry" {
			return nil, errors.New("invalid path telemetry envelope")
		}
		payload = envelope.Payload
	}
	var batch database.PathTelemetryBatch
	if err := json.Unmarshal(payload, &batch); err != nil {
		return nil, err
	}
	if batch.Observations == nil || len(batch.Observations) > database.MaxPathTelemetryBatchObservations || (batch.ProtocolVersion != 0 && batch.ProtocolVersion != signaling.ProtocolVersion) {
		return nil, errors.New("invalid path telemetry batch")
	}
	return &batch, nil
}
