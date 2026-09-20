package api

import (
	"encoding/json"
	"net/http"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

// SubmitPathTelemetry handles POST /api/v1/telemetry/paths.
func (s *Server) SubmitPathTelemetry(w http.ResponseWriter, r *http.Request) {
	claims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		http.Error(w, `{"error":"device authentication required"}`, http.StatusUnauthorized)
		return
	}

	var batch database.PathTelemetryBatch
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
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
	var batch database.PathTelemetryBatch
	if err := json.Unmarshal(payload, &batch); err != nil {
		return nil, err
	}
	return s.db.RecordPathObservations(reportingDeviceID, networkID, registrationSeq, batch.Observations, batch.IsResync)
}
