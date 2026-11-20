package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func (s *Server) RegisterWakeRoutes(mux *http.ServeMux) {
	user := s.auth.RequireAuth
	device := func(handler http.HandlerFunc) http.HandlerFunc {
		return auth.RequireDeviceAuth(s.db)(s.RequireCurrentDeviceRegistrationSession(handler))
	}
	any := func(handler http.HandlerFunc) http.HandlerFunc {
		return auth.RequireAnyAuth(s.auth, s.db)(s.RequireCurrentDeviceRegistrationSession(handler))
	}

	mux.HandleFunc("PUT /api/v1/devices/{id}/wake", device(s.setDeviceWakeTarget))
	mux.HandleFunc("DELETE /api/v1/devices/{id}/wake", device(s.setDeviceWakeTarget))
	mux.HandleFunc("GET /api/v1/devices/{id}/wake", user(s.wakeTargetStatus))
	mux.HandleFunc("POST /api/v1/devices/{id}/wake", user(s.triggerWake))
	mux.HandleFunc("GET /api/v1/networks/{network}/wake-targets", user(s.listManualWakeTargets))
	mux.HandleFunc("POST /api/v1/networks/{network}/wake-targets", user(s.createManualWakeTarget))
	mux.HandleFunc("PATCH /api/v1/wake-targets/{target}", user(s.changeManualWakeTarget))
	mux.HandleFunc("DELETE /api/v1/wake-targets/{target}", user(s.changeManualWakeTarget))
	mux.HandleFunc("GET /api/v1/wake-targets/{target}/wake", user(s.wakeTargetStatus))
	mux.HandleFunc("POST /api/v1/wake-targets/{target}/wake", user(s.triggerWake))
	mux.HandleFunc("GET /api/v1/wake/jobs/{job}", any(s.getWakeJob))
	mux.HandleFunc("GET /api/v1/wake/jobs", device(s.listWakeJobs))
	mux.HandleFunc("POST /api/v1/wake/jobs/{job}/claim", device(s.claimWakeJob))
	mux.HandleFunc("POST /api/v1/wake/jobs/{job}/result", device(s.finishWakeJob))
}

func wakeError(w http.ResponseWriter, err error) {
	if writeRegistrationSessionConflict(w, err) {
		return
	}
	var typed *database.WakeError
	if !errors.As(err, &typed) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "wake operation failed", "error_code": "wake_internal"})
		return
	}
	status := http.StatusConflict
	switch typed.Code {
	case "wake_invalid":
		status = http.StatusBadRequest
	case "wake_not_found":
		status = http.StatusNotFound
	case "wake_device_credential_required":
		status = http.StatusUnauthorized
	case "wake_forbidden", "target_blocked", "wake_proxy_required":
		status = http.StatusForbidden
	case "wake_rate_limited":
		status = http.StatusTooManyRequests
		w.Header().Set("Retry-After", "60")
	}
	body := map[string]any{"error": "wake operation rejected", "error_code": typed.Code}
	if typed.Agents != nil {
		body["agents"] = typed.Agents
	}
	writeJSON(w, status, body)
}

func wakeReadJSON(w http.ResponseWriter, r *http.Request, value any, optional bool) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(value)
	if optional && err == io.EOF {
		return true
	}
	if err != nil || decoder.Decode(&struct{}{}) != io.EOF {
		wakeError(w, &database.WakeError{Code: "wake_invalid"})
		return false
	}
	return true
}

func wakeSession(w http.ResponseWriter, r *http.Request) (database.WakeDeviceSession, bool) {
	w.Header().Set("Cache-Control", "no-store")
	claims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		wakeError(w, &database.WakeError{Code: "wake_device_credential_required"})
		return database.WakeDeviceSession{}, false
	}
	sequence, _ := currentRequestRegistrationSequence(r)
	return database.WakeDeviceSession{DeviceID: claims.DeviceID, CredentialID: claims.CredentialID, RegistrationSeq: sequence}, true
}

func wakeRef(r *http.Request) database.WakeTargetRef {
	return database.WakeTargetRef{DeviceID: r.PathValue("id"), TargetID: r.PathValue("target")}
}

func (s *Server) setDeviceWakeTarget(w http.ResponseWriter, r *http.Request) {
	session, ok := wakeSession(w, r)
	if !ok {
		return
	}
	if session.DeviceID != r.PathValue("id") {
		wakeError(w, &database.WakeError{Code: "wake_forbidden"})
		return
	}
	var input struct {
		MAC string `json:"mac"`
		NIC string `json:"nic"`
	}
	remove := r.Method == http.MethodDelete
	if !remove && !wakeReadJSON(w, r, &input, false) {
		return
	}
	if err := s.db.SetDeviceWakeTarget(session, input.MAC, input.NIC, remove); err != nil {
		wakeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) wakeTargetStatus(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	status, err := s.db.WakeTargetStatus(actor, wakeRef(r))
	wakeResponse(w, http.StatusOK, status, err)
}

func (s *Server) triggerWake(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var input struct {
		AgentID string `json:"agent_device_id"`
	}
	if !wakeReadJSON(w, r, &input, true) {
		return
	}
	job, err := s.db.EnqueueWakeJob(actor, wakeRef(r), input.AgentID)
	wakeResponse(w, http.StatusAccepted, job, err)
}

func (s *Server) listManualWakeTargets(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	targets, err := s.db.ListManualWakeTargets(actor, r.PathValue("network"))
	wakeResponse(w, http.StatusOK, map[string]any{"targets": targets}, err)
}

func (s *Server) createManualWakeTarget(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var input database.ManualWakeTargetInput
	if !wakeReadJSON(w, r, &input, false) {
		return
	}
	target, err := s.db.CreateManualWakeTarget(actor, r.PathValue("network"), input)
	wakeResponse(w, http.StatusCreated, target, err)
}

func (s *Server) changeManualWakeTarget(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var input database.ManualWakeTargetInput
	remove := r.Method == http.MethodDelete
	if !remove && !wakeReadJSON(w, r, &input, false) {
		return
	}
	target, err := s.db.ChangeManualWakeTarget(actor, r.PathValue("target"), input, remove)
	if remove && err == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	wakeResponse(w, http.StatusOK, target, err)
}

func (s *Server) getWakeJob(w http.ResponseWriter, r *http.Request) {
	if _, err := auth.GetDeviceClaims(r.Context()); err == nil {
		session, ok := wakeSession(w, r)
		if !ok {
			return
		}
		job, err := s.db.GetWakeJob("", r.PathValue("job"), &session)
		wakeResponse(w, http.StatusOK, job, err)
		return
	}
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	job, err := s.db.GetWakeJob(actor, r.PathValue("job"), nil)
	wakeResponse(w, http.StatusOK, job, err)
}

func (s *Server) listWakeJobs(w http.ResponseWriter, r *http.Request) {
	session, ok := wakeSession(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	limit := 4
	var err error
	if query.Get("limit") != "" {
		limit, err = strconv.Atoi(query.Get("limit"))
	}
	if state := query.Get("state"); (state != "" && state != "queued") || err != nil {
		wakeError(w, &database.WakeError{Code: "wake_invalid"})
		return
	}
	jobs, err := s.db.ListWakeJobs(session, limit)
	wakeResponse(w, http.StatusOK, map[string]any{"jobs": jobs}, err)
}

func (s *Server) claimWakeJob(w http.ResponseWriter, r *http.Request) {
	session, ok := wakeSession(w, r)
	if !ok {
		return
	}
	claim, err := s.db.ClaimWakeJob(session, r.PathValue("job"))
	wakeResponse(w, http.StatusOK, claim, err)
}

func (s *Server) finishWakeJob(w http.ResponseWriter, r *http.Request) {
	session, ok := wakeSession(w, r)
	if !ok {
		return
	}
	var input struct {
		ClaimToken string `json:"claim_token"`
		State      string `json:"state"`
		Reason     string `json:"reason"`
	}
	if !wakeReadJSON(w, r, &input, false) {
		return
	}
	job, err := s.db.FinishWakeJob(session, r.PathValue("job"), input.ClaimToken, input.State, input.Reason)
	wakeResponse(w, http.StatusOK, job, err)
}

func wakeResponse(w http.ResponseWriter, status int, value any, err error) {
	if err != nil {
		wakeError(w, err)
		return
	}
	writeJSON(w, status, value)
}
