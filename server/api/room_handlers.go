package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func (s *Server) RegisterRoomRoutes(mux *http.ServeMux, sensitiveLimit func(http.HandlerFunc) http.HandlerFunc) {
	account := s.auth.RequireAuth
	device := auth.RequireDeviceAuth(s.db)
	mux.HandleFunc("GET /api/v1/rooms", account(s.ListRooms))
	mux.HandleFunc("POST /api/v1/rooms", sensitiveLimit(account(s.CreateRoom)))
	mux.HandleFunc("POST /api/v1/rooms/join", sensitiveLimit(account(s.JoinRoom)))
	mux.HandleFunc("GET /api/v1/rooms/{room}", account(s.GetRoom))
	mux.HandleFunc("PATCH /api/v1/rooms/{room}", sensitiveLimit(account(s.UpdateRoom)))
	mux.HandleFunc("DELETE /api/v1/rooms/{room}", account(s.DeleteRoom))
	mux.HandleFunc("POST /api/v1/rooms/{room}/leave", account(s.LeaveRoom))
	mux.HandleFunc("DELETE /api/v1/rooms/{room}/members/{member}", account(s.KickRoomMember))
	mux.HandleFunc("DELETE /api/v1/rooms/{room}/bans/{member}", account(s.UnbanRoomMember))
	mux.HandleFunc("POST /api/v1/rooms/{room}/invitation", sensitiveLimit(account(s.RotateRoomInvitation)))
	mux.HandleFunc("DELETE /api/v1/rooms/{room}/invitation", account(s.RevokeRoomInvitation))
	mux.HandleFunc("POST /api/v1/rooms/{room}/devices", account(s.EnableRoomDevice))
	mux.HandleFunc("PATCH /api/v1/rooms/{room}/devices/{device}", account(s.AssignRoomDeviceIP))
	mux.HandleFunc("DELETE /api/v1/rooms/{room}/devices/{device}", account(s.DisableRoomDevice))
	mux.HandleFunc("GET /api/v1/room-roster", device(s.RoomRoster))
}

func roomRequestUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	claims, err := auth.GetClaims(r.Context())
	if err != nil || claims.UserID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
		return "", false
	}
	return claims.UserID, true
}

func decodeRoomRequest(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeRoomError(w, database.ErrRoomInvalidInput)
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeRoomError(w, database.ErrRoomInvalidInput)
		return false
	}
	return true
}

func writeRoomError(w http.ResponseWriter, err error) {
	w.Header().Set("Cache-Control", "no-store")
	status, code := http.StatusInternalServerError, "room_operation_failed"
	switch {
	case errors.Is(err, database.ErrRoomNotFound):
		status, code = http.StatusNotFound, "room_not_found"
	case errors.Is(err, database.ErrRoomForbidden):
		status, code = http.StatusForbidden, "room_access_denied"
	case errors.Is(err, database.ErrRoomCredentials):
		status, code = http.StatusForbidden, "invalid_room_credentials"
	case errors.Is(err, database.ErrRoomJoinRateLimited):
		status, code = http.StatusTooManyRequests, "room_join_rate_limited"
		w.Header().Set("Retry-After", "60")
	case errors.Is(err, database.ErrRoomAlreadyOwned):
		status, code = http.StatusConflict, "one_owned_room_per_account"
	case errors.Is(err, database.ErrRoomSubnetExhausted):
		status, code = http.StatusConflict, "room_subnet_pool_exhausted"
	case errors.Is(err, database.ErrRoomIPUnavailable):
		status, code = http.StatusConflict, "room_ip_unavailable"
	case errors.Is(err, database.ErrRoomLimit):
		status, code = http.StatusConflict, "room_limit_reached"
	case errors.Is(err, database.ErrRoomOwnerCannotLeave):
		status, code = http.StatusConflict, "owner_must_dissolve_room"
	case errors.Is(err, database.ErrRoomUnsupportedNetwork):
		status, code = http.StatusConflict, "room_device_requires_default_network"
	case errors.Is(err, database.ErrRoomInvalidInput):
		status, code = http.StatusBadRequest, "invalid_room_input"
	}
	writeJSON(w, status, map[string]any{"success": false, "error": code, "error_code": code})
}

func roomMutationResult(w http.ResponseWriter, err error) {
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) ListRooms(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	rooms, err := s.db.ListRooms(userID)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "rooms": rooms, "max_joined_rooms": database.MaxJoinedRooms})
}

func (s *Server) CreateRoom(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	var request struct {
		Name string `json:"name"`
		Password string `json:"password"`
	}
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	room, err := s.db.CreateRoom(userID, request.Name, request.Password)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"success": true, "room": room})
}

func (s *Server) JoinRoom(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	var request struct {
		Number string `json:"number"`
		Password string `json:"password"`
		Invitation string `json:"invitation"`
	}
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	room, err := s.db.JoinRoom(userID, request.Number, request.Password, request.Invitation)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "room": room})
}

func (s *Server) GetRoom(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	detail, err := s.db.GetRoom(userID, r.PathValue("room"))
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

func (s *Server) UpdateRoom(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	var request struct {
		Name *string `json:"name"`
		Password *string `json:"password"`
	}
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	room, err := s.db.UpdateRoom(userID, r.PathValue("room"), request.Name, request.Password)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "room": room})
}

func (s *Server) DeleteRoom(w http.ResponseWriter, r *http.Request) {
	if userID, ok := roomRequestUser(w, r); ok {
		roomMutationResult(w, s.db.DeleteRoom(userID, r.PathValue("room")))
	}
}

func (s *Server) LeaveRoom(w http.ResponseWriter, r *http.Request) {
	if userID, ok := roomRequestUser(w, r); ok {
		roomMutationResult(w, s.db.LeaveRoom(userID, r.PathValue("room")))
	}
}

func (s *Server) KickRoomMember(w http.ResponseWriter, r *http.Request) {
	if userID, ok := roomRequestUser(w, r); ok {
		roomMutationResult(w, s.db.KickRoomMember(userID, r.PathValue("room"), r.PathValue("member")))
	}
}

func (s *Server) UnbanRoomMember(w http.ResponseWriter, r *http.Request) {
	if userID, ok := roomRequestUser(w, r); ok {
		roomMutationResult(w, s.db.UnbanRoomMember(userID, r.PathValue("room"), r.PathValue("member")))
	}
}

func (s *Server) RotateRoomInvitation(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	var request struct {
		TTLSeconds int64 `json:"ttl_seconds"`
	}
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	if request.TTLSeconds == 0 {
		request.TTLSeconds = 24 * 3600
	}
	invitation, expires, err := s.db.RotateRoomInvitation(userID, r.PathValue("room"), request.TTLSeconds)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "invitation": invitation, "expires_at": expires})
}

func (s *Server) RevokeRoomInvitation(w http.ResponseWriter, r *http.Request) {
	if userID, ok := roomRequestUser(w, r); ok {
		roomMutationResult(w, s.db.RevokeRoomInvitation(userID, r.PathValue("room")))
	}
}

func (s *Server) EnableRoomDevice(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	var request struct {
		DeviceID string `json:"device_id"`
	}
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	ip, err := s.db.EnableRoomDevice(userID, r.PathValue("room"), request.DeviceID)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "virtual_ip": ip})
}

func (s *Server) AssignRoomDeviceIP(w http.ResponseWriter, r *http.Request) {
	userID, ok := roomRequestUser(w, r)
	if !ok {
		return
	}
	var request struct {
		VirtualIP string `json:"virtual_ip"`
	}
	if !decodeRoomRequest(w, r, &request) {
		return
	}
	ip, err := s.db.AssignRoomDeviceIP(userID, r.PathValue("room"), r.PathValue("device"), request.VirtualIP)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "virtual_ip": ip})
}

func (s *Server) DisableRoomDevice(w http.ResponseWriter, r *http.Request) {
	if userID, ok := roomRequestUser(w, r); ok {
		roomMutationResult(w, s.db.DisableRoomDevice(userID, r.PathValue("room"), r.PathValue("device")))
	}
}

func (s *Server) RoomRoster(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	claims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "device_credential_required"})
		return
	}
	roster, err := s.db.GetRoomRoster(claims.DeviceID)
	if err != nil {
		writeRoomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, roster)
}
