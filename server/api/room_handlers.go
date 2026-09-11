package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
)

func (s *Server) RegisterRoomRoutes(mux *http.ServeMux) {
	for pattern, handler := range map[string]http.HandlerFunc{
		"POST /api/v1/rooms/{room}/device-access":                   s.RequestRoomDevice,
		"POST /api/v1/rooms/{room}/device-access/{access}/{action}": s.ChangeRoomDeviceAccess,
		"PUT /api/v1/rooms/{room}/device-policy":                    s.SetRoomDeviceApproval,
		"GET /api/v1/rooms":                                         s.ListRooms,
		"POST /api/v1/rooms":                                        s.CreateRoom,
		"POST /api/v1/rooms/join":                                   s.JoinRoom,
		"GET /api/v1/rooms/{room}":                                  s.GetRoom,
		"PATCH /api/v1/rooms/{room}":                                s.UpdateRoom,
		"DELETE /api/v1/rooms/{room}":                               s.DeleteRoom,
		"POST /api/v1/rooms/{room}/leave":                           s.LeaveRoom,
		"DELETE /api/v1/rooms/{room}/members/{user}":                s.RemoveRoomMember,
		"PUT /api/v1/rooms/{room}/bans/{user}":                      s.BanRoomMember,
		"DELETE /api/v1/rooms/{room}/bans/{user}":                   s.UnbanRoomMember,
		"PATCH /api/v1/rooms/{room}/devices/{device}":               s.AssignRoomDeviceIP,
		"DELETE /api/v1/rooms/{room}/devices/{device}":              s.DeleteRoomDevice,
		"GET /api/v1/rooms/{room}/invites":                          s.ListRoomInvites,
		"POST /api/v1/rooms/{room}/invites":                         s.CreateRoomInvite,
		"DELETE /api/v1/rooms/{room}/invites/{invite}":              s.RevokeRoomInvite,
	} {
		mux.HandleFunc(pattern, s.auth.RequireAuth(handler))
	}
}

func roomActor(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, err := auth.GetClaims(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "user authentication required"})
		return "", false
	}
	w.Header().Set("Cache-Control", "no-store")
	return claims.UserID, true
}

func roomBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		roomError(w, database.ErrRoomInvalid)
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		roomError(w, database.ErrRoomInvalid)
		return false
	}
	return true
}

func roomError(w http.ResponseWriter, err error) {
	status, code, message := http.StatusInternalServerError, "room_internal", "room operation failed"
	switch {
	case errors.Is(err, database.ErrRoomDeviceBlocked):
		status, code, message = http.StatusForbidden, "room_device_blocked", err.Error()
	case errors.Is(err, database.ErrRoomDevicePending):
		status, code, message = http.StatusForbidden, "room_device_pending", err.Error()
	case errors.Is(err, database.ErrRoomDevicePaused):
		status, code, message = http.StatusForbidden, "room_device_paused", err.Error()
	case errors.Is(err, database.ErrRoomAccess):
		status, code, message = http.StatusForbidden, "room_access", database.ErrRoomAccess.Error()
	case errors.Is(err, database.ErrRoomExists):
		status, code, message = http.StatusConflict, "room_exists", database.ErrRoomExists.Error()
	case errors.Is(err, database.ErrRoomInvalid):
		status, code, message = http.StatusBadRequest, "room_invalid", database.ErrRoomInvalid.Error()
	case errors.Is(err, database.ErrRoomJoin):
		status, code, message = http.StatusForbidden, "room_join", database.ErrRoomJoin.Error()
	case errors.Is(err, database.ErrRoomExhausted):
		status, code, message = http.StatusConflict, "room_exhausted", database.ErrRoomExhausted.Error()
	case errors.Is(err, database.ErrRoomIPConflict):
		status, code, message = http.StatusConflict, "room_ip_conflict", "room address unavailable"
	case errors.Is(err, database.ErrRoomDeviceStateConflict):
		status, code, message = http.StatusConflict, "room_device_state_conflict", "room device state changed"
	case errors.Is(err, database.ErrRoomInviteLimit):
		status, code, message = http.StatusConflict, "room_invite_limit", "room invite limit reached"
	case errors.Is(err, database.ErrRoomConflict):
		status, code, message = http.StatusConflict, "room_conflict", database.ErrRoomConflict.Error()
	case errors.Is(err, database.ErrRoomRateLimit):
		status, code, message = http.StatusTooManyRequests, "room_rate_limit", database.ErrRoomRateLimit.Error()
		w.Header().Set("Retry-After", "60")
	}
	writeJSON(w, status, map[string]any{"error": message, "error_code": code})
}

func (s *Server) roomChanged(roomID string, revoked []string) {
	for _, id := range revoked {
		if s.hub != nil {
			s.hub.Disconnect(id)
		}
		if s.signalNotifier != nil {
			s.signalNotifier.notify(id)
		}
	}
	devices, err := s.db.ListDevicesByNetwork(roomID)
	if err != nil {
		return
	}
	for _, device := range devices {
		if s.hub != nil {
			s.hub.Notify(device.ID)
		}
		if s.signalNotifier != nil {
			s.signalNotifier.notify(device.ID)
		}
	}
}

func (s *Server) ListRooms(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	rooms, err := s.db.ListRooms(actor)
	if err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"rooms": rooms, "user_id": actor, "room_protocol_version": 1})
}

func (s *Server) CreateRoom(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if !roomBody(w, r, &req) {
		return
	}
	room, err := s.db.CreateRoom(actor, req.Name, req.Password)
	if err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"room": room})
}

func (s *Server) JoinRoom(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Code        string `json:"room_code"`
		Password    string `json:"password"`
		InviteToken string `json:"invite_token"`
	}
	if !roomBody(w, r, &req) {
		return
	}
	room, err := s.db.JoinRoom(actor, req.Code, req.Password, req.InviteToken)
	if err != nil {
		roomError(w, err)
		return
	}
	s.roomChanged(room.ID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"room": room})
}

func (s *Server) GetRoom(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	details, err := s.db.GetRoom(actor, r.PathValue("room"))
	if err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, details)
}

func (s *Server) UpdateRoom(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Name       *string `json:"name"`
		Password   *string `json:"password"`
		JoinLocked *bool   `json:"join_locked"`
	}
	if !roomBody(w, r, &req) {
		return
	}
	if err := s.db.UpdateRoom(actor, r.PathValue("room"), req.Name, req.Password, req.JoinLocked); err != nil {
		roomError(w, err)
		return
	}
	s.roomChanged(r.PathValue("room"), nil)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) DeleteRoom(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	ids, err := s.db.DeleteRoom(actor, r.PathValue("room"))
	if err != nil {
		roomError(w, err)
		return
	}
	s.roomChanged(r.PathValue("room"), ids)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) LeaveRoom(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	s.removeRoomMember(w, r, actor, actor, false)
}

func (s *Server) RemoveRoomMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	s.removeRoomMember(w, r, actor, r.PathValue("user"), false)
}

func (s *Server) BanRoomMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	s.removeRoomMember(w, r, actor, r.PathValue("user"), true)
}

func (s *Server) removeRoomMember(w http.ResponseWriter, r *http.Request, actor, target string, ban bool) {
	ids, err := s.db.RemoveRoomMember(actor, r.PathValue("room"), target, ban)
	if err != nil {
		roomError(w, err)
		return
	}
	s.roomChanged(r.PathValue("room"), ids)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) UnbanRoomMember(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	if err := s.db.UnbanRoomMember(actor, r.PathValue("room"), r.PathValue("user")); err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) AssignRoomDeviceIP(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var req struct {
		IP string `json:"virtual_ip"`
	}
	if !roomBody(w, r, &req) {
		return
	}
	changed, err := s.db.AssignRoomDeviceIPIfChanged(actor, r.PathValue("room"), r.PathValue("device"), req.IP)
	if err != nil {
		roomError(w, err)
		return
	}
	if changed {
		s.roomChanged(r.PathValue("room"), []string{r.PathValue("device")})
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "changed": changed, "reconnect_required": changed})
}

func (s *Server) DeleteRoomDevice(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	if err := s.db.DeleteRoomDevice(actor, r.PathValue("room"), r.PathValue("device")); err != nil {
		roomError(w, err)
		return
	}
	s.roomChanged(r.PathValue("room"), []string{r.PathValue("device")})
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) ListRoomInvites(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	invites, err := s.db.ListRoomInvites(actor, r.PathValue("room"))
	if err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": invites})
}

func (s *Server) CreateRoomInvite(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var req struct {
		TTLSeconds int64 `json:"ttl_seconds"`
		MaxUses    int   `json:"max_uses"`
	}
	if !roomBody(w, r, &req) {
		return
	}
	if req.TTLSeconds == 0 {
		req.TTLSeconds = 86400
	}
	if req.MaxUses == 0 {
		req.MaxUses = 10
	}
	invite, token, err := s.db.CreateRoomInvite(actor, r.PathValue("room"), req.TTLSeconds, req.MaxUses)
	if err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"invite": invite, "invite_token": token})
}

func (s *Server) RevokeRoomInvite(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	if err := s.db.RevokeRoomInvite(actor, r.PathValue("room"), r.PathValue("invite")); err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// Device controls require account authentication, never a daemon credential.
func (s *Server) RequestRoomDevice(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var req struct {
		PublicKey  string `json:"public_key"`
		DeviceName string `json:"device_name"`
		Platform   string `json:"platform"`
		Resume     bool   `json:"resume"`
	}
	if !roomBody(w, r, &req) {
		return
	}
	access, err := s.db.RequestRoomDevice(actor, r.PathValue("room"), req.PublicKey, req.DeviceName, req.Platform, req.Resume)
	if err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"access": access})
}
func (s *Server) ChangeRoomDeviceAccess(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	ids, err := s.db.ChangeRoomDeviceAccess(actor, r.PathValue("room"), r.PathValue("access"), r.PathValue("action"))
	if err != nil {
		roomError(w, err)
		return
	}
	s.roomChanged(r.PathValue("room"), ids)
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
func (s *Server) SetRoomDeviceApproval(w http.ResponseWriter, r *http.Request) {
	actor, ok := roomActor(w, r)
	if !ok {
		return
	}
	var req struct {
		Required *bool `json:"require_approval"`
	}
	if !roomBody(w, r, &req) {
		return
	}
	if req.Required == nil {
		roomError(w, database.ErrRoomInvalid)
		return
	}
	if err := s.db.SetRoomDeviceApproval(actor, r.PathValue("room"), *req.Required); err != nil {
		roomError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
