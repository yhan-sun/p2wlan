package api

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"

	"github.com/yhan-sun/p2wlan/server/auth"
	"github.com/yhan-sun/p2wlan/server/database"
	"github.com/yhan-sun/p2wlan/server/signaling"
)

type registrationSessionContextKey struct{}

type registrationSessionGate struct {
	server   *Server
	deviceID string
	release  func()
}

type registrationSessionGateContextKey struct{}

func (gate *registrationSessionGate) releaseCurrent() {
	if gate.release != nil {
		gate.release()
		gate.release = nil
	}
}

// All fenced REST handlers finish their state changes before their first
// response write. Releasing at this boundary avoids holding a device lock while
// a slow network reader receives JSON, without allocating a second response.
type registrationSessionResponseWriter struct {
	http.ResponseWriter
	release func()
}

func (w *registrationSessionResponseWriter) WriteHeader(status int) {
	w.release()
	w.ResponseWriter.WriteHeader(status)
}

func (w *registrationSessionResponseWriter) Write(body []byte) (int, error) {
	w.release()
	return w.ResponseWriter.Write(body)
}

// RequireCurrentDeviceRegistrationSession serializes state-changing work with
// re-registration. Request/response network I/O and idle signal waits do not
// hold a device lock. Each resumed poll revalidates credential and sequence.
func (s *Server) RequireCurrentDeviceRegistrationSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := auth.GetDeviceClaims(r.Context())
		if err != nil {
			next(w, r)
			return
		}
		// Ordinary control requests already have this production mux limit.
		// Read outside the session lock so a partial JSON body cannot prevent
		// the same device from registering its replacement process.
		const maxControlBody = 1 << 20
		body, err := io.ReadAll(io.LimitReader(r.Body, maxControlBody+1))
		if err != nil {
			if r.Context().Err() == nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
				} else {
					http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
				}
			}
			return
		}
		if len(body) > maxControlBody {
			http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		gate := &registrationSessionGate{server: s, deviceID: claims.DeviceID}
		r = r.WithContext(context.WithValue(r.Context(), registrationSessionGateContextKey{}, gate))
		if sequence, ok := registrationSequenceFromHeader(r); ok {
			r = r.WithContext(context.WithValue(r.Context(), registrationSessionContextKey{}, sequence))
		}
		guarded := &registrationSessionResponseWriter{ResponseWriter: w, release: gate.releaseCurrent}
		defer gate.releaseCurrent()
		if !resumeDeviceRegistrationSession(guarded, r) {
			return
		}
		next(guarded, r)
	}
}

func pauseDeviceRegistrationSession(r *http.Request) {
	if gate, ok := r.Context().Value(registrationSessionGateContextKey{}).(*registrationSessionGate); ok {
		gate.releaseCurrent()
	}
}

func resumeDeviceRegistrationSession(w http.ResponseWriter, r *http.Request) bool {
	gate, ok := r.Context().Value(registrationSessionGateContextKey{}).(*registrationSessionGate)
	if !ok || gate.release != nil {
		return true
	}
	unlock, ok := gate.server.lockDeviceRegistrationSession(w, r, gate.deviceID)
	if !ok {
		return false
	}
	gate.release = unlock
	accepted := false
	// The original auth check may predate body I/O or an idle long poll.
	// Recheck both revocation/expiry and the registration under the short lock.
	auth.RequireDeviceAuth(gate.server.db)(auth.RequireCurrentDeviceRegistrationSession(gate.server.db)(func(http.ResponseWriter, *http.Request) {
		accepted = true
	}))(w, r)
	if !accepted {
		gate.releaseCurrent()
	}
	return accepted
}

// WebSocketRegistrationSessionGuard keeps a device's registration lock from
// the authoritative sequence re-check through signaling.Hub.register.  The
// signaling package releases it immediately after registration, before the
// socket begins its long-lived read/write pumps.
func (s *Server) WebSocketRegistrationSessionGuard() signaling.UpgradeGuard {
	return func(w http.ResponseWriter, r *http.Request) (func(), bool) {
		claims, err := auth.GetDeviceClaims(r.Context())
		if err != nil {
			http.Error(w, `{"error":"device authentication required"}`, http.StatusUnauthorized)
			return nil, false
		}
		unlock, ok := s.lockDeviceRegistrationSession(w, r, claims.DeviceID)
		if !ok {
			return nil, false
		}
		accepted := false
		guarded := &registrationSessionResponseWriter{ResponseWriter: w, release: unlock}
		auth.RequireDeviceAuth(s.db)(auth.RequireCurrentDeviceRegistrationSession(s.db)(func(http.ResponseWriter, *http.Request) {
			accepted = true
		}))(guarded, r)
		if !accepted {
			unlock()
			return nil, false
		}
		return unlock, true
	}
}

func (s *Server) lockDeviceRegistrationSession(w http.ResponseWriter, r *http.Request, deviceID string) (func(), bool) {
	unlock, err := s.registrationSessionLocks.LockContext(r.Context(), deviceID)
	if err == nil {
		var once sync.Once
		return func() { once.Do(unlock) }, true
	}
	if r.Context().Err() == nil {
		code := "registration_session_unavailable"
		switch {
		case errors.Is(err, errRegistrationSessionWaitTimeout):
			code = "registration_session_wait_timeout"
		case errors.Is(err, errRegistrationSessionCapacity):
			code = "registration_session_capacity"
		}
		w.Header().Set("Retry-After", "2")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "registration session temporarily unavailable", "error_code": code,
		})
	}
	return nil, false
}

func registrationSequenceFromHeader(r *http.Request) (int64, bool) {
	values := r.Header.Values(auth.RegistrationSequenceHeader)
	if len(values) != 1 {
		return 0, false
	}
	sequence, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || sequence <= 0 {
		return 0, false
	}
	return sequence, true
}

func currentRequestRegistrationSequence(r *http.Request) (int64, bool) {
	sequence, ok := r.Context().Value(registrationSessionContextKey{}).(int64)
	return sequence, ok && sequence > 0
}

func writeRegistrationSessionConflict(w http.ResponseWriter, err error) bool {
	var conflict *database.RegistrationSessionConflictError
	if !errors.As(err, &conflict) {
		return false
	}
	writeJSON(w, http.StatusConflict, map[string]interface{}{
		"error":            "device registration session is no longer current",
		"error_code":       auth.RegistrationLifecycleConflictCode,
		"registration_seq": conflict.CurrentSequence,
	})
	return true
}
