// Package api — relay ticket issuance endpoint.
//
// POST /api/v1/relay/tickets accepts a device credential and returns a
// short-lived EdDSA-signed JWT that the client can use to authenticate
// to a specific relay server.
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/yhan-sun/p2wlan/server/auth"
)

// relayTicketRateLimiter is a simple per-device rate limiter for the
// relay ticket endpoint.
type relayTicketRateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*ticketRateBucket
	maxReqs  int
	window   time.Duration
}

type ticketRateBucket struct {
	count int
	reset time.Time
}

func newRelayTicketRateLimiter(maxReqs int, window time.Duration) *relayTicketRateLimiter {
	return &relayTicketRateLimiter{
		buckets: make(map[string]*ticketRateBucket),
		maxReqs: maxReqs,
		window:  window,
	}
}

func (l *relayTicketRateLimiter) allow(deviceID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[deviceID]
	if !ok || now.After(b.reset) {
		l.buckets[deviceID] = &ticketRateBucket{count: 1, reset: now.Add(l.window)}
		return true
	}
	b.count++
	if b.count > l.maxReqs {
		return false
	}
	return true
}

// ticketRateLimiter is the global rate limiter for the ticket endpoint.
var ticketRateLimiter = newRelayTicketRateLimiter(auth.DefaultTicketRateLimit, auth.DefaultTicketRateWindow)

// CreateRelayTicket handles POST /api/v1/relay/tickets.
//
// This endpoint requires a valid device credential. It does NOT accept user JWT
// fallback. The device must exist, its credential must not be revoked/expired,
// and the audience/region must match a relay in the catalog.
func (s *Server) CreateRelayTicket(w http.ResponseWriter, r *http.Request) {
	// ---- Auth: device credential only ----
	deviceClaims, err := auth.GetDeviceClaims(r.Context())
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"error": "device credential required",
		})
		return
	}

	// ---- Rate limit ----
	if !ticketRateLimiter.allow(deviceClaims.DeviceID) {
		writeJSON(w, http.StatusTooManyRequests, map[string]interface{}{
			"error": "rate limit exceeded",
		})
		return
	}

	// ---- Parse request ----
	var req struct {
		Audience string `json:"audience"`
		Region   string `json:"region"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "invalid request body",
		})
		return
	}

	req.Audience = strings.TrimSpace(req.Audience)
	req.Region = strings.TrimSpace(req.Region)

	if req.Audience == "" && req.Region == "" {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "audience or region is required",
		})
		return
	}

	// ---- Resolve relay descriptor ----
	var descriptor *RelayDescriptor
	if req.Audience != "" {
		descriptor = s.relayCatalog.LookupByAudience(req.Audience)
	} else {
		descriptor = s.relayCatalog.LookupByRegion(req.Region)
	}

	if descriptor == nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "relay not found",
		})
		return
	}

	// Cross-check: if both audience and region are provided, they must match
	// the same relay descriptor.
	if req.Audience != "" && req.Region != "" {
		if descriptor.Audience != req.Audience || descriptor.Region != req.Region {
			writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "audience and region do not match the same relay",
			})
			return
		}
	}

	// ---- Verify device state ----
	device, err := s.db.GetDevice(deviceClaims.DeviceID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{
			"error": "device not found",
		})
		return
	}

	// Verify network hasn't changed
	if device.NetworkID != deviceClaims.NetworkID {
		writeJSON(w, http.StatusForbidden, map[string]interface{}{
			"error": "network mismatch",
		})
		return
	}

	// ---- Check signer ----
	if s.relayTicketSigner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error": "relay ticket signing not configured",
		})
		return
	}

	// ---- Sign ticket ----
	now := time.Now()
	tokenStr, expiresAt, err := s.relayTicketSigner.SignTicket(
		device.ID,
		device.NetworkID,
		device.ID, // node_id = device_id in current model
		descriptor.Audience,
		descriptor.Region,
		now,
	)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"error": "ticket signing failed",
		})
		return
	}

	// ---- Respond ----
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ticket":     tokenStr,
		"expires_at": expiresAt,
		"audience":   descriptor.Audience,
		"region":     descriptor.Region,
	})
}
