package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"os"
	"strings"
	"time"
)

// loadTicketKeyring parses RELAY_TICKET_KEYRING_JSON or config field.
// Expected format: {"kid-1": "<hex-encoded 32-byte Ed25519 public key>", ...}
func loadTicketKeyring(config *RelayConfig) (map[string]ed25519.PublicKey, error) {
	raw := strings.TrimSpace(config.TicketKeyringJSON)
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("RELAY_TICKET_KEYRING_JSON"))
	}
	if raw == "" {
		return nil, fmt.Errorf("no ticket keyring configured")
	}

	var rawKeys map[string]string
	if err := json.Unmarshal([]byte(raw), &rawKeys); err != nil {
		return nil, fmt.Errorf("invalid ticket keyring JSON: %w", err)
	}

	keyring := make(map[string]ed25519.PublicKey)
	for kid, hexKey := range rawKeys {
		bytes, err := hex.DecodeString(strings.TrimSpace(hexKey))
		if err != nil {
			return nil, fmt.Errorf("invalid hex key for kid '%s': %w", kid, err)
		}
		if len(bytes) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("public key for kid '%s' is %d bytes (expected %d)", kid, len(bytes), ed25519.PublicKeySize)
		}
		keyring[kid] = ed25519.PublicKey(bytes)
	}

	if len(keyring) == 0 {
		return nil, fmt.Errorf("ticket keyring is empty")
	}

	return keyring, nil
}

func (s *RelayServer) isTicketJTIRevoked(jti string) bool {
	if _, revoked := s.revokedTicketJTIs[jti]; revoked {
		return true
	}
	s.revocationMu.RLock()
	defer s.revocationMu.RUnlock()
	_, revoked := s.onlineRevokedTicketJTIs[jti]
	return revoked
}

func (s *RelayServer) isDeviceRevoked(deviceID string) bool {
	if _, revoked := s.revokedDeviceIDs[deviceID]; revoked {
		return true
	}
	s.revocationMu.RLock()
	defer s.revocationMu.RUnlock()
	_, revoked := s.onlineRevokedDeviceIDs[deviceID]
	return revoked
}

func (s *RelayServer) isCredentialRevoked(credentialID string) bool {
	if credentialID == "" {
		return false
	}
	s.revocationMu.RLock()
	defer s.revocationMu.RUnlock()
	_, revoked := s.onlineRevokedCredentialIDs[credentialID]
	return revoked
}

// verifyTicket parses and validates a relay ticket JWT.
func (s *RelayServer) verifyTicket(tokenStr string) (*relayTicketClaims, error) {
	if s.ticketKeyring == nil {
		return nil, fmt.Errorf("ticket verification not configured")
	}

	clockSkew := s.config.TicketMaxClockSkew
	if clockSkew <= 0 {
		clockSkew = 30 * time.Second
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer("p2wlan-control"),
		jwt.WithLeeway(clockSkew),
	)

	token, err := parser.ParseWithClaims(tokenStr, &relayTicketClaims{},
		func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != "EdDSA" {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			typ, _ := t.Header["typ"].(string)
			if typ != "p2wlan-relay+jwt" {
				return nil, fmt.Errorf("invalid token type")
			}
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, fmt.Errorf("missing kid")
			}
			pub, ok := s.ticketKeyring[kid]
			if !ok {
				return nil, fmt.Errorf("unknown kid: %s", kid)
			}
			return ed25519.PublicKey(pub), nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("ticket verification failed: %w", err)
	}

	claims, ok := token.Claims.(*relayTicketClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid ticket claims")
	}

	// Validate required claims
	if claims.DeviceID == "" {
		return nil, fmt.Errorf("missing device_id")
	}
	if claims.NetworkID == "" {
		return nil, fmt.Errorf("missing network_id")
	}
	if claims.NodeID == "" {
		return nil, fmt.Errorf("missing node_id")
	}
	if claims.RelayProtocol != 1 {
		return nil, fmt.Errorf("unsupported relay protocol: %d", claims.RelayProtocol)
	}

	// Strict claim validation
	if claims.Subject != claims.DeviceID {
		return nil, fmt.Errorf("identity mismatch: sub '%s' != device_id '%s'",
			claims.Subject, claims.DeviceID)
	}
	if claims.ID == "" {
		return nil, fmt.Errorf("missing jti")
	}
	if s.isTicketJTIRevoked(claims.ID) {
		return nil, fmt.Errorf("ticket revoked")
	}
	if s.isDeviceRevoked(claims.DeviceID) {
		return nil, fmt.Errorf("device revoked")
	}
	if s.isCredentialRevoked(claims.CredentialID) {
		return nil, fmt.Errorf("credential revoked")
	}
	if claims.IssuedAt == nil {
		return nil, fmt.Errorf("missing iat")
	}
	if claims.ExpiresAt == nil {
		return nil, fmt.Errorf("missing exp")
	}
	if claims.NotBefore == nil {
		return nil, fmt.Errorf("missing nbf")
	}
	// Audience must be single value, not array
	if len(claims.Audience) != 1 {
		return nil, fmt.Errorf("audience must be a single value, got %d", len(claims.Audience))
	}

	// Validate audience matches this relay (mandatory when auth is enabled)
	if s.config.RelayAudience == "" {
		return nil, fmt.Errorf("relay audience not configured; required for ticket verification")
	}
	audMatch := false
	for _, aud := range claims.Audience {
		if aud == s.config.RelayAudience {
			audMatch = true
			break
		}
	}
	if !audMatch {
		return nil, fmt.Errorf("audience mismatch: ticket is for %v, relay expects %s",
			claims.Audience, s.config.RelayAudience)
	}

	// Validate region matches (mandatory when auth is enabled)
	if s.config.RelayRegion == "" {
		return nil, fmt.Errorf("relay region not configured; required for ticket verification")
	}
	if claims.RelayRegion != s.config.RelayRegion {
		return nil, fmt.Errorf("region mismatch: ticket is for '%s', relay serves '%s'",
			claims.RelayRegion, s.config.RelayRegion)
	}

	return claims, nil
}
