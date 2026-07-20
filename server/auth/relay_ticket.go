// Package auth provides EdDSA relay ticket signing and verification.
//
// Relay tickets are short-lived JWTs signed by the control plane with an
// Ed25519 private key. Relays verify them with the corresponding public keys
// from a keyring that supports current and previous keys for rotation.
package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	RelayTicketIssuer       = "p2wlan-control"
	RelayTicketTyp          = "p2wlan-relay+jwt"
	RelayTicketAlg          = "EdDSA"
	RelayTicketProtocol     = 1
	DefaultTicketTTL        = 5 * time.Minute
	MinTicketTTL            = 30 * time.Second
	MaxTicketTTL            = 15 * time.Minute
	DefaultClockSkew        = 30 * time.Second
	DefaultTicketRateLimit  = 5               // per device per minute
	DefaultTicketRateWindow = 1 * time.Minute
)

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

var (
	ErrRelayTicketSignerNotConfigured = errors.New("relay ticket signer not configured")
	ErrRelayTicketInvalidAlg          = errors.New("invalid relay ticket algorithm")
	ErrRelayTicketInvalidTyp          = errors.New("invalid relay ticket type")
	ErrRelayTicketMissingKid          = errors.New("relay ticket missing kid")
	ErrRelayTicketUnknownKid          = errors.New("unknown relay ticket kid")
	ErrRelayTicketInvalidIssuer       = errors.New("invalid relay ticket issuer")
	ErrRelayTicketInvalidAudience     = errors.New("invalid relay ticket audience")
	ErrRelayTicketExpired             = errors.New("relay ticket expired")
	ErrRelayTicketNotYetValid         = errors.New("relay ticket not yet valid")
	ErrRelayTicketNoDeviceID          = errors.New("relay ticket missing device_id")
	ErrRelayTicketNoNetworkID         = errors.New("relay ticket missing network_id")
	ErrRelayTicketNoNodeID            = errors.New("relay ticket missing node_id")
)

// ---------------------------------------------------------------------------
// Relay ticket claims
// ---------------------------------------------------------------------------

// RelayTicketClaims are the JWT claims carried in a relay registration ticket.
type RelayTicketClaims struct {
	DeviceID     string `json:"device_id"`
	NetworkID    string `json:"network_id"`
	NodeID       string `json:"node_id"`
	RelayRegion  string `json:"relay_region"`
	RelayProtocol int   `json:"relay_protocol"`
	jwt.RegisteredClaims
}

// Validate performs claim-level validation beyond what the JWT library does.
func (c *RelayTicketClaims) Validate(now time.Time, clockSkew time.Duration) error {
	if c.DeviceID == "" {
		return ErrRelayTicketNoDeviceID
	}
	if c.NetworkID == "" {
		return ErrRelayTicketNoNetworkID
	}
	if c.NodeID == "" {
		return ErrRelayTicketNoNodeID
	}
	if c.RelayProtocol != RelayTicketProtocol {
		return fmt.Errorf("unsupported relay protocol: %d", c.RelayProtocol)
	}

	// Issuer
	if c.Issuer != RelayTicketIssuer {
		return ErrRelayTicketInvalidIssuer
	}

	// Time-based checks
	if c.ExpiresAt != nil && now.After(c.ExpiresAt.Add(clockSkew)) {
		return ErrRelayTicketExpired
	}
	if c.NotBefore != nil && now.Before(c.NotBefore.Add(-clockSkew)) {
		return ErrRelayTicketNotYetValid
	}
	return nil
}

// ---------------------------------------------------------------------------
// Signer key bundle
// ---------------------------------------------------------------------------

// SignerKey holds an active Ed25519 private key with its kid.
type SignerKey struct {
	Kid        string
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// RelayTicketSigner creates and signs relay tickets.
type RelayTicketSigner struct {
	active    SignerKey
	previous  *SignerKey // for rotation: kept until max ticket TTL + skew passes
	ttl       time.Duration
	fingerprint string // hex SHA-256 of active public key, first 8 chars
}

// RelayTicketVerifier verifies relay tickets using a keyring.
type RelayTicketVerifier struct {
	keys      map[string]ed25519.PublicKey // kid -> public key
	clockSkew time.Duration
}

// NewRelayTicketVerifier creates a verifier with the given public keys and clock skew.
func NewRelayTicketVerifier(keys map[string]ed25519.PublicKey, clockSkew time.Duration) *RelayTicketVerifier {
	if clockSkew <= 0 {
		clockSkew = DefaultClockSkew
	}
	return &RelayTicketVerifier{keys: keys, clockSkew: clockSkew}
}

// Verify parses and validates a relay ticket JWT.
// It locks the algorithm to EdDSA, checks kid/typ, and validates all claims.
func (v *RelayTicketVerifier) Verify(tokenStr string) (*RelayTicketClaims, error) {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{RelayTicketAlg}),
		jwt.WithIssuer(RelayTicketIssuer),
		jwt.WithLeeway(v.clockSkew),
	)

	token, err := parser.ParseWithClaims(tokenStr, &RelayTicketClaims{},
		func(t *jwt.Token) (interface{}, error) {
			// Enforce algorithm
			if t.Method.Alg() != RelayTicketAlg {
				return nil, ErrRelayTicketInvalidAlg
			}

			// Enforce typ
			typ, ok := t.Header["typ"].(string)
			if !ok || typ != RelayTicketTyp {
				return nil, ErrRelayTicketInvalidTyp
			}

			// Enforce kid
			kid, ok := t.Header["kid"].(string)
			if !ok || kid == "" {
				return nil, ErrRelayTicketMissingKid
			}

			pub, ok := v.keys[kid]
			if !ok {
				return nil, fmt.Errorf("%w: %s", ErrRelayTicketUnknownKid, kid)
			}
			return ed25519.PublicKey(pub), nil
		},
	)
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*RelayTicketClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid relay ticket claims")
	}

	if err := claims.Validate(time.Now(), v.clockSkew); err != nil {
		return nil, err
	}

	return claims, nil
}

// KeyCount returns the number of public keys in the verifier.
func (v *RelayTicketVerifier) KeyCount() int {
	return len(v.keys)
}

// ---------------------------------------------------------------------------
// Signer creation
// ---------------------------------------------------------------------------

// keyFingerprint returns a short hex fingerprint for a public key.
func keyFingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])[:8]
}

// LoadSignerFromEnv reads relay ticket signer configuration from environment.
//
// Two modes are supported:
//
// 1. RELAY_TICKET_SIGNER_JSON (inline hex keys, for testing/dev):
//
//	{
//	  "active": {"kid": "key-1", "private_key": "<hex-encoded 64-byte seed>"},
//	  "previous": {"kid": "key-0", "private_key": "<hex-encoded 64-byte seed>"}
//	}
//
// 2. RELAY_TICKET_SIGNER_KEY_FILE (PKCS#8 PEM file path, for production).
//
//	The kid is derived from RELAY_TICKET_SIGNER_KID env var.
//	Optional RELAY_TICKET_SIGNER_PREV_KEY_FILE and RELAY_TICKET_SIGNER_PREV_KID
//	for the previous key during rotation.
//
// Mode 2 is preferred for production; mode 1 exists for compatibility.
func LoadSignerFromEnv() (*RelayTicketSigner, error) {
	// Try PKCS#8 PEM file mode first (production)
	keyFile := strings.TrimSpace(os.Getenv("RELAY_TICKET_SIGNER_KEY_FILE"))
	if keyFile != "" {
		return loadSignerFromPEMFiles()
	}

	// Fall back to JSON inline mode (testing/development)
	raw := strings.TrimSpace(os.Getenv("RELAY_TICKET_SIGNER_JSON"))
	if raw == "" {
		return nil, nil // not configured — relay ticket endpoint will be disabled
	}

	return loadSignerFromJSON(raw)
}

// loadSignerFromPEMFiles loads Ed25519 private keys from PKCS#8 PEM files.
func loadSignerFromPEMFiles() (*RelayTicketSigner, error) {
	activeKid := strings.TrimSpace(os.Getenv("RELAY_TICKET_SIGNER_KID"))
	if activeKid == "" {
		return nil, errors.New("RELAY_TICKET_SIGNER_KID is required when using PEM file mode")
	}

	activeKeyFile := strings.TrimSpace(os.Getenv("RELAY_TICKET_SIGNER_KEY_FILE"))
	activePEM, err := os.ReadFile(activeKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read active signing key file '%s': %w", activeKeyFile, err)
	}

	activePriv, err := parseEd25519PrivateKey(activePEM)
	if err != nil {
		return nil, fmt.Errorf("active signing key '%s': %w", activeKeyFile, err)
	}
	activePub := activePriv.Public().(ed25519.PublicKey)

	signer := &RelayTicketSigner{
		active: SignerKey{
			Kid:        activeKid,
			PrivateKey: activePriv,
			PublicKey:  activePub,
		},
		fingerprint: keyFingerprint(activePub),
	}

	// Optional previous key for rotation
	prevKid := strings.TrimSpace(os.Getenv("RELAY_TICKET_SIGNER_PREV_KID"))
	prevKeyFile := strings.TrimSpace(os.Getenv("RELAY_TICKET_SIGNER_PREV_KEY_FILE"))
	if prevKid != "" && prevKeyFile != "" {
		if prevKid == activeKid {
			return nil, errors.New("active and previous kid must differ")
		}
		prevPEM, err := os.ReadFile(prevKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read previous signing key file '%s': %w", prevKeyFile, err)
		}
		prevPriv, err := parseEd25519PrivateKey(prevPEM)
		if err != nil {
			return nil, fmt.Errorf("previous signing key '%s': %w", prevKeyFile, err)
		}
		prevPub := prevPriv.Public().(ed25519.PublicKey)
		signer.previous = &SignerKey{
			Kid:        prevKid,
			PrivateKey: prevPriv,
			PublicKey:  prevPub,
		}
	}

	ttlRaw := strings.TrimSpace(os.Getenv("RELAY_TICKET_TTL"))
	if ttlRaw != "" {
		d, err := time.ParseDuration(ttlRaw)
		if err != nil {
			return nil, fmt.Errorf("RELAY_TICKET_TTL: invalid duration: %w", err)
		}
		if d < MinTicketTTL || d > MaxTicketTTL {
			return nil, fmt.Errorf("RELAY_TICKET_TTL: must be between %s and %s", MinTicketTTL, MaxTicketTTL)
		}
		signer.ttl = d
	} else {
		signer.ttl = DefaultTicketTTL
	}

	return signer, nil
}

// parseEd25519PrivateKey parses a PEM-encoded Ed25519 private key (PKCS#8).
func parseEd25519PrivateKey(pemData []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Try PKCS#8 format
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an Ed25519 private key (got %T)", key)
	}

	return edKey, nil
}

func loadSignerFromJSON(raw string) (*RelayTicketSigner, error) {
	var cfg struct {
		Active struct {
			Kid        string `json:"kid"`
			PrivateKey string `json:"private_key"`
		} `json:"active"`
		Previous *struct {
			Kid        string `json:"kid"`
			PrivateKey string `json:"private_key"`
		} `json:"previous"`
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("RELAY_TICKET_SIGNER_JSON: invalid JSON: %w", err)
	}

	if cfg.Active.Kid == "" {
		return nil, errors.New("RELAY_TICKET_SIGNER_JSON: active.kid is required")
	}

	activeSeed, err := hex.DecodeString(strings.TrimSpace(cfg.Active.PrivateKey))
	if err != nil {
		return nil, fmt.Errorf("RELAY_TICKET_SIGNER_JSON: active.private_key hex decode: %w", err)
	}
	if len(activeSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("RELAY_TICKET_SIGNER_JSON: active.private_key must be %d bytes (got %d)", ed25519.SeedSize, len(activeSeed))
	}

	activePriv := ed25519.NewKeyFromSeed(activeSeed)
	activePub, ok := activePriv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("RELAY_TICKET_SIGNER_JSON: failed to derive public key")
	}
	_ = activePub

	signer := &RelayTicketSigner{
		active: SignerKey{
			Kid:        cfg.Active.Kid,
			PrivateKey: activePriv,
			PublicKey:  activePub,
		},
		fingerprint: keyFingerprint(activePub),
	}

	if cfg.Previous != nil && cfg.Previous.Kid != "" {
		if cfg.Previous.Kid == cfg.Active.Kid {
			return nil, errors.New("RELAY_TICKET_SIGNER_JSON: active and previous kid must differ")
		}
		prevSeed, err := hex.DecodeString(strings.TrimSpace(cfg.Previous.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("RELAY_TICKET_SIGNER_JSON: previous.private_key hex decode: %w", err)
		}
		if len(prevSeed) != ed25519.SeedSize {
			return nil, fmt.Errorf("RELAY_TICKET_SIGNER_JSON: previous.private_key must be %d bytes (got %d)", ed25519.SeedSize, len(prevSeed))
		}
		prevPriv := ed25519.NewKeyFromSeed(prevSeed)
		prevPub := prevPriv.Public().(ed25519.PublicKey)
		signer.previous = &SignerKey{
			Kid:        cfg.Previous.Kid,
			PrivateKey: prevPriv,
			PublicKey:  prevPub,
		}
	}

	ttlRaw := strings.TrimSpace(os.Getenv("RELAY_TICKET_TTL"))
	if ttlRaw != "" {
		d, err := time.ParseDuration(ttlRaw)
		if err != nil {
			return nil, fmt.Errorf("RELAY_TICKET_TTL: invalid duration: %w", err)
		}
		if d < MinTicketTTL || d > MaxTicketTTL {
			return nil, fmt.Errorf("RELAY_TICKET_TTL: must be between %s and %s", MinTicketTTL, MaxTicketTTL)
		}
		signer.ttl = d
	} else {
		signer.ttl = DefaultTicketTTL
	}

	return signer, nil
}

// ActiveKid returns the active signing key ID.
func (s *RelayTicketSigner) ActiveKid() string {
	return s.active.Kid
}

// ActivePublicKey returns the active public key (for relay verifier config).
func (s *RelayTicketSigner) ActivePublicKey() ed25519.PublicKey {
	return s.active.PublicKey
}

// ActivePublicKeyHex returns the active public key as a hex string.
func (s *RelayTicketSigner) ActivePublicKeyHex() string {
	return hex.EncodeToString(s.active.PublicKey)
}

// Fingerprint returns a short hex fingerprint of the active public key.
func (s *RelayTicketSigner) Fingerprint() string {
	return s.fingerprint
}

// PreviousPublicKey returns the optional previous public key (for key rotation).
func (s *RelayTicketSigner) PreviousPublicKey() (string, ed25519.PublicKey, bool) {
	if s.previous == nil {
		return "", nil, false
	}
	return s.previous.Kid, s.previous.PublicKey, true
}

// PublicKeyring returns all public keys for relay verifier configuration,
// suitable for serialization to RELAY_TICKET_KEYRING_JSON.
func (s *RelayTicketSigner) PublicKeyring() map[string]string {
	kr := map[string]string{
		s.active.Kid: hex.EncodeToString(s.active.PublicKey),
	}
	if s.previous != nil {
		kr[s.previous.Kid] = hex.EncodeToString(s.previous.PublicKey)
	}
	return kr
}

// SignTicket creates a signed relay ticket JWT for the given claims.
func (s *RelayTicketSigner) SignTicket(deviceID, networkID, nodeID, audience, region string, now time.Time) (string, int64, error) {
	if s == nil {
		return "", 0, ErrRelayTicketSignerNotConfigured
	}

	exp := now.Add(s.ttl)
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", 0, fmt.Errorf("generate jti: %w", err)
	}

	claims := &RelayTicketClaims{
		DeviceID:      deviceID,
		NetworkID:     networkID,
		NodeID:        nodeID,
		RelayRegion:   region,
		RelayProtocol: RelayTicketProtocol,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    RelayTicketIssuer,
			Subject:   deviceID,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        hex.EncodeToString(jti),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.active.Kid
	token.Header["typ"] = RelayTicketTyp

	tokenStr, err := token.SignedString(s.active.PrivateKey)
	if err != nil {
		return "", 0, fmt.Errorf("sign ticket: %w", err)
	}

	return tokenStr, exp.Unix(), nil
}
