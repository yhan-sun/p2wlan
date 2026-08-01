package database

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ---- Authorization types ----

// DeviceChallenge represents a one-time challenge for device identity verification.
type DeviceChallenge struct {
	ID        string `json:"id"`
	DeviceID  string `json:"device_id"`
	Challenge []byte `json:"challenge"`
	ExpiresAt int64  `json:"expires_at"`
	Consumed  bool   `json:"consumed"`
	CreatedAt int64  `json:"created_at"`
}

// DeviceCredential represents a device-specific authentication token.
type DeviceCredential struct {
	ID        string `json:"id"`
	DeviceID  string `json:"device_id"`
	TokenHash []byte `json:"-"`
	ExpiresAt int64  `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
	CreatedAt int64  `json:"created_at"`
}

// RelayRevocationSnapshot is the control-plane snapshot consumed by relays.
type RelayRevocationSnapshot struct {
	GeneratedAt          string   `json:"generated_at"`
	Version              int64    `json:"version"`
	RevokedDeviceIDs     []string `json:"revoked_device_ids"`
	RevokedCredentialIDs []string `json:"revoked_credential_ids"`
	RevokedJTIs          []string `json:"revoked_jtis,omitempty"`
}

const (
	RelayRevocationDeviceID     = "device_id"
	RelayRevocationCredentialID = "credential_id"
	RelayRevocationJTI          = "jti"
)

// NetworkMembership links a user to a network.
type NetworkMembership struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	NetworkID string `json:"network_id"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
}

// ---- Challenge operations ----

// CreateChallenge generates a new device challenge.
func (db *DB) CreateChallenge(deviceID string, challenge []byte, expiresAt int64) (*DeviceChallenge, error) {
	id := fmt.Sprintf("challenge-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	_, err := db.Exec(`INSERT INTO device_challenges (id, device_id, challenge, expires_at, consumed, created_at)
        VALUES (?, ?, ?, ?, 0, ?)`, id, deviceID, challenge, expiresAt, now)
	if err != nil {
		return nil, err
	}
	return &DeviceChallenge{
		ID: id, DeviceID: deviceID, Challenge: challenge,
		ExpiresAt: expiresAt, Consumed: false, CreatedAt: now,
	}, nil
}

// GetChallenge retrieves a challenge by ID.
func (db *DB) GetChallenge(challengeID string) (*DeviceChallenge, error) {
	var c DeviceChallenge
	var consumed int
	err := db.QueryRow(`SELECT id, device_id, challenge, expires_at, consumed, created_at
        FROM device_challenges WHERE id = ?`, challengeID).
		Scan(&c.ID, &c.DeviceID, &c.Challenge, &c.ExpiresAt, &consumed, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.Consumed = consumed == 1
	return &c, nil
}

// ConsumeChallenge marks a challenge as consumed (one-time use).
func (db *DB) ConsumeChallenge(challengeID string) error {
	_, err := db.Exec(`UPDATE device_challenges SET consumed = 1 WHERE id = ?`, challengeID)
	return err
}

// ---- Credential operations ----

// CreateDeviceCredential creates a new device credential and returns the credential
// record along with the raw token. The token is only returned once; only its hash is stored.
func (db *DB) CreateDeviceCredential(deviceID string, ttlSec int64) (*DeviceCredential, string, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, "", fmt.Errorf("generate credential token: %w", err)
	}
	rawToken := "dc-" + hex.EncodeToString(rawBytes)
	hash := hashToken(rawToken)
	id := fmt.Sprintf("cred-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	expires := now + ttlSec

	_, err := db.Exec(`INSERT INTO device_credentials (id, device_id, token_hash, expires_at, revoked, created_at)
		VALUES (?, ?, ?, ?, 0, ?)`, id, deviceID, hash, expires, now)
	if err != nil {
		return nil, "", err
	}

	return &DeviceCredential{
		ID: id, DeviceID: deviceID, TokenHash: hash,
		ExpiresAt: expires, Revoked: false, CreatedAt: now,
	}, rawToken, nil
}

// UpdateDeviceEd25519PublicKey stores the verified Ed25519 identity key for a device.
func (db *DB) UpdateDeviceEd25519PublicKey(deviceID, ed25519PublicKey string) error {
	_, err := db.Exec(`UPDATE devices SET ed25519_public_key = ? WHERE id = ?`, ed25519PublicKey, deviceID)
	return err
}

// ValidateDeviceCredential validates a credential token and returns the credential and device.
func (db *DB) ValidateDeviceCredential(token string) (*DeviceCredential, *Device, error) {
	hash := hashToken(token)

	var cred DeviceCredential
	var revoked int
	err := db.QueryRow(`SELECT id, device_id, token_hash, expires_at, revoked, created_at
		FROM device_credentials WHERE token_hash = ?`, hash).
		Scan(&cred.ID, &cred.DeviceID, &cred.TokenHash, &cred.ExpiresAt, &revoked, &cred.CreatedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid credential: %w", err)
	}
	cred.Revoked = revoked == 1

	if cred.Revoked {
		return nil, nil, fmt.Errorf("credential revoked")
	}
	if time.Now().Unix() > cred.ExpiresAt {
		return nil, nil, fmt.Errorf("credential expired")
	}

	device, err := db.GetDevice(cred.DeviceID)
	if err != nil {
		return nil, nil, fmt.Errorf("device not found: %w", err)
	}

	return &cred, device, nil
}

// RevokeDeviceCredential revokes a device credential.
func (db *DB) RevokeDeviceCredential(credentialID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`UPDATE device_credentials SET revoked = 1 WHERE id = ?`, credentialID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO relay_revocations (kind, value, created_at)
		SELECT ?, id, ? FROM device_credentials WHERE id = ?`,
		RelayRevocationCredentialID, now, credentialID); err != nil {
		return err
	}
	return tx.Commit()
}

// RevokeDeviceCredentials revokes all credentials currently issued to a device.
func (db *DB) RevokeDeviceCredentials(deviceID string) (int64, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO relay_revocations (kind, value, created_at)
		SELECT ?, id, ? FROM device_credentials WHERE device_id = ?`,
		RelayRevocationCredentialID, now, deviceID); err != nil {
		return 0, err
	}
	res, err := tx.Exec(`UPDATE device_credentials SET revoked = 1 WHERE device_id = ? AND revoked = 0`, deviceID)
	if err != nil {
		return 0, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return rows, nil
}

// RecordRelayTicketRevocation stores a ticket jti tombstone for relay denylist feeds.
func (db *DB) RecordRelayTicketRevocation(jti string) error {
	if strings.TrimSpace(jti) == "" {
		return nil
	}
	_, err := db.Exec(`INSERT OR IGNORE INTO relay_revocations (kind, value, created_at) VALUES (?, ?, ?)`,
		RelayRevocationJTI, strings.TrimSpace(jti), time.Now().Unix())
	return err
}

// RelayRevocationSnapshot returns all relay revocation tombstones.
func (db *DB) RelayRevocationSnapshot() (*RelayRevocationSnapshot, error) {
	rows, err := db.Query(`SELECT kind, value, created_at FROM relay_revocations ORDER BY kind, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	snapshot := &RelayRevocationSnapshot{
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		RevokedDeviceIDs:     []string{},
		RevokedCredentialIDs: []string{},
		RevokedJTIs:          []string{},
	}
	for rows.Next() {
		var kind, value string
		var createdAt int64
		if err := rows.Scan(&kind, &value, &createdAt); err != nil {
			return nil, err
		}
		if createdAt > snapshot.Version {
			snapshot.Version = createdAt
		}
		switch kind {
		case RelayRevocationDeviceID:
			snapshot.RevokedDeviceIDs = append(snapshot.RevokedDeviceIDs, value)
		case RelayRevocationCredentialID:
			snapshot.RevokedCredentialIDs = append(snapshot.RevokedCredentialIDs, value)
		case RelayRevocationJTI:
			snapshot.RevokedJTIs = append(snapshot.RevokedJTIs, value)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

// hashToken returns a SHA-256 hash of an opaque credential token.
func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}
