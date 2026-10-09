package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidDeviceCredential means the database authoritatively rejected a
// credential. Other errors mean validation could not complete; callers must
// deny the request without telling the client to discard its credentials.
var ErrInvalidDeviceCredential = errors.New("invalid device credential")

// ValidateDeviceCredential validates a persisted credential and its current
// device/network authorization. Storage failures remain distinguishable from
// an unknown, expired, revoked or deleted credential.
func (db *DB) ValidateDeviceCredential(token string) (*DeviceCredential, *Device, error) {
	var cred DeviceCredential
	var revoked int
	err := db.QueryRow(`SELECT id, device_id, token_hash, expires_at, revoked, created_at
		FROM device_credentials WHERE token_hash = ?`, hashToken(token)).
		Scan(&cred.ID, &cred.DeviceID, &cred.TokenHash, &cred.ExpiresAt, &revoked, &cred.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrInvalidDeviceCredential
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read device credential: %w", err)
	}
	cred.Revoked = revoked == 1
	if cred.Revoked || time.Now().Unix() > cred.ExpiresAt {
		return nil, nil, ErrInvalidDeviceCredential
	}

	device, err := db.GetDevice(cred.DeviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrInvalidDeviceCredential
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read credential device: %w", err)
	}
	if strings.HasPrefix(device.NetworkID, "room-") {
		allowed, err := db.UserHasNetworkAccess(device.UserID, device.NetworkID)
		if err != nil {
			return nil, nil, fmt.Errorf("read credential membership: %w", err)
		}
		if !allowed {
			return nil, nil, ErrRoomAccess
		}
	}
	allowed, err := db.RoomDeviceAllowed(device)
	if err != nil {
		return nil, nil, fmt.Errorf("read credential device access: %w", err)
	}
	if !allowed {
		return nil, nil, ErrRoomAccess
	}
	return &cred, device, nil
}
