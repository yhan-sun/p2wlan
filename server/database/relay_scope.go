package database

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// RelayForwardingScope is derived from authoritative database state, never
// from the caller's network or role. The existing signed network_id field
// carries this scope, so older relays also isolate newly issued tickets.
func (db *DB) RelayForwardingScope(device *Device) (string, error) {
	if device == nil || device.UserID == "" || device.NetworkID == "" {
		return "", fmt.Errorf("missing relay identity")
	}
	room, err := db.IsRoom(device.NetworkID)
	if err != nil {
		return "", err
	}
	if room {
		allowed, err := db.UserHasNetworkAccess(device.UserID, device.NetworkID)
		if err != nil || !allowed {
			return "", ErrRoomAccess
		}
		allowed, err = db.RoomDeviceAllowed(device)
		if err != nil || !allowed {
			return "", ErrRoomAccess
		}
		return device.NetworkID, nil
	}
	identity, err := json.Marshal([2]string{device.UserID, device.NetworkID})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(identity)
	return "account-v1:" + hex.EncodeToString(digest[:]), nil
}
