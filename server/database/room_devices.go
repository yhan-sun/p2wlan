package database

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

var (
	ErrRoomDeviceBlocked = errors.New("device is blocked in this room")
	ErrRoomDevicePending = errors.New("device is awaiting room owner approval")
	ErrRoomDevicePaused  = errors.New("device was disconnected; reconnect explicitly")
)

// Access survives credential rotation and removal of a device registration.
// A new installation/key is a new device and is subject to approval again.
type RoomDeviceAccess struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
	State      string `json:"state"`
	BlockedBy  string `json:"blocked_by,omitempty"`
	DeviceID   string `json:"device_id"`
	Revision   int64  `json:"revision"`
}

func migrateRoomDevices(db *sql.DB) error {
	_, err := db.Exec(`
 CREATE TABLE IF NOT EXISTS room_device_settings (
 network_id TEXT PRIMARY KEY REFERENCES rooms(network_id) ON DELETE CASCADE,
 require_approval INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS room_device_access (
 id TEXT PRIMARY KEY, network_id TEXT NOT NULL REFERENCES rooms(network_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id), public_key TEXT NOT NULL,
 device_name TEXT NOT NULL, platform TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('allowed','paused','blocked','pending')),
 blocked_by TEXT NOT NULL DEFAULT '', revision INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL, UNIQUE(network_id, public_key));
 INSERT OR IGNORE INTO room_device_access(id,network_id,user_id,public_key,device_name,platform,state,created_at)
 SELECT 'access-' || d.id,d.network_id,d.user_id,d.public_key,d.device_name,d.platform,'allowed',d.created_at
 FROM devices d JOIN rooms r ON r.network_id=d.network_id;
 `)
	return err
}

func roomDeviceStateError(state string) error {
	switch state {
	case "allowed":
		return nil
	case "paused":
		return ErrRoomDevicePaused
	case "blocked":
		return ErrRoomDeviceBlocked
	case "pending":
		return ErrRoomDevicePending
	}
	return ErrRoomAccess
}

func ensureRoomDeviceAccess(tx *sql.Tx, user, room, key, name, platform string) (*RoomDeviceAccess, error) {
	var member bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM network_memberships WHERE network_id=? AND user_id=?)`, room, user).Scan(&member); err != nil {
		return nil, err
	}
	if !member {
		return nil, ErrRoomAccess
	}
	var approval bool
	if err := tx.QueryRow(`SELECT COALESCE((SELECT require_approval FROM room_device_settings WHERE network_id=?),0) FROM rooms WHERE network_id=?`, room, room).Scan(&approval); err != nil {
		return nil, ErrRoomAccess
	}
	// Never claim an existing device identity belonging to a different account.
	var existingOwner string
	err := tx.QueryRow(`SELECT user_id FROM devices WHERE public_key=?`, key).Scan(&existingOwner)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if err == nil && existingOwner != user {
		return nil, ErrRoomAccess
	}
	id, err := roomRandomID("access-", 16)
	if err != nil {
		return nil, err
	}
	state := "allowed"
	if approval {
		state = "pending"
	}
	// The account owner can approve their own new device explicitly; there is
	// no privileged creation device and no implicit approval during registration.
	if _, err = tx.Exec(`INSERT OR IGNORE INTO room_device_access(id,network_id,user_id,public_key,device_name,platform,state,created_at) VALUES(?,?,?,?,?,?,?,?)`, id, room, user, key, name, platform, state, time.Now().Unix()); err != nil {
		return nil, err
	}
	a := &RoomDeviceAccess{}
	err = tx.QueryRow(`SELECT id,user_id,public_key,device_name,platform,state,blocked_by,revision FROM room_device_access WHERE network_id=? AND public_key=?`, room, key).Scan(&a.ID, &a.UserID, &a.PublicKey, &a.DeviceName, &a.Platform, &a.State, &a.BlockedBy, &a.Revision)
	if err != nil {
		return nil, err
	}
	if a.UserID != user {
		return nil, ErrRoomAccess
	}
	return a, nil
}

// RequestRoomDevice is called by the account UI. Only an explicit local
// connect may resume a paused device; daemon re-registration never does.
func (db *DB) RequestRoomDevice(user, room, key, name, platform string, resume bool) (*RoomDeviceAccess, error) {
	if strings.TrimSpace(key) == "" || len(key) > 128 || strings.TrimSpace(name) == "" || len(name) > 128 || len(platform) > 64 {
		return nil, ErrRoomInvalid
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	a, err := ensureRoomDeviceAccess(tx, user, room, key, name, platform)
	if err != nil {
		return nil, err
	}
	if resume && a.State == "paused" {
		if _, err = tx.Exec(`UPDATE room_device_access SET state='allowed',revision=revision+1 WHERE id=?`, a.ID); err != nil {
			return nil, err
		}
		a.State = "allowed"
		a.Revision++
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return a, roomDeviceStateError(a.State)
}

func (db *DB) SetRoomDeviceApproval(actor, room string, required bool) error {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = roomOwner(tx, actor, room); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO room_device_settings(network_id,require_approval) VALUES(?,?) ON CONFLICT(network_id) DO UPDATE SET require_approval=excluded.require_approval`, room, required); err != nil {
		return err
	}
	// Existing decisions, including pending requests, are preserved.
	return tx.Commit()
}

func (db *DB) ChangeRoomDeviceAccess(actor, room, id, action string) ([]string, error) {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var owner, user, key, state, blockedBy string
	err = tx.QueryRow(`SELECT r.owner_id,a.user_id,a.public_key,a.state,a.blocked_by FROM room_device_access a JOIN rooms r ON r.network_id=a.network_id JOIN network_memberships m ON m.network_id=r.network_id AND m.user_id=? WHERE a.network_id=? AND a.id=?`, actor, room, id).Scan(&owner, &user, &key, &state, &blockedBy)
	if err != nil {
		return nil, ErrRoomAccess
	}
	if actor != owner && actor != user {
		return nil, ErrRoomAccess
	}
	next := state
	switch action {
	case "disconnect":
		if state == "allowed" {
			next = "paused"
		}
	case "block":
		if state == "pending" && actor != owner {
			return nil, ErrRoomAccess
		}
		next = "blocked"
		if blockedBy != owner {
			blockedBy = actor
		}
	case "unblock":
		if state != "blocked" {
			return nil, ErrRoomDeviceStateConflict
		}
		if actor != owner && blockedBy != actor {
			return nil, ErrRoomAccess
		}
		next = "paused"
		blockedBy = ""
	case "approve":
		if actor != owner {
			return nil, ErrRoomAccess
		}
		if state != "pending" {
			return nil, ErrRoomDeviceStateConflict
		}
		next = "paused"
	default:
		return nil, ErrRoomInvalid
	}
	ids := []string{}
	rows, err := tx.Query(`SELECT id FROM devices WHERE network_id=? AND public_key=?`, room, key)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var device string
		if err = rows.Scan(&device); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, device)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if next != "allowed" {
		for _, device := range ids {
			if err = revokeRoomDeviceTx(tx, device, false); err != nil {
				return nil, err
			}
		}
	}
	if _, err = tx.Exec(`UPDATE room_device_access SET state=?,blocked_by=?,revision=revision+1 WHERE id=?`, next, blockedBy, id); err != nil {
		return nil, err
	}
	return ids, tx.Commit()
}

func (db *DB) RoomDeviceAllowed(device *Device) (bool, error) {
	var denied bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM room_device_access WHERE network_id=? AND public_key=? AND state!='allowed')`, device.NetworkID, device.PublicKey).Scan(&denied)
	return !denied, err
}

func loadRoomDeviceAccess(tx *sql.Tx, out *RoomDetails) error {
	if err := tx.QueryRow(`SELECT COALESCE((SELECT require_approval FROM room_device_settings WHERE network_id=?),0)`, out.Room.ID).Scan(&out.DeviceApprovalRequired); err != nil {
		return err
	}
	rows, err := tx.Query(`SELECT a.id,a.user_id,a.public_key,a.device_name,a.platform,a.state,a.blocked_by,a.revision,COALESCE(d.id,'') FROM room_device_access a LEFT JOIN devices d ON d.network_id=a.network_id AND d.public_key=a.public_key WHERE a.network_id=? AND EXISTS(SELECT 1 FROM network_memberships m WHERE m.network_id=a.network_id AND m.user_id=a.user_id) ORDER BY a.created_at,a.id`, out.Room.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	out.DeviceAccess = []RoomDeviceAccess{}
	for rows.Next() {
		var a RoomDeviceAccess
		if err = rows.Scan(&a.ID, &a.UserID, &a.PublicKey, &a.DeviceName, &a.Platform, &a.State, &a.BlockedBy, &a.Revision, &a.DeviceID); err != nil {
			return err
		}
		out.DeviceAccess = append(out.DeviceAccess, a)
	}
	return rows.Err()
}
