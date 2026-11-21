package database

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

const wakeTargetColumns = `id,network_id,owner_user_id,COALESCE(device_id,''),name,mac,preferred_agent_device_id,enabled`

func readWakeTarget(row interface{ Scan(...any) error }) (WakeTarget, error) {
	var t WakeTarget
	err := row.Scan(&t.ID, &t.NetworkID, &t.owner, &t.device, &t.Name, &t.mac, &t.PreferredAgentDeviceID, &t.Enabled)
	return t, err
}

// lookupWakeTarget applies the same two account/room visibility predicates as
// ListVisibleDevices. An undiscoverable device is indistinguishable from a
// missing one. Within a room, a known but revoked device is explicitly denied.
func lookupWakeTarget(tx *sql.Tx, actor string, ref WakeTargetRef, now int64) (WakeTarget, bool, error) {
	if ref.DeviceID == "" {
		target, err := loadManualWakeTarget(tx, actor, ref.TargetID, false)
		return target, false, err
	}
	var device wakeDevice
	var allowed bool
	err := tx.QueryRow(`SELECT d.id,d.network_id,d.user_id,d.device_name,
		d.online=1 AND d.last_seen>=?,`+deviceRoomAllowedSQL+` FROM devices d WHERE d.id=? AND `+deviceAccountVisibleSQL,
		now-DeviceOnlineTTL, ref.DeviceID, actor, actor).
		Scan(&device.id, &device.network, &device.owner, &device.name, &device.online, &allowed)
	if err != nil {
		return WakeTarget{}, false, wakeMissing(err)
	}
	if !allowed {
		return WakeTarget{}, false, wakeError("target_blocked")
	}
	target, err := readWakeTarget(tx.QueryRow(`SELECT `+wakeTargetColumns+` FROM wake_targets WHERE device_id=?`, device.id))
	if errors.Is(err, sql.ErrNoRows) {
		return WakeTarget{NetworkID: device.network, owner: device.owner, device: device.id}, device.online, nil
	}
	return target, device.online, err
}

func (db *DB) WakeTargetStatus(actor string, ref WakeTargetRef) (WakeTargetStatus, error) {
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		return WakeTargetStatus{}, err
	}
	defer tx.Rollback()
	target, online, err := lookupWakeTarget(tx, actor, ref, now)
	if err != nil {
		return WakeTargetStatus{}, err
	}
	agents, err := wakeEligibleAgents(tx, actor, target, now)
	if err != nil {
		return WakeTargetStatus{}, err
	}
	return WakeTargetStatus{
		Online: online, HasMAC: target.Enabled && target.mac != "", Agents: agents,
		PreferredAgentDeviceID: target.PreferredAgentDeviceID,
	}, tx.Commit()
}

func (db *DB) SetDeviceWakeTarget(session WakeDeviceSession, macIn, nic string, remove bool) error {
	var mac string
	if !remove {
		var err error
		mac, err = normalizeWakeMAC(macIn)
		if err != nil {
			return err
		}
		if !validateWakeText(nic, 128) {
			return wakeError("wake_invalid")
		}
	}
	now := time.Now().Unix()
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	device, err := wakeRegistrationDevice(tx, session, false, now)
	if err != nil {
		return err
	}
	if remove {
		_, err = tx.Exec(`DELETE FROM wake_targets WHERE device_id=?`, device.id)
	} else {
		// Keep rate history tied to the same device across off/on changes.
		id := "wake-target-device-" + device.id
		_, err = tx.Exec(`INSERT INTO wake_targets (id,network_id,owner_user_id,kind,device_id,name,mac,nic,created_at,updated_at)
			VALUES (?,?,?,'device',?,?,?,?,?,?) ON CONFLICT(device_id) WHERE device_id IS NOT NULL
			DO UPDATE SET mac=excluded.mac,nic=excluded.nic,name=excluded.name,enabled=1,updated_at=excluded.updated_at`,
			id, device.network, device.owner, device.id, device.name, mac, nic, now, now)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

type ManualWakeTargetInput struct {
	Name                   *string `json:"name"`
	MAC                    *string `json:"mac"`
	PreferredAgentDeviceID *string `json:"preferred_agent_device_id"`
	Enabled                *bool   `json:"enabled"`
}

func (db *DB) ListManualWakeTargets(actor, network string) ([]WakeTarget, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	roomOwnerID, err := wakeManualNetwork(tx, actor, network)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT `+wakeTargetColumns+` FROM wake_targets
		WHERE network_id=? AND kind='manual' AND (owner_user_id=? OR ?=?) ORDER BY created_at,id`,
		network, actor, roomOwnerID, actor)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WakeTarget{}
	for rows.Next() {
		target, err := readWakeTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func (db *DB) CreateManualWakeTarget(actor, network string, input ManualWakeTargetInput) (WakeTarget, error) {
	if input.Name == nil || input.MAC == nil {
		return WakeTarget{}, wakeError("wake_invalid")
	}
	id, err := roomRandomID("wake-target-", 16)
	if err != nil {
		return WakeTarget{}, err
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return WakeTarget{}, err
	}
	defer tx.Rollback()
	roomOwnerID, err := wakeManualNetwork(tx, actor, network)
	if err != nil {
		return WakeTarget{}, err
	}
	if roomOwnerID != "" && roomOwnerID != actor {
		return WakeTarget{}, wakeError("wake_forbidden")
	}
	target := WakeTarget{ID: id, NetworkID: network, owner: actor, Enabled: true}
	if err = mergeManualWakeTarget(tx, actor, &target, input); err != nil {
		return WakeTarget{}, err
	}
	now := time.Now().Unix()
	_, err = tx.Exec(`INSERT INTO wake_targets (id,network_id,owner_user_id,kind,name,mac,preferred_agent_device_id,enabled,created_at,updated_at)
		VALUES (?,?,?,'manual',?,?,?,?,?,?)`, target.ID, network, actor, target.Name, target.mac,
		target.PreferredAgentDeviceID, target.Enabled, now, now)
	if err != nil {
		return WakeTarget{}, err
	}
	return target, tx.Commit()
}

func (db *DB) ChangeManualWakeTarget(actor, id string, input ManualWakeTargetInput, remove bool) (WakeTarget, error) {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return WakeTarget{}, err
	}
	defer tx.Rollback()
	target, err := loadManualWakeTarget(tx, actor, id, true)
	if err != nil {
		return WakeTarget{}, err
	}
	if remove {
		_, err = tx.Exec(`DELETE FROM wake_targets WHERE id=?`, id)
	} else {
		if err = mergeManualWakeTarget(tx, actor, &target, input); err != nil {
			return WakeTarget{}, err
		}
		_, err = tx.Exec(`UPDATE wake_targets SET name=?,mac=?,preferred_agent_device_id=?,enabled=?,updated_at=? WHERE id=?`,
			target.Name, target.mac, target.PreferredAgentDeviceID, target.Enabled, time.Now().Unix(), id)
	}
	if err != nil {
		return WakeTarget{}, err
	}
	return target, tx.Commit()
}

func loadManualWakeTarget(tx *sql.Tx, actor, id string, ownerOnly bool) (WakeTarget, error) {
	target, err := readWakeTarget(tx.QueryRow(`SELECT `+wakeTargetColumns+` FROM wake_targets WHERE id=? AND kind='manual'`, id))
	if err != nil {
		return WakeTarget{}, wakeMissing(err)
	}
	roomOwnerID, err := wakeManualNetwork(tx, actor, target.NetworkID)
	var denial *WakeError
	if errors.As(err, &denial) {
		return WakeTarget{}, wakeError("wake_not_found")
	}
	if err != nil {
		return WakeTarget{}, err
	}
	if actor != target.owner && (ownerOnly || actor != roomOwnerID) {
		return WakeTarget{}, wakeError("wake_not_found")
	}
	return target, nil
}

func wakeManualNetwork(tx *sql.Tx, actor, network string) (string, error) {
	var owner string
	err := tx.QueryRow(`SELECT COALESCE(r.owner_id,'') FROM network_memberships m
		LEFT JOIN rooms r ON r.network_id=m.network_id WHERE m.network_id=? AND m.user_id=?`, network, actor).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", wakeError("wake_forbidden")
	}
	return owner, err
}

func mergeManualWakeTarget(tx *sql.Tx, actor string, target *WakeTarget, input ManualWakeTargetInput) error {
	if input.Name != nil {
		name := strings.TrimSpace(*input.Name)
		if !validRoomName(name) {
			return wakeError("wake_invalid")
		}
		target.Name = name
	}
	if input.MAC != nil {
		mac, err := normalizeWakeMAC(*input.MAC)
		if err != nil {
			return err
		}
		target.mac = mac
	}
	if input.PreferredAgentDeviceID != nil {
		id := *input.PreferredAgentDeviceID
		if !validateWakeText(id, 256) {
			return wakeError("wake_invalid")
		}
		if id != "" {
			var valid bool
			err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM devices d WHERE d.id=? AND d.network_id=? AND d.wake_proxy=1
				AND `+deviceRoomAllowedSQL+` AND `+deviceAccountVisibleSQL+`)`, id, target.NetworkID, actor, actor).Scan(&valid)
			if err != nil {
				return err
			}
			if !valid {
				return wakeError("wake_agent_unavailable")
			}
		}
		target.PreferredAgentDeviceID = id
	}
	if input.Enabled != nil {
		target.Enabled = *input.Enabled
	}
	return nil
}
