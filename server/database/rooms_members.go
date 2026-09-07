package database

import (
	"database/sql"
	"errors"
	"net/netip"
	"time"
)

func (db *DB) LeaveRoom(userID, id string) error {
	tx, err := db.beginRoomTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	room, err := requireRoomMember(tx, id, userID, false)
	if err != nil {
		return err
	}
	if room.OwnerID == userID {
		return ErrRoomOwnerCannotLeave
	}
	if _, err := tx.Exec(`DELETE FROM room_members WHERE room_id = ? AND user_id = ?`, id, userID); err != nil {
		return err
	}
	if err := bumpRoomRevision(tx, id); err != nil {
		return err
	}
	if err := purgeUnauthorizedRoomSignals(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) KickRoomMember(userID, id, targetUserID string) error {
	tx, err := db.beginRoomTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	room, err := requireRoomMember(tx, id, userID, true)
	if err != nil {
		return err
	}
	if targetUserID == room.OwnerID {
		return ErrRoomOwnerCannotLeave
	}
	result, err := tx.Exec(`UPDATE room_members SET banned = 1 WHERE room_id = ? AND user_id = ?`, id, targetUserID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return ErrRoomNotFound
	}
	if _, err := tx.Exec(`DELETE FROM room_devices WHERE room_id = ? AND user_id = ?`, id, targetUserID); err != nil {
		return err
	}
	if err := bumpRoomRevision(tx, id); err != nil {
		return err
	}
	if err := purgeUnauthorizedRoomSignals(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) UnbanRoomMember(userID, id, targetUserID string) error {
	tx, err := db.beginRoomTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := requireRoomMember(tx, id, userID, true); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM room_members WHERE room_id = ? AND user_id = ? AND banned = 1`, id, targetUserID); err != nil {
		return err
	}
	if err := bumpRoomRevision(tx, id); err != nil {
		return err
	}
	return tx.Commit()
}

func allocateRoomIP(tx *sql.Tx, room roomSecret, requested, deviceID string) (string, error) {
	prefix, err := netip.ParsePrefix(room.CIDR)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 {
		return "", ErrRoomInvalidInput
	}
	var current string
	err = tx.QueryRow(`SELECT virtual_ip FROM room_devices WHERE room_id = ? AND device_id = ?`, room.ID, deviceID).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	available := func(ip netip.Addr) (bool, error) {
		bytes := ip.As4()
		if !prefix.Contains(ip) || bytes[3] == 0 || bytes[3] == 255 {
			return false, nil
		}
		if ip.String() == current {
			return true, nil
		}
		var used int
		err := tx.QueryRow(`SELECT
			(SELECT COUNT(*) FROM room_devices WHERE room_id = ? AND virtual_ip = ?) +
			(SELECT COUNT(*) FROM room_ip_holds WHERE room_id = ? AND virtual_ip = ? AND reusable_after > ?)`, room.ID, ip.String(), room.ID, ip.String(), time.Now().Unix()).Scan(&used)
		return used == 0, err
	}
	if requested != "" {
		ip, err := netip.ParseAddr(requested)
		if err != nil || !ip.Is4() {
			return "", ErrRoomInvalidInput
		}
		ok, err := available(ip)
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrRoomIPUnavailable
		}
		return ip.String(), nil
	}
	if current != "" {
		return current, nil
	}
	for ip := prefix.Masked().Addr().Next(); prefix.Contains(ip); ip = ip.Next() {
		ok, err := available(ip)
		if err != nil {
			return "", err
		}
		if ok {
			return ip.String(), nil
		}
	}
	return "", ErrRoomIPUnavailable
}

func (db *DB) EnableRoomDevice(userID, id, deviceID string) (string, error) {
	tx, err := db.beginRoomTx()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	room, err := requireRoomMember(tx, id, userID, false)
	if err != nil {
		return "", err
	}
	var ownerID, networkID string
	err = tx.QueryRow(`SELECT user_id, network_id FROM devices WHERE id = ?`, deviceID).Scan(&ownerID, &networkID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && ownerID != userID) {
		return "", ErrRoomForbidden
	}
	if err != nil {
		return "", err
	}
	if networkID != "default" {
		return "", ErrRoomUnsupportedNetwork
	}
	ip, err := allocateRoomIP(tx, room, "", deviceID)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`INSERT INTO room_devices(room_id, device_id, user_id, virtual_ip, created_at) VALUES(?, ?, ?, ?, ?)
		ON CONFLICT(room_id, device_id) DO NOTHING`, id, deviceID, userID, ip, time.Now().Unix()); err != nil {
		return "", err
	}
	if err := bumpRoomRevision(tx, id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return ip, nil
}

func (db *DB) AssignRoomDeviceIP(userID, id, deviceID, requested string) (string, error) {
	if requested == "" {
		return "", ErrRoomInvalidInput
	}
	tx, err := db.beginRoomTx()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	room, err := requireRoomMember(tx, id, userID, true)
	if err != nil {
		return "", err
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM room_devices WHERE room_id = ? AND device_id = ?`, id, deviceID).Scan(&count); err != nil {
		return "", err
	}
	if count == 0 {
		return "", ErrRoomNotFound
	}
	ip, err := allocateRoomIP(tx, room, requested, deviceID)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`UPDATE room_devices SET virtual_ip = ? WHERE room_id = ? AND device_id = ?`, ip, id, deviceID); err != nil {
		return "", err
	}
	if err := bumpRoomRevision(tx, id); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return ip, nil
}

func (db *DB) DisableRoomDevice(userID, id, deviceID string) error {
	tx, err := db.beginRoomTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	room, err := requireRoomMember(tx, id, userID, false)
	if err != nil {
		return err
	}
	var deviceOwnerID string
	err = tx.QueryRow(`SELECT user_id FROM room_devices WHERE room_id = ? AND device_id = ?`, id, deviceID).Scan(&deviceOwnerID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRoomNotFound
	}
	if err != nil {
		return err
	}
	if userID != room.OwnerID && userID != deviceOwnerID {
		return ErrRoomForbidden
	}
	if _, err := tx.Exec(`DELETE FROM room_devices WHERE room_id = ? AND device_id = ?`, id, deviceID); err != nil {
		return err
	}
	if err := bumpRoomRevision(tx, id); err != nil {
		return err
	}
	if err := purgeUnauthorizedRoomSignals(tx); err != nil {
		return err
	}
	return tx.Commit()
}
