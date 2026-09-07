package database

import (
	"database/sql"
	"errors"
	"time"
)

const activeRoomPair = `SELECT 1 FROM room_devices a
	JOIN room_devices b ON b.room_id = a.room_id
	JOIN rooms r ON r.id = a.room_id AND r.deleted_at = 0
	JOIN room_members ma ON ma.room_id = a.room_id AND ma.user_id = a.user_id AND ma.banned = 0
	JOIN room_members mb ON mb.room_id = b.room_id AND mb.user_id = b.user_id AND mb.banned = 0
	JOIN room_client_leases ca ON ca.device_id = a.device_id
	JOIN room_client_leases cb ON cb.device_id = b.device_id
	WHERE a.device_id = ? AND b.device_id = ? AND ca.refreshed_at > ? AND cb.refreshed_at > ? LIMIT 1`

func (db *DB) DevicesShareRoom(from, to string) (bool, error) {
	var found int
	cutoff := time.Now().Unix() - RoomClientLeaseSeconds
	err := db.QueryRow(activeRoomPair, from, to, cutoff, cutoff).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func purgeUnauthorizedRoomSignals(tx *sql.Tx) error {
	cutoff := time.Now().Unix() - RoomClientLeaseSeconds
	_, err := tx.Exec(`DELETE FROM signals WHERE EXISTS (
		SELECT 1 FROM devices f JOIN devices t ON t.id = signals.to_node_id
		WHERE f.id = signals.from_node_id AND f.user_id <> t.user_id AND NOT EXISTS (
			SELECT 1 FROM room_devices a JOIN room_devices b ON b.room_id = a.room_id
			JOIN rooms r ON r.id = a.room_id AND r.deleted_at = 0
			JOIN room_members ma ON ma.room_id = a.room_id AND ma.user_id = a.user_id AND ma.banned = 0
			JOIN room_members mb ON mb.room_id = b.room_id AND mb.user_id = b.user_id AND mb.banned = 0
			JOIN room_client_leases ca ON ca.device_id = a.device_id
			JOIN room_client_leases cb ON cb.device_id = b.device_id
			WHERE a.device_id = f.id AND b.device_id = t.id AND ca.refreshed_at > ? AND cb.refreshed_at > ?
		)
	)`, cutoff, cutoff)
	return err
}

func (db *DB) GetRoomRoster(deviceID string) (RoomRoster, error) {
	result := RoomRoster{
		ProtocolVersion: 1,
		LeaseSeconds: RoomLeaseSeconds,
		LocalAddresses: []RoomAddress{},
		PrivatePeerIDs: []string{},
		Grants: []RoomPeerGrant{},
		Nodes: []Device{},
	}
	tx, err := db.beginRoomTx()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	var userID, networkID string
	if err := tx.QueryRow(`SELECT user_id, network_id FROM devices WHERE id = ?`, deviceID).Scan(&userID, &networkID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, ErrRoomForbidden
		}
		return result, err
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT INTO room_client_leases(device_id, refreshed_at) VALUES(?, ?)
		ON CONFLICT(device_id) DO UPDATE SET refreshed_at = excluded.refreshed_at`, deviceID, now); err != nil {
		return result, err
	}
	rows, err := tx.Query(`SELECT r.id, r.cidr, rd.virtual_ip FROM room_devices rd
		JOIN rooms r ON r.id = rd.room_id AND r.deleted_at = 0
		JOIN room_members m ON m.room_id = rd.room_id AND m.user_id = rd.user_id AND m.banned = 0
		WHERE rd.device_id = ? ORDER BY r.id`, deviceID)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var address RoomAddress
		if err := rows.Scan(&address.RoomID, &address.CIDR, &address.VirtualIP); err != nil {
			rows.Close()
			return result, err
		}
		result.LocalAddresses = append(result.LocalAddresses, address)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	rows, err = tx.Query(`SELECT b.room_id, b.device_id, b.virtual_ip FROM room_devices a
		JOIN room_devices b ON b.room_id = a.room_id AND b.device_id <> a.device_id
		JOIN rooms r ON r.id = a.room_id AND r.deleted_at = 0
		JOIN room_members ma ON ma.room_id = a.room_id AND ma.user_id = a.user_id AND ma.banned = 0
		JOIN room_members mb ON mb.room_id = b.room_id AND mb.user_id = b.user_id AND mb.banned = 0
		JOIN room_client_leases cb ON cb.device_id = b.device_id AND cb.refreshed_at > ?
		WHERE a.device_id = ? ORDER BY b.room_id, b.device_id`, now-RoomClientLeaseSeconds, deviceID)
	if err != nil {
		return result, err
	}
	roomPeerIPs := map[string]string{}
	for rows.Next() {
		var grant RoomPeerGrant
		if err := rows.Scan(&grant.RoomID, &grant.NodeID, &grant.VirtualIP); err != nil {
			rows.Close()
			return result, err
		}
		result.Grants = append(result.Grants, grant)
		if _, exists := roomPeerIPs[grant.NodeID]; !exists {
			roomPeerIPs[grant.NodeID] = grant.VirtualIP
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	rows, err = tx.Query(`SELECT d.id, d.user_id, d.network_id, d.public_key, d.device_name, d.platform,
		d.virtual_ip, d.nat_type, d.endpoint, d.relay_rtt_ms, d.last_seen, COALESCE(d.app_version, ''), d.online, d.created_at
		FROM devices d WHERE d.id <> ? AND ((d.user_id = ? AND d.network_id = ?) OR EXISTS (
			SELECT 1 FROM room_devices a JOIN room_devices b ON b.room_id = a.room_id
			JOIN rooms r ON r.id = a.room_id AND r.deleted_at = 0
			JOIN room_members ma ON ma.room_id = a.room_id AND ma.user_id = a.user_id AND ma.banned = 0
			JOIN room_members mb ON mb.room_id = b.room_id AND mb.user_id = b.user_id AND mb.banned = 0
			JOIN room_client_leases cb ON cb.device_id = b.device_id AND cb.refreshed_at > ?
			WHERE a.device_id = ? AND b.device_id = d.id
		)) ORDER BY d.id`, deviceID, userID, networkID, now-RoomClientLeaseSeconds, deviceID)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var device Device
		var rtt sql.NullInt64
		if err := rows.Scan(&device.ID, &device.UserID, &device.NetworkID, &device.PublicKey, &device.DeviceName, &device.Platform,
			&device.VirtualIP, &device.NATType, &device.Endpoint, &rtt, &device.LastSeen, &device.AppVersion, &device.Online, &device.CreatedAt); err != nil {
			rows.Close()
			return result, err
		}
		if rtt.Valid {
			value := rtt.Int64
			device.RelayRTTMS = &value
		}
		device.Online = device.Online && device.LastSeen > 0 && now-device.LastSeen <= DeviceOnlineTTL
		if device.UserID == userID && device.NetworkID == networkID {
			result.PrivatePeerIDs = append(result.PrivatePeerIDs, device.ID)
		} else {
			ip, exists := roomPeerIPs[device.ID]
			if !exists {
				rows.Close()
				return result, ErrRoomForbidden
			}
			device.VirtualIP = ip
		}
		result.Nodes = append(result.Nodes, device)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}
