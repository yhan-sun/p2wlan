package database

import (
	"fmt"
	"net/netip"
	"time"
)

// ---- Network membership operations ----

// CreateNetworkMembership adds a user to a network.
func (db *DB) CreateNetworkMembership(userID, networkID, role string) (*NetworkMembership, error) {
	id, err := roomRandomID("mem-", 16)
	if err != nil {
		return nil, fmt.Errorf("generate membership ID: %w", err)
	}
	now := time.Now().Unix()
	_, err = db.Exec(`INSERT INTO network_memberships (id, user_id, network_id, role, created_at)
        VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, network_id) DO NOTHING`, id, userID, networkID, role, now)
	if err != nil {
		return nil, err
	}
	var membership NetworkMembership
	err = db.QueryRow(`SELECT id, user_id, network_id, role, created_at FROM network_memberships
		WHERE user_id = ? AND network_id = ?`, userID, networkID).
		Scan(&membership.ID, &membership.UserID, &membership.NetworkID, &membership.Role, &membership.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &membership, nil
}

// GetUserNetworks returns all networks the user is a member of.
func (db *DB) GetUserNetworks(userID string) ([]Network, error) {
	rows, err := db.Query(`SELECT n.id, n.name, n.cidr, n.owner_id, n.created_at
        FROM networks n
        JOIN network_memberships m ON m.network_id = n.id
        WHERE m.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []Network
	for rows.Next() {
		var n Network
		if err := rows.Scan(&n.ID, &n.Name, &n.CIDR, &n.OwnerID, &n.CreatedAt); err != nil {
			return nil, err
		}
		networks = append(networks, n)
	}
	return networks, nil
}

// UserHasNetworkAccess checks if a user has access to a specific network.
func (db *DB) UserHasNetworkAccess(userID, networkID string) (bool, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM network_memberships
        WHERE user_id = ? AND network_id = ?`, userID, networkID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// DeviceBelongsToUser checks whether the device is owned by the given user.
func (db *DB) DeviceBelongsToUser(deviceID, userID string) (bool, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE id = ? AND user_id = ?`, deviceID, userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// DeviceAccessibleByUser checks ownership or network membership access for
// explicit network-level operations. Account-scoped device listings and
// management must use DeviceBelongsToUser instead.
func (db *DB) DeviceAccessibleByUser(deviceID, userID string) (bool, error) {
	owned, err := db.DeviceBelongsToUser(deviceID, userID)
	if err != nil {
		return false, err
	}
	if owned {
		return true, nil
	}
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM devices d
		JOIN network_memberships m ON m.network_id = d.network_id
		WHERE d.id = ? AND m.user_id = ?`, deviceID, userID).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// CreateNetwork creates a private network owned by the given user.
func (db *DB) CreateNetwork(ownerID, name, cidr string) (*Network, error) {
	if name == "" {
		return nil, fmt.Errorf("network name is required")
	}
	if cidr == "" {
		cidr = "10.20.0.0/16"
	}
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid cidr: %w", err)
	}
	id, err := roomRandomID("net-", 16)
	if err != nil {
		return nil, err
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT cidr FROM room_subnets WHERE network_id IS NOT NULL OR reusable_after > ?`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var reserved string
		if err := rows.Scan(&reserved); err != nil {
			rows.Close()
			return nil, err
		}
		roomPrefix, err := netip.ParsePrefix(reserved)
		if err != nil || roomPrefix.Overlaps(prefix) {
			rows.Close()
			return nil, ErrRoomConflict
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	_, err = tx.Exec(`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, name, cidr, ownerID, now)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES (?, ?, ?, 'owner', ?)`, "mem-"+id, ownerID, id, now); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Network{ID: id, Name: name, CIDR: cidr, OwnerID: ownerID, CreatedAt: now}, nil
}
