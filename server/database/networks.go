package database

import (
	"fmt"
	"net"
	"time"
)

// ---- Network membership operations ----

// CreateNetworkMembership adds a user to a network.
func (db *DB) CreateNetworkMembership(userID, networkID, role string) (*NetworkMembership, error) {
	id := fmt.Sprintf("mem-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	_, err := db.Exec(`INSERT OR IGNORE INTO network_memberships (id, user_id, network_id, role, created_at)
        VALUES (?, ?, ?, ?, ?)`, id, userID, networkID, role, now)
	if err != nil {
		return nil, err
	}
	return &NetworkMembership{
		ID: id, UserID: userID, NetworkID: networkID,
		Role: role, CreatedAt: now,
	}, nil
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

// DeviceAccessibleByUser checks ownership or network membership access.
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
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		return nil, fmt.Errorf("invalid cidr: %w", err)
	}
	id := fmt.Sprintf("net-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	_, err := db.Exec(`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES (?, ?, ?, ?, ?)`,
		id, name, cidr, ownerID, now)
	if err != nil {
		return nil, err
	}
	if _, err := db.CreateNetworkMembership(ownerID, id, "owner"); err != nil {
		return nil, err
	}
	return &Network{ID: id, Name: name, CIDR: cidr, OwnerID: ownerID, CreatedAt: now}, nil
}
