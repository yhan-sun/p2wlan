package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---- Tunnel operations ----

// Tunnel represents a port mapping.
type Tunnel struct {
	ID             string `json:"id"`
	DeviceID       string `json:"device_id"`
	Protocol       string `json:"protocol"`
	LocalPort      int    `json:"local_port"`
	RemotePort     int    `json:"remote_port"`
	LocalAddress   string `json:"local_address"`
	PublicEndpoint string `json:"public_endpoint"`
	Active         bool   `json:"active"`
	CreatedAt      int64  `json:"created_at"`
}

const (
	tunnelPortStart = 30000
	tunnelPortEnd   = 60999
)

var (
	// ErrTunnelPortInUse means a requested public port is already allocated.
	ErrTunnelPortInUse = errors.New("tunnel remote port already allocated")
	// ErrTunnelPortExhausted means the automatic public port pool is full.
	ErrTunnelPortExhausted = errors.New("tunnel remote port pool exhausted")
)

// CreateTunnel inserts a new port mapping.
func (db *DB) CreateTunnel(deviceID, protocol string, localPort, remotePort int, localAddr string) (*Tunnel, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	id := fmt.Sprintf("tunnel-%d", time.Now().UnixNano())
	now := time.Now().Unix()

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if remotePort == 0 {
		remotePort, err = db.allocateTunnelPort(tx, protocol)
		if err != nil {
			return nil, err
		}
	} else {
		inUse, err := db.tunnelPortInUse(tx, protocol, remotePort)
		if err != nil {
			return nil, err
		}
		if inUse {
			return nil, ErrTunnelPortInUse
		}
	}

	publicEndpoint := fmt.Sprintf("relay.p2pnet.io:%d", remotePort)

	_, err = tx.Exec(`INSERT INTO tunnels (id, device_id, protocol, local_port, remote_port, local_address, public_endpoint, active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
		id, deviceID, protocol, localPort, remotePort, localAddr, publicEndpoint, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Tunnel{
		ID: id, DeviceID: deviceID, Protocol: protocol,
		LocalPort: localPort, RemotePort: remotePort, LocalAddress: localAddr,
		PublicEndpoint: publicEndpoint, Active: true, CreatedAt: now,
	}, nil
}

func (db *DB) allocateTunnelPort(tx *sql.Tx, protocol string) (int, error) {
	rows, err := tx.Query(`SELECT remote_port FROM tunnels WHERE protocol = ? AND remote_port BETWEEN ? AND ? ORDER BY remote_port`,
		protocol, tunnelPortStart, tunnelPortEnd)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	next := tunnelPortStart
	for rows.Next() {
		var used int
		if err := rows.Scan(&used); err != nil {
			return 0, err
		}
		if used < next {
			continue
		}
		if used == next {
			next++
			continue
		}
		if used > next {
			return next, nil
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if next > tunnelPortEnd {
		return 0, ErrTunnelPortExhausted
	}
	return next, nil
}

func (db *DB) tunnelPortInUse(tx *sql.Tx, protocol string, remotePort int) (bool, error) {
	var existing int
	err := tx.QueryRow(`SELECT 1 FROM tunnels WHERE protocol = ? AND remote_port = ? LIMIT 1`, protocol, remotePort).Scan(&existing)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetTunnel retrieves a tunnel by ID.
func (db *DB) GetTunnel(tunnelID string) (*Tunnel, error) {
	var t Tunnel
	var active int
	err := db.QueryRow(`SELECT id, device_id, protocol, local_port, remote_port, local_address, public_endpoint, active, created_at
		FROM tunnels WHERE id = ?`, tunnelID).
		Scan(&t.ID, &t.DeviceID, &t.Protocol, &t.LocalPort, &t.RemotePort,
			&t.LocalAddress, &t.PublicEndpoint, &active, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	t.Active = active == 1
	return &t, nil
}

// DeleteTunnel removes a port mapping.
func (db *DB) DeleteTunnel(tunnelID string) error {
	_, err := db.Exec(`DELETE FROM tunnels WHERE id = ?`, tunnelID)
	return err
}

// ListTunnelsByDevice returns all tunnels for a device.
func (db *DB) ListTunnelsByDevice(deviceID string) ([]Tunnel, error) {
	rows, err := db.Query(`SELECT id, device_id, protocol, local_port, remote_port, local_address, public_endpoint, active, created_at
		FROM tunnels WHERE device_id = ?`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tunnels []Tunnel
	for rows.Next() {
		var t Tunnel
		var active int
		if err := rows.Scan(&t.ID, &t.DeviceID, &t.Protocol, &t.LocalPort, &t.RemotePort,
			&t.LocalAddress, &t.PublicEndpoint, &active, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.Active = active == 1
		tunnels = append(tunnels, t)
	}
	return tunnels, nil
}
