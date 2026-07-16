// Package database provides the SQLite-backed persistence layer.
package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the sql.DB connection.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database and runs migrations.
func New(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return &DB{db}, nil
}

func migrate(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id          TEXT PRIMARY KEY,
		email       TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS networks (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL,
		cidr        TEXT NOT NULL DEFAULT '10.20.0.0/16',
		owner_id    TEXT NOT NULL REFERENCES users(id),
		created_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS devices (
		id          TEXT PRIMARY KEY,
		user_id     TEXT NOT NULL REFERENCES users(id),
		network_id  TEXT NOT NULL REFERENCES networks(id),
		public_key  TEXT NOT NULL,
		device_name TEXT NOT NULL,
		platform    TEXT NOT NULL DEFAULT '',
		virtual_ip  TEXT NOT NULL DEFAULT '',
		nat_type    TEXT NOT NULL DEFAULT '',
		endpoint    TEXT NOT NULL DEFAULT '',
		last_seen   INTEGER NOT NULL DEFAULT 0,
		online      INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS tunnels (
		id            TEXT PRIMARY KEY,
		device_id     TEXT NOT NULL REFERENCES devices(id),
		protocol      TEXT NOT NULL DEFAULT 'tcp',
		local_port    INTEGER NOT NULL,
		remote_port   INTEGER NOT NULL,
		local_address TEXT NOT NULL DEFAULT '127.0.0.1',
		public_endpoint TEXT NOT NULL DEFAULT '',
		active        INTEGER NOT NULL DEFAULT 0,
		created_at    INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_devices_network ON devices(network_id);
	CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);
	`

	_, err := db.Exec(schema)
	return err
}

// ---- User operations ----

// User represents a registered user.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	CreatedAt    int64  `json:"created_at"`
}

// CreateUser inserts a new user.
func (db *DB) CreateUser(email, passwordHash string) (*User, error) {
	id := fmt.Sprintf("user-%d", time.Now().UnixNano())
	now := time.Now().Unix()

	_, err := db.Exec(`INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)`,
		id, email, passwordHash, now)
	if err != nil {
		return nil, err
	}

	return &User{ID: id, Email: email, PasswordHash: passwordHash, CreatedAt: now}, nil
}

// GetUserByEmail looks up a user by email.
func (db *DB) GetUserByEmail(email string) (*User, error) {
	var u User
	err := db.QueryRow(`SELECT id, email, password_hash, created_at FROM users WHERE email = ?`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ---- Device operations ----

// Device represents a registered device/node.
type Device struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	NetworkID  string `json:"network_id"`
	PublicKey  string `json:"public_key"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
	VirtualIP  string `json:"virtual_ip"`
	NATType    string `json:"nat_type"`
	Endpoint   string `json:"endpoint"`
	LastSeen   int64  `json:"last_seen"`
	Online     bool   `json:"online"`
	CreatedAt  int64  `json:"created_at"`
}

// CreateDevice inserts a new device and assigns a virtual IP.
func (db *DB) CreateDevice(userID, networkID, publicKey, deviceName, platform string) (*Device, error) {
	id := fmt.Sprintf("node-%s", publicKey[:16])
	now := time.Now().Unix()

	// Assign virtual IP (simple: find next available in 10.20.x.x range)
	virtualIP, err := db.assignVirtualIP(networkID)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, last_seen, online, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)`,
		id, userID, networkID, publicKey, deviceName, platform, virtualIP, now, now)
	if err != nil {
		return nil, err
	}

	return &Device{
		ID: id, UserID: userID, NetworkID: networkID,
		PublicKey: publicKey, DeviceName: deviceName, Platform: platform,
		VirtualIP: virtualIP, LastSeen: now, Online: true, CreatedAt: now,
	}, nil
}

// assignVirtualIP finds the next available virtual IP in a network.
func (db *DB) assignVirtualIP(networkID string) (string, error) {
	// Simple: count existing devices, assign 10.20.0.(N+2)
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM devices WHERE network_id = ?`, networkID).Scan(&count)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("10.20.0.%d", count+2), nil
}

// ListDevicesByNetwork returns all devices in a network.
func (db *DB) ListDevicesByNetwork(networkID string) ([]Device, error) {
	rows, err := db.Query(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, last_seen, online, created_at
		FROM devices WHERE network_id = ?`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var online int
		if err := rows.Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &d.LastSeen, &online, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.Online = online == 1
		devices = append(devices, d)
	}
	return devices, nil
}

// UpdateDeviceEndpoint updates a device's endpoint and NAT type.
func (db *DB) UpdateDeviceEndpoint(deviceID, endpoint, natType string) error {
	_, err := db.Exec(`UPDATE devices SET endpoint = ?, nat_type = ?, last_seen = ?, online = 1 WHERE id = ?`,
		endpoint, natType, time.Now().Unix(), deviceID)
	return err
}

// DeleteDevice removes a device.
func (db *DB) DeleteDevice(deviceID string) error {
	_, err := db.Exec(`DELETE FROM devices WHERE id = ?`, deviceID)
	return err
}

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

// CreateTunnel inserts a new port mapping.
func (db *DB) CreateTunnel(deviceID, protocol string, localPort, remotePort int, localAddr string) (*Tunnel, error) {
	id := fmt.Sprintf("tunnel-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	publicEndpoint := fmt.Sprintf("relay.p2pnet.io:%d", remotePort)

	_, err := db.Exec(`INSERT INTO tunnels (id, device_id, protocol, local_port, remote_port, local_address, public_endpoint, active, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)`,
		id, deviceID, protocol, localPort, remotePort, localAddr, publicEndpoint, now)
	if err != nil {
		return nil, err
	}

	return &Tunnel{
		ID: id, DeviceID: deviceID, Protocol: protocol,
		LocalPort: localPort, RemotePort: remotePort, LocalAddress: localAddr,
		PublicEndpoint: publicEndpoint, Active: true, CreatedAt: now,
	}, nil
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
