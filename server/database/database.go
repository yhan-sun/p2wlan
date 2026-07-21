// Package database provides the SQLite-backed persistence layer.
package database

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB connection.
type DB struct {
	*sql.DB
}

// New opens (or creates) the SQLite database and runs migrations.
func New(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA journal_mode = WAL;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable wal mode: %w", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout = 5000;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set busy timeout: %w", err)
	}
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
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

	CREATE TABLE IF NOT EXISTS signals (
		id          TEXT PRIMARY KEY,
		from_node_id TEXT NOT NULL,
		to_node_id   TEXT NOT NULL,
		type        TEXT NOT NULL,
		candidates  TEXT NOT NULL DEFAULT '[]',
		candidate_sources TEXT NOT NULL DEFAULT '{}',
		handshake   TEXT NOT NULL DEFAULT '',
		punch_at_ms INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
	CREATE INDEX IF NOT EXISTS idx_devices_network ON devices(network_id);
	CREATE INDEX IF NOT EXISTS idx_tunnels_device ON tunnels(device_id);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_tunnels_protocol_remote_port ON tunnels(protocol, remote_port);
	CREATE INDEX IF NOT EXISTS idx_signals_to_node ON signals(to_node_id, created_at);

	CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_net_ip ON devices(network_id, virtual_ip);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_net_pubkey ON devices(network_id, public_key);

	-- Stage 2: authorization and device identity
	CREATE TABLE IF NOT EXISTS device_challenges (
		id          TEXT PRIMARY KEY,
		device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		challenge   BLOB NOT NULL,
		expires_at  INTEGER NOT NULL,
		consumed    INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
	);
	CREATE INDEX IF NOT EXISTS idx_dev_chan_device ON device_challenges(device_id);
	CREATE INDEX IF NOT EXISTS idx_dev_chan_expires ON device_challenges(expires_at);

	CREATE TABLE IF NOT EXISTS device_credentials (
		id          TEXT PRIMARY KEY,
		device_id   TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		token_hash  BLOB NOT NULL,
		expires_at  INTEGER NOT NULL,
		revoked     INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now'))
	);
	CREATE INDEX IF NOT EXISTS idx_dev_cred_device ON device_credentials(device_id);
	CREATE INDEX IF NOT EXISTS idx_dev_cred_hash ON device_credentials(token_hash);
	CREATE INDEX IF NOT EXISTS idx_dev_cred_expires ON device_credentials(expires_at);

	CREATE TABLE IF NOT EXISTS network_memberships (
		id          TEXT PRIMARY KEY,
		user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		network_id  TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
		role        TEXT NOT NULL DEFAULT 'member',
		created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now')),
		UNIQUE(user_id, network_id)
	);
	CREATE INDEX IF NOT EXISTS idx_net_mem_user ON network_memberships(user_id);
	CREATE INDEX IF NOT EXISTS idx_net_mem_network ON network_memberships(network_id);

	-- Add ed25519_public_key column to existing devices (IF NOT EXISTS is handled via ALTER IGNORE)
	`

	if _, err := db.Exec(schema); err != nil {
		return err
	}

	_, _ = db.Exec(`ALTER TABLE devices ADD COLUMN ed25519_public_key TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN candidate_sources TEXT NOT NULL DEFAULT '{}'`)
	_, _ = db.Exec(`ALTER TABLE signals ADD COLUMN punch_at_ms INTEGER NOT NULL DEFAULT 0`)

	// Insert default system user and network to satisfy foreign keys,
	// then grant the system user membership to the default network.
	initData := `
	INSERT OR IGNORE INTO users (id, email, password_hash, created_at)
	VALUES ('system', 'system@p2wlan.local', '', 0);

	INSERT OR IGNORE INTO networks (id, name, cidr, owner_id, created_at)
	VALUES ('default', 'Default Network', '10.20.0.0/16', 'system', 0);

	INSERT OR IGNORE INTO network_memberships (id, user_id, network_id, role)
	VALUES ('mem-default-system', 'system', 'default', 'owner');
	`
	_, err := db.Exec(initData)
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

// Network represents a virtual network.
type Network struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CIDR      string `json:"cidr"`
	OwnerID   string `json:"owner_id"`
	CreatedAt int64  `json:"created_at"`
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

	// Auto-join the user to the default network (for backward compatibility)
	db.CreateNetworkMembership(id, "default", "member")
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

// ---- Authorization types ----

// DeviceChallenge represents a one-time challenge for device identity verification.
type DeviceChallenge struct {
	ID        string `json:"id"`
	DeviceID  string `json:"device_id"`
	Challenge []byte `json:"challenge"`
	ExpiresAt int64  `json:"expires_at"`
	Consumed  bool   `json:"consumed"`
	CreatedAt int64  `json:"created_at"`
}

// DeviceCredential represents a device-specific authentication token.
type DeviceCredential struct {
	ID        string `json:"id"`
	DeviceID  string `json:"device_id"`
	TokenHash []byte `json:"-"`
	ExpiresAt int64  `json:"expires_at"`
	Revoked   bool   `json:"revoked"`
	CreatedAt int64  `json:"created_at"`
}

// NetworkMembership links a user to a network.
type NetworkMembership struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	NetworkID string `json:"network_id"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
}

// ---- Challenge operations ----

// CreateChallenge generates a new device challenge.
func (db *DB) CreateChallenge(deviceID string, challenge []byte, expiresAt int64) (*DeviceChallenge, error) {
	id := fmt.Sprintf("challenge-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	_, err := db.Exec(`INSERT INTO device_challenges (id, device_id, challenge, expires_at, consumed, created_at)
        VALUES (?, ?, ?, ?, 0, ?)`, id, deviceID, challenge, expiresAt, now)
	if err != nil {
		return nil, err
	}
	return &DeviceChallenge{
		ID: id, DeviceID: deviceID, Challenge: challenge,
		ExpiresAt: expiresAt, Consumed: false, CreatedAt: now,
	}, nil
}

// GetChallenge retrieves a challenge by ID.
func (db *DB) GetChallenge(challengeID string) (*DeviceChallenge, error) {
	var c DeviceChallenge
	var consumed int
	err := db.QueryRow(`SELECT id, device_id, challenge, expires_at, consumed, created_at
        FROM device_challenges WHERE id = ?`, challengeID).
		Scan(&c.ID, &c.DeviceID, &c.Challenge, &c.ExpiresAt, &consumed, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.Consumed = consumed == 1
	return &c, nil
}

// ConsumeChallenge marks a challenge as consumed (one-time use).
func (db *DB) ConsumeChallenge(challengeID string) error {
	_, err := db.Exec(`UPDATE device_challenges SET consumed = 1 WHERE id = ?`, challengeID)
	return err
}

// ---- Credential operations ----

// CreateDeviceCredential creates a new device credential and returns the credential
// record along with the raw token. The token is only returned once; only its hash is stored.
func (db *DB) CreateDeviceCredential(deviceID string, ttlSec int64) (*DeviceCredential, string, error) {
	rawBytes := make([]byte, 32)
	if _, err := rand.Read(rawBytes); err != nil {
		return nil, "", fmt.Errorf("generate credential token: %w", err)
	}
	rawToken := "dc-" + hex.EncodeToString(rawBytes)
	hash := hashToken(rawToken)
	id := fmt.Sprintf("cred-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	expires := now + ttlSec

	_, err := db.Exec(`INSERT INTO device_credentials (id, device_id, token_hash, expires_at, revoked, created_at)
		VALUES (?, ?, ?, ?, 0, ?)`, id, deviceID, hash, expires, now)
	if err != nil {
		return nil, "", err
	}

	return &DeviceCredential{
		ID: id, DeviceID: deviceID, TokenHash: hash,
		ExpiresAt: expires, Revoked: false, CreatedAt: now,
	}, rawToken, nil
}

// ValidateDeviceCredential validates a credential token and returns the credential and device.
func (db *DB) ValidateDeviceCredential(token string) (*DeviceCredential, *Device, error) {
	hash := hashToken(token)

	var cred DeviceCredential
	var revoked int
	err := db.QueryRow(`SELECT id, device_id, token_hash, expires_at, revoked, created_at
		FROM device_credentials WHERE token_hash = ?`, hash).
		Scan(&cred.ID, &cred.DeviceID, &cred.TokenHash, &cred.ExpiresAt, &revoked, &cred.CreatedAt)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid credential: %w", err)
	}
	cred.Revoked = revoked == 1

	if cred.Revoked {
		return nil, nil, fmt.Errorf("credential revoked")
	}
	if time.Now().Unix() > cred.ExpiresAt {
		return nil, nil, fmt.Errorf("credential expired")
	}

	device, err := db.GetDevice(cred.DeviceID)
	if err != nil {
		return nil, nil, fmt.Errorf("device not found: %w", err)
	}

	return &cred, device, nil
}

// RevokeDeviceCredential revokes a device credential.
func (db *DB) RevokeDeviceCredential(credentialID string) error {
	_, err := db.Exec(`UPDATE device_credentials SET revoked = 1 WHERE id = ?`, credentialID)
	return err
}

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

// GetDevice retrieves a device by ID.
func (db *DB) GetDevice(deviceID string) (*Device, error) {
	var d Device
	var online int
	err := db.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, last_seen, online, created_at, COALESCE(ed25519_public_key, '')
		FROM devices WHERE id = ?`, deviceID).
		Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &d.LastSeen, &online, &d.CreatedAt, &d.Ed25519PublicKey)
	if err != nil {
		return nil, err
	}
	d.Online = online == 1
	return &d, nil
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

// ---- Device operations ----

// Device represents a registered device/node.
type Device struct {
	ID               string `json:"id"`
	UserID           string `json:"user_id"`
	NetworkID        string `json:"network_id"`
	PublicKey        string `json:"public_key"`
	DeviceName       string `json:"device_name"`
	Platform         string `json:"platform"`
	VirtualIP        string `json:"virtual_ip"`
	NATType          string `json:"nat_type"`
	Endpoint         string `json:"endpoint"`
	LastSeen         int64  `json:"last_seen"`
	Online           bool   `json:"online"`
	Ed25519PublicKey string `json:"ed25519_public_key,omitempty"`
	CreatedAt        int64  `json:"created_at"`
}

// CreateDevice inserts a new device and assigns a virtual IP.
func (db *DB) CreateDevice(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey string) (*Device, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var existing Device
	var online int
	err = tx.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, last_seen, online, created_at
		FROM devices WHERE public_key = ? LIMIT 1`, publicKey).
		Scan(&existing.ID, &existing.UserID, &existing.NetworkID, &existing.PublicKey, &existing.DeviceName, &existing.Platform,
			&existing.VirtualIP, &existing.NATType, &existing.Endpoint, &existing.LastSeen, &online, &existing.CreatedAt)
	if err == nil {
		if existing.UserID != userID {
			return nil, fmt.Errorf("public key is already registered by another user")
		}
		if existing.NetworkID != networkID {
			return nil, fmt.Errorf("public key is already registered in another network")
		}

		now := time.Now().Unix()
		_, err = tx.Exec(`UPDATE devices SET device_name = ?, platform = ?, last_seen = ?, online = 1, ed25519_public_key = CASE WHEN ? != '' THEN ? ELSE ed25519_public_key END WHERE id = ?`,
			deviceName, platform, now, ed25519PublicKey, ed25519PublicKey, existing.ID)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}

		existing.DeviceName = deviceName
		existing.Platform = platform
		existing.LastSeen = now
		existing.Online = true
		return &existing, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}

	idSuffix := publicKey
	if len(idSuffix) > 16 {
		idSuffix = idSuffix[:16]
	}
	id := fmt.Sprintf("node-%s-%d", idSuffix, time.Now().UnixNano())
	now := time.Now().Unix()

	virtualIP, err := db.assignVirtualIP(tx, networkID)
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, last_seen, online, created_at, ed25519_public_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id, userID, networkID, publicKey, deviceName, platform, virtualIP, now, now, ed25519PublicKey)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Device{
		ID: id, UserID: userID, NetworkID: networkID,
		PublicKey: publicKey, DeviceName: deviceName, Platform: platform,
		VirtualIP: virtualIP, LastSeen: now, Online: true,
		Ed25519PublicKey: ed25519PublicKey, CreatedAt: now,
	}, nil
}

// GetDeviceByPublicKey looks up a device by network and public key.
func (db *DB) GetDeviceByPublicKey(networkID, publicKey string) (*Device, error) {
	var d Device
	var online int
	err := db.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, last_seen, online, created_at, COALESCE(ed25519_public_key, '')
		FROM devices WHERE network_id = ? AND public_key = ? LIMIT 1`, networkID, publicKey).
		Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &d.LastSeen, &online, &d.CreatedAt, &d.Ed25519PublicKey)
	if err != nil {
		return nil, err
	}
	d.Online = online == 1
	return &d, nil
}

func nextIP(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] > 0 {
			break
		}
	}
	return next
}

// assignVirtualIP finds the next available virtual IP in a network.
func (db *DB) assignVirtualIP(tx *sql.Tx, networkID string) (string, error) {
	var cidr string
	err := tx.QueryRow(`SELECT cidr FROM networks WHERE id = ?`, networkID).Scan(&cidr)
	if err != nil {
		return "", fmt.Errorf("query network cidr: %w", err)
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse network cidr '%s': %w", cidr, err)
	}

	rows, err := tx.Query(`SELECT virtual_ip FROM devices WHERE network_id = ?`, networkID)
	if err != nil {
		return "", fmt.Errorf("query allocated IPs: %w", err)
	}
	defer rows.Close()

	allocated := make(map[string]bool)
	for rows.Next() {
		var vip string
		if err := rows.Scan(&vip); err != nil {
			return "", err
		}
		allocated[vip] = true
	}

	curr := nextIP(ipnet.IP) // Network Address (skip)
	curr = nextIP(curr)      // Start from .2

	broadcast := make(net.IP, len(ipnet.IP))
	for i := range broadcast {
		broadcast[i] = ipnet.IP[i] | ^ipnet.Mask[i]
	}

	for ipnet.Contains(curr) {
		if curr.Equal(broadcast) {
			break
		}
		ipStr := curr.String()
		if !allocated[ipStr] {
			return ipStr, nil
		}
		curr = nextIP(curr)
	}

	return "", fmt.Errorf("IP address pool exhausted for network %s", networkID)
}

// DeviceOnlineTTL is how long a device remains "online" without a last_seen update.
// Defaults to 90 seconds — a few missed heartbeats of the typical 5–15s poll interval.
const DeviceOnlineTTL = 90

// ListDevicesByNetwork returns all devices in a network.
// Devices whose last_seen is older than DeviceOnlineTTL are reported as offline
// even if the online flag is still set (lease / TTL semantics).
func (db *DB) ListDevicesByNetwork(networkID string) ([]Device, error) {
	now := time.Now().Unix()

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
		// Lease semantics: last_seen older than TTL or never seen (0) => offline.
		if online == 1 && d.LastSeen > 0 && now-d.LastSeen <= DeviceOnlineTTL {
			d.Online = true
		} else {
			d.Online = false
		}
		devices = append(devices, d)
	}
	return devices, nil
}

// MarkStaleDevicesOffline sets online=0 for devices whose last_seen is older than ttlSeconds.
func (db *DB) MarkStaleDevicesOffline(ttlSeconds int64) error {
	cutoff := time.Now().Unix() - ttlSeconds
	_, err := db.Exec(`UPDATE devices SET online = 0 WHERE online = 1 AND last_seen > 0 AND last_seen < ?`, cutoff)
	return err
}

// UpdateDeviceEndpoint updates a device's endpoint and NAT type.
func (db *DB) UpdateDeviceEndpoint(deviceID, endpoint, natType string) error {
	_, err := db.Exec(`UPDATE devices SET endpoint = ?, nat_type = ?, last_seen = ?, online = 1 WHERE id = ?`,
		endpoint, natType, time.Now().Unix(), deviceID)
	return err
}

// UpdateDeviceName changes the user-visible name of a registered device.
func (db *DB) UpdateDeviceName(deviceID, deviceName string) error {
	_, err := db.Exec(`UPDATE devices SET device_name = ? WHERE id = ?`, deviceName, deviceID)
	return err
}

// DeleteDevice removes a device.
func (db *DB) DeleteDevice(deviceID string) error {
	_, err := db.Exec(`DELETE FROM devices WHERE id = ?`, deviceID)
	return err
}

// ---- Signaling operations ----

// Signal represents one queued control-plane signaling message.
type Signal struct {
	ID               string            `json:"id"`
	FromNodeID       string            `json:"from_node_id"`
	ToNodeID         string            `json:"to_node_id"`
	Type             string            `json:"type"`
	Candidates       []string          `json:"candidates"`
	CandidateSources map[string]string `json:"candidate_sources,omitempty"`
	Handshake        string            `json:"handshake"`
	PunchAtMS        int64             `json:"punch_at_ms,omitempty"`
	CreatedAt        int64             `json:"created_at"`
}

const signalTTLSeconds int64 = 120

// CreateSignal queues a signaling message for a target node.
func (db *DB) CreateSignal(fromNodeID, toNodeID, typ string, candidates []string, candidateSources map[string]string, handshake string) (*Signal, error) {
	return db.CreateSignalWithPunchAt(fromNodeID, toNodeID, typ, candidates, candidateSources, handshake, 0)
}

// CreateSignalWithPunchAt queues a signaling message with an optional synchronized punch window.
func (db *DB) CreateSignalWithPunchAt(fromNodeID, toNodeID, typ string, candidates []string, candidateSources map[string]string, handshake string, punchAtMS int64) (*Signal, error) {
	if candidates == nil {
		candidates = []string{}
	}
	if candidateSources == nil {
		candidateSources = map[string]string{}
	}

	candidatesJSON, err := json.Marshal(candidates)
	if err != nil {
		return nil, err
	}
	candidateSourcesJSON, err := json.Marshal(candidateSources)
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("signal-%d", time.Now().UnixNano())
	now := time.Now().Unix()
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if _, err = tx.Exec(`DELETE FROM signals WHERE created_at < ?`, now-signalTTLSeconds); err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`DELETE FROM signals WHERE from_node_id = ? AND to_node_id = ? AND type = ?`, fromNodeID, toNodeID, typ); err != nil {
		return nil, err
	}
	_, err = tx.Exec(`INSERT INTO signals (id, from_node_id, to_node_id, type, candidates, candidate_sources, handshake, punch_at_ms, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, fromNodeID, toNodeID, typ, string(candidatesJSON), string(candidateSourcesJSON), handshake, punchAtMS, now)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Signal{
		ID: id, FromNodeID: fromNodeID, ToNodeID: toNodeID, Type: typ,
		Candidates: candidates, CandidateSources: candidateSources, Handshake: handshake, PunchAtMS: punchAtMS, CreatedAt: now,
	}, nil
}

// ListAndDeleteSignals returns queued messages for a node and deletes them atomically.
func (db *DB) ListAndDeleteSignals(toNodeID string) ([]Signal, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`DELETE FROM signals WHERE created_at < ?`, now-signalTTLSeconds); err != nil {
		return nil, err
	}

	rows, err := tx.Query(`SELECT id, from_node_id, to_node_id, type, candidates, candidate_sources, handshake, punch_at_ms, created_at
		FROM signals WHERE to_node_id = ? AND created_at >= ? ORDER BY created_at ASC`, toNodeID, now-signalTTLSeconds)
	if err != nil {
		return nil, err
	}

	signals := []Signal{}
	for rows.Next() {
		var s Signal
		var candidatesJSON string
		var candidateSourcesJSON string
		if err := rows.Scan(&s.ID, &s.FromNodeID, &s.ToNodeID, &s.Type, &candidatesJSON, &candidateSourcesJSON, &s.Handshake, &s.PunchAtMS, &s.CreatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(candidatesJSON), &s.Candidates); err != nil {
			return nil, err
		}
		if s.Candidates == nil {
			s.Candidates = []string{}
		}
		if err := json.Unmarshal([]byte(candidateSourcesJSON), &s.CandidateSources); err != nil {
			return nil, err
		}
		if s.CandidateSources == nil {
			s.CandidateSources = map[string]string{}
		}
		signals = append(signals, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	if _, err := tx.Exec(`DELETE FROM signals WHERE to_node_id = ?`, toNodeID); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return signals, nil
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

// hashToken returns a SHA-256 hash of an opaque credential token.
func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// ForeignKeysEnabled reports whether SQLite foreign key enforcement is active.
func (db *DB) ForeignKeysEnabled() (bool, error) {
	var enabled int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&enabled); err != nil {
		return false, err
	}
	return enabled == 1, nil
}
