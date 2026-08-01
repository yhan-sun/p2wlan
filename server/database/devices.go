package database

import (
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"
)

// GetDevice retrieves a device by ID.
func (db *DB) GetDevice(deviceID string) (*Device, error) {
	var d Device
	var online int
	var relayRTTMS sql.NullInt64
	err := db.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at, COALESCE(ed25519_public_key, '')
		FROM devices WHERE id = ?`, deviceID).
		Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &relayRTTMS, &d.LastSeen, &d.AppVersion, &online, &d.CreatedAt, &d.Ed25519PublicKey)
	if err != nil {
		return nil, err
	}
	d.Online = online == 1
	d.RelayRTTMS = nullInt64Ptr(relayRTTMS)
	return &d, nil
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
	RelayRTTMS       *int64 `json:"relay_rtt_ms,omitempty"`
	LastSeen         int64  `json:"last_seen"`
	AppVersion       string `json:"app_version"`
	Online           bool   `json:"online"`
	Ed25519PublicKey string `json:"ed25519_public_key,omitempty"`
	CreatedAt        int64  `json:"created_at"`
}

func nullInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

// CreateDevice inserts a new device and assigns a virtual IP.
func (db *DB) CreateDevice(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey string) (*Device, error) {
	return db.CreateDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, "", "")
}

// CreateDeviceWithOptions inserts or updates a device with optional runtime metadata.
func (db *DB) CreateDeviceWithOptions(userID, networkID, publicKey, deviceName, platform, ed25519PublicKey, requestedVirtualIP, appVersion string) (*Device, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var existing Device
	var online int
	var existingRelayRTTMS sql.NullInt64
	err = tx.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at
		FROM devices WHERE public_key = ? LIMIT 1`, publicKey).
		Scan(&existing.ID, &existing.UserID, &existing.NetworkID, &existing.PublicKey, &existing.DeviceName, &existing.Platform,
			&existing.VirtualIP, &existing.NATType, &existing.Endpoint, &existingRelayRTTMS, &existing.LastSeen, &existing.AppVersion, &online, &existing.CreatedAt)
	if err == nil {
		if existing.UserID != userID {
			return nil, fmt.Errorf("public key is already registered by another user")
		}
		if existing.NetworkID != networkID {
			return nil, fmt.Errorf("public key is already registered in another network")
		}

		virtualIP := existing.VirtualIP
		if strings.TrimSpace(requestedVirtualIP) != "" && requestedVirtualIP != existing.VirtualIP {
			virtualIP, err = db.reserveVirtualIP(tx, networkID, requestedVirtualIP, existing.ID)
			if err != nil {
				return nil, err
			}
		}

		now := time.Now().Unix()
		_, err = tx.Exec(`UPDATE devices SET device_name = ?, platform = ?, virtual_ip = ?, app_version = CASE WHEN ? != '' THEN ? ELSE app_version END, last_seen = ?, online = 1, ed25519_public_key = CASE WHEN ? != '' THEN ? ELSE ed25519_public_key END WHERE id = ?`,
			deviceName, platform, virtualIP, appVersion, appVersion, now, ed25519PublicKey, ed25519PublicKey, existing.ID)
		if err != nil {
			return nil, err
		}
		if err := tx.Commit(); err != nil {
			return nil, err
		}

		existing.DeviceName = deviceName
		existing.Platform = platform
		existing.VirtualIP = virtualIP
		if appVersion != "" {
			existing.AppVersion = appVersion
		}
		existing.RelayRTTMS = nullInt64Ptr(existingRelayRTTMS)
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

	virtualIP, err := db.reserveVirtualIP(tx, networkID, requestedVirtualIP, "")
	if err != nil {
		return nil, err
	}

	_, err = tx.Exec(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, app_version, last_seen, online, created_at, ed25519_public_key)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`,
		id, userID, networkID, publicKey, deviceName, platform, virtualIP, appVersion, now, now, ed25519PublicKey)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return &Device{
		ID: id, UserID: userID, NetworkID: networkID,
		PublicKey: publicKey, DeviceName: deviceName, Platform: platform,
		VirtualIP: virtualIP, AppVersion: appVersion, LastSeen: now, Online: true,
		Ed25519PublicKey: ed25519PublicKey, CreatedAt: now,
	}, nil
}

// GetDeviceByPublicKey looks up a device by network and public key.
func (db *DB) GetDeviceByPublicKey(networkID, publicKey string) (*Device, error) {
	var d Device
	var online int
	var relayRTTMS sql.NullInt64
	err := db.QueryRow(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at, COALESCE(ed25519_public_key, '')
		FROM devices WHERE network_id = ? AND public_key = ? LIMIT 1`, networkID, publicKey).
		Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &relayRTTMS, &d.LastSeen, &d.AppVersion, &online, &d.CreatedAt, &d.Ed25519PublicKey)
	if err != nil {
		return nil, err
	}
	d.Online = online == 1
	d.RelayRTTMS = nullInt64Ptr(relayRTTMS)
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

func networkIP(ipnet *net.IPNet) net.IP {
	base := ipnet.IP.To4()
	if base == nil {
		base = ipnet.IP
	}
	network := make(net.IP, len(base))
	copy(network, base)
	return network
}

func broadcastIP(ipnet *net.IPNet) net.IP {
	base := networkIP(ipnet)
	broadcast := make(net.IP, len(base))
	for i := range broadcast {
		broadcast[i] = base[i] | ^ipnet.Mask[i]
	}
	return broadcast
}

// reserveVirtualIP validates a requested IP or finds the next available IP in a network.
func (db *DB) reserveVirtualIP(tx *sql.Tx, networkID, requestedIP, excludeDeviceID string) (string, error) {
	var cidr string
	err := tx.QueryRow(`SELECT cidr FROM networks WHERE id = ?`, networkID).Scan(&cidr)
	if err != nil {
		return "", fmt.Errorf("query network cidr: %w", err)
	}

	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", fmt.Errorf("parse network cidr '%s': %w", cidr, err)
	}

	network := networkIP(ipnet)
	broadcast := broadcastIP(ipnet)
	requestedIP = strings.TrimSpace(requestedIP)
	if requestedIP != "" {
		ip := net.ParseIP(requestedIP).To4()
		if ip == nil {
			return "", fmt.Errorf("virtual_ip must be an IPv4 address")
		}
		if !ipnet.Contains(ip) {
			return "", fmt.Errorf("virtual_ip %s is outside network CIDR %s", ip.String(), cidr)
		}
		if ip.Equal(network) || ip.Equal(broadcast) {
			return "", fmt.Errorf("virtual_ip %s cannot be the network or broadcast address", ip.String())
		}
		var existingID string
		err := tx.QueryRow(`SELECT id FROM devices WHERE network_id = ? AND virtual_ip = ? LIMIT 1`, networkID, ip.String()).Scan(&existingID)
		if err == nil && existingID != excludeDeviceID {
			return "", fmt.Errorf("virtual_ip %s is already assigned", ip.String())
		}
		if err != nil && err != sql.ErrNoRows {
			return "", err
		}
		return ip.String(), nil
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

	curr := nextIP(network) // Network address (skip)
	curr = nextIP(curr)     // Start from .2
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

// assignVirtualIP finds the next available virtual IP in a network.
func (db *DB) assignVirtualIP(tx *sql.Tx, networkID string) (string, error) {
	return db.reserveVirtualIP(tx, networkID, "", "")
}

// DeviceOnlineTTL is how long a device remains "online" without a last_seen update.
// Defaults to 90 seconds — a few missed heartbeats of the typical 5–15s poll interval.
const DeviceOnlineTTL = 90

// ListDevicesByNetwork returns all devices in a network.
// Devices whose last_seen is older than DeviceOnlineTTL are reported as offline
// even if the online flag is still set (lease / TTL semantics).
func (db *DB) ListDevicesByNetwork(networkID string) ([]Device, error) {
	now := time.Now().Unix()

	rows, err := db.Query(`SELECT id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, endpoint, relay_rtt_ms, last_seen, COALESCE(app_version, ''), online, created_at
		FROM devices WHERE network_id = ?`, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var d Device
		var online int
		var relayRTTMS sql.NullInt64
		if err := rows.Scan(&d.ID, &d.UserID, &d.NetworkID, &d.PublicKey, &d.DeviceName, &d.Platform,
			&d.VirtualIP, &d.NATType, &d.Endpoint, &relayRTTMS, &d.LastSeen, &d.AppVersion, &online, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.RelayRTTMS = nullInt64Ptr(relayRTTMS)
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
func (db *DB) UpdateDeviceEndpoint(deviceID, endpoint, natType string, relayRTTMS *int64) error {
	_, err := db.Exec(`UPDATE devices SET endpoint = ?, nat_type = ?, relay_rtt_ms = ?, last_seen = ?, online = 1 WHERE id = ?`,
		endpoint, natType, relayRTTMS, time.Now().Unix(), deviceID)
	return err
}

// UpdateDeviceName changes the user-visible name of a registered device.
func (db *DB) UpdateDeviceName(deviceID, deviceName string) error {
	_, err := db.Exec(`UPDATE devices SET device_name = ? WHERE id = ?`, deviceName, deviceID)
	return err
}

// UpdateDeviceVirtualIP changes a device's assigned virtual IP after validating the network pool.
func (db *DB) UpdateDeviceVirtualIP(deviceID, virtualIP string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var networkID string
	if err := tx.QueryRow(`SELECT network_id FROM devices WHERE id = ?`, deviceID).Scan(&networkID); err != nil {
		return err
	}
	reservedIP, err := db.reserveVirtualIP(tx, networkID, virtualIP, deviceID)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE devices SET virtual_ip = ? WHERE id = ?`, reservedIP, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}

// DeleteDevice removes a device.
func (db *DB) DeleteDevice(deviceID string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT OR IGNORE INTO relay_revocations (kind, value, created_at) VALUES (?, ?, ?)`,
		RelayRevocationDeviceID, deviceID, now); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO relay_revocations (kind, value, created_at)
		SELECT ?, id, ? FROM device_credentials WHERE device_id = ?`,
		RelayRevocationCredentialID, now, deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE device_credentials SET revoked = 1 WHERE device_id = ? AND revoked = 0`, deviceID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM devices WHERE id = ?`, deviceID); err != nil {
		return err
	}
	return tx.Commit()
}
