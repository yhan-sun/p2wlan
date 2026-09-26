package database

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

var ErrInvalidAdminDeviceStatus = errors.New("invalid admin device status filter")

const (
	adminDefaultPageSize = 50
	adminMaxPageSize     = 200
)

// AdminOverview is a read-only snapshot for the server administration console.
// It deliberately exposes operational metadata only; credentials, key material,
// support bundles, and signal payloads are never included.
type AdminOverview struct {
	GeneratedAt    int64                `json:"generated_at"`
	Users          int                  `json:"users"`
	Networks       int                  `json:"networks"`
	Rooms          int                  `json:"rooms"`
	Devices        int                  `json:"devices"`
	OnlineDevices  int                  `json:"online_devices"`
	ActiveTunnels  int                  `json:"active_tunnels"`
	PendingSignals int                  `json:"pending_signals"`
	RecentDevices  []AdminDeviceSummary `json:"recent_devices"`
}

type AdminDeviceSummary struct {
	ID          string `json:"id"`
	OwnerID     string `json:"owner_id"`
	Username    string `json:"username"`
	DeviceName  string `json:"device_name"`
	Platform    string `json:"platform"`
	VirtualIP   string `json:"virtual_ip"`
	NetworkID   string `json:"network_id"`
	NetworkName string `json:"network_name"`
	NATType     string `json:"nat_type"`
	RelayRTTMS  *int64 `json:"relay_rtt_ms,omitempty"`
	LastSeen    int64  `json:"last_seen"`
	AppVersion  string `json:"app_version"`
	Online      bool   `json:"online"`
}

type AdminNetworkSummary struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	CIDR          string `json:"cidr"`
	OwnerID       string `json:"owner_id"`
	OwnerUsername string `json:"owner_username"`
	MemberCount   int    `json:"member_count"`
	DeviceCount   int    `json:"device_count"`
	OnlineDevices int    `json:"online_devices"`
	IsRoom        bool   `json:"is_room"`
	CreatedAt     int64  `json:"created_at"`
}

type AdminRoomSummary struct {
	ID            string `json:"id"`
	Code          string `json:"code"`
	Name          string `json:"name"`
	CIDR          string `json:"cidr"`
	OwnerID       string `json:"owner_id"`
	OwnerUsername string `json:"owner_username"`
	MemberCount   int    `json:"member_count"`
	DeviceCount   int    `json:"device_count"`
	OnlineDevices int    `json:"online_devices"`
	JoinLocked    bool   `json:"join_locked"`
	CreatedAt     int64  `json:"created_at"`
}

type AdminDevicePage struct {
	Total  int                  `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
	Items  []AdminDeviceSummary `json:"items"`
}

type AdminNetworkPage struct {
	Total  int                   `json:"total"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
	Items  []AdminNetworkSummary `json:"items"`
}

type AdminRoomPage struct {
	Total  int                `json:"total"`
	Limit  int                `json:"limit"`
	Offset int                `json:"offset"`
	Items  []AdminRoomSummary `json:"items"`
}

func normalizeAdminPage(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = adminDefaultPageSize
	}
	if limit > adminMaxPageSize {
		limit = adminMaxPageSize
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// adminOnlineCutoff is the lease boundary bound to adminOnlineLeaseSQL.
func adminOnlineCutoff() int64 {
	return time.Now().Unix() - DeviceOnlineTTL
}

// adminOnlineLeaseSQL builds the device-online predicate that mirrors the
// authoritative lease semantics in listDevices. Device online state has exactly
// one owner: a heartbeat lease that expires after DeviceOnlineTTL. Admin queries
// must not read the raw online column directly, because only a graceful daemon
// shutdown clears that flag and an abnormal exit would otherwise be reported as
// online forever. Callers bind adminOnlineCutoff() for the "?" placeholder.
func adminOnlineLeaseSQL(alias string) string {
	return fmt.Sprintf("(%s.online = 1 AND %s.last_seen > 0 AND %s.last_seen >= ?)", alias, alias, alias)
}

// adminDeviceOnline applies the same lease rule to a row already read into Go.
func adminDeviceOnline(online, lastSeen int64, cutoff int64) bool {
	return online == 1 && lastSeen > 0 && lastSeen >= cutoff
}

func adminDeviceColumns() string {
	return `d.id,
		d.user_id,
		COALESCE(NULLIF(u.username, ''), u.email),
		d.device_name,
		d.platform,
		d.virtual_ip,
		d.network_id,
		COALESCE(n.name, d.network_id),
		d.nat_type,
		d.relay_rtt_ms,
		d.last_seen,
		COALESCE(d.app_version, ''),
		d.online`
}

func scanAdminDevice(row interface{ Scan(...any) error }, cutoff int64) (AdminDeviceSummary, error) {
	var item AdminDeviceSummary
	var online int
	var relayRTT sql.NullInt64
	err := row.Scan(
		&item.ID,
		&item.OwnerID,
		&item.Username,
		&item.DeviceName,
		&item.Platform,
		&item.VirtualIP,
		&item.NetworkID,
		&item.NetworkName,
		&item.NATType,
		&relayRTT,
		&item.LastSeen,
		&item.AppVersion,
		&online,
	)
	if err != nil {
		return AdminDeviceSummary{}, err
	}
	item.Online = adminDeviceOnline(int64(online), item.LastSeen, cutoff)
	item.RelayRTTMS = nullInt64Ptr(relayRTT)
	return item, nil
}

// AdminOverviewSnapshot returns a transaction-consistent summary for the
// read-only administration console.
func (db *DB) AdminOverviewSnapshot() (*AdminOverview, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	result := &AdminOverview{GeneratedAt: time.Now().Unix(), RecentDevices: []AdminDeviceSummary{}}
	cutoff := adminOnlineCutoff()
	countQuery := `SELECT
		(SELECT COUNT(*) FROM users WHERE id <> 'system'),
		(SELECT COUNT(*) FROM networks WHERE id <> 'default'),
		(SELECT COUNT(*) FROM rooms),
		(SELECT COUNT(*) FROM devices),
		(SELECT COUNT(*) FROM devices WHERE ` + adminOnlineLeaseSQL("devices") + `),
		(SELECT COUNT(*) FROM tunnels WHERE active = 1),
		(SELECT COUNT(*) FROM signals)`
	if err := tx.QueryRow(countQuery, cutoff).Scan(
		&result.Users,
		&result.Networks,
		&result.Rooms,
		&result.Devices,
		&result.OnlineDevices,
		&result.ActiveTunnels,
		&result.PendingSignals,
	); err != nil {
		return nil, fmt.Errorf("admin overview counts: %w", err)
	}

	rows, err := tx.Query(`SELECT ` + adminDeviceColumns() + `
		FROM devices d
		JOIN users u ON u.id = d.user_id
		LEFT JOIN networks n ON n.id = d.network_id
		ORDER BY d.last_seen DESC, d.created_at DESC, d.id ASC
		LIMIT 8`)
	if err != nil {
		return nil, fmt.Errorf("admin recent devices: %w", err)
	}
	for rows.Next() {
		item, scanErr := scanAdminDevice(rows, cutoff)
		if scanErr != nil {
			rows.Close()
			return nil, fmt.Errorf("scan admin recent device: %w", scanErr)
		}
		result.RecentDevices = append(result.RecentDevices, item)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// AdminDevices lists devices with bounded pagination and a small set of
// server-side filters. Search is intentionally limited to non-secret display
// metadata.
func (db *DB) AdminDevices(query, status string, limit, offset int) (*AdminDevicePage, error) {
	limit, offset = normalizeAdminPage(limit, offset)
	query, status, err := normalizeAdminDeviceFilter(query, status)
	if err != nil {
		return nil, err
	}
	cutoff := adminOnlineCutoff()
	clause, args := adminDeviceFilterSQL(query, status, cutoff)

	var total int
	countArgs := append([]any(nil), args...)
	if err := db.QueryRow(`SELECT COUNT(*)
		FROM devices d
		JOIN users u ON u.id = d.user_id
		LEFT JOIN networks n ON n.id = d.network_id
		WHERE `+clause, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count admin devices: %w", err)
	}

	listArgs := append(append([]any(nil), args...), cutoff, limit, offset)
	rows, err := db.Query(`SELECT `+adminDeviceColumns()+`
		FROM devices d
		JOIN users u ON u.id = d.user_id
		LEFT JOIN networks n ON n.id = d.network_id
		WHERE `+clause+`
		ORDER BY `+adminOnlineLeaseSQL("d")+` DESC, d.last_seen DESC, d.device_name COLLATE NOCASE ASC, d.id ASC
		LIMIT ? OFFSET ?`, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("list admin devices: %w", err)
	}
	defer rows.Close()

	items := make([]AdminDeviceSummary, 0, min(limit, total))
	for rows.Next() {
		item, scanErr := scanAdminDevice(rows, cutoff)
		if scanErr != nil {
			return nil, fmt.Errorf("scan admin device: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &AdminDevicePage{Total: total, Limit: limit, Offset: offset, Items: items}, nil
}

func (db *DB) AdminNetworks(limit, offset int) (*AdminNetworkPage, error) {
	limit, offset = normalizeAdminPage(limit, offset)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM networks WHERE id <> 'default'`).Scan(&total); err != nil {
		return nil, fmt.Errorf("count admin networks: %w", err)
	}
	cutoff := adminOnlineCutoff()
	rows, err := db.Query(`SELECT
		n.id,
		n.name,
		n.cidr,
		n.owner_id,
		COALESCE(NULLIF(u.username, ''), u.email),
		(SELECT COUNT(*) FROM network_memberships m WHERE m.network_id = n.id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = n.id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = n.id AND `+adminOnlineLeaseSQL("d")+`),
		EXISTS(SELECT 1 FROM rooms r WHERE r.network_id = n.id),
		n.created_at
		FROM networks n
		JOIN users u ON u.id = n.owner_id
		WHERE n.id <> 'default'
		ORDER BY n.created_at DESC, n.name COLLATE NOCASE ASC, n.id ASC
		LIMIT ? OFFSET ?`, cutoff, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list admin networks: %w", err)
	}
	defer rows.Close()
	items := make([]AdminNetworkSummary, 0, min(limit, total))
	for rows.Next() {
		var item AdminNetworkSummary
		var isRoom int
		if err := rows.Scan(&item.ID, &item.Name, &item.CIDR, &item.OwnerID, &item.OwnerUsername, &item.MemberCount, &item.DeviceCount, &item.OnlineDevices, &isRoom, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan admin network: %w", err)
		}
		item.IsRoom = isRoom == 1
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &AdminNetworkPage{Total: total, Limit: limit, Offset: offset, Items: items}, nil
}

func (db *DB) AdminRooms(limit, offset int) (*AdminRoomPage, error) {
	limit, offset = normalizeAdminPage(limit, offset)
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM rooms`).Scan(&total); err != nil {
		return nil, fmt.Errorf("count admin rooms: %w", err)
	}
	cutoff := adminOnlineCutoff()
	rows, err := db.Query(`SELECT
		r.network_id,
		r.room_code,
		n.name,
		n.cidr,
		r.owner_id,
		COALESCE(NULLIF(u.username, ''), u.email),
		(SELECT COUNT(*) FROM network_memberships m WHERE m.network_id = r.network_id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = r.network_id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = r.network_id AND `+adminOnlineLeaseSQL("d")+`),
		r.join_locked,
		r.created_at
		FROM rooms r
		JOIN networks n ON n.id = r.network_id
		JOIN users u ON u.id = r.owner_id
		ORDER BY r.created_at DESC, n.name COLLATE NOCASE ASC, r.network_id ASC
		LIMIT ? OFFSET ?`, cutoff, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list admin rooms: %w", err)
	}
	defer rows.Close()
	items := make([]AdminRoomSummary, 0, min(limit, total))
	for rows.Next() {
		var item AdminRoomSummary
		var joinLocked int
		if err := rows.Scan(&item.ID, &item.Code, &item.Name, &item.CIDR, &item.OwnerID, &item.OwnerUsername, &item.MemberCount, &item.DeviceCount, &item.OnlineDevices, &joinLocked, &item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan admin room: %w", err)
		}
		item.JoinLocked = joinLocked == 1
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &AdminRoomPage{Total: total, Limit: limit, Offset: offset, Items: items}, nil
}
