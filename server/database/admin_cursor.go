package database

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidAdminCursor = errors.New("invalid admin cursor")

const adminCursorVersion = 1

type AdminAccountCursorPage struct {
	Total      int                   `json:"total"`
	Limit      int                   `json:"limit"`
	SnapshotAt int64                 `json:"snapshot_at"`
	NextCursor string                `json:"next_cursor,omitempty"`
	Items      []AdminAccountSummary `json:"items"`
}

type AdminDeviceCursorPage struct {
	Total      int                  `json:"total"`
	Limit      int                  `json:"limit"`
	SnapshotAt int64                `json:"snapshot_at"`
	NextCursor string               `json:"next_cursor,omitempty"`
	Items      []AdminDeviceSummary `json:"items"`
}

type AdminNetworkCursorPage struct {
	Total      int                   `json:"total"`
	Limit      int                   `json:"limit"`
	SnapshotAt int64                 `json:"snapshot_at"`
	NextCursor string                `json:"next_cursor,omitempty"`
	Items      []AdminNetworkSummary `json:"items"`
}

type AdminRoomCursorPage struct {
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	SnapshotAt int64              `json:"snapshot_at"`
	NextCursor string             `json:"next_cursor,omitempty"`
	Items      []AdminRoomSummary `json:"items"`
}

type adminListCursor struct {
	Version    int    `json:"v"`
	Kind       string `json:"kind"`
	BeforeRow  int64  `json:"before_row"`
	SnapshotAt int64  `json:"snapshot_at"`
	Query      string `json:"q,omitempty"`
	Status     string `json:"status,omitempty"`
}

func normalizeAdminCursorLimit(limit int) int {
	if limit <= 0 {
		return adminDefaultPageSize
	}
	if limit > adminMaxPageSize {
		return adminMaxPageSize
	}
	return limit
}

// adminStableSnapshotAt intentionally trails wall clock time by one second.
// Entity creation timestamps are stored with second precision; using the
// previous complete second means a newly inserted row can never join an
// already-issued cursor page merely because it shares the current second.
func adminStableSnapshotAt() int64 {
	return time.Now().Unix() - 1
}

func encodeAdminCursor(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodeAdminListCursor(raw, kind, query, status string) (adminListCursor, error) {
	if raw == "" {
		return adminListCursor{
			Version:    adminCursorVersion,
			Kind:       kind,
			SnapshotAt: adminStableSnapshotAt(),
			Query:      query,
			Status:     status,
		}, nil
	}
	if len(raw) > 2048 {
		return adminListCursor{}, ErrInvalidAdminCursor
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return adminListCursor{}, ErrInvalidAdminCursor
	}
	var cursor adminListCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return adminListCursor{}, ErrInvalidAdminCursor
	}
	if cursor.Version != adminCursorVersion || cursor.Kind != kind || cursor.BeforeRow < 0 || cursor.SnapshotAt <= 0 || cursor.Query != query || cursor.Status != status {
		return adminListCursor{}, ErrInvalidAdminCursor
	}
	return cursor, nil
}

func nextAdminListCursor(cursor adminListCursor, before int64) (string, error) {
	cursor.BeforeRow = before
	return encodeAdminCursor(cursor)
}

func adminCursorRowClause(alias string, cursor adminListCursor) (string, []any) {
	clause := fmt.Sprintf("%s.created_at <= ?", alias)
	args := []any{cursor.SnapshotAt}
	if cursor.BeforeRow > 0 {
		clause += fmt.Sprintf(" AND %s.rowid < ?", alias)
		args = append(args, cursor.BeforeRow)
	}
	return clause, args
}

func (db *DB) AdminAccountsCursor(query, cursorRaw string, limit int) (*AdminAccountCursorPage, error) {
	limit = normalizeAdminCursorLimit(limit)
	query = strings.TrimSpace(query)
	cursor, err := decodeAdminListCursor(cursorRaw, "accounts", query, "")
	if err != nil {
		return nil, err
	}

	where := `u.id <> 'system' AND u.created_at <= ?`
	countArgs := []any{cursor.SnapshotAt}
	filterArgs := []any{}
	if query != "" {
		escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(query)
		pattern := "%" + escaped + "%"
		where += ` AND (COALESCE(NULLIF(u.username, ''), u.email) LIKE ? ESCAPE '!' OR u.email LIKE ? ESCAPE '!')`
		countArgs = append(countArgs, pattern, pattern)
		filterArgs = append(filterArgs, pattern, pattern)
	}
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users u WHERE `+where, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count cursor admin accounts: %w", err)
	}

	listWhere := `u.id <> 'system' AND u.created_at <= ?`
	listArgs := []any{adminOnlineCutoff(), cursor.SnapshotAt}
	if query != "" {
		listWhere += ` AND (COALESCE(NULLIF(u.username, ''), u.email) LIKE ? ESCAPE '!' OR u.email LIKE ? ESCAPE '!')`
		listArgs = append(listArgs, filterArgs...)
	}
	if cursor.BeforeRow > 0 {
		listWhere += ` AND u.rowid < ?`
		listArgs = append(listArgs, cursor.BeforeRow)
	}
	listArgs = append(listArgs, limit+1)
	rows, err := db.Query(`SELECT u.rowid, `+adminAccountColumns()+`
		FROM users u
		WHERE `+listWhere+`
		ORDER BY u.rowid DESC
		LIMIT ?`, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("list cursor admin accounts: %w", err)
	}
	defer rows.Close()

	type rowItem struct {
		rowID int64
		item  AdminAccountSummary
	}
	items := make([]rowItem, 0, min(limit+1, total))
	for rows.Next() {
		var current rowItem
		if err := rows.Scan(&current.rowID, &current.item.ID, &current.item.Username, &current.item.Email, &current.item.DeviceCount, &current.item.OnlineDevices, &current.item.NetworkCount, &current.item.RoomCount, &current.item.LastSeen, &current.item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan cursor admin account: %w", err)
		}
		items = append(items, current)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	page := &AdminAccountCursorPage{Total: total, Limit: limit, SnapshotAt: cursor.SnapshotAt, Items: make([]AdminAccountSummary, 0, min(limit, len(items)))}
	for i, current := range items {
		if i >= limit {
			break
		}
		page.Items = append(page.Items, current.item)
	}
	if len(items) > limit && len(page.Items) > 0 {
		page.NextCursor, err = nextAdminListCursor(cursor, items[limit-1].rowID)
		if err != nil {
			return nil, err
		}
	}
	return page, nil
}

func (db *DB) AdminDevicesCursor(query, status, cursorRaw string, limit int) (*AdminDeviceCursorPage, error) {
	limit = normalizeAdminCursorLimit(limit)
	query = strings.TrimSpace(query)
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "all"
	}
	if status != "all" && status != "online" && status != "offline" {
		return nil, ErrInvalidAdminDeviceStatus
	}
	cursor, err := decodeAdminListCursor(cursorRaw, "devices", query, status)
	if err != nil {
		return nil, err
	}
	cutoff := adminOnlineCutoff()

	where := []string{"d.created_at <= ?"}
	args := []any{cursor.SnapshotAt}
	if query != "" {
		escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(query)
		pattern := "%" + escaped + "%"
		where = append(where, `(d.device_name LIKE ? ESCAPE '!' OR COALESCE(NULLIF(u.username, ''), u.email) LIKE ? ESCAPE '!' OR d.virtual_ip LIKE ? ESCAPE '!' OR COALESCE(n.name, '') LIKE ? ESCAPE '!')`)
		args = append(args, pattern, pattern, pattern, pattern)
	}
	switch status {
	case "online":
		where = append(where, adminOnlineLeaseSQL("d"))
		args = append(args, cutoff)
	case "offline":
		where = append(where, "NOT "+adminOnlineLeaseSQL("d"))
		args = append(args, cutoff)
	}
	clause := strings.Join(where, " AND ")
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM devices d JOIN users u ON u.id=d.user_id LEFT JOIN networks n ON n.id=d.network_id WHERE `+clause, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count cursor admin devices: %w", err)
	}

	listClause := clause
	listArgs := append([]any(nil), args...)
	if cursor.BeforeRow > 0 {
		listClause += ` AND d.rowid < ?`
		listArgs = append(listArgs, cursor.BeforeRow)
	}
	// adminDeviceColumns returns the raw online flag; scanAdminDevice applies
	// the heartbeat lease using the same cutoff used by filters.
	listArgs = append(listArgs, limit+1)
	rows, err := db.Query(`SELECT d.rowid, `+adminDeviceColumns()+`
		FROM devices d JOIN users u ON u.id=d.user_id LEFT JOIN networks n ON n.id=d.network_id
		WHERE `+listClause+`
		ORDER BY d.rowid DESC LIMIT ?`, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("list cursor admin devices: %w", err)
	}
	defer rows.Close()

	type rowItem struct {
		rowID int64
		item  AdminDeviceSummary
	}
	items := make([]rowItem, 0, min(limit+1, total))
	for rows.Next() {
		var current rowItem
		var online int64
		var relayRTT interface{}
		if err := rows.Scan(&current.rowID, &current.item.ID, &current.item.Username, &current.item.DeviceName, &current.item.Platform, &current.item.VirtualIP, &current.item.NetworkID, &current.item.NetworkName, &current.item.NATType, &relayRTT, &current.item.LastSeen, &current.item.AppVersion, &online); err != nil {
			return nil, fmt.Errorf("scan cursor admin device: %w", err)
		}
		current.item.Online = adminDeviceOnline(online, current.item.LastSeen, cutoff)
		if relayRTT != nil {
			switch value := relayRTT.(type) {
			case int64:
				current.item.RelayRTTMS = &value
			case int:
				converted := int64(value)
				current.item.RelayRTTMS = &converted
			}
		}
		items = append(items, current)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	page := &AdminDeviceCursorPage{Total: total, Limit: limit, SnapshotAt: cursor.SnapshotAt, Items: make([]AdminDeviceSummary, 0, min(limit, len(items)))}
	for i, current := range items {
		if i >= limit {
			break
		}
		page.Items = append(page.Items, current.item)
	}
	if len(items) > limit && len(page.Items) > 0 {
		page.NextCursor, err = nextAdminListCursor(cursor, items[limit-1].rowID)
		if err != nil {
			return nil, err
		}
	}
	return page, nil
}

func (db *DB) AdminNetworksCursor(cursorRaw string, limit int) (*AdminNetworkCursorPage, error) {
	limit = normalizeAdminCursorLimit(limit)
	cursor, err := decodeAdminListCursor(cursorRaw, "networks", "", "")
	if err != nil {
		return nil, err
	}
	cutoff := adminOnlineCutoff()
	where := `n.id <> 'default' AND n.created_at <= ?`
	countArgs := []any{cursor.SnapshotAt}
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM networks n WHERE `+where, countArgs...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count cursor admin networks: %w", err)
	}
	listWhere := where
	args := []any{cutoff, cursor.SnapshotAt}
	if cursor.BeforeRow > 0 {
		listWhere += ` AND n.rowid < ?`
		args = append(args, cursor.BeforeRow)
	}
	args = append(args, limit+1)
	rows, err := db.Query(`SELECT n.rowid, n.id, n.name, n.cidr,
		COALESCE(NULLIF(u.username, ''), u.email),
		(SELECT COUNT(*) FROM network_memberships m WHERE m.network_id=n.id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id=n.id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id=n.id AND `+adminOnlineLeaseSQL("d")+`),
		EXISTS(SELECT 1 FROM rooms r WHERE r.network_id=n.id), n.created_at
		FROM networks n JOIN users u ON u.id=n.owner_id
		WHERE `+listWhere+`
		ORDER BY n.rowid DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list cursor admin networks: %w", err)
	}
	defer rows.Close()
	type rowItem struct {
		rowID int64
		item  AdminNetworkSummary
	}
	items := make([]rowItem, 0, min(limit+1, total))
	for rows.Next() {
		var current rowItem
		var isRoom int
		if err := rows.Scan(&current.rowID, &current.item.ID, &current.item.Name, &current.item.CIDR, &current.item.OwnerUsername, &current.item.MemberCount, &current.item.DeviceCount, &current.item.OnlineDevices, &isRoom, &current.item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan cursor admin network: %w", err)
		}
		current.item.IsRoom = isRoom == 1
		items = append(items, current)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	page := &AdminNetworkCursorPage{Total: total, Limit: limit, SnapshotAt: cursor.SnapshotAt, Items: make([]AdminNetworkSummary, 0, min(limit, len(items)))}
	for i, current := range items {
		if i >= limit {
			break
		}
		page.Items = append(page.Items, current.item)
	}
	if len(items) > limit && len(page.Items) > 0 {
		page.NextCursor, err = nextAdminListCursor(cursor, items[limit-1].rowID)
		if err != nil {
			return nil, err
		}
	}
	return page, nil
}

func (db *DB) AdminRoomsCursor(cursorRaw string, limit int) (*AdminRoomCursorPage, error) {
	limit = normalizeAdminCursorLimit(limit)
	cursor, err := decodeAdminListCursor(cursorRaw, "rooms", "", "")
	if err != nil {
		return nil, err
	}
	cutoff := adminOnlineCutoff()
	where := `r.created_at <= ?`
	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM rooms r WHERE `+where, cursor.SnapshotAt).Scan(&total); err != nil {
		return nil, fmt.Errorf("count cursor admin rooms: %w", err)
	}
	listWhere := where
	args := []any{cutoff, cursor.SnapshotAt}
	if cursor.BeforeRow > 0 {
		listWhere += ` AND r.rowid < ?`
		args = append(args, cursor.BeforeRow)
	}
	args = append(args, limit+1)
	rows, err := db.Query(`SELECT r.rowid, r.network_id, r.room_code, n.name, n.cidr,
		COALESCE(NULLIF(u.username, ''), u.email),
		(SELECT COUNT(*) FROM network_memberships m WHERE m.network_id=r.network_id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id=r.network_id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id=r.network_id AND `+adminOnlineLeaseSQL("d")+`),
		r.join_locked, r.created_at
		FROM rooms r JOIN networks n ON n.id=r.network_id JOIN users u ON u.id=r.owner_id
		WHERE `+listWhere+`
		ORDER BY r.rowid DESC LIMIT ?`, args...)
	if err != nil {
		return nil, fmt.Errorf("list cursor admin rooms: %w", err)
	}
	defer rows.Close()
	type rowItem struct {
		rowID int64
		item  AdminRoomSummary
	}
	items := make([]rowItem, 0, min(limit+1, total))
	for rows.Next() {
		var current rowItem
		var locked int
		if err := rows.Scan(&current.rowID, &current.item.ID, &current.item.Code, &current.item.Name, &current.item.CIDR, &current.item.OwnerUsername, &current.item.MemberCount, &current.item.DeviceCount, &current.item.OnlineDevices, &locked, &current.item.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan cursor admin room: %w", err)
		}
		current.item.JoinLocked = locked == 1
		items = append(items, current)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	page := &AdminRoomCursorPage{Total: total, Limit: limit, SnapshotAt: cursor.SnapshotAt, Items: make([]AdminRoomSummary, 0, min(limit, len(items)))}
	for i, current := range items {
		if i >= limit {
			break
		}
		page.Items = append(page.Items, current.item)
	}
	if len(items) > limit && len(page.Items) > 0 {
		page.NextCursor, err = nextAdminListCursor(cursor, items[limit-1].rowID)
		if err != nil {
			return nil, err
		}
	}
	return page, nil
}
