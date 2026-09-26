package database

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

var ErrInvalidAdminDeviceCursor = errors.New("invalid admin device cursor")

const MaxAdminDeviceCursorLength = 1024

type AdminDeviceCursorPage struct {
	Total       int                  `json:"total"`
	Limit       int                  `json:"limit"`
	NextCursor  string               `json:"next_cursor,omitempty"`
	GeneratedAt int64                `json:"generated_at"`
	Items       []AdminDeviceSummary `json:"items"`
}

type adminDeviceCursor struct {
	Version int    `json:"v"`
	AfterID string `json:"after"`
	Filter  string `json:"filter"`
}

func normalizeAdminDeviceFilter(query, status string) (string, string, error) {
	query = strings.TrimSpace(query)
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "all"
	}
	if status != "all" && status != "online" && status != "offline" {
		return "", "", ErrInvalidAdminDeviceStatus
	}
	return query, status, nil
}

func adminDeviceFilterSQL(query, status string, cutoff int64) (string, []any) {
	where := []string{"1 = 1"}
	args := make([]any, 0, 5)
	if query != "" {
		where = append(where, `(d.device_name LIKE ? ESCAPE '!' OR COALESCE(NULLIF(u.username, ''), u.email) LIKE ? ESCAPE '!' OR d.virtual_ip LIKE ? ESCAPE '!' OR COALESCE(n.name, '') LIKE ? ESCAPE '!')`)
		escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(query)
		pattern := "%" + escaped + "%"
		args = append(args, pattern, pattern, pattern, pattern)
	}
	if status == "online" {
		where = append(where, adminOnlineLeaseSQL("d"))
		args = append(args, cutoff)
	} else if status == "offline" {
		where = append(where, "NOT "+adminOnlineLeaseSQL("d"))
		args = append(args, cutoff)
	}
	return strings.Join(where, " AND "), args
}

func adminDeviceFilterIdentity(query, status string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(query+"\x00"+status)))
}

func decodeAdminDeviceCursor(cursor, filter string) (string, error) {
	if cursor == "" {
		return "", nil
	}
	if len(cursor) > MaxAdminDeviceCursorLength {
		return "", ErrInvalidAdminDeviceCursor
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(cursor)
	if err != nil {
		return "", ErrInvalidAdminDeviceCursor
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value adminDeviceCursor
	if err := decoder.Decode(&value); err != nil {
		return "", ErrInvalidAdminDeviceCursor
	}
	if decoder.Decode(new(any)) != io.EOF || value.Version != 1 || value.AfterID == "" || len(value.AfterID) > 128 || value.Filter != filter {
		return "", ErrInvalidAdminDeviceCursor
	}
	return value.AfterID, nil
}

// AdminDevicesCursor orders by immutable device ID, so heartbeats cannot move
// a device across a page boundary. Each page is a transaction-consistent live
// view, not a frozen roster: deleted devices disappear, and status filters use
// the current heartbeat lease. New/matching IDs at or before the cursor become
// visible when the caller restarts from the first page. The cursor is scoped to
// the normalized search/status, not an authorization credential; the HTTP route
// must still require the independent administrator token on every request.
func (db *DB) AdminDevicesCursor(query, status, cursor string, limit int) (*AdminDeviceCursorPage, error) {
	query, status, err := normalizeAdminDeviceFilter(query, status)
	if err != nil {
		return nil, err
	}
	filter := adminDeviceFilterIdentity(query, status)
	afterID, err := decodeAdminDeviceCursor(cursor, filter)
	if err != nil {
		return nil, err
	}
	limit, _ = normalizeAdminPage(limit, 0)
	generatedAt := time.Now().Unix()
	cutoff := generatedAt - DeviceOnlineTTL
	clause, args := adminDeviceFilterSQL(query, status, cutoff)
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	page := &AdminDeviceCursorPage{Limit: limit, GeneratedAt: generatedAt, Items: []AdminDeviceSummary{}}
	const from = ` FROM devices d JOIN users u ON u.id = d.user_id LEFT JOIN networks n ON n.id = d.network_id WHERE `
	if err := tx.QueryRow(`SELECT COUNT(*)`+from+clause, args...).Scan(&page.Total); err != nil {
		return nil, fmt.Errorf("count cursor admin devices: %w", err)
	}
	listArgs := append(append([]any(nil), args...), afterID, limit+1)
	rows, err := tx.Query(`SELECT `+adminDeviceColumns()+from+clause+` AND d.id > ? ORDER BY d.id ASC LIMIT ?`, listArgs...)
	if err != nil {
		return nil, fmt.Errorf("list cursor admin devices: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		item, err := scanAdminDevice(rows, cutoff)
		if err != nil {
			return nil, fmt.Errorf("scan cursor admin device: %w", err)
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if len(page.Items) > limit {
		page.Items = page.Items[:limit]
		encoded, err := json.Marshal(adminDeviceCursor{Version: 1, AfterID: page.Items[limit-1].ID, Filter: filter})
		if err != nil {
			return nil, fmt.Errorf("encode admin device cursor: %w", err)
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(encoded)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return page, nil
}
