package database

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type AdminConnectionSummary struct {
	SchemaVersion           int     `json:"schema_version"`
	Directional             bool    `json:"directional"`
	ReportingDeviceID       string  `json:"reporting_device_id"`
	ReportingDeviceName     string  `json:"reporting_device_name"`
	ReportingUserID         string  `json:"reporting_user_id"`
	ReportingUsername       string  `json:"reporting_username"`
	RemoteDeviceID          string  `json:"remote_device_id"`
	RemoteDeviceName        string  `json:"remote_device_name"`
	RemoteUserID            string  `json:"remote_user_id"`
	RemoteUsername          string  `json:"remote_username"`
	NetworkID               string  `json:"network_id"`
	NetworkName             string  `json:"network_name"`
	Lifecycle               string  `json:"lifecycle"`
	CurrentPath             *string `json:"current_path"`
	PreviousPath            *string `json:"previous_path"`
	TransitionReason        string  `json:"transition_reason"`
	DirectState             string  `json:"direct_state,omitempty"`
	RelayState              string  `json:"relay_state,omitempty"`
	RecoveryState           string  `json:"recovery_state,omitempty"`
	RelayServer             string  `json:"relay_server,omitempty"`
	SelectedPathMTU         *uint32 `json:"selected_path_mtu,omitempty"`
	SelectedUDPDatagramSize *uint32 `json:"selected_udp_datagram_size,omitempty"`
	LastHandshakeAgeMS      *uint64 `json:"last_handshake_age_ms,omitempty"`
	LastValidationRTTMS     *uint64 `json:"last_validation_rtt_ms,omitempty"`
	PathAgeMS               uint64  `json:"path_age_ms"`
	ObservedAt              int64   `json:"observed_at"`
	ReceivedAt              int64   `json:"received_at"`
	Fresh                   bool    `json:"fresh"`
	Freshness               string  `json:"freshness"`
	ObservationRevision     uint64  `json:"observation_revision"`
}

type AdminConnectionPage struct {
	Total  int                      `json:"total"`
	Limit  int                      `json:"limit"`
	Offset int                      `json:"offset"`
	Items  []AdminConnectionSummary `json:"items"`
}

type AdminConnectionFilter struct {
	NetworkID         string
	AccountID         string
	DeviceID          string
	ReportingDeviceID string
	RemoteDeviceID    string
	Path              string
	Freshness         string // "all", "fresh", "stale"
}

type AdminConnectionTransitionSummary struct {
	ID                  string  `json:"id"`
	SchemaVersion       int     `json:"schema_version"`
	Directional         bool    `json:"directional"`
	ReportingDeviceID   string  `json:"reporting_device_id"`
	RemoteDeviceID      string  `json:"remote_device_id"`
	NetworkID           string  `json:"network_id"`
	Lifecycle           string  `json:"lifecycle"`
	CurrentPath         *string `json:"current_path"`
	PreviousPath        *string `json:"previous_path"`
	TransitionReason    string  `json:"transition_reason"`
	SelectedPathMTU     *uint32 `json:"selected_path_mtu,omitempty"`
	ObservedAt          int64   `json:"observed_at"`
	CreatedAt           int64   `json:"created_at"`
	ObservationRevision uint64  `json:"observation_revision"`
}

type AdminConnectionTransitionPage struct {
	Limit      int                                `json:"limit"`
	NextCursor string                             `json:"next_cursor,omitempty"`
	Items      []AdminConnectionTransitionSummary `json:"items"`
}

type AdminConnectionTransitionFilter struct {
	ReportingDeviceID string
	RemoteDeviceID    string
	NetworkID         string
}

// AdminConnections lists authoritative path observations reported by daemons.
// Observations are directional and filtered according to the caller's criteria.
func (db *DB) AdminConnections(filter AdminConnectionFilter, limit, offset int) (*AdminConnectionPage, error) {
	limit, offset = normalizeAdminPage(limit, offset)

	var conditions []string
	var args []interface{}

	if filter.NetworkID != "" {
		conditions = append(conditions, "o.network_id = ?")
		args = append(args, filter.NetworkID)
	}
	if filter.AccountID != "" {
		conditions = append(conditions, "(rd.user_id = ? OR remd.user_id = ?)")
		args = append(args, filter.AccountID, filter.AccountID)
	}
	if filter.DeviceID != "" {
		conditions = append(conditions, "(o.reporting_device_id = ? OR o.remote_device_id = ?)")
		args = append(args, filter.DeviceID, filter.DeviceID)
	}
	if filter.ReportingDeviceID != "" {
		conditions = append(conditions, "o.reporting_device_id = ?")
		args = append(args, filter.ReportingDeviceID)
	}
	if filter.RemoteDeviceID != "" {
		conditions = append(conditions, "o.remote_device_id = ?")
		args = append(args, filter.RemoteDeviceID)
	}
	if filter.Path != "" {
		switch strings.ToLower(filter.Path) {
		case "direct", "relay":
			conditions = append(conditions, "o.current_path = ?")
			args = append(args, strings.ToLower(filter.Path))
		case "none":
			conditions = append(conditions, "(o.current_path IS NULL OR o.current_path = '')")
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	baseQuery := `
		FROM peer_path_observations o
		JOIN devices rd ON o.reporting_device_id = rd.id
		JOIN users ru ON rd.user_id = ru.id
		JOIN devices remd ON o.remote_device_id = remd.id
		JOIN users remu ON remd.user_id = remu.id
		JOIN networks n ON o.network_id = n.id
		` + whereClause

	now := time.Now().Unix()

	// Query all matching rows to calculate freshness correctly and filter if needed
	query := `
		SELECT
			o.schema_version,
			o.reporting_device_id,
			rd.device_name,
			rd.user_id,
			ru.username,
			rd.online,
			rd.last_seen,
			o.remote_device_id,
			remd.device_name,
			remd.user_id,
			remu.username,
			o.network_id,
			n.name,
			o.lifecycle,
			o.current_path,
			o.previous_path,
			o.transition_reason,
			o.direct_state,
			o.relay_state,
			o.recovery_state,
			o.relay_server,
			o.selected_path_mtu,
			o.selected_udp_datagram_size,
			o.last_handshake_age_ms,
			o.last_validation_rtt_ms,
			o.path_age_ms,
			o.observed_at,
			o.received_at,
			o.observation_revision
		` + baseQuery + `
		ORDER BY o.received_at DESC, o.reporting_device_id ASC, o.remote_device_id ASC
	`

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query admin connections: %w", err)
	}
	defer rows.Close()

	var allItems []AdminConnectionSummary
	for rows.Next() {
		var item AdminConnectionSummary
		item.Directional = true

		var (
			reportingOnline         int
			reportingLastSeen       int64
			currentPath             sql.NullString
			previousPath            sql.NullString
			selectedPathMTU         sql.NullInt64
			selectedUDPDatagramSize sql.NullInt64
			lastHandshakeAgeMS      sql.NullInt64
			lastValidationRTTMS     sql.NullInt64
		)

		err := rows.Scan(
			&item.SchemaVersion,
			&item.ReportingDeviceID,
			&item.ReportingDeviceName,
			&item.ReportingUserID,
			&item.ReportingUsername,
			&reportingOnline,
			&reportingLastSeen,
			&item.RemoteDeviceID,
			&item.RemoteDeviceName,
			&item.RemoteUserID,
			&item.RemoteUsername,
			&item.NetworkID,
			&item.NetworkName,
			&item.Lifecycle,
			&currentPath,
			&previousPath,
			&item.TransitionReason,
			&item.DirectState,
			&item.RelayState,
			&item.RecoveryState,
			&item.RelayServer,
			&selectedPathMTU,
			&selectedUDPDatagramSize,
			&lastHandshakeAgeMS,
			&lastValidationRTTMS,
			&item.PathAgeMS,
			&item.ObservedAt,
			&item.ReceivedAt,
			&item.ObservationRevision,
		)
		if err != nil {
			return nil, fmt.Errorf("scan admin connection: %w", err)
		}

		if currentPath.Valid && currentPath.String != "" {
			item.CurrentPath = &currentPath.String
		}
		if previousPath.Valid && previousPath.String != "" {
			item.PreviousPath = &previousPath.String
		}
		if selectedPathMTU.Valid {
			v := uint32(selectedPathMTU.Int64)
			item.SelectedPathMTU = &v
		}
		if selectedUDPDatagramSize.Valid {
			v := uint32(selectedUDPDatagramSize.Int64)
			item.SelectedUDPDatagramSize = &v
		}
		if lastHandshakeAgeMS.Valid {
			v := uint64(lastHandshakeAgeMS.Int64)
			item.LastHandshakeAgeMS = &v
		}
		if lastValidationRTTMS.Valid {
			v := uint64(lastValidationRTTMS.Int64)
			item.LastValidationRTTMS = &v
		}

		reporterOnline := reportingOnline == 1 && reportingLastSeen > 0 && (now-reportingLastSeen <= DeviceOnlineTTL)
		timeFresh := (now - item.ReceivedAt <= DeviceOnlineTTL)
		item.Fresh = reporterOnline && timeFresh

		if !reporterOnline {
			item.Freshness = "reporter_offline"
		} else if !timeFresh {
			item.Freshness = "stale"
		} else {
			item.Freshness = "fresh"
		}

		if filter.Freshness == "fresh" && !item.Fresh {
			continue
		}
		if filter.Freshness == "stale" && item.Fresh {
			continue
		}

		allItems = append(allItems, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin connections: %w", err)
	}

	total := len(allItems)
	start := offset
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}

	pageItems := allItems[start:end]
	if pageItems == nil {
		pageItems = []AdminConnectionSummary{}
	}

	return &AdminConnectionPage{
		Total:  total,
		Limit:  limit,
		Offset: offset,
		Items:  pageItems,
	}, nil
}

// AdminConnectionTransitions returns transition history for connection paths,
// ordered newest-first with stable cursor pagination.
func (db *DB) AdminConnectionTransitions(filter AdminConnectionTransitionFilter, limit int, cursor string) (*AdminConnectionTransitionPage, error) {
	if limit <= 0 {
		limit = adminDefaultPageSize
	}
	if limit > adminMaxPageSize {
		limit = adminMaxPageSize
	}

	var conditions []string
	var args []interface{}

	if filter.ReportingDeviceID != "" {
		conditions = append(conditions, "t.reporting_device_id = ?")
		args = append(args, filter.ReportingDeviceID)
	}
	if filter.RemoteDeviceID != "" {
		conditions = append(conditions, "t.remote_device_id = ?")
		args = append(args, filter.RemoteDeviceID)
	}
	if filter.NetworkID != "" {
		conditions = append(conditions, "t.network_id = ?")
		args = append(args, filter.NetworkID)
	}

	if cursor != "" {
		parts := strings.SplitN(cursor, ":", 2)
		if len(parts) == 2 {
			if cursorTime, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
				cursorID := parts[1]
				conditions = append(conditions, "(t.created_at < ? OR (t.created_at = ? AND t.id < ?))")
				args = append(args, cursorTime, cursorTime, cursorID)
			}
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Fetch limit + 1 to detect if there is a next page
	query := fmt.Sprintf(`
		SELECT
			t.id,
			t.schema_version,
			t.reporting_device_id,
			t.remote_device_id,
			t.network_id,
			t.lifecycle,
			t.current_path,
			t.previous_path,
			t.transition_reason,
			t.selected_path_mtu,
			t.observed_at,
			t.created_at,
			t.observation_revision
		FROM peer_path_transitions t
		%s
		ORDER BY t.created_at DESC, t.id DESC
		LIMIT ?
	`, whereClause)

	args = append(args, limit+1)
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query admin connection transitions: %w", err)
	}
	defer rows.Close()

	var items []AdminConnectionTransitionSummary
	for rows.Next() {
		var item AdminConnectionTransitionSummary
		item.Directional = true

		var (
			currPath sql.NullString
			prevPath sql.NullString
			mtu      sql.NullInt64
		)

		err := rows.Scan(
			&item.ID,
			&item.SchemaVersion,
			&item.ReportingDeviceID,
			&item.RemoteDeviceID,
			&item.NetworkID,
			&item.Lifecycle,
			&currPath,
			&prevPath,
			&item.TransitionReason,
			&mtu,
			&item.ObservedAt,
			&item.CreatedAt,
			&item.ObservationRevision,
		)
		if err != nil {
			return nil, fmt.Errorf("scan admin transition: %w", err)
		}

		if currPath.Valid && currPath.String != "" {
			item.CurrentPath = &currPath.String
		}
		if prevPath.Valid && prevPath.String != "" {
			item.PreviousPath = &prevPath.String
		}
		if mtu.Valid {
			v := uint32(mtu.Int64)
			item.SelectedPathMTU = &v
		}

		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admin transitions: %w", err)
	}

	nextCursor := ""
	if len(items) > limit {
		items = items[:limit]
		last := items[len(items)-1]
		nextCursor = fmt.Sprintf("%d:%s", last.CreatedAt, last.ID)
	}

	if items == nil {
		items = []AdminConnectionTransitionSummary{}
	}

	return &AdminConnectionTransitionPage{
		Limit:      limit,
		NextCursor: nextCursor,
		Items:      items,
	}, nil
}
