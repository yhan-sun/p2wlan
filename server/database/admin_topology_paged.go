package database

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidAdminTopologyView = errors.New("invalid admin topology view")

type AdminTopologyPage struct {
	GeneratedAt              int64               `json:"generated_at"`
	SnapshotAt               int64               `json:"snapshot_at"`
	Scope                    string              `json:"scope"`
	View                     string              `json:"view"`
	Phase                    string              `json:"phase"`
	FocusAccountID           string              `json:"focus_account_id,omitempty"`
	PathObservationAvailable bool                `json:"path_observation_available"`
	PathObservationNote      string              `json:"path_observation_note"`
	Complete                 bool                `json:"complete"`
	NextCursor               string              `json:"next_cursor,omitempty"`
	Nodes                    []AdminTopologyNode `json:"nodes"`
	Edges                    []AdminTopologyEdge `json:"edges"`
}

type adminTopologySnapshot struct {
	Users       int64 `json:"users"`
	Networks    int64 `json:"networks"`
	Rooms       int64 `json:"rooms"`
	Memberships int64 `json:"memberships"`
	Devices     int64 `json:"devices"`
	Signals     int64 `json:"signals"`
}

type adminTopologyCursor struct {
	Version    int                   `json:"v"`
	AccountID  string                `json:"account_id,omitempty"`
	View       string                `json:"view"`
	Phase      string                `json:"phase"`
	AfterRow   int64                 `json:"after_row"`
	SnapshotAt int64                 `json:"snapshot_at"`
	Snapshot   adminTopologySnapshot `json:"snapshot"`
}

const (
	topologyViewSummary = "summary"
	topologyViewFull    = "full"
)

func adminTopologyNote() string {
	return "Control does not persist the daemon's current Direct/Relay business path; topology edges describe account membership, private default-device ownership, device attachment, and pending signaling only."
}

func topologyBound(alias string, maxRow, snapshotAt int64) string {
	return fmt.Sprintf("%s.rowid <= %d AND %s.created_at <= %d", alias, maxRow, alias, snapshotAt)
}

func topologyFocusNetworks(accountID string, snapshot adminTopologySnapshot, snapshotAt int64) (string, []any) {
	query := `SELECT m.network_id
		FROM network_memberships m
		JOIN networks n ON n.id = m.network_id
		WHERE m.user_id = ? AND m.network_id <> 'default' AND ` +
		topologyBound("m", snapshot.Memberships, snapshotAt) + ` AND ` + topologyBound("n", snapshot.Networks, snapshotAt)
	return query, []any{accountID}
}

func captureAdminTopologySnapshot(db *DB, accountID string) (adminTopologyCursor, error) {
	snapshotAt := adminStableSnapshotAt()
	tx, err := db.Begin()
	if err != nil {
		return adminTopologyCursor{}, err
	}
	defer tx.Rollback()

	if accountID != "" {
		var exists int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ? AND id <> 'system' AND created_at <= ?`, accountID, snapshotAt).Scan(&exists); err != nil {
			return adminTopologyCursor{}, fmt.Errorf("check paged topology account: %w", err)
		}
		if exists == 0 {
			return adminTopologyCursor{}, ErrAdminAccountNotFound
		}
	}

	var snapshot adminTopologySnapshot
	if err := tx.QueryRow(`SELECT
		COALESCE((SELECT MAX(rowid) FROM users WHERE created_at <= ?), 0),
		COALESCE((SELECT MAX(rowid) FROM networks WHERE created_at <= ?), 0),
		COALESCE((SELECT MAX(rowid) FROM rooms WHERE created_at <= ?), 0),
		COALESCE((SELECT MAX(rowid) FROM network_memberships WHERE created_at <= ?), 0),
		COALESCE((SELECT MAX(rowid) FROM devices WHERE created_at <= ?), 0),
		COALESCE((SELECT MAX(rowid) FROM signals WHERE created_at <= ?), 0)`,
		snapshotAt, snapshotAt, snapshotAt, snapshotAt, snapshotAt, snapshotAt,
	).Scan(&snapshot.Users, &snapshot.Networks, &snapshot.Rooms, &snapshot.Memberships, &snapshot.Devices, &snapshot.Signals); err != nil {
		return adminTopologyCursor{}, fmt.Errorf("capture admin topology snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return adminTopologyCursor{}, err
	}
	return adminTopologyCursor{
		Version:    adminCursorVersion,
		AccountID:  accountID,
		Phase:      "accounts",
		SnapshotAt: snapshotAt,
		Snapshot:   snapshot,
	}, nil
}

func decodeAdminTopologyCursor(raw, accountID, view string) (adminTopologyCursor, error) {
	if view != topologyViewSummary && view != topologyViewFull {
		return adminTopologyCursor{}, ErrInvalidAdminTopologyView
	}
	if raw == "" {
		return adminTopologyCursor{}, nil
	}
	if len(raw) > 4096 {
		return adminTopologyCursor{}, ErrInvalidAdminCursor
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return adminTopologyCursor{}, ErrInvalidAdminCursor
	}
	var cursor adminTopologyCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return adminTopologyCursor{}, ErrInvalidAdminCursor
	}
	if cursor.Version != adminCursorVersion || cursor.AccountID != accountID || cursor.View != view || cursor.SnapshotAt <= 0 || cursor.AfterRow < 0 || !validTopologyPhase(cursor.Phase, view) {
		return adminTopologyCursor{}, ErrInvalidAdminCursor
	}
	return cursor, nil
}

func validTopologyPhase(phase, view string) bool {
	if phase == "accounts" || phase == "networks" || phase == "memberships" || phase == "done" {
		return true
	}
	return view == topologyViewFull && (phase == "devices" || phase == "personal" || phase == "signals")
}

func nextTopologyPhase(phase, view string) string {
	switch phase {
	case "accounts":
		return "networks"
	case "networks":
		return "memberships"
	case "memberships":
		if view == topologyViewSummary {
			return "done"
		}
		return "devices"
	case "devices":
		return "personal"
	case "personal":
		return "signals"
	default:
		return "done"
	}
}

func (db *DB) AdminTopologyPage(accountID, view, cursorRaw string, limit int) (*AdminTopologyPage, error) {
	accountID = strings.TrimSpace(accountID)
	view = strings.TrimSpace(view)
	if accountID == "system" {
		return nil, ErrAdminAccountNotFound
	}
	limit = normalizeAdminCursorLimit(limit)
	cursor, err := decodeAdminTopologyCursor(cursorRaw, accountID, view)
	if err != nil {
		return nil, err
	}
	if cursorRaw == "" {
		cursor, err = captureAdminTopologySnapshot(db, accountID)
		if err != nil {
			return nil, err
		}
		cursor.View = view
	}

	page := &AdminTopologyPage{
		GeneratedAt:              time.Now().Unix(),
		SnapshotAt:               cursor.SnapshotAt,
		Scope:                    "global",
		View:                     view,
		FocusAccountID:           accountID,
		PathObservationAvailable: false,
		PathObservationNote:      adminTopologyNote(),
		Nodes:                    []AdminTopologyNode{},
		Edges:                    []AdminTopologyEdge{},
	}
	if accountID != "" {
		page.Scope = "account"
	}

	// Empty phases are skipped inside one request so callers never need to
	// spin on a cursor that yielded no graph contribution. The phase count is
	// fixed and small, so this loop has a strict upper bound.
	for attempts := 0; attempts < 7 && cursor.Phase != "done"; attempts++ {
		page.Phase = cursor.Phase
		var nodes []AdminTopologyNode
		var edges []AdminTopologyEdge
		var lastRow int64
		var hasMore bool
		switch cursor.Phase {
		case "accounts":
			nodes, lastRow, hasMore, err = db.adminTopologyAccountPage(cursor, limit)
		case "networks":
			nodes, lastRow, hasMore, err = db.adminTopologyNetworkPage(cursor, limit)
		case "memberships":
			edges, lastRow, hasMore, err = db.adminTopologyMembershipPage(cursor, limit)
		case "devices":
			nodes, edges, lastRow, hasMore, err = db.adminTopologyDevicePage(cursor, limit, false)
		case "personal":
			nodes, edges, lastRow, hasMore, err = db.adminTopologyDevicePage(cursor, limit, true)
		case "signals":
			edges, lastRow, hasMore, err = db.adminTopologySignalPage(cursor, limit)
		}
		if err != nil {
			return nil, err
		}
		page.Nodes = append(page.Nodes, nodes...)
		page.Edges = append(page.Edges, edges...)
		if hasMore {
			cursor.AfterRow = lastRow
		} else {
			cursor.Phase = nextTopologyPhase(cursor.Phase, view)
			cursor.AfterRow = 0
		}
		if len(nodes) > 0 || len(edges) > 0 {
			break
		}
	}

	if cursor.Phase == "done" {
		page.Complete = true
		return page, nil
	}
	page.NextCursor, err = encodeAdminCursor(cursor)
	if err != nil {
		return nil, err
	}
	return page, nil
}

func (db *DB) adminTopologyAccountPage(cursor adminTopologyCursor, limit int) ([]AdminTopologyNode, int64, bool, error) {
	bound := topologyBound("u", cursor.Snapshot.Users, cursor.SnapshotAt)
	where := `u.id <> 'system' AND ` + bound + fmt.Sprintf(" AND u.rowid > %d", cursor.AfterRow)
	args := []any{}
	if cursor.AccountID != "" {
		focusQuery, focusArgs := topologyFocusNetworks(cursor.AccountID, cursor.Snapshot, cursor.SnapshotAt)
		where += ` AND (u.id = ? OR EXISTS (
			SELECT 1 FROM network_memberships peer
			WHERE peer.user_id = u.id AND ` + topologyBound("peer", cursor.Snapshot.Memberships, cursor.SnapshotAt) + `
			AND peer.network_id IN (` + focusQuery + `)))`
		args = append(args, cursor.AccountID)
		args = append(args, focusArgs...)
	}
	args = append(args, limit+1)
	rows, err := db.Query(`SELECT u.rowid, u.id, COALESCE(NULLIF(u.username, ''), u.email)
		FROM users u WHERE `+where+` ORDER BY u.rowid ASC LIMIT ?`, args...)
	if err != nil {
		return nil, 0, false, fmt.Errorf("paged topology accounts: %w", err)
	}
	defer rows.Close()
	type rowItem struct {
		rowID    int64
		id       string
		username string
	}
	items := make([]rowItem, 0, limit+1)
	for rows.Next() {
		var item rowItem
		if err := rows.Scan(&item.rowID, &item.id, &item.username); err != nil {
			return nil, 0, false, fmt.Errorf("scan paged topology account: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	nodes := make([]AdminTopologyNode, 0, len(items))
	var lastRow int64
	for _, item := range items {
		lastRow = item.rowID
		nodes = append(nodes, AdminTopologyNode{ID: "account:" + item.id, Kind: "account", Label: item.username, AccountID: item.id, Username: item.username, Focus: cursor.AccountID != "" && item.id == cursor.AccountID})
	}
	return nodes, lastRow, hasMore, nil
}

func (db *DB) adminTopologyNetworkPage(cursor adminTopologyCursor, limit int) ([]AdminTopologyNode, int64, bool, error) {
	where := `n.id <> 'default' AND ` + topologyBound("n", cursor.Snapshot.Networks, cursor.SnapshotAt) + fmt.Sprintf(" AND n.rowid > %d", cursor.AfterRow)
	args := []any{}
	if cursor.AccountID != "" {
		focusQuery, focusArgs := topologyFocusNetworks(cursor.AccountID, cursor.Snapshot, cursor.SnapshotAt)
		where += ` AND n.id IN (` + focusQuery + `)`
		args = append(args, focusArgs...)
	}
	args = append(args, limit+1)
	roomBound := topologyBound("r", cursor.Snapshot.Rooms, cursor.SnapshotAt)
	rows, err := db.Query(`SELECT n.rowid, n.id, n.name, n.cidr, n.owner_id,
		EXISTS(SELECT 1 FROM rooms r WHERE r.network_id=n.id AND `+roomBound+`),
		COALESCE((SELECT r.room_code FROM rooms r WHERE r.network_id=n.id AND `+roomBound+` LIMIT 1), '')
		FROM networks n WHERE `+where+` ORDER BY n.rowid ASC LIMIT ?`, args...)
	if err != nil {
		return nil, 0, false, fmt.Errorf("paged topology networks: %w", err)
	}
	defer rows.Close()
	type rowItem struct {
		rowID, isRoom int64
		id, name, cidr, ownerID, roomCode string
	}
	items := make([]rowItem, 0, limit+1)
	for rows.Next() {
		var item rowItem
		if err := rows.Scan(&item.rowID, &item.id, &item.name, &item.cidr, &item.ownerID, &item.isRoom, &item.roomCode); err != nil {
			return nil, 0, false, fmt.Errorf("scan paged topology network: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	nodes := make([]AdminTopologyNode, 0, len(items))
	var lastRow int64
	for _, item := range items {
		lastRow = item.rowID
		kind := "network"
		if item.isRoom == 1 {
			kind = "room"
		}
		nodes = append(nodes, AdminTopologyNode{ID: "network:" + item.id, Kind: kind, Label: item.name, OwnerID: item.ownerID, NetworkID: item.id, NetworkKind: kind, CIDR: item.cidr, RoomCode: item.roomCode})
	}
	return nodes, lastRow, hasMore, nil
}

func (db *DB) adminTopologyMembershipPage(cursor adminTopologyCursor, limit int) ([]AdminTopologyEdge, int64, bool, error) {
	where := `m.network_id <> 'default' AND m.user_id <> 'system' AND ` + topologyBound("m", cursor.Snapshot.Memberships, cursor.SnapshotAt) +
		` AND ` + topologyBound("u", cursor.Snapshot.Users, cursor.SnapshotAt) + ` AND ` + topologyBound("n", cursor.Snapshot.Networks, cursor.SnapshotAt) + fmt.Sprintf(" AND m.rowid > %d", cursor.AfterRow)
	args := []any{}
	if cursor.AccountID != "" {
		focusQuery, focusArgs := topologyFocusNetworks(cursor.AccountID, cursor.Snapshot, cursor.SnapshotAt)
		where += ` AND m.network_id IN (` + focusQuery + `)`
		args = append(args, focusArgs...)
	}
	args = append(args, limit+1)
	rows, err := db.Query(`SELECT m.rowid, m.user_id, m.network_id, COALESCE(m.role, 'member')
		FROM network_memberships m JOIN users u ON u.id=m.user_id JOIN networks n ON n.id=m.network_id
		WHERE `+where+` ORDER BY m.rowid ASC LIMIT ?`, args...)
	if err != nil {
		return nil, 0, false, fmt.Errorf("paged topology memberships: %w", err)
	}
	defer rows.Close()
	type rowItem struct{ rowID int64; userID, networkID, role string }
	items := make([]rowItem, 0, limit+1)
	for rows.Next() {
		var item rowItem
		if err := rows.Scan(&item.rowID, &item.userID, &item.networkID, &item.role); err != nil {
			return nil, 0, false, fmt.Errorf("scan paged topology membership: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	edges := make([]AdminTopologyEdge, 0, len(items))
	var lastRow int64
	for _, item := range items {
		lastRow = item.rowID
		edges = append(edges, AdminTopologyEdge{ID: "membership:" + item.userID + ":" + item.networkID, Source: "account:" + item.userID, Target: "network:" + item.networkID, Kind: "membership", Role: item.role})
	}
	return edges, lastRow, hasMore, nil
}

func (db *DB) adminTopologyDevicePage(cursor adminTopologyCursor, limit int, personal bool) ([]AdminTopologyNode, []AdminTopologyEdge, int64, bool, error) {
	where := topologyBound("d", cursor.Snapshot.Devices, cursor.SnapshotAt) + ` AND ` + topologyBound("u", cursor.Snapshot.Users, cursor.SnapshotAt) + fmt.Sprintf(" AND d.rowid > %d", cursor.AfterRow)
	args := []any{}
	if personal {
		where += ` AND d.network_id = 'default' AND d.user_id <> 'system'`
		if cursor.AccountID != "" {
			where += ` AND d.user_id = ?`
			args = append(args, cursor.AccountID)
		}
	} else {
		where += ` AND d.network_id <> 'default' AND ` + topologyBound("n", cursor.Snapshot.Networks, cursor.SnapshotAt)
		if cursor.AccountID != "" {
			focusQuery, focusArgs := topologyFocusNetworks(cursor.AccountID, cursor.Snapshot, cursor.SnapshotAt)
			where += ` AND d.network_id IN (` + focusQuery + `)`
			args = append(args, focusArgs...)
		}
	}
	args = append(args, limit+1)
	joinNetwork := `LEFT JOIN networks n ON n.id=d.network_id`
	if !personal {
		joinNetwork = `JOIN networks n ON n.id=d.network_id`
	}
	rows, err := db.Query(`SELECT d.rowid, d.id, d.user_id, COALESCE(NULLIF(u.username, ''), u.email),
		d.device_name, d.platform, d.virtual_ip, d.network_id, d.nat_type, d.relay_rtt_ms,
		d.last_seen, COALESCE(d.app_version, ''), d.online
		FROM devices d JOIN users u ON u.id=d.user_id `+joinNetwork+`
		WHERE `+where+` ORDER BY d.rowid ASC LIMIT ?`, args...)
	if err != nil {
		return nil, nil, 0, false, fmt.Errorf("paged topology devices: %w", err)
	}
	defer rows.Close()
	type rowItem struct {
		rowID, lastSeen, online int64
		id, userID, username, name, platform, virtualIP, networkID, natType, appVersion string
		relayRTT sql.NullInt64
	}
	items := make([]rowItem, 0, limit+1)
	for rows.Next() {
		var item rowItem
		if err := rows.Scan(&item.rowID, &item.id, &item.userID, &item.username, &item.name, &item.platform, &item.virtualIP, &item.networkID, &item.natType, &item.relayRTT, &item.lastSeen, &item.appVersion, &item.online); err != nil {
			return nil, nil, 0, false, fmt.Errorf("scan paged topology device: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, 0, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	cutoff := adminOnlineCutoff()
	nodes := make([]AdminTopologyNode, 0, len(items))
	edges := make([]AdminTopologyEdge, 0, len(items))
	var lastRow int64
	for _, item := range items {
		lastRow = item.rowID
		online := adminDeviceOnline(item.online, item.lastSeen, cutoff)
		nodes = append(nodes, AdminTopologyNode{ID: "device:" + item.id, Kind: "device", Label: item.name, AccountID: item.userID, Username: item.username, NetworkID: item.networkID, VirtualIP: item.virtualIP, Platform: item.platform, NATType: item.natType, AppVersion: item.appVersion, RelayRTTMS: nullInt64Ptr(item.relayRTT), LastSeen: item.lastSeen, Online: &online, Focus: cursor.AccountID != "" && item.userID == cursor.AccountID})
		if personal {
			edges = append(edges, AdminTopologyEdge{ID: "personal-attachment:" + item.id, Source: "account:" + item.userID, Target: "device:" + item.id, Kind: "attachment", Role: "private-default"})
		} else {
			edges = append(edges, AdminTopologyEdge{ID: "attachment:" + item.id, Source: "network:" + item.networkID, Target: "device:" + item.id, Kind: "attachment"})
		}
	}
	return nodes, edges, lastRow, hasMore, nil
}

func (db *DB) adminTopologySignalPage(cursor adminTopologyCursor, limit int) ([]AdminTopologyEdge, int64, bool, error) {
	deviceBoundF := topologyBound("fd", cursor.Snapshot.Devices, cursor.SnapshotAt)
	deviceBoundT := topologyBound("td", cursor.Snapshot.Devices, cursor.SnapshotAt)
	userBoundF := topologyBound("fu", cursor.Snapshot.Users, cursor.SnapshotAt)
	userBoundT := topologyBound("tu", cursor.Snapshot.Users, cursor.SnapshotAt)
	where := topologyBound("s", cursor.Snapshot.Signals, cursor.SnapshotAt) + fmt.Sprintf(" AND s.rowid > %d", cursor.AfterRow) +
		` AND ` + deviceBoundF + ` AND ` + deviceBoundT + ` AND ` + userBoundF + ` AND ` + userBoundT
	args := []any{}
	if cursor.AccountID == "" {
		where += ` AND (fd.network_id='default' OR (` + topologyBound("fn", cursor.Snapshot.Networks, cursor.SnapshotAt) + ` AND fn.id IS NOT NULL))`
		where += ` AND (td.network_id='default' OR (` + topologyBound("tn", cursor.Snapshot.Networks, cursor.SnapshotAt) + ` AND tn.id IS NOT NULL))`
	} else {
		focusQuery, focusArgs := topologyFocusNetworks(cursor.AccountID, cursor.Snapshot, cursor.SnapshotAt)
		where += ` AND ((fd.network_id='default' AND fd.user_id=?) OR fd.network_id IN (` + focusQuery + `))`
		args = append(args, cursor.AccountID)
		args = append(args, focusArgs...)
		focusQuery2, focusArgs2 := topologyFocusNetworks(cursor.AccountID, cursor.Snapshot, cursor.SnapshotAt)
		where += ` AND ((td.network_id='default' AND td.user_id=?) OR td.network_id IN (` + focusQuery2 + `))`
		args = append(args, cursor.AccountID)
		args = append(args, focusArgs2...)
	}
	args = append(args, limit+1)
	rows, err := db.Query(`SELECT s.rowid, s.id, s.from_node_id, s.to_node_id, s.type, s.created_at
		FROM signals s
		JOIN devices fd ON fd.id=s.from_node_id JOIN users fu ON fu.id=fd.user_id LEFT JOIN networks fn ON fn.id=fd.network_id
		JOIN devices td ON td.id=s.to_node_id JOIN users tu ON tu.id=td.user_id LEFT JOIN networks tn ON tn.id=td.network_id
		WHERE `+where+` ORDER BY s.rowid ASC LIMIT ?`, args...)
	if err != nil {
		return nil, 0, false, fmt.Errorf("paged topology signals: %w", err)
	}
	defer rows.Close()
	type rowItem struct{ rowID, createdAt int64; id, fromID, toID, signalType string }
	items := make([]rowItem, 0, limit+1)
	for rows.Next() {
		var item rowItem
		if err := rows.Scan(&item.rowID, &item.id, &item.fromID, &item.toID, &item.signalType, &item.createdAt); err != nil {
			return nil, 0, false, fmt.Errorf("scan paged topology signal: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false, err
	}
	hasMore := len(items) > limit
	if hasMore {
		items = items[:limit]
	}
	edges := make([]AdminTopologyEdge, 0, len(items))
	var lastRow int64
	for _, item := range items {
		lastRow = item.rowID
		edges = append(edges, AdminTopologyEdge{ID: "signal:" + item.id, Source: "device:" + item.fromID, Target: "device:" + item.toID, Kind: "pending_signal", SignalType: item.signalType, Count: 1, CreatedAt: item.createdAt})
	}
	return edges, lastRow, hasMore, nil
}
