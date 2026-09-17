package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrAdminAccountNotFound = errors.New("admin account not found")

type AdminAccountSummary struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	DeviceCount   int    `json:"device_count"`
	OnlineDevices int    `json:"online_devices"`
	NetworkCount  int    `json:"network_count"`
	RoomCount     int    `json:"room_count"`
	LastSeen      int64  `json:"last_seen"`
	CreatedAt     int64  `json:"created_at"`
}

type AdminAccountPage struct {
	Total  int                   `json:"total"`
	Limit  int                   `json:"limit"`
	Offset int                   `json:"offset"`
	Items  []AdminAccountSummary `json:"items"`
}

type AdminAccountDetail struct {
	Account  AdminAccountSummary   `json:"account"`
	Devices  []AdminDeviceSummary  `json:"devices"`
	Networks []AdminNetworkSummary `json:"networks"`
	Rooms    []AdminRoomSummary    `json:"rooms"`
}

// AdminTopology is a logical control-plane graph. It deliberately does not
// claim a current Direct/Relay business path because that state is owned by the
// daemon and is not persisted by Control today.
type AdminTopology struct {
	GeneratedAt              int64               `json:"generated_at"`
	Scope                    string              `json:"scope"`
	FocusAccountID           string              `json:"focus_account_id,omitempty"`
	PathObservationAvailable bool                `json:"path_observation_available"`
	PathObservationNote      string              `json:"path_observation_note"`
	Nodes                    []AdminTopologyNode `json:"nodes"`
	Edges                    []AdminTopologyEdge `json:"edges"`
}

type AdminTopologyNode struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	AccountID   string `json:"account_id,omitempty"`
	Username    string `json:"username,omitempty"`
	OwnerID     string `json:"owner_id,omitempty"`
	NetworkID   string `json:"network_id,omitempty"`
	NetworkKind string `json:"network_kind,omitempty"`
	CIDR        string `json:"cidr,omitempty"`
	RoomCode    string `json:"room_code,omitempty"`
	VirtualIP   string `json:"virtual_ip,omitempty"`
	Platform    string `json:"platform,omitempty"`
	NATType     string `json:"nat_type,omitempty"`
	AppVersion  string `json:"app_version,omitempty"`
	RelayRTTMS  *int64 `json:"relay_rtt_ms,omitempty"`
	LastSeen    int64  `json:"last_seen,omitempty"`
	Online      *bool  `json:"online,omitempty"`
	Focus       bool   `json:"focus,omitempty"`
}

type AdminTopologyEdge struct {
	ID         string `json:"id"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	Kind       string `json:"kind"`
	Role       string `json:"role,omitempty"`
	SignalType string `json:"signal_type,omitempty"`
	Count      int    `json:"count,omitempty"`
	CreatedAt  int64  `json:"created_at,omitempty"`
}

func adminAccountColumns() string {
	return `u.id,
		COALESCE(NULLIF(u.username, ''), u.email),
		u.email,
		(SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id),
		(SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.online = 1),
		(SELECT COUNT(*) FROM network_memberships m WHERE m.user_id = u.id AND m.network_id <> 'default'),
		(SELECT COUNT(*) FROM network_memberships m JOIN rooms r ON r.network_id = m.network_id WHERE m.user_id = u.id),
		COALESCE((SELECT MAX(d.last_seen) FROM devices d WHERE d.user_id = u.id), 0),
		u.created_at`
}

func scanAdminAccount(row interface{ Scan(...any) error }) (AdminAccountSummary, error) {
	var item AdminAccountSummary
	err := row.Scan(
		&item.ID,
		&item.Username,
		&item.Email,
		&item.DeviceCount,
		&item.OnlineDevices,
		&item.NetworkCount,
		&item.RoomCount,
		&item.LastSeen,
		&item.CreatedAt,
	)
	return item, err
}

func (db *DB) AdminAccounts(query string, limit, offset int) (*AdminAccountPage, error) {
	limit, offset = normalizeAdminPage(limit, offset)
	query = strings.TrimSpace(query)
	where := `u.id <> 'system'`
	args := []any{}
	if query != "" {
		escaped := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(query)
		pattern := "%" + escaped + "%"
		where += ` AND (COALESCE(NULLIF(u.username, ''), u.email) LIKE ? ESCAPE '!' OR u.email LIKE ? ESCAPE '!')`
		args = append(args, pattern, pattern)
	}

	var total int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users u WHERE `+where, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("count admin accounts: %w", err)
	}
	rows, err := db.Query(`SELECT `+adminAccountColumns()+`
		FROM users u
		WHERE `+where+`
		ORDER BY COALESCE((SELECT MAX(d.last_seen) FROM devices d WHERE d.user_id = u.id), 0) DESC,
			COALESCE(NULLIF(u.username, ''), u.email) COLLATE NOCASE ASC
		LIMIT ? OFFSET ?`, append(args, limit, offset)...)
	if err != nil {
		return nil, fmt.Errorf("list admin accounts: %w", err)
	}
	defer rows.Close()
	items := make([]AdminAccountSummary, 0, min(limit, total))
	for rows.Next() {
		item, scanErr := scanAdminAccount(rows)
		if scanErr != nil {
			return nil, fmt.Errorf("scan admin account: %w", scanErr)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return &AdminAccountPage{Total: total, Limit: limit, Offset: offset, Items: items}, nil
}

func (db *DB) AdminAccount(accountID string) (*AdminAccountDetail, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "" || accountID == "system" {
		return nil, ErrAdminAccountNotFound
	}
	account, err := scanAdminAccount(db.QueryRow(`SELECT `+adminAccountColumns()+`
		FROM users u WHERE u.id = ? AND u.id <> 'system'`, accountID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAdminAccountNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load admin account: %w", err)
	}

	detail := &AdminAccountDetail{
		Account:  account,
		Devices:  []AdminDeviceSummary{},
		Networks: []AdminNetworkSummary{},
		Rooms:    []AdminRoomSummary{},
	}

	deviceRows, err := db.Query(`SELECT `+adminDeviceColumns()+`
		FROM devices d
		JOIN users u ON u.id = d.user_id
		LEFT JOIN networks n ON n.id = d.network_id
		WHERE d.user_id = ?
		ORDER BY d.online DESC, d.last_seen DESC, d.device_name COLLATE NOCASE ASC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("load admin account devices: %w", err)
	}
	for deviceRows.Next() {
		item, scanErr := scanAdminDevice(deviceRows)
		if scanErr != nil {
			deviceRows.Close()
			return nil, fmt.Errorf("scan admin account device: %w", scanErr)
		}
		detail.Devices = append(detail.Devices, item)
	}
	if err := deviceRows.Close(); err != nil {
		return nil, err
	}
	if err := deviceRows.Err(); err != nil {
		return nil, err
	}

	networkRows, err := db.Query(`SELECT
		n.id, n.name, n.cidr,
		COALESCE(NULLIF(owner.username, ''), owner.email),
		(SELECT COUNT(*) FROM network_memberships m2 WHERE m2.network_id = n.id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = n.id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = n.id AND d.online = 1),
		EXISTS(SELECT 1 FROM rooms r WHERE r.network_id = n.id),
		n.created_at
		FROM network_memberships m
		JOIN networks n ON n.id = m.network_id
		JOIN users owner ON owner.id = n.owner_id
		WHERE m.user_id = ? AND n.id <> 'default'
		ORDER BY n.name COLLATE NOCASE ASC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("load admin account networks: %w", err)
	}
	for networkRows.Next() {
		var item AdminNetworkSummary
		var isRoom int
		if err := networkRows.Scan(&item.ID, &item.Name, &item.CIDR, &item.OwnerUsername, &item.MemberCount, &item.DeviceCount, &item.OnlineDevices, &isRoom, &item.CreatedAt); err != nil {
			networkRows.Close()
			return nil, fmt.Errorf("scan admin account network: %w", err)
		}
		item.IsRoom = isRoom == 1
		detail.Networks = append(detail.Networks, item)
	}
	if err := networkRows.Close(); err != nil {
		return nil, err
	}
	if err := networkRows.Err(); err != nil {
		return nil, err
	}

	roomRows, err := db.Query(`SELECT
		r.network_id, r.room_code, n.name, n.cidr,
		COALESCE(NULLIF(owner.username, ''), owner.email),
		(SELECT COUNT(*) FROM network_memberships m2 WHERE m2.network_id = r.network_id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = r.network_id),
		(SELECT COUNT(*) FROM devices d WHERE d.network_id = r.network_id AND d.online = 1),
		r.join_locked, r.created_at
		FROM network_memberships m
		JOIN rooms r ON r.network_id = m.network_id
		JOIN networks n ON n.id = r.network_id
		JOIN users owner ON owner.id = r.owner_id
		WHERE m.user_id = ?
		ORDER BY n.name COLLATE NOCASE ASC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("load admin account rooms: %w", err)
	}
	for roomRows.Next() {
		var item AdminRoomSummary
		var locked int
		if err := roomRows.Scan(&item.ID, &item.Code, &item.Name, &item.CIDR, &item.OwnerUsername, &item.MemberCount, &item.DeviceCount, &item.OnlineDevices, &locked, &item.CreatedAt); err != nil {
			roomRows.Close()
			return nil, fmt.Errorf("scan admin account room: %w", err)
		}
		item.JoinLocked = locked == 1
		detail.Rooms = append(detail.Rooms, item)
	}
	if err := roomRows.Close(); err != nil {
		return nil, err
	}
	if err := roomRows.Err(); err != nil {
		return nil, err
	}

	return detail, nil
}

func (db *DB) AdminTopology(accountID string) (*AdminTopology, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID == "system" {
		return nil, ErrAdminAccountNotFound
	}
	if accountID != "" {
		var exists int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ? AND id <> 'system'`, accountID).Scan(&exists); err != nil {
			return nil, fmt.Errorf("check topology account: %w", err)
		}
		if exists == 0 {
			return nil, ErrAdminAccountNotFound
		}
	}

	result := &AdminTopology{
		GeneratedAt:              time.Now().Unix(),
		Scope:                    "global",
		FocusAccountID:           accountID,
		PathObservationAvailable: false,
		PathObservationNote:      "Control does not persist the daemon's current Direct/Relay business path; topology edges describe account membership, private default-device ownership, device attachment, and pending signaling only.",
		Nodes:                    []AdminTopologyNode{},
		Edges:                    []AdminTopologyEdge{},
	}
	if accountID != "" {
		result.Scope = "account"
	}

	accountWhere := `u.id <> 'system'`
	networkWhere := `n.id <> 'default'`
	membershipWhere := `m.network_id <> 'default' AND m.user_id <> 'system'`
	deviceWhere := `d.network_id <> 'default'`
	var accountArgs, networkArgs, membershipArgs, deviceArgs []any
	if accountID != "" {
		focusNetworks := `SELECT m0.network_id FROM network_memberships m0 WHERE m0.user_id = ? AND m0.network_id <> 'default'`
		accountWhere = `(u.id = ? OR EXISTS (SELECT 1 FROM network_memberships ma WHERE ma.user_id = u.id AND ma.network_id IN (` + focusNetworks + `))) AND u.id <> 'system'`
		accountArgs = []any{accountID, accountID}
		networkWhere = `n.id IN (` + focusNetworks + `)`
		networkArgs = []any{accountID}
		membershipWhere = `m.network_id IN (` + focusNetworks + `) AND m.user_id <> 'system'`
		membershipArgs = []any{accountID}
		deviceWhere = `d.network_id IN (` + focusNetworks + `)`
		deviceArgs = []any{accountID}
	}

	accountRows, err := db.Query(`SELECT u.id, COALESCE(NULLIF(u.username, ''), u.email)
		FROM users u WHERE `+accountWhere+`
		ORDER BY COALESCE(NULLIF(u.username, ''), u.email) COLLATE NOCASE ASC`, accountArgs...)
	if err != nil {
		return nil, fmt.Errorf("topology accounts: %w", err)
	}
	for accountRows.Next() {
		var id, username string
		if err := accountRows.Scan(&id, &username); err != nil {
			accountRows.Close()
			return nil, fmt.Errorf("scan topology account: %w", err)
		}
		result.Nodes = append(result.Nodes, AdminTopologyNode{ID: "account:" + id, Kind: "account", Label: username, AccountID: id, Username: username, Focus: accountID != "" && id == accountID})
	}
	if err := accountRows.Close(); err != nil {
		return nil, err
	}
	if err := accountRows.Err(); err != nil {
		return nil, err
	}

	networkRows, err := db.Query(`SELECT n.id, n.name, n.cidr, n.owner_id,
		EXISTS(SELECT 1 FROM rooms r WHERE r.network_id = n.id),
		COALESCE((SELECT r.room_code FROM rooms r WHERE r.network_id = n.id), '')
		FROM networks n WHERE `+networkWhere+`
		ORDER BY n.name COLLATE NOCASE ASC`, networkArgs...)
	if err != nil {
		return nil, fmt.Errorf("topology networks: %w", err)
	}
	for networkRows.Next() {
		var id, name, cidr, ownerID, roomCode string
		var isRoom int
		if err := networkRows.Scan(&id, &name, &cidr, &ownerID, &isRoom, &roomCode); err != nil {
			networkRows.Close()
			return nil, fmt.Errorf("scan topology network: %w", err)
		}
		kind := "network"
		if isRoom == 1 {
			kind = "room"
		}
		result.Nodes = append(result.Nodes, AdminTopologyNode{ID: "network:" + id, Kind: kind, Label: name, OwnerID: ownerID, NetworkID: id, NetworkKind: kind, CIDR: cidr, RoomCode: roomCode})
	}
	if err := networkRows.Close(); err != nil {
		return nil, err
	}
	if err := networkRows.Err(); err != nil {
		return nil, err
	}

	membershipRows, err := db.Query(`SELECT m.user_id, m.network_id, COALESCE(m.role, 'member')
		FROM network_memberships m WHERE `+membershipWhere+`
		ORDER BY m.network_id, m.user_id`, membershipArgs...)
	if err != nil {
		return nil, fmt.Errorf("topology memberships: %w", err)
	}
	for membershipRows.Next() {
		var userID, networkID, role string
		if err := membershipRows.Scan(&userID, &networkID, &role); err != nil {
			membershipRows.Close()
			return nil, fmt.Errorf("scan topology membership: %w", err)
		}
		result.Edges = append(result.Edges, AdminTopologyEdge{ID: "membership:" + userID + ":" + networkID, Source: "account:" + userID, Target: "network:" + networkID, Kind: "membership", Role: role})
	}
	if err := membershipRows.Close(); err != nil {
		return nil, err
	}
	if err := membershipRows.Err(); err != nil {
		return nil, err
	}

	deviceIDs := map[string]struct{}{}
	deviceRows, err := db.Query(`SELECT d.id, d.user_id, COALESCE(NULLIF(u.username, ''), u.email),
		d.device_name, d.platform, d.virtual_ip, d.network_id, d.nat_type, d.relay_rtt_ms,
		d.last_seen, COALESCE(d.app_version, ''), d.online
		FROM devices d JOIN users u ON u.id = d.user_id
		WHERE `+deviceWhere+`
		ORDER BY d.online DESC, d.device_name COLLATE NOCASE ASC`, deviceArgs...)
	if err != nil {
		return nil, fmt.Errorf("topology devices: %w", err)
	}
	for deviceRows.Next() {
		var id, userID, username, name, platform, virtualIP, networkID, natType, appVersion string
		var relayRTT sql.NullInt64
		var lastSeen int64
		var onlineInt int
		if err := deviceRows.Scan(&id, &userID, &username, &name, &platform, &virtualIP, &networkID, &natType, &relayRTT, &lastSeen, &appVersion, &onlineInt); err != nil {
			deviceRows.Close()
			return nil, fmt.Errorf("scan topology device: %w", err)
		}
		online := onlineInt == 1
		deviceIDs[id] = struct{}{}
		result.Nodes = append(result.Nodes, AdminTopologyNode{ID: "device:" + id, Kind: "device", Label: name, AccountID: userID, Username: username, NetworkID: networkID, VirtualIP: virtualIP, Platform: platform, NATType: natType, AppVersion: appVersion, RelayRTTMS: nullInt64Ptr(relayRTT), LastSeen: lastSeen, Online: &online, Focus: accountID != "" && userID == accountID})
		result.Edges = append(result.Edges, AdminTopologyEdge{ID: "attachment:" + id, Source: "network:" + networkID, Target: "device:" + id, Kind: "attachment"})
	}
	if err := deviceRows.Close(); err != nil {
		return nil, err
	}
	if err := deviceRows.Err(); err != nil {
		return nil, err
	}

	// The legacy database has one shared row called "default", but product
	// semantics explicitly keep that roster account-private. Drawing the shared
	// row would falsely imply cross-account reachability; dropping it entirely
	// would hide the most common personal devices. Render those devices directly
	// under their owning account instead.
	personalWhere := `d.network_id = 'default' AND d.user_id <> 'system'`
	personalArgs := []any{}
	if accountID != "" {
		personalWhere += ` AND d.user_id = ?`
		personalArgs = append(personalArgs, accountID)
	}
	personalRows, err := db.Query(`SELECT d.id, d.user_id, COALESCE(NULLIF(u.username, ''), u.email),
		d.device_name, d.platform, d.virtual_ip, d.network_id, d.nat_type, d.relay_rtt_ms,
		d.last_seen, COALESCE(d.app_version, ''), d.online
		FROM devices d JOIN users u ON u.id = d.user_id
		WHERE `+personalWhere+`
		ORDER BY d.online DESC, d.device_name COLLATE NOCASE ASC`, personalArgs...)
	if err != nil {
		return nil, fmt.Errorf("topology personal devices: %w", err)
	}
	for personalRows.Next() {
		var id, userID, username, name, platform, virtualIP, networkID, natType, appVersion string
		var relayRTT sql.NullInt64
		var lastSeen int64
		var onlineInt int
		if err := personalRows.Scan(&id, &userID, &username, &name, &platform, &virtualIP, &networkID, &natType, &relayRTT, &lastSeen, &appVersion, &onlineInt); err != nil {
			personalRows.Close()
			return nil, fmt.Errorf("scan topology personal device: %w", err)
		}
		online := onlineInt == 1
		deviceIDs[id] = struct{}{}
		result.Nodes = append(result.Nodes, AdminTopologyNode{ID: "device:" + id, Kind: "device", Label: name, AccountID: userID, Username: username, NetworkID: networkID, VirtualIP: virtualIP, Platform: platform, NATType: natType, AppVersion: appVersion, RelayRTTMS: nullInt64Ptr(relayRTT), LastSeen: lastSeen, Online: &online, Focus: accountID != "" && userID == accountID})
		result.Edges = append(result.Edges, AdminTopologyEdge{ID: "personal-attachment:" + id, Source: "account:" + userID, Target: "device:" + id, Kind: "attachment", Role: "private-default"})
	}
	if err := personalRows.Close(); err != nil {
		return nil, err
	}
	if err := personalRows.Err(); err != nil {
		return nil, err
	}

	// Signaling is durable coordination state, not proof of a connected data path.
	signalRows, err := db.Query(`SELECT from_node_id, to_node_id, type, COUNT(*), MAX(created_at)
		FROM signals GROUP BY from_node_id, to_node_id, type ORDER BY MAX(created_at) DESC`)
	if err != nil {
		return nil, fmt.Errorf("topology pending signals: %w", err)
	}
	for signalRows.Next() {
		var fromID, toID, signalType string
		var count int
		var createdAt int64
		if err := signalRows.Scan(&fromID, &toID, &signalType, &count, &createdAt); err != nil {
			signalRows.Close()
			return nil, fmt.Errorf("scan topology pending signal: %w", err)
		}
		if _, ok := deviceIDs[fromID]; !ok {
			continue
		}
		if _, ok := deviceIDs[toID]; !ok {
			continue
		}
		result.Edges = append(result.Edges, AdminTopologyEdge{ID: fmt.Sprintf("signal:%s:%s:%s", fromID, toID, signalType), Source: "device:" + fromID, Target: "device:" + toID, Kind: "pending_signal", SignalType: signalType, Count: count, CreatedAt: createdAt})
	}
	if err := signalRows.Close(); err != nil {
		return nil, err
	}
	if err := signalRows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
