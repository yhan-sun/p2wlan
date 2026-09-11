package database

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrRoomAccess    = errors.New("room not found or access denied")
	ErrRoomExists    = errors.New("you already own a room")
	ErrRoomInvalid   = errors.New("invalid room request")
	ErrRoomJoin      = errors.New("invalid room or join credential")
	ErrRoomExhausted = errors.New("room address pool exhausted")
	ErrRoomConflict  = errors.New("room operation conflicts with current state")
	ErrRoomRateLimit = errors.New("too many room join attempts")
)

var (
	ErrRoomIPConflict          = fmt.Errorf("%w: room address unavailable", ErrRoomConflict)
	ErrRoomDeviceStateConflict = fmt.Errorf("%w: room device state changed", ErrRoomConflict)
	ErrRoomInviteLimit         = fmt.Errorf("%w: room invite limit reached", ErrRoomConflict)
)

const RoomAuthorizationLeaseSeconds = 30
const roomSubnetQuarantineSeconds = 300
const roomColumns = `r.network_id, r.room_code, n.name, n.cidr, r.owner_id, r.join_locked, r.revision, r.created_at`

var roomDummyHash, _ = bcrypt.GenerateFromPassword([]byte("p2wlan-room-dummy-credential"), bcrypt.DefaultCost)

type Room struct {
	DeviceControlsVersion int      `json:"device_controls_version"`
	OwnerUsername         string   `json:"owner_username"`
	MemberCount           int      `json:"member_count"`
	OnlineMemberCount     int      `json:"online_member_count"`
	OwnerDeviceIPs        []string `json:"owner_device_ips"`

	ID         string `json:"id"`
	Code       string `json:"room_code"`
	Name       string `json:"name"`
	CIDR       string `json:"cidr"`
	OwnerID    string `json:"owner_id"`
	JoinLocked bool   `json:"join_locked"`
	Revision   int64  `json:"revision"`
	CreatedAt  int64  `json:"created_at"`
	Role       string `json:"role"`
}

type RoomMember struct {
	Username  string `json:"username"`
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	CreatedAt int64  `json:"created_at"`
}

type RoomDetails struct {
	Room                   *Room              `json:"room"`
	Members                []RoomMember       `json:"members"`
	Devices                []Device           `json:"devices"`
	BannedUserIDs          []string           `json:"banned_user_ids"`
	DeviceAccess           []RoomDeviceAccess `json:"device_access"`
	DeviceApprovalRequired bool               `json:"device_approval_required"`
}

type RoomInvite struct {
	ID        string `json:"id"`
	ExpiresAt int64  `json:"expires_at"`
	MaxUses   int    `json:"max_uses"`
	Uses      int    `json:"uses"`
	Revoked   bool   `json:"revoked"`
	CreatedAt int64  `json:"created_at"`
}

func migrateRooms(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS room_write_lock (id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL);
	INSERT OR IGNORE INTO room_write_lock (id, revision) VALUES (1, 0);
	CREATE TABLE IF NOT EXISTS rooms (
		network_id TEXT PRIMARY KEY REFERENCES networks(id) ON DELETE CASCADE,
		room_code TEXT NOT NULL UNIQUE,
		owner_id TEXT NOT NULL UNIQUE REFERENCES users(id),
		password_hash BLOB NOT NULL,
		join_locked INTEGER NOT NULL DEFAULT 0,
		revision INTEGER NOT NULL DEFAULT 1,
		created_at INTEGER NOT NULL
	);
	CREATE TABLE IF NOT EXISTS room_subnets (
		cidr TEXT PRIMARY KEY,
		network_id TEXT UNIQUE,
		reusable_after INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE IF NOT EXISTS room_bans (
		network_id TEXT NOT NULL REFERENCES rooms(network_id) ON DELETE CASCADE,
		user_id TEXT NOT NULL REFERENCES users(id),
		created_at INTEGER NOT NULL,
		PRIMARY KEY (network_id, user_id)
	);
	CREATE TABLE IF NOT EXISTS room_invites (
		id TEXT PRIMARY KEY,
		network_id TEXT NOT NULL REFERENCES rooms(network_id) ON DELETE CASCADE,
		token_hash BLOB NOT NULL UNIQUE,
		expires_at INTEGER NOT NULL,
		max_uses INTEGER NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
		uses INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
		revoked INTEGER NOT NULL DEFAULT 0,
		created_at INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_room_invites_network ON room_invites(network_id);
	CREATE TABLE IF NOT EXISTS room_join_limits (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		window_start INTEGER NOT NULL,
		attempts INTEGER NOT NULL
	);
	CREATE TRIGGER IF NOT EXISTS room_device_member_insert BEFORE INSERT ON devices
	WHEN EXISTS (SELECT 1 FROM rooms WHERE network_id = NEW.network_id)
	AND NOT EXISTS (SELECT 1 FROM network_memberships WHERE network_id = NEW.network_id AND user_id = NEW.user_id)
	BEGIN SELECT RAISE(ABORT, 'room membership required'); END;
	CREATE TRIGGER IF NOT EXISTS room_device_member_update BEFORE UPDATE OF network_id, user_id ON devices
	WHEN EXISTS (SELECT 1 FROM rooms WHERE network_id = NEW.network_id)
	AND NOT EXISTS (SELECT 1 FROM network_memberships WHERE network_id = NEW.network_id AND user_id = NEW.user_id)
	BEGIN SELECT RAISE(ABORT, 'room membership required'); END;
	`)
	if err != nil {
		return err
	}
	return migrateRoomDevices(db)
}

func (db *DB) beginRoomWrite() (*sql.Tx, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	if _, err = tx.Exec(`UPDATE room_write_lock SET revision = revision + 1 WHERE id = 1`); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func roomRandomID(prefix string, size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func validRoomName(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) >= 1 && utf8.RuneCountInString(name) <= 64 && !strings.ContainsAny(name, "\x00\r\n")
}

func roomPasswordHash(password string) ([]byte, error) {
	if len(password) < 8 || len(password) > 72 || !utf8.ValidString(password) {
		return nil, ErrRoomInvalid
	}
	return bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
}

func scanRoom(row interface{ Scan(...any) error }) (*Room, error) {
	r := &Room{DeviceControlsVersion: 1}
	err := row.Scan(&r.ID, &r.Code, &r.Name, &r.CIDR, &r.OwnerID, &r.JoinLocked, &r.Revision, &r.CreatedAt)
	return r, err
}

func roomOwner(tx *sql.Tx, userID, roomID string) error {
	var ok bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM rooms WHERE network_id = ? AND owner_id = ?)`, roomID, userID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrRoomAccess
	}
	return nil
}

func (db *DB) IsRoom(networkID string) (bool, error) {
	var yes bool
	err := db.QueryRow(`SELECT EXISTS(SELECT 1 FROM rooms WHERE network_id = ?)`, networkID).Scan(&yes)
	return yes, err
}

func (db *DB) CreateRoom(ownerID, name, password string) (*Room, error) {
	name = strings.TrimSpace(name)
	if !validRoomName(name) {
		return nil, ErrRoomInvalid
	}
	hash, err := roomPasswordHash(password)
	if err != nil {
		return nil, err
	}
	id, err := roomRandomID("room-", 16)
	if err != nil {
		return nil, err
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rooms WHERE owner_id = ?`, ownerID).Scan(&count); err != nil {
		return nil, err
	}
	if count != 0 {
		return nil, ErrRoomExists
	}
	cidr, err := allocateRoomSubnet(tx, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	var code string
	for i := 0; i < 32; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(90000000))
		if err != nil {
			return nil, err
		}
		code = fmt.Sprintf("%08d", n.Int64()+10000000)
		if err := tx.QueryRow(`SELECT COUNT(*) FROM rooms WHERE room_code = ?`, code).Scan(&count); err != nil {
			return nil, err
		}
		if count == 0 {
			break
		}
		code = ""
	}
	if code == "" {
		return nil, ErrRoomConflict
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES (?, ?, ?, ?, ?)`, id, name, cidr, ownerID, now); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO rooms (network_id, room_code, owner_id, password_hash, created_at) VALUES (?, ?, ?, ?, ?)`, id, code, ownerID, hash, now); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES (?, ?, ?, 'owner', ?)`, "mem-"+id, ownerID, id, now); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`INSERT INTO room_subnets (cidr, network_id) VALUES (?, ?) ON CONFLICT(cidr) DO UPDATE SET network_id = excluded.network_id, reusable_after = 0`, cidr, id); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &Room{ID: id, Code: code, Name: name, CIDR: cidr, OwnerID: ownerID, CreatedAt: now, Revision: 1, Role: "owner", DeviceControlsVersion: 1}, nil
}

func allocateRoomSubnet(tx *sql.Tx, now int64) (string, error) {
	rows, err := tx.Query(`SELECT cidr FROM networks UNION SELECT cidr FROM room_subnets WHERE network_id IS NOT NULL OR reusable_after > ?`, now)
	if err != nil {
		return "", err
	}
	var occupied []netip.Prefix
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return "", err
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			rows.Close()
			return "", fmt.Errorf("invalid existing network CIDR: %w", err)
		}
		occupied = append(occupied, prefix.Masked())
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	for i := 1; i <= 256; i++ {
		candidate := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 21, byte(i % 256), 0}), 24)
		conflict := false
		for _, prefix := range occupied {
			if candidate.Overlaps(prefix) {
				conflict = true
				break
			}
		}
		if !conflict {
			return candidate.String(), nil
		}
	}
	return "", ErrRoomExhausted
}

func (db *DB) ListRooms(userID string) ([]Room, error) {
	rows, err := db.Query(`SELECT `+roomColumns+`, m.role,
 (SELECT username FROM users WHERE id = r.owner_id),
 (SELECT COUNT(*) FROM network_memberships WHERE network_id = r.network_id),
 (SELECT COUNT(DISTINCT d.user_id) FROM devices d JOIN network_memberships nm ON nm.user_id = d.user_id AND nm.network_id = d.network_id WHERE d.network_id = r.network_id AND d.online = 1 AND d.last_seen > 0 AND d.last_seen >= ?),
 COALESCE((SELECT GROUP_CONCAT(virtual_ip) FROM devices WHERE network_id = r.network_id AND user_id = r.owner_id AND online = 1 AND last_seen > 0 AND last_seen >= ?), '')
 FROM rooms r JOIN networks n ON n.id = r.network_id JOIN network_memberships m ON m.network_id = r.network_id WHERE m.user_id = ? ORDER BY CASE WHEN r.owner_id = ? THEN 0 ELSE 1 END, r.created_at, r.network_id`, time.Now().Unix()-DeviceOnlineTTL, time.Now().Unix()-DeviceOnlineTTL, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Room{}
	for rows.Next() {
		var r Room
		r.DeviceControlsVersion = 1
		var ownerIPs string
		if err := rows.Scan(&r.ID, &r.Code, &r.Name, &r.CIDR, &r.OwnerID, &r.JoinLocked, &r.Revision, &r.CreatedAt, &r.Role, &r.OwnerUsername, &r.MemberCount, &r.OnlineMemberCount, &ownerIPs); err != nil {
			return nil, err
		}
		r.OwnerDeviceIPs = []string{}
		if ownerIPs != "" {
			r.OwnerDeviceIPs = strings.Split(ownerIPs, ",")
		}
		result = append(result, r)
	}
	return result, rows.Err()
}

func (db *DB) GetRoom(userID, roomID string) (*RoomDetails, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	room, err := scanRoom(tx.QueryRow(`SELECT `+roomColumns+` FROM rooms r JOIN networks n ON n.id = r.network_id JOIN network_memberships m ON m.network_id = r.network_id WHERE r.network_id = ? AND m.user_id = ?`, roomID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRoomAccess
	}
	if err != nil {
		return nil, err
	}
	room.Role = "member"
	if room.OwnerID == userID {
		room.Role = "owner"
	}
	out := &RoomDetails{Room: room, Members: []RoomMember{}, Devices: []Device{}, BannedUserIDs: []string{}}
	rows, err := tx.Query(`SELECT m.user_id, m.role, m.created_at, u.username FROM network_memberships m JOIN users u ON u.id = m.user_id WHERE m.network_id = ? ORDER BY CASE WHEN m.role = 'owner' THEN 0 ELSE 1 END, m.created_at, m.user_id`, roomID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var m RoomMember
		if err := rows.Scan(&m.UserID, &m.Role, &m.CreatedAt, &m.Username); err != nil {
			rows.Close()
			return nil, err
		}
		out.Members = append(out.Members, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.Query(`SELECT id, user_id, device_name, platform, virtual_ip, app_version, online, last_seen FROM devices WHERE network_id = ? ORDER BY user_id, created_at, id`, roomID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var d Device
		d.NetworkID = roomID
		if err := rows.Scan(&d.ID, &d.UserID, &d.DeviceName, &d.Platform, &d.VirtualIP, &d.AppVersion, &d.Online, &d.LastSeen); err != nil {
			rows.Close()
			return nil, err
		}
		d.Online = d.Online && d.LastSeen > 0 && time.Now().Unix()-d.LastSeen <= DeviceOnlineTTL
		out.Devices = append(out.Devices, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if room.OwnerID == userID {
		rows, err = tx.Query(`SELECT user_id FROM room_bans WHERE network_id = ? ORDER BY created_at, user_id`, roomID)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			out.BannedUserIDs = append(out.BannedUserIDs, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	if err := loadRoomDeviceAccess(tx, out); err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func (db *DB) consumeRoomJoinAttempt(userID string) error {
	now := time.Now().Unix()
	var attempts int
	err := db.QueryRow(`INSERT INTO room_join_limits (user_id, window_start, attempts) VALUES (?, ?, 1)
	ON CONFLICT(user_id) DO UPDATE SET
	attempts = CASE WHEN room_join_limits.window_start <= ? OR room_join_limits.window_start > ? THEN 1 ELSE room_join_limits.attempts + 1 END,
	window_start = CASE WHEN room_join_limits.window_start <= ? OR room_join_limits.window_start > ? THEN excluded.window_start ELSE room_join_limits.window_start END
	RETURNING attempts`, userID, now, now-60, now, now-60, now).Scan(&attempts)
	if err != nil {
		return err
	}
	if attempts > 10 {
		return ErrRoomRateLimit
	}
	return nil
}

func (db *DB) JoinRoom(userID, code, password, inviteToken string) (*Room, error) {
	if err := db.consumeRoomJoinAttempt(userID); err != nil {
		return nil, err
	}
	if len(code) != 8 || len(password) > 72 || len(inviteToken) > 128 || (password == "") == (inviteToken == "") {
		return nil, ErrRoomJoin
	}
	var roomID string
	var hash []byte
	var revision int64
	err := db.QueryRow(`SELECT network_id, password_hash, revision FROM rooms WHERE room_code = ?`, code).Scan(&roomID, &hash, &revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if password != "" {
		compareHash := hash
		if len(compareHash) == 0 {
			compareHash = roomDummyHash
		}
		if bcrypt.CompareHashAndPassword(compareHash, []byte(password)) != nil || roomID == "" {
			return nil, ErrRoomJoin
		}
	} else if roomID == "" {
		return nil, ErrRoomJoin
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	room, err := scanRoom(tx.QueryRow(`SELECT `+roomColumns+` FROM rooms r JOIN networks n ON n.id = r.network_id WHERE r.network_id = ? AND r.revision = ?`, roomID, revision))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRoomJoin
	}
	if err != nil {
		return nil, err
	}
	var banned, joined bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM room_bans WHERE network_id = ? AND user_id = ?), EXISTS(SELECT 1 FROM network_memberships WHERE network_id = ? AND user_id = ?)`, roomID, userID, roomID, userID).Scan(&banned, &joined); err != nil {
		return nil, err
	}
	if banned {
		return nil, ErrRoomJoin
	}
	var inviteID string
	if inviteToken != "" {
		digest := sha256.Sum256([]byte(inviteToken))
		query := `SELECT id FROM room_invites WHERE network_id = ? AND token_hash = ? AND revoked = 0 AND expires_at > ?`
		if !joined {
			query += ` AND uses < max_uses`
		}
		if err := tx.QueryRow(query, roomID, digest[:], time.Now().Unix()).Scan(&inviteID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrRoomJoin
			}
			return nil, err
		}
	}
	if !joined {
		if room.JoinLocked {
			return nil, ErrRoomJoin
		}
		id, err := roomRandomID("mem-", 16)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES (?, ?, ?, 'member', ?)`, id, userID, roomID, time.Now().Unix()); err != nil {
			return nil, err
		}
		if inviteID != "" {
			if _, err := tx.Exec(`UPDATE room_invites SET uses = uses + 1 WHERE id = ?`, inviteID); err != nil {
				return nil, err
			}
		}
	}
	room.Role = "member"
	if userID == room.OwnerID {
		room.Role = "owner"
	}
	return room, tx.Commit()
}

func (db *DB) UpdateRoom(userID, roomID string, name, password *string, locked *bool) error {
	var hash []byte
	var err error
	if name == nil && password == nil && locked == nil {
		return ErrRoomInvalid
	}
	if name != nil {
		n := strings.TrimSpace(*name)
		name = &n
		if !validRoomName(n) {
			return ErrRoomInvalid
		}
	}
	if password != nil {
		hash, err = roomPasswordHash(*password)
		if err != nil {
			return err
		}
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, userID, roomID); err != nil {
		return err
	}
	if name != nil {
		if _, err := tx.Exec(`UPDATE networks SET name = ? WHERE id = ?`, *name, roomID); err != nil {
			return err
		}
	}
	if password != nil {
		if _, err := tx.Exec(`UPDATE rooms SET password_hash = ? WHERE network_id = ?`, hash, roomID); err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE room_invites SET revoked = 1 WHERE network_id = ?`, roomID); err != nil {
			return err
		}
	}
	if locked != nil {
		if _, err := tx.Exec(`UPDATE rooms SET join_locked = ? WHERE network_id = ?`, *locked, roomID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`UPDATE rooms SET revision = revision + 1 WHERE network_id = ?`, roomID); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) CreateRoomInvite(userID, roomID string, ttlSeconds int64, maxUses int) (*RoomInvite, string, error) {
	if ttlSeconds < 60 || ttlSeconds > 7*24*3600 || maxUses < 1 || maxUses > 1000 {
		return nil, "", ErrRoomInvalid
	}
	token, err := roomRandomID("", 32)
	if err != nil {
		return nil, "", err
	}
	id, err := roomRandomID("invite-", 16)
	if err != nil {
		return nil, "", err
	}
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, "", err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, userID, roomID); err != nil {
		return nil, "", err
	}
	now := time.Now().Unix()
	if _, err := tx.Exec(`DELETE FROM room_invites WHERE network_id = ? AND (expires_at <= ? OR revoked = 1)`, roomID, now); err != nil {
		return nil, "", err
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM room_invites WHERE network_id = ?`, roomID).Scan(&count); err != nil {
		return nil, "", err
	}
	if count >= 32 {
		return nil, "", ErrRoomInviteLimit
	}
	digest := sha256.Sum256([]byte(token))
	invite := &RoomInvite{ID: id, ExpiresAt: now + ttlSeconds, MaxUses: maxUses, CreatedAt: now}
	if _, err := tx.Exec(`INSERT INTO room_invites (id, network_id, token_hash, expires_at, max_uses, created_at) VALUES (?, ?, ?, ?, ?, ?)`, id, roomID, digest[:], invite.ExpiresAt, maxUses, now); err != nil {
		return nil, "", err
	}
	if err := tx.Commit(); err != nil {
		return nil, "", err
	}
	return invite, token, nil
}

func (db *DB) ListRoomInvites(userID, roomID string) ([]RoomInvite, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, userID, roomID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(`SELECT id, expires_at, max_uses, uses, revoked, created_at FROM room_invites WHERE network_id = ? ORDER BY created_at DESC, id`, roomID)
	if err != nil {
		return nil, err
	}
	result := []RoomInvite{}
	for rows.Next() {
		var i RoomInvite
		if err := rows.Scan(&i.ID, &i.ExpiresAt, &i.MaxUses, &i.Uses, &i.Revoked, &i.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		result = append(result, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return result, tx.Commit()
}

func (db *DB) RevokeRoomInvite(userID, roomID, inviteID string) error {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, userID, roomID); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE room_invites SET revoked = 1 WHERE network_id = ? AND id = ?`, roomID, inviteID); err != nil {
		return err
	}
	return tx.Commit()
}

func revokeRoomDeviceTx(tx *sql.Tx, deviceID string, remove bool) error {
	now := time.Now().Unix()
	if remove {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO relay_revocations (kind, value, created_at) VALUES (?, ?, ?)`, RelayRevocationDeviceID, deviceID, now); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO relay_revocations (kind, value, created_at) SELECT ?, id, ? FROM device_credentials WHERE device_id = ?`, RelayRevocationCredentialID, now, deviceID); err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM tunnels WHERE device_id = ?`,
		`DELETE FROM device_challenges WHERE device_id = ?`,
		`UPDATE device_credentials SET revoked = 1 WHERE device_id = ?`,
		`UPDATE devices SET online = 0, endpoint = '', nat_type = 'unknown', relay_rtt_ms = NULL WHERE id = ?`,
	} {
		if _, err := tx.Exec(query, deviceID); err != nil {
			return err
		}
	}
	for _, query := range []string{
		`DELETE FROM signals WHERE from_node_id = ? OR to_node_id = ?`,
	} {
		if _, err := tx.Exec(query, deviceID, deviceID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM signal_send_events WHERE from_node_id = ?`, deviceID); err != nil {
		return err
	}
	if remove {
		if _, err := tx.Exec(`DELETE FROM signal_seqs WHERE from_node_id = ? OR to_node_id = ?`, deviceID, deviceID); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM devices WHERE id = ?`, deviceID); err != nil {
			return err
		}
	}
	return nil
}

func roomDeviceIDs(tx *sql.Tx, roomID, userID string) ([]string, error) {
	query := `SELECT id FROM devices WHERE network_id = ?`
	args := []any{roomID}
	if userID != "" {
		query += ` AND user_id = ?`
		args = append(args, userID)
	}
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (db *DB) RemoveRoomMember(actorID, roomID, targetID string, ban bool) ([]string, error) {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var ownerID string
	if err := tx.QueryRow(`SELECT owner_id FROM rooms WHERE network_id = ?`, roomID).Scan(&ownerID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRoomAccess
		}
		return nil, err
	}
	if ownerID != actorID && (actorID != targetID || ban) {
		return nil, ErrRoomAccess
	}
	if targetID == ownerID {
		return nil, ErrRoomConflict
	}
	var member bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM network_memberships WHERE network_id = ? AND user_id = ?)`, roomID, actorID).Scan(&member); err != nil {
		return nil, err
	}
	if !member {
		return nil, ErrRoomAccess
	}
	ids, err := roomDeviceIDs(tx, roomID, targetID)
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := revokeRoomDeviceTx(tx, id, true); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`DELETE FROM network_memberships WHERE network_id = ? AND user_id = ?`, roomID, targetID); err != nil {
		return nil, err
	}
	if ban {
		if _, err := tx.Exec(`INSERT OR IGNORE INTO room_bans (network_id, user_id, created_at) VALUES (?, ?, ?)`, roomID, targetID, time.Now().Unix()); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`UPDATE rooms SET revision = revision + 1 WHERE network_id = ?`, roomID); err != nil {
		return nil, err
	}
	return ids, tx.Commit()
}

func (db *DB) UnbanRoomMember(actorID, roomID, targetID string) error {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, actorID, roomID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM room_bans WHERE network_id = ? AND user_id = ?`, roomID, targetID); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) DeleteRoom(actorID, roomID string) ([]string, error) {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, actorID, roomID); err != nil {
		return nil, err
	}
	ids, err := roomDeviceIDs(tx, roomID, "")
	if err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := revokeRoomDeviceTx(tx, id, true); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`UPDATE room_subnets SET network_id = NULL, reusable_after = ? WHERE network_id = ?`, time.Now().Unix()+roomSubnetQuarantineSeconds, roomID); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM networks WHERE id = ?`, roomID); err != nil {
		return nil, err
	}
	return ids, tx.Commit()
}

func (db *DB) AssignRoomDeviceIP(actorID, roomID, deviceID, ip string) error {
	_, err := db.AssignRoomDeviceIPIfChanged(actorID, roomID, deviceID, ip)
	return err
}

func (db *DB) AssignRoomDeviceIPIfChanged(actorID, roomID, deviceID, ip string) (bool, error) {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, actorID, roomID); err != nil {
		return false, err
	}
	var currentIP string
	if err := tx.QueryRow(`SELECT virtual_ip FROM devices WHERE id = ? AND network_id = ?`, deviceID, roomID).Scan(&currentIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrRoomAccess
		}
		return false, err
	}
	if ip == "" {
		return false, ErrRoomInvalid
	}
	reserved, err := db.reserveVirtualIP(tx, roomID, ip, deviceID)
	if err != nil {
		return false, fmt.Errorf("%w: %s", ErrRoomIPConflict, err)
	}
	if reserved == currentIP {
		return false, tx.Commit()
	}
	if err := revokeRoomDeviceTx(tx, deviceID, false); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE devices SET virtual_ip = ? WHERE id = ?`, reserved, deviceID); err != nil {
		return false, err
	}
	if _, err := tx.Exec(`UPDATE rooms SET revision = revision + 1 WHERE network_id = ?`, roomID); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (db *DB) DeleteRoomDevice(actorID, roomID, deviceID string) error {
	tx, err := db.beginRoomWrite()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := roomOwner(tx, actorID, roomID); err != nil {
		return err
	}
	var found bool
	if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM devices WHERE id = ? AND network_id = ?)`, deviceID, roomID).Scan(&found); err != nil {
		return err
	}
	if !found {
		return ErrRoomAccess
	}
	if err := revokeRoomDeviceTx(tx, deviceID, true); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) ListVisibleDevices(userID, networkID string) ([]Device, error) {
	return db.listDevices(`FROM devices d WHERE d.network_id = ? AND NOT EXISTS(SELECT 1 FROM room_device_access a WHERE a.network_id=d.network_id AND a.public_key=d.public_key AND a.state!='allowed') AND ((d.user_id = ? AND NOT EXISTS(SELECT 1 FROM rooms WHERE network_id = d.network_id)) OR (EXISTS (SELECT 1 FROM network_memberships self WHERE self.network_id = d.network_id AND self.user_id = ?) AND EXISTS (SELECT 1 FROM rooms WHERE network_id = d.network_id) AND EXISTS (SELECT 1 FROM network_memberships peer WHERE peer.network_id = d.network_id AND peer.user_id = d.user_id)))`, networkID, userID, userID)
}

func (db *DB) DevicesMayCommunicate(fromID, toID string) (bool, error) {
	var allowed bool
	err := db.QueryRow(devicesMayCommunicateSQL, fromID, toID).Scan(&allowed)
	return allowed, err
}

const devicesMayCommunicateSQL = `SELECT EXISTS(SELECT 1 FROM devices a JOIN devices b ON b.network_id = a.network_id WHERE a.id = ? AND b.id = ? AND NOT EXISTS(SELECT 1 FROM room_device_access access WHERE access.network_id=a.network_id AND access.public_key IN (a.public_key,b.public_key) AND access.state!='allowed') AND (
		(a.user_id = b.user_id AND NOT EXISTS(SELECT 1 FROM rooms WHERE network_id = a.network_id)) OR
		(EXISTS(SELECT 1 FROM rooms WHERE network_id = a.network_id) AND EXISTS(SELECT 1 FROM network_memberships WHERE network_id = a.network_id AND user_id = a.user_id) AND EXISTS(SELECT 1 FROM network_memberships WHERE network_id = b.network_id AND user_id = b.user_id))
	))`
