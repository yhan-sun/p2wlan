package database

import (
	"crypto/rand"
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

const (
	MaxJoinedRooms = 32
	MaxRoomMembers = 254
	RoomLeaseSeconds = 30
	RoomClientLeaseSeconds = 60
)

var (
	ErrRoomNotFound = errors.New("room_not_found")
	ErrRoomForbidden = errors.New("room_access_denied")
	ErrRoomAlreadyOwned = errors.New("one_owned_room_per_account")
	ErrRoomCredentials = errors.New("invalid_room_credentials")
	ErrRoomJoinRateLimited = errors.New("room_join_rate_limited")
	ErrRoomLimit = errors.New("room_limit_reached")
	ErrRoomSubnetExhausted = errors.New("room_subnet_pool_exhausted")
	ErrRoomIPUnavailable = errors.New("room_ip_unavailable")
	ErrRoomInvalidInput = errors.New("invalid_room_input")
	ErrRoomOwnerCannotLeave = errors.New("owner_must_dissolve_room")
	ErrRoomUnsupportedNetwork = errors.New("room_device_requires_default_network")
)

type Room struct {
	ID string `json:"id"`
	Number string `json:"number"`
	Name string `json:"name"`
	CIDR string `json:"cidr"`
	OwnerID string `json:"owner_id"`
	Revision int64 `json:"revision"`
	CreatedAt int64 `json:"created_at"`
	Role string `json:"role"`
}

type RoomMember struct {
	UserID string `json:"user_id"`
	Role string `json:"role"`
	JoinedAt int64 `json:"joined_at"`
	Banned bool `json:"banned"`
}

type RoomDevice struct {
	DeviceID string `json:"device_id"`
	UserID string `json:"user_id"`
	DeviceName string `json:"device_name"`
	Platform string `json:"platform"`
	VirtualIP string `json:"virtual_ip"`
	Online bool `json:"online"`
	LastSeen int64 `json:"last_seen"`
}

type RoomDetail struct {
	Room Room `json:"room"`
	Members []RoomMember `json:"members"`
	Devices []RoomDevice `json:"devices"`
}

type RoomAddress struct {
	RoomID string `json:"room_id"`
	CIDR string `json:"cidr"`
	VirtualIP string `json:"virtual_ip"`
}

type RoomPeerGrant struct {
	RoomID string `json:"room_id"`
	NodeID string `json:"node_id"`
	VirtualIP string `json:"virtual_ip"`
}

type RoomRoster struct {
	ProtocolVersion int `json:"protocol_version"`
	LeaseSeconds int `json:"lease_seconds"`
	LocalAddresses []RoomAddress `json:"local_addresses"`
	PrivatePeerIDs []string `json:"private_peer_ids"`
	Grants []RoomPeerGrant `json:"grants"`
	Nodes []Device `json:"nodes"`
}

type roomSecret struct {
	Room
	PasswordHash string
	InviteHash []byte
	InviteExpiresAt int64
}

func roomID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func roomNumber() (string, error) {
	value, err := rand.Int(rand.Reader, big.NewInt(90000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08d", value.Int64()+10000000), nil
}

func validRoomNumber(number string) bool {
	if len(number) != 8 || number[0] == '0' {
		return false
	}
	for _, c := range number {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func roomPasswordHash(password string) (string, error) {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 8 || len(password) > 72 {
		return "", ErrRoomInvalidInput
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func roomName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 64 {
		return "", ErrRoomInvalidInput
	}
	for _, c := range name {
		if c < 32 || c == 127 {
			return "", ErrRoomInvalidInput
		}
	}
	return name, nil
}

func (db *DB) beginRoomTx() (*sql.Tx, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`UPDATE room_allocator SET serial = serial + 1 WHERE id = 1`); err != nil {
		tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func roomInTx(tx *sql.Tx, id string) (roomSecret, error) {
	var room roomSecret
	err := tx.QueryRow(`SELECT id, number, name, cidr, owner_id, revision, created_at, password_hash, invite_hash, invite_expires_at
		FROM rooms WHERE id = ? AND deleted_at = 0`, id).Scan(&room.ID, &room.Number, &room.Name, &room.CIDR, &room.OwnerID, &room.Revision, &room.CreatedAt, &room.PasswordHash, &room.InviteHash, &room.InviteExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return room, ErrRoomNotFound
	}
	return room, err
}

func requireRoomMember(tx *sql.Tx, id, userID string, ownerOnly bool) (roomSecret, error) {
	room, err := roomInTx(tx, id)
	if err != nil {
		return room, err
	}
	if ownerOnly {
		if room.OwnerID != userID {
			return room, ErrRoomForbidden
		}
	} else {
		var banned int
		if err := tx.QueryRow(`SELECT banned FROM room_members WHERE room_id = ? AND user_id = ?`, id, userID).Scan(&banned); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return room, ErrRoomForbidden
			}
			return room, err
		}
		if banned != 0 {
			return room, ErrRoomForbidden
		}
	}
	room.Role = "member"
	if room.OwnerID == userID {
		room.Role = "owner"
	}
	return room, nil
}

func bumpRoomRevision(tx *sql.Tx, roomID string) error {
	_, err := tx.Exec(`UPDATE rooms SET revision = revision + 1 WHERE id = ? AND deleted_at = 0`, roomID)
	return err
}

func allocateRoomCIDR(tx *sql.Tx) (string, error) {
	rows, err := tx.Query(`SELECT cidr FROM networks UNION ALL SELECT cidr FROM rooms`)
	if err != nil {
		return "", err
	}
	var existing []netip.Prefix
	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			rows.Close()
			return "", err
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			rows.Close()
			return "", fmt.Errorf("invalid allocated network CIDR")
		}
		existing = append(existing, prefix.Masked())
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return "", err
	}
	for index := 1; index <= 256; index++ {
		candidate := netip.MustParsePrefix(fmt.Sprintf("10.21.%d.0/24", index%256))
		overlap := false
		for _, prefix := range existing {
			if candidate.Overlaps(prefix) {
				overlap = true
				break
			}
		}
		if !overlap {
			return candidate.String(), nil
		}
	}
	return "", ErrRoomSubnetExhausted
}

func consumeRoomJoinAttempt(db *DB, userID string) error {
	tx, err := db.beginRoomTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	_, err = tx.Exec(`INSERT INTO room_join_attempts(user_id, window_start, attempts) VALUES(?, ?, 1)
		ON CONFLICT(user_id) DO UPDATE SET
		attempts = CASE WHEN room_join_attempts.window_start <= ? - 60 THEN 1 ELSE room_join_attempts.attempts + 1 END,
		window_start = CASE WHEN room_join_attempts.window_start <= ? - 60 THEN ? ELSE room_join_attempts.window_start END`, userID, now, now, now, now)
	if err != nil {
		return err
	}
	var attempts int
	if err := tx.QueryRow(`SELECT attempts FROM room_join_attempts WHERE user_id = ?`, userID).Scan(&attempts); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if attempts > 10 {
		return ErrRoomJoinRateLimited
	}
	return nil
}
