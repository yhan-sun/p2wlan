package database

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func (db *DB) CreateRoom(userID, name, password string) (Room, error) {
	var empty Room
	name, err := roomName(name)
	if err != nil {
		return empty, err
	}
	hash, err := roomPasswordHash(password)
	if err != nil {
		return empty, err
	}
	id, err := roomID("room-")
	if err != nil {
		return empty, err
	}
	tx, err := db.beginRoomTx()
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	var owned int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM rooms WHERE owner_id = ? AND deleted_at = 0`, userID).Scan(&owned); err != nil {
		return empty, err
	}
	if owned > 0 {
		return empty, ErrRoomAlreadyOwned
	}
	if err := checkRoomMembershipLimit(tx, userID); err != nil {
		return empty, err
	}
	cidr, err := allocateRoomCIDR(tx)
	if err != nil {
		return empty, err
	}
	var number string
	for range 16 {
		number, err = roomNumber()
		if err != nil {
			return empty, err
		}
		var used int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM rooms WHERE number = ?`, number).Scan(&used); err != nil {
			return empty, err
		}
		if used == 0 {
			break
		}
		number = ""
	}
	if number == "" {
		return empty, ErrRoomLimit
	}
	now := time.Now().Unix()
	_, err = tx.Exec(`INSERT INTO rooms(id, number, name, cidr, owner_id, password_hash, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)`, id, number, name, cidr, userID, hash, now)
	if err != nil {
		return empty, err
	}
	if _, err := tx.Exec(`INSERT INTO room_members(room_id, user_id, joined_at) VALUES(?, ?, ?)`, id, userID, now); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return Room{ID: id, Number: number, Name: name, CIDR: cidr, OwnerID: userID, Revision: 1, CreatedAt: now, Role: "owner"}, nil
}

func checkRoomMembershipLimit(tx *sql.Tx, userID string) error {
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM room_members m JOIN rooms r ON r.id = m.room_id WHERE m.user_id = ? AND m.banned = 0 AND r.deleted_at = 0`, userID).Scan(&count); err != nil {
		return err
	}
	if count >= MaxJoinedRooms {
		return ErrRoomLimit
	}
	return nil
}

func (db *DB) JoinRoom(userID, number, password, invitation string) (Room, error) {
	var empty Room
	if err := consumeRoomJoinAttempt(db, userID); err != nil {
		return empty, err
	}
	if !validRoomNumber(number) || (password == "") == (invitation == "") || len(password) > 72 || len(invitation) > 128 {
		return empty, ErrRoomCredentials
	}
	var verified roomSecret
	err := db.QueryRow(`SELECT id, password_hash, invite_hash, invite_expires_at FROM rooms WHERE number = ? AND deleted_at = 0`, number).Scan(&verified.ID, &verified.PasswordHash, &verified.InviteHash, &verified.InviteExpiresAt)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return empty, err
	}
	if password != "" {
		hash := verified.PasswordHash
		if hash == "" {
			hash = "$2a$10$7EqJtq98hPqEX7fNZaFWoO5jI6F.f5EyjEOlF3c4pIckwtOyyeTG."
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil || verified.ID == "" {
			return empty, ErrRoomCredentials
		}
	} else {
		digest := sha256.Sum256([]byte(invitation))
		if len(invitation) != 43 || verified.InviteExpiresAt <= time.Now().Unix() || subtle.ConstantTimeCompare(digest[:], verified.InviteHash) != 1 {
			return empty, ErrRoomCredentials
		}
	}
	tx, err := db.beginRoomTx()
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	room, err := roomInTx(tx, verified.ID)
	if errors.Is(err, ErrRoomNotFound) {
		return empty, ErrRoomCredentials
	}
	if err != nil {
		return empty, err
	}
	if password != "" {
		if room.PasswordHash != verified.PasswordHash {
			return empty, ErrRoomCredentials
		}
	} else if subtle.ConstantTimeCompare(room.InviteHash, verified.InviteHash) != 1 || room.InviteExpiresAt <= time.Now().Unix() {
		return empty, ErrRoomCredentials
	}
	var banned int
	err = tx.QueryRow(`SELECT banned FROM room_members WHERE room_id = ? AND user_id = ?`, room.ID, userID).Scan(&banned)
	if err == nil {
		if banned != 0 {
			return empty, ErrRoomForbidden
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if err := checkRoomMembershipLimit(tx, userID); err != nil {
			return empty, err
		}
		var members int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM room_members WHERE room_id = ? AND banned = 0`, room.ID).Scan(&members); err != nil {
			return empty, err
		}
		if members >= MaxRoomMembers {
			return empty, ErrRoomLimit
		}
		if _, err := tx.Exec(`INSERT INTO room_members(room_id, user_id, joined_at) VALUES(?, ?, ?)`, room.ID, userID, time.Now().Unix()); err != nil {
			return empty, err
		}
		if err := bumpRoomRevision(tx, room.ID); err != nil {
			return empty, err
		}
		room.Revision++
	} else {
		return empty, err
	}
	room.Role = "member"
	if room.OwnerID == userID {
		room.Role = "owner"
	}
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return room.Room, nil
}

func (db *DB) ListRooms(userID string) ([]Room, error) {
	rows, err := db.Query(`SELECT r.id, r.number, r.name, r.cidr, r.owner_id, r.revision, r.created_at
		FROM rooms r JOIN room_members m ON m.room_id = r.id WHERE m.user_id = ? AND m.banned = 0 AND r.deleted_at = 0 ORDER BY r.created_at, r.id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	rooms := []Room{}
	for rows.Next() {
		var room Room
		if err := rows.Scan(&room.ID, &room.Number, &room.Name, &room.CIDR, &room.OwnerID, &room.Revision, &room.CreatedAt); err != nil {
			return nil, err
		}
		room.Role = "member"
		if room.OwnerID == userID {
			room.Role = "owner"
		}
		rooms = append(rooms, room)
	}
	return rooms, rows.Err()
}

func (db *DB) GetRoom(userID, id string) (RoomDetail, error) {
	result := RoomDetail{Members: []RoomMember{}, Devices: []RoomDevice{}}
	tx, err := db.Begin()
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	room, err := requireRoomMember(tx, id, userID, false)
	if err != nil {
		return result, err
	}
	result.Room = room.Room
	rows, err := tx.Query(`SELECT user_id, joined_at, banned FROM room_members WHERE room_id = ? AND (banned = 0 OR ? = ?) ORDER BY joined_at, user_id`, id, userID, room.OwnerID)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var member RoomMember
		if err := rows.Scan(&member.UserID, &member.JoinedAt, &member.Banned); err != nil {
			rows.Close()
			return result, err
		}
		member.Role = "member"
		if member.UserID == room.OwnerID {
			member.Role = "owner"
		}
		result.Members = append(result.Members, member)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	rows, err = tx.Query(`SELECT d.id, d.user_id, d.device_name, d.platform, rd.virtual_ip, d.online, d.last_seen
		FROM room_devices rd JOIN devices d ON d.id = rd.device_id WHERE rd.room_id = ? ORDER BY rd.virtual_ip, d.id`, id)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var device RoomDevice
		if err := rows.Scan(&device.DeviceID, &device.UserID, &device.DeviceName, &device.Platform, &device.VirtualIP, &device.Online, &device.LastSeen); err != nil {
			rows.Close()
			return result, err
		}
		device.Online = device.Online && device.LastSeen > 0 && time.Now().Unix()-device.LastSeen <= DeviceOnlineTTL
		result.Devices = append(result.Devices, device)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return result, err
	}
	return result, tx.Commit()
}

func (db *DB) UpdateRoom(userID, id string, name, password *string) (Room, error) {
	var empty Room
	if name == nil && password == nil {
		return empty, ErrRoomInvalidInput
	}
	var normalized, hash string
	var err error
	if name != nil {
		normalized, err = roomName(*name)
		if err != nil {
			return empty, err
		}
	}
	if password != nil {
		hash, err = roomPasswordHash(*password)
		if err != nil {
			return empty, err
		}
	}
	tx, err := db.beginRoomTx()
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	room, err := requireRoomMember(tx, id, userID, true)
	if err != nil {
		return empty, err
	}
	if name != nil {
		if _, err := tx.Exec(`UPDATE rooms SET name = ? WHERE id = ?`, normalized, id); err != nil {
			return empty, err
		}
		room.Name = normalized
	}
	if password != nil {
		if _, err := tx.Exec(`UPDATE rooms SET password_hash = ? WHERE id = ?`, hash, id); err != nil {
			return empty, err
		}
	}
	if err := bumpRoomRevision(tx, id); err != nil {
		return empty, err
	}
	room.Revision++
	if err := tx.Commit(); err != nil {
		return empty, err
	}
	return room.Room, nil
}

func (db *DB) RotateRoomInvitation(userID, id string, ttlSeconds int64) (string, int64, error) {
	if ttlSeconds < 300 || ttlSeconds > 7*24*3600 {
		return "", 0, ErrRoomInvalidInput
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", 0, err
	}
	invitation := base64.RawURLEncoding.EncodeToString(raw[:])
	digest := sha256.Sum256([]byte(invitation))
	expires := time.Now().Unix() + ttlSeconds
	tx, err := db.beginRoomTx()
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	if _, err := requireRoomMember(tx, id, userID, true); err != nil {
		return "", 0, err
	}
	if _, err := tx.Exec(`UPDATE rooms SET invite_hash = ?, invite_expires_at = ?, revision = revision + 1 WHERE id = ?`, digest[:], expires, id); err != nil {
		return "", 0, err
	}
	if err := tx.Commit(); err != nil {
		return "", 0, err
	}
	return invitation, expires, nil
}

func (db *DB) RevokeRoomInvitation(userID, id string) error {
	tx, err := db.beginRoomTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := requireRoomMember(tx, id, userID, true); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE rooms SET invite_hash = NULL, invite_expires_at = 0, revision = revision + 1 WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (db *DB) DeleteRoom(userID, id string) error {
	tx, err := db.beginRoomTx()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := requireRoomMember(tx, id, userID, true); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM room_members WHERE room_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE rooms SET deleted_at = ?, password_hash = '', invite_hash = NULL, invite_expires_at = 0, revision = revision + 1 WHERE id = ?`, time.Now().Unix(), id); err != nil {
		return err
	}
	if err := purgeUnauthorizedRoomSignals(tx); err != nil {
		return err
	}
	return tx.Commit()
}
