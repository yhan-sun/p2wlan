package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const roomTestPassword = "friend-room-password"

func roomTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(filepath.Join(t.TempDir(), "rooms.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func roomTestUser(t *testing.T, db *DB, name string) *User {
	t.Helper()
	user, err := db.CreateUser(name+"@rooms.example", "account-password-hash")
	if err != nil {
		t.Fatal(err)
	}
	return user
}

func roomTestDevice(t *testing.T, db *DB, user *User, name string) *Device {
	t.Helper()
	device, err := db.CreateDevice(user.ID, "default", "room-key-"+name, name, "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func roomTestCreate(t *testing.T, db *DB, user *User) Room {
	t.Helper()
	room, err := db.CreateRoom(user.ID, "朋友的房间", roomTestPassword)
	if err != nil {
		t.Fatal(err)
	}
	return room
}

func roomTestJoin(t *testing.T, db *DB, user *User, room Room) {
	t.Helper()
	if _, err := db.JoinRoom(user.ID, room.Number, roomTestPassword, ""); err != nil {
		t.Fatal(err)
	}
}

func roomTestEnable(t *testing.T, db *DB, user *User, room Room, device *Device) string {
	t.Helper()
	ip, err := db.EnableRoomDevice(user.ID, room.ID, device.ID)
	if err != nil {
		t.Fatal(err)
	}
	return ip
}

func roomTestRoster(t *testing.T, db *DB, device *Device) RoomRoster {
	t.Helper()
	roster, err := db.GetRoomRoster(device.ID)
	if err != nil {
		t.Fatal(err)
	}
	return roster
}

func TestRoomLifecycleOwnershipAndPrivacy(t *testing.T) {
	db := roomTestDB(t)
	a, b, c := roomTestUser(t, db, "a"), roomTestUser(t, db, "b"), roomTestUser(t, db, "c")
	room := roomTestCreate(t, db, a)
	if room.CIDR != "10.21.1.0/24" || len(room.Number) != 8 || room.Role != "owner" {
		t.Fatalf("unexpected room: %+v", room)
	}
	if _, err := db.CreateRoom(a.ID, "duplicate", roomTestPassword); !errors.Is(err, ErrRoomAlreadyOwned) {
		t.Fatalf("second owned room: %v", err)
	}
	if _, err := db.JoinRoom(b.ID, room.Number, "wrong-password", ""); !errors.Is(err, ErrRoomCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	roomTestJoin(t, db, b, room)
	roomTestJoin(t, db, b, room)
	detail, err := db.GetRoom(b.ID, room.ID)
	if err != nil || len(detail.Members) != 2 || detail.Room.Role != "member" {
		t.Fatalf("member detail: %+v %v", detail, err)
	}
	if _, err := db.GetRoom(c.ID, room.ID); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("unrelated user saw room: %v", err)
	}
	name := "unauthorized change"
	if _, err := db.UpdateRoom(b.ID, room.ID, &name, nil); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("member changed room: %v", err)
	}
	if err := db.DeleteRoom(b.ID, room.ID); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("member dissolved room: %v", err)
	}
	if err := db.LeaveRoom(a.ID, room.ID); !errors.Is(err, ErrRoomOwnerCannotLeave) {
		t.Fatalf("owner left: %v", err)
	}
	other := roomTestCreate(t, db, b)
	roomTestJoin(t, db, a, other)
	rooms, err := db.ListRooms(a.ID)
	if err != nil || len(rooms) != 2 {
		t.Fatalf("multiple memberships: %+v %v", rooms, err)
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{roomTestPassword, "password_hash", "invite_hash", a.Email, b.Email} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("room detail exposed %q", forbidden)
		}
	}
}

func TestRoomInvitationRotationExpiryAndBan(t *testing.T) {
	db := roomTestDB(t)
	a, b, c := roomTestUser(t, db, "a"), roomTestUser(t, db, "b"), roomTestUser(t, db, "c")
	room := roomTestCreate(t, db, a)
	old, _, err := db.RotateRoomInvitation(a.ID, room.ID, 3600)
	if err != nil || len(old) != 43 {
		t.Fatalf("invitation: %v", err)
	}
	current, _, err := db.RotateRoomInvitation(a.ID, room.ID, 3600)
	if err != nil || current == old {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := db.JoinRoom(b.ID, room.Number, "", old); !errors.Is(err, ErrRoomCredentials) {
		t.Fatalf("old link admitted: %v", err)
	}
	if _, err := db.JoinRoom(b.ID, room.Number, "", current); err != nil {
		t.Fatal(err)
	}
	if err := db.KickRoomMember(b.ID, room.ID, a.ID); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("nonowner kick: %v", err)
	}
	if err := db.KickRoomMember(a.ID, room.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.JoinRoom(b.ID, room.Number, "", current); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("banned member rejoined by link: %v", err)
	}
	if _, err := db.JoinRoom(b.ID, room.Number, roomTestPassword, ""); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("banned member rejoined by password: %v", err)
	}
	if err := db.UnbanRoomMember(a.ID, room.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetRoom(b.ID, room.ID); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("unban silently restored membership: %v", err)
	}
	roomTestJoin(t, db, b, room)
	if _, err := db.Exec(`UPDATE rooms SET invite_expires_at = ? WHERE id = ?`, time.Now().Unix()-1, room.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.JoinRoom(c.ID, room.Number, "", current); !errors.Is(err, ErrRoomCredentials) {
		t.Fatalf("expired invitation: %v", err)
	}
	fresh, _, err := db.RotateRoomInvitation(a.ID, room.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RevokeRoomInvitation(a.ID, room.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.JoinRoom(c.ID, room.Number, "", fresh); !errors.Is(err, ErrRoomCredentials) {
		t.Fatalf("revoked invitation: %v", err)
	}
	password := "a-new-room-password"
	if _, err := db.UpdateRoom(a.ID, room.ID, nil, &password); err != nil {
		t.Fatal(err)
	}
	if _, err := db.JoinRoom(c.ID, room.Number, roomTestPassword, ""); !errors.Is(err, ErrRoomCredentials) {
		t.Fatalf("old password accepted: %v", err)
	}
	if _, err := db.JoinRoom(c.ID, room.Number, password, ""); err != nil {
		t.Fatal(err)
	}
}

func TestRoomDeviceOptInIsolationAndRevocation(t *testing.T) {
	db := roomTestDB(t)
	a, b, c := roomTestUser(t, db, "a"), roomTestUser(t, db, "b"), roomTestUser(t, db, "c")
	ad, bd, cd := roomTestDevice(t, db, a, "a"), roomTestDevice(t, db, b, "b"), roomTestDevice(t, db, c, "c")
	extra := roomTestDevice(t, db, a, "a-private")
	ar, cr := roomTestCreate(t, db, a), roomTestCreate(t, db, c)
	roomTestJoin(t, db, b, ar)
	roomTestJoin(t, db, b, cr)
	if len(roomTestRoster(t, db, ad).LocalAddresses) != 0 {
		t.Fatal("room membership silently shared device")
	}
	if _, err := db.EnableRoomDevice(a.ID, ar.ID, bd.ID); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("owner enrolled foreign device without consent: %v", err)
	}
	roomTestEnable(t, db, a, ar, ad)
	bIP := roomTestEnable(t, db, b, ar, bd)
	roomTestEnable(t, db, b, cr, bd)
	roomTestEnable(t, db, c, cr, cd)
	roomTestRoster(t, db, bd)
	roomTestRoster(t, db, cd)
	rosterA := roomTestRoster(t, db, ad)
	if len(rosterA.LocalAddresses) != 1 || len(rosterA.Grants) != 1 || len(rosterA.PrivatePeerIDs) != 1 || rosterA.PrivatePeerIDs[0] != extra.ID {
		t.Fatalf("unexpected scoped roster: %+v", rosterA)
	}
	seenB := false
	for _, peer := range rosterA.Nodes {
		if peer.ID == bd.ID {
			seenB = true
			if peer.VirtualIP != bIP || peer.VirtualIP == bd.VirtualIP {
				t.Fatal("room peer exposed private-network IP")
			}
		}
		if peer.ID == cd.ID {
			t.Fatal("room-to-room visibility leaked")
		}
	}
	if !seenB {
		t.Fatal("authorized opted-in peer absent")
	}
	for _, pair := range []struct{ from, to string; allowed bool }{{ad.ID, bd.ID, true}, {bd.ID, cd.ID, true}, {ad.ID, cd.ID, false}} {
		allowed, err := db.DevicesShareRoom(pair.from, pair.to)
		if err != nil || allowed != pair.allowed {
			t.Fatalf("room pair authorization: %+v got %v %v", pair, allowed, err)
		}
	}
	if err := db.KickRoomMember(a.ID, ar.ID, b.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := db.DevicesShareRoom(ad.ID, bd.ID); err != nil || allowed {
		t.Fatalf("kick did not revoke access: %v %v", allowed, err)
	}
	if allowed, err := db.DevicesShareRoom(bd.ID, cd.ID); err != nil || !allowed {
		t.Fatalf("kick affected unrelated room: %v %v", allowed, err)
	}
	if len(roomTestRoster(t, db, ad).Grants) != 0 || len(roomTestRoster(t, db, bd).LocalAddresses) != 1 {
		t.Fatal("room revocation snapshot mismatch")
	}
	if device, err := db.GetDevice(bd.ID); err != nil || device.VirtualIP != bd.VirtualIP {
		t.Fatalf("kick modified canonical device: %+v %v", device, err)
	}
	if _, err := db.Exec(`UPDATE room_client_leases SET refreshed_at = 0 WHERE device_id = ?`, cd.ID); err != nil {
		t.Fatal(err)
	}
	if allowed, err := db.DevicesShareRoom(bd.ID, cd.ID); err != nil || allowed {
		t.Fatalf("stale room client lease accepted: %v %v", allowed, err)
	}
}

func TestRoomIPAssignmentRejectsInvalidAndQuarantines(t *testing.T) {
	db := roomTestDB(t)
	a, b := roomTestUser(t, db, "a"), roomTestUser(t, db, "b")
	ad, bd := roomTestDevice(t, db, a, "a"), roomTestDevice(t, db, b, "b")
	room := roomTestCreate(t, db, a)
	roomTestJoin(t, db, b, room)
	aIP := roomTestEnable(t, db, a, room, ad)
	oldB := roomTestEnable(t, db, b, room, bd)
	if aIP != "10.21.1.1" || oldB != "10.21.1.2" {
		t.Fatalf("initial assignment: %s %s", aIP, oldB)
	}
	if _, err := db.AssignRoomDeviceIP(b.ID, room.ID, bd.ID, "10.21.1.42"); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("member self-assigned: %v", err)
	}
	for _, ip := range []string{aIP, "10.21.1.0", "10.21.1.255", "10.21.2.42", "20.21.1.42"} {
		if _, err := db.AssignRoomDeviceIP(a.ID, room.ID, bd.ID, ip); !errors.Is(err, ErrRoomIPUnavailable) {
			t.Fatalf("unsafe or duplicate IP %s: %v", ip, err)
		}
	}
	for _, ip := range []string{"", "::1", "not-an-ip"} {
		if _, err := db.AssignRoomDeviceIP(a.ID, room.ID, bd.ID, ip); !errors.Is(err, ErrRoomInvalidInput) {
			t.Fatalf("invalid IP %s: %v", ip, err)
		}
	}
	if _, err := db.AssignRoomDeviceIP(a.ID, room.ID, bd.ID, "10.21.1.42"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.AssignRoomDeviceIP(a.ID, room.ID, ad.ID, oldB); !errors.Is(err, ErrRoomIPUnavailable) {
		t.Fatalf("IP change bypassed reuse quarantine: %v", err)
	}
	if err := db.DisableRoomDevice(b.ID, room.ID, ad.ID); !errors.Is(err, ErrRoomForbidden) {
		t.Fatalf("member disabled foreign device: %v", err)
	}
	if err := db.DisableRoomDevice(b.ID, room.ID, bd.ID); err != nil {
		t.Fatal(err)
	}
	nextIP := roomTestEnable(t, db, b, room, bd)
	if nextIP == oldB || nextIP == "10.21.1.42" {
		t.Fatal("device removal bypassed IP quarantine")
	}
	if _, err := db.Exec(`DELETE FROM devices WHERE id = ?`, bd.ID); err != nil {
		t.Fatal(err)
	}
	var held int
	if err := db.QueryRow(`SELECT COUNT(*) FROM room_ip_holds WHERE room_id = ? AND virtual_ip = ? AND reusable_after > ?`, room.ID, nextIP, time.Now().Unix()).Scan(&held); err != nil || held != 1 {
		t.Fatalf("global device deletion did not quarantine room IP: %d %v", held, err)
	}
}

func TestRoomSubnetAllocationConcurrentAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rooms.db")
	first, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	users := make([]*User, 8)
	for i := range users {
		users[i] = roomTestUser(t, first, fmt.Sprintf("concurrent-%d", i))
	}
	if _, err := first.CreateNetwork(users[0].ID, "existing overlapping network", "10.21.1.128/25"); err != nil {
		t.Fatal(err)
	}
	type outcome struct { room Room; err error }
	results := make(chan outcome, len(users))
	var wg sync.WaitGroup
	for i, user := range users {
		wg.Add(1)
		go func(i int, user *User) {
			defer wg.Done()
			db := first
			if i%2 != 0 {
				db = second
			}
			room, err := db.CreateRoom(user.ID, "concurrent room", roomTestPassword)
			results <- outcome{room, err}
		}(i, user)
	}
	wg.Wait()
	close(results)
	cidrs, numbers := map[string]bool{}, map[string]bool{}
	var last Room
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		prefix, err := netip.ParsePrefix(result.room.CIDR)
		if err != nil || !prefix.Addr().IsPrivate() || prefix.Bits() != 24 || result.room.CIDR == "10.21.1.0/24" || cidrs[result.room.CIDR] || numbers[result.room.Number] {
			t.Fatalf("conflicting allocation: %+v", result.room)
		}
		cidrs[result.room.CIDR], numbers[result.room.Number] = true, true
		last = result.room
	}
	if err := first.DeleteRoom(last.OwnerID, last.ID); err != nil {
		t.Fatal(err)
	}
	replacement, err := second.CreateRoom(last.OwnerID, "replacement", roomTestPassword)
	if err != nil || replacement.CIDR == last.CIDR || replacement.Number == last.Number {
		t.Fatalf("deleted room allocation reused: %+v %v", replacement, err)
	}
	third, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer third.Close()
	detail, err := third.GetRoom(replacement.OwnerID, replacement.ID)
	if err != nil || detail.Room.CIDR != replacement.CIDR {
		t.Fatalf("restart lost room assignment: %+v %v", detail, err)
	}
}

func TestRoomConcurrentSingleOwnerConstraint(t *testing.T) {
	db := roomTestDB(t)
	owner := roomTestUser(t, db, "owner")
	results := make(chan error, 6)
	for range 6 {
		go func() {
			_, err := db.CreateRoom(owner.ID, "one room", roomTestPassword)
			results <- err
		}()
	}
	success := 0
	for range 6 {
		err := <-results
		if err == nil {
			success++
		} else if !errors.Is(err, ErrRoomAlreadyOwned) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("created %d rooms for one account", success)
	}
}

func TestRoomJoinRateLimitPersistsAcrossConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rooms.db")
	db, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user := roomTestUser(t, db, "attempts")
	for range 10 {
		if _, err := db.JoinRoom(user.ID, "invalid", roomTestPassword, ""); !errors.Is(err, ErrRoomCredentials) {
			t.Fatal(err)
		}
	}
	other, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.JoinRoom(user.ID, "invalid", roomTestPassword, ""); !errors.Is(err, ErrRoomJoinRateLimited) {
		t.Fatalf("reconnect bypassed attempts: %v", err)
	}
	if _, err := db.Exec(`UPDATE room_join_attempts SET window_start = ? WHERE user_id = ?`, time.Now().Unix()-61, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := other.JoinRoom(user.ID, "invalid", roomTestPassword, ""); !errors.Is(err, ErrRoomCredentials) {
		t.Fatalf("expired window did not reset: %v", err)
	}
}

func TestRoomSubnetExhaustionAndValidation(t *testing.T) {
	db := roomTestDB(t)
	owner := roomTestUser(t, db, "owner")
	for _, password := range []string{"", "1234567", strings.Repeat("密", 25)} {
		if _, err := db.CreateRoom(owner.ID, "test", password); !errors.Is(err, ErrRoomInvalidInput) {
			t.Fatalf("invalid password accepted: %v", err)
		}
	}
	for _, name := range []string{" ", "bad\nname", strings.Repeat("房", 65)} {
		if _, err := db.CreateRoom(owner.ID, name, roomTestPassword); !errors.Is(err, ErrRoomInvalidInput) {
			t.Fatalf("invalid room name accepted: %v", err)
		}
	}
	if _, err := db.CreateNetwork(owner.ID, "occupied pool", "10.21.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateRoom(owner.ID, "no capacity", roomTestPassword); !errors.Is(err, ErrRoomSubnetExhausted) {
		t.Fatalf("pool exhaustion: %v", err)
	}
	rooms, err := db.ListRooms(owner.ID)
	if err != nil || len(rooms) != 0 {
		t.Fatalf("failed allocation left a room: %+v %v", rooms, err)
	}
}
