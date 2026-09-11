package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestRelayScopesMatchAccountAndRoomAuthorization(t *testing.T) {
	db := roomTestDB(t)
	a, b := roomTestUser(t, db, "scope-a"), roomTestUser(t, db, "scope-b")
	personalA := roomTestDevice(t, db, a, "default", "scope-key-a")
	personalA2 := roomTestDevice(t, db, a, "default", "scope-key-a2")
	personalB := roomTestDevice(t, db, b, "default", "scope-key-b")
	scope := func(d *Device) string {
		t.Helper()
		s, err := db.RelayForwardingScope(d)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if scope(personalA) != scope(personalA2) || scope(personalA) == scope(personalB) || scope(personalA) == "default" {
		t.Fatal("personal forwarding must be scoped to account and network")
	}
	other, err := db.CreateNetwork(a, "other", "10.30.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if scope(personalA) == scope(&Device{UserID: a, NetworkID: other.ID}) {
		t.Fatal("distinct networks shared scope")
	}
	room := roomTestRoom(t, db, a)
	if _, err := db.JoinRoom(b, room.Code, "safe-password", ""); err != nil {
		t.Fatal(err)
	}
	da := roomTestDevice(t, db, a, room.ID, "room-scope-a")
	dbb := roomTestDevice(t, db, b, room.ID, "room-scope-b")
	if scope(da) != room.ID || scope(da) != scope(dbb) {
		t.Fatal("room members must share room scope")
	}
	if _, err := db.RemoveRoomMember(a, room.ID, b, true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.RelayForwardingScope(dbb); err == nil {
		t.Fatal("removed membership issued a scope")
	}
}

func TestRevocationPagesBoundBytesAndFreezeHighWater(t *testing.T) {
	db := roomTestDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1400; i++ {
		value := fmt.Sprintf("%04d-%s", i, strings.Repeat("x", 900))
		if _, err := tx.Exec(`INSERT INTO relay_revocations(kind,value,created_at) VALUES(?,?,?)`, RelayRevocationJTI, value, time.Now().Unix()); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	whole, err := db.RelayRevocationSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(whole)
	if len(encoded) <= 1<<20 {
		t.Fatal("fixture must exceed old one-megabyte limit")
	}
	first, err := db.RelayRevocationPage(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !first.HasMore {
		t.Fatal("large feed was not paginated")
	}
	if err := db.RecordRelayTicketRevocation("after-initial-high-water"); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	page := first
	for rounds := 0; ; rounds++ {
		if rounds > 20 {
			t.Fatal("pagination failed to terminate")
		}
		body, _ := json.Marshal(page)
		if len(body) > relayRevocationPageBytes {
			t.Fatalf("page exceeds byte cap: %d", len(body))
		}
		if page.Version != first.Version {
			t.Fatal("catch-up high-water moved")
		}
		for _, id := range page.RevokedJTIs {
			if seen[id] {
				t.Fatal("duplicate across pages")
			}
			seen[id] = true
		}
		if !page.HasMore {
			break
		}
		previous := page.NextCursor
		page, err = db.RelayRevocationPage(previous, first.Version)
		if err != nil {
			t.Fatal(err)
		}
		if page.NextCursor <= previous {
			t.Fatal("cursor made no progress")
		}
	}
	if len(seen) != 1400 || seen["after-initial-high-water"] {
		t.Fatal("fixed catch-up snapshot is inconsistent")
	}
	delta, err := db.RelayRevocationPage(page.NextCursor, 0)
	if err != nil || len(delta.RevokedJTIs) != 1 || delta.RevokedJTIs[0] != "after-initial-high-water" {
		t.Fatalf("missing subsequent delta: %+v %v", delta, err)
	}
	idle, err := db.RelayRevocationPage(delta.NextCursor, 0)
	if err != nil || idle.HasMore || idle.NextCursor != delta.NextCursor || len(idle.RevokedJTIs) != 0 {
		t.Fatalf("bad idle page: %+v %v", idle, err)
	}
}

func TestRevocationPruningAndMigrationNeverRewindCursor(t *testing.T) {
	db := roomTestDB(t)
	if _, err := db.Exec(`INSERT INTO relay_revocations(kind,value,created_at) VALUES(?,?,?)`, RelayRevocationJTI, "old", time.Now().Unix()-RelayRevocationRetentionSeconds-1); err != nil {
		t.Fatal(err)
	}
	var before int64
	if err := db.QueryRow(`SELECT revision FROM relay_revocation_clock WHERE id=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.RelayRevocationSnapshot()
	if err != nil || len(snapshot.RevokedJTIs) != 0 || snapshot.Version != before {
		t.Fatalf("prune rewound clock: %+v %v", snapshot, err)
	}
	if err := migrateRelayRevocations(db.DB); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordRelayTicketRevocation("new"); err != nil {
		t.Fatal(err)
	}
	page, err := db.RelayRevocationPage(before, 0)
	if err != nil || page.Version <= before || len(page.RevokedJTIs) != 1 {
		t.Fatalf("migration/prune lost new revocation: %+v %v", page, err)
	}
	if _, err := db.RelayRevocationPage(page.Version+1, 0); !errors.Is(err, ErrRevocationCursor) {
		t.Fatal("accepted future cursor")
	}
	if _, err := db.RelayRevocationPage(-1, 0); !errors.Is(err, ErrRevocationCursor) {
		t.Fatal("accepted negative cursor")
	}
}

func TestUnchangedRoomIPKeepsCredentialAndRevision(t *testing.T) {
	db := roomTestDB(t)
	owner := roomTestUser(t, db, "ip-owner")
	room := roomTestRoom(t, db, owner)
	device := roomTestDevice(t, db, owner, room.ID, "ip-key")
	_, credential, err := db.CreateDeviceCredential(device.ID, 3600)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := db.AssignRoomDeviceIPIfChanged(owner, room.ID, device.ID, device.VirtualIP)
	if err != nil || changed {
		t.Fatalf("same IP mutated state: %v %v", changed, err)
	}
	if _, _, err := db.ValidateDeviceCredential(credential); err != nil {
		t.Fatal("unchanged IP revoked credential", err)
	}
	details, err := db.GetRoom(owner, room.ID)
	if err != nil || details.Room.Revision != room.Revision {
		t.Fatal("unchanged IP bumped revision")
	}
	changed, err = db.AssignRoomDeviceIPIfChanged(owner, room.ID, device.ID, "10.21.1.40")
	if err != nil || !changed {
		t.Fatalf("real IP change not applied: %v %v", changed, err)
	}
	if _, _, err := db.ValidateDeviceCredential(credential); err == nil {
		t.Fatal("real IP change failed to revoke old credential")
	}
}
