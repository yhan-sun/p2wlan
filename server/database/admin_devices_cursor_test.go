package database

import (
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func adminDeviceCursorTestDB(t *testing.T, count int) *DB {
	t.Helper()
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id,email,password_hash,created_at,username) VALUES ('cursor-owner','cursor@example.test','secret-hash',1,'cursor-owner')`); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= count; i++ {
		insertAdminCursorDevice(t, db, fmt.Sprintf("d%02d", i))
	}
	return db
}

func insertAdminCursorDevice(t *testing.T, db *DB, id string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO devices (id,user_id,network_id,public_key,device_name,platform,virtual_ip,nat_type,last_seen,app_version,online,created_at) VALUES (?,'cursor-owner','default',?,?,'linux',?,'unknown',?,'test',1,1)`, id, "secret-key-"+id, id, "ip-"+id, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
}

func requireAdminCursorIDs(t *testing.T, page *AdminDeviceCursorPage, ids ...string) {
	t.Helper()
	actual := make([]string, 0, len(page.Items))
	for _, item := range page.Items {
		actual = append(actual, item.ID)
		if item.OwnerID != "cursor-owner" {
			t.Fatalf("wrong account deep-link ID: %+v", item)
		}
	}
	if !reflect.DeepEqual(actual, ids) {
		t.Fatalf("device IDs = %v, want %v", actual, ids)
	}
}

func TestAdminDevicesCursorIsStableAcrossHeartbeats(t *testing.T) {
	db := adminDeviceCursorTestDB(t, 26)
	first, err := db.AdminDevicesCursor("", "all", "", 25)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 26 || first.Limit != 25 || len(first.Items) != 25 || first.NextCursor == "" || first.GeneratedAt <= 0 {
		t.Fatalf("unexpected first page: %+v", first)
	}
	// Previously this heartbeat moved d26 ahead of the offset boundary, so the
	// second page repeated d25 and never returned d26.
	if _, err := db.Exec(`UPDATE devices SET last_seen=? WHERE id='d26'`, time.Now().Unix()+1); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE devices SET last_seen=1,online=0 WHERE id='d01'`); err != nil {
		t.Fatal(err)
	}
	second, err := db.AdminDevicesCursor("", "all", first.NextCursor, 25)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, second, "d26")
	if second.NextCursor != "" || second.Total != 26 {
		t.Fatalf("unexpected final page: %+v", second)
	}
	seen := map[string]bool{}
	for _, item := range append(first.Items, second.Items...) {
		if seen[item.ID] {
			t.Fatalf("device repeated across heartbeat change: %s", item.ID)
		}
		seen[item.ID] = true
	}
	if len(seen) != 26 {
		t.Fatalf("devices omitted: %v", seen)
	}
}

func TestAdminDevicesCursorHandlesDeletionAndInsertion(t *testing.T) {
	db := adminDeviceCursorTestDB(t, 4)
	first, err := db.AdminDevicesCursor("", "", "", 2)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, first, "d01", "d02")
	// The cursor remains usable when its anchor and a following row disappear.
	if _, err := db.Exec(`DELETE FROM devices WHERE id IN ('d02','d03')`); err != nil {
		t.Fatal(err)
	}
	insertAdminCursorDevice(t, db, "d00")
	insertAdminCursorDevice(t, db, "d05")
	second, err := db.AdminDevicesCursor("", "all", first.NextCursor, 10)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, second, "d04", "d05")
	if second.Total != 4 || second.NextCursor != "" {
		t.Fatalf("live count must reflect deletion/insertion: %+v", second)
	}
	restarted, err := db.AdminDevicesCursor("", "all", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, restarted, "d00", "d01", "d04", "d05")
}

func TestAdminDevicesCursorStatusUsesCurrentLease(t *testing.T) {
	db := adminDeviceCursorTestDB(t, 4)
	if _, err := db.Exec(`UPDATE devices SET last_seen=1 WHERE id IN ('d01','d04')`); err != nil {
		t.Fatal(err)
	}
	first, err := db.AdminDevicesCursor("", "online", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, first, "d02")
	if first.Total != 2 {
		t.Fatalf("expired raw online flag counted as online: %+v", first)
	}
	if _, err := db.Exec(`UPDATE devices SET last_seen=? WHERE id IN ('d01','d04')`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE devices SET online=0 WHERE id='d03'`); err != nil {
		t.Fatal(err)
	}
	second, err := db.AdminDevicesCursor("", "online", first.NextCursor, 10)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, second, "d04")
	if second.Total != 3 || !second.Items[0].Online {
		t.Fatalf("status/count must use current lease: %+v", second)
	}
	restarted, err := db.AdminDevicesCursor("", "online", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, restarted, "d01", "d02", "d04")
	offline, err := db.AdminDevicesCursor("", "offline", "", 10)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, offline, "d03")
}

func TestAdminDevicesCursorSearchAndFilterBinding(t *testing.T) {
	db := adminDeviceCursorTestDB(t, 3)
	if _, err := db.Exec(`UPDATE devices SET device_name='percent%_!' WHERE id IN ('d01','d03')`); err != nil {
		t.Fatal(err)
	}
	first, err := db.AdminDevicesCursor(" %_! ", " ONLINE ", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, first, "d01")
	if first.Total != 2 || first.NextCursor == "" {
		t.Fatalf("LIKE metacharacters must be literal: %+v", first)
	}
	second, err := db.AdminDevicesCursor("%_!", "online", first.NextCursor, 5)
	if err != nil {
		t.Fatal(err)
	}
	requireAdminCursorIDs(t, second, "d03")
	for _, filter := range [][2]string{{"different", "online"}, {"%_!", "offline"}, {"%_!", "all"}} {
		if _, err := db.AdminDevicesCursor(filter[0], filter[1], first.NextCursor, 5); !errors.Is(err, ErrInvalidAdminDeviceCursor) {
			t.Fatalf("cursor accepted different filter %v: %v", filter, err)
		}
	}
	for _, query := range []string{"cursor-owner", "ip-d02", "d02", "' OR 1=1 --"} {
		page, err := db.AdminDevicesCursor(query, "all", "", 10)
		if err != nil {
			t.Fatal(err)
		}
		want := 1
		if query == "cursor-owner" {
			want = 3
		} else if query == "' OR 1=1 --" {
			want = 0
		}
		if page.Total != want {
			t.Fatalf("query %q returned %d devices, want %d", query, page.Total, want)
		}
	}
}

func TestAdminDevicesCursorRejectsMalformedCursors(t *testing.T) {
	db := adminDeviceCursorTestDB(t, 1)
	filter := adminDeviceFilterIdentity("", "all")
	validJSON := fmt.Sprintf(`{"v":1,"after":"d01","filter":%q}`, filter)
	bad := []string{"not-a-cursor", " ", strings.Repeat("x", MaxAdminDeviceCursorLength+1)}
	for _, raw := range []string{
		`null`, `[]`, `{}`, validJSON + `{}`, strings.Replace(validJSON, `"v":1`, `"v":2`, 1),
		strings.Replace(validJSON, `"d01"`, `""`, 1), strings.Replace(validJSON, `"d01"`, `"`+strings.Repeat("d", 129)+`"`, 1),
		strings.Replace(validJSON, `"v":1`, `"unexpected":1,"v":1`, 1),
	} {
		bad = append(bad, base64.RawURLEncoding.EncodeToString([]byte(raw)))
	}
	for _, cursor := range bad {
		if _, err := db.AdminDevicesCursor("", "all", cursor, 25); !errors.Is(err, ErrInvalidAdminDeviceCursor) {
			t.Fatalf("accepted malformed cursor %q: %v", cursor, err)
		}
	}
	if _, err := db.AdminDevicesCursor("", "maybe", "", 25); !errors.Is(err, ErrInvalidAdminDeviceStatus) {
		t.Fatalf("invalid status: %v", err)
	}
	page, err := db.AdminDevicesCursor("", "all", "", 500)
	if err != nil || page.Limit != adminMaxPageSize {
		t.Fatalf("unbounded page: %+v, %v", page, err)
	}
}

func TestAdminResourceOwnerIDsSupportDeepLinks(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)
	// Bob's room belongs to Alice: links must use the resource owner, rather
	// than the account whose membership selected the row.
	detail, err := db.AdminAccount("u2")
	if err != nil {
		t.Fatal(err)
	}
	if len(detail.Devices) != 1 || detail.Devices[0].OwnerID != "u2" || len(detail.Networks) != 1 || detail.Networks[0].OwnerID != "u1" || len(detail.Rooms) != 1 || detail.Rooms[0].OwnerID != "u1" {
		t.Fatalf("account detail returned wrong owner links: %+v", detail)
	}
	networks, err := db.AdminNetworks(25, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range networks.Items {
		if network.OwnerID != "u1" {
			t.Fatalf("wrong network owner: %+v", network)
		}
	}
	rooms, err := db.AdminRooms(25, 0)
	if err != nil || len(rooms.Items) != 1 || rooms.Items[0].OwnerID != "u1" {
		t.Fatalf("wrong room owner: %+v, %v", rooms, err)
	}
	devices, err := db.AdminDevicesCursor("Personal", "online", "", 25)
	if err != nil || devices.Total != 1 || len(devices.Items) != 1 || devices.Items[0].OwnerID != "u1" || devices.Items[0].ID != "d1" {
		t.Fatalf("network-name search returned wrong device/owner: %+v, %v", devices, err)
	}
	devices, err = db.AdminDevicesCursor("Friends", "all", "", 25)
	if err != nil || devices.Total != 2 || len(devices.Items) != 2 || devices.Items[1].OwnerID != "u2" {
		t.Fatalf("shared-room search lost device ownership: %+v, %v", devices, err)
	}
}

func TestAdminDevicesCursorEmptyPage(t *testing.T) {
	db := adminDeviceCursorTestDB(t, 0)
	page, err := db.AdminDevicesCursor("", "all", "", 25)
	if err != nil || page.Total != 0 || page.Items == nil || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("empty roster must return an empty list: %+v, %v", page, err)
	}
}
