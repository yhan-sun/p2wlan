package database

import "testing"

func seedAdminTestData(t *testing.T, db *DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u1', 'alice@example.test', 'x', 10, 'alice')`,
		`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES ('n1', 'Personal', '10.20.1.0/24', 'u1', 20)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m1', 'u1', 'n1', 'owner', 20)`,
		`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES ('room-1', 'Friends', '10.66.1.0/24', 'u1', 30)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m2', 'u1', 'room-1', 'owner', 30)`,
		`INSERT INTO rooms (network_id, room_code, owner_id, password_hash, join_locked, revision, created_at) VALUES ('room-1', '12345678', 'u1', X'01', 0, 1, 30)`,
		`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, relay_rtt_ms, last_seen, app_version, online, created_at) VALUES ('d1', 'u1', 'n1', 'pk1', 'Alice Mac', 'macos', '10.20.1.2', 'p2v2:g=1;m=endpoint_independent', 18, 100, '0.1.163', 1, 40)`,
		`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, last_seen, app_version, online, created_at) VALUES ('d2', 'u1', 'room-1', 'pk2', 'Linux Box', 'linux', '10.66.1.2', 'unknown', 80, '0.1.163', 0, 50)`,
		`INSERT INTO tunnels (id, device_id, protocol, local_port, remote_port, active, created_at) VALUES ('t1', 'd1', 'tcp', 22, 22022, 1, 60)`,
		`INSERT INTO signals (id, from_node_id, to_node_id, type, created_at) VALUES ('s1', 'd1', 'd2', 'offer', 70)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("seed admin data: %v\n%s", err, statement)
		}
	}
}

func TestAdminOverviewSnapshotUsesRealCounts(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	overview, err := db.AdminOverviewSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if overview.Users != 1 || overview.Networks != 2 || overview.Rooms != 1 || overview.Devices != 2 || overview.OnlineDevices != 1 || overview.ActiveTunnels != 1 || overview.PendingSignals != 1 {
		t.Fatalf("unexpected overview: %+v", overview)
	}
	if len(overview.RecentDevices) != 2 || overview.RecentDevices[0].ID != "d1" {
		t.Fatalf("unexpected recent devices: %+v", overview.RecentDevices)
	}
}

func TestAdminDevicesFiltersAndBoundsPagination(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	page, err := db.AdminDevices("Alice", "online", 500, -1)
	if err != nil {
		t.Fatal(err)
	}
	if page.Limit != adminMaxPageSize || page.Offset != 0 || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != "d1" {
		t.Fatalf("unexpected device page: %+v", page)
	}
	if _, err := db.AdminDevices("", "maybe", 50, 0); err != ErrInvalidAdminDeviceStatus {
		t.Fatalf("expected invalid status error, got %v", err)
	}
}

func TestAdminNetworkAndRoomPages(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	networks, err := db.AdminNetworks(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if networks.Total != 2 || len(networks.Items) != 2 {
		t.Fatalf("unexpected networks: %+v", networks)
	}
	var roomNetwork *AdminNetworkSummary
	for i := range networks.Items {
		if networks.Items[i].ID == "room-1" {
			roomNetwork = &networks.Items[i]
		}
	}
	if roomNetwork == nil || !roomNetwork.IsRoom || roomNetwork.MemberCount != 1 || roomNetwork.DeviceCount != 1 {
		t.Fatalf("unexpected room network: %+v", roomNetwork)
	}

	rooms, err := db.AdminRooms(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rooms.Total != 1 || len(rooms.Items) != 1 || rooms.Items[0].Code != "12345678" || rooms.Items[0].OwnerUsername != "alice" {
		t.Fatalf("unexpected rooms: %+v", rooms)
	}
}
