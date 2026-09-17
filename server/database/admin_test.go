package database

import (
	"errors"
	"testing"
)

func seedAdminTestData(t *testing.T, db *DB) {
	t.Helper()
	statements := []string{
		`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u1', 'alice@example.test', 'x', 10, 'alice')`,
		`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u2', 'bob@example.test', 'x', 11, 'bob')`,
		`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES ('n1', 'Personal', '10.20.1.0/24', 'u1', 20)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m1', 'u1', 'n1', 'owner', 20)`,
		`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES ('room-1', 'Friends', '10.66.1.0/24', 'u1', 30)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m2', 'u1', 'room-1', 'owner', 30)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m3', 'u2', 'room-1', 'member', 31)`,
		`INSERT INTO rooms (network_id, room_code, owner_id, password_hash, join_locked, revision, created_at) VALUES ('room-1', '12345678', 'u1', X'01', 0, 1, 30)`,
		`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, relay_rtt_ms, last_seen, app_version, online, created_at) VALUES ('d1', 'u1', 'n1', 'pk1', 'Alice Mac', 'macos', '10.20.1.2', 'p2v2:g=1;m=endpoint_independent', 18, 100, '0.1.163', 1, 40)`,
		`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, last_seen, app_version, online, created_at) VALUES ('d2', 'u1', 'room-1', 'pk2', 'Alice Linux', 'linux', '10.66.1.2', 'unknown', 80, '0.1.163', 0, 50)`,
		`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, relay_rtt_ms, last_seen, app_version, online, created_at) VALUES ('d3', 'u2', 'room-1', 'pk3', 'Bob PC', 'windows', '10.66.1.3', 'p2v2:g=1;m=address_dependent', 32, 110, '0.1.163', 1, 51)`,
		`INSERT INTO tunnels (id, device_id, protocol, local_port, remote_port, active, created_at) VALUES ('t1', 'd1', 'tcp', 22, 22022, 1, 60)`,
		`INSERT INTO signals (id, from_node_id, to_node_id, type, created_at) VALUES ('s1', 'd1', 'd2', 'offer', 70)`,
		`INSERT INTO signals (id, from_node_id, to_node_id, type, created_at) VALUES ('s2', 'd2', 'd3', 'candidate', 90)`,
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
	if overview.Users != 2 || overview.Networks != 2 || overview.Rooms != 1 || overview.Devices != 3 || overview.OnlineDevices != 2 || overview.ActiveTunnels != 1 || overview.PendingSignals != 2 {
		t.Fatalf("unexpected overview: %+v", overview)
	}
	if len(overview.RecentDevices) != 3 || overview.RecentDevices[0].ID != "d3" {
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
	if roomNetwork == nil || !roomNetwork.IsRoom || roomNetwork.MemberCount != 2 || roomNetwork.DeviceCount != 2 {
		t.Fatalf("unexpected room network: %+v", roomNetwork)
	}

	rooms, err := db.AdminRooms(50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rooms.Total != 1 || len(rooms.Items) != 1 || rooms.Items[0].Code != "12345678" || rooms.Items[0].OwnerUsername != "alice" || rooms.Items[0].MemberCount != 2 {
		t.Fatalf("unexpected rooms: %+v", rooms)
	}
}

func TestAdminAccountsAndAccountDetail(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	page, err := db.AdminAccounts("", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if page.Total != 2 || len(page.Items) != 2 {
		t.Fatalf("unexpected accounts: %+v", page)
	}
	if page.Items[0].ID != "u2" || page.Items[0].DeviceCount != 1 || page.Items[0].OnlineDevices != 1 || page.Items[0].RoomCount != 1 {
		t.Fatalf("unexpected most recent account: %+v", page.Items[0])
	}

	search, err := db.AdminAccounts("alice", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if search.Total != 1 || search.Items[0].ID != "u1" {
		t.Fatalf("unexpected account search: %+v", search)
	}

	detail, err := db.AdminAccount("u1")
	if err != nil {
		t.Fatal(err)
	}
	if detail.Account.Username != "alice" || len(detail.Devices) != 2 || len(detail.Networks) != 2 || len(detail.Rooms) != 1 {
		t.Fatalf("unexpected account detail: %+v", detail)
	}
	if _, err := db.AdminAccount("missing"); !errors.Is(err, ErrAdminAccountNotFound) {
		t.Fatalf("expected account not found, got %v", err)
	}
}

func TestAdminAccountTopologyIncludesSharedPeersWithoutInventingPath(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	topology, err := db.AdminTopology("u1")
	if err != nil {
		t.Fatal(err)
	}
	if topology.Scope != "account" || topology.FocusAccountID != "u1" || topology.PathObservationAvailable {
		t.Fatalf("unexpected topology metadata: %+v", topology)
	}

	nodes := map[string]AdminTopologyNode{}
	for _, node := range topology.Nodes {
		nodes[node.ID] = node
	}
	for _, id := range []string{"account:u1", "account:u2", "network:n1", "network:room-1", "device:d1", "device:d2", "device:d3"} {
		if _, ok := nodes[id]; !ok {
			t.Fatalf("expected topology node %s; got %+v", id, topology.Nodes)
		}
	}
	if !nodes["account:u1"].Focus || nodes["account:u2"].Focus {
		t.Fatalf("unexpected focus flags: u1=%+v u2=%+v", nodes["account:u1"], nodes["account:u2"])
	}

	var sharedPeerMembership, pendingSignal bool
	for _, edge := range topology.Edges {
		if edge.Kind == "membership" && edge.Source == "account:u2" && edge.Target == "network:room-1" {
			sharedPeerMembership = true
		}
		if edge.Kind == "pending_signal" && edge.Source == "device:d2" && edge.Target == "device:d3" && edge.SignalType == "candidate" {
			pendingSignal = true
		}
		if edge.Kind == "direct" || edge.Kind == "relay" {
			t.Fatalf("control topology must not invent data-path edges: %+v", edge)
		}
	}
	if !sharedPeerMembership || !pendingSignal {
		t.Fatalf("missing shared peer relationship or signaling edge: %+v", topology.Edges)
	}
}

func TestAdminGlobalTopologyContainsAllAccounts(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	topology, err := db.AdminTopology("")
	if err != nil {
		t.Fatal(err)
	}
	if topology.Scope != "global" || topology.PathObservationAvailable {
		t.Fatalf("unexpected global topology metadata: %+v", topology)
	}
	accounts := map[string]bool{}
	for _, node := range topology.Nodes {
		if node.Kind == "account" {
			accounts[node.AccountID] = true
		}
	}
	if !accounts["u1"] || !accounts["u2"] || len(accounts) != 2 {
		t.Fatalf("unexpected global accounts: %+v", accounts)
	}
}
