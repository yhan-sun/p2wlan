package database

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func seedAdminTestData(t *testing.T, db *DB) {
	t.Helper()
	// Device online state is a heartbeat lease, not a stored fact: a device only
	// counts as online while its last_seen is inside DeviceOnlineTTL. Seeding
	// absolute timestamps would silently make every seeded device offline.
	now := time.Now().Unix()
	statements := []string{
		`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u1', 'alice@example.test', 'x', 10, 'alice')`,
		`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u2', 'bob@example.test', 'x', 11, 'bob')`,
		`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES ('n1', 'Personal', '10.20.1.0/24', 'u1', 20)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m1', 'u1', 'n1', 'owner', 20)`,
		`INSERT INTO networks (id, name, cidr, owner_id, created_at) VALUES ('room-1', 'Friends', '10.66.1.0/24', 'u1', 30)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m2', 'u1', 'room-1', 'owner', 30)`,
		`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m3', 'u2', 'room-1', 'member', 31)`,
		`INSERT INTO rooms (network_id, room_code, owner_id, password_hash, join_locked, revision, created_at) VALUES ('room-1', '12345678', 'u1', X'01', 0, 1, 30)`,
		fmt.Sprintf(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, relay_rtt_ms, last_seen, app_version, online, created_at) VALUES ('d1', 'u1', 'n1', 'pk1', 'Alice Mac', 'macos', '10.20.1.2', 'p2v2:g=1;m=endpoint_independent', 18, %d, '0.1.163', 1, 40)`, now-10),
		fmt.Sprintf(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, last_seen, app_version, online, created_at) VALUES ('d2', 'u1', 'room-1', 'pk2', 'Alice Linux', 'linux', '10.66.1.2', 'unknown', %d, '0.1.163', 0, 50)`, now-300),
		fmt.Sprintf(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, relay_rtt_ms, last_seen, app_version, online, created_at) VALUES ('d3', 'u2', 'room-1', 'pk3', 'Bob PC', 'windows', '10.66.1.3', 'p2v2:g=1;m=address_dependent', 32, %d, '0.1.163', 1, 51)`, now-5),
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

// TestAdminOnlineStateFollowsHeartbeatLease pins the rule that the console may
// not read the raw devices.online flag. Only a graceful daemon shutdown clears
// that flag, so an abnormal exit would otherwise be reported as online forever.
func TestAdminOnlineStateFollowsHeartbeatLease(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	if _, err := db.Exec(`UPDATE devices SET online = 1, last_seen = ? WHERE id = 'd2'`, time.Now().Unix()-DeviceOnlineTTL-30); err != nil {
		t.Fatal(err)
	}

	overview, err := db.AdminOverviewSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if overview.OnlineDevices != 2 {
		t.Fatalf("stale online flag must not be counted online: %+v", overview)
	}

	online, err := db.AdminDevices("", "online", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if online.Total != 2 {
		t.Fatalf("unexpected online total: %+v", online)
	}
	for _, item := range online.Items {
		if item.ID == "d2" {
			t.Fatalf("stale device must not satisfy the online filter: %+v", online)
		}
	}

	offline, err := db.AdminDevices("Alice", "offline", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if offline.Total != 1 || len(offline.Items) != 1 || offline.Items[0].ID != "d2" || offline.Items[0].Online {
		t.Fatalf("stale device must be reported offline: %+v", offline)
	}

	topology, err := db.AdminTopology("u1")
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range topology.Nodes {
		if node.ID != "device:d2" {
			continue
		}
		if node.Online == nil || *node.Online {
			t.Fatalf("stale topology device must be offline: %+v", node)
		}
	}
}

// TestAdminFocusTopologyKeepsDefaultOnlyAccount covers an account that owns only
// a legacy private default device and has no non-default membership. The focus
// query must still render that account and its own device.
func TestAdminFocusTopologyKeepsDefaultOnlyAccount(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u3', 'carol@example.test', 'x', 12, 'carol')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m4', 'u3', 'default', 'owner', 12)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, last_seen, app_version, online, created_at) VALUES ('default-u3', 'u3', 'default', 'pk-default-u3', 'Carol Personal', 'linux', '10.20.0.12', 'unknown', ?, '0.1.163', 1, 12)`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	topology, err := db.AdminTopology("u3")
	if err != nil {
		t.Fatal(err)
	}
	nodes := map[string]AdminTopologyNode{}
	for _, node := range topology.Nodes {
		nodes[node.ID] = node
	}
	if _, ok := nodes["network:default"]; ok {
		t.Fatal("legacy shared default network must never be rendered as a shared topology node")
	}
	account, ok := nodes["account:u3"]
	if !ok {
		t.Fatalf("focus topology must keep an account that only owns a private default device: %+v", topology.Nodes)
	}
	if !account.Focus {
		t.Fatalf("focus account flag missing: %+v", account)
	}
	if _, ok := nodes["device:default-u3"]; !ok {
		t.Fatalf("focus topology must keep the account's own private default device: %+v", topology.Nodes)
	}
	var attached bool
	for _, edge := range topology.Edges {
		if edge.ID == "personal-attachment:default-u3" && edge.Source == "account:u3" && edge.Target == "device:default-u3" {
			attached = true
		}
	}
	if !attached {
		t.Fatalf("private default device must attach to its own account: %+v", topology.Edges)
	}
}
