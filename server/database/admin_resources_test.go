package database

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func adminResourceTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	seedAdminTestData(t, db)
	return db
}

func TestAdminResourceSearchAndMembershipApplyBeforePagination(t *testing.T) {
	db := adminResourceTestDB(t)
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO networks(id,name,cidr,owner_id,created_at) VALUES('studio','Studio% Lab','10.90.0.0/24','u2',40)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO network_memberships(id,user_id,network_id,role,created_at) VALUES('studio-member','u2','studio','owner',40)`); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ q, id string }{{"12345678", "room-1"}, {"n1", "n1"}, {"10.20.1.0/24", "n1"}, {"%", "studio"}} {
		page, err := db.AdminNetworksFiltered(ctx, AdminResourceFilter{Query: tc.q}, 1, 0)
		if err != nil || page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != tc.id || page.GeneratedAt <= 0 {
			t.Fatalf("search %q: %+v %v", tc.q, page, err)
		}
	}
	first, err := db.AdminNetworksFiltered(ctx, AdminResourceFilter{AccountID: "u2"}, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.AdminNetworksFiltered(ctx, AdminResourceFilter{AccountID: "u2"}, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 2 || second.Total != 2 || first.Items[0].ID == second.Items[0].ID || second.Items[0].ID == "n1" {
		t.Fatalf("membership pagination: %+v %+v", first, second)
	}
	rooms, err := db.AdminRoomsFiltered(ctx, AdminResourceFilter{Query: "12345678", AccountID: "u2"}, 1, 0)
	if err != nil || rooms.Total != 1 || len(rooms.Items) != 1 || rooms.Items[0].ID != "room-1" || rooms.GeneratedAt <= 0 {
		t.Fatalf("room code/member search: %+v %v", rooms, err)
	}
	empty, err := db.AdminRoomsFiltered(ctx, AdminResourceFilter{AccountID: "missing"}, 1, 0)
	if err != nil || empty.Total != 0 || len(empty.Items) != 0 {
		t.Fatalf("missing member scope: %+v %v", empty, err)
	}
}

func TestAdminAccountSummaryOmitsUnboundedResourcesAndDeviceCursorBindsAccount(t *testing.T) {
	db := adminResourceTestDB(t)
	ctx := context.Background()
	summary, err := db.AdminAccountSummary(ctx, "u1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	if len(object) != 1 || object["account"] == nil || summary.Account.DeviceCount != 2 {
		t.Fatalf("summary must not load arrays: %s", raw)
	}
	first, err := db.AdminDevicesCursorScoped(ctx, "", "all", "", 1, "u1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := db.AdminDevicesCursorScoped(ctx, "", "all", first.NextCursor, 1, "u1")
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 2 || second.Total != 2 || len(second.Items) != 1 || first.Items[0].ID == second.Items[0].ID {
		t.Fatalf("account device pages: %+v %+v", first, second)
	}
	for _, scope := range []string{"", "u2"} {
		if _, err := db.AdminDevicesCursorScoped(ctx, "", "all", first.NextCursor, 1, scope); !errors.Is(err, ErrInvalidAdminDeviceCursor) {
			t.Fatalf("cursor crossed scope %q: %v", scope, err)
		}
	}
	if _, err := db.AdminAccountSummary(ctx, "missing"); !errors.Is(err, ErrAdminAccountNotFound) {
		t.Fatalf("missing account: %v", err)
	}
}

func TestNetworkTopologyIndependentOfGlobalPageAndExplicitlyBounded(t *testing.T) {
	db := adminResourceTestDB(t)
	ctx := context.Background()
	for i := 0; i < 15; i++ {
		id := fmt.Sprintf("a%02d", i)
		if _, err := db.Exec(`INSERT INTO users(id,email,password_hash,created_at,username) VALUES(?,?, 'x',1,?)`, id, id+"@example.test", id); err != nil {
			t.Fatal(err)
		}
	}
	global, err := db.AdminTopologyPage("", 12, 600)
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range global.Nodes {
		if node.NetworkID == "room-1" {
			t.Fatal("fixture target must be outside first account page")
		}
	}
	graph, err := db.AdminTopologyNetwork(ctx, "room-1", 600)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Complete || graph.Partial || graph.Scope != "network" || graph.FocusNetworkID != "room-1" || len(graph.Nodes) != 5 {
		t.Fatalf("exact graph: %+v", graph)
	}
	bounded, err := db.AdminTopologyNetwork(ctx, "room-1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bounded.Partial || bounded.Complete || bounded.PartialReason != "node_budget" || len(bounded.Nodes) > 2 {
		t.Fatalf("bounded graph: %+v", bounded)
	}
	nodes := map[string]bool{}
	for _, node := range bounded.Nodes {
		nodes[node.ID] = true
	}
	for _, edge := range bounded.Edges {
		if !nodes[edge.Source] || !nodes[edge.Target] {
			t.Fatalf("dangling bounded edge: %+v", edge)
		}
	}
	if _, err := db.AdminTopologyNetwork(ctx, "missing", 600); !errors.Is(err, ErrAdminNetworkNotFound) {
		t.Fatalf("missing graph: %v", err)
	}
}

func TestPersonalNetworkTopologyNeverMergesDefaultAccounts(t *testing.T) {
	db := adminResourceTestDB(t)
	ctx := context.Background()
	for _, owner := range []string{"u1", "u2"} {
		if _, err := db.Exec(`INSERT INTO devices(id,user_id,network_id,public_key,device_name,platform,virtual_ip,nat_type,last_seen,online,created_at) VALUES(?,?,'default',?,'Personal','linux',?,'unknown',?,1,1)`, "private-"+owner, owner, "key-"+owner, "ip-"+owner, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := db.AdminTopologyNetwork(ctx, "personal:u1", 600)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Complete || len(graph.Nodes) != 2 || len(graph.Edges) != 1 || graph.Edges[0].Role != "private-default" {
		t.Fatalf("private graph: %+v", graph)
	}
	for _, node := range graph.Nodes {
		if node.AccountID != "u1" {
			t.Fatalf("cross-account personal node: %+v", node)
		}
	}
	if _, err := db.AdminTopologyNetwork(ctx, "default", 600); !errors.Is(err, ErrAdminNetworkNotFound) {
		t.Fatalf("shared default must not be exposed: %v", err)
	}
}

func TestScopedAdminQueriesHonorCancellation(t *testing.T) {
	db := adminResourceTestDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reads := []func() error{
		func() error { _, err := db.AdminNetworksFiltered(ctx, AdminResourceFilter{}, 1, 0); return err },
		func() error { _, err := db.AdminRoomsFiltered(ctx, AdminResourceFilter{}, 1, 0); return err },
		func() error { _, err := db.AdminAccountSummary(ctx, "u1"); return err },
		func() error { _, err := db.AdminTopologyNetwork(ctx, "room-1", 10); return err },
		func() error { _, err := db.AdminDevicesCursorScoped(ctx, "", "all", "", 1, "u1"); return err },
	}
	for _, read := range reads {
		if err := read(); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled SQL continued: %v", err)
		}
	}
}

func TestPersonalTopologyReportsEdgeBudgetWithoutDanglingNodes(t *testing.T) {
	db := adminResourceTestDB(t)
	_, err := db.Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<64)
		INSERT INTO devices(id,user_id,network_id,public_key,device_name,platform,virtual_ip,nat_type,last_seen,online,created_at)
		SELECT 'edge-device-'||n,'u1','default','edge-key-'||n,'Device '||n,'linux','ip-'||n,'unknown',1,0,1 FROM seq`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n<64)
		INSERT INTO signals(id,from_node_id,to_node_id,type,created_at)
		SELECT 'edge-signal-'||a.n||'-'||b.n,'edge-device-'||a.n,'edge-device-'||b.n,'candidate',? FROM seq a CROSS JOIN seq b`, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	graph, err := db.AdminTopologyNetwork(context.Background(), "personal:u1", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !graph.Partial || graph.Complete || graph.PartialReason != "edge_budget" || len(graph.Edges) != graph.EdgeBudget {
		t.Fatalf("edge budget must be visible: %+v", graph)
	}
	nodes := map[string]bool{}
	for _, node := range graph.Nodes {
		nodes[node.ID] = true
	}
	for _, edge := range graph.Edges {
		if !nodes[edge.Source] || !nodes[edge.Target] {
			t.Fatalf("dangling edge: %+v", edge)
		}
	}
}
