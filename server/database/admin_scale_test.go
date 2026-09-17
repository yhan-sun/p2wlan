package database

import (
	"errors"
	"testing"
	"time"
)

func TestAdminAccountCursorFreezesInsertionHorizon(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	first, err := db.AdminAccountsCursor("", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 2 || len(first.Items) != 1 || first.NextCursor == "" {
		t.Fatalf("unexpected first account cursor page: %+v", first)
	}
	firstID := first.Items[0].ID

	// This account is newer than the snapshot carried by the first cursor. It
	// must not suddenly appear halfway through the traversal or change total.
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u-new', 'new@example.test', 'x', ?, 'new')`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	second, err := db.AdminAccountsCursor("", first.NextCursor, 1)
	if err != nil {
		t.Fatal(err)
	}
	if second.Total != 2 || len(second.Items) != 1 || second.Items[0].ID == firstID || second.Items[0].ID == "u-new" {
		t.Fatalf("cursor traversal drifted after insert: first=%+v second=%+v", first, second)
	}
	if second.NextCursor != "" {
		t.Fatalf("two-row snapshot should be complete after two pages: %+v", second)
	}
}

func TestAdminCursorRejectsFilterReuse(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	page, err := db.AdminAccountsCursor("", "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor == "" {
		t.Fatal("expected another account page")
	}
	if _, err := db.AdminAccountsCursor("alice", page.NextCursor, 1); !errors.Is(err, ErrInvalidAdminCursor) {
		t.Fatalf("cursor must be bound to its filter, got %v", err)
	}
}

func collectTopologyPages(t *testing.T, db *DB, accountID, view string, limit int, afterFirst func()) *AdminTopologyPage {
	t.Helper()
	cursor := ""
	merged := &AdminTopologyPage{Nodes: []AdminTopologyNode{}, Edges: []AdminTopologyEdge{}}
	for pageNumber := 0; pageNumber < 100; pageNumber++ {
		page, err := db.AdminTopologyPage(accountID, view, cursor, limit)
		if err != nil {
			t.Fatalf("topology page %d: %v", pageNumber, err)
		}
		if pageNumber == 0 {
			merged.GeneratedAt = page.GeneratedAt
			merged.SnapshotAt = page.SnapshotAt
			merged.Scope = page.Scope
			merged.View = page.View
			merged.FocusAccountID = page.FocusAccountID
			merged.PathObservationAvailable = page.PathObservationAvailable
			merged.PathObservationNote = page.PathObservationNote
			if afterFirst != nil {
				afterFirst()
			}
		} else if page.SnapshotAt != merged.SnapshotAt {
			t.Fatalf("snapshot changed between pages: first=%d page=%d", merged.SnapshotAt, page.SnapshotAt)
		}
		merged.Nodes = append(merged.Nodes, page.Nodes...)
		merged.Edges = append(merged.Edges, page.Edges...)
		if page.Complete {
			merged.Complete = true
			return merged
		}
		if page.NextCursor == "" {
			t.Fatalf("incomplete topology page has no continuation: %+v", page)
		}
		cursor = page.NextCursor
	}
	t.Fatal("topology pagination did not terminate")
	return nil
}

func TestAdminTopologySummaryPagesWithoutSilentTruncation(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	topology := collectTopologyPages(t, db, "", topologyViewSummary, 1, nil)
	if !topology.Complete || topology.Scope != "global" || topology.View != topologyViewSummary {
		t.Fatalf("unexpected topology summary metadata: %+v", topology)
	}
	accounts := map[string]bool{}
	networks := map[string]bool{}
	memberships := 0
	for _, node := range topology.Nodes {
		switch node.Kind {
		case "account":
			accounts[node.AccountID] = true
		case "network", "room":
			networks[node.NetworkID] = true
		case "device":
			t.Fatalf("summary view must not silently include device detail: %+v", node)
		}
	}
	for _, edge := range topology.Edges {
		if edge.Kind != "membership" {
			t.Fatalf("summary view returned non-membership edge: %+v", edge)
		}
		memberships++
	}
	if !accounts["u1"] || !accounts["u2"] || !networks["n1"] || !networks["room-1"] || memberships != 3 {
		t.Fatalf("summary lost graph relationships: accounts=%v networks=%v memberships=%d", accounts, networks, memberships)
	}
}

func TestAdminTopologyCursorFreezesNewIdentities(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	topology := collectTopologyPages(t, db, "", topologyViewSummary, 1, func() {
		if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u-late', 'late@example.test', 'x', ?, 'late')`, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	})
	for _, node := range topology.Nodes {
		if node.ID == "account:u-late" {
			t.Fatalf("new identity leaked into existing topology snapshot: %+v", node)
		}
	}
}

func TestAdminFullAccountTopologyPagesKeepPrivateDefaultIsolation(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, created_at, username) VALUES ('u3', 'carol@example.test', 'x', 12, 'carol')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO network_memberships (id, user_id, network_id, role, created_at) VALUES ('m-default-u3', 'u3', 'default', 'member', 12)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO devices (id, user_id, network_id, public_key, device_name, platform, virtual_ip, nat_type, last_seen, app_version, online, created_at) VALUES ('private-u3', 'u3', 'default', 'pk-private-u3', 'Carol Private', 'linux', '10.20.0.30', 'unknown', ?, '0.1.163', 1, 12)`, time.Now().Unix()-5); err != nil {
		t.Fatal(err)
	}

	topology := collectTopologyPages(t, db, "u1", topologyViewFull, 1, nil)
	nodes := map[string]AdminTopologyNode{}
	for _, node := range topology.Nodes {
		nodes[node.ID] = node
	}
	for _, id := range []string{"account:u1", "account:u2", "network:n1", "network:room-1", "device:d1", "device:d2", "device:d3"} {
		if _, ok := nodes[id]; !ok {
			t.Fatalf("expected full account topology node %s; got %+v", id, topology.Nodes)
		}
	}
	if _, ok := nodes["device:private-u3"]; ok {
		t.Fatalf("unrelated private default device leaked into account topology: %+v", nodes["device:private-u3"])
	}
	if _, ok := nodes["account:u3"]; ok {
		t.Fatalf("unrelated account leaked into account topology: %+v", nodes["account:u3"])
	}
}

func TestAdminTopologyCursorRejectsViewReuse(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	seedAdminTestData(t, db)

	page, err := db.AdminTopologyPage("", topologyViewSummary, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	if page.NextCursor == "" {
		t.Fatal("expected topology continuation")
	}
	if _, err := db.AdminTopologyPage("", topologyViewFull, page.NextCursor, 1); !errors.Is(err, ErrInvalidAdminCursor) {
		t.Fatalf("topology cursor must be bound to its view, got %v", err)
	}
}
