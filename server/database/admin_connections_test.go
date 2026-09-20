package database

import (
	"path/filepath"
	"testing"
	"time"
)

func TestAdminConnectionsFilteringAndPagination(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "control.db")
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New database: %v", err)
	}
	defer db.Close()

	// Scenario 34: no telemetry -> empty, not guessing path
	emptyPage, err := db.AdminConnections(AdminConnectionFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("AdminConnections failed on empty DB: %v", err)
	}
	if emptyPage.Total != 0 || len(emptyPage.Items) != 0 {
		t.Fatalf("expected 0 connections when no telemetry, got %d", emptyPage.Total)
	}

	// Setup users, networks, devices
	u1, _ := db.CreateUser("user1@example.com", "hash1")
	u2, _ := db.CreateUser("user2@example.com", "hash2")

	net1, _ := db.CreateNetwork(u1.ID, "Net 1", "10.20.0.0/16")
	net2, _ := db.CreateNetwork(u2.ID, "Net 2", "10.30.0.0/16")

	devA, _ := db.CreateDevice(u1.ID, net1.ID, "pub-a", "Device A", "linux", "10.20.0.2")
	devB, _ := db.CreateDevice(u1.ID, net1.ID, "pub-b", "Device B", "linux", "10.20.0.3")
	devC, _ := db.CreateDevice(u2.ID, net2.ID, "pub-c", "Device C", "macos", "10.30.0.2")
	devD, _ := db.CreateDevice(u2.ID, net2.ID, "pub-d", "Device D", "windows", "10.30.0.3")

	// Set devices online
	now := time.Now().Unix()
	db.Exec("UPDATE devices SET online = 1, last_seen = ? WHERE id IN (?, ?, ?, ?)", now, devA.ID, devB.ID, devC.ID, devD.ID)

	// Add observations:
	// A -> B in Net 1 (Direct)
	// B -> A in Net 1 (Relay) - directional difference!
	// C -> D in Net 2 (Direct)
	obsAB := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      devB.ID,
		NetworkID:           net1.ID,
		ObservationRevision: 1,
		Lifecycle:           "online",
		CurrentPath:         strPtr("direct"),
		TransitionReason:    "direct_committed",
		ObservedAt:          now,
	}
	obsBA := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      devA.ID,
		NetworkID:           net1.ID,
		ObservationRevision: 1,
		Lifecycle:           "online",
		CurrentPath:         strPtr("relay"),
		TransitionReason:    "relay_peer_confirmed",
		ObservedAt:          now,
	}
	obsCD := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      devD.ID,
		NetworkID:           net2.ID,
		ObservationRevision: 1,
		Lifecycle:           "online",
		CurrentPath:         strPtr("direct"),
		TransitionReason:    "direct_committed",
		ObservedAt:          now,
	}

	db.RecordPathObservations(devA.ID, net1.ID, 1, []PathObservation{obsAB}, false)
	db.RecordPathObservations(devB.ID, net1.ID, 1, []PathObservation{obsBA}, false)
	db.RecordPathObservations(devC.ID, net2.ID, 1, []PathObservation{obsCD}, false)

	// 25. List connections (all)
	allPage, err := db.AdminConnections(AdminConnectionFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("AdminConnections failed: %v", err)
	}
	if allPage.Total != 3 {
		t.Fatalf("expected 3 connections total, got %d", allPage.Total)
	}

	// 32. Directional semantics preserved:
	// Verify A -> B is direct, while B -> A is relay
	var foundAB, foundBA bool
	for _, item := range allPage.Items {
		if !item.Directional {
			t.Fatalf("expected directional: true for every item")
		}
		if item.ReportingDeviceID == devA.ID && item.RemoteDeviceID == devB.ID {
			foundAB = true
			if item.CurrentPath == nil || *item.CurrentPath != "direct" {
				t.Fatalf("expected A->B direct, got %v", item.CurrentPath)
			}
		}
		if item.ReportingDeviceID == devB.ID && item.RemoteDeviceID == devA.ID {
			foundBA = true
			if item.CurrentPath == nil || *item.CurrentPath != "relay" {
				t.Fatalf("expected B->A relay, got %v", item.CurrentPath)
			}
		}
	}
	if !foundAB || !foundBA {
		t.Fatalf("missing A->B or B->A directional connections")
	}

	// 26. Account filter (u1 should show 2, u2 should show 1)
	u1Page, _ := db.AdminConnections(AdminConnectionFilter{AccountID: u1.ID}, 10, 0)
	if u1Page.Total != 2 {
		t.Fatalf("expected 2 connections for user 1, got %d", u1Page.Total)
	}
	u2Page, _ := db.AdminConnections(AdminConnectionFilter{AccountID: u2.ID}, 10, 0)
	if u2Page.Total != 1 {
		t.Fatalf("expected 1 connection for user 2, got %d", u2Page.Total)
	}

	// 27. Network filter
	net1Page, _ := db.AdminConnections(AdminConnectionFilter{NetworkID: net1.ID}, 10, 0)
	if net1Page.Total != 2 {
		t.Fatalf("expected 2 connections in net1, got %d", net1Page.Total)
	}
	net2Page, _ := db.AdminConnections(AdminConnectionFilter{NetworkID: net2.ID}, 10, 0)
	if net2Page.Total != 1 {
		t.Fatalf("expected 1 connection in net2, got %d", net2Page.Total)
	}

	// 28. Device filter (Device A)
	devAPage, _ := db.AdminConnections(AdminConnectionFilter{DeviceID: devA.ID}, 10, 0)
	if devAPage.Total != 2 {
		t.Fatalf("expected 2 connections involving device A, got %d", devAPage.Total)
	}

	// Text search is applied server-side across device, account, and network labels.
	searchDevice, _ := db.AdminConnections(AdminConnectionFilter{Query: "device a"}, 10, 0)
	if searchDevice.Total != 2 {
		t.Fatalf("expected 2 directional connections involving Device A, got %d", searchDevice.Total)
	}
	searchNetwork, _ := db.AdminConnections(AdminConnectionFilter{Query: "net 2"}, 10, 0)
	if searchNetwork.Total != 1 {
		t.Fatalf("expected 1 connection matching Net 2, got %d", searchNetwork.Total)
	}
	searchUser, _ := db.AdminConnections(AdminConnectionFilter{Query: u1.Username}, 10, 0)
	if searchUser.Total != 2 {
		t.Fatalf("expected 2 connections matching user 1, got %d", searchUser.Total)
	}

	// 29. Path filter
	directPage, _ := db.AdminConnections(AdminConnectionFilter{Path: "direct"}, 10, 0)
	if directPage.Total != 2 {
		t.Fatalf("expected 2 direct connections, got %d", directPage.Total)
	}
	relayPage, _ := db.AdminConnections(AdminConnectionFilter{Path: "relay"}, 10, 0)
	if relayPage.Total != 1 {
		t.Fatalf("expected 1 relay connection, got %d", relayPage.Total)
	}

	// 31. Stable pagination (limit 2, offset 0; limit 2, offset 2)
	p1, _ := db.AdminConnections(AdminConnectionFilter{}, 2, 0)
	if len(p1.Items) != 2 || p1.Total != 3 {
		t.Fatalf("expected page 1 with 2 items, total 3; got len=%d total=%d", len(p1.Items), p1.Total)
	}
	p2, _ := db.AdminConnections(AdminConnectionFilter{}, 2, 2)
	if len(p2.Items) != 1 || p2.Total != 3 {
		t.Fatalf("expected page 2 with 1 item, total 3; got len=%d total=%d", len(p2.Items), p2.Total)
	}
	if p1.Items[0].ReportingDeviceID == p2.Items[0].ReportingDeviceID && p1.Items[0].RemoteDeviceID == p2.Items[0].RemoteDeviceID {
		t.Fatalf("pagination overlap detected between page 1 and page 2")
	}
}

// TestAdminConnectionTransitionsCursorOrdering tests scenario 35: transition history ordering and cursor.
func TestAdminConnectionTransitionsCursorOrdering(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "control.db")
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New database: %v", err)
	}
	defer db.Close()

	u1, _ := db.CreateUser("user1@example.com", "hash1")
	net1, _ := db.CreateNetwork(u1.ID, "Net 1", "10.20.0.0/16")
	devA, _ := db.CreateDevice(u1.ID, net1.ID, "pub-a", "Device A", "linux", "10.20.0.2")
	devB, _ := db.CreateDevice(u1.ID, net1.ID, "pub-b", "Device B", "linux", "10.20.0.3")

	// Insert 3 transitions
	paths := []string{"direct", "relay", "direct"}
	reasons := []string{"direct_committed", "relay_peer_confirmed", "direct_committed"}
	for i := 0; i < 3; i++ {
		obs := PathObservation{
			SchemaVersion:       1,
			RemoteDeviceID:      devB.ID,
			NetworkID:           net1.ID,
			ObservationRevision: uint64(i + 1),
			Lifecycle:           "online",
			CurrentPath:         strPtr(paths[i]),
			TransitionReason:    reasons[i],
			ObservedAt:          time.Now().Unix(),
		}
		db.RecordPathObservations(devA.ID, net1.ID, 1, []PathObservation{obs}, false)
		time.Sleep(10 * time.Millisecond)
	}

	// Fetch with limit = 2
	p1, err := db.AdminConnectionTransitions(AdminConnectionTransitionFilter{ReportingDeviceID: devA.ID}, 2, "")
	if err != nil {
		t.Fatalf("page 1 failed: %v", err)
	}
	if len(p1.Items) != 2 {
		t.Fatalf("expected 2 items in page 1, got %d", len(p1.Items))
	}
	if p1.NextCursor == "" {
		t.Fatalf("expected non-empty next cursor")
	}
	// Verify newest first: first item should be revision 3
	if p1.Items[0].ObservationRevision != 3 {
		t.Fatalf("expected newest revision 3 first, got %d", p1.Items[0].ObservationRevision)
	}

	// Fetch page 2 using cursor
	p2, err := db.AdminConnectionTransitions(AdminConnectionTransitionFilter{ReportingDeviceID: devA.ID}, 2, p1.NextCursor)
	if err != nil {
		t.Fatalf("page 2 failed: %v", err)
	}
	if len(p2.Items) != 1 {
		t.Fatalf("expected 1 item in page 2, got %d", len(p2.Items))
	}
	if p2.Items[0].ObservationRevision != 1 {
		t.Fatalf("expected revision 1 on page 2, got %d", p2.Items[0].ObservationRevision)
	}
}
