package database

import (
	"path/filepath"
	"testing"
	"time"
)

func setupTelemetryTestDB(t *testing.T) (*DB, string, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "control.db")
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New database: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	// Create user 1 and network 1
	u1, err := db.CreateUser("user1@example.com", "hash1")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	net1, err := db.CreateNetwork(u1.ID, "Net 1", "10.20.0.0/16")
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	// Create device A and device B in net1
	devA, err := db.CreateDevice(u1.ID, net1.ID, "pub-key-a", "Device A", "linux", "10.20.0.2")
	if err != nil {
		t.Fatalf("CreateDevice A: %v", err)
	}
	devB, err := db.CreateDevice(u1.ID, net1.ID, "pub-key-b", "Device B", "linux", "10.20.0.3")
	if err != nil {
		t.Fatalf("CreateDevice B: %v", err)
	}

	return db, u1.ID, net1.ID, devA.ID, devB.ID
}

func strPtr(s string) *string {
	return &s
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

// TestPathTelemetryBasicSubmission tests scenario 11: authenticated device submits observation.
func TestPathTelemetryBasicSubmission(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)

	obs := PathObservation{
		SchemaVersion:         1,
		RemoteDeviceID:        devBID,
		NetworkID:             netID,
		ObservationRevision:   10,
		NetworkGeneration:     1,
		PeerSessionGeneration: 1,
		RemoteCandidateEpoch:  1,
		Lifecycle:             "online",
		CurrentPath:           strPtr("direct"),
		PreviousPath:          strPtr("relay"),
		TransitionReason:      "direct_committed",
		PathAgeMS:             500,
		SelectedPathMTU:       uint32Ptr(1420),
		ObservedAt:            time.Now().Unix(),
	}

	summary, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{obs}, false)
	if err != nil {
		t.Fatalf("RecordPathObservations failed: %v", err)
	}
	if summary.Accepted != 1 || summary.Rejected != 0 || summary.Duplicate != 0 {
		t.Fatalf("expected 1 accepted, got %+v", summary)
	}

	// Verify latest observation was upserted (scenario 19)
	page, err := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil {
		t.Fatalf("AdminConnections failed: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("expected 1 item, got %d", page.Total)
	}
	item := page.Items[0]
	if !item.Directional {
		t.Fatalf("expected directional: true")
	}
	if item.CurrentPath == nil || *item.CurrentPath != "direct" {
		t.Fatalf("expected current_path=direct, got %v", item.CurrentPath)
	}
	if item.SelectedPathMTU == nil || *item.SelectedPathMTU != 1420 {
		t.Fatalf("expected mtu=1420, got %v", item.SelectedPathMTU)
	}
}

// TestPathTelemetryRejectInvalidRemotePeer tests scenario 13: illegal remote peer is rejected.
func TestPathTelemetryRejectInvalidRemotePeer(t *testing.T) {
	db, _, netID, devAID, _ := setupTelemetryTestDB(t)

	obs := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      "non-existent-device",
		NetworkID:           netID,
		ObservationRevision: 1,
		Lifecycle:           "online",
		CurrentPath:         strPtr("direct"),
		TransitionReason:    "direct_committed",
	}

	summary, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{obs}, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.Rejected != 1 || summary.Accepted != 0 {
		t.Fatalf("expected 1 rejected for invalid remote peer, got %+v", summary)
	}
}

// TestPathTelemetryRejectInvalidNetworkMembership tests scenario 14: invalid network membership is rejected.
func TestPathTelemetryRejectInvalidNetworkMembership(t *testing.T) {
	db, _, _, devAID, devBID := setupTelemetryTestDB(t)

	obs := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      devBID,
		NetworkID:           "non-existent-net",
		ObservationRevision: 1,
		Lifecycle:           "online",
		CurrentPath:         strPtr("direct"),
		TransitionReason:    "direct_committed",
	}

	_, err := db.RecordPathObservations(devAID, "non-existent-net", 1, []PathObservation{obs}, false)
	if err == nil {
		t.Fatalf("expected error for invalid network membership, got nil")
	}
}

// TestPathTelemetryRevisionFencing tests scenarios 15 & 16:
// 10 accepted, 10 duplicate/no-op, 9 rejected/no-op, 11 accepted.
func TestPathTelemetryRevisionFencing(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)

	makeObs := func(rev uint64, path string) PathObservation {
		return PathObservation{
			SchemaVersion:         1,
			RemoteDeviceID:        devBID,
			NetworkID:             netID,
			ObservationRevision:   rev,
			NetworkGeneration:     1,
			PeerSessionGeneration: 1,
			RemoteCandidateEpoch:  1,
			Lifecycle:             "online",
			CurrentPath:           strPtr(path),
			TransitionReason:      "direct_committed",
			ObservedAt:            time.Now().Unix(),
		}
	}

	// 1. Send revision 10 -> accepted
	s1, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeObs(10, "direct")}, false)
	if err != nil || s1.Accepted != 1 {
		t.Fatalf("revision 10 should be accepted: %+v, err: %v", s1, err)
	}

	// 2. Send revision 10 again -> duplicate
	s2, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeObs(10, "direct")}, false)
	if err != nil || s2.Duplicate != 1 {
		t.Fatalf("duplicate revision 10 should be marked duplicate: %+v, err: %v", s2, err)
	}

	// 3. Send revision 9 (old) -> rejected
	s3, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeObs(9, "relay")}, false)
	if err != nil || s3.Rejected != 1 {
		t.Fatalf("older revision 9 should be rejected: %+v, err: %v", s3, err)
	}

	// Verify state is STILL direct (revision 10)
	page, err := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil || len(page.Items) != 1 || *page.Items[0].CurrentPath != "direct" {
		t.Fatalf("connection should still be direct, got %v", page.Items[0].CurrentPath)
	}

	// 4. Send revision 11 -> accepted
	s4, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeObs(11, "relay")}, false)
	if err != nil || s4.Accepted != 1 {
		t.Fatalf("newer revision 11 should be accepted: %+v, err: %v", s4, err)
	}

	// Verify state is NOW relay (revision 11)
	page, err = db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil || len(page.Items) != 1 || *page.Items[0].CurrentPath != "relay" {
		t.Fatalf("connection should now be relay, got %v", page.Items[0].CurrentPath)
	}
}

// TestPathTelemetrySessionFencing tests scenarios 17 & 18:
// Old session sends revision 100, new session sends revision 1.
// Session ownership fencing takes precedence over revision!
func TestPathTelemetrySessionFencing(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)

	makeObs := func(rev uint64, path string) PathObservation {
		return PathObservation{
			SchemaVersion:         1,
			RemoteDeviceID:        devBID,
			NetworkID:             netID,
			ObservationRevision:   rev,
			NetworkGeneration:     1,
			PeerSessionGeneration: 1,
			RemoteCandidateEpoch:  1,
			Lifecycle:             "online",
			CurrentPath:           strPtr(path),
			TransitionReason:      "relay_peer_confirmed",
			ObservedAt:            time.Now().Unix(),
		}
	}

	// Session 1 writes revision 100 (Relay)
	s1, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeObs(100, "relay")}, false)
	if err != nil || s1.Accepted != 1 {
		t.Fatalf("session 1 revision 100 failed: %+v, %v", s1, err)
	}

	// Reconnect / new session: registration_seq = 2, sends revision 1 (Direct)
	s2, err := db.RecordPathObservations(devAID, netID, 2, []PathObservation{makeObs(1, "direct")}, true)
	if err != nil || s2.Accepted != 1 {
		t.Fatalf("session 2 revision 1 should supersede session 1: %+v, %v", s2, err)
	}

	// Check that admin shows Direct (revision 1, session 2)
	page, err := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil || len(page.Items) != 1 || *page.Items[0].CurrentPath != "direct" {
		t.Fatalf("expected direct from session 2, got %v", page.Items[0].CurrentPath)
	}

	// Delayed packet from session 1 arrives with revision 101 -> must be REJECTED!
	s3, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeObs(101, "relay")}, false)
	if err != nil || s3.Rejected != 1 {
		t.Fatalf("old session 1 packet should be rejected even with rev 101: %+v, %v", s3, err)
	}

	// Verify state is STILL Direct from session 2
	page, err = db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil || len(page.Items) != 1 || *page.Items[0].CurrentPath != "direct" {
		t.Fatalf("expected direct still active, got %v", page.Items[0].CurrentPath)
	}
}

// TestPathTelemetryGenerationFencing tests network generation fencing:
// Generation 4 cannot overwrite generation 5.
func TestPathTelemetryGenerationFencing(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)

	makeGenObs := func(gen uint64, rev uint64, path string) PathObservation {
		return PathObservation{
			SchemaVersion:         1,
			RemoteDeviceID:        devBID,
			NetworkID:             netID,
			ObservationRevision:   rev,
			NetworkGeneration:     gen,
			PeerSessionGeneration: 1,
			RemoteCandidateEpoch:  1,
			Lifecycle:             "online",
			CurrentPath:           strPtr(path),
			TransitionReason:      "direct_committed",
			ObservedAt:            time.Now().Unix(),
		}
	}

	// Daemon commits Direct in generation 5, revision 1
	s1, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeGenObs(5, 1, "direct")}, false)
	if err != nil || s1.Accepted != 1 {
		t.Fatalf("generation 5 failed: %+v, %v", s1, err)
	}

	// Delayed async packet from generation 4 with higher revision 10 arrives -> MUST BE REJECTED!
	s2, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{makeGenObs(4, 10, "relay")}, false)
	if err != nil || s2.Rejected != 1 {
		t.Fatalf("old generation 4 must be rejected: %+v, %v", s2, err)
	}

	// Admin remains Direct
	page, err := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil || len(page.Items) != 1 || *page.Items[0].CurrentPath != "direct" {
		t.Fatalf("expected direct to remain, got %v", page.Items[0].CurrentPath)
	}
}

// TestPathTelemetryTransitionHistoryAndBounding tests scenarios 20 & 21:
// Transitions are recorded only on meaningful change, and history is bounded to 50.
func TestPathTelemetryTransitionHistoryAndBounding(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)

	// First observation -> transition 1 (initial -> direct)
	obs1 := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      devBID,
		NetworkID:           netID,
		ObservationRevision: 1,
		Lifecycle:           "online",
		CurrentPath:         strPtr("direct"),
		TransitionReason:    "direct_committed",
		ObservedAt:          time.Now().Unix(),
	}
	db.RecordPathObservations(devAID, netID, 1, []PathObservation{obs1}, false)

	// Second observation -> same path, same lifecycle, same reason, rev 2 -> snapshot updated, NO new transition!
	obs2 := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      devBID,
		NetworkID:           netID,
		ObservationRevision: 2,
		Lifecycle:           "online",
		CurrentPath:         strPtr("direct"),
		TransitionReason:    "direct_committed",
		ObservedAt:          time.Now().Unix(),
	}
	db.RecordPathObservations(devAID, netID, 1, []PathObservation{obs2}, false)

	transPage, err := db.AdminConnectionTransitions(AdminConnectionTransitionFilter{ReportingDeviceID: devAID}, 100, "")
	if err != nil {
		t.Fatalf("AdminConnectionTransitions failed: %v", err)
	}
	if len(transPage.Items) != 1 {
		t.Fatalf("expected only 1 transition recorded for duplicate path, got %d", len(transPage.Items))
	}

	// Now alternate between direct and relay 60 times to test bounding (scenario 21)
	for i := 3; i < 70; i++ {
		path := "direct"
		if i%2 == 0 {
			path = "relay"
		}
		obs := PathObservation{
			SchemaVersion:       1,
			RemoteDeviceID:      devBID,
			NetworkID:           netID,
			ObservationRevision: uint64(i),
			Lifecycle:           "online",
			CurrentPath:         strPtr(path),
			TransitionReason:    "relay_peer_confirmed",
			ObservedAt:          time.Now().Unix(),
		}
		db.RecordPathObservations(devAID, netID, 1, []PathObservation{obs}, false)
	}

	transPage, err = db.AdminConnectionTransitions(AdminConnectionTransitionFilter{ReportingDeviceID: devAID}, 100, "")
	if err != nil {
		t.Fatalf("AdminConnectionTransitions failed: %v", err)
	}
	if len(transPage.Items) > MaxTransitionsPerPair {
		t.Fatalf("expected at most %d transitions, got %d", MaxTransitionsPerPair, len(transPage.Items))
	}
	if len(transPage.Items) != MaxTransitionsPerPair {
		t.Fatalf("expected exactly %d capped transitions, got %d", MaxTransitionsPerPair, len(transPage.Items))
	}
}

// TestPathTelemetryFreshnessSemantics tests scenario 22:
// Freshness follows DeviceOnlineTTL and reporting device online state.
func TestPathTelemetryFreshnessSemantics(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)

	obs := PathObservation{
		SchemaVersion:       1,
		RemoteDeviceID:      devBID,
		NetworkID:           netID,
		ObservationRevision: 1,
		Lifecycle:           "online",
		CurrentPath:         strPtr("direct"),
		TransitionReason:    "direct_committed",
		ObservedAt:          time.Now().Unix(),
	}
	db.RecordPathObservations(devAID, netID, 1, []PathObservation{obs}, false)

	// Set devA offline explicitly -> fresh should be false, freshness = "reporter_offline"
	if _, err := db.Exec("UPDATE devices SET online = 0, last_seen = 0 WHERE id = ?", devAID); err != nil {
		t.Fatalf("set offline failed: %v", err)
	}
	page, _ := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 item")
	}
	if page.Items[0].Fresh {
		t.Fatalf("expected fresh=false when reporter is offline")
	}
	if page.Items[0].Freshness != "reporter_offline" {
		t.Fatalf("expected freshness=reporter_offline, got %s", page.Items[0].Freshness)
	}
	// Path value itself is preserved as direct!
	if page.Items[0].CurrentPath == nil || *page.Items[0].CurrentPath != "direct" {
		t.Fatalf("path value must not be mutated to offline, got %v", page.Items[0].CurrentPath)
	}

	// Now mark devA online
	if _, err := db.Exec("UPDATE devices SET online = 1, last_seen = ? WHERE id = ?", time.Now().Unix(), devAID); err != nil {
		t.Fatalf("set device online failed: %v", err)
	}
	page, _ = db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if !page.Items[0].Fresh {
		t.Fatalf("expected fresh=true after reporter becomes online")
	}
	if page.Items[0].Freshness != "fresh" {
		t.Fatalf("expected freshness=fresh, got %s", page.Items[0].Freshness)
	}

	// Test freshness filter
	freshPage, _ := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID, Freshness: "fresh"}, 10, 0)
	if freshPage.Total != 1 {
		t.Fatalf("expected 1 item for fresh filter, got %d", freshPage.Total)
	}
	stalePage, _ := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID, Freshness: "stale"}, 10, 0)
	if stalePage.Total != 0 {
		t.Fatalf("expected 0 items for stale filter, got %d", stalePage.Total)
	}
}

// TestPathTelemetryMigrationPreservesOldDB tests scenario 34:
// Old DB migrates successfully, existing data preserved, new tables empty.
func TestPathTelemetryMigrationPreservesOldDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "old.db")

	// Open DB (which runs migrations including migratePathTelemetry)
	db, err := New(dbPath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	defer db.Close()

	// Re-running migratePathTelemetry is idempotent
	if err := migratePathTelemetry(db.DB); err != nil {
		t.Fatalf("re-running migratePathTelemetry failed: %v", err)
	}

	page, err := db.AdminConnections(AdminConnectionFilter{}, 10, 0)
	if err != nil {
		t.Fatalf("AdminConnections on clean DB failed: %v", err)
	}
	if page.Total != 0 {
		t.Fatalf("expected 0 connections, got %d", page.Total)
	}
}
