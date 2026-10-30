package database

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAdminPathsRequireCurrentRegistration(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	user, err := db.CreateUser("registration@example.test", "hash")
	if err != nil {
		t.Fatal(err)
	}
	one, two := int64(1), int64(2)
	reporter, err := db.RegisterDeviceWithOptions(user.ID, "default", "reporter-key", "Reporter", "linux", "", "", "", DeviceRegistrationAttempt{Incarnation: &one, EnforceIncarnation: true})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := db.CreateDevice(user.ID, "default", "remote-key", "Remote", "linux", "")
	if err != nil {
		t.Fatal(err)
	}
	observation := PathObservation{SchemaVersion: 1, RemoteDeviceID: remote.ID, NetworkID: "default", ObservationRevision: 1, Lifecycle: "online", CurrentPath: strPtr("direct"), TransitionReason: "direct_committed", ObservedAt: time.Now().Unix()}
	if result, err := db.RecordPathObservations(reporter.ID, "default", reporter.RegistrationSeq, []PathObservation{observation}, false); err != nil || result.Accepted != 1 {
		t.Fatalf("initial observation: %+v %v", result, err)
	}
	if err := db.ReleaseDevicePresence(reporter.ID); err != nil {
		t.Fatal(err)
	}
	current, err := db.RegisterDeviceWithOptions(user.ID, "default", reporter.PublicKey, "Reporter", "linux", "", "", "", DeviceRegistrationAttempt{Incarnation: &two, EnforceIncarnation: true})
	if err != nil {
		t.Fatal(err)
	}
	page, err := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: reporter.ID}, 10, 0)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("historical observation: %+v %v", page, err)
	}
	if page.Items[0].Fresh || page.Items[0].Freshness != "stale" {
		t.Fatalf("old registration must remain historical: %+v", page.Items[0])
	}
	fresh, err := db.AdminConnections(AdminConnectionFilter{Freshness: "fresh"}, 10, 0)
	if err != nil || fresh.Total != 0 {
		t.Fatalf("fresh filter accepted an old registration: %+v %v", fresh, err)
	}
	health, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{})
	if err != nil || health.Summary.FreshDirect != 0 || health.Summary.StaleObservations != 1 || len(health.Alerts) != 1 || !hasHealthSignal(health.Alerts[0], "stale_observation") {
		t.Fatalf("health revived an old path: %+v %v", health, err)
	}
	if result, err := db.RecordPathObservations(reporter.ID, "default", current.RegistrationSeq, []PathObservation{observation}, true); err != nil || result.Accepted != 1 {
		t.Fatalf("current owner observation: %+v %v", result, err)
	}
	fresh, err = db.AdminConnections(AdminConnectionFilter{Freshness: "fresh"}, 10, 0)
	if err != nil || fresh.Total != 1 || !fresh.Items[0].Fresh {
		t.Fatalf("current observation did not restore freshness: %+v %v", fresh, err)
	}
}

func TestAdminConnectionSearchTreatsWildcardsLiterally(t *testing.T) {
	db, _, network, reporter, remote := setupTelemetryTestDB(t)
	if _, err := db.Exec(`UPDATE devices SET device_name='Literal %_! marker' WHERE id=?`, reporter); err != nil {
		t.Fatal(err)
	}
	obs := PathObservation{SchemaVersion: 1, RemoteDeviceID: remote, NetworkID: network, ObservationRevision: 1, Lifecycle: "online", CurrentPath: strPtr("direct")}
	if result, err := db.RecordPathObservations(reporter, network, 1, []PathObservation{obs}, false); err != nil || result.Accepted != 1 {
		t.Fatalf("seed observation: %+v %v", result, err)
	}
	for _, query := range []string{"%", "_", "!", "%_!", "literal"} {
		page, err := db.AdminConnections(AdminConnectionFilter{Query: query}, 10, 0)
		if err != nil || page.Total != 1 {
			t.Fatalf("literal matching %q: %+v %v", query, page, err)
		}
	}
	if _, err := db.Exec(`UPDATE devices SET device_name='Ordinary label' WHERE id=?`, reporter); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"%", "_", "!"} {
		page, err := db.AdminConnections(AdminConnectionFilter{Query: query}, 10, 0)
		if err != nil || page.Total != 0 {
			t.Fatalf("wildcard broadened %q: %+v %v", query, page, err)
		}
	}
}

func TestCanceledAdminPathQueriesDoNotWaitForDatabase(t *testing.T) {
	db, err := New(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	connection, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reads := map[string]func() error{
		"connections": func() error { _, err := db.AdminConnections(AdminConnectionFilter{Context: ctx}, 10, 0); return err },
		"transitions": func() error {
			_, err := db.AdminConnectionTransitions(AdminConnectionTransitionFilter{Context: ctx}, 10, "")
			return err
		},
		"trends": func() error {
			_, err := db.AdminConnectionTrends(AdminConnectionTrendsFilter{Context: ctx})
			return err
		},
	}
	for name, read := range reads {
		t.Run(name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() { done <- read() }()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("expected cancellation, got %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("canceled query waited for the occupied SQLite connection")
			}
		})
	}
}

func TestAdminSummaryIdentifiesPersonalGroupsWithoutLoadingDevices(t *testing.T) {
	db := adminResourceTestDB(t)
	if _, err := db.Exec(`INSERT INTO devices(id,user_id,network_id,public_key,device_name,virtual_ip,created_at) VALUES('personal-old','u1','default','personal-key-old','Personal','10.20.0.20',1)`); err != nil {
		t.Fatal(err)
	}
	graph := collectTopologyPages(t, db, "", topologyViewSummary, 1, func() {
		// Backdating the new row must not evade the captured rowid horizon.
		if _, err := db.Exec(`INSERT INTO devices(id,user_id,network_id,public_key,device_name,virtual_ip,created_at) VALUES('personal-new','u2','default','personal-key-new','New personal','10.20.0.21',1)`); err != nil {
			t.Fatal(err)
		}
	})
	marked := map[string]bool{}
	for _, node := range graph.Nodes {
		if node.Kind == "device" {
			t.Fatal("summary loaded device details")
		}
		if node.Kind == "account" {
			marked[node.AccountID] = node.HasPersonalDevices
		}
	}
	if !marked["u1"] || marked["u2"] {
		t.Fatalf("personal group existence escaped snapshot horizon: %+v", marked)
	}
}

func TestExpiredSignalsAreExcludedFromAdminCountsAndGraphs(t *testing.T) {
	db := adminResourceTestDB(t)
	if _, err := db.Exec(`UPDATE signals SET created_at=? WHERE id='s2'`, time.Now().Unix()-signalTTLSeconds-1); err != nil {
		t.Fatal(err)
	}
	overview, err := db.AdminOverviewSnapshot()
	if err != nil || overview.PendingSignals != 1 {
		t.Fatalf("expired signal counted as pending: %+v %v", overview, err)
	}
	legacy, err := db.AdminTopology("")
	if err != nil {
		t.Fatal(err)
	}
	page, err := db.AdminTopologyPage("", 12, 600)
	if err != nil {
		t.Fatal(err)
	}
	network, err := db.AdminTopologyNetwork(context.Background(), "room-1", 600)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := collectTopologyPages(t, db, "", topologyViewFull, 100, nil)
	for name, edges := range map[string][]AdminTopologyEdge{"legacy": legacy.Edges, "page": page.Edges, "network": network.Edges, "snapshot": snapshot.Edges} {
		for _, edge := range edges {
			if edge.Kind == "pending_signal" && edge.Source == "device:d2" && edge.Target == "device:d3" {
				t.Fatalf("%s retained expired signal: %+v", name, edge)
			}
		}
	}
}
