package database

import (
	"errors"
	"testing"
	"time"
)

func setHealthTestDevicesOnline(t *testing.T, db *DB, deviceIDs ...string) {
	t.Helper()
	now := time.Now().Unix()
	for _, deviceID := range deviceIDs {
		if _, err := db.Exec("UPDATE devices SET online = 1, last_seen = ? WHERE id = ?", now, deviceID); err != nil {
			t.Fatalf("mark %s online: %v", deviceID, err)
		}
	}
}

func recordHealthObservation(
	t *testing.T,
	db *DB,
	reportingDeviceID, remoteDeviceID, networkID string,
	revision uint64,
	currentPath, previousPath *string,
	reason string,
	validationRTT *uint64,
) {
	t.Helper()
	obs := PathObservation{
		SchemaVersion:         PathTelemetrySchemaVersion,
		RemoteDeviceID:        remoteDeviceID,
		NetworkID:             networkID,
		ObservationRevision:   revision,
		NetworkGeneration:     1,
		PeerSessionGeneration: 1,
		RemoteCandidateEpoch:  1,
		Lifecycle:             "online",
		CurrentPath:           currentPath,
		PreviousPath:          previousPath,
		TransitionReason:      reason,
		LastValidationRTTMS:   validationRTT,
		ObservedAt:            time.Now().Unix(),
	}
	summary, err := db.RecordPathObservations(reportingDeviceID, networkID, 1, []PathObservation{obs}, false)
	if err != nil {
		t.Fatalf("record health observation: %v", err)
	}
	if summary.Accepted != 1 {
		t.Fatalf("expected health observation accepted, got %+v", summary)
	}
}

func findHealthAlert(t *testing.T, alerts []AdminConnectionHealthAlert, reportingDeviceID string) AdminConnectionHealthAlert {
	t.Helper()
	for _, alert := range alerts {
		if alert.ReportingDeviceID == reportingDeviceID {
			return alert
		}
	}
	t.Fatalf("missing health alert for reporting device %s", reportingDeviceID)
	return AdminConnectionHealthAlert{}
}

func hasHealthSignal(alert AdminConnectionHealthAlert, signal string) bool {
	for _, candidate := range alert.Signals {
		if candidate == signal {
			return true
		}
	}
	return false
}

func TestAdminConnectionHealthEmptyAndValidation(t *testing.T) {
	db, _, _, _, _ := setupTelemetryTestDB(t)

	health, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{})
	if err != nil {
		t.Fatalf("AdminConnectionHealth empty: %v", err)
	}
	if health.SchemaVersion != AdminConnectionHealthSchemaVersion ||
		health.WindowSeconds != DefaultConnectionHealthWindowSeconds ||
		health.AlertsLimit != DefaultConnectionHealthAlertLimit ||
		health.HistoryLimitPerDirection != MaxTransitionsPerPair {
		t.Fatalf("unexpected health defaults: %+v", health)
	}
	if health.Summary.TotalObservations != 0 || health.AlertsTotal != 0 || len(health.Alerts) != 0 {
		t.Fatalf("empty telemetry must produce empty health response: %+v", health)
	}

	if _, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{WindowSeconds: MinConnectionHealthWindowSeconds - 1}); !errors.Is(err, ErrInvalidConnectionHealthWindow) {
		t.Fatalf("expected invalid window error, got %v", err)
	}
	if _, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{AlertLimit: MaxConnectionHealthAlertLimit + 1}); !errors.Is(err, ErrInvalidConnectionHealthLimit) {
		t.Fatalf("expected invalid alert limit error, got %v", err)
	}
}

func TestAdminConnectionHealthDerivesBoundedOperationalSignals(t *testing.T) {
	db, user1ID, net1ID, devAID, devBID := setupTelemetryTestDB(t)

	devC, err := db.CreateDevice(user1ID, net1ID, "pub-key-c", "Device C", "linux", "10.20.0.4")
	if err != nil {
		t.Fatal(err)
	}
	devD, err := db.CreateDevice(user1ID, net1ID, "pub-key-d", "Device D", "linux", "10.20.0.5")
	if err != nil {
		t.Fatal(err)
	}
	devE, err := db.CreateDevice(user1ID, net1ID, "pub-key-e", "Device E", "linux", "10.20.0.6")
	if err != nil {
		t.Fatal(err)
	}
	devF, err := db.CreateDevice(user1ID, net1ID, "pub-key-f", "Device F", "linux", "10.20.0.7")
	if err != nil {
		t.Fatal(err)
	}
	devG, err := db.CreateDevice(user1ID, net1ID, "pub-key-g", "Device G", "linux", "10.20.0.8")
	if err != nil {
		t.Fatal(err)
	}
	devH, err := db.CreateDevice(user1ID, net1ID, "pub-key-h", "Device H", "linux", "10.20.0.9")
	if err != nil {
		t.Fatal(err)
	}
	devK, err := db.CreateDevice(user1ID, net1ID, "pub-key-k", "Device K", "linux", "10.20.0.10")
	if err != nil {
		t.Fatal(err)
	}
	devL, err := db.CreateDevice(user1ID, net1ID, "pub-key-l", "Device L", "linux", "10.20.0.11")
	if err != nil {
		t.Fatal(err)
	}

	user2, err := db.CreateUser("health-relay@example.com", "hash2")
	if err != nil {
		t.Fatal(err)
	}
	net2, err := db.CreateNetwork(user2.ID, "Relay-only network", "10.30.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	devI, err := db.CreateDevice(user2.ID, net2.ID, "pub-key-i", "Device I", "linux", "10.30.0.2")
	if err != nil {
		t.Fatal(err)
	}
	devJ, err := db.CreateDevice(user2.ID, net2.ID, "pub-key-j", "Device J", "linux", "10.30.0.3")
	if err != nil {
		t.Fatal(err)
	}

	setHealthTestDevicesOnline(
		t,
		db,
		devAID, devBID,
		devC.ID, devD.ID,
		devE.ID, devF.ID,
		devG.ID, devH.ID,
		devK.ID, devL.ID,
		devI.ID, devJ.ID,
	)

	// A -> B flaps between Direct and Relay five times, with three explicit
	// Direct failure reasons. The final Relay path is not itself an alert;
	// only the recent transition/failure evidence is.
	paths := []string{"direct", "relay", "direct", "relay", "direct", "relay"}
	reasons := []string{
		"direct_committed",
		"direct_path_failed",
		"direct_committed",
		"direct_path_failed",
		"direct_committed",
		"direct_probe_failed",
	}
	for i, path := range paths {
		var previous *string
		if i > 0 {
			previous = strPtr(paths[i-1])
		}
		recordHealthObservation(
			t, db, devAID, devBID, net1ID,
			uint64(i+1), strPtr(path), previous, reasons[i], uint64Ptr(55),
		)
	}

	// C -> D is fresh but currently has no committed active path.
	recordHealthObservation(t, db, devC.ID, devD.ID, net1ID, 1, nil, nil, "peer_online", nil)

	// E -> F has a recent observation but its reporter lease has expired.
	recordHealthObservation(t, db, devE.ID, devF.ID, net1ID, 1, strPtr("direct"), nil, "direct_committed", nil)
	if _, err := db.Exec(
		"UPDATE devices SET last_seen = ? WHERE id = ?",
		time.Now().Unix()-DeviceOnlineTTL-5,
		devE.ID,
	); err != nil {
		t.Fatalf("expire reporter lease: %v", err)
	}

	// G -> H keeps a live reporter but its latest observation has expired.
	recordHealthObservation(t, db, devG.ID, devH.ID, net1ID, 1, strPtr("direct"), nil, "direct_committed", nil)
	if _, err := db.Exec(
		"UPDATE peer_path_observations SET received_at = ? WHERE reporting_device_id = ?",
		time.Now().Unix()-DeviceOnlineTTL-5,
		devG.ID,
	); err != nil {
		t.Fatalf("expire observation: %v", err)
	}

	// K -> L is a fresh observation whose peer lifecycle is explicitly offline.
	// No active path is expected here and must not become a no_active_path warning.
	offlineObs := PathObservation{
		SchemaVersion:         PathTelemetrySchemaVersion,
		RemoteDeviceID:        devL.ID,
		NetworkID:             net1ID,
		ObservationRevision:   1,
		NetworkGeneration:     1,
		PeerSessionGeneration: 1,
		RemoteCandidateEpoch:  1,
		Lifecycle:             "offline",
		CurrentPath:           nil,
		PreviousPath:          nil,
		TransitionReason:      "peer_left",
		ObservedAt:            time.Now().Unix(),
	}
	offlineSummary, err := db.RecordPathObservations(devK.ID, net1ID, 1, []PathObservation{offlineObs}, false)
	if err != nil || offlineSummary.Accepted != 1 {
		t.Fatalf("record expected-offline observation: summary=%+v err=%v", offlineSummary, err)
	}

	// I -> J is a healthy, static Relay observation in another network. Relay
	// usage is a factual path category and must not be treated as an alert.
	recordHealthObservation(t, db, devI.ID, devJ.ID, net2.ID, 1, strPtr("relay"), nil, "relay_peer_confirmed", uint64Ptr(40))

	health, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{WindowSeconds: 3600})
	if err != nil {
		t.Fatalf("AdminConnectionHealth: %v", err)
	}

	if health.Summary.TotalObservations != 6 ||
		health.Summary.FreshObservations != 4 ||
		health.Summary.StaleObservations != 1 ||
		health.Summary.ReporterOfflineObservations != 1 {
		t.Fatalf("unexpected observation summary: %+v", health.Summary)
	}
	if health.Summary.FreshDirect != 0 || health.Summary.FreshRelay != 2 || health.Summary.FreshOnlineNoPath != 1 {
		t.Fatalf("unexpected fresh path distribution: %+v", health.Summary)
	}
	if health.Summary.ValidationRTTSamples != 2 ||
		health.Summary.MaxValidationRTTMS == nil ||
		*health.Summary.MaxValidationRTTMS != 55 {
		t.Fatalf("unexpected validation RTT summary: %+v", health.Summary)
	}
	if health.Summary.RecentPathSwitches != 5 ||
		health.Summary.RecentDirectFailures != 3 ||
		health.Summary.RecentRelayFailures != 0 ||
		health.Summary.FrequentSwitchingConnections != 1 ||
		health.Summary.RepeatedFailureConnections != 1 {
		t.Fatalf("unexpected transition summary: %+v", health.Summary)
	}
	if health.AlertsTotal != 4 || len(health.Alerts) != 4 {
		t.Fatalf("expected four attention connections, got total=%d alerts=%+v", health.AlertsTotal, health.Alerts)
	}

	flapping := findHealthAlert(t, health.Alerts, devAID)
	if flapping.Severity != "warning" ||
		!hasHealthSignal(flapping, "frequent_path_switching") ||
		!hasHealthSignal(flapping, "repeated_path_failures") ||
		flapping.CurrentPath == nil ||
		*flapping.CurrentPath != "relay" {
		t.Fatalf("unexpected flapping alert: %+v", flapping)
	}

	noPath := findHealthAlert(t, health.Alerts, devC.ID)
	if noPath.Severity != "warning" || !hasHealthSignal(noPath, "no_active_path") || noPath.CurrentPath != nil || !noPath.Fresh {
		t.Fatalf("unexpected no-active-path alert: %+v", noPath)
	}

	reporterOffline := findHealthAlert(t, health.Alerts, devE.ID)
	if reporterOffline.Severity != "info" || reporterOffline.Freshness != "reporter_offline" || !hasHealthSignal(reporterOffline, "reporter_offline") {
		t.Fatalf("unexpected reporter-offline alert: %+v", reporterOffline)
	}

	stale := findHealthAlert(t, health.Alerts, devG.ID)
	if stale.Severity != "info" || stale.Freshness != "stale" || !hasHealthSignal(stale, "stale_observation") {
		t.Fatalf("unexpected stale alert: %+v", stale)
	}
	for _, alert := range health.Alerts {
		if alert.ReportingDeviceID == devK.ID {
			t.Fatalf("offline lifecycle with no path must not alert: %+v", alert)
		}
	}

	relayOnly, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{NetworkID: net2.ID})
	if err != nil {
		t.Fatalf("relay-only network health: %v", err)
	}
	if relayOnly.Summary.TotalObservations != 1 || relayOnly.Summary.FreshRelay != 1 || relayOnly.AlertsTotal != 0 || len(relayOnly.Alerts) != 0 {
		t.Fatalf("static relay path must not be classified as unhealthy: %+v", relayOnly)
	}

	limited, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{NetworkID: net1ID, AlertLimit: 2})
	if err != nil {
		t.Fatalf("limited health alerts: %v", err)
	}
	if limited.AlertsTotal != 4 || len(limited.Alerts) != 2 {
		t.Fatalf("expected exact total with bounded alert list, got total=%d len=%d", limited.AlertsTotal, len(limited.Alerts))
	}

	// Once A -> B transition history falls outside the requested window, its
	// current Relay snapshot remains factual but the flapping/failure signals
	// disappear. Other current observation alerts remain.
	if _, err := db.Exec(
		"UPDATE peer_path_transitions SET created_at = ? WHERE reporting_device_id = ? AND remote_device_id = ? AND network_id = ?",
		time.Now().Unix()-7200,
		devAID,
		devBID,
		net1ID,
	); err != nil {
		t.Fatalf("age path transition history: %v", err)
	}
	windowed, err := db.AdminConnectionHealth(AdminConnectionHealthFilter{NetworkID: net1ID, WindowSeconds: 3600})
	if err != nil {
		t.Fatalf("windowed connection health: %v", err)
	}
	if windowed.Summary.RecentPathSwitches != 0 ||
		windowed.Summary.RecentDirectFailures != 0 ||
		windowed.Summary.FrequentSwitchingConnections != 0 ||
		windowed.Summary.RepeatedFailureConnections != 0 {
		t.Fatalf("old transition history must not affect current window: %+v", windowed.Summary)
	}
	if windowed.AlertsTotal != 3 {
		t.Fatalf("expected no-path/offline/stale alerts only after transition window expiry, got %d", windowed.AlertsTotal)
	}
}
