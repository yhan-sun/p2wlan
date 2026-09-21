package database

import (
	"errors"
	"testing"
	"time"
)

func TestConnectionMetricsRollupFollowsAcceptedTelemetry(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)

	first := PathObservation{
		SchemaVersion:         PathTelemetrySchemaVersion,
		RemoteDeviceID:        devBID,
		NetworkID:             netID,
		ObservationRevision:   1,
		NetworkGeneration:     1,
		PeerSessionGeneration: 1,
		RemoteCandidateEpoch:  1,
		Lifecycle:             "online",
		CurrentPath:           strPtr("direct"),
		TransitionReason:      "direct_committed",
		SelectedMTU:           uint32Ptr(1400),
		LastDirectLatencyMS:   uint64Ptr(40),
		ObservedAt:            time.Now().Unix(),
	}
	firstSummary, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{first}, false)
	if err != nil || firstSummary.Accepted != 1 {
		t.Fatalf("first telemetry: summary=%+v err=%v", firstSummary, err)
	}

	duplicate, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{first}, false)
	if err != nil || duplicate.Duplicate != 1 {
		t.Fatalf("duplicate telemetry: summary=%+v err=%v", duplicate, err)
	}

	older := first
	older.ObservationRevision = 0
	older.CurrentPath = strPtr("relay")
	rejected, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{older}, false)
	if err != nil || rejected.Rejected != 1 {
		t.Fatalf("older telemetry: summary=%+v err=%v", rejected, err)
	}

	second := PathObservation{
		SchemaVersion:         PathTelemetrySchemaVersion,
		RemoteDeviceID:        devBID,
		NetworkID:             netID,
		ObservationRevision:   2,
		NetworkGeneration:     1,
		PeerSessionGeneration: 1,
		RemoteCandidateEpoch:  1,
		Lifecycle:             "online",
		CurrentPath:           strPtr("relay"),
		PreviousPath:          strPtr("direct"),
		TransitionReason:      "direct_path_failed",
		SelectedMTU:           uint32Ptr(1300),
		LastRelayLatencyMS:    uint64Ptr(120),
		ObservedAt:            time.Now().Unix(),
	}
	secondSummary, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{second}, false)
	if err != nil || secondSummary.Accepted != 1 {
		t.Fatalf("second telemetry: summary=%+v err=%v", secondSummary, err)
	}

	// A new registration owner may replay the same latest snapshot after
	// takeover. Current Rust wire does not mark mark_all_dirty() payloads with
	// is_resync, so owner advancement itself fences the long-term trend sample.
	resyncSummary, err := db.RecordPathObservations(devAID, netID, 2, []PathObservation{second}, false)
	if err != nil || resyncSummary.Accepted != 1 {
		t.Fatalf("owner-advance resync telemetry: summary=%+v err=%v", resyncSummary, err)
	}

	// An explicit resync marker remains excluded too.
	explicitResync := second
	explicitResync.ObservationRevision = 3
	explicitSummary, err := db.RecordPathObservations(devAID, netID, 2, []PathObservation{explicitResync}, true)
	if err != nil || explicitSummary.Accepted != 1 {
		t.Fatalf("explicit resync telemetry: summary=%+v err=%v", explicitSummary, err)
	}

	trends, err := db.AdminConnectionTrends(AdminConnectionTrendsFilter{NetworkID: netID, WindowHours: 1})
	if err != nil {
		t.Fatalf("AdminConnectionTrends: %v", err)
	}
	if len(trends.Buckets) != 1 {
		t.Fatalf("expected one hourly bucket, got %d", len(trends.Buckets))
	}
	bucket := trends.Buckets[0]
	if bucket.AcceptedObservationSamples != 2 ||
		bucket.DirectObservationSamples != 1 ||
		bucket.RelayObservationSamples != 1 ||
		bucket.NoPathObservationSamples != 0 {
		t.Fatalf("unexpected observation samples: %+v", bucket)
	}
	if bucket.PathSwitches != 1 || bucket.DirectFailures != 1 || bucket.RelayFailures != 0 {
		t.Fatalf("unexpected transition metrics: %+v", bucket)
	}
	if bucket.ValidationRTTSamples != 2 ||
		bucket.AverageValidationRTTMS == nil || *bucket.AverageValidationRTTMS != 80 ||
		bucket.MaxValidationRTTMS == nil || *bucket.MaxValidationRTTMS != 120 {
		t.Fatalf("unexpected RTT metrics: %+v", bucket)
	}
	if bucket.ValidationRTTHistogram.LE50 != 1 ||
		bucket.ValidationRTTHistogram.LE100 != 1 ||
		bucket.ValidationRTTHistogram.LE250 != 2 {
		t.Fatalf("unexpected RTT histogram: %+v", bucket.ValidationRTTHistogram)
	}
	if bucket.ValidationRTTP50UpperBoundMS == nil || *bucket.ValidationRTTP50UpperBoundMS != 50 {
		t.Fatalf("unexpected p50 upper bound: %+v", bucket.ValidationRTTP50UpperBoundMS)
	}
	if bucket.ValidationRTTP95UpperBoundMS == nil || *bucket.ValidationRTTP95UpperBoundMS != 250 {
		t.Fatalf("unexpected p95 upper bound: %+v", bucket.ValidationRTTP95UpperBoundMS)
	}

	page, err := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("AdminConnections: page=%+v err=%v", page, err)
	}
	if page.Items[0].SelectedPathMTU == nil || *page.Items[0].SelectedPathMTU != 1300 {
		t.Fatalf("selected_mtu wire alias was not persisted: %+v", page.Items[0].SelectedPathMTU)
	}
	if page.Items[0].LastValidationRTTMS == nil || *page.Items[0].LastValidationRTTMS != 120 {
		t.Fatalf("relay latency wire alias was not normalized: %+v", page.Items[0].LastValidationRTTMS)
	}
}

func TestConnectionMetricsRetentionGapFillingAndNetworkScope(t *testing.T) {
	db, _, net1ID, _, _ := setupTelemetryTestDB(t)
	user2, err := db.CreateUser("trends-user2@example.com", "hash2")
	if err != nil {
		t.Fatal(err)
	}
	net2, err := db.CreateNetwork(user2.ID, "Net 2", "10.30.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	current := connectionMetricBucketStart(now)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}

	net1Current := connectionMetricDelta{
		AcceptedObservationSamples: 2,
		DirectObservationSamples:   2,
		ValidationRTTSamples:       2,
		ValidationRTTSumMS:         120,
		ValidationRTTMaxMS:         70,
		RTTLE50:                    1,
		RTTLE100:                   2,
		RTTLE250:                   2,
		RTTLE500:                   2,
		RTTLE1000:                  2,
		RTTLE3000:                  2,
		RTTLE10000:                 2,
	}
	if err := upsertConnectionMetricHourly(tx, net1ID, current, net1Current); err != nil {
		t.Fatal(err)
	}
	net2Current := connectionMetricDelta{
		AcceptedObservationSamples: 3,
		RelayObservationSamples:    3,
		PathSwitches:               1,
	}
	if err := upsertConnectionMetricHourly(tx, net2.ID, current, net2Current); err != nil {
		t.Fatal(err)
	}
	if err := upsertConnectionMetricHourly(tx, net1ID, current-2*ConnectionMetricsBucketSeconds, connectionMetricDelta{
		AcceptedObservationSamples: 1,
		NoPathObservationSamples:   1,
	}); err != nil {
		t.Fatal(err)
	}
	oldBucket := current - int64(ConnectionMetricsRetentionHours)*ConnectionMetricsBucketSeconds
	if err := upsertConnectionMetricHourly(tx, net1ID, oldBucket, connectionMetricDelta{
		AcceptedObservationSamples: 99,
		DirectObservationSamples:   99,
	}); err != nil {
		t.Fatal(err)
	}
	if err := pruneConnectionMetrics(tx, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var oldRows int
	if err := db.QueryRow("SELECT COUNT(*) FROM connection_metric_hourly WHERE bucket_start = ?", oldBucket).Scan(&oldRows); err != nil {
		t.Fatal(err)
	}
	if oldRows != 0 {
		t.Fatalf("expected expired rollup to be pruned, got %d rows", oldRows)
	}

	global, err := db.AdminConnectionTrends(AdminConnectionTrendsFilter{WindowHours: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(global.Buckets) != 3 {
		t.Fatalf("expected three fixed hourly buckets, got %d", len(global.Buckets))
	}
	if global.Buckets[0].NoPathObservationSamples != 1 {
		t.Fatalf("expected oldest in-window bucket to contain no-path sample: %+v", global.Buckets[0])
	}
	if global.Buckets[1].AcceptedObservationSamples != 0 {
		t.Fatalf("missing hour must be returned as zero bucket: %+v", global.Buckets[1])
	}
	last := global.Buckets[2]
	if last.AcceptedObservationSamples != 5 ||
		last.DirectObservationSamples != 2 ||
		last.RelayObservationSamples != 3 ||
		last.PathSwitches != 1 {
		t.Fatalf("unexpected global current bucket: %+v", last)
	}

	net1, err := db.AdminConnectionTrends(AdminConnectionTrendsFilter{NetworkID: net1ID, WindowHours: 3})
	if err != nil {
		t.Fatal(err)
	}
	if net1.NetworkName != "Net 1" || net1.NetworkID != net1ID {
		t.Fatalf("unexpected network scope metadata: %+v", net1)
	}
	net1Last := net1.Buckets[2]
	if net1Last.AcceptedObservationSamples != 2 ||
		net1Last.DirectObservationSamples != 2 ||
		net1Last.RelayObservationSamples != 0 ||
		net1Last.AverageValidationRTTMS == nil ||
		*net1Last.AverageValidationRTTMS != 60 {
		t.Fatalf("unexpected network-scoped current bucket: %+v", net1Last)
	}

	if _, err := db.AdminConnectionTrends(AdminConnectionTrendsFilter{WindowHours: MaxConnectionTrendsWindowHours + 1}); !errors.Is(err, ErrInvalidConnectionTrendsWindow) {
		t.Fatalf("expected invalid trends window, got %v", err)
	}

	if err := migrateConnectionMetrics(db.DB); err != nil {
		t.Fatalf("connection metrics migration must be idempotent: %v", err)
	}
}

func TestConnectionMetricsPercentileOverflowDoesNotFabricateBound(t *testing.T) {
	hist := AdminValidationRTTHistogram{
		LE50:    0,
		LE100:   0,
		LE250:   0,
		LE500:   0,
		LE1000:  0,
		LE3000:  0,
		LE10000: 1,
		GT10000: 9,
	}
	if got := percentileUpperBound(hist, 10, 50, 100); got != nil {
		t.Fatalf("p50 lands in overflow bucket and must not fabricate bound, got %d", *got)
	}
	if got := percentileUpperBound(hist, 10, 10, 100); got == nil || *got != 10000 {
		t.Fatalf("p10 should be bounded by 10s, got %+v", got)
	}
}


func TestConnectionMetricsDropsAbsurdValidationRTT(t *testing.T) {
	db, _, netID, devAID, devBID := setupTelemetryTestDB(t)
	absurd := uint64(MaxPathTelemetryValidationRTTMS + 1)
	obs := PathObservation{
		SchemaVersion:         PathTelemetrySchemaVersion,
		RemoteDeviceID:        devBID,
		NetworkID:             netID,
		ObservationRevision:   1,
		NetworkGeneration:     1,
		PeerSessionGeneration: 1,
		RemoteCandidateEpoch:  1,
		Lifecycle:             "online",
		CurrentPath:           strPtr("direct"),
		TransitionReason:      "direct_committed",
		LastDirectLatencyMS:   &absurd,
		ObservedAt:            time.Now().Unix(),
	}
	summary, err := db.RecordPathObservations(devAID, netID, 1, []PathObservation{obs}, false)
	if err != nil || summary.Accepted != 1 {
		t.Fatalf("telemetry with absurd RTT should keep path state but drop RTT sample: summary=%+v err=%v", summary, err)
	}

	page, err := db.AdminConnections(AdminConnectionFilter{ReportingDeviceID: devAID}, 10, 0)
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("AdminConnections: page=%+v err=%v", page, err)
	}
	if page.Items[0].LastValidationRTTMS != nil {
		t.Fatalf("absurd RTT must not reach authoritative snapshot: %v", *page.Items[0].LastValidationRTTMS)
	}

	trends, err := db.AdminConnectionTrends(AdminConnectionTrendsFilter{NetworkID: netID, WindowHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	bucket := trends.Buckets[0]
	if bucket.AcceptedObservationSamples != 1 || bucket.DirectObservationSamples != 1 {
		t.Fatalf("path sample should still be counted: %+v", bucket)
	}
	if bucket.ValidationRTTSamples != 0 || bucket.AverageValidationRTTMS != nil || bucket.MaxValidationRTTMS != nil {
		t.Fatalf("absurd RTT must not enter rollup: %+v", bucket)
	}
}
