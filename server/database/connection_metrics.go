package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	ConnectionMetricsSchemaVersion       = 1
	ConnectionMetricsBucketSeconds int64 = 3600
	ConnectionMetricsRetentionHours      = 24 * 30
	DefaultConnectionTrendsWindowHours   = 24
	MaxConnectionTrendsWindowHours       = ConnectionMetricsRetentionHours
)

var ErrInvalidConnectionTrendsWindow = errors.New("connection trends window_hours out of range")

var connectionMetricsRTTBoundsMS = [...]uint64{50, 100, 250, 500, 1000, 3000, 10000}

type connectionMetricDelta struct {
	AcceptedObservationSamples int64
	DirectObservationSamples   int64
	RelayObservationSamples    int64
	NoPathObservationSamples   int64
	PathSwitches               int64
	DirectFailures             int64
	RelayFailures              int64
	ValidationRTTSamples       int64
	ValidationRTTSumMS         int64
	ValidationRTTMaxMS         int64
	RTTLE50                    int64
	RTTLE100                   int64
	RTTLE250                   int64
	RTTLE500                   int64
	RTTLE1000                  int64
	RTTLE3000                  int64
	RTTLE10000                 int64
	RTTGT10000                 int64
}

type AdminValidationRTTHistogram struct {
	LE50    int64 `json:"le_50_ms"`
	LE100   int64 `json:"le_100_ms"`
	LE250   int64 `json:"le_250_ms"`
	LE500   int64 `json:"le_500_ms"`
	LE1000  int64 `json:"le_1000_ms"`
	LE3000  int64 `json:"le_3000_ms"`
	LE10000 int64 `json:"le_10000_ms"`
	GT10000 int64 `json:"gt_10000_ms"`
}

type AdminConnectionTrendBucket struct {
	BucketStart                  int64                       `json:"bucket_start"`
	AcceptedObservationSamples   int64                       `json:"accepted_observation_samples"`
	DirectObservationSamples     int64                       `json:"direct_observation_samples"`
	RelayObservationSamples      int64                       `json:"relay_observation_samples"`
	NoPathObservationSamples     int64                       `json:"no_path_observation_samples"`
	PathSwitches                 int64                       `json:"path_switches"`
	DirectFailures               int64                       `json:"direct_failures"`
	RelayFailures                int64                       `json:"relay_failures"`
	ValidationRTTSamples         int64                       `json:"validation_rtt_samples"`
	AverageValidationRTTMS       *uint64                     `json:"average_validation_rtt_ms,omitempty"`
	MaxValidationRTTMS           *uint64                     `json:"max_validation_rtt_ms,omitempty"`
	ValidationRTTP50UpperBoundMS *uint64                     `json:"validation_rtt_p50_upper_bound_ms,omitempty"`
	ValidationRTTP95UpperBoundMS *uint64                     `json:"validation_rtt_p95_upper_bound_ms,omitempty"`
	ValidationRTTHistogram       AdminValidationRTTHistogram `json:"validation_rtt_histogram"`
}

type AdminConnectionTrendsFilter struct {
	NetworkID   string
	WindowHours int
}

type AdminConnectionTrends struct {
	SchemaVersion       int                          `json:"schema_version"`
	GeneratedAt         int64                        `json:"generated_at"`
	BucketSeconds       int64                        `json:"bucket_seconds"`
	WindowHours         int                          `json:"window_hours"`
	RetentionHours      int                          `json:"retention_hours"`
	NetworkID           string                       `json:"network_id,omitempty"`
	NetworkName         string                       `json:"network_name,omitempty"`
	SampleSemantics     string                       `json:"sample_semantics"`
	PercentileSemantics string                       `json:"percentile_semantics"`
	RTTBucketBoundsMS   []uint64                     `json:"rtt_bucket_bounds_ms"`
	Buckets             []AdminConnectionTrendBucket `json:"buckets"`
}

func migrateConnectionMetrics(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS connection_metric_hourly (
		bucket_start                  INTEGER NOT NULL,
		network_id                    TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
		accepted_observation_samples  INTEGER NOT NULL DEFAULT 0,
		direct_observation_samples    INTEGER NOT NULL DEFAULT 0,
		relay_observation_samples     INTEGER NOT NULL DEFAULT 0,
		no_path_observation_samples   INTEGER NOT NULL DEFAULT 0,
		path_switches                 INTEGER NOT NULL DEFAULT 0,
		direct_failures               INTEGER NOT NULL DEFAULT 0,
		relay_failures                INTEGER NOT NULL DEFAULT 0,
		validation_rtt_samples        INTEGER NOT NULL DEFAULT 0,
		validation_rtt_sum_ms         INTEGER NOT NULL DEFAULT 0,
		validation_rtt_max_ms         INTEGER NOT NULL DEFAULT 0,
		rtt_le_50                     INTEGER NOT NULL DEFAULT 0,
		rtt_le_100                    INTEGER NOT NULL DEFAULT 0,
		rtt_le_250                    INTEGER NOT NULL DEFAULT 0,
		rtt_le_500                    INTEGER NOT NULL DEFAULT 0,
		rtt_le_1000                   INTEGER NOT NULL DEFAULT 0,
		rtt_le_3000                   INTEGER NOT NULL DEFAULT 0,
		rtt_le_10000                  INTEGER NOT NULL DEFAULT 0,
		rtt_gt_10000                  INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (bucket_start, network_id)
	);
	CREATE INDEX IF NOT EXISTS idx_connection_metric_hourly_network_bucket
		ON connection_metric_hourly(network_id, bucket_start);
	`
	_, err := db.Exec(schema)
	return err
}

func connectionMetricBucketStart(unixSeconds int64) int64 {
	if unixSeconds < 0 {
		return 0
	}
	return unixSeconds - unixSeconds%ConnectionMetricsBucketSeconds
}

func connectionMetricsRetentionCutoff(unixSeconds int64) int64 {
	current := connectionMetricBucketStart(unixSeconds)
	return current - int64(ConnectionMetricsRetentionHours-1)*ConnectionMetricsBucketSeconds
}

func connectionMetricDeltaForObservation(
	currentPath *string,
	pathSwitched bool,
	recordTransition bool,
	reason string,
	validationRTT *uint64,
	isResync bool,
) connectionMetricDelta {
	var delta connectionMetricDelta
	if isResync {
		return delta
	}

	delta.AcceptedObservationSamples = 1
	switch {
	case currentPath == nil:
		delta.NoPathObservationSamples = 1
	case *currentPath == "direct":
		delta.DirectObservationSamples = 1
	case *currentPath == "relay":
		delta.RelayObservationSamples = 1
	}

	if pathSwitched {
		delta.PathSwitches = 1
	}
	if recordTransition {
		switch reason {
		case "direct_probe_failed", "direct_path_failed":
			delta.DirectFailures = 1
		case "relay_path_failed":
			delta.RelayFailures = 1
		}
	}

	if validationRTT == nil {
		return delta
	}
	rtt := *validationRTT
	delta.ValidationRTTSamples = 1
	const maxSQLiteInt64 = uint64(^uint64(0) >> 1)
	if rtt > maxSQLiteInt64 {
		delta.ValidationRTTSumMS = int64(maxSQLiteInt64)
		delta.ValidationRTTMaxMS = int64(maxSQLiteInt64)
	} else {
		delta.ValidationRTTSumMS = int64(rtt)
		delta.ValidationRTTMaxMS = int64(rtt)
	}
	if rtt <= 50 {
		delta.RTTLE50 = 1
	}
	if rtt <= 100 {
		delta.RTTLE100 = 1
	}
	if rtt <= 250 {
		delta.RTTLE250 = 1
	}
	if rtt <= 500 {
		delta.RTTLE500 = 1
	}
	if rtt <= 1000 {
		delta.RTTLE1000 = 1
	}
	if rtt <= 3000 {
		delta.RTTLE3000 = 1
	}
	if rtt <= 10000 {
		delta.RTTLE10000 = 1
	} else {
		delta.RTTGT10000 = 1
	}
	return delta
}

func (d connectionMetricDelta) empty() bool {
	return d.AcceptedObservationSamples == 0 &&
		d.PathSwitches == 0 &&
		d.DirectFailures == 0 &&
		d.RelayFailures == 0 &&
		d.ValidationRTTSamples == 0
}

func upsertConnectionMetricHourly(tx *sql.Tx, networkID string, unixSeconds int64, delta connectionMetricDelta) error {
	if delta.empty() {
		return nil
	}
	_, err := tx.Exec(`
		INSERT INTO connection_metric_hourly (
			bucket_start, network_id,
			accepted_observation_samples,
			direct_observation_samples,
			relay_observation_samples,
			no_path_observation_samples,
			path_switches,
			direct_failures,
			relay_failures,
			validation_rtt_samples,
			validation_rtt_sum_ms,
			validation_rtt_max_ms,
			rtt_le_50,
			rtt_le_100,
			rtt_le_250,
			rtt_le_500,
			rtt_le_1000,
			rtt_le_3000,
			rtt_le_10000,
			rtt_gt_10000
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(bucket_start, network_id) DO UPDATE SET
			accepted_observation_samples = accepted_observation_samples + excluded.accepted_observation_samples,
			direct_observation_samples = direct_observation_samples + excluded.direct_observation_samples,
			relay_observation_samples = relay_observation_samples + excluded.relay_observation_samples,
			no_path_observation_samples = no_path_observation_samples + excluded.no_path_observation_samples,
			path_switches = path_switches + excluded.path_switches,
			direct_failures = direct_failures + excluded.direct_failures,
			relay_failures = relay_failures + excluded.relay_failures,
			validation_rtt_samples = validation_rtt_samples + excluded.validation_rtt_samples,
			validation_rtt_sum_ms = validation_rtt_sum_ms + excluded.validation_rtt_sum_ms,
			validation_rtt_max_ms = MAX(validation_rtt_max_ms, excluded.validation_rtt_max_ms),
			rtt_le_50 = rtt_le_50 + excluded.rtt_le_50,
			rtt_le_100 = rtt_le_100 + excluded.rtt_le_100,
			rtt_le_250 = rtt_le_250 + excluded.rtt_le_250,
			rtt_le_500 = rtt_le_500 + excluded.rtt_le_500,
			rtt_le_1000 = rtt_le_1000 + excluded.rtt_le_1000,
			rtt_le_3000 = rtt_le_3000 + excluded.rtt_le_3000,
			rtt_le_10000 = rtt_le_10000 + excluded.rtt_le_10000,
			rtt_gt_10000 = rtt_gt_10000 + excluded.rtt_gt_10000
	`,
		connectionMetricBucketStart(unixSeconds), networkID,
		delta.AcceptedObservationSamples,
		delta.DirectObservationSamples,
		delta.RelayObservationSamples,
		delta.NoPathObservationSamples,
		delta.PathSwitches,
		delta.DirectFailures,
		delta.RelayFailures,
		delta.ValidationRTTSamples,
		delta.ValidationRTTSumMS,
		delta.ValidationRTTMaxMS,
		delta.RTTLE50,
		delta.RTTLE100,
		delta.RTTLE250,
		delta.RTTLE500,
		delta.RTTLE1000,
		delta.RTTLE3000,
		delta.RTTLE10000,
		delta.RTTGT10000,
	)
	if err != nil {
		return fmt.Errorf("upsert connection metric hourly: %w", err)
	}
	return nil
}

func pruneConnectionMetrics(tx *sql.Tx, unixSeconds int64) error {
	if _, err := tx.Exec(
		`DELETE FROM connection_metric_hourly WHERE bucket_start < ?`,
		connectionMetricsRetentionCutoff(unixSeconds),
	); err != nil {
		return fmt.Errorf("prune connection metrics: %w", err)
	}
	return nil
}

func normalizeConnectionTrendsFilter(filter AdminConnectionTrendsFilter) (AdminConnectionTrendsFilter, error) {
	if filter.WindowHours == 0 {
		filter.WindowHours = DefaultConnectionTrendsWindowHours
	}
	if filter.WindowHours < 1 || filter.WindowHours > MaxConnectionTrendsWindowHours {
		return filter, ErrInvalidConnectionTrendsWindow
	}
	filter.NetworkID = strings.TrimSpace(filter.NetworkID)
	return filter, nil
}

func percentileUpperBound(hist AdminValidationRTTHistogram, total int64, numerator, denominator int64) *uint64 {
	if total <= 0 || denominator <= 0 || numerator <= 0 {
		return nil
	}
	target := (total*numerator + denominator - 1) / denominator
	cumulative := []int64{
		hist.LE50,
		hist.LE100,
		hist.LE250,
		hist.LE500,
		hist.LE1000,
		hist.LE3000,
		hist.LE10000,
	}
	for index, count := range cumulative {
		if count >= target {
			value := connectionMetricsRTTBoundsMS[index]
			return &value
		}
	}
	return nil
}

func finalizeTrendBucket(bucket *AdminConnectionTrendBucket, rttSum, rttMax int64) {
	if bucket.ValidationRTTSamples <= 0 {
		return
	}
	average := uint64(rttSum / bucket.ValidationRTTSamples)
	maximum := uint64(rttMax)
	bucket.AverageValidationRTTMS = &average
	bucket.MaxValidationRTTMS = &maximum
	bucket.ValidationRTTP50UpperBoundMS = percentileUpperBound(
		bucket.ValidationRTTHistogram,
		bucket.ValidationRTTSamples,
		50,
		100,
	)
	bucket.ValidationRTTP95UpperBoundMS = percentileUpperBound(
		bucket.ValidationRTTHistogram,
		bucket.ValidationRTTSamples,
		95,
		100,
	)
}

// AdminConnectionTrends returns fixed one-hour rollups. Missing hours are
// returned as zero buckets so charting callers never need to infer gaps.
func (db *DB) AdminConnectionTrends(filter AdminConnectionTrendsFilter) (*AdminConnectionTrends, error) {
	filter, err := normalizeConnectionTrendsFilter(filter)
	if err != nil {
		return nil, err
	}

	generatedAt := time.Now().Unix()
	currentBucket := connectionMetricBucketStart(generatedAt)
	startBucket := currentBucket - int64(filter.WindowHours-1)*ConnectionMetricsBucketSeconds

	var (
		networkName string
		conditions  = []string{"bucket_start >= ?", "bucket_start <= ?"}
		args        = []interface{}{startBucket, currentBucket}
	)
	if filter.NetworkID != "" {
		conditions = append(conditions, "network_id = ?")
		args = append(args, filter.NetworkID)
		_ = db.QueryRow(`SELECT name FROM networks WHERE id = ?`, filter.NetworkID).Scan(&networkName)
	}

	query := `
		SELECT
			bucket_start,
			SUM(accepted_observation_samples),
			SUM(direct_observation_samples),
			SUM(relay_observation_samples),
			SUM(no_path_observation_samples),
			SUM(path_switches),
			SUM(direct_failures),
			SUM(relay_failures),
			SUM(validation_rtt_samples),
			SUM(validation_rtt_sum_ms),
			MAX(validation_rtt_max_ms),
			SUM(rtt_le_50),
			SUM(rtt_le_100),
			SUM(rtt_le_250),
			SUM(rtt_le_500),
			SUM(rtt_le_1000),
			SUM(rtt_le_3000),
			SUM(rtt_le_10000),
			SUM(rtt_gt_10000)
		FROM connection_metric_hourly
		WHERE ` + strings.Join(conditions, " AND ") + `
		GROUP BY bucket_start
		ORDER BY bucket_start ASC
	`
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query connection trends: %w", err)
	}
	defer rows.Close()

	observed := make(map[int64]AdminConnectionTrendBucket, filter.WindowHours)
	for rows.Next() {
		var (
			bucket         AdminConnectionTrendBucket
			rttSum, rttMax int64
		)
		if err := rows.Scan(
			&bucket.BucketStart,
			&bucket.AcceptedObservationSamples,
			&bucket.DirectObservationSamples,
			&bucket.RelayObservationSamples,
			&bucket.NoPathObservationSamples,
			&bucket.PathSwitches,
			&bucket.DirectFailures,
			&bucket.RelayFailures,
			&bucket.ValidationRTTSamples,
			&rttSum,
			&rttMax,
			&bucket.ValidationRTTHistogram.LE50,
			&bucket.ValidationRTTHistogram.LE100,
			&bucket.ValidationRTTHistogram.LE250,
			&bucket.ValidationRTTHistogram.LE500,
			&bucket.ValidationRTTHistogram.LE1000,
			&bucket.ValidationRTTHistogram.LE3000,
			&bucket.ValidationRTTHistogram.LE10000,
			&bucket.ValidationRTTHistogram.GT10000,
		); err != nil {
			return nil, fmt.Errorf("scan connection trend bucket: %w", err)
		}
		finalizeTrendBucket(&bucket, rttSum, rttMax)
		observed[bucket.BucketStart] = bucket
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connection trends: %w", err)
	}

	buckets := make([]AdminConnectionTrendBucket, 0, filter.WindowHours)
	for bucketStart := startBucket; bucketStart <= currentBucket; bucketStart += ConnectionMetricsBucketSeconds {
		if bucket, ok := observed[bucketStart]; ok {
			buckets = append(buckets, bucket)
		} else {
			buckets = append(buckets, AdminConnectionTrendBucket{BucketStart: bucketStart})
		}
	}

	bounds := make([]uint64, len(connectionMetricsRTTBoundsMS))
	copy(bounds, connectionMetricsRTTBoundsMS[:])
	return &AdminConnectionTrends{
		SchemaVersion:       ConnectionMetricsSchemaVersion,
		GeneratedAt:         generatedAt,
		BucketSeconds:       ConnectionMetricsBucketSeconds,
		WindowHours:         filter.WindowHours,
		RetentionHours:      ConnectionMetricsRetentionHours,
		NetworkID:           filter.NetworkID,
		NetworkName:         networkName,
		SampleSemantics:     "accepted_non_resync_committed_observation_samples",
		PercentileSemantics: "fixed_histogram_upper_bound",
		RTTBucketBoundsMS:   bounds,
		Buckets:             buckets,
	}, nil
}
