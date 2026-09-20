package database

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	AdminConnectionHealthSchemaVersion          = 1
	DefaultConnectionHealthWindowSeconds        = 3600
	MinConnectionHealthWindowSeconds            = 60
	MaxConnectionHealthWindowSeconds            = 86400
	DefaultConnectionHealthAlertLimit           = 50
	MaxConnectionHealthAlertLimit               = 100
	ConnectionHealthFrequentSwitchThreshold     = 4
	ConnectionHealthRepeatedFailureThreshold    = 3
)

var (
	ErrInvalidConnectionHealthWindow = errors.New("connection health window_seconds out of range")
	ErrInvalidConnectionHealthLimit  = errors.New("connection health limit out of range")
)

type AdminConnectionHealthFilter struct {
	NetworkID     string
	AccountID     string
	DeviceID      string
	WindowSeconds int
	AlertLimit    int
}

type AdminConnectionHealthThresholds struct {
	FrequentPathSwitches int `json:"frequent_path_switches"`
	RepeatedPathFailures int `json:"repeated_path_failures"`
}

type AdminConnectionHealthSummary struct {
	TotalObservations             int     `json:"total_observations"`
	FreshObservations             int     `json:"fresh_observations"`
	StaleObservations             int     `json:"stale_observations"`
	ReporterOfflineObservations   int     `json:"reporter_offline_observations"`
	FreshDirect                   int     `json:"fresh_direct"`
	FreshRelay                    int     `json:"fresh_relay"`
	FreshNoPath                   int     `json:"fresh_no_path"`
	ValidationRTTSamples          int     `json:"validation_rtt_samples"`
	AverageValidationRTTMS        *uint64 `json:"average_validation_rtt_ms,omitempty"`
	MaxValidationRTTMS            *uint64 `json:"max_validation_rtt_ms,omitempty"`
	RecentPathSwitches            int     `json:"recent_path_switches"`
	RecentDirectFailures          int     `json:"recent_direct_failures"`
	RecentRelayFailures           int     `json:"recent_relay_failures"`
	FrequentSwitchingConnections  int     `json:"frequent_switching_connections"`
	RepeatedFailureConnections    int     `json:"repeated_failure_connections"`
}

type AdminConnectionHealthAlert struct {
	Severity              string   `json:"severity"`
	Signals               []string `json:"signals"`
	ReportingDeviceID     string   `json:"reporting_device_id"`
	ReportingDeviceName   string   `json:"reporting_device_name"`
	ReportingUserID       string   `json:"reporting_user_id"`
	ReportingUsername     string   `json:"reporting_username"`
	RemoteDeviceID        string   `json:"remote_device_id"`
	RemoteDeviceName      string   `json:"remote_device_name"`
	RemoteUserID          string   `json:"remote_user_id"`
	RemoteUsername        string   `json:"remote_username"`
	NetworkID             string   `json:"network_id"`
	NetworkName           string   `json:"network_name"`
	CurrentPath           *string  `json:"current_path"`
	Fresh                 bool     `json:"fresh"`
	Freshness             string   `json:"freshness"`
	ReceivedAt            int64    `json:"received_at"`
	LastValidationRTTMS   *uint64  `json:"last_validation_rtt_ms,omitempty"`
	RecentPathSwitches    int      `json:"recent_path_switches"`
	RecentDirectFailures  int      `json:"recent_direct_failures"`
	RecentRelayFailures   int      `json:"recent_relay_failures"`
	LastTransitionAt      int64    `json:"last_transition_at,omitempty"`
}

type AdminConnectionHealth struct {
	SchemaVersion             int                             `json:"schema_version"`
	GeneratedAt               int64                           `json:"generated_at"`
	WindowSeconds             int                             `json:"window_seconds"`
	HistoryLimitPerDirection  int                             `json:"history_limit_per_direction"`
	Thresholds                AdminConnectionHealthThresholds `json:"thresholds"`
	Summary                   AdminConnectionHealthSummary    `json:"summary"`
	AlertsTotal               int                             `json:"alerts_total"`
	AlertsLimit               int                             `json:"alerts_limit"`
	Alerts                    []AdminConnectionHealthAlert    `json:"alerts"`
}

func normalizeConnectionHealthFilter(filter AdminConnectionHealthFilter) (AdminConnectionHealthFilter, error) {
	if filter.WindowSeconds == 0 {
		filter.WindowSeconds = DefaultConnectionHealthWindowSeconds
	}
	if filter.WindowSeconds < MinConnectionHealthWindowSeconds || filter.WindowSeconds > MaxConnectionHealthWindowSeconds {
		return filter, ErrInvalidConnectionHealthWindow
	}
	if filter.AlertLimit == 0 {
		filter.AlertLimit = DefaultConnectionHealthAlertLimit
	}
	if filter.AlertLimit < 1 || filter.AlertLimit > MaxConnectionHealthAlertLimit {
		return filter, ErrInvalidConnectionHealthLimit
	}
	filter.NetworkID = strings.TrimSpace(filter.NetworkID)
	filter.AccountID = strings.TrimSpace(filter.AccountID)
	filter.DeviceID = strings.TrimSpace(filter.DeviceID)
	return filter, nil
}

func connectionHealthScope(filter AdminConnectionHealthFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if filter.NetworkID != "" {
		conditions = append(conditions, "o.network_id = ?")
		args = append(args, filter.NetworkID)
	}
	if filter.AccountID != "" {
		conditions = append(conditions, "(rd.user_id = ? OR remd.user_id = ?)")
		args = append(args, filter.AccountID, filter.AccountID)
	}
	if filter.DeviceID != "" {
		conditions = append(conditions, "(o.reporting_device_id = ? OR o.remote_device_id = ?)")
		args = append(args, filter.DeviceID, filter.DeviceID)
	}
	if len(conditions) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conditions, " AND "), args
}

func connectionHealthCTE(filter AdminConnectionHealthFilter, generatedAt int64) (string, []interface{}) {
	windowStart := generatedAt - int64(filter.WindowSeconds)
	freshCutoff := generatedAt - DeviceOnlineTTL
	scopeSQL, scopeArgs := connectionHealthScope(filter)

	transitionNetworkClause := ""
	args := []interface{}{windowStart}
	if filter.NetworkID != "" {
		transitionNetworkClause = " AND network_id = ?"
		args = append(args, filter.NetworkID)
	}
	args = append(args, freshCutoff, freshCutoff, freshCutoff)
	args = append(args, scopeArgs...)

	cte := fmt.Sprintf(`
WITH transition_stats AS (
	SELECT
		reporting_device_id,
		remote_device_id,
		network_id,
		COALESCE(SUM(CASE
			WHEN previous_path IS NOT NULL
				AND current_path IS NOT NULL
				AND previous_path <> current_path
			THEN 1 ELSE 0 END), 0) AS recent_path_switches,
		COALESCE(SUM(CASE
			WHEN transition_reason IN ('direct_probe_failed', 'direct_path_failed')
			THEN 1 ELSE 0 END), 0) AS recent_direct_failures,
		COALESCE(SUM(CASE
			WHEN transition_reason = 'relay_path_failed'
			THEN 1 ELSE 0 END), 0) AS recent_relay_failures,
		COALESCE(MAX(created_at), 0) AS last_transition_at
	FROM peer_path_transitions
	WHERE created_at >= ?%s
	GROUP BY reporting_device_id, remote_device_id, network_id
),
scoped AS (
	SELECT
		o.reporting_device_id,
		rd.device_name AS reporting_device_name,
		rd.user_id AS reporting_user_id,
		ru.username AS reporting_username,
		o.remote_device_id,
		remd.device_name AS remote_device_name,
		remd.user_id AS remote_user_id,
		remu.username AS remote_username,
		o.network_id,
		n.name AS network_name,
		o.current_path,
		o.received_at,
		o.last_validation_rtt_ms,
		CASE
			WHEN rd.online = 1 AND rd.last_seen > 0 AND rd.last_seen >= ?
			THEN 1 ELSE 0
		END AS reporter_online,
		CASE
			WHEN rd.online = 1
				AND rd.last_seen > 0
				AND rd.last_seen >= ?
				AND o.received_at >= ?
			THEN 1 ELSE 0
		END AS fresh,
		COALESCE(ts.recent_path_switches, 0) AS recent_path_switches,
		COALESCE(ts.recent_direct_failures, 0) AS recent_direct_failures,
		COALESCE(ts.recent_relay_failures, 0) AS recent_relay_failures,
		COALESCE(ts.last_transition_at, 0) AS last_transition_at
	FROM peer_path_observations o
	JOIN devices rd ON rd.id = o.reporting_device_id
	JOIN users ru ON ru.id = rd.user_id
	JOIN devices remd ON remd.id = o.remote_device_id
	JOIN users remu ON remu.id = remd.user_id
	JOIN networks n ON n.id = o.network_id
	LEFT JOIN transition_stats ts
		ON ts.reporting_device_id = o.reporting_device_id
		AND ts.remote_device_id = o.remote_device_id
		AND ts.network_id = o.network_id
	%s
)
`, transitionNetworkClause, scopeSQL)

	return cte, args
}

func (db *DB) adminConnectionObservationHealthSummary(filter AdminConnectionHealthFilter, generatedAt int64) (AdminConnectionHealthSummary, error) {
	freshCutoff := generatedAt - DeviceOnlineTTL
	scopeSQL, scopeArgs := connectionHealthScope(filter)
	args := []interface{}{freshCutoff, freshCutoff, freshCutoff}
	args = append(args, scopeArgs...)

	query := fmt.Sprintf(`
WITH scoped AS (
	SELECT
		o.current_path,
		o.last_validation_rtt_ms,
		CASE
			WHEN rd.online = 1 AND rd.last_seen > 0 AND rd.last_seen >= ?
			THEN 1 ELSE 0
		END AS reporter_online,
		CASE
			WHEN rd.online = 1
				AND rd.last_seen > 0
				AND rd.last_seen >= ?
				AND o.received_at >= ?
			THEN 1 ELSE 0
		END AS fresh
	FROM peer_path_observations o
	JOIN devices rd ON rd.id = o.reporting_device_id
	JOIN devices remd ON remd.id = o.remote_device_id
	%s
)
SELECT
	COUNT(*),
	COALESCE(SUM(CASE WHEN fresh = 1 THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN reporter_online = 1 AND fresh = 0 THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN reporter_online = 0 THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN fresh = 1 AND current_path = 'direct' THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN fresh = 1 AND current_path = 'relay' THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN fresh = 1 AND (current_path IS NULL OR current_path = '') THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN fresh = 1 AND last_validation_rtt_ms IS NOT NULL THEN 1 ELSE 0 END), 0),
	CAST(ROUND(AVG(CASE WHEN fresh = 1 THEN last_validation_rtt_ms END)) AS INTEGER),
	MAX(CASE WHEN fresh = 1 THEN last_validation_rtt_ms END)
FROM scoped
`, scopeSQL)

	var (
		summary AdminConnectionHealthSummary
		avgRTT  sql.NullInt64
		maxRTT  sql.NullInt64
	)
	err := db.QueryRow(query, args...).Scan(
		&summary.TotalObservations,
		&summary.FreshObservations,
		&summary.StaleObservations,
		&summary.ReporterOfflineObservations,
		&summary.FreshDirect,
		&summary.FreshRelay,
		&summary.FreshNoPath,
		&summary.ValidationRTTSamples,
		&avgRTT,
		&maxRTT,
	)
	if err != nil {
		return summary, fmt.Errorf("query connection observation health summary: %w", err)
	}
	if avgRTT.Valid {
		value := uint64(avgRTT.Int64)
		summary.AverageValidationRTTMS = &value
	}
	if maxRTT.Valid {
		value := uint64(maxRTT.Int64)
		summary.MaxValidationRTTMS = &value
	}
	return summary, nil
}

func (db *DB) adminConnectionTransitionHealthSummary(filter AdminConnectionHealthFilter, generatedAt int64, summary *AdminConnectionHealthSummary) (int, error) {
	cte, args := connectionHealthCTE(filter, generatedAt)
	query := cte + `
SELECT
	COALESCE(SUM(recent_path_switches), 0),
	COALESCE(SUM(recent_direct_failures), 0),
	COALESCE(SUM(recent_relay_failures), 0),
	COALESCE(SUM(CASE WHEN recent_path_switches >= ? THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE WHEN recent_direct_failures + recent_relay_failures >= ? THEN 1 ELSE 0 END), 0),
	COALESCE(SUM(CASE
		WHEN fresh = 0
			OR (fresh = 1 AND (current_path IS NULL OR current_path = ''))
			OR recent_path_switches >= ?
			OR recent_direct_failures + recent_relay_failures >= ?
		THEN 1 ELSE 0 END), 0)
FROM scoped
`
	args = append(args,
		ConnectionHealthFrequentSwitchThreshold,
		ConnectionHealthRepeatedFailureThreshold,
		ConnectionHealthFrequentSwitchThreshold,
		ConnectionHealthRepeatedFailureThreshold,
	)

	var alertsTotal int
	err := db.QueryRow(query, args...).Scan(
		&summary.RecentPathSwitches,
		&summary.RecentDirectFailures,
		&summary.RecentRelayFailures,
		&summary.FrequentSwitchingConnections,
		&summary.RepeatedFailureConnections,
		&alertsTotal,
	)
	if err != nil {
		return 0, fmt.Errorf("query connection transition health summary: %w", err)
	}
	return alertsTotal, nil
}

func (db *DB) adminConnectionHealthAlerts(filter AdminConnectionHealthFilter, generatedAt int64) ([]AdminConnectionHealthAlert, error) {
	cte, args := connectionHealthCTE(filter, generatedAt)
	query := cte + `
SELECT
	reporting_device_id,
	reporting_device_name,
	reporting_user_id,
	reporting_username,
	remote_device_id,
	remote_device_name,
	remote_user_id,
	remote_username,
	network_id,
	network_name,
	current_path,
	received_at,
	last_validation_rtt_ms,
	reporter_online,
	fresh,
	recent_path_switches,
	recent_direct_failures,
	recent_relay_failures,
	last_transition_at
FROM scoped
WHERE
	fresh = 0
	OR (fresh = 1 AND (current_path IS NULL OR current_path = ''))
	OR recent_path_switches >= ?
	OR recent_direct_failures + recent_relay_failures >= ?
ORDER BY
	CASE
		WHEN (fresh = 1 AND (current_path IS NULL OR current_path = ''))
			OR recent_path_switches >= ?
			OR recent_direct_failures + recent_relay_failures >= ?
		THEN 0 ELSE 1
	END ASC,
	CASE WHEN last_transition_at > received_at THEN last_transition_at ELSE received_at END DESC,
	reporting_device_id ASC,
	remote_device_id ASC
LIMIT ?
`
	args = append(args,
		ConnectionHealthFrequentSwitchThreshold,
		ConnectionHealthRepeatedFailureThreshold,
		ConnectionHealthFrequentSwitchThreshold,
		ConnectionHealthRepeatedFailureThreshold,
		filter.AlertLimit,
	)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query connection health alerts: %w", err)
	}
	defer rows.Close()

	alerts := make([]AdminConnectionHealthAlert, 0, filter.AlertLimit)
	for rows.Next() {
		var (
			item              AdminConnectionHealthAlert
			currentPath       sql.NullString
			lastValidationRTT sql.NullInt64
			reporterOnline    int
			fresh             int
		)
		if err := rows.Scan(
			&item.ReportingDeviceID,
			&item.ReportingDeviceName,
			&item.ReportingUserID,
			&item.ReportingUsername,
			&item.RemoteDeviceID,
			&item.RemoteDeviceName,
			&item.RemoteUserID,
			&item.RemoteUsername,
			&item.NetworkID,
			&item.NetworkName,
			&currentPath,
			&item.ReceivedAt,
			&lastValidationRTT,
			&reporterOnline,
			&fresh,
			&item.RecentPathSwitches,
			&item.RecentDirectFailures,
			&item.RecentRelayFailures,
			&item.LastTransitionAt,
		); err != nil {
			return nil, fmt.Errorf("scan connection health alert: %w", err)
		}

		if currentPath.Valid && currentPath.String != "" {
			item.CurrentPath = &currentPath.String
		}
		if lastValidationRTT.Valid {
			value := uint64(lastValidationRTT.Int64)
			item.LastValidationRTTMS = &value
		}

		item.Fresh = fresh == 1
		switch {
		case reporterOnline == 0:
			item.Freshness = "reporter_offline"
			item.Signals = append(item.Signals, "reporter_offline")
		case !item.Fresh:
			item.Freshness = "stale"
			item.Signals = append(item.Signals, "stale_observation")
		default:
			item.Freshness = "fresh"
		}

		warning := false
		if item.Fresh && item.CurrentPath == nil {
			item.Signals = append(item.Signals, "no_active_path")
			warning = true
		}
		if item.RecentPathSwitches >= ConnectionHealthFrequentSwitchThreshold {
			item.Signals = append(item.Signals, "frequent_path_switching")
			warning = true
		}
		if item.RecentDirectFailures+item.RecentRelayFailures >= ConnectionHealthRepeatedFailureThreshold {
			item.Signals = append(item.Signals, "repeated_path_failures")
			warning = true
		}
		if warning {
			item.Severity = "warning"
		} else {
			item.Severity = "info"
		}
		alerts = append(alerts, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate connection health alerts: %w", err)
	}
	return alerts, nil
}

// AdminConnectionHealth derives bounded operational signals from current
// authoritative observations plus the retained transition history. It does not
// persist an independent health state or infer the active path.
func (db *DB) AdminConnectionHealth(filter AdminConnectionHealthFilter) (*AdminConnectionHealth, error) {
	filter, err := normalizeConnectionHealthFilter(filter)
	if err != nil {
		return nil, err
	}
	generatedAt := time.Now().Unix()

	summary, err := db.adminConnectionObservationHealthSummary(filter, generatedAt)
	if err != nil {
		return nil, err
	}
	alertsTotal, err := db.adminConnectionTransitionHealthSummary(filter, generatedAt, &summary)
	if err != nil {
		return nil, err
	}
	alerts, err := db.adminConnectionHealthAlerts(filter, generatedAt)
	if err != nil {
		return nil, err
	}

	return &AdminConnectionHealth{
		SchemaVersion:            AdminConnectionHealthSchemaVersion,
		GeneratedAt:              generatedAt,
		WindowSeconds:            filter.WindowSeconds,
		HistoryLimitPerDirection: MaxTransitionsPerPair,
		Thresholds: AdminConnectionHealthThresholds{
			FrequentPathSwitches: ConnectionHealthFrequentSwitchThreshold,
			RepeatedPathFailures: ConnectionHealthRepeatedFailureThreshold,
		},
		Summary:     summary,
		AlertsTotal: alertsTotal,
		AlertsLimit: filter.AlertLimit,
		Alerts:      alerts,
	}, nil
}
