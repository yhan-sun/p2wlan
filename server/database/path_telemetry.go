package database

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	PathTelemetrySchemaVersion      = 1
	MaxTransitionsPerPair           = 50
	MaxPathTelemetryValidationRTTMS = 24 * 60 * 60 * 1000
)

var (
	ErrInvalidReportingDevice = errors.New("invalid reporting device or network membership")
	ErrInvalidRemoteDevice    = errors.New("invalid remote device in network")
)

// PathObservation represents an authoritative, committed path observation from a daemon.
type PathObservation struct {
	SchemaVersion           int     `json:"schema_version"`
	RemoteDeviceID          string  `json:"remote_device_id"`
	NetworkID               string  `json:"network_id"`
	ObservationRevision     uint64  `json:"observation_revision"`
	NetworkGeneration       uint64  `json:"network_generation"`
	PeerSessionGeneration   uint64  `json:"peer_session_generation"`
	RemoteCandidateEpoch    uint64  `json:"remote_candidate_epoch"`
	Lifecycle               string  `json:"lifecycle"`
	CurrentPath             *string `json:"current_path"`
	PreviousPath            *string `json:"previous_path"`
	TransitionReason        string  `json:"transition_reason"`
	PathAgeMS               uint64  `json:"path_age_ms"`
	SelectedPathMTU         *uint32 `json:"selected_path_mtu,omitempty"`
	SelectedMTU             *uint32 `json:"selected_mtu,omitempty"`
	SelectedUDPDatagramSize *uint32 `json:"selected_udp_datagram_size,omitempty"`
	DirectState             string  `json:"direct_state,omitempty"`
	RelayState              string  `json:"relay_state,omitempty"`
	RecoveryState           string  `json:"recovery_state,omitempty"`
	RelayServer             string  `json:"relay_server,omitempty"`
	LastHandshakeAgeMS      *uint64 `json:"last_handshake_age_ms,omitempty"`
	LastValidationRTTMS     *uint64 `json:"last_validation_rtt_ms,omitempty"`
	LastDirectLatencyMS     *uint64 `json:"last_direct_latency_ms,omitempty"`
	LastRelayLatencyMS      *uint64 `json:"last_relay_latency_ms,omitempty"`
	ObservedAt              int64   `json:"observed_at"`
}

type PathTelemetryBatch struct {
	ProtocolVersion int               `json:"protocol_version"`
	Observations    []PathObservation `json:"observations"`
	IsResync        bool              `json:"is_resync"`
}

type PathTelemetryIngestSummary struct {
	Total     int `json:"total"`
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate"`
	Rejected  int `json:"rejected"`
}

var validTransitionReasons = map[string]struct{}{
	"initial":                         {},
	"peer_online":                     {},
	"direct_first_started":            {},
	"direct_first_satisfied":          true,
	"direct_first_deadline":           {},
	"peer_left":                       {},
	"identity_reset":                  {},
	"network_generation_advanced":     {},
	"remote_candidate_epoch_advanced": {},
	"relay_transport_ready":           {},
	"relay_peer_confirmed":            {},
	"relay_business_usable":           {},
	"relay_health_observed":           {},
	"relay_transport_lost":            {},
	"relay_path_failed":               {},
	"direct_probe_started":            {},
	"direct_validation_started":       {},
	"direct_committed":                {},
	"direct_probe_failed":             {},
	"direct_path_failed":              {},
	"direct_attempt_cancelled":        {},
	"direct_retry_scheduled":          {},
	"compatibility_state_requested":   {},
}

func sanitizeTransitionReason(reason string) string {
	if _, ok := validTransitionReasons[reason]; ok {
		return reason
	}
	return "unknown"
}

func sanitizePath(p *string) *string {
	if p == nil {
		return nil
	}
	switch *p {
	case "direct", "relay":
		val := *p
		return &val
	default:
		return nil
	}
}

func sanitizeLifecycle(l string) string {
	switch l {
	case "online", "offline", "unbound":
		return l
	default:
		return "unbound"
	}
}

func normalizedSelectedPathMTU(obs PathObservation) *uint32 {
	if obs.SelectedPathMTU != nil {
		return obs.SelectedPathMTU
	}
	return obs.SelectedMTU
}

func normalizedValidationRTT(obs PathObservation, currentPath *string) *uint64 {
	var value *uint64
	if obs.LastValidationRTTMS != nil {
		value = obs.LastValidationRTTMS
	} else if currentPath != nil {
		switch *currentPath {
		case "direct":
			value = obs.LastDirectLatencyMS
		case "relay":
			value = obs.LastRelayLatencyMS
		}
	}
	if value == nil || *value > MaxPathTelemetryValidationRTTMS {
		return nil
	}
	return value
}

func migratePathTelemetry(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS peer_path_observations (
		reporting_device_id        TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		remote_device_id           TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		network_id                 TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
		schema_version             INTEGER NOT NULL DEFAULT 1,
		registration_seq           INTEGER NOT NULL DEFAULT 0,
		observation_revision       INTEGER NOT NULL DEFAULT 0,
		network_generation         INTEGER NOT NULL DEFAULT 0,
		peer_session_generation    INTEGER NOT NULL DEFAULT 0,
		remote_candidate_epoch     INTEGER NOT NULL DEFAULT 0,
		lifecycle                  TEXT NOT NULL DEFAULT 'unbound',
		current_path               TEXT,
		previous_path              TEXT,
		transition_reason          TEXT NOT NULL DEFAULT '',
		path_age_ms                INTEGER NOT NULL DEFAULT 0,
		selected_path_mtu          INTEGER,
		selected_udp_datagram_size INTEGER,
		direct_state               TEXT NOT NULL DEFAULT '',
		relay_state                TEXT NOT NULL DEFAULT '',
		recovery_state             TEXT NOT NULL DEFAULT '',
		relay_server               TEXT NOT NULL DEFAULT '',
		last_handshake_age_ms      INTEGER,
		last_validation_rtt_ms     INTEGER,
		observed_at                INTEGER NOT NULL,
		received_at                INTEGER NOT NULL,
		PRIMARY KEY (reporting_device_id, remote_device_id, network_id)
	);

	CREATE INDEX IF NOT EXISTS idx_peer_path_obs_reporting ON peer_path_observations(reporting_device_id);
	CREATE INDEX IF NOT EXISTS idx_peer_path_obs_network ON peer_path_observations(network_id);
	CREATE INDEX IF NOT EXISTS idx_peer_path_obs_received ON peer_path_observations(received_at);

	CREATE TABLE IF NOT EXISTS peer_path_transitions (
		id                   TEXT PRIMARY KEY,
		reporting_device_id  TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		remote_device_id     TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
		network_id           TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
		schema_version       INTEGER NOT NULL DEFAULT 1,
		registration_seq     INTEGER NOT NULL DEFAULT 0,
		observation_revision INTEGER NOT NULL DEFAULT 0,
		network_generation   INTEGER NOT NULL DEFAULT 0,
		peer_session_generation INTEGER NOT NULL DEFAULT 0,
		remote_candidate_epoch INTEGER NOT NULL DEFAULT 0,
		lifecycle            TEXT NOT NULL DEFAULT '',
		current_path         TEXT,
		previous_path        TEXT,
		transition_reason    TEXT NOT NULL DEFAULT '',
		selected_path_mtu    INTEGER,
		observed_at          INTEGER NOT NULL,
		created_at           INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_peer_path_trans_pair ON peer_path_transitions(reporting_device_id, remote_device_id, network_id, created_at DESC);
	CREATE INDEX IF NOT EXISTS idx_peer_path_trans_created ON peer_path_transitions(created_at);
	CREATE INDEX IF NOT EXISTS idx_peer_path_trans_network_created ON peer_path_transitions(network_id, created_at DESC);
	`
	_, err := db.Exec(schema)
	return err
}

func newTransitionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("ppt-%016x-%s", time.Now().UnixMicro(), hex.EncodeToString(b[:]))
}

type existingPathObservation struct {
	RegistrationSeq       int64
	ObservationRevision   uint64
	NetworkGeneration     uint64
	PeerSessionGeneration uint64
	RemoteCandidateEpoch  uint64
	Lifecycle             string
	CurrentPath           sql.NullString
	TransitionReason      string
}

// RecordPathObservations validates and persists path telemetry observations from an
// authenticated reporting device. It enforces strict session and generation fencing,
// maintains the latest snapshot per directional peer pair, and logs bounded transition
// history on real changes.
func (db *DB) RecordPathObservations(
	reportingDeviceID, networkID string,
	registrationSeq int64,
	observations []PathObservation,
	isResync bool,
) (*PathTelemetryIngestSummary, error) {
	if reportingDeviceID == "" || networkID == "" {
		return nil, errors.New("reporting_device_id and network_id are required")
	}

	// 1. Verify reporting device belongs to network_id
	var reportingExists int
	err := db.QueryRow(
		`SELECT COUNT(*) FROM devices WHERE id = ? AND network_id = ?`,
		reportingDeviceID, networkID,
	).Scan(&reportingExists)
	if err != nil {
		return nil, fmt.Errorf("validating reporting device: %w", err)
	}
	if reportingExists == 0 {
		return nil, ErrInvalidReportingDevice
	}

	summary := &PathTelemetryIngestSummary{
		Total: len(observations),
	}
	if len(observations) == 0 {
		return summary, nil
	}

	now := time.Now().Unix()

	tx, err := db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin telemetry tx: %w", err)
	}
	defer tx.Rollback()

	for _, obs := range observations {
		remoteID := obs.RemoteDeviceID
		if remoteID == "" || remoteID == reportingDeviceID {
			summary.Rejected++
			continue
		}

		// Verify remote device exists in the same network
		var remoteExists int
		err := tx.QueryRow(
			`SELECT COUNT(*) FROM devices WHERE id = ? AND network_id = ?`,
			remoteID, networkID,
		).Scan(&remoteExists)
		if err != nil || remoteExists == 0 {
			summary.Rejected++
			continue
		}

		obsReason := sanitizeTransitionReason(obs.TransitionReason)
		currPath := sanitizePath(obs.CurrentPath)
		prevPath := sanitizePath(obs.PreviousPath)
		lifecycle := sanitizeLifecycle(obs.Lifecycle)
		selectedPathMTU := normalizedSelectedPathMTU(obs)
		validationRTT := normalizedValidationRTT(obs, currPath)

		// Check existing observation
		var existing existingPathObservation
		var exists bool
		row := tx.QueryRow(
			`SELECT registration_seq, observation_revision, network_generation,
			        peer_session_generation, remote_candidate_epoch, lifecycle,
			        current_path, transition_reason
			 FROM peer_path_observations
			 WHERE reporting_device_id = ? AND remote_device_id = ? AND network_id = ?`,
			reportingDeviceID, remoteID, networkID,
		)
		if scanErr := row.Scan(
			&existing.RegistrationSeq,
			&existing.ObservationRevision,
			&existing.NetworkGeneration,
			&existing.PeerSessionGeneration,
			&existing.RemoteCandidateEpoch,
			&existing.Lifecycle,
			&existing.CurrentPath,
			&existing.TransitionReason,
		); scanErr == nil {
			exists = true
		} else if !errors.Is(scanErr, sql.ErrNoRows) {
			return nil, fmt.Errorf("inspecting existing observation: %w", scanErr)
		}

		ownerAdvanced := exists && registrationSeq > existing.RegistrationSeq
		if exists {
			// Fencing hierarchy:
			// 1. Session registration sequence (server-issued owner identity)
			if registrationSeq < existing.RegistrationSeq {
				// Old session cannot overwrite new session
				summary.Rejected++
				continue
			}
			if registrationSeq == existing.RegistrationSeq {
				// Within same session: compare generations
				if obs.NetworkGeneration < existing.NetworkGeneration {
					summary.Rejected++
					continue
				}
				if obs.NetworkGeneration == existing.NetworkGeneration {
					if obs.PeerSessionGeneration < existing.PeerSessionGeneration {
						summary.Rejected++
						continue
					}
					if obs.PeerSessionGeneration == existing.PeerSessionGeneration {
						if obs.RemoteCandidateEpoch < existing.RemoteCandidateEpoch {
							summary.Rejected++
							continue
						}
						if obs.RemoteCandidateEpoch == existing.RemoteCandidateEpoch {
							// Compare revisions
							if obs.ObservationRevision < existing.ObservationRevision {
								summary.Rejected++
								continue
							}
							if obs.ObservationRevision == existing.ObservationRevision {
								summary.Duplicate++
								continue
							}
						}
					}
				}
			}
			// registrationSeq > existing.RegistrationSeq falls through to ACCEPT
		}

		// Accepted: determine if a transition should be recorded. The long-term
		// path-switch metric is intentionally narrower than transition history:
		// only an observed Direct<->Relay change counts as a path switch.
		var recordTransition bool
		var pathSwitched bool
		if !exists {
			recordTransition = true
		} else {
			existingCurrentPath := ""
			if existing.CurrentPath.Valid {
				existingCurrentPath = existing.CurrentPath.String
			}
			incomingCurrentPath := ""
			if currPath != nil {
				incomingCurrentPath = *currPath
			}
			pathSwitched = !ownerAdvanced &&
				existingCurrentPath != "" &&
				incomingCurrentPath != "" &&
				existingCurrentPath != incomingCurrentPath

			if existingCurrentPath != incomingCurrentPath ||
				existing.Lifecycle != lifecycle ||
				existing.TransitionReason != obsReason {
				recordTransition = true
			}
		}

		if recordTransition {
			transID := newTransitionID()
			_, err := tx.Exec(`
				INSERT INTO peer_path_transitions (
					id, reporting_device_id, remote_device_id, network_id,
					schema_version, registration_seq, observation_revision,
					network_generation, peer_session_generation, remote_candidate_epoch,
					lifecycle, current_path, previous_path, transition_reason,
					selected_path_mtu, observed_at, created_at
				) VALUES (
					?, ?, ?, ?,
					?, ?, ?,
					?, ?, ?,
					?, ?, ?, ?,
					?, ?, ?
				)
			`,
				transID, reportingDeviceID, remoteID, networkID,
				PathTelemetrySchemaVersion, registrationSeq, obs.ObservationRevision,
				obs.NetworkGeneration, obs.PeerSessionGeneration, obs.RemoteCandidateEpoch,
				lifecycle, currPath, prevPath, obsReason,
				selectedPathMTU, obs.ObservedAt, now,
			)
			if err != nil {
				return nil, fmt.Errorf("insert transition: %w", err)
			}

			// Prune transition history to MaxTransitionsPerPair
			_, err = tx.Exec(`
				DELETE FROM peer_path_transitions
				WHERE reporting_device_id = ? AND remote_device_id = ? AND network_id = ?
				  AND id NOT IN (
					  SELECT id FROM peer_path_transitions
					  WHERE reporting_device_id = ? AND remote_device_id = ? AND network_id = ?
					  ORDER BY created_at DESC, id DESC
					  LIMIT ?
				  )
			`, reportingDeviceID, remoteID, networkID, reportingDeviceID, remoteID, networkID, MaxTransitionsPerPair)
			if err != nil {
				return nil, fmt.Errorf("prune transitions: %w", err)
			}
		}

		// Upsert into peer_path_observations
		_, err = tx.Exec(`
			INSERT INTO peer_path_observations (
				reporting_device_id, remote_device_id, network_id,
				schema_version, registration_seq, observation_revision,
				network_generation, peer_session_generation, remote_candidate_epoch,
				lifecycle, current_path, previous_path, transition_reason,
				path_age_ms, selected_path_mtu, selected_udp_datagram_size,
				direct_state, relay_state, recovery_state, relay_server,
				last_handshake_age_ms, last_validation_rtt_ms,
				observed_at, received_at
			) VALUES (
				?, ?, ?,
				?, ?, ?,
				?, ?, ?,
				?, ?, ?, ?,
				?, ?, ?,
				?, ?, ?, ?,
				?, ?,
				?, ?
			) ON CONFLICT(reporting_device_id, remote_device_id, network_id) DO UPDATE SET
				schema_version = excluded.schema_version,
				registration_seq = excluded.registration_seq,
				observation_revision = excluded.observation_revision,
				network_generation = excluded.network_generation,
				peer_session_generation = excluded.peer_session_generation,
				remote_candidate_epoch = excluded.remote_candidate_epoch,
				lifecycle = excluded.lifecycle,
				current_path = excluded.current_path,
				previous_path = excluded.previous_path,
				transition_reason = excluded.transition_reason,
				path_age_ms = excluded.path_age_ms,
				selected_path_mtu = excluded.selected_path_mtu,
				selected_udp_datagram_size = excluded.selected_udp_datagram_size,
				direct_state = excluded.direct_state,
				relay_state = excluded.relay_state,
				recovery_state = excluded.recovery_state,
				relay_server = excluded.relay_server,
				last_handshake_age_ms = excluded.last_handshake_age_ms,
				last_validation_rtt_ms = excluded.last_validation_rtt_ms,
				observed_at = excluded.observed_at,
				received_at = excluded.received_at
		`,
			reportingDeviceID, remoteID, networkID,
			PathTelemetrySchemaVersion, registrationSeq, obs.ObservationRevision,
			obs.NetworkGeneration, obs.PeerSessionGeneration, obs.RemoteCandidateEpoch,
			lifecycle, currPath, prevPath, obsReason,
			obs.PathAgeMS, selectedPathMTU, obs.SelectedUDPDatagramSize,
			obs.DirectState, obs.RelayState, obs.RecoveryState, obs.RelayServer,
			obs.LastHandshakeAgeMS, validationRTT,
			obs.ObservedAt, now,
		)
		if err != nil {
			return nil, fmt.Errorf("upsert observation: %w", err)
		}

		delta := connectionMetricDeltaForObservation(
			currPath,
			pathSwitched,
			recordTransition && !ownerAdvanced,
			obsReason,
			validationRTT,
			isResync || ownerAdvanced,
		)
		if err := upsertConnectionMetricHourly(tx, networkID, now, delta); err != nil {
			return nil, err
		}

		summary.Accepted++
	}

	if err := pruneConnectionMetrics(tx, now); err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit telemetry tx: %w", err)
	}

	return summary, nil
}
