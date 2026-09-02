//! Bounded, generation-aware path observability.
//!
//! All transition telemetry is recorded synchronously at
//! [`PeerConnection::commit_path_transition`], the sole authoritative path
//! commit point. The recorder owns no async locks, performs no I/O and keeps a
//! fixed-size event ring, so diagnostics cannot mutate or block the dataplane.

use std::collections::VecDeque;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::path_state_machine::{
    DirectPathState, PathEvent, PathRecoveryState, PathTransitionDecision, PathTransitionOutcome,
    RelayPathState,
};
use super::{
    DirectTraversalEvent, NetworkPath, PathHealthDiagnostics, PeerConnection, PeerPathLifecycle,
};

pub const PATH_OBSERVABILITY_SCHEMA_VERSION: u32 = 1;
pub const PATH_TRANSITION_EVENT_LIMIT: usize = 32;
pub const DIRECT_CONNECT_HISTOGRAM_BOUNDS_MS: [u64; 8] =
    [50, 100, 250, 500, 1_000, 3_000, 10_000, 30_000];
pub const RELAY_SAFE_PATH_MTU: u32 = 1_380;

/// Stable metric names. These are field names rather than dynamic label
/// values, which keeps cardinality bounded by construction.
#[cfg_attr(not(test), allow(dead_code))]
pub const PATH_OBSERVABILITY_METRIC_NAMES: [&str; 23] = [
    "accepted_transitions",
    "accepted_observations",
    "duplicate_events",
    "rejected_transitions",
    "path_changes",
    "direct_attempts",
    "direct_retries",
    "direct_validations",
    "direct_successes",
    "direct_failures",
    "validation_failures",
    "relay_confirmations",
    "relay_fallbacks",
    "relay_failures",
    "candidate_refreshes",
    "control_reconnects",
    "network_generation_changes",
    "lifecycle_resets",
    "dplpmtud_changes",
    "active_tasks",
    "active_sockets",
    "dropped_transition_events",
    "direct_time_to_connect_ms",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathLatencyHistogram {
    pub bounds_ms: Vec<u64>,
    /// One bucket for every bound plus one overflow bucket.
    pub buckets: Vec<u64>,
    pub count: u64,
    pub sum_ms: u64,
    pub max_ms: Option<u64>,
}

impl Default for PathLatencyHistogram {
    fn default() -> Self {
        Self {
            bounds_ms: DIRECT_CONNECT_HISTOGRAM_BOUNDS_MS.to_vec(),
            buckets: vec![0; DIRECT_CONNECT_HISTOGRAM_BOUNDS_MS.len() + 1],
            count: 0,
            sum_ms: 0,
            max_ms: None,
        }
    }
}

impl PathLatencyHistogram {
    fn observe(&mut self, value_ms: u64) {
        let index = self
            .bounds_ms
            .iter()
            .position(|bound| value_ms <= *bound)
            .unwrap_or(self.bounds_ms.len());
        if let Some(bucket) = self.buckets.get_mut(index) {
            *bucket = bucket.saturating_add(1);
        }
        self.count = self.count.saturating_add(1);
        self.sum_ms = self.sum_ms.saturating_add(value_ms);
        self.max_ms = Some(
            self.max_ms
                .map_or(value_ms, |current| current.max(value_ms)),
        );
    }

    pub(crate) fn merge_from(&mut self, other: &Self) {
        if self.bounds_ms != other.bounds_ms || self.buckets.len() != other.buckets.len() {
            return;
        }
        for (target, source) in self.buckets.iter_mut().zip(&other.buckets) {
            *target = target.saturating_add(*source);
        }
        self.count = self.count.saturating_add(other.count);
        self.sum_ms = self.sum_ms.saturating_add(other.sum_ms);
        if let Some(value) = other.max_ms {
            self.max_ms = Some(self.max_ms.map_or(value, |current| current.max(value)));
        }
    }
}

/// Process-bounded counters. No peer ID, endpoint, IP, session identifier or
/// arbitrary error text can become a label because the schema has no label
/// map at all.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PathObservabilityMetrics {
    pub accepted_transitions: u64,
    pub accepted_observations: u64,
    pub duplicate_events: u64,
    pub rejected_transitions: u64,
    pub path_changes: u64,
    pub direct_attempts: u64,
    pub direct_retries: u64,
    pub direct_validations: u64,
    pub direct_successes: u64,
    pub direct_failures: u64,
    pub validation_failures: u64,
    pub relay_confirmations: u64,
    pub relay_fallbacks: u64,
    pub relay_failures: u64,
    pub candidate_refreshes: u64,
    pub control_reconnects: u64,
    pub network_generation_changes: u64,
    pub lifecycle_resets: u64,
    pub dplpmtud_changes: u64,
    pub active_tasks: u64,
    pub active_sockets: u64,
    pub dropped_transition_events: u64,
    pub direct_time_to_connect_ms: PathLatencyHistogram,
}

impl PathObservabilityMetrics {
    pub(crate) fn merge_from(&mut self, other: &Self) {
        macro_rules! add {
            ($field:ident) => {
                self.$field = self.$field.saturating_add(other.$field)
            };
        }
        add!(accepted_transitions);
        add!(accepted_observations);
        add!(duplicate_events);
        add!(rejected_transitions);
        add!(path_changes);
        add!(direct_attempts);
        add!(direct_retries);
        add!(direct_validations);
        add!(direct_successes);
        add!(direct_failures);
        add!(validation_failures);
        add!(relay_confirmations);
        add!(relay_fallbacks);
        add!(relay_failures);
        add!(candidate_refreshes);
        add!(control_reconnects);
        add!(network_generation_changes);
        add!(lifecycle_resets);
        add!(dplpmtud_changes);
        add!(active_tasks);
        add!(active_sockets);
        add!(dropped_transition_events);
        self.direct_time_to_connect_ms
            .merge_from(&other.direct_time_to_connect_ms);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathEpochDiagnostics {
    pub network_generation: u64,
    pub peer_session_generation: u64,
    pub remote_candidate_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathTransitionDiagnostics {
    pub age_ms: u64,
    pub revision: u64,
    pub event_kind: String,
    pub decision: String,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<PathEpochDiagnostics>,
    pub previous_path: Option<NetworkPath>,
    pub current_path: Option<NetworkPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PathHandshakeDiagnostics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_generation: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PathValidationDiagnostics {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_age_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation_rtt_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_endpoint_authenticated: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CandidatePunchSummaryDiagnostics {
    pub candidate_pair_count: usize,
    pub signaled_candidate_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_candidate_count: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_sent_probes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_unique_target_ports: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_repeated_target_ports: Option<u32>,
}

/// Versioned, backward-compatible per-peer diagnostics snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathObservabilitySnapshot {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_epoch: Option<PathEpochDiagnostics>,
    pub lifecycle: String,
    pub current_path: Option<NetworkPath>,
    pub previous_path: Option<NetworkPath>,
    pub transition_reason: String,
    pub path_age_ms: u64,
    pub path_state_revision: u64,
    pub direct_state: String,
    pub relay_state: String,
    pub recovery_state: String,
    pub direct_health: PathHealthDiagnostics,
    pub relay_health: PathHealthDiagnostics,
    pub latest_handshake: PathHandshakeDiagnostics,
    pub latest_validation: PathValidationDiagnostics,
    pub candidate_punch: CandidatePunchSummaryDiagnostics,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_path_mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_udp_datagram_size: Option<u32>,
    pub metrics: PathObservabilityMetrics,
    pub transitions: Vec<PathTransitionDiagnostics>,
}

impl Default for PathObservabilitySnapshot {
    fn default() -> Self {
        Self {
            schema_version: PATH_OBSERVABILITY_SCHEMA_VERSION,
            network_epoch: None,
            lifecycle: "unbound".to_string(),
            current_path: None,
            previous_path: None,
            transition_reason: "initial".to_string(),
            path_age_ms: 0,
            path_state_revision: 0,
            direct_state: "idle".to_string(),
            relay_state: "unavailable".to_string(),
            recovery_state: "stable".to_string(),
            direct_health: PathHealthDiagnostics {
                last_success_age_ms: None,
                last_failure_age_ms: None,
                consecutive_failures: 0,
                last_error: None,
                last_error_code: None,
                last_liveness: None,
                latency_ms: None,
                rtt_ewma_ms: None,
                jitter_ms: None,
                success_count: 0,
                failure_count: 0,
            },
            relay_health: PathHealthDiagnostics {
                last_success_age_ms: None,
                last_failure_age_ms: None,
                consecutive_failures: 0,
                last_error: None,
                last_error_code: None,
                last_liveness: None,
                latency_ms: None,
                rtt_ewma_ms: None,
                jitter_ms: None,
                success_count: 0,
                failure_count: 0,
            },
            latest_handshake: PathHandshakeDiagnostics::default(),
            latest_validation: PathValidationDiagnostics::default(),
            candidate_punch: CandidatePunchSummaryDiagnostics::default(),
            selected_path_mtu: None,
            selected_udp_datagram_size: None,
            metrics: PathObservabilityMetrics::default(),
            transitions: Vec::new(),
        }
    }
}

impl PathObservabilitySnapshot {
    pub(crate) fn apply_dplpmtud_runtime(
        &mut self,
        dplpmtud: Option<&crate::dplpmtud::DplpmtudSnapshot>,
    ) {
        match self.current_path {
            Some(NetworkPath::Direct) => {
                self.selected_path_mtu =
                    dplpmtud.and_then(|snapshot| snapshot.overlay_payload_budget);
                self.selected_udp_datagram_size =
                    dplpmtud.and_then(|snapshot| snapshot.confirmed_udp_datagram_size);
            }
            Some(NetworkPath::Relay) => {
                self.selected_path_mtu = Some(RELAY_SAFE_PATH_MTU);
                self.selected_udp_datagram_size = None;
            }
            None => {
                self.selected_path_mtu = None;
                self.selected_udp_datagram_size = None;
            }
        }
        self.metrics.dplpmtud_changes = dplpmtud.map_or(0, |snapshot| snapshot.revision);
    }
}

#[derive(Debug, Clone)]
struct RecordedPathTransition {
    recorded_at: Instant,
    revision: u64,
    event_kind: &'static str,
    decision: &'static str,
    reason_code: &'static str,
    epoch: Option<PathEpochDiagnostics>,
    previous_path: Option<NetworkPath>,
    current_path: Option<NetworkPath>,
}

#[derive(Debug, Clone)]
pub(crate) struct PathObservabilityState {
    metrics: PathObservabilityMetrics,
    transitions: VecDeque<RecordedPathTransition>,
    previous_path: Option<NetworkPath>,
    current_path_since: Instant,
    last_reason_code: &'static str,
    direct_attempt_started: Option<Instant>,
}

impl Default for PathObservabilityState {
    fn default() -> Self {
        Self {
            metrics: PathObservabilityMetrics::default(),
            transitions: VecDeque::with_capacity(PATH_TRANSITION_EVENT_LIMIT),
            previous_path: None,
            current_path_since: Instant::now(),
            last_reason_code: "initial",
            direct_attempt_started: None,
        }
    }
}

impl PathObservabilityState {
    pub(crate) fn record(
        &mut self,
        event: &PathEvent,
        outcome: &PathTransitionOutcome,
        now: Instant,
    ) {
        let previous_path = outcome.previous.active.network_path();
        let current_path = outcome.snapshot.state.active.network_path();
        let event_kind = event_kind(event);
        let decision = decision_label(outcome.decision);
        let reason_code = event_reason_code(event);

        match outcome.decision {
            PathTransitionDecision::Applied => {
                self.metrics.accepted_transitions =
                    self.metrics.accepted_transitions.saturating_add(1);
            }
            PathTransitionDecision::AcceptedObservation => {
                self.metrics.accepted_observations =
                    self.metrics.accepted_observations.saturating_add(1);
            }
            PathTransitionDecision::Duplicate => {
                self.metrics.duplicate_events = self.metrics.duplicate_events.saturating_add(1);
            }
            _ => {
                self.metrics.rejected_transitions =
                    self.metrics.rejected_transitions.saturating_add(1);
            }
        }

        if outcome.applies_side_effects() {
            self.record_applied_event(event, now);
        }

        if previous_path != current_path && outcome.applies_side_effects() {
            self.metrics.path_changes = self.metrics.path_changes.saturating_add(1);
            if current_path == Some(NetworkPath::Relay) {
                self.metrics.relay_fallbacks = self.metrics.relay_fallbacks.saturating_add(1);
            }
            self.previous_path = previous_path;
            self.current_path_since = now;
        }
        if outcome.applies_side_effects() {
            self.last_reason_code = reason_code;
        }

        if self.transitions.len() == PATH_TRANSITION_EVENT_LIMIT {
            self.transitions.pop_front();
            self.metrics.dropped_transition_events =
                self.metrics.dropped_transition_events.saturating_add(1);
        }
        self.transitions.push_back(RecordedPathTransition {
            recorded_at: now,
            revision: outcome.snapshot.revision,
            event_kind,
            decision,
            reason_code,
            epoch: event.epoch().map(|epoch| PathEpochDiagnostics {
                network_generation: epoch.network_generation,
                peer_session_generation: epoch.peer_session_generation.value(),
                remote_candidate_epoch: epoch.remote_candidate_epoch,
            }),
            previous_path,
            current_path,
        });
    }

    fn record_applied_event(&mut self, event: &PathEvent, now: Instant) {
        match event {
            PathEvent::PeerOnline { .. } => {}
            PathEvent::PeerLeft { .. } | PathEvent::IdentityReset => {
                self.metrics.lifecycle_resets = self.metrics.lifecycle_resets.saturating_add(1);
                self.direct_attempt_started = None;
            }
            PathEvent::NetworkGenerationAdvanced { .. } => {
                self.metrics.network_generation_changes =
                    self.metrics.network_generation_changes.saturating_add(1);
                self.direct_attempt_started = None;
            }
            PathEvent::RemoteCandidateEpochAdvanced { .. } => {
                self.metrics.candidate_refreshes =
                    self.metrics.candidate_refreshes.saturating_add(1);
            }
            PathEvent::RelayPeerConfirmed { .. } => {
                self.metrics.relay_confirmations =
                    self.metrics.relay_confirmations.saturating_add(1);
            }
            PathEvent::RelayTransportLost { .. } | PathEvent::RelayPathFailed { .. } => {
                self.metrics.relay_failures = self.metrics.relay_failures.saturating_add(1);
            }
            PathEvent::DirectProbeStarted { .. } => {
                self.metrics.direct_attempts = self.metrics.direct_attempts.saturating_add(1);
                self.direct_attempt_started = Some(now);
            }
            PathEvent::DirectRetryScheduled { .. } => {
                self.metrics.direct_retries = self.metrics.direct_retries.saturating_add(1);
                self.direct_attempt_started.get_or_insert(now);
            }
            PathEvent::DirectValidationStarted { .. } => {
                self.metrics.direct_validations = self.metrics.direct_validations.saturating_add(1);
                self.direct_attempt_started.get_or_insert(now);
            }
            PathEvent::DirectCommitted { .. } => {
                self.metrics.direct_successes = self.metrics.direct_successes.saturating_add(1);
                if let Some(started) = self.direct_attempt_started.take() {
                    self.metrics
                        .direct_time_to_connect_ms
                        .observe(duration_millis(now.saturating_duration_since(started)));
                }
            }
            PathEvent::DirectProbeFailed { .. }
            | PathEvent::DirectPathFailed { .. }
            | PathEvent::DirectAttemptCancelled { .. } => {
                self.metrics.direct_failures = self.metrics.direct_failures.saturating_add(1);
                self.metrics.validation_failures =
                    self.metrics.validation_failures.saturating_add(1);
                self.direct_attempt_started = None;
            }
            PathEvent::RelayTransportReady { .. }
            | PathEvent::RelayBusinessUsable { .. }
            | PathEvent::RelayHealthObserved { .. }
            | PathEvent::CompatibilityStateRequested { .. } => {}
        }
    }

    pub(crate) fn snapshot(&self, connection: &PeerConnection) -> PathObservabilitySnapshot {
        let machine = connection.path_state_snapshot();
        let current_path = machine.state.active.network_path();
        let latest_handshake = latest_handshake(&connection.direct_events);
        let latest_validation = latest_validation(&connection.direct_events);
        let candidate_punch = latest_candidate_punch(connection, &connection.direct_events);
        let mut snapshot = PathObservabilitySnapshot {
            schema_version: PATH_OBSERVABILITY_SCHEMA_VERSION,
            network_epoch: machine.state.epoch.map(|epoch| PathEpochDiagnostics {
                network_generation: epoch.network_generation,
                peer_session_generation: epoch.peer_session_generation.value(),
                remote_candidate_epoch: epoch.remote_candidate_epoch,
            }),
            lifecycle: lifecycle_label(machine.state.lifecycle).to_string(),
            current_path,
            previous_path: self.previous_path,
            transition_reason: self.last_reason_code.to_string(),
            path_age_ms: duration_millis(self.current_path_since.elapsed()),
            path_state_revision: machine.revision,
            direct_state: direct_state_label(&machine.state.direct).to_string(),
            relay_state: relay_state_label(&machine.state.relay).to_string(),
            recovery_state: recovery_state_label(&machine.state.recovery).to_string(),
            direct_health: PathHealthDiagnostics::from(&connection.direct_health),
            relay_health: PathHealthDiagnostics::from(&connection.relay_health),
            latest_handshake,
            latest_validation,
            candidate_punch,
            selected_path_mtu: (current_path == Some(NetworkPath::Relay))
                .then_some(RELAY_SAFE_PATH_MTU),
            selected_udp_datagram_size: None,
            metrics: self.metrics.clone(),
            transitions: self
                .transitions
                .iter()
                .map(|transition| PathTransitionDiagnostics {
                    age_ms: duration_millis(transition.recorded_at.elapsed()),
                    revision: transition.revision,
                    event_kind: transition.event_kind.to_string(),
                    decision: transition.decision.to_string(),
                    reason_code: transition.reason_code.to_string(),
                    epoch: transition.epoch.clone(),
                    previous_path: transition.previous_path,
                    current_path: transition.current_path,
                })
                .collect(),
        };
        snapshot.metrics.rejected_transitions = machine
            .rejected_transitions
            .max(snapshot.metrics.rejected_transitions);
        snapshot
    }
}

fn latest_handshake(events: &[DirectTraversalEvent]) -> PathHandshakeDiagnostics {
    events
        .iter()
        .rev()
        .find(|event| {
            let stage = event.stage.to_ascii_lowercase();
            stage.contains("handshake")
                || stage.contains("offer")
                || stage.contains("answer")
                || stage.contains("session")
        })
        .map(|event| PathHandshakeDiagnostics {
            latest_stage: Some(event.stage.clone()),
            latest_age_ms: Some(duration_millis(event.recorded_at.elapsed())),
            network_generation: Some(event.network_generation),
        })
        .unwrap_or_default()
}

fn latest_validation(events: &[DirectTraversalEvent]) -> PathValidationDiagnostics {
    events
        .iter()
        .rev()
        .find(|event| {
            event.validation_session_id.is_some()
                || event.request_id.is_some()
                || event.validation_rtt_ms.is_some()
                || event.stage.to_ascii_lowercase().contains("validation")
        })
        .map(|event| PathValidationDiagnostics {
            latest_stage: Some(event.stage.clone()),
            latest_age_ms: Some(duration_millis(event.recorded_at.elapsed())),
            validation_rtt_ms: event.validation_rtt_ms,
            ack_endpoint_authenticated: event.ack_endpoint_authenticated,
        })
        .unwrap_or_default()
}

fn latest_candidate_punch(
    connection: &PeerConnection,
    events: &[DirectTraversalEvent],
) -> CandidatePunchSummaryDiagnostics {
    let latest = events.iter().rev().find(|event| {
        event.candidate_count.is_some()
            || event.sent_probes.is_some()
            || event.probe_tx_unique_target_ports.is_some()
    });
    CandidatePunchSummaryDiagnostics {
        candidate_pair_count: connection.candidate_pairs.len(),
        signaled_candidate_count: connection.candidates.len(),
        latest_candidate_count: latest.and_then(|event| event.candidate_count),
        latest_sent_probes: latest.and_then(|event| event.sent_probes),
        latest_unique_target_ports: latest.and_then(|event| event.probe_tx_unique_target_ports),
        latest_repeated_target_ports: latest.and_then(|event| event.probe_tx_repeated_target_ports),
    }
}

fn event_kind(event: &PathEvent) -> &'static str {
    match event {
        PathEvent::PeerOnline { .. } => "peer_online",
        PathEvent::PeerLeft { .. } => "peer_left",
        PathEvent::IdentityReset => "identity_reset",
        PathEvent::NetworkGenerationAdvanced { .. } => "network_generation_advanced",
        PathEvent::RemoteCandidateEpochAdvanced { .. } => "remote_candidate_epoch_advanced",
        PathEvent::RelayTransportReady { .. } => "relay_transport_ready",
        PathEvent::RelayPeerConfirmed { .. } => "relay_peer_confirmed",
        PathEvent::RelayBusinessUsable { .. } => "relay_business_usable",
        PathEvent::RelayHealthObserved { .. } => "relay_health_observed",
        PathEvent::RelayTransportLost { .. } => "relay_transport_lost",
        PathEvent::RelayPathFailed { .. } => "relay_path_failed",
        PathEvent::DirectProbeStarted { .. } => "direct_probe_started",
        PathEvent::DirectValidationStarted { .. } => "direct_validation_started",
        PathEvent::DirectCommitted { .. } => "direct_committed",
        PathEvent::DirectProbeFailed { .. } => "direct_probe_failed",
        PathEvent::DirectPathFailed { .. } => "direct_path_failed",
        PathEvent::DirectAttemptCancelled { .. } => "direct_attempt_cancelled",
        PathEvent::DirectRetryScheduled { .. } => "direct_retry_scheduled",
        PathEvent::CompatibilityStateRequested { .. } => "compatibility_state_requested",
    }
}

fn event_reason_code(event: &PathEvent) -> &'static str {
    event_kind(event)
}

fn decision_label(decision: PathTransitionDecision) -> &'static str {
    match decision {
        PathTransitionDecision::Applied => "applied",
        PathTransitionDecision::AcceptedObservation => "accepted_observation",
        PathTransitionDecision::Duplicate => "duplicate",
        PathTransitionDecision::RejectedNetworkGeneration => "rejected_network_generation",
        PathTransitionDecision::RejectedPeerSessionGeneration => "rejected_peer_session_generation",
        PathTransitionDecision::RejectedRemoteCandidateEpoch => "rejected_remote_candidate_epoch",
        PathTransitionDecision::RejectedPeerOffline => "rejected_peer_offline",
        PathTransitionDecision::RejectedDirectValidationIdentity => {
            "rejected_direct_validation_identity"
        }
        PathTransitionDecision::RejectedRelayConnectionIdentity => {
            "rejected_relay_connection_identity"
        }
        PathTransitionDecision::RejectedRevision => "rejected_revision",
        PathTransitionDecision::RejectedIllegalTransition => "rejected_illegal_transition",
    }
}

fn lifecycle_label(lifecycle: PeerPathLifecycle) -> &'static str {
    match lifecycle {
        PeerPathLifecycle::Unbound => "unbound",
        PeerPathLifecycle::Online => "online",
        PeerPathLifecycle::Offline => "offline",
    }
}

fn direct_state_label(state: &DirectPathState) -> &'static str {
    match state {
        DirectPathState::Idle => "idle",
        DirectPathState::Probing { .. } => "probing",
        DirectPathState::Validating(_) => "validating",
        DirectPathState::Committed(_) => "committed",
    }
}

fn relay_state_label(state: &RelayPathState) -> &'static str {
    match state {
        RelayPathState::Unavailable => "unavailable",
        RelayPathState::Ready(_) => "ready",
        RelayPathState::Confirmed(_) => "confirmed",
        RelayPathState::Usable(_) => "usable",
    }
}

fn recovery_state_label(state: &PathRecoveryState) -> &'static str {
    match state {
        PathRecoveryState::Stable => "stable",
        PathRecoveryState::Degraded { .. } => "degraded",
        PathRecoveryState::Recovering { .. } => "recovering",
    }
}

fn duration_millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{
        DirectAttemptNumber, DirectValidationIdentity, PathEpoch, PathEvent, PeerSessionGeneration,
    };

    fn epoch() -> PathEpoch {
        PathEpoch::new(7, PeerSessionGeneration::for_test(3), 11)
    }

    #[test]
    fn path_observability_metrics_are_bounded() {
        let mut connection = PeerConnection::new("peer-sensitive-id", "10.20.0.2");
        connection.commit_path_transition(PathEvent::PeerOnline { epoch: epoch() }, |_| {});
        for attempt in 0..(PATH_TRANSITION_EVENT_LIMIT as u32 + 9) {
            connection.commit_path_transition(
                PathEvent::DirectProbeStarted {
                    epoch: epoch(),
                    attempt: DirectAttemptNumber(u64::from(attempt.saturating_add(1))),
                },
                |_| {},
            );
            connection
                .commit_path_transition(PathEvent::DirectProbeFailed { epoch: epoch() }, |_| {});
        }
        let snapshot = connection.path_observability.snapshot(&connection);
        assert_eq!(snapshot.schema_version, PATH_OBSERVABILITY_SCHEMA_VERSION);
        assert_eq!(snapshot.transitions.len(), PATH_TRANSITION_EVENT_LIMIT);
        assert!(snapshot.metrics.dropped_transition_events > 0);
        assert_eq!(
            snapshot.metrics.direct_time_to_connect_ms.buckets.len(),
            DIRECT_CONNECT_HISTOGRAM_BOUNDS_MS.len() + 1
        );
        let json = serde_json::to_string(&snapshot).expect("snapshot serializes");
        assert!(!json.contains("peer-sensitive-id"));
        assert!(!json.contains("10.20.0.2"));
    }

    #[test]
    fn path_observability_tests_direct_to_relay_to_direct_timeline() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        use super::super::path_state_machine::RelayConnectionIncarnation;
        use crate::peer::RelayConnectionIdentity;

        let mut connection = PeerConnection::new("peer-a", "10.20.0.2");
        let epoch = epoch();
        connection.commit_path_transition(PathEvent::PeerOnline { epoch }, |_| {});
        let relay = RelayConnectionIdentity {
            epoch,
            endpoint: "relay.test:443".to_string(),
            incarnation: RelayConnectionIncarnation::Known(9),
        };
        connection.commit_path_transition(
            PathEvent::RelayPeerConfirmed {
                relay: relay.clone(),
            },
            |_| {},
        );

        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40001);
        connection.commit_path_transition(
            PathEvent::DirectValidationStarted {
                validation: DirectValidationIdentity::owned(epoch, 1, Some(7), Some(endpoint)),
            },
            |_| {},
        );
        connection.commit_path_transition(
            PathEvent::DirectCommitted {
                validation: DirectValidationIdentity::authenticated_ack(
                    epoch,
                    1,
                    7,
                    Some(endpoint),
                    endpoint,
                ),
            },
            |_| {},
        );
        connection.commit_path_transition(PathEvent::DirectPathFailed { epoch }, |_| {});
        connection.commit_path_transition(
            PathEvent::DirectValidationStarted {
                validation: DirectValidationIdentity::owned(epoch, 2, Some(8), Some(endpoint)),
            },
            |_| {},
        );
        connection.commit_path_transition(
            PathEvent::DirectCommitted {
                validation: DirectValidationIdentity::authenticated_ack(
                    epoch,
                    2,
                    8,
                    Some(endpoint),
                    endpoint,
                ),
            },
            |_| {},
        );

        let snapshot = connection.path_observability.snapshot(&connection);
        assert!(snapshot.metrics.path_changes >= 3);
        assert_eq!(snapshot.metrics.direct_successes, 2);
        assert!(snapshot
            .transitions
            .iter()
            .any(|event| event.previous_path == Some(NetworkPath::Direct)
                && event.current_path == Some(NetworkPath::Relay)));
        assert!(snapshot
            .transitions
            .iter()
            .any(|event| event.previous_path == Some(NetworkPath::Relay)
                && event.current_path == Some(NetworkPath::Direct)));
    }

    #[test]
    fn rejected_and_duplicate_events_are_observable_without_side_effect_labels() {
        let mut connection = PeerConnection::new("peer-a", "10.20.0.2");
        let epoch = epoch();
        connection.commit_path_transition(PathEvent::PeerOnline { epoch }, |_| {});
        connection.commit_path_transition(PathEvent::PeerOnline { epoch }, |_| {});
        connection.commit_path_transition(
            PathEvent::DirectProbeStarted {
                epoch: PathEpoch::new(6, PeerSessionGeneration::for_test(3), 11),
                attempt: DirectAttemptNumber(1),
            },
            |_| {},
        );
        let snapshot = connection.path_observability.snapshot(&connection);
        assert!(snapshot.metrics.duplicate_events >= 1);
        assert!(snapshot.metrics.rejected_transitions >= 1);
        assert!(PATH_OBSERVABILITY_METRIC_NAMES
            .iter()
            .all(|name| !name.contains("peer") && !name.contains("endpoint")));
    }
}
