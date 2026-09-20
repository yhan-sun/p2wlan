//! Wire DTOs for authoritative active-path telemetry.
//!
//! Strict privacy policy: Telemetry payloads contain only abstract path
//! classifications ("direct", "relay", "none"), lifecycle states, generation
//! counters, revisions, bounded latency EWMA/samples, and reason codes.
//! IP addresses, ports, candidate socket addresses, WireGuard keys, and packet
//! payloads are strictly forbidden and never serialized.

use serde::{Deserialize, Serialize};

use super::super::path_observability::PathObservabilitySnapshot;
use super::super::types::NetworkPath;

/// Bounded transition history item sent in wire telemetry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathTransitionTeleItem {
    pub revision: u64,
    pub event_kind: String,
    pub decision: String,
    pub reason_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_path: Option<String>,
    pub age_ms: u64,
}

/// Authoritative active-path observation for a single remote peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathTelemetryObservation {
    pub remote_device_id: String,
    pub network_id: String,
    pub current_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
    pub transition_reason: String,
    pub network_generation: u64,
    pub peer_session_generation: u64,
    pub remote_candidate_epoch: u64,
    pub observation_revision: u64,
    pub direct_state: String,
    pub relay_state: String,
    pub path_age_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_direct_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_relay_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_mtu: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transitions: Vec<PathTransitionTeleItem>,
}

/// Batch of active-path telemetry observations sent to the Control server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathTelemetryPayload {
    pub device_id: String,
    pub network_id: String,
    pub sent_at: i64,
    pub observations: Vec<PathTelemetryObservation>,
}

/// WebSocket signaling frame wrapping a path telemetry payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathTelemetryFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub payload: PathTelemetryPayload,
}

/// WebSocket signaling frame acknowledging receipt of path telemetry.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PathTelemetryAckFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    #[serde(default)]
    pub sent_at: i64,
}

/// Convert a NetworkPath enum into a stable wire string.
pub fn path_to_wire(path: Option<NetworkPath>) -> String {
    match path {
        Some(NetworkPath::Direct) => "direct".to_string(),
        Some(NetworkPath::Relay) => "relay".to_string(),
        None => "none".to_string(),
    }
}

/// Convert an optional NetworkPath into an optional wire string.
pub fn opt_path_to_wire(path: Option<NetworkPath>) -> Option<String> {
    path.map(|p| match p {
        NetworkPath::Direct => "direct".to_string(),
        NetworkPath::Relay => "relay".to_string(),
    })
}

/// Convert an in-memory PathObservabilitySnapshot into a wire-ready PathTelemetryObservation.
pub fn observation_from_snapshot(
    remote_device_id: &str,
    network_id: &str,
    snapshot: &PathObservabilitySnapshot,
) -> PathTelemetryObservation {
    let (network_gen, peer_session_gen, remote_cand_epoch) = match &snapshot.network_epoch {
        Some(epoch) => (
            epoch.network_generation,
            epoch.peer_session_generation,
            epoch.remote_candidate_epoch,
        ),
        None => (0, 0, 0),
    };

    let direct_latency = snapshot
        .direct_health
        .latency_ms
        .or(snapshot.direct_health.rtt_ewma_ms);
    let relay_latency = snapshot
        .relay_health
        .latency_ms
        .or(snapshot.relay_health.rtt_ewma_ms);

    // Bound transitions to at most 32 recent items
    let transitions = snapshot
        .transitions
        .iter()
        .take(32)
        .map(|t| PathTransitionTeleItem {
            revision: t.revision,
            event_kind: t.event_kind.clone(),
            decision: t.decision.clone(),
            reason_code: t.reason_code.clone(),
            previous_path: opt_path_to_wire(t.previous_path),
            current_path: opt_path_to_wire(t.current_path),
            age_ms: t.age_ms,
        })
        .collect();

    PathTelemetryObservation {
        remote_device_id: remote_device_id.to_string(),
        network_id: network_id.to_string(),
        current_path: path_to_wire(snapshot.current_path),
        previous_path: opt_path_to_wire(snapshot.previous_path),
        transition_reason: snapshot.transition_reason.clone(),
        network_generation: network_gen,
        peer_session_generation: peer_session_gen,
        remote_candidate_epoch: remote_cand_epoch,
        observation_revision: snapshot.path_state_revision,
        direct_state: snapshot.direct_state.clone(),
        relay_state: snapshot.relay_state.clone(),
        path_age_ms: snapshot.path_age_ms,
        last_direct_latency_ms: direct_latency,
        last_relay_latency_ms: relay_latency,
        selected_mtu: snapshot.selected_path_mtu,
        transitions,
    }
}
