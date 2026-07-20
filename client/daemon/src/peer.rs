//! Peer connection manager.
//!
//! Manages connections to other nodes in the virtual network:
//! - Tracks active peer tunnels (WireGuard sessions)
//! - Handles ICE candidate exchange for NAT traversal
//! - Falls back to relay when direct connection fails
//! - Routes packets between TUN device and peer tunnels

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

use crate::config::Config;
use crate::control::PeerInfo;

const DIRECT_TRIAL_WINDOW: Duration = Duration::from_secs(10);
const DIRECT_RETRY_BACKOFF_MAX_EXPONENT: u32 = 3;
const DIRECT_TO_RELAY_HYSTERESIS_MARGIN: i32 = 15;
const DIRECT_TRIAL_MIN_SCORE: i32 = 40;

/// Stable reason code emitted when a local network generation changes.
pub const REASON_NETWORK_GENERATION_CHANGED: &str = "network_generation_changed";
/// Stable reason code for direct path probe timeout/failure.
pub const REASON_DIRECT_PROBE_FAILED: &str = "direct_probe_failed";
/// Stable reason code for direct path send failure.
pub const REASON_DIRECT_SEND_FAILED: &str = "direct_send_failed";
/// Stable reason code for WireGuard handshake timeout.
pub const REASON_HANDSHAKE_TIMEOUT: &str = "handshake_timeout";
/// Path selector chose a confirmed Direct UDP pair.
pub const REASON_PATH_DIRECT_CONFIRMED: &str = "path_direct_confirmed";
/// Path selector chose a recent Direct trial while Relay stays available.
pub const REASON_PATH_DIRECT_TRIAL: &str = "path_direct_trial";
/// Path selector chose Direct because Relay is unavailable.
pub const REASON_PATH_RELAY_UNAVAILABLE: &str = "path_relay_unavailable";
/// Path selector chose Relay because Direct is disabled by policy.
pub const REASON_PATH_DIRECT_DISABLED: &str = "path_direct_disabled";
/// Path selector chose Relay because Direct has no candidate endpoint.
pub const REASON_PATH_DIRECT_NO_ENDPOINT: &str = "path_direct_no_endpoint";
/// Path selector chose Relay because Direct has not been confirmed.
pub const REASON_PATH_DIRECT_NOT_CONFIRMED: &str = "path_direct_not_confirmed";
/// Path selector chose Relay because Direct quality is worse than Relay.
pub const REASON_PATH_DIRECT_DEGRADED: &str = "path_direct_degraded";
/// Path selector found no usable Direct or Relay path.
pub const REASON_PATH_UNAVAILABLE: &str = "path_unavailable";

// ============================================================
// Connection State
// ============================================================

/// The state of a peer connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// No connection attempted yet.
    Idle,
    /// Currently performing NAT detection / ICE candidate gathering.
    Connecting,
    /// Attempting UDP hole punching.
    HolePunching,
    /// Direct P2P connection established.
    Direct,
    /// Direct connection failed, falling back to relay.
    FallbackToRelay,
    /// Connected via relay server.
    Relay,
    /// Connection failed.
    Failed,
    /// Connection closed.
    Closed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connecting => write!(f, "connecting"),
            Self::HolePunching => write!(f, "hole_punching"),
            Self::Direct => write!(f, "direct"),
            Self::FallbackToRelay => write!(f, "fallback_to_relay"),
            Self::Relay => write!(f, "relay"),
            Self::Failed => write!(f, "failed"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

/// The transport path used for peer traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPath {
    /// Direct UDP path.
    Direct,
    /// Relay fallback path.
    Relay,
}

impl std::fmt::Display for NetworkPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Relay => write!(f, "relay"),
        }
    }
}

/// Explicit result from the data path selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSelection {
    /// Selected path, if any path can be attempted.
    pub path: Option<NetworkPath>,
    /// Direct UDP endpoint to use when `path == Direct`.
    pub direct_endpoint: Option<SocketAddr>,
    /// Stable machine-readable reason code.
    pub reason_code: &'static str,
    /// Human-readable reason for diagnostics and logs.
    pub reason: String,
    /// Whether the chosen Direct path is fully confirmed.
    pub direct_confirmed: bool,
    /// Explainable Direct path score, when a Direct endpoint exists.
    pub direct_score: Option<PathScore>,
    /// Explainable Relay path score, when Relay is available.
    pub relay_score: Option<PathScore>,
}

impl PathSelection {
    fn direct(
        endpoint: SocketAddr,
        reason_code: &'static str,
        reason: impl Into<String>,
        direct_confirmed: bool,
    ) -> Self {
        Self {
            path: Some(NetworkPath::Direct),
            direct_endpoint: Some(endpoint),
            reason_code,
            reason: reason.into(),
            direct_confirmed,
            direct_score: None,
            relay_score: None,
        }
    }

    fn relay(reason_code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            path: Some(NetworkPath::Relay),
            direct_endpoint: None,
            reason_code,
            reason: reason.into(),
            direct_confirmed: false,
            direct_score: None,
            relay_score: None,
        }
    }

    fn unavailable(reason_code: &'static str, reason: impl Into<String>) -> Self {
        Self {
            path: None,
            direct_endpoint: None,
            reason_code,
            reason: reason.into(),
            direct_confirmed: false,
            direct_score: None,
            relay_score: None,
        }
    }

    fn with_scores(
        mut self,
        direct_score: Option<PathScore>,
        relay_score: Option<PathScore>,
    ) -> Self {
        self.direct_score = direct_score;
        self.relay_score = relay_score;
        self
    }
}

/// Explainable score used by the path selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathScore {
    pub path: NetworkPath,
    pub score: i32,
    pub reachable: bool,
    pub reachability_score: i32,
    pub preference_score: i32,
    pub latency_score: i32,
    pub stability_score: i32,
    pub penalty_score: i32,
    pub reason: String,
}

/// Serializable path selector diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathSelectionDiagnostics {
    pub path: Option<NetworkPath>,
    pub direct_endpoint: Option<String>,
    pub reason_code: String,
    pub reason: String,
    pub direct_confirmed: bool,
    pub direct_score: Option<PathScoreDiagnostics>,
    pub relay_score: Option<PathScoreDiagnostics>,
}

impl From<&PathSelection> for PathSelectionDiagnostics {
    fn from(selection: &PathSelection) -> Self {
        Self {
            path: selection.path,
            direct_endpoint: selection
                .direct_endpoint
                .map(|endpoint| endpoint.to_string()),
            reason_code: selection.reason_code.to_string(),
            reason: selection.reason.clone(),
            direct_confirmed: selection.direct_confirmed,
            direct_score: selection
                .direct_score
                .as_ref()
                .map(PathScoreDiagnostics::from),
            relay_score: selection
                .relay_score
                .as_ref()
                .map(PathScoreDiagnostics::from),
        }
    }
}

/// Serializable path score diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathScoreDiagnostics {
    pub path: NetworkPath,
    pub score: i32,
    pub reachable: bool,
    pub reachability_score: i32,
    pub preference_score: i32,
    pub latency_score: i32,
    pub stability_score: i32,
    pub penalty_score: i32,
    pub reason: String,
}

impl From<&PathScore> for PathScoreDiagnostics {
    fn from(score: &PathScore) -> Self {
        Self {
            path: score.path,
            score: score.score,
            reachable: score.reachable,
            reachability_score: score.reachability_score,
            preference_score: score.preference_score,
            latency_score: score.latency_score,
            stability_score: score.stability_score,
            penalty_score: score.penalty_score,
            reason: score.reason.clone(),
        }
    }
}

/// Reachability state for one direct candidate pair.
///
/// The daemon currently has a single local UDP socket per network generation,
/// so the pair key is represented as `(local network generation, remote endpoint)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidatePairState {
    /// Candidate is known but not scheduled yet.
    Frozen,
    /// Candidate is ready for probing.
    Waiting,
    /// Probe traffic has been sent or an inbound punch was observed.
    Probing,
    /// Bidirectional probe succeeded but the pair is not selected.
    Succeeded,
    /// Selected direct traffic path.
    Selected,
    /// Probe failed before selection.
    Failed,
    /// Previously usable pair became stale or unhealthy.
    Degraded,
}

/// State and health for one direct candidate pair.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Remote UDP candidate endpoint.
    pub remote_endpoint: SocketAddr,
    /// Local network generation this pair belongs to.
    pub local_generation: u64,
    /// Current reachability state.
    pub state: CandidatePairState,
    /// First successful bidirectional probe or encrypted packet.
    pub first_success_at: Option<Instant>,
    /// Most recent successful bidirectional probe or encrypted packet.
    pub last_success_at: Option<Instant>,
    /// Most recent failed probe/path event.
    pub last_failure_at: Option<Instant>,
    /// Consecutive pair-level failures since the last success.
    pub consecutive_failures: u32,
    /// Stable machine-readable reason for the last failure.
    pub last_error_code: Option<String>,
    /// Human-readable last failure detail.
    pub last_error: Option<String>,
    /// Most recent RTT measurement for this pair.
    pub rtt_ms: Option<u64>,
    /// Smoothed RTT estimate for this pair.
    pub rtt_ewma_ms: Option<u64>,
    /// Smoothed absolute RTT variation for this pair.
    pub jitter_ms: Option<u64>,
    /// Successful reachability samples observed for this pair.
    pub success_count: u64,
    /// Failed reachability samples observed for this pair.
    pub failure_count: u64,
}

impl CandidatePair {
    fn new(remote_endpoint: SocketAddr, local_generation: u64) -> Self {
        Self {
            remote_endpoint,
            local_generation,
            state: CandidatePairState::Waiting,
            first_success_at: None,
            last_success_at: None,
            last_failure_at: None,
            consecutive_failures: 0,
            last_error_code: None,
            last_error: None,
            rtt_ms: None,
            rtt_ewma_ms: None,
            jitter_ms: None,
            success_count: 0,
            failure_count: 0,
        }
    }

    fn record_probing(&mut self) {
        if !matches!(
            self.state,
            CandidatePairState::Succeeded | CandidatePairState::Selected
        ) {
            self.state = CandidatePairState::Probing;
        }
    }

    fn record_success(&mut self, latency: Option<Duration>, selected: bool) {
        let now = Instant::now();
        if self.first_success_at.is_none() {
            self.first_success_at = Some(now);
        }
        self.last_success_at = Some(now);
        self.consecutive_failures = 0;
        self.success_count = self.success_count.saturating_add(1);
        self.last_error_code = None;
        self.last_error = None;
        if let Some(latency) = latency {
            let latency_ms = duration_millis(latency);
            self.rtt_ms = Some(latency_ms);
            update_latency_ewma(&mut self.rtt_ewma_ms, &mut self.jitter_ms, latency_ms);
        }
        self.state = if selected {
            CandidatePairState::Selected
        } else {
            CandidatePairState::Succeeded
        };
    }

    fn record_failure(&mut self, code: impl Into<String>, reason: impl Into<String>) {
        self.last_failure_at = Some(Instant::now());
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_error_code = Some(code.into());
        self.last_error = Some(reason.into());
        self.state = if matches!(
            self.state,
            CandidatePairState::Succeeded | CandidatePairState::Selected
        ) {
            CandidatePairState::Degraded
        } else {
            CandidatePairState::Failed
        };
    }

    fn record_generation_change(&mut self, reason: impl Into<String>) {
        self.record_failure(REASON_NETWORK_GENERATION_CHANGED, reason);
        self.state = CandidatePairState::Degraded;
    }

    fn failure_age(&self) -> Option<Duration> {
        self.last_failure_at
            .map(|last_failure| last_failure.elapsed())
    }

    fn first_success_age(&self) -> Option<Duration> {
        self.first_success_at
            .map(|first_success| first_success.elapsed())
    }

    fn success_age(&self) -> Option<Duration> {
        self.last_success_at
            .map(|last_success| last_success.elapsed())
    }
}

/// Health counters for one transport path.
#[derive(Debug, Clone, Default)]
pub struct PathHealth {
    /// Last successful path event.
    pub last_success_at: Option<Instant>,
    /// Last failed path event.
    pub last_failure_at: Option<Instant>,
    /// Consecutive failures since the last success.
    pub consecutive_failures: u32,
    /// Last diagnostic error for this path.
    pub last_error: Option<String>,
    /// Stable machine-readable reason for the last failure.
    pub last_error_code: Option<String>,
    /// Most recent measured round-trip time for this path.
    pub latency_ms: Option<u64>,
    /// Smoothed RTT estimate for this path.
    pub rtt_ewma_ms: Option<u64>,
    /// Smoothed absolute RTT variation for this path.
    pub jitter_ms: Option<u64>,
    /// Successful path samples observed.
    pub success_count: u64,
    /// Failed path samples observed.
    pub failure_count: u64,
}

impl PathHealth {
    fn record_success(&mut self) {
        self.last_success_at = Some(Instant::now());
        self.consecutive_failures = 0;
        self.success_count = self.success_count.saturating_add(1);
        self.last_error = None;
        self.last_error_code = None;
    }

    fn record_success_with_latency(&mut self, latency: Duration) {
        self.record_success();
        let latency_ms = duration_millis(latency);
        self.latency_ms = Some(latency_ms);
        update_latency_ewma(&mut self.rtt_ewma_ms, &mut self.jitter_ms, latency_ms);
    }

    fn record_failure(&mut self, code: impl Into<String>, reason: impl Into<String>) {
        self.last_failure_at = Some(Instant::now());
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.failure_count = self.failure_count.saturating_add(1);
        self.last_error_code = Some(code.into());
        self.last_error = Some(reason.into());
    }

    fn record_generation_change(&mut self, reason: impl Into<String>) {
        self.last_success_at = None;
        self.latency_ms = None;
        self.rtt_ewma_ms = None;
        self.jitter_ms = None;
        self.consecutive_failures = 0;
        self.record_failure(REASON_NETWORK_GENERATION_CHANGED, reason);
    }

    fn failure_age(&self) -> Option<Duration> {
        self.last_failure_at
            .map(|last_failure| last_failure.elapsed())
    }

    fn success_age(&self) -> Option<Duration> {
        self.last_success_at
            .map(|last_success| last_success.elapsed())
    }

    fn retry_after(&self, base: Duration) -> Duration {
        if base.is_zero() || self.consecutive_failures <= 1 {
            return base;
        }
        let exponent = self
            .consecutive_failures
            .saturating_sub(1)
            .min(DIRECT_RETRY_BACKOFF_MAX_EXPONENT);
        base.checked_mul(1_u32 << exponent).unwrap_or(Duration::MAX)
    }

    fn retry_remaining(&self, base: Duration) -> Duration {
        let retry_after = self.retry_after(base);
        match self.failure_age() {
            Some(age) if age < retry_after => retry_after - age,
            _ => Duration::ZERO,
        }
    }

    fn retry_due(&self, base: Duration) -> bool {
        self.retry_remaining(base).is_zero()
    }
}

// ============================================================
// Peer Connection
// ============================================================

/// Information about a connection to a specific peer.
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Peer node ID.
    pub node_id: String,
    /// Human-readable peer device name.
    pub device_name: String,
    /// Peer's virtual IP.
    pub virtual_ip: String,
    /// Peer's public endpoint (ip:port) if known.
    pub endpoint: Option<SocketAddr>,
    /// Peer's NAT type.
    pub nat_type: String,
    /// Current connection state.
    pub state: ConnectionState,
    /// When the connection was established.
    pub connected_at: Option<Instant>,
    /// Bytes sent to this peer.
    pub bytes_sent: u64,
    /// Bytes received from this peer.
    pub bytes_received: u64,
    /// Which relay server is being used (if connected via relay).
    pub relay_server: Option<String>,
    /// ICE candidates for this peer.
    pub candidates: Vec<String>,
    /// Direct UDP path health.
    pub direct_health: PathHealth,
    /// Relay path health.
    pub relay_health: PathHealth,
    /// Local network generation in which the direct path was last confirmed.
    pub direct_generation: u64,
    /// Direct candidate-pair reachability table.
    pub candidate_pairs: Vec<CandidatePair>,
    /// Last selector decision made for outbound peer traffic.
    pub last_path_selection: Option<PathSelection>,
}

impl PeerConnection {
    /// Create a new peer connection in Idle state.
    pub fn new(node_id: &str, virtual_ip: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            device_name: String::new(),
            virtual_ip: virtual_ip.to_string(),
            endpoint: None,
            nat_type: String::new(),
            state: ConnectionState::Idle,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            relay_server: None,
            candidates: Vec::new(),
            direct_health: PathHealth::default(),
            relay_health: PathHealth::default(),
            direct_generation: 0,
            candidate_pairs: Vec::new(),
            last_path_selection: None,
        }
    }

    /// Whether the connection is active (direct or relay).
    pub fn is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Direct | ConnectionState::Relay)
    }

    /// Whether the connection is via relay.
    pub fn is_relay(&self) -> bool {
        self.state == ConnectionState::Relay
    }

    /// Transition to a new state.
    pub fn transition(&mut self, new_state: ConnectionState) {
        if self.state != new_state {
            info!(
                "Peer {} state: {} → {}",
                self.node_id, self.state, new_state
            );
        }
        if (new_state == ConnectionState::Direct || new_state == ConnectionState::Relay)
            && self.connected_at.is_none()
        {
            self.connected_at = Some(Instant::now());
        }
        self.state = new_state;
    }

    /// Current selected traffic path, if active.
    pub fn active_path(&self) -> Option<NetworkPath> {
        match self.state {
            ConnectionState::Direct => Some(NetworkPath::Direct),
            ConnectionState::Relay => Some(NetworkPath::Relay),
            _ => None,
        }
    }

    /// Record bytes sent.
    pub fn record_sent(&mut self, n: u64) {
        self.bytes_sent += n;
    }

    /// Record bytes received.
    pub fn record_received(&mut self, n: u64) {
        self.bytes_received += n;
    }

    fn candidate_endpoints(&self) -> Vec<SocketAddr> {
        let mut endpoints = Vec::new();
        for candidate in &self.candidates {
            if let Ok(endpoint) = candidate.parse::<SocketAddr>() {
                if !endpoints.contains(&endpoint) {
                    endpoints.push(endpoint);
                }
            }
        }
        if let Some(endpoint) = self.endpoint {
            if !endpoints.contains(&endpoint) {
                endpoints.push(endpoint);
            }
        }
        endpoints
    }

    fn ensure_candidate_pair(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
    ) -> &mut CandidatePair {
        if let Some(index) = self.candidate_pairs.iter().position(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
        }) {
            return &mut self.candidate_pairs[index];
        }
        self.candidate_pairs
            .push(CandidatePair::new(endpoint, local_generation));
        self.candidate_pairs
            .last_mut()
            .expect("candidate pair inserted")
    }

    fn ensure_current_candidate_pairs(&mut self, local_generation: u64) {
        for endpoint in self.candidate_endpoints() {
            self.ensure_candidate_pair(endpoint, local_generation);
        }
    }

    fn candidate_probe_endpoints(&mut self, local_generation: u64) -> Vec<SocketAddr> {
        self.ensure_current_candidate_pairs(local_generation);
        let endpoints = self.candidate_endpoints();
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && endpoints.contains(&pair.remote_endpoint)
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| {
            candidate_pair_probe_rank(a.state)
                .cmp(&candidate_pair_probe_rank(b.state))
                .then_with(|| {
                    a.rtt_ewma_ms
                        .or(a.rtt_ms)
                        .unwrap_or(u64::MAX)
                        .cmp(&b.rtt_ewma_ms.or(b.rtt_ms).unwrap_or(u64::MAX))
                })
                .then_with(|| {
                    a.jitter_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.jitter_ms.unwrap_or(u64::MAX))
                })
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });
        pairs.into_iter().map(|pair| pair.remote_endpoint).collect()
    }

    fn direct_endpoint_for_send(&self, local_generation: u64) -> Option<SocketAddr> {
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && matches!(
                        pair.state,
                        CandidatePairState::Selected
                            | CandidatePairState::Succeeded
                            | CandidatePairState::Probing
                            | CandidatePairState::Waiting
                    )
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| {
            candidate_pair_send_rank(a.state)
                .cmp(&candidate_pair_send_rank(b.state))
                .then_with(|| {
                    a.rtt_ewma_ms
                        .or(a.rtt_ms)
                        .unwrap_or(u64::MAX)
                        .cmp(&b.rtt_ewma_ms.or(b.rtt_ms).unwrap_or(u64::MAX))
                })
                .then_with(|| {
                    a.jitter_ms
                        .unwrap_or(u64::MAX)
                        .cmp(&b.jitter_ms.unwrap_or(u64::MAX))
                })
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });

        pairs
            .first()
            .map(|pair| pair.remote_endpoint)
            .or(self.endpoint)
    }

    fn has_current_direct_pair_for_data(&self, local_generation: u64) -> bool {
        self.candidate_pairs.iter().any(|pair| {
            pair.local_generation == local_generation
                && matches!(
                    pair.state,
                    CandidatePairState::Selected
                        | CandidatePairState::Succeeded
                        | CandidatePairState::Probing
                )
        })
    }

    fn direct_path_score(
        &self,
        local_generation: u64,
        direct_endpoint: Option<SocketAddr>,
        confirmed: bool,
        trial: bool,
    ) -> Option<PathScore> {
        let direct_endpoint = direct_endpoint?;
        let pair = self.candidate_pairs.iter().find(|pair| {
            pair.local_generation == local_generation && pair.remote_endpoint == direct_endpoint
        });

        let reachable = confirmed || trial;
        let reachability_score = if confirmed {
            80
        } else if trial {
            50
        } else {
            0
        };
        let preference_score = 10;
        let latency_ms = pair
            .and_then(|pair| pair.rtt_ewma_ms.or(pair.rtt_ms))
            .or(self
                .direct_health
                .rtt_ewma_ms
                .or(self.direct_health.latency_ms));
        let jitter_ms = pair
            .and_then(|pair| pair.jitter_ms)
            .or(self.direct_health.jitter_ms);
        let latency_score = latency_score(latency_ms);
        let jitter_penalty = jitter_penalty(jitter_ms);
        let stability_score = stability_score(
            self.direct_health.success_count,
            self.direct_health.consecutive_failures,
            self.direct_health.failure_count,
        );
        let migration_penalty = if trial && !confirmed { -5 } else { 0 };
        let penalty_score = jitter_penalty + migration_penalty;
        let score =
            reachability_score + preference_score + latency_score + stability_score + penalty_score;
        Some(PathScore {
            path: NetworkPath::Direct,
            score,
            reachable,
            reachability_score,
            preference_score,
            latency_score,
            stability_score,
            penalty_score,
            reason: format!(
                "reachable={reachable} confirmed={confirmed} trial={trial} rtt={} jitter={} failures={}",
                format_optional_ms(latency_ms),
                format_optional_ms(jitter_ms),
                self.direct_health.consecutive_failures,
            ),
        })
    }

    fn relay_path_score(&self, relay_available: bool) -> Option<PathScore> {
        if !relay_available {
            return None;
        }
        let reachability_score = 55;
        let preference_score = 0;
        let latency_score = latency_score(
            self.relay_health
                .rtt_ewma_ms
                .or(self.relay_health.latency_ms),
        );
        let jitter_penalty = jitter_penalty(self.relay_health.jitter_ms);
        let stability_score = stability_score(
            self.relay_health.success_count,
            self.relay_health.consecutive_failures,
            self.relay_health.failure_count,
        );
        let penalty_score = jitter_penalty;
        let score =
            reachability_score + preference_score + latency_score + stability_score + penalty_score;
        Some(PathScore {
            path: NetworkPath::Relay,
            score,
            reachable: true,
            reachability_score,
            preference_score,
            latency_score,
            stability_score,
            penalty_score,
            reason: format!(
                "relay_available=true rtt={} jitter={} failures={}",
                format_optional_ms(
                    self.relay_health
                        .rtt_ewma_ms
                        .or(self.relay_health.latency_ms)
                ),
                format_optional_ms(self.relay_health.jitter_ms),
                self.relay_health.consecutive_failures,
            ),
        })
    }

    fn select_path_for_data(
        &self,
        local_generation: u64,
        prefer_direct: bool,
        relay_available: bool,
    ) -> PathSelection {
        let direct_endpoint = self.direct_endpoint_for_send(local_generation);
        let relay_score = self.relay_path_score(relay_available);

        if !prefer_direct {
            return if relay_available {
                PathSelection::relay(
                    REASON_PATH_DIRECT_DISABLED,
                    "relay policy disables direct UDP",
                )
                .with_scores(None, relay_score)
            } else if let Some(endpoint) = direct_endpoint {
                let direct_score =
                    self.direct_path_score(local_generation, Some(endpoint), false, false);
                PathSelection::direct(
                    endpoint,
                    REASON_PATH_RELAY_UNAVAILABLE,
                    "relay unavailable; attempting best-effort direct UDP",
                    false,
                )
                .with_scores(direct_score, None)
            } else {
                PathSelection::unavailable(
                    REASON_PATH_UNAVAILABLE,
                    "relay unavailable and no direct UDP endpoint exists",
                )
                .with_scores(None, None)
            };
        }

        let Some(endpoint) = direct_endpoint else {
            return if relay_available {
                PathSelection::relay(
                    REASON_PATH_DIRECT_NO_ENDPOINT,
                    "direct UDP has no candidate endpoint",
                )
                .with_scores(None, relay_score)
            } else {
                PathSelection::unavailable(
                    REASON_PATH_UNAVAILABLE,
                    "no relay and no direct UDP endpoint exists",
                )
                .with_scores(None, None)
            };
        };

        let direct_pair_ready = self.has_current_direct_pair_for_data(local_generation);
        let confirmed_direct = self.state == ConnectionState::Direct && direct_pair_ready;
        let trial_direct = direct_pair_ready
            && self.direct_health.consecutive_failures == 0
            && self
                .direct_health
                .success_age()
                .map(|age| age <= DIRECT_TRIAL_WINDOW)
                .unwrap_or(false);
        let direct_score = self.direct_path_score(
            local_generation,
            Some(endpoint),
            confirmed_direct,
            trial_direct,
        );

        if self.state == ConnectionState::Direct && direct_pair_ready {
            if let (Some(direct_score), Some(relay_score)) = (&direct_score, &relay_score) {
                if direct_score.score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN < relay_score.score {
                    return PathSelection::relay(
                        REASON_PATH_DIRECT_DEGRADED,
                        format!(
                            "direct score {} is below relay score {} after hysteresis",
                            direct_score.score, relay_score.score
                        ),
                    )
                    .with_scores(Some(direct_score.clone()), Some(relay_score.clone()));
                }
            }
            return PathSelection::direct(
                endpoint,
                REASON_PATH_DIRECT_CONFIRMED,
                direct_score
                    .as_ref()
                    .map(|score| format!("direct UDP pair is confirmed; score={}", score.score))
                    .unwrap_or_else(|| "direct UDP pair is confirmed".to_string()),
                true,
            )
            .with_scores(direct_score, relay_score);
        }

        if !relay_available {
            return PathSelection::direct(
                endpoint,
                REASON_PATH_RELAY_UNAVAILABLE,
                "relay unavailable; attempting best-effort direct UDP",
                false,
            )
            .with_scores(direct_score, None);
        }

        if trial_direct
            && direct_score
                .as_ref()
                .map(|score| score.score >= DIRECT_TRIAL_MIN_SCORE)
                .unwrap_or(true)
        {
            return PathSelection::direct(
                endpoint,
                REASON_PATH_DIRECT_TRIAL,
                direct_score
                    .as_ref()
                    .map(|score| {
                        format!(
                            "recent direct UDP success is in trial window; score={}",
                            score.score
                        )
                    })
                    .unwrap_or_else(|| "recent direct UDP success is in trial window".to_string()),
                false,
            )
            .with_scores(direct_score, relay_score);
        }

        PathSelection::relay(
            REASON_PATH_DIRECT_NOT_CONFIRMED,
            match (&direct_score, &relay_score) {
                (Some(direct_score), Some(relay_score)) => format!(
                    "direct UDP pair is not confirmed enough; direct_score={} relay_score={}",
                    direct_score.score, relay_score.score
                ),
                _ => "direct UDP pair is not confirmed; using relay".to_string(),
            },
        )
        .with_scores(direct_score, relay_score)
    }

    fn mark_candidate_pair_probing(&mut self, endpoint: SocketAddr, local_generation: u64) {
        self.ensure_candidate_pair(endpoint, local_generation)
            .record_probing();
    }

    fn mark_candidate_pair_success(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        latency: Option<Duration>,
        selected: bool,
    ) {
        self.ensure_candidate_pair(endpoint, local_generation)
            .record_success(latency, selected);
    }

    fn mark_current_candidate_pairs_failed(
        &mut self,
        local_generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        let code = code.into();
        let reason = reason.into();
        for endpoint in self.candidate_endpoints() {
            self.ensure_candidate_pair(endpoint, local_generation)
                .record_failure(code.clone(), reason.clone());
        }
    }

    fn mark_network_generation_changed(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        self.candidate_pairs
            .retain(|pair| pair.local_generation.saturating_add(1) >= local_generation);
        for pair in &mut self.candidate_pairs {
            if pair.local_generation < local_generation {
                pair.record_generation_change(reason.clone());
            }
        }
        self.ensure_current_candidate_pairs(local_generation);
    }

    fn direct_retry_after(&self, base: Duration) -> Duration {
        self.direct_health.retry_after(base)
    }

    fn direct_retry_remaining(&self, base: Duration) -> Duration {
        self.direct_health.retry_remaining(base)
    }

    fn direct_retry_due(&self, base: Duration) -> bool {
        self.direct_health.retry_due(base)
    }
}

// ============================================================
// Peer Manager
// ============================================================

/// Manages all peer connections.
pub struct PeerManager {
    /// Active peer connections, indexed by node ID.
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    /// Virtual IP → node ID mapping for routing.
    ip_to_node: Arc<RwLock<HashMap<String, String>>>,
    /// Monotonic local network generation. Incremented when local UDP candidates change.
    network_generation: Arc<RwLock<u64>>,
    /// Configuration.
    _config: Config,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new(config: Config) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            ip_to_node: Arc::new(RwLock::new(HashMap::new())),
            network_generation: Arc::new(RwLock::new(0)),
            _config: config,
        }
    }

    /// Current local network generation.
    pub async fn current_network_generation(&self) -> u64 {
        *self.network_generation.read().await
    }

    /// Advance local network generation and invalidate confirmed direct paths.
    ///
    /// Existing remote candidates are kept so they can be reprobed, but prior
    /// direct success is no longer trusted for active-path selection.
    pub async fn advance_network_generation(&self, reason: impl Into<String>) -> u64 {
        let reason = reason.into();
        let generation = {
            let mut generation = self.network_generation.write().await;
            *generation = generation.saturating_add(1);
            *generation
        };

        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            conn.direct_health.record_generation_change(reason.clone());
            conn.mark_network_generation_changed(generation, reason.clone());
            if conn.state == ConnectionState::Direct {
                conn.transition(ConnectionState::FallbackToRelay);
            }
        }

        info!("Local network generation advanced to {generation}: {reason}");
        generation
    }

    /// Add or update a peer from control plane info.
    pub async fn add_peer(&self, info: &PeerInfo) {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let mut ip_map = self.ip_to_node.write().await;

        let conn = conns
            .entry(info.node_id.clone())
            .or_insert_with(|| PeerConnection::new(&info.node_id, &info.virtual_ip));

        conn.virtual_ip = info.virtual_ip.clone();
        conn.device_name = info.device_name.clone();
        conn.nat_type = info.nat_type.clone();
        if let Ok(addr) = info.endpoint.parse::<SocketAddr>() {
            conn.endpoint = Some(addr);
            conn.ensure_candidate_pair(addr, generation);
        }

        ip_map.insert(info.virtual_ip.clone(), info.node_id.clone());
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, node_id: &str) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.remove(node_id) {
            let mut ip_map = self.ip_to_node.write().await;
            ip_map.remove(&conn.virtual_ip);
        }
    }

    /// Get a peer connection by node ID.
    pub async fn get_connection(&self, node_id: &str) -> Option<PeerConnection> {
        self.connections.read().await.get(node_id).cloned()
    }

    /// Look up the node ID for a virtual IP.
    pub async fn resolve_virtual_ip(&self, virtual_ip: &str) -> Option<String> {
        self.ip_to_node.read().await.get(virtual_ip).cloned()
    }

    /// Update a peer's connection state.
    pub async fn update_state(&self, node_id: &str, state: ConnectionState) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.transition(state);
        }
    }

    /// Add ICE candidates for a peer.
    pub async fn add_candidates(&self, node_id: &str, candidates: &[String]) {
        let generation = self.current_network_generation().await;
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            for c in candidates {
                if !conn.candidates.contains(c) {
                    conn.candidates.push(c.clone());
                }
                if let Ok(endpoint) = c.parse::<SocketAddr>() {
                    conn.ensure_candidate_pair(endpoint, generation);
                }
            }

            if conn.endpoint.is_none() {
                conn.endpoint = conn
                    .candidates
                    .iter()
                    .find_map(|candidate| candidate.parse::<SocketAddr>().ok());
            }
        }
    }

    /// Learn a candidate endpoint after receiving a probe or packet from that address.
    ///
    /// This intentionally does not mark the peer as Direct. UDP punch probes only
    /// prove that a candidate address is visible; the direct path is confirmed
    /// only after an encrypted WireGuard packet decrypts successfully.
    pub async fn learn_endpoint_from_addr(&self, endpoint: SocketAddr) -> Option<String> {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;

        for (node_id, conn) in conns.iter_mut() {
            let matches_candidate = conn
                .candidates
                .iter()
                .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
                .any(|candidate| candidate == endpoint);
            let matches_current = conn.endpoint == Some(endpoint);

            if matches_candidate || matches_current {
                conn.endpoint = Some(endpoint);
                conn.mark_candidate_pair_probing(endpoint, generation);
                return Some(node_id.clone());
            }
        }

        None
    }

    /// Backwards-compatible alias for endpoint learning.
    pub async fn select_endpoint_from_addr(&self, endpoint: SocketAddr) -> Option<String> {
        self.learn_endpoint_from_addr(endpoint).await
    }

    /// Return the best current direct endpoint for encrypted UDP data.
    pub async fn direct_endpoint_for_send(&self, node_id: &str) -> Option<SocketAddr> {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.direct_endpoint_for_send(generation))
    }

    /// Return direct UDP endpoints for NAT keepalive probes.
    pub async fn direct_endpoints(&self) -> Vec<(String, SocketAddr)> {
        let generation = self.current_network_generation().await;
        self.connections
            .read()
            .await
            .values()
            .filter(|conn| conn.state == ConnectionState::Direct)
            .filter_map(|conn| {
                conn.direct_endpoint_for_send(generation)
                    .map(|endpoint| (conn.node_id.clone(), endpoint))
            })
            .collect()
    }

    /// Return candidate endpoints that should continue receiving direct-path probes.
    pub async fn direct_probe_targets(&self) -> Vec<(String, Vec<SocketAddr>)> {
        let generation = self.current_network_generation().await;
        self.connections
            .write()
            .await
            .values_mut()
            .filter(|conn| conn.state != ConnectionState::Direct)
            .filter_map(|conn| {
                let endpoints = conn.candidate_probe_endpoints(generation);

                if endpoints.is_empty() {
                    None
                } else {
                    for endpoint in &endpoints {
                        conn.mark_candidate_pair_probing(*endpoint, generation);
                    }
                    Some((conn.node_id.clone(), endpoints))
                }
            })
            .collect()
    }

    /// Return candidate endpoints that are due for direct-path reprobe.
    ///
    /// Unlike `direct_probe_targets`, this only transitions pairs to Probing
    /// after the peer-level retry cooldown has elapsed, so diagnostics do not
    /// report a probe that was intentionally suppressed by backoff.
    pub async fn direct_probe_targets_due(
        &self,
        base_retry_after: Duration,
    ) -> Vec<(String, Vec<SocketAddr>)> {
        let generation = self.current_network_generation().await;
        self.connections
            .write()
            .await
            .values_mut()
            .filter(|conn| conn.state != ConnectionState::Direct)
            .filter(|conn| conn.direct_retry_due(base_retry_after))
            .filter_map(|conn| {
                let endpoints = conn.candidate_probe_endpoints(generation);

                if endpoints.is_empty() {
                    None
                } else {
                    for endpoint in &endpoints {
                        conn.mark_candidate_pair_probing(*endpoint, generation);
                    }
                    Some((conn.node_id.clone(), endpoints))
                }
            })
            .collect()
    }

    /// Select the data path for one outbound encrypted packet.
    pub async fn select_path_for_data(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
    ) -> PathSelection {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        match conns.get_mut(node_id) {
            Some(conn) => {
                let selection =
                    conn.select_path_for_data(generation, prefer_direct, relay_available);
                conn.last_path_selection = Some(selection.clone());
                selection
            }
            None => {
                if relay_available {
                    PathSelection::relay(
                        REASON_PATH_DIRECT_NO_ENDPOINT,
                        "peer has no direct state; using relay",
                    )
                } else {
                    PathSelection::unavailable(
                        REASON_PATH_UNAVAILABLE,
                        "peer has no direct state and relay is unavailable",
                    )
                }
            }
        }
    }

    /// Whether encrypted data should use direct UDP for this peer right now.
    pub async fn should_use_direct_for_data(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
    ) -> bool {
        self.select_path_for_data(node_id, prefer_direct, relay_available)
            .await
            .path
            == Some(NetworkPath::Direct)
    }

    /// Whether direct retry suppression has expired for diagnostics/probing.
    pub async fn direct_retry_due(&self, node_id: &str, retry_after: Duration) -> bool {
        let Some(conn) = self.connections.read().await.get(node_id).cloned() else {
            return false;
        };

        conn.direct_retry_due(retry_after)
    }

    /// Whether the peer currently has a verified direct path.
    pub async fn is_direct(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .map(|conn| conn.state == ConnectionState::Direct)
            .unwrap_or(false)
    }

    /// Record a successful direct-path event.
    pub async fn record_direct_success(&self, node_id: &str, endpoint: Option<SocketAddr>) {
        let generation = self.current_network_generation().await;
        self.record_direct_success_for_generation(node_id, endpoint, generation)
            .await;
    }

    /// Record a successful direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_success_for_generation(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            let selected_endpoint = endpoint.or(conn.endpoint);
            if let Some(endpoint) = selected_endpoint {
                conn.endpoint = Some(endpoint);
                conn.mark_candidate_pair_success(endpoint, generation, None, true);
            }
            conn.direct_generation = generation;
            conn.direct_health.record_success();
            conn.transition(ConnectionState::Direct);
            return true;
        }
        false
    }

    /// Record that a UDP punch endpoint is reachable. A matched ACK confirms
    /// bidirectional UDP reachability; an inbound punch alone remains provisional.
    pub async fn record_direct_probe_success(&self, node_id: &str, endpoint: SocketAddr) {
        self.record_direct_probe_success_with_latency(node_id, endpoint, None)
            .await;
    }

    /// Record a successful direct-path probe and its measured round-trip time.
    pub async fn record_direct_probe_success_with_latency(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_probe_success_with_latency_for_generation(
            node_id, endpoint, latency, generation,
        )
        .await;
    }

    /// Record a direct-path probe result for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_probe_success_with_latency_for_generation(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        generation: u64,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.endpoint = Some(endpoint);
            conn.direct_generation = generation;
            let ack_confirmed = latency.is_some();
            if ack_confirmed {
                conn.mark_candidate_pair_success(endpoint, generation, latency, true);
            } else {
                conn.mark_candidate_pair_probing(endpoint, generation);
            }
            match latency {
                Some(latency) => conn.direct_health.record_success_with_latency(latency),
                None => conn.direct_health.record_success(),
            }
            if ack_confirmed {
                conn.transition(ConnectionState::Direct);
                return true;
            }
            if matches!(
                conn.state,
                ConnectionState::Idle
                    | ConnectionState::Connecting
                    | ConnectionState::FallbackToRelay
            ) {
                conn.transition(ConnectionState::HolePunching);
            }
            return true;
        }
        false
    }

    /// Record a failed direct-path event and enter relay fallback state.
    pub async fn record_direct_failure(&self, node_id: &str, reason: impl Into<String>) {
        self.record_direct_failure_with_code(node_id, REASON_DIRECT_PROBE_FAILED, reason)
            .await;
    }

    /// Record a failed direct-path event with a stable reason code.
    pub async fn record_direct_failure_with_code(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_failure_for_generation(node_id, generation, code, reason)
            .await;
    }

    /// Record a failed direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_failure_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            let code = code.into();
            let reason = reason.into();
            conn.direct_health
                .record_failure(code.clone(), reason.clone());
            conn.mark_current_candidate_pairs_failed(generation, code, reason);
            if conn.state != ConnectionState::Relay {
                conn.transition(ConnectionState::FallbackToRelay);
            }
            return true;
        }
        false
    }

    /// Whether the peer is direct in a specific generation.
    pub async fn is_direct_for_generation(&self, node_id: &str, generation: u64) -> bool {
        generation == self.current_network_generation().await && self.is_direct(node_id).await
    }

    /// Set the relay server for a peer.
    pub async fn set_relay(&self, node_id: &str, relay_server: &str) {
        self.record_relay_success(node_id, relay_server, true).await;
    }

    /// Record a successful relay-path event.
    pub async fn record_relay_success(
        &self,
        node_id: &str,
        relay_server: &str,
        switch_to_relay: bool,
    ) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.relay_server = Some(relay_server.to_string());
            conn.relay_health.record_success();
            if switch_to_relay || conn.state != ConnectionState::Direct {
                conn.transition(ConnectionState::Relay);
            }
        }
    }

    /// Record bytes sent to a peer.
    pub async fn record_sent(&self, node_id: &str, n: u64) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_sent(n);
        }
    }

    /// Record bytes received from a peer.
    pub async fn record_received(&self, node_id: &str, n: u64) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_received(n);
        }
    }

    /// Get all active connections.
    pub async fn active_connections(&self) -> Vec<PeerConnection> {
        self.connections
            .read()
            .await
            .values()
            .filter(|c| c.is_active())
            .cloned()
            .collect()
    }

    /// Get all connections (including inactive).
    pub async fn all_connections(&self) -> Vec<PeerConnection> {
        self.connections.read().await.values().cloned().collect()
    }

    /// Get serializable diagnostics for every peer.
    pub async fn diagnostics(&self) -> Vec<PeerDiagnostics> {
        let mut peers: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .map(PeerDiagnostics::from)
            .collect();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }

    /// Get diagnostics with the live path-selector decision for every peer.
    ///
    /// This does not update `last_path_selection`; it is a read-only snapshot
    /// used by CLI/UI diagnostics to explain why data would use Direct or Relay
    /// right now.
    pub async fn diagnostics_with_path_selection(
        &self,
        prefer_direct: bool,
        relay_available: bool,
        direct_retry_after: Duration,
    ) -> Vec<PeerDiagnostics> {
        let generation = self.current_network_generation().await;
        let mut peers: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .map(|conn| {
                let current_selection =
                    conn.select_path_for_data(generation, prefer_direct, relay_available);
                PeerDiagnostics::from_connection_with_path_selection(
                    conn,
                    Some(&current_selection),
                    Some(direct_retry_after),
                )
            })
            .collect();
        peers.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        peers
    }

    /// Get connection statistics.
    pub async fn stats(&self) -> PeerManagerStats {
        let conns = self.connections.read().await;
        let total = conns.len();
        let direct = conns
            .values()
            .filter(|c| c.state == ConnectionState::Direct)
            .count();
        let relay = conns
            .values()
            .filter(|c| c.state == ConnectionState::Relay)
            .count();
        let total_bytes_sent = conns.values().map(|c| c.bytes_sent).sum();
        let total_bytes_received = conns.values().map(|c| c.bytes_received).sum();

        PeerManagerStats {
            total_peers: total,
            direct_connections: direct,
            relay_connections: relay,
            total_bytes_sent,
            total_bytes_received,
        }
    }
}

/// Aggregate statistics for the peer manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerManagerStats {
    pub total_peers: usize,
    pub direct_connections: usize,
    pub relay_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

/// Serializable peer connection diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerDiagnostics {
    pub node_id: String,
    pub device_name: String,
    pub virtual_ip: String,
    pub endpoint: Option<String>,
    pub nat_type: String,
    pub state: ConnectionState,
    pub active_path: Option<NetworkPath>,
    pub connected_for_ms: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub relay_server: Option<String>,
    pub candidates: Vec<String>,
    pub direct: PathHealthDiagnostics,
    pub relay: PathHealthDiagnostics,
    pub direct_generation: u64,
    pub candidate_pairs: Vec<CandidatePairDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_remaining_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_path_selection: Option<PathSelectionDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_path_selection: Option<PathSelectionDiagnostics>,
}

impl PeerDiagnostics {
    fn from_connection_with_path_selection(
        conn: &PeerConnection,
        current_selection: Option<&PathSelection>,
        direct_retry_after: Option<Duration>,
    ) -> Self {
        let mut candidate_pairs = conn
            .candidate_pairs
            .iter()
            .map(CandidatePairDiagnostics::from)
            .collect::<Vec<_>>();
        candidate_pairs.sort_by(|a, b| {
            a.local_generation
                .cmp(&b.local_generation)
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });

        Self {
            node_id: conn.node_id.clone(),
            device_name: conn.device_name.clone(),
            virtual_ip: conn.virtual_ip.clone(),
            endpoint: conn.endpoint.map(|endpoint| endpoint.to_string()),
            nat_type: conn.nat_type.clone(),
            state: conn.state,
            active_path: conn.active_path(),
            connected_for_ms: conn
                .connected_at
                .map(|connected_at| duration_millis(connected_at.elapsed())),
            bytes_sent: conn.bytes_sent,
            bytes_received: conn.bytes_received,
            relay_server: conn.relay_server.clone(),
            candidates: conn.candidates.clone(),
            direct: PathHealthDiagnostics::from(&conn.direct_health),
            relay: PathHealthDiagnostics::from(&conn.relay_health),
            direct_generation: conn.direct_generation,
            candidate_pairs,
            direct_retry_after_ms: direct_retry_after
                .map(|base| duration_millis(conn.direct_retry_after(base))),
            direct_retry_remaining_ms: direct_retry_after
                .map(|base| duration_millis(conn.direct_retry_remaining(base))),
            current_path_selection: current_selection.map(PathSelectionDiagnostics::from),
            last_path_selection: conn
                .last_path_selection
                .as_ref()
                .map(PathSelectionDiagnostics::from),
        }
    }
}

impl From<&PeerConnection> for PeerDiagnostics {
    fn from(conn: &PeerConnection) -> Self {
        Self::from_connection_with_path_selection(conn, None, None)
    }
}

/// Serializable candidate-pair diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePairDiagnostics {
    pub remote_endpoint: String,
    pub local_generation: u64,
    pub state: CandidatePairState,
    pub first_success_age_ms: Option<u64>,
    pub last_success_age_ms: Option<u64>,
    pub last_failure_age_ms: Option<u64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub last_error_code: Option<String>,
    pub rtt_ms: Option<u64>,
    pub rtt_ewma_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub success_count: u64,
    pub failure_count: u64,
}

impl From<&CandidatePair> for CandidatePairDiagnostics {
    fn from(pair: &CandidatePair) -> Self {
        Self {
            remote_endpoint: pair.remote_endpoint.to_string(),
            local_generation: pair.local_generation,
            state: pair.state,
            first_success_age_ms: pair.first_success_age().map(duration_millis),
            last_success_age_ms: pair.success_age().map(duration_millis),
            last_failure_age_ms: pair.failure_age().map(duration_millis),
            consecutive_failures: pair.consecutive_failures,
            last_error: pair.last_error.clone(),
            last_error_code: pair.last_error_code.clone(),
            rtt_ms: pair.rtt_ms,
            rtt_ewma_ms: pair.rtt_ewma_ms,
            jitter_ms: pair.jitter_ms,
            success_count: pair.success_count,
            failure_count: pair.failure_count,
        }
    }
}

/// Serializable health counters for one transport path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHealthDiagnostics {
    pub last_success_age_ms: Option<u64>,
    pub last_failure_age_ms: Option<u64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub last_error_code: Option<String>,
    pub latency_ms: Option<u64>,
    pub rtt_ewma_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    pub success_count: u64,
    pub failure_count: u64,
}

impl From<&PathHealth> for PathHealthDiagnostics {
    fn from(health: &PathHealth) -> Self {
        Self {
            last_success_age_ms: health.success_age().map(duration_millis),
            last_failure_age_ms: health.failure_age().map(duration_millis),
            consecutive_failures: health.consecutive_failures,
            last_error: health.last_error.clone(),
            last_error_code: health.last_error_code.clone(),
            latency_ms: health.latency_ms,
            rtt_ewma_ms: health.rtt_ewma_ms,
            jitter_ms: health.jitter_ms,
            success_count: health.success_count,
            failure_count: health.failure_count,
        }
    }
}

fn candidate_pair_probe_rank(state: CandidatePairState) -> u8 {
    match state {
        CandidatePairState::Waiting => 0,
        CandidatePairState::Probing => 1,
        CandidatePairState::Succeeded => 2,
        CandidatePairState::Selected => 3,
        CandidatePairState::Failed => 4,
        CandidatePairState::Degraded => 5,
        CandidatePairState::Frozen => 6,
    }
}

fn candidate_pair_send_rank(state: CandidatePairState) -> u8 {
    match state {
        CandidatePairState::Selected => 0,
        CandidatePairState::Succeeded => 1,
        CandidatePairState::Probing => 2,
        CandidatePairState::Waiting => 3,
        CandidatePairState::Failed => 4,
        CandidatePairState::Degraded => 5,
        CandidatePairState::Frozen => 6,
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn update_latency_ewma(ewma_ms: &mut Option<u64>, jitter_ms: &mut Option<u64>, sample_ms: u64) {
    match *ewma_ms {
        Some(previous) => {
            let delta = sample_ms.abs_diff(previous);
            let next_ewma = ((previous as u128 * 7) + sample_ms as u128).div_ceil(8) as u64;
            let next_jitter = match *jitter_ms {
                Some(previous_jitter) => {
                    ((previous_jitter as u128 * 3) + delta as u128).div_ceil(4) as u64
                }
                None => delta,
            };
            *ewma_ms = Some(next_ewma);
            *jitter_ms = Some(next_jitter);
        }
        None => {
            *ewma_ms = Some(sample_ms);
            *jitter_ms = Some(0);
        }
    }
}

fn latency_score(latency_ms: Option<u64>) -> i32 {
    match latency_ms {
        Some(ms) if ms <= 30 => 10,
        Some(ms) if ms <= 80 => 6,
        Some(ms) if ms <= 150 => 2,
        Some(ms) if ms <= 300 => -5,
        Some(_) => -15,
        None => 0,
    }
}

fn jitter_penalty(jitter_ms: Option<u64>) -> i32 {
    match jitter_ms {
        Some(ms) if ms <= 10 => 0,
        Some(ms) if ms <= 40 => -5,
        Some(_) => -15,
        None => 0,
    }
}

fn stability_score(success_count: u64, consecutive_failures: u32, failure_count: u64) -> i32 {
    let success_bonus = success_count.min(5) as i32 * 2;
    let consecutive_penalty = consecutive_failures.min(4) as i32 * -20;
    let history_penalty = failure_count.min(5) as i32 * -3;
    success_bonus + consecutive_penalty + history_penalty
}

fn format_optional_ms(value: Option<u64>) -> String {
    value
        .map(|ms| format!("{ms}ms"))
        .unwrap_or_else(|| "unknown".to_string())
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::generate_default("https://ctrl.test", "net1").unwrap()
    }

    fn test_peer(node_id: &str, endpoint: SocketAddr) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        }
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Idle.to_string(), "idle");
        assert_eq!(ConnectionState::Direct.to_string(), "direct");
        assert_eq!(ConnectionState::Relay.to_string(), "relay");
    }

    #[test]
    fn test_peer_connection_new() {
        let conn = PeerConnection::new("peer1", "10.20.0.2");
        assert_eq!(conn.node_id, "peer1");
        assert_eq!(conn.virtual_ip, "10.20.0.2");
        assert!(!conn.is_active());
        assert!(!conn.is_relay());
    }

    #[test]
    fn test_peer_connection_transition() {
        let mut conn = PeerConnection::new("peer1", "10.20.0.2");
        assert_eq!(conn.state, ConnectionState::Idle);

        conn.transition(ConnectionState::Connecting);
        assert_eq!(conn.state, ConnectionState::Connecting);
        assert!(conn.connected_at.is_none());

        conn.transition(ConnectionState::Direct);
        assert!(conn.is_active());
        assert!(!conn.is_relay());
        assert!(conn.connected_at.is_some());
    }

    #[test]
    fn test_peer_connection_relay() {
        let mut conn = PeerConnection::new("peer1", "10.20.0.2");
        conn.transition(ConnectionState::Relay);
        assert!(conn.is_active());
        assert!(conn.is_relay());
    }

    #[test]
    fn test_peer_connection_bytes() {
        let mut conn = PeerConnection::new("peer1", "10.20.0.2");
        conn.record_sent(100);
        conn.record_sent(50);
        conn.record_received(200);
        assert_eq!(conn.bytes_sent, 150);
        assert_eq!(conn.bytes_received, 200);
    }

    #[tokio::test]
    async fn test_peer_manager_add_remove() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            device_name: "Office Mac".to_string(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };

        manager.add_peer(&peer_info).await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.virtual_ip, "10.20.0.2");
        assert_eq!(conn.device_name, "Office Mac");

        // Resolve virtual IP
        let node_id = manager.resolve_virtual_ip("10.20.0.2").await.unwrap();
        assert_eq!(node_id, "peer1");

        manager.remove_peer("peer1").await;
        assert!(manager.get_connection("peer1").await.is_none());
    }

    #[tokio::test]
    async fn test_peer_manager_candidates() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };

        manager.add_peer(&peer_info).await;
        manager
            .add_candidates(
                "peer1",
                &["10.0.0.1:5000".to_string(), "192.168.1.1:5000".to_string()],
            )
            .await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.candidates.len(), 2);
        assert_eq!(conn.candidate_pairs.len(), 3);
        assert!(conn
            .candidate_pairs
            .iter()
            .all(|pair| pair.local_generation == 0 && pair.state == CandidatePairState::Waiting));
    }

    #[tokio::test]
    async fn candidate_pairs_track_probe_success_failure_and_generation() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51826".parse().unwrap();

        manager
            .add_peer(&PeerInfo {
                node_id: "peer1".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;

        let targets = manager.direct_probe_targets().await;
        assert_eq!(targets, vec![("peer1".to_string(), vec![endpoint])]);
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.candidate_pairs.len(), 1);
        assert_eq!(conn.candidate_pairs[0].state, CandidatePairState::Probing);

        assert!(
            manager
                .record_direct_probe_success_with_latency_for_generation(
                    "peer1",
                    endpoint,
                    Some(Duration::from_millis(9)),
                    0,
                )
                .await
        );
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.candidate_pairs[0].state, CandidatePairState::Selected);
        assert_eq!(conn.candidate_pairs[0].rtt_ms, Some(9));

        let generation = manager.advance_network_generation("wifi_to_hotspot").await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(generation, 1);
        assert_eq!(conn.candidate_pairs.len(), 2);
        assert!(conn.candidate_pairs.iter().any(|pair| {
            pair.local_generation == 0
                && pair.remote_endpoint == endpoint
                && pair.state == CandidatePairState::Degraded
                && pair.last_error_code.as_deref() == Some(REASON_NETWORK_GENERATION_CHANGED)
        }));
        assert!(conn.candidate_pairs.iter().any(|pair| {
            pair.local_generation == 1
                && pair.remote_endpoint == endpoint
                && pair.state == CandidatePairState::Waiting
        }));

        assert!(
            manager
                .record_direct_failure_for_generation(
                    "peer1",
                    generation,
                    REASON_DIRECT_PROBE_FAILED,
                    "no ACK",
                )
                .await
        );
        let conn = manager.get_connection("peer1").await.unwrap();
        assert!(conn.candidate_pairs.iter().any(|pair| {
            pair.local_generation == generation
                && pair.remote_endpoint == endpoint
                && pair.state == CandidatePairState::Failed
                && pair.last_error.as_deref() == Some("no ACK")
        }));
    }

    #[tokio::test]
    async fn candidate_pair_selection_prefers_selected_endpoint_for_send() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let old_endpoint: SocketAddr = "127.0.0.1:51827".parse().unwrap();
        let new_endpoint: SocketAddr = "127.0.0.1:51828".parse().unwrap();

        manager
            .add_peer(&PeerInfo {
                node_id: "peer1".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: old_endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;
        manager
            .add_candidates("peer1", &[new_endpoint.to_string()])
            .await;

        assert_eq!(
            manager.direct_endpoint_for_send("peer1").await,
            Some(old_endpoint)
        );

        assert!(
            manager
                .record_direct_probe_success_with_latency_for_generation(
                    "peer1",
                    new_endpoint,
                    Some(Duration::from_millis(4)),
                    0,
                )
                .await
        );

        assert_eq!(
            manager.direct_endpoint_for_send("peer1").await,
            Some(new_endpoint)
        );
        assert_eq!(
            manager.direct_endpoints().await,
            vec![("peer1".to_string(), new_endpoint)]
        );
    }

    #[tokio::test]
    async fn candidate_pair_probe_targets_prioritize_non_failed_pairs() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let failed_endpoint: SocketAddr = "127.0.0.1:51829".parse().unwrap();
        let waiting_endpoint: SocketAddr = "127.0.0.1:51830".parse().unwrap();

        manager
            .add_peer(&PeerInfo {
                node_id: "peer1".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: failed_endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;
        manager
            .add_candidates("peer1", &[waiting_endpoint.to_string()])
            .await;

        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.ensure_candidate_pair(failed_endpoint, 0)
                .record_failure(REASON_DIRECT_PROBE_FAILED, "no ACK");
        }

        let targets = manager.direct_probe_targets().await;
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, "peer1");
        assert_eq!(targets[0].1, vec![waiting_endpoint, failed_endpoint]);
    }

    #[tokio::test]
    async fn test_peer_manager_selects_endpoint_from_candidates() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };

        manager.add_peer(&peer_info).await;
        manager
            .add_candidates(
                "peer1",
                &[
                    "not-a-socket".to_string(),
                    "127.0.0.1:51820".to_string(),
                    "10.0.0.1:51820".to_string(),
                ],
            )
            .await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.endpoint, Some("127.0.0.1:51820".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_peer_manager_learns_endpoint_from_probe_source_without_confirming_direct() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };
        let selected_endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();

        manager.add_peer(&peer_info).await;
        manager
            .add_candidates("peer1", &[selected_endpoint.to_string()])
            .await;

        let selected = manager.learn_endpoint_from_addr(selected_endpoint).await;
        assert_eq!(selected, Some("peer1".to_string()));

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.endpoint, Some(selected_endpoint));
        assert_eq!(conn.state, ConnectionState::Idle);
        assert!(manager.direct_endpoints().await.is_empty());
    }

    #[tokio::test]
    async fn path_selector_prefers_relay_until_direct_is_confirmed() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51831".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;

        let waiting = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(waiting.path, Some(NetworkPath::Relay));
        assert_eq!(waiting.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
        assert_eq!(waiting.direct_endpoint, None);

        let no_relay = manager.select_path_for_data("peer1", true, false).await;
        assert_eq!(no_relay.path, Some(NetworkPath::Direct));
        assert_eq!(no_relay.reason_code, REASON_PATH_RELAY_UNAVAILABLE);
        assert_eq!(no_relay.direct_endpoint, Some(endpoint));
        assert!(!no_relay.direct_confirmed);

        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(6)),
            )
            .await;
        let confirmed = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(confirmed.path, Some(NetworkPath::Direct));
        assert_eq!(confirmed.reason_code, REASON_PATH_DIRECT_CONFIRMED);
        assert_eq!(confirmed.direct_endpoint, Some(endpoint));
        assert!(confirmed.direct_confirmed);
        assert!(
            confirmed.direct_score.as_ref().unwrap().score
                > confirmed.relay_score.as_ref().unwrap().score
        );
    }

    #[tokio::test]
    async fn path_selector_uses_scores_and_hysteresis_for_degraded_direct() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51836".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(18)),
            )
            .await;
        manager
            .record_relay_success("peer1", "relay.test:443", false)
            .await;

        let healthy = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(healthy.path, Some(NetworkPath::Direct));
        assert_eq!(healthy.reason_code, REASON_PATH_DIRECT_CONFIRMED);

        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.direct_health.consecutive_failures = 3;
            conn.direct_health.failure_count = 3;
            conn.direct_health.rtt_ewma_ms = Some(650);
            conn.direct_health.jitter_ms = Some(120);
        }

        let degraded = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(degraded.path, Some(NetworkPath::Relay));
        assert_eq!(degraded.reason_code, REASON_PATH_DIRECT_DEGRADED);
        assert!(
            degraded.direct_score.as_ref().unwrap().score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN
                < degraded.relay_score.as_ref().unwrap().score
        );
    }

    #[tokio::test]
    async fn path_selector_honors_relay_policy_and_reports_no_path() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51832".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        let relay_policy = manager.select_path_for_data("peer1", false, true).await;
        assert_eq!(relay_policy.path, Some(NetworkPath::Relay));
        assert_eq!(relay_policy.reason_code, REASON_PATH_DIRECT_DISABLED);

        let no_state = manager.select_path_for_data("missing", true, false).await;
        assert_eq!(no_state.path, None);
        assert_eq!(no_state.reason_code, REASON_PATH_UNAVAILABLE);
    }

    #[tokio::test]
    async fn path_selection_diagnostics_exposes_current_and_last_selection() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51833".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;

        let diagnostics = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        assert_eq!(diagnostics.len(), 1);
        let current = diagnostics[0].current_path_selection.as_ref().unwrap();
        assert_eq!(current.path, Some(NetworkPath::Relay));
        assert_eq!(current.direct_endpoint, None);
        assert_eq!(current.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
        assert!(
            current.direct_score.as_ref().unwrap().score
                < current.relay_score.as_ref().unwrap().score
        );
        assert_eq!(diagnostics[0].last_path_selection, None);

        let selected = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(selected.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);

        let diagnostics = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        let current = diagnostics[0].current_path_selection.as_ref().unwrap();
        let last = diagnostics[0].last_path_selection.as_ref().unwrap();
        assert_eq!(current.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
        assert_eq!(last.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);

        let json = serde_json::to_value(&diagnostics[0]).unwrap();
        assert_eq!(
            json["current_path_selection"]["reason_code"],
            REASON_PATH_DIRECT_NOT_CONFIRMED
        );
        assert_eq!(
            json["last_path_selection"]["reason_code"],
            REASON_PATH_DIRECT_NOT_CONFIRMED
        );
        assert!(json["current_path_selection"]["direct_score"]["score"].is_i64());
        assert!(json["current_path_selection"]["relay_score"]["score"].is_i64());
    }

    #[tokio::test]
    async fn direct_probe_targets_due_respects_backoff_without_false_probing() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51834".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;

        let first_targets = manager
            .direct_probe_targets_due(Duration::from_secs(5))
            .await;
        assert_eq!(first_targets, vec![("peer1".to_string(), vec![endpoint])]);

        manager
            .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "no ACK")
            .await;
        manager
            .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "still no ACK")
            .await;

        let suppressed = manager
            .direct_probe_targets_due(Duration::from_secs(5))
            .await;
        assert!(suppressed.is_empty());

        let diagnostics = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        assert_eq!(diagnostics[0].direct_retry_after_ms, Some(10_000));
        assert!(diagnostics[0].direct_retry_remaining_ms.unwrap() > 0);
        assert_eq!(diagnostics[0].direct.failure_count, 2);
        assert!(diagnostics[0].candidate_pairs.iter().all(|pair| {
            pair.state != CandidatePairState::Probing
                && pair.failure_count == 2
                && pair.last_error_code.as_deref() == Some(REASON_DIRECT_PROBE_FAILED)
        }));
    }

    #[tokio::test]
    async fn direct_path_latency_tracks_ewma_and_jitter() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51835".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(8)),
            )
            .await;
        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(24)),
            )
            .await;

        let diagnostics = manager.diagnostics().await;
        assert_eq!(diagnostics[0].direct.success_count, 2);
        assert_eq!(diagnostics[0].direct.latency_ms, Some(24));
        assert_eq!(diagnostics[0].direct.rtt_ewma_ms, Some(10));
        assert_eq!(diagnostics[0].direct.jitter_ms, Some(4));
        assert_eq!(diagnostics[0].candidate_pairs[0].success_count, 2);
        assert_eq!(diagnostics[0].candidate_pairs[0].rtt_ewma_ms, Some(10));
        assert_eq!(diagnostics[0].candidate_pairs[0].jitter_ms, Some(4));
    }

    #[tokio::test]
    async fn test_peer_manager_path_health_drives_data_path() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51822".parse().unwrap();

        manager
            .add_peer(&PeerInfo {
                node_id: "peer1".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;

        assert!(
            !manager
                .should_use_direct_for_data("peer1", true, true)
                .await
        );
        assert!(
            manager
                .should_use_direct_for_data("peer1", true, false)
                .await
        );

        manager
            .record_direct_failure("peer1", "probe timeout")
            .await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::FallbackToRelay);
        assert_eq!(conn.direct_health.consecutive_failures, 1);
        assert_eq!(
            conn.direct_health.last_error.as_deref(),
            Some("probe timeout")
        );
        assert_eq!(
            conn.direct_health.last_error_code.as_deref(),
            Some(REASON_DIRECT_PROBE_FAILED)
        );

        manager.set_relay("peer1", "127.0.0.1:9000").await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Relay);
        assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
        assert!(conn.relay_health.last_success_at.is_some());

        manager.record_direct_probe_success("peer1", endpoint).await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Relay);
        assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
        assert!(conn.direct_health.last_success_at.is_some());
        assert!(
            manager
                .should_use_direct_for_data("peer1", true, true)
                .await
        );

        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(12)),
            )
            .await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Direct);
        assert_eq!(conn.active_path(), Some(NetworkPath::Direct));
        assert_eq!(conn.direct_health.consecutive_failures, 0);
        assert!(
            manager
                .should_use_direct_for_data("peer1", true, true)
                .await
        );
    }

    #[tokio::test]
    async fn network_generation_invalidates_direct_and_ignores_stale_results() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let old_endpoint: SocketAddr = "127.0.0.1:51824".parse().unwrap();
        let new_endpoint: SocketAddr = "127.0.0.1:51825".parse().unwrap();

        manager
            .add_peer(&PeerInfo {
                node_id: "peer1".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: old_endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;

        assert_eq!(manager.current_network_generation().await, 0);
        assert!(
            manager
                .record_direct_probe_success_with_latency_for_generation(
                    "peer1",
                    old_endpoint,
                    Some(Duration::from_millis(8)),
                    0,
                )
                .await
        );
        assert!(manager.is_direct_for_generation("peer1", 0).await);

        let generation = manager.advance_network_generation("wifi_to_hotspot").await;
        assert_eq!(generation, 1);
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::FallbackToRelay);
        assert_eq!(
            conn.direct_health.last_error_code.as_deref(),
            Some(REASON_NETWORK_GENERATION_CHANGED)
        );
        assert!(
            !manager
                .should_use_direct_for_data("peer1", true, true)
                .await
        );

        assert!(
            !manager
                .record_direct_probe_success_with_latency_for_generation(
                    "peer1",
                    old_endpoint,
                    Some(Duration::from_millis(5)),
                    0,
                )
                .await
        );
        assert_eq!(
            manager.get_connection("peer1").await.unwrap().state,
            ConnectionState::FallbackToRelay
        );

        assert!(
            manager
                .record_direct_probe_success_with_latency_for_generation(
                    "peer1",
                    new_endpoint,
                    Some(Duration::from_millis(7)),
                    generation,
                )
                .await
        );
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Direct);
        assert_eq!(conn.endpoint, Some(new_endpoint));
        assert_eq!(conn.direct_generation, generation);
    }

    #[test]
    fn test_diagnostics_enums_serialize_as_snake_case() {
        assert_eq!(
            serde_json::to_string(&ConnectionState::HolePunching).unwrap(),
            "\"hole_punching\""
        );
        assert_eq!(
            serde_json::to_string(&NetworkPath::Direct).unwrap(),
            "\"direct\""
        );
    }

    #[tokio::test]
    async fn test_peer_manager_direct_probe_targets_exclude_direct_peers() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51823".parse().unwrap();

        manager
            .add_peer(&PeerInfo {
                node_id: "peer1".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;

        assert_eq!(
            manager.direct_probe_targets().await,
            vec![("peer1".to_string(), vec![endpoint])]
        );

        manager.record_direct_success("peer1", Some(endpoint)).await;
        assert!(manager.direct_probe_targets().await.is_empty());
    }

    #[tokio::test]
    async fn test_peer_manager_stats() {
        let config = test_config();
        let manager = PeerManager::new(config);

        // Add two peers
        for (id, ip) in [("p1", "10.20.0.2"), ("p2", "10.20.0.3")] {
            let peer_info = PeerInfo {
                node_id: id.to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: "1.2.3.4:5000".to_string(),
                nat_type: "FullCone".to_string(),
                virtual_ip: ip.to_string(),
                online: true,
                last_seen: 0,
            };
            manager.add_peer(&peer_info).await;
        }

        manager.update_state("p1", ConnectionState::Direct).await;
        manager.update_state("p2", ConnectionState::Relay).await;

        manager.record_sent("p1", 1000).await;
        manager.record_received("p2", 500).await;

        let stats = manager.stats().await;
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.direct_connections, 1);
        assert_eq!(stats.relay_connections, 1);
        assert_eq!(stats.total_bytes_sent, 1000);
        assert_eq!(stats.total_bytes_received, 500);
    }

    #[tokio::test]
    async fn test_peer_manager_active_connections() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };
        manager.add_peer(&peer_info).await;

        // Initially no active connections
        assert!(manager.active_connections().await.is_empty());

        manager.update_state("peer1", ConnectionState::Direct).await;
        assert_eq!(manager.active_connections().await.len(), 1);
    }
}
