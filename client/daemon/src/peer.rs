//! Peer connection manager.
//!
//! Manages connections to other nodes in the virtual network:
//! - Tracks active peer tunnels (WireGuard sessions)
//! - Handles ICE candidate exchange for NAT traversal
//! - Falls back to relay when direct connection fails
//! - Routes packets between TUN device and peer tunnels

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_crypto::{hmac, NodeIdentity};
use p2pnet_nat::{MappingBehavior, NatProfile, ProbeMacKey};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// WebSocket signals do not include a server-time offset.  A bounded grace
// period prevents a peer with a modestly fast system clock from rejecting an
// otherwise fresh server-issued candidate set.  Generation ordering still
// prevents old sets from replacing newer ones.
const CANDIDATE_EXPIRY_CLOCK_SKEW_GRACE_MS: u64 = 120_000;

use crate::config::Config;
use crate::control::PeerInfo;
use crate::traversal_history::{
    traversal_history_path, TraversalHistory, TraversalHistoryDiagnostics,
};

const DIRECT_TRIAL_WINDOW: Duration = Duration::from_secs(10);
const PEER_REFLEXIVE_STICKY_WINDOW: Duration = Duration::from_secs(10);
/// Keep relay-backed direct probing alive.
///
/// Relay already provides the data-plane safety net, so direct UDP retries should stay cheap but
/// frequent enough to catch peer-reflexive discoveries, refreshed NAT mappings, and brief symmetric
/// NAT punch windows.  With the default 5s base interval this caps the retry cadence at 10s instead
/// of drifting out to 40s after repeated failures.
const DIRECT_RETRY_BACKOFF_MAX_EXPONENT: u32 = 1;
const DIRECT_TO_RELAY_HYSTERESIS_MARGIN: i32 = 15;
const DIRECT_CONFIRMED_MIN_SCORE: i32 = 60;
const DIRECT_KEEPALIVE_FAILURE_THRESHOLD: u32 = 3;
const PREDICTED_PROBE_BUDGET_PER_CYCLE: usize = 2;
const PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 8;
const PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE: usize = 0;
const PREDICTED_PROBE_FAILURE_BUDGET_PER_CYCLE: usize = 1;
const BIRTHDAY_PROBE_BUDGET_PER_CYCLE: usize = 16;
const BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 32;
const DIRECT_TRIAL_MIN_SCORE: i32 = 40;
const PATH_SELECTION_EVENT_LIMIT: usize = 16;
const DIRECT_TRAVERSAL_EVENT_LIMIT: usize = 32;
const RELAY_PEER_CONFIRMATION_MAX_AGE: Duration = Duration::from_secs(30);
const PROBE_MAC_KEY_DOMAIN: &[u8] = b"p2wlan udp probe v2 mac key";

/// Stable reason code emitted when a local network generation changes.
pub const REASON_NETWORK_GENERATION_CHANGED: &str = "network_generation_changed";
/// Stable reason code for direct path probe timeout/failure.
pub const REASON_DIRECT_PROBE_FAILED: &str = "direct_probe_failed";
/// Stable reason code for direct path send failure.
pub const REASON_DIRECT_SEND_FAILED: &str = "direct_send_failed";
/// Direct UDP keepalive did not receive a matching authenticated ACK.
pub const REASON_DIRECT_KEEPALIVE_TIMEOUT: &str = "direct_keepalive_timeout";
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
    /// Whether Relay should receive a hedged copy while Direct remains selected.
    pub relay_hedged: bool,
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
            relay_hedged: false,
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
            relay_hedged: false,
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
            relay_hedged: false,
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

    fn with_relay_hedge(mut self) -> Self {
        self.relay_hedged = true;
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
    pub relay_hedged: bool,
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
            relay_hedged: selection.relay_hedged,
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

/// One recorded path-selector transition for a peer.
#[derive(Debug, Clone)]
pub struct PathSelectionEvent {
    pub selected_at: Instant,
    pub network_generation: u64,
    pub previous_path: Option<NetworkPath>,
    pub selected_path: Option<NetworkPath>,
    pub direct_endpoint: Option<SocketAddr>,
    pub reason_code: String,
    pub reason: String,
    pub direct_confirmed: bool,
    pub relay_hedged: bool,
    pub direct_score: Option<PathScore>,
    pub relay_score: Option<PathScore>,
}

/// One recorded direct traversal event for a peer.
#[derive(Debug, Clone)]
pub struct DirectTraversalEvent {
    pub recorded_at: Instant,
    pub network_generation: u64,
    pub stage: String,
    pub endpoint: Option<SocketAddr>,
    pub candidate_count: Option<usize>,
    pub sent_probes: Option<u32>,
    pub detail: String,
}

impl DirectTraversalEvent {
    fn new(
        network_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            recorded_at: Instant::now(),
            network_generation,
            stage: stage.into(),
            endpoint,
            candidate_count,
            sent_probes,
            detail: detail.into(),
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

/// Where a candidate pair endpoint came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidatePairSource {
    /// Endpoint was signaled by the control plane or static peer metadata.
    Signaled,
    /// Endpoint came from the peer's host/local-interface candidate.
    Host,
    /// Endpoint came from the peer's STUN-observed server-reflexive candidate.
    StunObserved,
    /// Endpoint was opened through local gateway port mapping such as UPnP IGD.
    Upnp,
    /// Endpoint was opened through PCP MAP.
    Pcp,
    /// Endpoint was opened through NAT-PMP UDP mapping.
    NatPmp,
    /// Endpoint was predicted from the remote peer's NAT mapping delta.
    Predicted,
    /// Endpoint was synthesized by bounded birthday probing around a public candidate.
    Birthday,
    /// Endpoint was learned from legacy candidate-matched traffic.
    Learned,
    /// Endpoint was learned from an authenticated Probe v2 source address.
    PeerReflexive,
}

impl CandidatePairSource {
    pub fn history_label(self) -> &'static str {
        match self {
            Self::Signaled => "signaled",
            Self::Host => "host",
            Self::StunObserved => "stun_observed",
            Self::Upnp => "upnp",
            Self::Pcp => "pcp",
            Self::NatPmp => "nat_pmp",
            Self::Predicted => "predicted",
            Self::Birthday => "birthday",
            Self::Learned => "learned",
            Self::PeerReflexive => "peer_reflexive",
        }
    }

    pub fn is_persisted_history_source(self) -> bool {
        !matches!(self, Self::Signaled)
    }
}

/// State and health for one direct candidate pair.
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Remote UDP candidate endpoint.
    pub remote_endpoint: SocketAddr,
    /// Endpoint source used for probe ranking and diagnostics.
    pub source: CandidatePairSource,
    /// Local network generation this pair belongs to.
    pub local_generation: u64,
    /// Current reachability state.
    pub state: CandidatePairState,
    /// Most recent active probe sent for this pair.
    pub last_probe_at: Option<Instant>,
    /// Active probe packets sent to this pair.
    pub probe_count: u64,
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
    fn new_with_source(
        remote_endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) -> Self {
        Self {
            remote_endpoint,
            source,
            local_generation,
            state: CandidatePairState::Waiting,
            last_probe_at: None,
            probe_count: 0,
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

    fn promote_source(&mut self, source: CandidatePairSource) {
        if candidate_pair_source_rank(source) < candidate_pair_source_rank(self.source) {
            self.source = source;
        }
    }

    fn record_probing(&mut self) {
        self.last_probe_at = Some(Instant::now());
        self.probe_count = self.probe_count.saturating_add(1);
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

    fn is_confirmed(&self) -> bool {
        self.last_success_at.is_some_and(|success| {
            self.last_failure_at
                .map(|failure| success >= failure)
                .unwrap_or(true)
        })
    }

    fn is_confirmed_recent(&self, max_age: Duration) -> bool {
        self.is_confirmed()
            && self
                .success_age()
                .map(|age| age <= max_age)
                .unwrap_or(false)
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
    /// Peer's static WireGuard/X25519 public key as hex.
    pub public_key: String,
    /// Symmetric MAC key for authenticated UDP Probe v2.
    pub probe_mac_key: Option<ProbeMacKey>,
    /// Peer's virtual IP.
    pub virtual_ip: String,
    /// Peer's public endpoint (ip:port) if known.
    pub endpoint: Option<SocketAddr>,
    /// Endpoint currently advertised by peer metadata. This is kept separate
    /// from an authenticated peer-reflexive endpoint learned on the wire.
    pub signaled_endpoint: Option<SocketAddr>,
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
    /// Candidate strings from the most recent peer offer/answer.
    signaled_candidates: HashSet<String>,
    /// Newer candidate sets replace older ones; generation 0 remains valid for
    /// legacy peers that have not yet been upgraded.
    last_candidate_generation: u64,
    last_candidates_expires_at_ms: Option<u64>,
    /// Local-only source metadata keyed by candidate endpoint string.
    pub candidate_sources: HashMap<String, CandidatePairSource>,
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
    /// Recent real outbound path-selector transitions.
    pub path_events: Vec<PathSelectionEvent>,
    /// Recent direct traversal timeline events.
    pub direct_events: Vec<DirectTraversalEvent>,
}

impl PeerConnection {
    /// Create a new peer connection in Idle state.
    pub fn new(node_id: &str, virtual_ip: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key: String::new(),
            probe_mac_key: None,
            virtual_ip: virtual_ip.to_string(),
            endpoint: None,
            signaled_endpoint: None,
            nat_type: String::new(),
            state: ConnectionState::Idle,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            relay_server: None,
            candidates: Vec::new(),
            signaled_candidates: HashSet::new(),
            last_candidate_generation: 0,
            last_candidates_expires_at_ms: None,
            candidate_sources: HashMap::new(),
            direct_health: PathHealth::default(),
            relay_health: PathHealth::default(),
            direct_generation: 0,
            candidate_pairs: Vec::new(),
            last_path_selection: None,
            path_events: Vec::new(),
            direct_events: Vec::new(),
        }
    }

    fn reset_for_identity_change(&mut self) {
        self.endpoint = self.signaled_endpoint;
        self.candidates.clear();
        self.signaled_candidates.clear();
        self.last_candidate_generation = 0;
        self.last_candidates_expires_at_ms = None;
        self.candidate_sources.clear();
        self.state = ConnectionState::Idle;
        self.connected_at = None;
        self.relay_server = None;
        self.direct_health = PathHealth::default();
        self.relay_health = PathHealth::default();
        self.direct_generation = 0;
        self.candidate_pairs.clear();
        self.last_path_selection = None;
        self.path_events.clear();
        self.direct_events.clear();
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

    fn candidate_source_for_endpoint(&self, endpoint: SocketAddr) -> CandidatePairSource {
        self.candidate_sources
            .get(&endpoint.to_string())
            .copied()
            .unwrap_or(CandidatePairSource::Signaled)
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
        self.ensure_candidate_pair_with_source(
            endpoint,
            local_generation,
            CandidatePairSource::Signaled,
        )
    }

    fn ensure_candidate_pair_with_source(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) -> &mut CandidatePair {
        if let Some(index) = self.candidate_pairs.iter().position(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
        }) {
            self.candidate_pairs[index].promote_source(source);
            return &mut self.candidate_pairs[index];
        }
        self.candidate_pairs.push(CandidatePair::new_with_source(
            endpoint,
            local_generation,
            source,
        ));
        self.candidate_pairs
            .last_mut()
            .expect("candidate pair inserted")
    }

    fn ensure_current_candidate_pairs(&mut self, local_generation: u64) {
        for endpoint in self.candidate_endpoints() {
            let source = self.candidate_source_for_endpoint(endpoint);
            self.ensure_candidate_pair_with_source(endpoint, local_generation, source);
        }
    }

    fn candidate_probe_endpoints(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
    ) -> Vec<SocketAddr> {
        self.ensure_current_candidate_pairs(local_generation);
        let mut endpoints = self.candidate_endpoints();
        self.ensure_birthday_candidate_pairs(
            local_generation,
            history,
            local_nat_profile,
            &mut endpoints,
        );
        let source_stats = candidate_pair_source_stats(&self.candidate_pairs, local_generation);
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
                    candidate_pair_source_quality_rank(&source_stats, history, a.source).cmp(
                        &candidate_pair_source_quality_rank(&source_stats, history, b.source),
                    )
                })
                .then_with(|| {
                    discovered_endpoint_probe_rank(a.source)
                        .cmp(&discovered_endpoint_probe_rank(b.source))
                })
                .then_with(|| {
                    endpoint_probe_rank(a.remote_endpoint)
                        .cmp(&endpoint_probe_rank(b.remote_endpoint))
                })
                .then_with(|| {
                    candidate_pair_source_rank(a.source).cmp(&candidate_pair_source_rank(b.source))
                })
                .then_with(|| a.probe_count.cmp(&b.probe_count))
                .then_with(|| a.consecutive_failures.cmp(&b.consecutive_failures))
                .then_with(|| a.failure_count.cmp(&b.failure_count))
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
        apply_adaptive_probe_budgets(pairs, &source_stats, history)
            .into_iter()
            .map(|pair| pair.remote_endpoint)
            .collect()
    }

    fn ensure_birthday_candidate_pairs(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
        endpoints: &mut Vec<SocketAddr>,
    ) {
        if !local_nat_profile.is_some_and(|profile| profile.birthday_candidate) {
            return;
        }
        let budget = birthday_probe_budget(history);
        if budget == 0 {
            return;
        }

        let bases = endpoints
            .iter()
            .copied()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .filter(|endpoint| {
                !matches!(
                    self.candidate_source_for_endpoint(*endpoint),
                    CandidatePairSource::Host
                        | CandidatePairSource::Upnp
                        | CandidatePairSource::Pcp
                        | CandidatePairSource::NatPmp
                )
            })
            .collect::<Vec<_>>();

        let mut generated = 0usize;
        for base in bases {
            for endpoint in birthday_probe_endpoints(base) {
                if generated >= budget {
                    return;
                }
                if endpoints.contains(&endpoint) {
                    continue;
                }
                endpoints.push(endpoint);
                self.ensure_candidate_pair_with_source(
                    endpoint,
                    local_generation,
                    CandidatePairSource::Birthday,
                );
                generated += 1;
            }
        }
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
            candidate_pair_send_rank(a)
                .cmp(&candidate_pair_send_rank(b))
                .then_with(|| {
                    a.success_age()
                        .unwrap_or(Duration::MAX)
                        .cmp(&b.success_age().unwrap_or(Duration::MAX))
                })
                .then_with(|| {
                    candidate_pair_source_rank(a.source).cmp(&candidate_pair_source_rank(b.source))
                })
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
                if direct_score.score < DIRECT_CONFIRMED_MIN_SCORE
                    && direct_score.score < relay_score.score
                {
                    if !self
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE)
                    {
                        return PathSelection::direct(
                            endpoint,
                            REASON_PATH_DIRECT_DEGRADED,
                            format!(
                                "confirmed direct score {} is poor, but relay is not peer-confirmed; retaining Direct with a Relay hedge",
                                direct_score.score
                            ),
                            true,
                        )
                        .with_scores(Some(direct_score.clone()), Some(relay_score.clone()))
                        .with_relay_hedge();
                    }
                    return PathSelection::relay(
                        REASON_PATH_DIRECT_DEGRADED,
                        format!(
                            "confirmed direct score {} is below quality floor {} and relay score {}",
                            direct_score.score, DIRECT_CONFIRMED_MIN_SCORE, relay_score.score
                        ),
                    )
                    .with_scores(Some(direct_score.clone()), Some(relay_score.clone()));
                }
                if direct_score.score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN < relay_score.score {
                    if !self
                        .relay_health
                        .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE)
                    {
                        return PathSelection::direct(
                            endpoint,
                            REASON_PATH_DIRECT_DEGRADED,
                            format!(
                                "direct score {} is below relay score {}, but relay is not peer-confirmed; retaining Direct with a Relay hedge",
                                direct_score.score, relay_score.score
                            ),
                            true,
                        )
                        .with_scores(Some(direct_score.clone()), Some(relay_score.clone()))
                        .with_relay_hedge();
                    }
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

        if trial_direct {
            let trial_is_viable = match (&direct_score, &relay_score) {
                (Some(direct_score), Some(_)) => direct_score.score >= DIRECT_TRIAL_MIN_SCORE,
                (Some(direct_score), None) => direct_score.score >= DIRECT_TRIAL_MIN_SCORE,
                (None, _) => true,
            };

            if trial_is_viable {
                let should_hedge_relay =
                    matches!((&direct_score, &relay_score), (Some(_), Some(_)));
                let selection = PathSelection::direct(
                    endpoint,
                    REASON_PATH_DIRECT_TRIAL,
                    direct_score
                        .as_ref()
                        .map(|score| {
                            format!(
                                "recent UDP reachability is in trial window; score={}; sending Direct with Relay hedge until encrypted data confirms",
                                score.score
                            )
                        })
                        .unwrap_or_else(|| {
                            "recent UDP reachability is in trial window; sending Direct with Relay hedge until encrypted data confirms".to_string()
                        }),
                    false,
                )
                .with_scores(direct_score, relay_score);

                return if should_hedge_relay {
                    selection.with_relay_hedge()
                } else {
                    selection
                };
            }
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

    fn mark_candidate_pair_probing_with_source(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) {
        self.ensure_candidate_pair_with_source(endpoint, local_generation, source)
            .record_probing();
    }

    fn mark_candidate_pair_success(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        latency: Option<Duration>,
        selected: bool,
    ) -> CandidatePairSource {
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        pair.record_success(latency, selected);
        pair.source
    }

    fn mark_current_candidate_pairs_failed(
        &mut self,
        local_generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Vec<CandidatePairSource> {
        let code = code.into();
        let reason = reason.into();
        let mut probed_sources = Vec::new();
        for endpoint in self.candidate_endpoints() {
            let pair = self.ensure_candidate_pair(endpoint, local_generation);
            if pair.last_probe_at.is_some() && !probed_sources.contains(&pair.source) {
                probed_sources.push(pair.source);
            }
            pair.record_failure(code.clone(), reason.clone());
        }
        probed_sources
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

    fn record_path_selection_event(&mut self, local_generation: u64, selection: &PathSelection) {
        let previous = self.last_path_selection.as_ref();
        let changed = previous
            .map(|previous| {
                previous.path != selection.path
                    || previous.reason_code != selection.reason_code
                    || previous.direct_endpoint != selection.direct_endpoint
                    || previous.relay_hedged != selection.relay_hedged
            })
            .unwrap_or(true);
        if !changed {
            return;
        }

        self.path_events.push(PathSelectionEvent {
            selected_at: Instant::now(),
            network_generation: local_generation,
            previous_path: previous.and_then(|selection| selection.path),
            selected_path: selection.path,
            direct_endpoint: selection.direct_endpoint,
            reason_code: selection.reason_code.to_string(),
            reason: selection.reason.clone(),
            direct_confirmed: selection.direct_confirmed,
            relay_hedged: selection.relay_hedged,
            direct_score: selection.direct_score.clone(),
            relay_score: selection.relay_score.clone(),
        });

        if self.path_events.len() > PATH_SELECTION_EVENT_LIMIT {
            let excess = self.path_events.len() - PATH_SELECTION_EVENT_LIMIT;
            self.path_events.drain(0..excess);
        }
    }

    fn record_direct_event(
        &mut self,
        local_generation: u64,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.direct_events.push(DirectTraversalEvent::new(
            local_generation,
            stage,
            endpoint,
            candidate_count,
            sent_probes,
            detail,
        ));

        if self.direct_events.len() > DIRECT_TRAVERSAL_EVENT_LIMIT {
            let excess = self.direct_events.len() - DIRECT_TRAVERSAL_EVENT_LIMIT;
            self.direct_events.drain(0..excess);
        }
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
    /// Latest local NAT profile used to decide whether bounded birthday probing is suitable.
    local_nat_profile: Arc<RwLock<Option<NatProfile>>>,
    /// Anonymous local traversal outcome history.
    traversal_history: Arc<RwLock<TraversalHistory>>,
    /// Optional persistent history path.
    traversal_history_path: Option<PathBuf>,
    /// Configuration.
    config: Config,
}

/// Metadata changes observed while applying one control-plane peer snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerUpdate {
    pub is_new: bool,
    pub virtual_ip_changed: bool,
    pub endpoint_changed: bool,
    pub public_key_changed: bool,
}

fn derive_probe_mac_key(config: &Config, peer_public_key: &str) -> Option<ProbeMacKey> {
    let local_private = decode_x25519_key_bytes(&config.node.private_key).ok()?;
    let peer_public = decode_x25519_key_bytes(peer_public_key).ok()?;
    let identity = NodeIdentity::from_private_key(local_private);
    let shared = identity.diffie_hellman(&peer_public).ok()?;
    Some(hmac(&shared, PROBE_MAC_KEY_DOMAIN))
}

fn decode_x25519_key_bytes(hex_value: &str) -> std::result::Result<[u8; 32], ()> {
    let bytes = hex::decode(hex_value.trim()).map_err(|_| ())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ())
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new(config: Config) -> Self {
        let history_path = traversal_history_path(&config);
        let traversal_history = TraversalHistory::load(history_path.as_deref());
        Self::new_with_history(config, history_path, traversal_history)
    }

    fn new_with_history(
        config: Config,
        traversal_history_path: Option<PathBuf>,
        traversal_history: TraversalHistory,
    ) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            ip_to_node: Arc::new(RwLock::new(HashMap::new())),
            network_generation: Arc::new(RwLock::new(0)),
            local_nat_profile: Arc::new(RwLock::new(None)),
            traversal_history: Arc::new(RwLock::new(traversal_history)),
            traversal_history_path,
            config,
        }
    }

    /// Update the latest local NAT profile used by adaptive probe scheduling.
    pub async fn update_nat_profile(&self, profile: NatProfile) {
        *self.local_nat_profile.write().await = Some(profile);
    }

    /// Bound probe rounds from the observed local NAT behavior.  Endpoint-
    /// independent NATs benefit from a short synchronized burst; dependent
    /// mappings need a wider bounded window.  UDP-blocked networks retain one
    /// lightweight attempt so the path can recover after a transient change.
    pub async fn recommended_punch_attempts(&self, configured: u32) -> u32 {
        let configured = configured.clamp(1, 10);
        let profile = self.local_nat_profile.read().await;
        match profile.as_ref().map(|profile| profile.mapping_behavior) {
            Some(MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent) => {
                configured.min(4)
            }
            Some(MappingBehavior::AddressOrPortDependent) => configured.clamp(6, 8),
            Some(MappingBehavior::UdpBlocked) => 1,
            Some(MappingBehavior::Unknown) | None => configured.min(6),
        }
    }

    /// Serializable local traversal history diagnostics.
    pub async fn traversal_history_diagnostics(&self) -> TraversalHistoryDiagnostics {
        self.traversal_history.read().await.diagnostics()
    }

    async fn record_traversal_success(&self, source: CandidatePairSource) {
        if !source.is_persisted_history_source() {
            return;
        }
        let snapshot = {
            let mut history = self.traversal_history.write().await;
            history.record_success(source);
            history.clone()
        };
        self.persist_traversal_history(&snapshot);
    }

    async fn record_traversal_failures(&self, sources: Vec<CandidatePairSource>) {
        let mut unique_sources = Vec::new();
        for source in sources {
            if source.is_persisted_history_source() && !unique_sources.contains(&source) {
                unique_sources.push(source);
            }
        }
        if unique_sources.is_empty() {
            return;
        }

        let snapshot = {
            let mut history = self.traversal_history.write().await;
            for source in unique_sources {
                history.record_failure(source);
            }
            history.clone()
        };
        self.persist_traversal_history(&snapshot);
    }

    fn persist_traversal_history(&self, history: &TraversalHistory) {
        let Some(path) = self.traversal_history_path.as_deref() else {
            return;
        };
        if let Err(error) = history.save(path) {
            warn!(
                "Failed to persist traversal history at {}: {error}",
                path.display()
            );
        }
    }

    async fn local_nat_profile_for_probe_budget(&self) -> Option<NatProfile> {
        if !self.config.network.birthday_probing_enabled {
            return None;
        }
        self.local_nat_profile.read().await.clone()
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
    pub async fn add_peer(&self, info: &PeerInfo) -> PeerUpdate {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let mut ip_map = self.ip_to_node.write().await;

        let is_new = !conns.contains_key(&info.node_id);

        let conn = conns
            .entry(info.node_id.clone())
            .or_insert_with(|| PeerConnection::new(&info.node_id, &info.virtual_ip));

        let old_virtual_ip = conn.virtual_ip.clone();
        let old_public_key = conn.public_key.clone();
        let old_signaled_endpoint = conn.signaled_endpoint;
        let virtual_ip_changed = !is_new && old_virtual_ip != info.virtual_ip;
        let public_key_changed = !is_new && old_public_key != info.public_key;

        if virtual_ip_changed
            && ip_map.get(&old_virtual_ip).map(String::as_str) == Some(info.node_id.as_str())
        {
            ip_map.remove(&old_virtual_ip);
        }
        conn.virtual_ip = info.virtual_ip.clone();
        conn.device_name = info.device_name.clone();
        if conn.public_key != info.public_key {
            conn.public_key = info.public_key.clone();
            conn.probe_mac_key = derive_probe_mac_key(&self.config, &info.public_key);
            if conn.probe_mac_key.is_none() {
                debug!(
                    "Peer {} has no usable Probe v2 MAC key; falling back to legacy UDP probes",
                    info.node_id
                );
            }
        }
        if public_key_changed {
            conn.reset_for_identity_change();
        }
        conn.nat_type = info.nat_type.clone();

        let signaled_endpoint = if info.endpoint.trim().is_empty() {
            None
        } else {
            match info.endpoint.parse::<SocketAddr>() {
                Ok(endpoint) => Some(endpoint),
                Err(error) => {
                    warn!(
                        "Ignoring invalid endpoint '{}' for peer {}: {error}",
                        info.endpoint, info.node_id
                    );
                    None
                }
            }
        };
        let endpoint_changed = !is_new && old_signaled_endpoint != signaled_endpoint;
        if (endpoint_changed && conn.endpoint == old_signaled_endpoint) || conn.endpoint.is_none() {
            conn.endpoint = signaled_endpoint;
        }
        conn.signaled_endpoint = signaled_endpoint;
        if let Some(addr) = signaled_endpoint {
            conn.ensure_candidate_pair(addr, generation);
        }

        ip_map.insert(info.virtual_ip.clone(), info.node_id.clone());
        PeerUpdate {
            is_new,
            virtual_ip_changed,
            endpoint_changed,
            public_key_changed,
        }
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

    /// Record a direct traversal timeline event for diagnostics.
    pub async fn record_direct_event(
        &self,
        node_id: &str,
        stage: impl Into<String>,
        endpoint: Option<SocketAddr>,
        candidate_count: Option<usize>,
        sent_probes: Option<u32>,
        detail: impl Into<String>,
    ) {
        let generation = self.current_network_generation().await;
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_direct_event(
                generation,
                stage,
                endpoint,
                candidate_count,
                sent_probes,
                detail,
            );
        }
    }

    /// Return the Probe v2 MAC key for a known peer, if both public keys are valid.
    pub async fn probe_key_for_peer(&self, node_id: &str) -> Option<ProbeMacKey> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.probe_mac_key)
    }

    /// Add ICE candidates for a peer.
    pub async fn add_candidates(&self, node_id: &str, candidates: &[String]) {
        // This compatibility API has always meant explicitly signaled
        // candidates.  Preserve that behavior; wire signals which genuinely
        // omit metadata enter through `add_candidates_with_metadata` and are
        // classified from their address there.
        let sources = candidates
            .iter()
            .cloned()
            .map(|candidate| (candidate, "signaled".to_string()))
            .collect::<HashMap<_, _>>();
        self.add_candidates_with_metadata(node_id, candidates, &sources, 0, None)
            .await;
    }

    /// Add ICE candidates plus optional source metadata for a peer.
    pub async fn add_candidates_with_sources(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
    ) {
        self.add_candidates_with_metadata(node_id, candidates, candidate_sources, 0, None)
            .await;
    }

    /// Install a versioned candidate set, ignoring a stale signal or an
    /// already-expired set before it can reintroduce old NAT ports.
    pub async fn add_candidates_with_metadata(
        &self,
        node_id: &str,
        candidates: &[String],
        candidate_sources: &HashMap<String, String>,
        candidate_generation: u64,
        candidates_expires_at_ms: Option<u64>,
    ) {
        let generation = self.current_network_generation().await;
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            let now_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .min(u64::MAX as u128) as u64;
            if candidates_expires_at_ms.is_some_and(|expires_at| {
                expires_at.saturating_add(CANDIDATE_EXPIRY_CLOCK_SKEW_GRACE_MS) <= now_ms
            }) {
                conn.record_direct_event(
                    generation,
                    "candidates_expired",
                    None,
                    Some(candidates.len()),
                    None,
                    "ignored expired signaled UDP candidate set",
                );
                return;
            }
            if candidate_generation != 0 && candidate_generation <= conn.last_candidate_generation {
                conn.record_direct_event(
                    generation,
                    "candidates_stale",
                    None,
                    Some(candidates.len()),
                    None,
                    format!("ignored stale candidate generation {candidate_generation}"),
                );
                return;
            }
            if candidate_generation != 0 {
                conn.last_candidate_generation = candidate_generation;
            }
            conn.last_candidates_expires_at_ms = candidates_expires_at_ms;
            let old_signaled_endpoint = conn.signaled_endpoint;
            let previous_signaled = std::mem::take(&mut conn.signaled_candidates);
            let had_previous_signaled = !previous_signaled.is_empty();
            for candidate in previous_signaled {
                let learned = matches!(
                    conn.candidate_sources.get(&candidate),
                    Some(CandidatePairSource::Learned | CandidatePairSource::PeerReflexive)
                );
                if !learned {
                    conn.candidates.retain(|existing| existing != &candidate);
                    conn.candidate_sources.remove(&candidate);
                }
            }

            // A current trickled signal is authoritative.  Keeping the node
            // registry's old endpoint forever causes port churn to accumulate
            // stale public targets and wastes each synchronized punch window.
            if had_previous_signaled {
                if let Some(endpoint) = old_signaled_endpoint {
                    if !candidates
                        .iter()
                        .any(|candidate| candidate == &endpoint.to_string())
                    {
                        conn.signaled_endpoint = None;
                        if conn.endpoint == Some(endpoint) {
                            conn.endpoint = None;
                        }
                        let endpoint = endpoint.to_string();
                        if conn.candidate_sources.get(&endpoint)
                            == Some(&CandidatePairSource::Signaled)
                        {
                            conn.candidates.retain(|candidate| candidate != &endpoint);
                            conn.candidate_sources.remove(&endpoint);
                        }
                    }
                }
            }

            for c in candidates {
                if !conn.candidates.contains(c) {
                    conn.candidates.push(c.clone());
                }
                conn.signaled_candidates.insert(c.clone());
                // Old peers did not send candidate_sources.  Classifying
                // their literal socket address keeps a private LAN candidate
                // from taking precedence over a public server-reflexive one.
                let source = candidate_sources
                    .get(c)
                    .and_then(|value| candidate_pair_source_from_label(value))
                    .unwrap_or_else(|| infer_unlabeled_candidate_source(c));
                conn.candidate_sources.insert(c.clone(), source);
                if let Ok(endpoint) = c.parse::<SocketAddr>() {
                    conn.ensure_candidate_pair_with_source(endpoint, generation, source);
                }
            }

            if !candidates.is_empty() {
                conn.record_direct_event(
                    generation,
                    "candidates_received",
                    None,
                    Some(candidates.len()),
                    None,
                    format!(
                        "received {} signaled UDP candidates with {} source labels",
                        candidates.len(),
                        candidate_sources.len()
                    ),
                );
            }

            if conn.endpoint.is_none() {
                conn.endpoint = conn
                    .candidates
                    .iter()
                    .find_map(|candidate| candidate.parse::<SocketAddr>().ok());
            }
        }
    }

    /// Whether a bidirectional UDP probe succeeded in the current generation.
    pub async fn has_direct_probe_success_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> bool {
        generation == self.current_network_generation().await
            && self
                .connections
                .read()
                .await
                .get(node_id)
                .is_some_and(|conn| {
                    conn.candidate_pairs.iter().any(|pair| {
                        pair.local_generation == generation
                            && matches!(
                                pair.state,
                                CandidatePairState::Succeeded | CandidatePairState::Selected
                            )
                    })
                })
    }

    /// Monotonic count of matched bidirectional probe ACKs for one peer and
    /// generation. Callers can snapshot this before a probe round and require
    /// it to increase, avoiding false success from an older Succeeded pair.
    pub async fn direct_probe_success_count_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> u64 {
        if generation != self.current_network_generation().await {
            return 0;
        }
        self.connections
            .read()
            .await
            .get(node_id)
            .map(|conn| {
                conn.candidate_pairs
                    .iter()
                    .filter(|pair| pair.local_generation == generation)
                    .map(|pair| pair.success_count)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Learn an endpoint from an authenticated Probe v2 packet.
    ///
    /// Unlike legacy endpoint learning, this may accept a peer-reflexive source
    /// address that was not present in the control-plane candidate set because
    /// the probe MAC proves the sender controls the peer identity.
    pub async fn learn_authenticated_endpoint(&self, node_id: &str, endpoint: SocketAddr) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };

        if let Some(previous_endpoint) = conn.endpoint {
            let previous_endpoint_text = previous_endpoint.to_string();
            if !conn.candidates.contains(&previous_endpoint_text) {
                conn.candidates.push(previous_endpoint_text);
            }
        }
        conn.endpoint = Some(endpoint);
        let endpoint_text = endpoint.to_string();
        if !conn.candidates.contains(&endpoint_text) {
            conn.candidates.push(endpoint_text.clone());
        }
        conn.candidate_sources
            .insert(endpoint_text, CandidatePairSource::PeerReflexive);
        conn.mark_candidate_pair_probing_with_source(
            endpoint,
            generation,
            CandidatePairSource::PeerReflexive,
        );
        true
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
                conn.candidate_sources
                    .insert(endpoint.to_string(), CandidatePairSource::Learned);
                conn.mark_candidate_pair_probing_with_source(
                    endpoint,
                    generation,
                    CandidatePairSource::Learned,
                );
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

    /// Return candidate endpoints for a specific peer using the adaptive probe scheduler.
    pub async fn direct_probe_targets_for(&self, node_id: &str) -> Vec<SocketAddr> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return Vec::new();
        };
        if conn.state == ConnectionState::Direct {
            return Vec::new();
        }
        let endpoints =
            conn.candidate_probe_endpoints(generation, &history, local_nat_profile.as_ref());
        for endpoint in &endpoints {
            conn.mark_candidate_pair_probing(*endpoint, generation);
        }
        if !endpoints.is_empty() {
            conn.record_direct_event(
                generation,
                "probe_targets_selected",
                endpoints.first().copied(),
                Some(endpoints.len()),
                None,
                format!(
                    "selected {} UDP candidates for synchronized punching",
                    endpoints.len()
                ),
            );
        }
        endpoints
    }

    /// Return candidate endpoints that should continue receiving direct-path probes.
    pub async fn direct_probe_targets(&self) -> Vec<(String, Vec<SocketAddr>)> {
        let generation = self.current_network_generation().await;
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        self.connections
            .write()
            .await
            .values_mut()
            .filter(|conn| conn.state != ConnectionState::Direct)
            .filter_map(|conn| {
                let endpoints = conn.candidate_probe_endpoints(
                    generation,
                    &history,
                    local_nat_profile.as_ref(),
                );

                if endpoints.is_empty() {
                    None
                } else {
                    for endpoint in &endpoints {
                        conn.mark_candidate_pair_probing(*endpoint, generation);
                    }
                    conn.record_direct_event(
                        generation,
                        "probe_targets_due",
                        endpoints.first().copied(),
                        Some(endpoints.len()),
                        None,
                        format!(
                            "selected {} UDP candidates for background retry",
                            endpoints.len()
                        ),
                    );
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
        let history = self.traversal_history.read().await.clone();
        let local_nat_profile = self.local_nat_profile_for_probe_budget().await;
        self.connections
            .write()
            .await
            .values_mut()
            .filter(|conn| conn.state != ConnectionState::Direct)
            .filter(|conn| conn.direct_retry_due(base_retry_after))
            .filter_map(|conn| {
                let endpoints = conn.candidate_probe_endpoints(
                    generation,
                    &history,
                    local_nat_profile.as_ref(),
                );

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
                conn.record_path_selection_event(generation, &selection);
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

    /// Whether the peer is currently in Relay state.
    pub async fn is_relay(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .map(|conn| conn.state == ConnectionState::Relay)
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
        let source = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let selected_endpoint = endpoint.or(conn.endpoint);
            let source = selected_endpoint.map(|endpoint| {
                conn.endpoint = Some(endpoint);
                conn.mark_candidate_pair_success(endpoint, generation, None, true)
            });
            conn.direct_generation = generation;
            conn.direct_health.record_success();
            conn.record_direct_event(
                generation,
                "direct_confirmed",
                selected_endpoint,
                selected_endpoint.map(|_| 1),
                None,
                "encrypted data path confirmed Direct UDP",
            );
            conn.transition(ConnectionState::Direct);
            source
        };
        if let Some(source) = source {
            self.record_traversal_success(source).await;
        }
        true
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
        let source = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            conn.endpoint = Some(endpoint);
            let ack_confirmed = latency.is_some();
            let source = if ack_confirmed {
                Some(conn.mark_candidate_pair_success(endpoint, generation, latency, false))
            } else {
                conn.mark_candidate_pair_probing(endpoint, generation);
                None
            };
            match latency {
                Some(latency) => {
                    conn.record_direct_event(
                        generation,
                        "probe_ack_received",
                        Some(endpoint),
                        Some(1),
                        None,
                        format!(
                            "received UDP punch ACK from {endpoint} rtt={}ms",
                            duration_millis(latency)
                        ),
                    );
                    conn.direct_health.record_success_with_latency(latency);
                }
                None => conn.direct_health.record_success(),
            }
            if !ack_confirmed {
                conn.record_direct_event(
                    generation,
                    "inbound_probe_received",
                    Some(endpoint),
                    Some(1),
                    None,
                    format!("received inbound UDP probe from {endpoint}"),
                );
            }
            if conn.state != ConnectionState::Direct
                && matches!(
                    conn.state,
                    ConnectionState::Idle
                        | ConnectionState::Connecting
                        | ConnectionState::FallbackToRelay
                )
            {
                conn.transition(ConnectionState::HolePunching);
            }
            source
        };
        if let Some(source) = source {
            self.record_traversal_success(source).await;
        }
        true
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
        let probed_sources = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let code = code.into();
            let reason = reason.into();
            conn.direct_health
                .record_failure(code.clone(), reason.clone());
            conn.record_direct_event(
                generation,
                code.clone(),
                conn.endpoint,
                Some(conn.candidate_pairs.len()),
                None,
                reason.clone(),
            );
            let probed_sources = conn.mark_current_candidate_pairs_failed(generation, code, reason);
            if conn.state != ConnectionState::Relay {
                conn.transition(ConnectionState::FallbackToRelay);
            }
            probed_sources
        };
        self.record_traversal_failures(probed_sources).await;
        true
    }

    /// Record an unanswered direct keepalive without tearing down a path on one lost probe.
    pub async fn record_direct_keepalive_timeout_for_generation(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }

        let source = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            if conn.direct_generation != generation || conn.state != ConnectionState::Direct {
                return false;
            }

            let reason = format!("direct keepalive ACK timeout for {endpoint}");
            conn.direct_health
                .record_failure(REASON_DIRECT_KEEPALIVE_TIMEOUT, reason.clone());
            let pair = conn.ensure_candidate_pair(endpoint, generation);
            let source = pair.source;
            pair.record_failure(REASON_DIRECT_KEEPALIVE_TIMEOUT, reason);

            if conn.direct_health.consecutive_failures >= DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
                conn.transition(ConnectionState::FallbackToRelay);
            }
            source
        };
        self.record_traversal_failures(vec![source]).await;
        true
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

    /// Record that a relay path was attempted without treating TCP write success as delivery.
    pub async fn record_relay_attempt(&self, node_id: &str, relay_server: &str) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.relay_server = Some(relay_server.to_string());
        }
    }

    /// Record a relay-path failure for a specific peer.
    pub async fn record_relay_failure(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.relay_health.record_failure(code, reason);
            if conn.state == ConnectionState::Relay {
                conn.transition(ConnectionState::FallbackToRelay);
            }
        }
    }

    /// Invalidate every peer confirmation associated with a relay transport.
    pub async fn invalidate_relay_transport(
        &self,
        relay_server: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        let code = code.into();
        let reason = reason.into();
        for conn in self.connections.write().await.values_mut() {
            if conn.relay_server.as_deref() != Some(relay_server) {
                continue;
            }
            conn.relay_health
                .record_failure(code.clone(), reason.clone());
            conn.relay_server = None;
            if conn.state == ConnectionState::Relay {
                conn.transition(ConnectionState::FallbackToRelay);
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
        let generation = self.current_network_generation().await;
        let mut peers: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .map(|conn| {
                PeerDiagnostics::from_connection_with_path_selection(conn, None, None, generation)
            })
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
                    generation,
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

impl PeerManagerStats {
    /// Build aggregate statistics from diagnostics using the live selected data path.
    pub fn from_diagnostics(peers: &[PeerDiagnostics]) -> Self {
        Self {
            total_peers: peers.len(),
            direct_connections: peers
                .iter()
                .filter(|peer| peer.active_path == Some(NetworkPath::Direct))
                .count(),
            relay_connections: peers
                .iter()
                .filter(|peer| peer.active_path == Some(NetworkPath::Relay))
                .count(),
            total_bytes_sent: peers.iter().map(|peer| peer.bytes_sent).sum(),
            total_bytes_received: peers.iter().map(|peer| peer.bytes_received).sum(),
        }
    }
}

/// Aggregated direct candidate-pair outcomes grouped by endpoint source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePairSourceStats {
    pub source: CandidatePairSource,
    pub pair_count: u64,
    pub current_pair_count: u64,
    pub selected_count: u64,
    pub succeeded_count: u64,
    pub probing_count: u64,
    pub failed_count: u64,
    pub degraded_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub success_rate_per_mille: Option<u16>,
    pub last_success_age_ms: Option<u64>,
    pub last_failure_age_ms: Option<u64>,
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
    pub candidate_pair_stats: Vec<CandidatePairSourceStats>,
    pub candidate_pairs: Vec<CandidatePairDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_retry_remaining_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_path_selection: Option<PathSelectionDiagnostics>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_path_selection: Option<PathSelectionDiagnostics>,
    pub path_events: Vec<PathSelectionEventDiagnostics>,
    pub direct_events: Vec<DirectTraversalEventDiagnostics>,
}

impl PeerDiagnostics {
    fn from_connection_with_path_selection(
        conn: &PeerConnection,
        current_selection: Option<&PathSelection>,
        direct_retry_after: Option<Duration>,
        local_generation: u64,
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
            active_path: match current_selection {
                Some(selection) => match selection.path {
                    Some(NetworkPath::Direct) if selection.direct_confirmed => {
                        Some(NetworkPath::Direct)
                    }
                    Some(NetworkPath::Direct)
                        if conn
                            .relay_health
                            .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                    {
                        Some(NetworkPath::Relay)
                    }
                    Some(NetworkPath::Relay)
                        if conn
                            .relay_health
                            .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                    {
                        Some(NetworkPath::Relay)
                    }
                    _ => None,
                },
                None => match conn.active_path() {
                    Some(NetworkPath::Relay)
                        if !conn
                            .relay_health
                            .is_confirmed_recent(RELAY_PEER_CONFIRMATION_MAX_AGE) =>
                    {
                        None
                    }
                    path => path,
                },
            },
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
            candidate_pair_stats: candidate_pair_source_stats(
                &conn.candidate_pairs,
                local_generation,
            ),
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
            path_events: conn
                .path_events
                .iter()
                .map(PathSelectionEventDiagnostics::from)
                .collect(),
            direct_events: conn
                .direct_events
                .iter()
                .map(DirectTraversalEventDiagnostics::from)
                .collect(),
        }
    }
}

impl From<&PeerConnection> for PeerDiagnostics {
    fn from(conn: &PeerConnection) -> Self {
        Self::from_connection_with_path_selection(conn, None, None, conn.direct_generation)
    }
}

/// Serializable path-selector transition diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSelectionEventDiagnostics {
    pub selected_age_ms: u64,
    pub network_generation: u64,
    pub previous_path: Option<NetworkPath>,
    pub selected_path: Option<NetworkPath>,
    pub direct_endpoint: Option<String>,
    pub reason_code: String,
    pub reason: String,
    pub direct_confirmed: bool,
    pub relay_hedged: bool,
    pub direct_score: Option<PathScoreDiagnostics>,
    pub relay_score: Option<PathScoreDiagnostics>,
}

impl From<&PathSelectionEvent> for PathSelectionEventDiagnostics {
    fn from(event: &PathSelectionEvent) -> Self {
        Self {
            selected_age_ms: duration_millis(event.selected_at.elapsed()),
            network_generation: event.network_generation,
            previous_path: event.previous_path,
            selected_path: event.selected_path,
            direct_endpoint: event.direct_endpoint.map(|endpoint| endpoint.to_string()),
            reason_code: event.reason_code.clone(),
            reason: event.reason.clone(),
            direct_confirmed: event.direct_confirmed,
            relay_hedged: event.relay_hedged,
            direct_score: event.direct_score.as_ref().map(PathScoreDiagnostics::from),
            relay_score: event.relay_score.as_ref().map(PathScoreDiagnostics::from),
        }
    }
}

/// Serializable direct traversal timeline event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectTraversalEventDiagnostics {
    pub age_ms: u64,
    pub network_generation: u64,
    pub stage: String,
    pub endpoint: Option<String>,
    pub candidate_count: Option<usize>,
    pub sent_probes: Option<u32>,
    pub detail: String,
}

impl From<&DirectTraversalEvent> for DirectTraversalEventDiagnostics {
    fn from(event: &DirectTraversalEvent) -> Self {
        Self {
            age_ms: duration_millis(event.recorded_at.elapsed()),
            network_generation: event.network_generation,
            stage: event.stage.clone(),
            endpoint: event.endpoint.map(|endpoint| endpoint.to_string()),
            candidate_count: event.candidate_count,
            sent_probes: event.sent_probes,
            detail: event.detail.clone(),
        }
    }
}

/// Serializable candidate-pair diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CandidatePairDiagnostics {
    pub remote_endpoint: String,
    pub source: CandidatePairSource,
    pub local_generation: u64,
    pub state: CandidatePairState,
    pub last_probe_age_ms: Option<u64>,
    pub probe_count: u64,
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
            source: pair.source,
            local_generation: pair.local_generation,
            state: pair.state,
            last_probe_age_ms: pair.last_probe_at.map(|at| duration_millis(at.elapsed())),
            probe_count: pair.probe_count,
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

fn candidate_pair_source_stats(
    pairs: &[CandidatePair],
    local_generation: u64,
) -> Vec<CandidatePairSourceStats> {
    [
        CandidatePairSource::PeerReflexive,
        CandidatePairSource::Learned,
        CandidatePairSource::Host,
        CandidatePairSource::Upnp,
        CandidatePairSource::Pcp,
        CandidatePairSource::NatPmp,
        CandidatePairSource::StunObserved,
        CandidatePairSource::Signaled,
        CandidatePairSource::Predicted,
        CandidatePairSource::Birthday,
    ]
    .into_iter()
    .filter_map(|source| candidate_pair_source_stats_for(pairs, local_generation, source))
    .collect()
}

fn candidate_pair_source_stats_for(
    pairs: &[CandidatePair],
    local_generation: u64,
    source: CandidatePairSource,
) -> Option<CandidatePairSourceStats> {
    let mut pair_count = 0u64;
    let mut current_pair_count = 0u64;
    let mut selected_count = 0u64;
    let mut succeeded_count = 0u64;
    let mut probing_count = 0u64;
    let mut failed_count = 0u64;
    let mut degraded_count = 0u64;
    let mut success_count = 0u64;
    let mut failure_count = 0u64;
    let mut last_success_at: Option<Instant> = None;
    let mut last_failure_at: Option<Instant> = None;

    for pair in pairs.iter().filter(|pair| pair.source == source) {
        pair_count = pair_count.saturating_add(1);
        if pair.local_generation == local_generation {
            current_pair_count = current_pair_count.saturating_add(1);
        }
        match pair.state {
            CandidatePairState::Selected => selected_count = selected_count.saturating_add(1),
            CandidatePairState::Succeeded => succeeded_count = succeeded_count.saturating_add(1),
            CandidatePairState::Probing => probing_count = probing_count.saturating_add(1),
            CandidatePairState::Failed => failed_count = failed_count.saturating_add(1),
            CandidatePairState::Degraded => degraded_count = degraded_count.saturating_add(1),
            CandidatePairState::Frozen | CandidatePairState::Waiting => {}
        }
        success_count = success_count.saturating_add(pair.success_count);
        failure_count = failure_count.saturating_add(pair.failure_count);
        last_success_at = latest_instant(last_success_at, pair.last_success_at);
        last_failure_at = latest_instant(last_failure_at, pair.last_failure_at);
    }

    (pair_count > 0).then(|| CandidatePairSourceStats {
        source,
        pair_count,
        current_pair_count,
        selected_count,
        succeeded_count,
        probing_count,
        failed_count,
        degraded_count,
        success_count,
        failure_count,
        success_rate_per_mille: success_rate_per_mille(success_count, failure_count),
        last_success_age_ms: last_success_at.map(|at| duration_millis(at.elapsed())),
        last_failure_age_ms: last_failure_at.map(|at| duration_millis(at.elapsed())),
    })
}

fn apply_adaptive_probe_budgets<'a>(
    pairs: Vec<&'a CandidatePair>,
    stats: &[CandidatePairSourceStats],
    history: &TraversalHistory,
) -> Vec<&'a CandidatePair> {
    let predicted_budget = predicted_probe_budget(stats, history);
    let birthday_budget = birthday_probe_budget(history);
    let mut predicted_used = 0usize;
    let mut birthday_used = 0usize;
    pairs
        .into_iter()
        .filter(|pair| match pair.source {
            CandidatePairSource::Predicted => {
                if predicted_used < predicted_budget {
                    predicted_used += 1;
                    true
                } else {
                    false
                }
            }
            CandidatePairSource::Birthday => {
                if birthday_used < birthday_budget {
                    birthday_used += 1;
                    true
                } else {
                    false
                }
            }
            _ => true,
        })
        .collect()
}

fn predicted_probe_budget(stats: &[CandidatePairSourceStats], history: &TraversalHistory) -> usize {
    if history.source_in_cooldown(CandidatePairSource::Predicted) {
        return PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE;
    }
    if history
        .source(CandidatePairSource::Predicted)
        .is_some_and(|entry| entry.consecutive_failures >= 3)
    {
        return PREDICTED_PROBE_FAILURE_BUDGET_PER_CYCLE;
    }
    if history
        .source(CandidatePairSource::Predicted)
        .is_some_and(|entry| {
            entry.success_count >= 2 && entry.success_rate_per_mille().unwrap_or(0) >= 500
        })
    {
        return PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE;
    }
    if stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .is_some_and(|stats| stats.success_count > 0)
    {
        return PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE;
    }
    PREDICTED_PROBE_BUDGET_PER_CYCLE
}

fn birthday_probe_budget(history: &TraversalHistory) -> usize {
    if history.source_in_cooldown(CandidatePairSource::Birthday) {
        return 0;
    }
    if history
        .source(CandidatePairSource::Birthday)
        .is_some_and(|entry| entry.consecutive_failures >= 3)
    {
        return 0;
    }
    if history
        .source(CandidatePairSource::Birthday)
        .is_some_and(|entry| {
            entry.success_count > 0 && entry.success_rate_per_mille().unwrap_or(0) >= 500
        })
    {
        return BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE;
    }
    BIRTHDAY_PROBE_BUDGET_PER_CYCLE
}

fn latest_instant(current: Option<Instant>, candidate: Option<Instant>) -> Option<Instant> {
    match (current, candidate) {
        (Some(current), Some(candidate)) => Some(current.max(candidate)),
        (Some(current), None) => Some(current),
        (None, Some(candidate)) => Some(candidate),
        (None, None) => None,
    }
}

fn success_rate_per_mille(success_count: u64, failure_count: u64) -> Option<u16> {
    let total = success_count.saturating_add(failure_count);
    if total == 0 {
        return None;
    }
    Some(((success_count.saturating_mul(1000)) / total).min(1000) as u16)
}

fn candidate_pair_source_from_label(label: &str) -> Option<CandidatePairSource> {
    match label {
        "predicted" => Some(CandidatePairSource::Predicted),
        "peer_reflexive" => Some(CandidatePairSource::PeerReflexive),
        "learned" => Some(CandidatePairSource::Learned),
        "host" => Some(CandidatePairSource::Host),
        "stun_observed" => Some(CandidatePairSource::StunObserved),
        "upnp" | "port_mapping" => Some(CandidatePairSource::Upnp),
        "pcp" => Some(CandidatePairSource::Pcp),
        "nat_pmp" | "nat-pmp" => Some(CandidatePairSource::NatPmp),
        "birthday" => Some(CandidatePairSource::Birthday),
        "signaled" | "manual" => Some(CandidatePairSource::Signaled),
        _ => None,
    }
}

/// Best-effort compatibility classification for candidate sets from older
/// clients that predate `candidate_sources` metadata.  A public socket is not
/// proof that it was STUN-derived, but it is the safest first-round target for
/// a cross-LAN punch; RFC1918/link-local addresses remain host candidates.
fn infer_unlabeled_candidate_source(candidate: &str) -> CandidatePairSource {
    candidate
        .parse::<SocketAddr>()
        .ok()
        .filter(|endpoint| is_public_probe_endpoint(*endpoint))
        .map(|_| CandidatePairSource::StunObserved)
        .unwrap_or(CandidatePairSource::Host)
}

fn candidate_pair_source_quality_rank(
    stats: &[CandidatePairSourceStats],
    history: &TraversalHistory,
    source: CandidatePairSource,
) -> u16 {
    if history.source_in_cooldown(source) {
        return 1100;
    }
    if let Some(rate) = history.source_success_rate_per_mille(source) {
        return 1000u16.saturating_sub(rate);
    }
    let Some(stats) = stats.iter().find(|stats| stats.source == source) else {
        return 500;
    };
    let Some(rate) = stats.success_rate_per_mille else {
        return 500;
    };
    1000u16.saturating_sub(rate)
}

fn candidate_pair_source_rank(source: CandidatePairSource) -> u8 {
    match source {
        CandidatePairSource::PeerReflexive => 0,
        CandidatePairSource::Learned => 1,
        CandidatePairSource::Host => 2,
        CandidatePairSource::Upnp => 3,
        CandidatePairSource::Pcp => 4,
        CandidatePairSource::NatPmp => 5,
        CandidatePairSource::StunObserved => 6,
        CandidatePairSource::Signaled => 7,
        CandidatePairSource::Predicted => 8,
        CandidatePairSource::Birthday => 9,
    }
}

/// An endpoint observed from an authenticated packet is more valuable than
/// address-family ranking: it already proves that the peer can reach us.
/// Everything else is ordered by public-vs-private reachability first.
fn discovered_endpoint_probe_rank(source: CandidatePairSource) -> u8 {
    match source {
        CandidatePairSource::PeerReflexive => 0,
        CandidatePairSource::Learned => 1,
        _ => 2,
    }
}

fn birthday_probe_endpoints(base: SocketAddr) -> Vec<SocketAddr> {
    const DELTAS: [i32; 30] = [
        1, -1, 2, -2, 3, -3, 4, -4, 5, -5, 6, -6, 8, -8, 10, -10, 12, -12, 16, -16, 20, -20, 24,
        -24, 32, -32, 48, -48, 64, -64,
    ];

    DELTAS
        .into_iter()
        .filter_map(|delta| {
            let port = base.port() as i32 + delta;
            let port = u16::try_from(port).ok()?;
            (port > 0).then_some(SocketAddr::new(base.ip(), port))
        })
        .collect()
}

fn is_public_probe_endpoint(endpoint: SocketAddr) -> bool {
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            !ip.is_loopback()
                && !ip.is_private()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !is_shared_ipv4(ip)
        }
        IpAddr::V6(ip) => {
            let first_segment = ip.segments()[0];
            let is_unique_local = (first_segment & 0xfe00) == 0xfc00;
            let is_link_local = (first_segment & 0xffc0) == 0xfe80;
            !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unspecified()
                && !is_unique_local
                && !is_link_local
        }
    }
}

fn is_shared_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn endpoint_probe_rank(endpoint: SocketAddr) -> u8 {
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            if ip.is_loopback() || ip.is_private() || ip.is_link_local() {
                // A plain signaled RFC1918 endpoint is usually from a
                // different LAN.  It must not consume the first synchronized
                // punch window ahead of a public srflx endpoint.  Properly
                // labelled `host` candidates still receive their dedicated
                // source priority above, preserving same-LAN fast paths.
                3
            } else {
                1
            }
        }
        IpAddr::V6(ip) => {
            let first_segment = ip.segments()[0];
            let is_unique_local = (first_segment & 0xfe00) == 0xfc00;
            let is_link_local = (first_segment & 0xffc0) == 0xfe80;
            if ip.is_loopback() || is_unique_local || is_link_local {
                3
            } else {
                0
            }
        }
    }
}

fn candidate_pair_probe_rank(state: CandidatePairState) -> u8 {
    match state {
        CandidatePairState::Waiting | CandidatePairState::Probing => 0,
        CandidatePairState::Succeeded => 1,
        CandidatePairState::Selected => 2,
        CandidatePairState::Failed => 4,
        CandidatePairState::Degraded => 5,
        CandidatePairState::Frozen => 6,
    }
}

fn candidate_pair_send_rank(pair: &CandidatePair) -> u8 {
    match pair.state {
        CandidatePairState::Selected => 0,
        CandidatePairState::Succeeded | CandidatePairState::Probing
            if pair.source == CandidatePairSource::PeerReflexive
                && pair.last_probe_at.is_some_and(|last_probe| {
                    last_probe.elapsed() <= PEER_REFLEXIVE_STICKY_WINDOW
                }) =>
        {
            1
        }
        CandidatePairState::Succeeded => 2,
        CandidatePairState::Probing => 3,
        CandidatePairState::Waiting => 4,
        CandidatePairState::Failed => 5,
        CandidatePairState::Degraded => 6,
        CandidatePairState::Frozen => 7,
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

    #[test]
    fn unlabelled_private_candidates_do_not_beat_public_candidates() {
        let private: SocketAddr = "192.168.1.188:51820".parse().unwrap();
        let public: SocketAddr = "203.0.113.10:51820".parse().unwrap();
        assert!(endpoint_probe_rank(public) < endpoint_probe_rank(private));
    }

    fn test_config() -> Config {
        Config::generate_default("https://ctrl.test", "net1").unwrap()
    }

    fn birthday_nat_profile() -> NatProfile {
        NatProfile {
            local_addr: "0.0.0.0:60207".to_string(),
            observations: Vec::new(),
            udp_blocked: false,
            public_endpoint: Some("203.0.113.10:40007".to_string()),
            public_ip_stable: Some(true),
            public_port_stable: Some(false),
            port_preserved: Some(false),
            port_delta: None,
            likely_symmetric: Some(true),
            mapping_behavior: p2pnet_nat::MappingBehavior::AddressOrPortDependent,
            filtering_behavior: p2pnet_nat::FilteringBehavior::AddressOrPortDependent,
            hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
            mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
            prediction_candidate: false,
            predicted_endpoints: Vec::new(),
            birthday_candidate: true,
            confidence: 70,
        }
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
    async fn peer_update_removes_old_virtual_ip_and_clears_signaled_endpoint() {
        let manager = PeerManager::new(test_config());
        let mut peer = test_peer("peer1", "1.2.3.4:5000".parse().unwrap());
        manager.add_peer(&peer).await;

        peer.virtual_ip = "10.20.0.9".to_string();
        peer.endpoint.clear();
        let update = manager.add_peer(&peer).await;

        assert!(update.virtual_ip_changed);
        assert!(update.endpoint_changed);
        assert_eq!(manager.resolve_virtual_ip("10.20.0.2").await, None);
        assert_eq!(
            manager.resolve_virtual_ip("10.20.0.9").await.as_deref(),
            Some("peer1")
        );
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.signaled_endpoint, None);
        assert_eq!(conn.endpoint, None);
    }

    #[tokio::test]
    async fn clearing_signaled_endpoint_preserves_authenticated_peer_reflexive_endpoint() {
        let manager = PeerManager::new(test_config());
        let mut peer = test_peer("peer1", "1.2.3.4:5000".parse().unwrap());
        manager.add_peer(&peer).await;
        let learned: SocketAddr = "5.6.7.8:6000".parse().unwrap();
        assert!(manager.learn_authenticated_endpoint("peer1", learned).await);

        peer.endpoint.clear();
        manager.add_peer(&peer).await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.signaled_endpoint, None);
        assert_eq!(conn.endpoint, Some(learned));
    }

    #[tokio::test]
    async fn candidate_signal_replaces_old_signaled_set_but_preserves_learned_endpoint() {
        let manager = PeerManager::new(test_config());
        let peer = test_peer("peer1", "1.2.3.4:5000".parse().unwrap());
        manager.add_peer(&peer).await;
        manager
            .add_candidates("peer1", &["2.2.2.2:5000".to_string()])
            .await;
        let learned: SocketAddr = "3.3.3.3:5000".parse().unwrap();
        assert!(manager.learn_authenticated_endpoint("peer1", learned).await);

        manager
            .add_candidates("peer1", &["4.4.4.4:5000".to_string()])
            .await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert!(!conn.candidates.contains(&"2.2.2.2:5000".to_string()));
        assert!(conn.candidates.contains(&"4.4.4.4:5000".to_string()));
        assert!(conn.candidates.contains(&learned.to_string()));
    }

    #[tokio::test]
    async fn public_key_change_resets_confirmed_paths() {
        let manager = PeerManager::new(test_config());
        let endpoint: SocketAddr = "1.2.3.4:5000".parse().unwrap();
        let mut peer = test_peer("peer1", endpoint);
        manager.add_peer(&peer).await;
        manager.record_direct_success("peer1", Some(endpoint)).await;
        manager.set_relay("peer1", "relay.test:443").await;

        peer.public_key = "new-key".to_string();
        let update = manager.add_peer(&peer).await;
        assert!(update.public_key_changed);
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.active_path(), None);
        assert_eq!(conn.relay_server, None);
        assert!(conn.direct_health.last_success_at.is_none());
        assert!(conn.relay_health.last_success_at.is_none());
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
        assert_eq!(conn.candidate_pairs[0].state, CandidatePairState::Succeeded);
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
        assert!(manager.direct_endpoints().await.is_empty());
        manager
            .record_direct_success("peer1", Some(new_endpoint))
            .await;
        assert_eq!(
            manager.direct_endpoints().await,
            vec![("peer1".to_string(), new_endpoint)]
        );
    }

    #[tokio::test]
    async fn candidate_pair_stats_aggregate_real_outcomes_by_source() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let signaled_endpoint: SocketAddr = "127.0.0.1:51836".parse().unwrap();
        let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51837".parse().unwrap();

        manager
            .add_peer(&test_peer("peer1", signaled_endpoint))
            .await;

        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.ensure_candidate_pair_with_source(
                signaled_endpoint,
                0,
                CandidatePairSource::Signaled,
            )
            .record_success(Some(Duration::from_millis(12)), false);
            let peer_reflexive = conn.ensure_candidate_pair_with_source(
                peer_reflexive_endpoint,
                0,
                CandidatePairSource::PeerReflexive,
            );
            peer_reflexive.record_success(Some(Duration::from_millis(9)), false);
            peer_reflexive.record_failure(REASON_DIRECT_PROBE_FAILED, "no ACK");
        }

        let diagnostics = manager.diagnostics().await;
        let stats = &diagnostics[0].candidate_pair_stats;
        let signaled = stats
            .iter()
            .find(|stats| stats.source == CandidatePairSource::Signaled)
            .unwrap();
        assert_eq!(signaled.pair_count, 1);
        assert_eq!(signaled.current_pair_count, 1);
        assert_eq!(signaled.success_count, 1);
        assert_eq!(signaled.failure_count, 0);
        assert_eq!(signaled.success_rate_per_mille, Some(1000));

        let peer_reflexive = stats
            .iter()
            .find(|stats| stats.source == CandidatePairSource::PeerReflexive)
            .unwrap();
        assert_eq!(peer_reflexive.pair_count, 1);
        assert_eq!(peer_reflexive.degraded_count, 1);
        assert_eq!(peer_reflexive.success_count, 1);
        assert_eq!(peer_reflexive.failure_count, 1);
        assert_eq!(peer_reflexive.success_rate_per_mille, Some(500));

        let json = serde_json::to_value(&diagnostics[0]).unwrap();
        assert_eq!(json["candidate_pair_stats"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn candidate_pairs_record_predicted_source_from_signal_metadata() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager
            .add_candidates_with_sources(
                "peer1",
                &["203.0.113.10:40007".to_string()],
                &HashMap::from([("203.0.113.10:40007".to_string(), "predicted".to_string())]),
            )
            .await;

        let diagnostics = manager.diagnostics().await;
        let predicted = diagnostics[0]
            .candidate_pair_stats
            .iter()
            .find(|stats| stats.source == CandidatePairSource::Predicted)
            .unwrap();
        assert_eq!(predicted.current_pair_count, 1);
        assert!(diagnostics[0].candidate_pairs.iter().any(|pair| {
            pair.remote_endpoint == "203.0.113.10:40007"
                && pair.source == CandidatePairSource::Predicted
        }));
    }

    #[tokio::test]
    async fn fresh_candidate_signal_replaces_stale_registry_endpoint() {
        let manager = PeerManager::new(test_config());
        let stale: SocketAddr = "203.0.113.10:41000".parse().unwrap();
        let fresh: SocketAddr = "203.0.113.10:42000".parse().unwrap();
        manager.add_peer(&test_peer("peer1", stale)).await;

        manager
            .add_candidates("peer1", &["203.0.113.10:41500".to_string()])
            .await;
        manager.add_candidates("peer1", &[fresh.to_string()]).await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.signaled_endpoint, None);
        assert!(!conn.candidates.contains(&stale.to_string()));
        assert!(conn.candidates.contains(&fresh.to_string()));
        assert_eq!(conn.endpoint, Some(fresh));
    }

    #[tokio::test]
    async fn versioned_candidates_reject_stale_and_expired_sets() {
        let manager = PeerManager::new(test_config());
        let initial: SocketAddr = "203.0.113.10:42000".parse().unwrap();
        let stale: SocketAddr = "203.0.113.10:41000".parse().unwrap();
        let expired: SocketAddr = "203.0.113.10:43000".parse().unwrap();
        manager.add_peer(&test_peer("peer1", initial)).await;

        manager
            .add_candidates_with_metadata(
                "peer1",
                &[initial.to_string()],
                &HashMap::new(),
                10,
                Some(u64::MAX),
            )
            .await;
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[stale.to_string()],
                &HashMap::new(),
                9,
                Some(u64::MAX),
            )
            .await;
        manager
            .add_candidates_with_metadata(
                "peer1",
                &[expired.to_string()],
                &HashMap::new(),
                11,
                Some(1),
            )
            .await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.last_candidate_generation, 10);
        assert!(conn.candidates.contains(&initial.to_string()));
        assert!(!conn.candidates.contains(&stale.to_string()));
        assert!(!conn.candidates.contains(&expired.to_string()));
        assert!(conn
            .direct_events
            .iter()
            .any(|event| event.stage == "candidates_stale"));
        assert!(conn
            .direct_events
            .iter()
            .any(|event| event.stage == "candidates_expired"));
    }

    #[tokio::test]
    async fn punch_rounds_follow_observed_nat_behavior() {
        let manager = PeerManager::new(test_config());
        assert_eq!(manager.recommended_punch_attempts(10).await, 6);

        let mut endpoint_independent = birthday_nat_profile();
        endpoint_independent.mapping_behavior = MappingBehavior::EndpointIndependent;
        manager.update_nat_profile(endpoint_independent).await;
        assert_eq!(manager.recommended_punch_attempts(10).await, 4);

        manager.update_nat_profile(birthday_nat_profile()).await;
        assert_eq!(manager.recommended_punch_attempts(10).await, 8);
    }

    #[tokio::test]
    async fn predicted_candidates_have_independent_probe_budget() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        let candidates = vec![
            "203.0.113.10:40007".to_string(),
            "203.0.113.10:40009".to_string(),
            "203.0.113.10:40011".to_string(),
            "203.0.113.10:40013".to_string(),
        ];
        let sources = candidates
            .iter()
            .map(|candidate| (candidate.clone(), "predicted".to_string()))
            .collect::<HashMap<_, _>>();
        manager
            .add_candidates_with_sources("peer1", &candidates, &sources)
            .await;

        let targets = manager.direct_probe_targets_for("peer1").await;
        let predicted_count = targets
            .iter()
            .filter(|endpoint| endpoint.ip().to_string() == "203.0.113.10")
            .count();
        assert_eq!(predicted_count, PREDICTED_PROBE_BUDGET_PER_CYCLE);
    }

    #[test]
    fn birthday_probe_endpoints_cover_layered_port_window() {
        let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
        let endpoints = birthday_probe_endpoints(base);
        let ports = endpoints
            .iter()
            .map(SocketAddr::port)
            .collect::<HashSet<_>>();

        assert_eq!(endpoints.len(), 30);
        for port in [
            39999, 40001, 39996, 40004, 39990, 40010, 39968, 40032, 39936, 40064,
        ] {
            assert!(ports.contains(&port), "missing birthday port {port}");
        }
    }

    #[tokio::test]
    async fn birthday_candidates_use_wider_default_probe_budget() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager.update_nat_profile(birthday_nat_profile()).await;

        let targets = manager.direct_probe_targets_for("peer1").await;
        let birthday_count = targets
            .iter()
            .filter(|target| **target != endpoint && target.ip() == endpoint.ip())
            .count();

        assert!(targets.contains(&endpoint));
        assert_eq!(birthday_count, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);
    }

    #[tokio::test]
    async fn candidate_pair_probe_targets_use_source_success_feedback() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let signaled_endpoint: SocketAddr = "8.8.8.8:51838".parse().unwrap();
        let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51839".parse().unwrap();

        manager
            .add_peer(&test_peer("peer1", signaled_endpoint))
            .await;
        assert!(
            manager
                .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
                .await
        );

        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            let signaled = conn.ensure_candidate_pair_with_source(
                signaled_endpoint,
                0,
                CandidatePairSource::Signaled,
            );
            signaled.success_count = 2;
            signaled.state = CandidatePairState::Waiting;

            let peer_reflexive = conn.ensure_candidate_pair_with_source(
                peer_reflexive_endpoint,
                0,
                CandidatePairSource::PeerReflexive,
            );
            peer_reflexive.failure_count = 2;
            peer_reflexive.state = CandidatePairState::Waiting;
        }

        let targets = manager.direct_probe_targets().await;
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, "peer1");
        assert_eq!(
            targets[0].1,
            vec![signaled_endpoint, peer_reflexive_endpoint]
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
    async fn candidate_pair_probe_targets_promote_authenticated_peer_reflexive() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let signaled_endpoint: SocketAddr = "8.8.8.8:51830".parse().unwrap();
        let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51831".parse().unwrap();

        manager
            .add_peer(&PeerInfo {
                node_id: "peer1".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: signaled_endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;

        assert!(
            manager
                .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
                .await
        );

        let targets = manager.direct_probe_targets().await;
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].1,
            vec![peer_reflexive_endpoint, signaled_endpoint]
        );

        let conn = manager.get_connection("peer1").await.unwrap();
        let peer_reflexive_pair = conn
            .candidate_pairs
            .iter()
            .find(|pair| pair.remote_endpoint == peer_reflexive_endpoint)
            .unwrap();
        assert_eq!(
            peer_reflexive_pair.source,
            CandidatePairSource::PeerReflexive
        );
        assert_eq!(peer_reflexive_pair.probe_count, 2);
        assert!(peer_reflexive_pair.last_probe_at.is_some());

        let diagnostics = manager.diagnostics().await;
        let diagnostic_pair = diagnostics[0]
            .candidate_pairs
            .iter()
            .find(|pair| pair.remote_endpoint == peer_reflexive_endpoint.to_string())
            .unwrap();
        assert_eq!(diagnostic_pair.source, CandidatePairSource::PeerReflexive);
        assert_eq!(diagnostic_pair.probe_count, 2);
        assert!(diagnostic_pair.last_probe_age_ms.is_some());
    }

    #[tokio::test]
    async fn direct_send_prefers_fresh_authenticated_peer_reflexive_endpoint() {
        let manager = PeerManager::new(test_config());
        let signaled_endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();
        let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();
        manager
            .add_peer(&test_peer("peer1", signaled_endpoint))
            .await;

        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                signaled_endpoint,
                Some(Duration::from_millis(1)),
            )
            .await;
        assert!(
            manager
                .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
                .await
        );

        assert_eq!(
            manager.direct_endpoint_for_send("peer1").await,
            Some(peer_reflexive_endpoint)
        );
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
        let provisional = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(provisional.path, Some(NetworkPath::Direct));
        assert!(!provisional.direct_confirmed);
        assert_eq!(
            manager.get_connection("peer1").await.unwrap().active_path(),
            None
        );
        manager.record_direct_success("peer1", Some(endpoint)).await;
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
        manager.record_direct_success("peer1", Some(endpoint)).await;
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
    async fn path_selector_prefers_relay_when_confirmed_direct_quality_is_poor() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51838".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(700)),
            )
            .await;
        manager.record_direct_success("peer1", Some(endpoint)).await;
        manager
            .record_relay_success("peer1", "relay.test:443", false)
            .await;

        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.direct_health.consecutive_failures = 1;
            conn.direct_health.failure_count = 1;
            conn.direct_health.rtt_ewma_ms = Some(650);
            conn.direct_health.jitter_ms = Some(120);
        }

        let selected = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(selected.path, Some(NetworkPath::Relay));
        assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);
        let direct_score = selected.direct_score.as_ref().unwrap().score;
        let relay_score = selected.relay_score.as_ref().unwrap().score;
        assert!(direct_score < DIRECT_CONFIRMED_MIN_SCORE);
        assert!(direct_score < relay_score);
        assert!(direct_score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN >= relay_score);
    }

    #[tokio::test]
    async fn degraded_direct_is_retained_until_relay_peer_path_is_confirmed() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(700)),
            )
            .await;
        manager.record_direct_success("peer1", Some(endpoint)).await;
        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.direct_health.consecutive_failures = 2;
            conn.direct_health.failure_count = 2;
            conn.direct_health.rtt_ewma_ms = Some(650);
            conn.direct_health.jitter_ms = Some(120);
        }

        let selected = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(selected.path, Some(NetworkPath::Direct));
        assert!(selected.direct_confirmed);
        assert!(selected.relay_hedged);
        assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);

        let diagnostics = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));
        assert!(
            diagnostics[0]
                .current_path_selection
                .as_ref()
                .unwrap()
                .relay_hedged
        );
    }

    #[tokio::test]
    async fn path_selector_uses_hedged_trial_direct_when_relay_scores_higher() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51839".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager.set_relay("peer1", "relay.test:443").await;
        manager.record_direct_probe_success("peer1", endpoint).await;
        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.relay_health.rtt_ewma_ms = Some(10);
            conn.relay_health.success_count = 5;
        }

        let selected = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(selected.path, Some(NetworkPath::Direct));
        assert_eq!(selected.reason_code, REASON_PATH_DIRECT_TRIAL);
        assert!(selected.relay_hedged);
        assert!(!selected.direct_confirmed);
        assert!(
            selected.direct_score.as_ref().unwrap().score
                < selected.relay_score.as_ref().unwrap().score
        );
    }

    #[tokio::test]
    async fn path_selection_timeline_records_only_real_changes() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51837".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;

        let first = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(first.path, Some(NetworkPath::Relay));
        let repeated = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(repeated.path, Some(NetworkPath::Relay));

        let diagnostics = manager.diagnostics().await;
        assert_eq!(diagnostics[0].path_events.len(), 1);
        assert_eq!(diagnostics[0].path_events[0].previous_path, None);
        assert_eq!(
            diagnostics[0].path_events[0].selected_path,
            Some(NetworkPath::Relay)
        );
        assert_eq!(
            diagnostics[0].path_events[0].reason_code,
            REASON_PATH_DIRECT_NOT_CONFIRMED
        );

        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(9)),
            )
            .await;
        manager.record_direct_success("peer1", Some(endpoint)).await;
        let direct = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(direct.path, Some(NetworkPath::Direct));

        let diagnostics = manager.diagnostics().await;
        assert_eq!(diagnostics[0].path_events.len(), 2);
        assert_eq!(
            diagnostics[0].path_events[1].previous_path,
            Some(NetworkPath::Relay)
        );
        assert_eq!(
            diagnostics[0].path_events[1].selected_path,
            Some(NetworkPath::Direct)
        );
        assert_eq!(
            diagnostics[0].path_events[1].reason_code,
            REASON_PATH_DIRECT_CONFIRMED
        );

        let json = serde_json::to_value(&diagnostics[0]).unwrap();
        assert_eq!(json["path_events"].as_array().unwrap().len(), 2);
        assert!(json["path_events"][1]["direct_score"]["score"].is_i64());
    }

    #[tokio::test]
    async fn direct_traversal_timeline_records_probe_flow() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "203.0.113.10:60207".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        let candidates = vec![endpoint.to_string()];
        let sources = HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]);
        manager
            .add_candidates_with_sources("peer1", &candidates, &sources)
            .await;

        let targets = manager.direct_probe_targets_for("peer1").await;
        assert_eq!(targets, vec![endpoint]);

        manager
            .record_direct_event(
                "peer1",
                "punch_probes_sent",
                Some(endpoint),
                Some(targets.len()),
                Some(3),
                "sent test probes",
            )
            .await;

        let generation = manager.current_network_generation().await;
        assert!(
            manager
                .record_direct_probe_success_with_latency_for_generation(
                    "peer1",
                    endpoint,
                    Some(Duration::from_millis(42)),
                    generation,
                )
                .await
        );

        let diagnostics = manager.diagnostics().await;
        let stages = diagnostics[0]
            .direct_events
            .iter()
            .map(|event| event.stage.as_str())
            .collect::<Vec<_>>();

        assert!(stages.contains(&"candidates_received"));
        assert!(stages.contains(&"probe_targets_selected"));
        assert!(stages.contains(&"punch_probes_sent"));
        assert!(stages.contains(&"probe_ack_received"));
        assert_eq!(
            diagnostics[0]
                .direct_events
                .iter()
                .find(|event| event.stage == "probe_ack_received")
                .and_then(|event| event.endpoint.as_deref()),
            Some("203.0.113.10:60207")
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
        assert_eq!(diagnostics[0].active_path, None);
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
        assert_eq!(diagnostics[0].active_path, None);
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
    async fn relay_failure_clears_confirmed_active_path() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager.set_relay("peer1", "relay.test:443").await;
        let before = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        assert_eq!(before[0].active_path, Some(NetworkPath::Relay));

        manager
            .record_relay_failure("peer1", "peer_not_found", "peer not found: peer1")
            .await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::FallbackToRelay);
        let after = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        assert_eq!(after[0].active_path, None);
        assert_eq!(
            after[0].relay.last_error_code.as_deref(),
            Some("peer_not_found")
        );
    }

    #[tokio::test]
    async fn stale_relay_confirmation_is_not_reported_active_but_remains_available() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51844".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager.set_relay("peer1", "relay.test:443").await;
        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.relay_health.last_success_at =
                Some(Instant::now() - RELAY_PEER_CONFIRMATION_MAX_AGE - Duration::from_secs(1));
        }

        let diagnostics = manager.diagnostics().await;
        assert_eq!(diagnostics[0].state, ConnectionState::Relay);
        assert_eq!(diagnostics[0].active_path, None);
        assert!(diagnostics[0]
            .relay
            .last_success_age_ms
            .is_some_and(|age| age > duration_millis(RELAY_PEER_CONFIRMATION_MAX_AGE)));

        let selection = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(selection.path, Some(NetworkPath::Relay));

        let diagnostics = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        assert_eq!(diagnostics[0].active_path, None);
        assert_eq!(
            diagnostics[0]
                .current_path_selection
                .as_ref()
                .and_then(|selection| selection.path),
            Some(NetworkPath::Relay)
        );
    }

    #[tokio::test]
    async fn relay_transport_invalidation_clears_all_matching_peer_confirmations() {
        let manager = PeerManager::new(test_config());
        let endpoint: SocketAddr = "127.0.0.1:51843".parse().unwrap();
        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager.set_relay("peer1", "relay-a.test:443").await;

        manager
            .invalidate_relay_transport(
                "relay-a.test:443",
                "relay_transport_closed",
                "relay disconnected",
            )
            .await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.state, ConnectionState::FallbackToRelay);
        assert_eq!(conn.relay_server, None);
        assert!(!conn.relay_health.is_confirmed());
        assert_eq!(
            conn.relay_health.last_error_code.as_deref(),
            Some("relay_transport_closed")
        );
    }

    #[tokio::test]
    async fn peer_manager_stats_can_follow_selected_path_not_stale_state() {
        let config = test_config();
        let manager = PeerManager::new(config);
        let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

        manager.add_peer(&test_peer("peer1", endpoint)).await;
        manager
            .record_direct_probe_success_with_latency(
                "peer1",
                endpoint,
                Some(Duration::from_millis(700)),
            )
            .await;
        manager.record_direct_success("peer1", Some(endpoint)).await;
        manager
            .record_relay_success("peer1", "relay.test:443", false)
            .await;

        {
            let mut conns = manager.connections.write().await;
            let conn = conns.get_mut("peer1").unwrap();
            conn.direct_health.consecutive_failures = 1;
            conn.direct_health.failure_count = 1;
            conn.direct_health.rtt_ewma_ms = Some(650);
            conn.direct_health.jitter_ms = Some(120);
        }

        let stale_stats = manager.stats().await;
        assert_eq!(stale_stats.direct_connections, 1);

        let diagnostics = manager
            .diagnostics_with_path_selection(true, true, Duration::from_secs(5))
            .await;
        assert_eq!(diagnostics[0].state, ConnectionState::Direct);
        assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Relay));

        let selected_stats = PeerManagerStats::from_diagnostics(&diagnostics);
        assert_eq!(selected_stats.direct_connections, 0);
        assert_eq!(selected_stats.relay_connections, 1);
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
        let trial = manager.select_path_for_data("peer1", true, true).await;
        assert_eq!(trial.path, Some(NetworkPath::Direct));
        assert_eq!(trial.reason_code, REASON_PATH_DIRECT_TRIAL);
        assert!(trial.relay_hedged);
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
        manager.record_direct_success("peer1", Some(endpoint)).await;
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
        manager
            .record_direct_success("peer1", Some(old_endpoint))
            .await;
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
        assert_eq!(
            manager.get_connection("peer1").await.unwrap().state,
            ConnectionState::HolePunching
        );
        manager
            .record_direct_success_for_generation("peer1", Some(new_endpoint), generation)
            .await;
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
