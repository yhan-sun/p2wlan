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
const RECENT_DIRECT_TRIAL_FAILURE_TOLERANCE: u32 = 1;
/// Aggressive Direct reclaim window after the local network generation changes.
///
/// A peer that has previously confirmed Direct is likely to recover after a
/// mobile hotspot/base-station handover once fresh NAT mappings are visible.
/// During this short window we bypass ordinary background backoff while Relay
/// keeps the data plane usable.
pub const DIRECT_RECLAIM_WINDOW: Duration = Duration::from_secs(10);
/// Base cadence for relay-backed Direct reconnection.
///
/// Relay already provides the data-plane safety net, so peers with a plausible
/// punch window should retry quickly after a Direct path falls apart.  The
/// peer-level backoff below yields 1s, 2s, 4s, then 8s retries.
pub const DIRECT_RETRY_BASE_INTERVAL: Duration = Duration::from_secs(1);
const DIRECT_RETRY_BACKOFF_MAX_EXPONENT: u32 = 3;
const DIRECT_TO_RELAY_HYSTERESIS_MARGIN: i32 = 15;
const DIRECT_CONFIRMED_MIN_SCORE: i32 = 60;
const PRIVATE_DIRECT_RETAIN_MAX_RTT_MS: u64 = 250;
const DIRECT_KEEPALIVE_FAILURE_THRESHOLD: u32 = 3;
const PEER_REFLEXIVE_SAME_IP_RETAINED_PORTS: usize = 3;
const PREDICTED_PROBE_BUDGET_PER_CYCLE: usize = 24;
const PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 24;
const PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE: usize = 24;
const PREDICTED_PROBE_FAILURE_BUDGET_PER_CYCLE: usize = 8;
const BIRTHDAY_PROBE_BUDGET_PER_CYCLE: usize = 96;
const BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 128;
const BIRTHDAY_PROBE_COOLDOWN_BUDGET_PER_CYCLE: usize = 32;
const BIRTHDAY_PROBE_FAILURE_BUDGET_PER_CYCLE: usize = 32;
const BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE: usize = 4;
const BIRTHDAY_PROBE_NEAR_MAX_DELTA: i32 = 96;
const BIRTHDAY_PROBE_WIDE_MAX_DELTA: i32 = 32_768;
const BIRTHDAY_PROBE_WIDE_STRIDE: i32 = 251;
const CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE: Duration = Duration::from_secs(1);
const CANDIDATE_PAIR_FAILURE_COOLDOWN_MAX_EXPONENT: u32 = 3;
const PRIORITY_OUTBOUND_PROBE_FAILURE_COOLDOWN: Duration = Duration::from_secs(1);
const DIRECT_TRIAL_MIN_SCORE: i32 = 40;
const SLOW_DIRECT_RELAY_VALIDATION_RTT_MS: u64 = 300;
const PATH_SELECTION_EVENT_LIMIT: usize = 16;
const DIRECT_TRAVERSAL_EVENT_LIMIT: usize = 32;
const RELAY_PEER_CONFIRMATION_MAX_AGE: Duration = Duration::from_secs(30);
const PROBE_MAC_KEY_DOMAIN: &[u8] = b"p2wlan udp probe v2 mac key";
const PROBE_MAC_SESSION_KEY_DOMAIN: &[u8] = b"p2wlan udp probe v2 session key";
const PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN: &[u8] = b"p2wlan udp probe v2 ephemeral session key";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeTargetMode {
    /// The synchronized offer/answer punch window. Keep this compact so
    /// address/port-dependent NATs are not forced to create many competing
    /// mappings before the peer can answer.
    Synchronized,
    /// Background retries after relay is already available. These may spend a
    /// wider budget on birthday probes without delaying initial connectivity.
    Background,
    /// Short relay-backed recovery window after a generation change. This
    /// keeps birthday-style coverage but bypasses pair cooldowns like a
    /// synchronized punch so a previously working Direct path can be reclaimed.
    Reclaim,
}

impl ProbeTargetMode {
    fn bypasses_pair_cooldown(self) -> bool {
        matches!(self, Self::Synchronized | Self::Reclaim)
    }

    fn refreshes_speculative_budget(self) -> bool {
        matches!(self, Self::Synchronized | Self::Reclaim)
    }

    fn prioritizes_predicted(self) -> bool {
        matches!(self, Self::Synchronized | Self::Reclaim)
    }

    fn allows_local_nat_birthday(self) -> bool {
        matches!(self, Self::Synchronized | Self::Background | Self::Reclaim)
    }
}

/// Stable reason code emitted when a local network generation changes.
pub const REASON_NETWORK_GENERATION_CHANGED: &str = "network_generation_changed";
/// Stable reason code for direct path probe timeout/failure.
pub const REASON_DIRECT_PROBE_FAILED: &str = "direct_probe_failed";
/// Stable reason code for direct path send failure.
pub const REASON_DIRECT_SEND_FAILED: &str = "direct_send_failed";
/// Direct UDP keepalive did not receive a matching authenticated ACK.
pub const REASON_DIRECT_KEEPALIVE_TIMEOUT: &str = "direct_keepalive_timeout";
/// A nominated Direct trial did not receive encrypted data confirmation in time.
pub const REASON_DIRECT_TRIAL_EXPIRED: &str = "direct_trial_expired";
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

mod birthday;
mod candidate_ranking;
mod diagnostics;
mod endpoint;
mod probe_budget;
mod types;
#[cfg(test)]
use birthday::{
    birthday_probe_endpoints, birthday_probe_endpoints_for_bases, birthday_probe_near_rank_count,
};
use birthday::{
    birthday_probe_endpoints_for_bases_from_rank, birthday_probe_wide_rank_count,
    peer_candidates_need_port_scatter,
};
use candidate_ranking::{
    birthday_base_rank, candidate_pair_dynamic_probe_rank, candidate_pair_source_observed_age_ms,
    candidate_pair_source_quality_rank, candidate_pair_source_rank, discovered_endpoint_probe_rank,
    is_hard_nat_profile, peer_reflexive_retention_rank, should_retain_peer_reflexive_pair,
    speculative_probe_rotation_rank, speculative_probe_source_rank_for_mode,
};
use diagnostics::candidate_pair_source_stats;
pub use diagnostics::{
    CandidatePairDiagnostics, CandidatePairSourceStats, DirectTraversalEventDiagnostics,
    PathHealthDiagnostics, PathSelectionEventDiagnostics, PeerDiagnostics, PeerManagerStats,
};
use endpoint::{
    candidate_pair_failure_cooldown, candidate_pair_probe_due, candidate_pair_probe_rank_for_mode,
    classify_candidate_pair_path, classify_confirmed_direct_endpoint, endpoint_probe_rank,
    is_low_latency_direct_endpoint, is_overlay_endpoint, is_public_probe_endpoint,
    should_retain_private_direct_pair,
};
#[cfg(test)]
use probe_budget::birthday_probe_budget_for_base_count;
use probe_budget::{
    apply_adaptive_probe_budgets, birthday_probe_budget, candidate_pair_source_probe_budget,
    is_priority_outbound_probe_pair, is_speculative_probe_source, outbound_probe_priority_rank,
};
pub use types::{
    CandidatePair, CandidatePairSource, CandidatePairState, ConnectionState, DirectPathType,
    DirectTraversalEvent, NetworkPath, PathHealth, PathScore, PathScoreDiagnostics, PathSelection,
    PathSelectionDiagnostics, PathSelectionEvent,
};

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
    /// Peer application/daemon version reported by the control plane.
    pub app_version: String,
    /// Peer's static WireGuard/X25519 public key as hex.
    pub public_key: String,
    /// Symmetric MAC key for authenticated UDP Probe v2.
    pub probe_mac_key: Option<ProbeMacKey>,
    /// Current control-plane session ID used to bind Probe v2 MAC keys.
    pub probe_session_id: Option<String>,
    /// Session-local X25519 shared secret used to rotate Probe v2 MAC keys.
    pub probe_ephemeral_shared: Option<[u8; 32]>,
    /// Peer's virtual IP.
    pub virtual_ip: String,
    /// Peer's public endpoint (ip:port) if known.
    pub endpoint: Option<SocketAddr>,
    /// Endpoint currently advertised by peer metadata. This is kept separate
    /// from an authenticated peer-reflexive endpoint learned on the wire.
    pub signaled_endpoint: Option<SocketAddr>,
    /// Peer's NAT type.
    pub nat_type: String,
    /// Whether the control plane currently reports this peer online.
    pub online: bool,
    /// Last seen timestamp reported by the control plane.
    pub last_seen: u64,
    /// Peer-reported RTT to its selected relay server, in milliseconds.
    pub remote_relay_rtt_ms: Option<u64>,
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
    /// Short window after a local generation change where previous Direct peers
    /// are reprobed aggressively before returning to normal retry backoff.
    direct_reclaim_until: Option<Instant>,
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
            app_version: String::new(),
            public_key: String::new(),
            probe_mac_key: None,
            probe_session_id: None,
            probe_ephemeral_shared: None,
            virtual_ip: virtual_ip.to_string(),
            endpoint: None,
            signaled_endpoint: None,
            nat_type: String::new(),
            online: true,
            last_seen: 0,
            remote_relay_rtt_ms: None,
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
            direct_reclaim_until: None,
            candidate_pairs: Vec::new(),
            last_path_selection: None,
            path_events: Vec::new(),
            direct_events: Vec::new(),
        }
    }

    fn reset_for_identity_change(&mut self) {
        self.endpoint = self.signaled_endpoint;
        self.probe_session_id = None;
        self.probe_ephemeral_shared = None;
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
        self.direct_reclaim_until = None;
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

    fn ensure_candidate_pair_with_observed_source(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) -> &mut CandidatePair {
        if let Some(index) = self.candidate_pairs.iter().position(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
        }) {
            self.candidate_pairs[index].observe_source(source);
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

    fn prune_candidate_pairs_outside_targets(
        &mut self,
        local_generation: u64,
        endpoints: &[SocketAddr],
    ) -> usize {
        let target_endpoints = endpoints.iter().copied().collect::<HashSet<_>>();
        let before = self.candidate_pairs.len();
        self.candidate_pairs.retain(|pair| {
            if pair.local_generation != local_generation {
                return true;
            }
            if target_endpoints.contains(&pair.remote_endpoint) {
                return true;
            }
            matches!(
                pair.state,
                CandidatePairState::Selected | CandidatePairState::Succeeded
            ) && pair
                .last_success_at
                .is_some_and(|at| at.elapsed() < DIRECT_TRIAL_WINDOW)
        });
        before.saturating_sub(self.candidate_pairs.len())
    }

    fn candidate_probe_endpoints(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
        mode: ProbeTargetMode,
    ) -> Vec<SocketAddr> {
        self.ensure_current_candidate_pairs(local_generation);
        let mut endpoints = self.candidate_endpoints();
        self.ensure_birthday_candidate_pairs(
            local_generation,
            history,
            local_nat_profile,
            mode.allows_local_nat_birthday(),
            &mut endpoints,
        );
        self.prune_candidate_pairs_outside_targets(local_generation, &endpoints);
        let source_stats =
            candidate_pair_source_stats(&self.candidate_pairs, local_generation, None);
        let active_endpoint = self.endpoint;
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && endpoints.contains(&pair.remote_endpoint)
                    && (mode.bypasses_pair_cooldown() || candidate_pair_probe_due(pair))
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| {
            outbound_probe_priority_rank(a)
                .cmp(&outbound_probe_priority_rank(b))
                .then_with(|| {
                    speculative_probe_source_rank_for_mode(a.source, mode)
                        .cmp(&speculative_probe_source_rank_for_mode(b.source, mode))
                })
                .then_with(|| {
                    candidate_pair_probe_rank_for_mode(a.state, a.source, mode)
                        .cmp(&candidate_pair_probe_rank_for_mode(b.state, b.source, mode))
                })
                .then_with(|| {
                    candidate_pair_source_quality_rank(&source_stats, history, a.source).cmp(
                        &candidate_pair_source_quality_rank(&source_stats, history, b.source),
                    )
                })
                .then_with(|| {
                    candidate_pair_dynamic_probe_rank(a, active_endpoint)
                        .cmp(&candidate_pair_dynamic_probe_rank(b, active_endpoint))
                })
                .then_with(|| {
                    discovered_endpoint_probe_rank(a.source)
                        .cmp(&discovered_endpoint_probe_rank(b.source))
                })
                .then_with(|| {
                    speculative_probe_rotation_rank(a).cmp(&speculative_probe_rotation_rank(b))
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
        apply_adaptive_probe_budgets(pairs, &source_stats, history, mode)
            .into_iter()
            .map(|pair| pair.remote_endpoint)
            .collect()
    }

    fn ensure_birthday_candidate_pairs(
        &mut self,
        local_generation: u64,
        history: &TraversalHistory,
        local_nat_profile: Option<&NatProfile>,
        allow_local_nat_trigger: bool,
        endpoints: &mut Vec<SocketAddr>,
    ) {
        let bases = self.birthday_probe_bases(endpoints, local_generation);

        let local_needs_birthday = allow_local_nat_trigger
            && local_nat_profile.is_some_and(|profile| profile.birthday_candidate);
        let peer_looks_port_dependent = peer_candidates_need_port_scatter(&bases);
        if !local_needs_birthday && !peer_looks_port_dependent {
            return;
        }

        let per_base_budget = birthday_probe_budget(history);
        let budget =
            per_base_budget.saturating_mul(bases.len().min(BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE));
        if budget == 0 {
            return;
        }

        let mut generated = 0usize;
        let rotation_start_rank = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && pair.source == CandidatePairSource::Birthday
            })
            .map(|pair| pair.probe_count as usize)
            .min()
            .unwrap_or(0)
            .saturating_mul(per_base_budget)
            % birthday_probe_wide_rank_count();
        for endpoint in
            birthday_probe_endpoints_for_bases_from_rank(&bases, budget, rotation_start_rank)
        {
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
            if generated >= budget {
                return;
            }
        }
    }

    fn birthday_probe_bases(
        &self,
        endpoints: &[SocketAddr],
        local_generation: u64,
    ) -> Vec<SocketAddr> {
        let mut bases = endpoints
            .iter()
            .copied()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .filter(|endpoint| {
                !matches!(
                    self.candidate_source_for_endpoint(*endpoint),
                    CandidatePairSource::Host
                        | CandidatePairSource::Predicted
                        | CandidatePairSource::Birthday
                        | CandidatePairSource::Upnp
                        | CandidatePairSource::Pcp
                        | CandidatePairSource::NatPmp
                )
            })
            .collect::<Vec<_>>();

        bases.sort_by(|a, b| {
            birthday_base_rank(self, *a, local_generation)
                .cmp(&birthday_base_rank(self, *b, local_generation))
                .then_with(|| a.cmp(b))
        });
        bases.dedup();
        bases.truncate(BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE);
        bases
    }

    fn prune_stale_peer_reflexive_candidates_for_ip(
        &mut self,
        fresh_endpoint: SocketAddr,
        local_generation: u64,
    ) -> usize {
        if !is_public_probe_endpoint(fresh_endpoint) {
            return 0;
        }

        let mut peer_reflexive = self
            .candidate_sources
            .iter()
            .filter_map(|(candidate, source)| {
                (*source == CandidatePairSource::PeerReflexive)
                    .then(|| candidate.parse::<SocketAddr>().ok())
                    .flatten()
            })
            .filter(|endpoint| {
                endpoint.ip() == fresh_endpoint.ip() && is_public_probe_endpoint(*endpoint)
            })
            .collect::<Vec<_>>();

        if peer_reflexive.len() <= PEER_REFLEXIVE_SAME_IP_RETAINED_PORTS {
            return 0;
        }

        peer_reflexive.sort_by(|a, b| {
            peer_reflexive_retention_rank(self, *a, fresh_endpoint, local_generation)
                .cmp(&peer_reflexive_retention_rank(
                    self,
                    *b,
                    fresh_endpoint,
                    local_generation,
                ))
                .then_with(|| a.cmp(b))
        });

        let mut retained = peer_reflexive
            .iter()
            .take(PEER_REFLEXIVE_SAME_IP_RETAINED_PORTS)
            .copied()
            .collect::<HashSet<_>>();

        for pair in &self.candidate_pairs {
            if pair.local_generation == local_generation
                && pair.source == CandidatePairSource::PeerReflexive
                && pair.remote_endpoint.ip() == fresh_endpoint.ip()
                && should_retain_peer_reflexive_pair(pair)
            {
                retained.insert(pair.remote_endpoint);
            }
        }

        let removed = peer_reflexive
            .into_iter()
            .filter(|endpoint| !retained.contains(endpoint))
            .collect::<HashSet<_>>();
        if removed.is_empty() {
            return 0;
        }

        self.candidates.retain(|candidate| {
            candidate
                .parse::<SocketAddr>()
                .map_or(true, |endpoint| !removed.contains(&endpoint))
        });
        for endpoint in &removed {
            self.candidate_sources.remove(&endpoint.to_string());
        }
        self.candidate_pairs.retain(|pair| {
            !(pair.local_generation == local_generation
                && pair.source == CandidatePairSource::PeerReflexive
                && removed.contains(&pair.remote_endpoint)
                && !should_retain_peer_reflexive_pair(pair))
        });

        removed.len()
    }

    fn candidate_pairs_for_send(&self, local_generation: u64) -> Vec<&CandidatePair> {
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && !is_overlay_endpoint(pair.remote_endpoint)
                    && (matches!(
                        pair.state,
                        CandidatePairState::Selected
                            | CandidatePairState::Succeeded
                            | CandidatePairState::Probing
                            | CandidatePairState::Waiting
                    ) || is_recent_successful_direct_trial_pair(pair))
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
    }

    fn best_candidate_pair_for_send(&self, local_generation: u64) -> Option<&CandidatePair> {
        self.candidate_pairs_for_send(local_generation)
            .into_iter()
            .next()
    }

    fn should_probe_private_alternates_while_direct(&self, local_generation: u64) -> bool {
        if self.state != ConnectionState::Direct {
            return true;
        }

        let selected_pair = self.selected_candidate_pair_for_diagnostics(local_generation);
        if selected_pair.is_some_and(|pair| is_low_latency_direct_endpoint(pair.remote_endpoint)) {
            return false;
        }

        self.candidate_pairs.iter().any(|pair| {
            pair.local_generation == local_generation
                && (is_low_latency_direct_endpoint(pair.remote_endpoint)
                    || is_public_probe_endpoint(pair.remote_endpoint))
                && !matches!(
                    pair.state,
                    CandidatePairState::Selected | CandidatePairState::Succeeded
                )
                && candidate_pair_probe_due(pair)
        })
    }

    fn direct_endpoint_for_send(&self, local_generation: u64) -> Option<SocketAddr> {
        self.best_candidate_pair_for_send(local_generation)
            .map(|pair| pair.remote_endpoint)
            .or_else(|| {
                self.endpoint
                    .filter(|endpoint| !is_overlay_endpoint(*endpoint))
            })
    }

    fn selected_direct_endpoint_for_consent(&self, local_generation: u64) -> Option<SocketAddr> {
        self.candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && !is_overlay_endpoint(pair.remote_endpoint)
                    && pair.selected_at.is_some()
                    && pair.state != CandidatePairState::Frozen
            })
            .min_by(|a, b| {
                a.selected_at
                    .unwrap_or_else(Instant::now)
                    .cmp(&b.selected_at.unwrap_or_else(Instant::now))
                    .then_with(|| {
                        a.rtt_ewma_ms
                            .or(a.rtt_ms)
                            .unwrap_or(u64::MAX)
                            .cmp(&b.rtt_ewma_ms.or(b.rtt_ms).unwrap_or(u64::MAX))
                    })
                    .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
            })
            .map(|pair| pair.remote_endpoint)
    }

    fn selected_candidate_pair_for_diagnostics(
        &self,
        local_generation: u64,
    ) -> Option<&CandidatePair> {
        let mut pairs = self
            .candidate_pairs
            .iter()
            .filter(|pair| {
                pair.local_generation == local_generation
                    && pair.state == CandidatePairState::Selected
            })
            .collect::<Vec<_>>();
        pairs.sort_by(|a, b| {
            candidate_pair_send_rank(a)
                .cmp(&candidate_pair_send_rank(b))
                .then_with(|| {
                    candidate_pair_source_rank(a.source).cmp(&candidate_pair_source_rank(b.source))
                })
                .then_with(|| {
                    a.rtt_ewma_ms
                        .or(a.rtt_ms)
                        .unwrap_or(u64::MAX)
                        .cmp(&b.rtt_ewma_ms.or(b.rtt_ms).unwrap_or(u64::MAX))
                })
                .then_with(|| a.remote_endpoint.cmp(&b.remote_endpoint))
        });
        pairs.into_iter().next()
    }

    fn current_direct_pair_for_diagnostics(
        &self,
        local_generation: u64,
        current_selection: Option<&PathSelection>,
    ) -> Option<&CandidatePair> {
        if let Some(endpoint) = current_selection.and_then(|selection| selection.direct_endpoint) {
            if let Some(pair) = self.candidate_pairs.iter().find(|pair| {
                pair.local_generation == local_generation && pair.remote_endpoint == endpoint
            }) {
                return Some(pair);
            }
        }

        self.selected_candidate_pair_for_diagnostics(local_generation)
            .or_else(|| self.best_candidate_pair_for_send(local_generation))
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

        let selected_pair = self.candidate_pairs.iter().find(|pair| {
            pair.local_generation == local_generation && pair.remote_endpoint == endpoint
        });
        let selected_pair_state = selected_pair.map(|pair| pair.state);
        let confirmed_direct = self.state == ConnectionState::Direct
            && selected_pair_state == Some(CandidatePairState::Selected);
        let recent_success_trial =
            selected_pair.is_some_and(is_recent_successful_direct_trial_pair);
        let trial_direct = selected_pair.is_some_and(|pair| {
            pair.state == CandidatePairState::Succeeded
                || (pair.state == CandidatePairState::Probing && pair.nominated)
        }) && self.direct_health.consecutive_failures == 0
            && self
                .direct_health
                .success_age()
                .map(|age| age <= DIRECT_TRIAL_WINDOW)
                .unwrap_or(false)
            || recent_success_trial;
        let direct_score = self.direct_path_score(
            local_generation,
            Some(endpoint),
            confirmed_direct,
            trial_direct,
        );
        let retain_private_direct = selected_pair.is_some_and(should_retain_private_direct_pair);

        if confirmed_direct {
            if let (Some(direct_score), Some(relay_score)) = (&direct_score, &relay_score) {
                if !retain_private_direct
                    && direct_score.score < DIRECT_CONFIRMED_MIN_SCORE
                    && direct_score.score <= relay_score.score
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
                if !retain_private_direct
                    && direct_score.score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN < relay_score.score
                {
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
            let trial_is_viable = if recent_success_trial {
                true
            } else {
                match (&direct_score, &relay_score) {
                    (Some(direct_score), Some(_)) => direct_score.score >= DIRECT_TRIAL_MIN_SCORE,
                    (Some(direct_score), None) => direct_score.score >= DIRECT_TRIAL_MIN_SCORE,
                    (None, _) => true,
                }
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
        let peer_id = self.node_id.clone();
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        pair.record_probing(None);
        log_candidate_pair_state_changed(&peer_id, pair, old_state, "probe scheduled");
    }

    fn mark_candidate_pair_probing_with_source(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        source: CandidatePairSource,
    ) {
        let peer_id = self.node_id.clone();
        let pair =
            self.ensure_candidate_pair_with_observed_source(endpoint, local_generation, source);
        let old_state = pair.state;
        pair.record_probing(None);
        log_candidate_pair_state_changed(&peer_id, pair, old_state, "probe scheduled");
    }

    fn mark_candidate_pair_probing_with_local_endpoint(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) {
        let peer_id = self.node_id.clone();
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        pair.record_probing(local_endpoint);
        log_candidate_pair_state_changed(&peer_id, pair, old_state, "inbound probe observed");
    }

    fn mark_candidate_pair_success(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        latency: Option<Duration>,
        selected: bool,
        local_endpoint: Option<SocketAddr>,
    ) -> CandidatePairSource {
        let peer_id = self.node_id.clone();
        let pair = self.ensure_candidate_pair(endpoint, local_generation);
        let old_state = pair.state;
        pair.record_success(latency, selected, local_endpoint);
        log_candidate_pair_state_changed(
            &peer_id,
            pair,
            old_state,
            if selected {
                "encrypted data path confirmed Direct UDP"
            } else {
                "received UDP punch ACK"
            },
        );
        pair.source
    }

    fn mark_candidate_pair_nominated(
        &mut self,
        endpoint: SocketAddr,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
        reason: &str,
    ) -> Option<CandidatePairSource> {
        let peer_id = self.node_id.clone();
        let pair = self.candidate_pairs.iter_mut().find(|pair| {
            pair.remote_endpoint == endpoint && pair.local_generation == local_generation
        })?;
        let nominated = pair.nominate(local_endpoint);
        if nominated {
            log_candidate_pair_nominated(&peer_id, pair, reason);
        }
        Some(pair.source)
    }

    fn expire_stale_trial_nominations(
        &mut self,
        local_generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> usize {
        let peer_id = self.node_id.clone();
        let reason = format!(
            "direct trial was not encrypted-confirmed within {}ms",
            duration_millis(DIRECT_TRIAL_WINDOW)
        );
        let mut expired = 0usize;
        for pair in self
            .candidate_pairs
            .iter_mut()
            .filter(|pair| pair.local_generation == local_generation)
        {
            let old_state = pair.state;
            if pair.expire_stale_nomination(DIRECT_TRIAL_WINDOW, reason.clone(), local_endpoint) {
                expired += 1;
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
                info!(
                    event = "candidate_pair_nomination_expired",
                    peer_id = %peer_id,
                    local_endpoint = %format_log_endpoint(pair.local_endpoint),
                    remote_endpoint = %pair.remote_endpoint,
                    candidate_source = ?pair.source,
                    rtt_ms = ?pair.rtt_ewma_ms.or(pair.rtt_ms),
                    reason = %reason,
                    "candidate_pair_nomination_expired peer_id={} remote_endpoint={} reason={}",
                    peer_id,
                    pair.remote_endpoint,
                    reason
                );
            }
        }
        expired
    }

    fn mark_current_candidate_pairs_failed(
        &mut self,
        local_generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) -> Vec<CandidatePairSource> {
        let code = code.into();
        let reason = reason.into();
        let local_endpoint_text = format_log_endpoint(local_endpoint);
        let peer_id = self.node_id.clone();
        let mut probed_sources = Vec::new();
        let current_endpoints = self.candidate_endpoints();
        let has_probed_pair = current_endpoints.iter().copied().any(|endpoint| {
            let pair = self.ensure_candidate_pair(endpoint, local_generation);
            pair.last_probe_at.is_some()
        });
        for endpoint in current_endpoints {
            let pair = self.ensure_candidate_pair(endpoint, local_generation);
            if has_probed_pair && pair.last_probe_at.is_none() {
                continue;
            }
            if pair.last_probe_at.is_some() && !probed_sources.contains(&pair.source) {
                probed_sources.push(pair.source);
            }
            let candidate_source = pair.source;
            let rtt_ms = pair.rtt_ewma_ms.or(pair.rtt_ms);
            let old_state = pair.state;
            pair.record_failure(code.clone(), reason.clone(), local_endpoint);
            log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            info!(
                event = "candidate_pair_probe_failed",
                peer_id = %peer_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %endpoint,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %reason,
                "candidate_pair_probe_failed peer_id={} remote_endpoint={} reason={}",
                peer_id,
                endpoint,
                reason
            );
        }
        probed_sources
    }

    fn mark_network_generation_changed(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) {
        let reason = reason.into();
        let peer_id = self.node_id.clone();
        self.candidate_pairs
            .retain(|pair| pair.local_generation.saturating_add(1) >= local_generation);
        for pair in &mut self.candidate_pairs {
            if pair.local_generation < local_generation {
                let old_state = pair.state;
                pair.record_generation_change(reason.clone());
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            }
        }
        self.ensure_current_candidate_pairs(local_generation);
    }

    fn mark_candidate_refresh_generation_changed(
        &mut self,
        local_generation: u64,
        reason: impl Into<String>,
    ) -> bool {
        let reason = reason.into();
        let retained_private_direct = (self.state == ConnectionState::Direct)
            .then(|| {
                self.candidate_pairs
                    .iter()
                    .find(|pair| should_retain_private_direct_pair(pair))
                    .map(|pair| pair.retained_for_generation(local_generation))
            })
            .flatten();
        let retained_endpoint = retained_private_direct
            .as_ref()
            .map(|pair| pair.remote_endpoint);

        let peer_id = self.node_id.clone();
        self.candidate_pairs
            .retain(|pair| pair.local_generation.saturating_add(1) >= local_generation);
        for pair in &mut self.candidate_pairs {
            if pair.local_generation < local_generation {
                let old_state = pair.state;
                pair.record_generation_change(reason.clone());
                log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);
            }
        }
        self.ensure_current_candidate_pairs(local_generation);

        if let Some(retained) = retained_private_direct {
            if let Some(index) = self.candidate_pairs.iter().position(|pair| {
                pair.local_generation == local_generation
                    && pair.remote_endpoint == retained.remote_endpoint
            }) {
                self.candidate_pairs[index] = retained;
            } else {
                self.candidate_pairs.push(retained);
            }
            if let Some(endpoint) = retained_endpoint {
                self.endpoint = Some(endpoint);
                self.direct_generation = local_generation;
            }
            true
        } else {
            false
        }
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

    fn direct_reclaim_active(&self) -> bool {
        self.direct_reclaim_until
            .is_some_and(|until| Instant::now() < until)
    }

    fn start_direct_reclaim_window(&mut self, local_generation: u64, reason: &str) -> bool {
        if !self.has_direct_success_history() || self.candidate_endpoints().is_empty() {
            return false;
        }

        self.direct_reclaim_until = Some(Instant::now() + DIRECT_RECLAIM_WINDOW);
        let candidate_count = self.candidate_endpoints().len();
        self.record_direct_event(
            local_generation,
            "direct_reclaim_window_started",
            self.endpoint,
            Some(candidate_count),
            None,
            format!(
                "network changed after previous Direct success; aggressively reprobing for {}ms: {reason}",
                duration_millis(DIRECT_RECLAIM_WINDOW)
            ),
        );
        true
    }

    fn clear_direct_reclaim_window(&mut self) {
        self.direct_reclaim_until = None;
    }

    fn has_direct_success_history(&self) -> bool {
        self.direct_health.success_count > 0
            || self
                .candidate_pairs
                .iter()
                .any(|pair| pair.success_count > 0 || pair.selected_at.is_some())
    }

    fn has_private_direct_candidate(&self) -> bool {
        self.candidate_endpoints()
            .into_iter()
            .any(is_low_latency_direct_endpoint)
    }

    fn has_mapping_assisted_candidate(&self) -> bool {
        self.candidate_endpoints().into_iter().any(|endpoint| {
            matches!(
                self.candidate_source_for_endpoint(endpoint),
                CandidatePairSource::Upnp
                    | CandidatePairSource::Pcp
                    | CandidatePairSource::NatPmp
                    | CandidatePairSource::Predicted
            )
        })
    }

    fn peer_public_candidates_need_scatter(&self) -> bool {
        let bases = self
            .candidate_endpoints()
            .into_iter()
            .filter(|endpoint| is_public_probe_endpoint(*endpoint))
            .collect::<Vec<_>>();
        peer_candidates_need_port_scatter(&bases)
    }

    fn has_direct_retry_opportunity(&self, local_nat_profile: Option<&NatProfile>) -> bool {
        let endpoints = self.candidate_endpoints();
        if endpoints.is_empty() {
            return false;
        }

        // A path that has worked before is exactly the kind of transient NAT
        // window we want to recover quickly after sleep, network refresh, or
        // daemon socket rebinding.
        if self.has_direct_success_history()
            || self.has_private_direct_candidate()
            || self.has_mapping_assisted_candidate()
        {
            return true;
        }

        if local_nat_profile.is_some_and(|profile| profile.udp_blocked) {
            return false;
        }

        let local_is_hard = local_nat_profile.is_some_and(is_hard_nat_profile);
        let peer_looks_hard = self.peer_public_candidates_need_scatter();
        !(local_is_hard && peer_looks_hard)
    }

    fn record_path_selection_event(
        &mut self,
        local_generation: u64,
        selection: &PathSelection,
        local_endpoint: Option<SocketAddr>,
    ) {
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

        let previous_path = previous.and_then(|selection| selection.path);
        let pair = selection.direct_endpoint.and_then(|endpoint| {
            self.candidate_pairs.iter().find(|pair| {
                pair.local_generation == local_generation && pair.remote_endpoint == endpoint
            })
        });
        let remote_endpoint = selection.direct_endpoint;
        let remote_endpoint_text = match selection.path {
            Some(NetworkPath::Relay) => self
                .relay_server
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            _ => remote_endpoint
                .map(|endpoint| endpoint.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        };
        let local_endpoint_text = format_log_endpoint(
            local_endpoint.or_else(|| pair.and_then(|pair| pair.local_endpoint)),
        );
        let candidate_source = pair.map(|pair| pair.source);
        let rtt_ms = pair.and_then(|pair| pair.rtt_ewma_ms.or(pair.rtt_ms));
        let direct_type =
            classify_candidate_pair_path(selection.path, pair, selection.direct_confirmed);

        if selection.path == Some(NetworkPath::Direct) && selection.direct_confirmed {
            info!(
                event = "candidate_pair_selected",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "candidate_pair_selected peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
            match direct_type {
                DirectPathType::PublicUdp => info!(
                    event = "public_udp_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "public_udp_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::Overlay => info!(
                    event = "overlay_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "overlay_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                DirectPathType::Lan => info!(
                    event = "lan_direct_selected",
                    peer_id = %self.node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %remote_endpoint_text,
                    candidate_source = ?candidate_source,
                    rtt_ms = ?rtt_ms,
                    reason = %selection.reason,
                    "lan_direct_selected peer_id={} remote_endpoint={:?} reason={}",
                    self.node_id,
                    remote_endpoint,
                    selection.reason
                ),
                _ => {}
            }
        }

        if selection.path == Some(NetworkPath::Direct) && previous_path != Some(NetworkPath::Direct)
        {
            info!(
                event = "direct_path_promoted",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "direct_path_promoted peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
        }

        if selection.reason_code == REASON_PATH_DIRECT_DEGRADED {
            info!(
                event = "direct_path_degraded",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "direct_path_degraded peer_id={} remote_endpoint={:?} reason={}",
                self.node_id,
                remote_endpoint,
                selection.reason
            );
        }

        if selection.path == Some(NetworkPath::Relay) {
            info!(
                event = "relay_fallback_selected",
                peer_id = %self.node_id,
                local_endpoint = %local_endpoint_text,
                remote_endpoint = %remote_endpoint_text,
                relay_server = ?self.relay_server,
                candidate_source = ?candidate_source,
                rtt_ms = ?rtt_ms,
                reason = %selection.reason,
                "relay_fallback_selected peer_id={} reason={}",
                self.node_id,
                selection.reason
            );
        }

        self.path_events.push(PathSelectionEvent {
            selected_at: Instant::now(),
            network_generation: local_generation,
            previous_path,
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

fn derive_session_probe_mac_key(base_key: &ProbeMacKey, session_id: &str) -> ProbeMacKey {
    let mut input = Vec::with_capacity(PROBE_MAC_SESSION_KEY_DOMAIN.len() + session_id.len());
    input.extend_from_slice(PROBE_MAC_SESSION_KEY_DOMAIN);
    input.extend_from_slice(session_id.as_bytes());
    hmac(base_key, &input)
}

fn derive_ephemeral_session_probe_mac_key(
    base_key: &ProbeMacKey,
    session_id: &str,
    ephemeral_shared: &[u8; 32],
) -> ProbeMacKey {
    let mut input = Vec::with_capacity(
        PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN.len() + session_id.len() + ephemeral_shared.len(),
    );
    input.extend_from_slice(PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN);
    input.extend_from_slice(session_id.as_bytes());
    input.extend_from_slice(ephemeral_shared);
    hmac(base_key, &input)
}

fn effective_probe_mac_key(conn: &PeerConnection) -> Option<ProbeMacKey> {
    let base_key = conn.probe_mac_key?;
    Some(match conn.probe_session_id.as_deref() {
        Some(session_id) if !session_id.is_empty() => match conn.probe_ephemeral_shared.as_ref() {
            Some(shared) => derive_ephemeral_session_probe_mac_key(&base_key, session_id, shared),
            None => derive_session_probe_mac_key(&base_key, session_id),
        },
        _ => base_key,
    })
}

fn probe_key_type(conn: &PeerConnection) -> &'static str {
    if conn.probe_mac_key.is_none() {
        "none"
    } else if conn.probe_session_id.is_none() {
        "static"
    } else if conn.probe_ephemeral_shared.is_some() {
        "ephemeral_session"
    } else {
        "session"
    }
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

        let mut direct_reclaim_count = 0usize;
        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            conn.direct_health.record_generation_change(reason.clone());
            conn.mark_network_generation_changed(generation, reason.clone());
            if conn.state == ConnectionState::Direct {
                conn.transition(ConnectionState::FallbackToRelay);
            }
            if conn.start_direct_reclaim_window(generation, &reason) {
                direct_reclaim_count += 1;
            }
        }

        info!(
            "Local network generation advanced to {generation}: {reason}; opened {direct_reclaim_count} Direct reclaim window(s)"
        );
        generation
    }

    /// Advance local generation after a candidate refresh.
    ///
    /// Unlike a true interface transition, a periodic candidate refresh may
    /// change advertised public or gateway candidates while an authenticated
    /// low-latency private/LAN Direct path is still healthy. Preserve that
    /// selected private pair in the new generation so data traffic does not
    /// briefly fall back to relay on every refresh.
    pub async fn advance_candidate_refresh_generation(&self, reason: impl Into<String>) -> u64 {
        let reason = reason.into();
        let generation = {
            let mut generation = self.network_generation.write().await;
            *generation = generation.saturating_add(1);
            *generation
        };

        let mut retained_private_direct_count = 0usize;
        let mut direct_reclaim_count = 0usize;
        let mut conns = self.connections.write().await;
        for conn in conns.values_mut() {
            let retained_private_direct =
                conn.mark_candidate_refresh_generation_changed(generation, reason.clone());
            if retained_private_direct {
                retained_private_direct_count += 1;
                continue;
            }

            conn.direct_health.record_generation_change(reason.clone());
            if conn.state == ConnectionState::Direct {
                conn.transition(ConnectionState::FallbackToRelay);
            }
            if conn.start_direct_reclaim_window(generation, &reason) {
                direct_reclaim_count += 1;
            }
        }

        info!(
            "Local network generation advanced to {generation}: {reason}; retained {retained_private_direct_count} low-latency private direct path(s); opened {direct_reclaim_count} Direct reclaim window(s)"
        );
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
        conn.app_version = info.app_version.clone();
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
        conn.online = info.online;
        conn.last_seen = info.last_seen;
        conn.remote_relay_rtt_ms = info.relay_rtt_ms;

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
        if !info.online {
            conn.transition(ConnectionState::Closed);
            conn.relay_server = None;
            conn.probe_session_id = None;
            conn.probe_ephemeral_shared = None;
        } else if conn.state == ConnectionState::Closed {
            conn.transition(ConnectionState::Idle);
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

    /// Set the explicit control-plane session ID used to bind Probe v2 MAC keys.
    pub async fn set_probe_session_id(&self, node_id: &str, session_id: Option<String>) -> bool {
        let normalized = session_id.and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        });
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        if conn.probe_session_id == normalized {
            return true;
        }
        conn.probe_session_id = normalized;
        conn.probe_ephemeral_shared = None;
        true
    }

    /// Set the explicit traversal session and optional ephemeral X25519 shared secret.
    pub async fn set_probe_session_binding(
        &self,
        node_id: &str,
        session_id: Option<String>,
        ephemeral_shared: Option<[u8; 32]>,
    ) -> bool {
        let normalized = session_id.and_then(|value| {
            let trimmed = value.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_string())
        });
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.probe_session_id = normalized;
        conn.probe_ephemeral_shared = ephemeral_shared;
        true
    }

    /// Return the Probe v2 MAC key for a known peer, if both public keys are valid.
    ///
    /// New peers with an explicit signaling session ID receive a session-bound
    /// key; legacy peers without a session ID retain the static v2 skeleton key.
    pub async fn probe_key_for_peer(&self, node_id: &str) -> Option<ProbeMacKey> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(effective_probe_mac_key)
    }

    /// Return Probe v2 MAC keys to try for inbound compatibility.
    ///
    /// The strongest key is first.  When a session ID is active, weaker
    /// session/static fallbacks are retained so upgraded peers can still receive
    /// probes from older clients or from signals relayed by older control servers.
    pub async fn probe_keys_for_peer(&self, node_id: &str) -> Vec<ProbeMacKey> {
        let Some(conn) = self.connections.read().await.get(node_id).cloned() else {
            return Vec::new();
        };
        let mut keys = Vec::new();
        if let Some(key) = effective_probe_mac_key(&conn) {
            keys.push(key);
        }
        if conn.probe_session_id.is_some() {
            if let Some(base_key) = conn.probe_mac_key {
                if let Some(session_id) = conn.probe_session_id.as_deref() {
                    let session_key = derive_session_probe_mac_key(&base_key, session_id);
                    if !keys.contains(&session_key) {
                        keys.push(session_key);
                    }
                }
                if !keys.contains(&base_key) {
                    keys.push(base_key);
                }
            }
        }
        keys
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
                    conn.ensure_candidate_pair_with_observed_source(endpoint, generation, source);
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
        let pruned = conn.prune_stale_peer_reflexive_candidates_for_ip(endpoint, generation);
        if pruned > 0 {
            conn.record_direct_event(
                generation,
                "peer_reflexive_window_pruned",
                Some(endpoint),
                Some(conn.candidates.len()),
                None,
                format!(
                    "pruned {pruned} stale peer-reflexive UDP ports for {}",
                    endpoint.ip()
                ),
            );
        }
        true
    }

    /// Learn an endpoint from a legacy ACK correlated to an outstanding nonce.
    ///
    /// The caller must verify the nonce, generation, local socket, and source
    /// IP before using this method. Unlike Probe v2 learning, this endpoint is
    /// deliberately classified as merely learned rather than peer-reflexive.
    pub async fn learn_correlated_probe_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
    ) -> bool {
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
            .insert(endpoint_text, CandidatePairSource::Learned);
        conn.mark_candidate_pair_probing_with_source(
            endpoint,
            generation,
            CandidatePairSource::Learned,
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

    /// Record an authenticated remote ICE-style nomination check.
    ///
    /// This marks the candidate pair as nominated/trial-ready, but it still does not select
    /// Direct; encrypted data must decrypt successfully before the path becomes confirmed.
    pub async fn record_direct_nomination_check_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.mark_candidate_pair_probing_with_local_endpoint(endpoint, generation, local_endpoint);
        conn.mark_candidate_pair_nominated(
            endpoint,
            generation,
            local_endpoint,
            "received authenticated use_candidate connectivity check",
        )
        .is_some()
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
                conn.selected_direct_endpoint_for_consent(generation)
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
        if !conn.online {
            return Vec::new();
        }
        if conn.state == ConnectionState::Direct
            && !conn.should_probe_private_alternates_while_direct(generation)
        {
            return Vec::new();
        }
        let endpoints = conn.candidate_probe_endpoints(
            generation,
            &history,
            local_nat_profile.as_ref(),
            ProbeTargetMode::Synchronized,
        );
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
            .filter_map(|conn| {
                if !conn.online {
                    return None;
                }
                if conn.state == ConnectionState::Direct
                    && !conn.should_probe_private_alternates_while_direct(generation)
                {
                    return None;
                }
                if conn.state != ConnectionState::Direct
                    && !conn.has_direct_retry_opportunity(local_nat_profile.as_ref())
                {
                    if conn
                        .direct_events
                        .last()
                        .is_none_or(|event| {
                            event.network_generation != generation
                                || event.stage != "retry_skipped_no_viable_nat_window"
                        })
                    {
                        conn.record_direct_event(
                            generation,
                            "retry_skipped_no_viable_nat_window",
                            conn.endpoint,
                            None,
                            None,
                            "skipped background Direct retry because local/peer NAT signals show no viable punch window",
                        );
                    }
                    return None;
                }
                let endpoints = conn.candidate_probe_endpoints(
                    generation,
                    &history,
                    local_nat_profile.as_ref(),
                    ProbeTargetMode::Background,
                );

                if endpoints.is_empty() {
                    None
                } else {
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
    /// after the peer-level retry cooldown has elapsed, except during the
    /// short generation-change reclaim window for peers with previous Direct
    /// success.
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
            .filter_map(|conn| {
                if !conn.online {
                    return None;
                }
                if conn.state == ConnectionState::Direct {
                    return None;
                }
                let reclaim_active = conn.direct_reclaim_active();
                if !reclaim_active && !conn.direct_retry_due(base_retry_after) {
                    return None;
                }
                if !conn.has_direct_retry_opportunity(local_nat_profile.as_ref()) {
                    if conn
                        .direct_events
                        .last()
                        .is_none_or(|event| {
                            event.network_generation != generation
                                || event.stage != "retry_skipped_no_viable_nat_window"
                        })
                    {
                        conn.record_direct_event(
                            generation,
                            "retry_skipped_no_viable_nat_window",
                            conn.endpoint,
                            None,
                            None,
                            "skipped background Direct retry because local/peer NAT signals show no viable punch window",
                        );
                    }
                    return None;
                }
                let endpoints = conn.candidate_probe_endpoints(
                    generation,
                    &history,
                    local_nat_profile.as_ref(),
                    if reclaim_active {
                        ProbeTargetMode::Reclaim
                    } else {
                        ProbeTargetMode::Background
                    },
                );

                if endpoints.is_empty() {
                    None
                } else {
                    if reclaim_active {
                        conn.record_direct_event(
                            generation,
                            "direct_reclaim_targets_due",
                            endpoints.first().copied(),
                            Some(endpoints.len()),
                            None,
                            format!(
                                "selected {} UDP candidates for generation-change Direct reclaim",
                                endpoints.len()
                            ),
                        );
                    }
                    Some((conn.node_id.clone(), endpoints))
                }
            })
            .collect()
    }

    /// Record that a UDP probe datagram was actually sent to a candidate.
    ///
    /// Candidate selection can be broader than the outbound rate-limit budget;
    /// mark pairs as probing only once the UDP layer confirms a packet left.
    pub async fn record_direct_probe_sent(&self, node_id: &str, endpoint: SocketAddr) -> bool {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        conn.mark_candidate_pair_probing(endpoint, generation);
        true
    }

    /// Select the data path for one outbound encrypted packet.
    pub async fn select_path_for_data(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
    ) -> PathSelection {
        self.select_path_for_data_with_local_endpoint(node_id, prefer_direct, relay_available, None)
            .await
    }

    /// Select the data path and include the local UDP endpoint in transition diagnostics.
    pub async fn select_path_for_data_with_local_endpoint(
        &self,
        node_id: &str,
        prefer_direct: bool,
        relay_available: bool,
        local_endpoint: Option<SocketAddr>,
    ) -> PathSelection {
        let generation = self.current_network_generation().await;
        let mut conns = self.connections.write().await;
        match conns.get_mut(node_id) {
            Some(conn) => {
                conn.expire_stale_trial_nominations(generation, local_endpoint);
                let selection =
                    conn.select_path_for_data(generation, prefer_direct, relay_available);
                if selection.path == Some(NetworkPath::Direct)
                    && !selection.direct_confirmed
                    && selection.reason_code == REASON_PATH_DIRECT_TRIAL
                {
                    if let Some(endpoint) = selection.direct_endpoint {
                        conn.mark_candidate_pair_nominated(
                            endpoint,
                            generation,
                            local_endpoint,
                            &selection.reason,
                        );
                    }
                }
                conn.record_path_selection_event(generation, &selection, local_endpoint);
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

    /// Whether the peer is inside the aggressive Direct reclaim window.
    pub async fn direct_reclaim_active(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(PeerConnection::direct_reclaim_active)
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
        self.record_direct_success_with_local_endpoint(node_id, endpoint, None)
            .await;
    }

    /// Record a successful direct-path event with the local UDP endpoint that received it.
    pub async fn record_direct_success_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_success_for_generation_with_local_endpoint(
            node_id,
            endpoint,
            generation,
            local_endpoint,
        )
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
        self.record_direct_success_for_generation_with_local_endpoint(
            node_id, endpoint, generation, None,
        )
        .await
    }

    /// Record a successful direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_success_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        let source = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let was_direct = conn.state == ConnectionState::Direct;
            let previous_endpoint = conn.endpoint;
            let previous_generation = conn.direct_generation;
            let selected_endpoint = endpoint.or(conn.endpoint);
            let source = selected_endpoint.map(|endpoint| {
                conn.endpoint = Some(endpoint);
                conn.mark_candidate_pair_success(endpoint, generation, None, true, local_endpoint)
            });
            conn.direct_generation = generation;
            conn.direct_health.record_success();
            conn.clear_direct_reclaim_window();
            conn.record_direct_event(
                generation,
                "direct_confirmed",
                selected_endpoint,
                selected_endpoint.map(|_| 1),
                None,
                "encrypted data path confirmed Direct UDP",
            );
            conn.transition(ConnectionState::Direct);
            if let (Some(endpoint), Some(source)) = (selected_endpoint, source) {
                let direct_type = classify_confirmed_direct_endpoint(endpoint, source);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                let direct_confirmation_changed = !was_direct
                    || previous_endpoint != Some(endpoint)
                    || previous_generation != generation;
                if direct_confirmation_changed {
                    info!(
                        event = "candidate_pair_selected",
                        peer_id = %node_id,
                        local_endpoint = %local_endpoint_text,
                        remote_endpoint = %endpoint,
                        candidate_source = ?source,
                        rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                        reason = "encrypted data path confirmed Direct UDP",
                        "candidate_pair_selected peer_id={} remote_endpoint={} reason=encrypted data path confirmed Direct UDP",
                        node_id,
                        endpoint
                    );
                }
                if !was_direct {
                    info!(
                        event = "direct_path_promoted",
                        peer_id = %node_id,
                        local_endpoint = %local_endpoint_text,
                        remote_endpoint = %endpoint,
                        candidate_source = ?source,
                        rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                        reason = "encrypted data path confirmed Direct UDP",
                        "direct_path_promoted peer_id={} remote_endpoint={} reason=encrypted data path confirmed Direct UDP",
                        node_id,
                        endpoint
                    );
                }
                if direct_confirmation_changed {
                    match direct_type {
                        DirectPathType::PublicUdp => info!(
                            event = "public_udp_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "public_udp_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::Overlay => info!(
                            event = "overlay_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "overlay_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::Lan => info!(
                            event = "lan_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "lan_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        _ => {}
                    }
                }
            }
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
        self.record_direct_probe_success_with_local_endpoint(node_id, endpoint, None)
            .await;
    }

    /// Record that a UDP punch endpoint is reachable with the local socket that saw it.
    pub async fn record_direct_probe_success_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        local_endpoint: Option<SocketAddr>,
    ) {
        self.record_direct_probe_success_with_latency_and_local_endpoint(
            node_id,
            endpoint,
            None,
            local_endpoint,
        )
        .await;
    }

    /// Record a successful direct-path probe and its measured round-trip time.
    pub async fn record_direct_probe_success_with_latency(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
    ) {
        self.record_direct_probe_success_with_latency_and_local_endpoint(
            node_id, endpoint, latency, None,
        )
        .await;
    }

    /// Record a successful direct-path probe, latency, and local UDP endpoint.
    pub async fn record_direct_probe_success_with_latency_and_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            node_id,
            endpoint,
            latency,
            generation,
            local_endpoint,
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
        self.record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            node_id, endpoint, latency, generation, None,
        )
        .await
    }

    /// Record a direct-path probe result for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
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
                Some(conn.mark_candidate_pair_success(
                    endpoint,
                    generation,
                    latency,
                    false,
                    local_endpoint,
                ))
            } else {
                conn.mark_candidate_pair_probing_with_local_endpoint(
                    endpoint,
                    generation,
                    local_endpoint,
                );
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
                    if let Some(source) = source {
                        let local_endpoint_text = format_log_endpoint(local_endpoint);
                        info!(
                            event = "candidate_pair_probe_succeeded",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = duration_millis(latency),
                            reason = "received UDP punch ACK",
                            "candidate_pair_probe_succeeded peer_id={} remote_endpoint={} rtt_ms={}",
                            node_id,
                            endpoint,
                            duration_millis(latency)
                        );
                    }
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
        self.record_direct_failure_with_code_and_local_endpoint(node_id, code, reason, None)
            .await;
    }

    /// Record a failed direct-path event with a stable reason code and local UDP endpoint.
    pub async fn record_direct_failure_with_code_and_local_endpoint(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_failure_for_generation_with_local_endpoint(
            node_id,
            generation,
            code,
            reason,
            local_endpoint,
        )
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
        self.record_direct_failure_for_generation_with_local_endpoint(
            node_id, generation, code, reason, None,
        )
        .await
    }

    /// Record a failed direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_failure_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        generation: u64,
        code: impl Into<String>,
        reason: impl Into<String>,
        local_endpoint: Option<SocketAddr>,
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
            let probed_sources =
                conn.mark_current_candidate_pairs_failed(generation, code, reason, local_endpoint);
            if conn.state != ConnectionState::Relay {
                conn.transition(ConnectionState::FallbackToRelay);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                info!(
                    event = "direct_path_degraded",
                    peer_id = %node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = ?conn.endpoint,
                    candidate_source = ?conn.endpoint.and_then(|endpoint| {
                        conn.candidate_pairs
                            .iter()
                            .find(|pair| {
                                pair.local_generation == generation
                                    && pair.remote_endpoint == endpoint
                            })
                            .map(|pair| pair.source)
                    }),
                    rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                    reason = %conn.direct_health.last_error.as_deref().unwrap_or("direct path failed"),
                    "direct_path_degraded peer_id={} reason={}",
                    node_id,
                    conn.direct_health.last_error.as_deref().unwrap_or("direct path failed")
                );
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
        self.record_direct_keepalive_timeout_for_generation_with_local_endpoint(
            node_id, endpoint, generation, None,
        )
        .await
    }

    /// Record an unanswered direct keepalive and the local UDP endpoint that sent it.
    pub async fn record_direct_keepalive_timeout_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
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
            let peer_id = conn.node_id.clone();
            let pair = conn.ensure_candidate_pair(endpoint, generation);
            let source = pair.source;
            let old_state = pair.state;
            pair.record_failure(
                REASON_DIRECT_KEEPALIVE_TIMEOUT,
                reason.clone(),
                local_endpoint,
            );
            log_candidate_pair_state_changed(&peer_id, pair, old_state, &reason);

            if conn.direct_health.consecutive_failures >= DIRECT_KEEPALIVE_FAILURE_THRESHOLD {
                conn.transition(ConnectionState::FallbackToRelay);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                info!(
                    event = "direct_path_degraded",
                    peer_id = %node_id,
                    local_endpoint = %local_endpoint_text,
                    remote_endpoint = %endpoint,
                    candidate_source = ?source,
                    rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                    reason = "direct keepalive failure threshold reached",
                    "direct_path_degraded peer_id={} remote_endpoint={} reason=direct keepalive failure threshold reached",
                    node_id,
                    endpoint
                );
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
        self.record_relay_success_inner(node_id, relay_server, switch_to_relay, None)
            .await;
    }

    /// Record a successful relay-path event with measured peer round-trip latency.
    pub async fn record_relay_success_with_latency(
        &self,
        node_id: &str,
        relay_server: &str,
        switch_to_relay: bool,
        latency: Duration,
    ) {
        self.record_relay_success_inner(node_id, relay_server, switch_to_relay, Some(latency))
            .await;
    }

    async fn record_relay_success_inner(
        &self,
        node_id: &str,
        relay_server: &str,
        switch_to_relay: bool,
        latency: Option<Duration>,
    ) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.relay_server = Some(relay_server.to_string());
            if let Some(latency) = latency {
                conn.relay_health.record_success_with_latency(latency);
            } else {
                conn.relay_health.record_success();
            }
            if switch_to_relay || conn.state != ConnectionState::Direct {
                conn.transition(ConnectionState::Relay);
                info!(
                    event = "relay_fallback_selected",
                    peer_id = %node_id,
                    local_endpoint = "relay",
                    remote_endpoint = %relay_server,
                    direct_endpoint = ?conn.endpoint,
                    relay_server = %relay_server,
                    candidate_source = ?conn.endpoint.and_then(|endpoint| {
                        conn.candidate_pairs
                            .iter()
                            .find(|pair| pair.remote_endpoint == endpoint)
                            .map(|pair| pair.source)
                    }),
                    rtt_ms = ?conn.relay_health.rtt_ewma_ms.or(conn.relay_health.latency_ms),
                    reason = %format!("relay {relay_server} selected"),
                    "relay_fallback_selected peer_id={} relay_server={}",
                    node_id,
                    relay_server
                );
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

    /// Return peers that need an active relay data-plane confirmation.
    pub async fn relay_validation_targets(
        &self,
        max_success_age: Duration,
    ) -> Vec<(String, String)> {
        self.connections
            .read()
            .await
            .values()
            .filter(|conn| {
                conn.state != ConnectionState::Direct
                    || conn
                        .direct_health
                        .rtt_ewma_ms
                        .or(conn.direct_health.latency_ms)
                        .is_some_and(|rtt| rtt >= SLOW_DIRECT_RELAY_VALIDATION_RTT_MS)
            })
            .filter(|conn| !conn.relay_health.is_confirmed_recent(max_success_age))
            .map(|conn| (conn.node_id.clone(), conn.virtual_ip.clone()))
            .collect()
    }

    /// Get serializable diagnostics for every peer.
    pub async fn diagnostics(&self) -> Vec<PeerDiagnostics> {
        let generation = self.current_network_generation().await;
        let traversal_history = self.traversal_history.read().await.clone();
        let mut peers: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .map(|conn| {
                PeerDiagnostics::from_connection_with_path_selection(
                    conn,
                    None,
                    None,
                    generation,
                    None,
                    Some(&traversal_history),
                )
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
        local_endpoint: Option<SocketAddr>,
    ) -> Vec<PeerDiagnostics> {
        let generation = self.current_network_generation().await;
        let traversal_history = self.traversal_history.read().await.clone();
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
                    local_endpoint,
                    Some(&traversal_history),
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

fn candidate_pair_probe_retry_remaining(pair: &CandidatePair) -> Option<Duration> {
    let retry_after = candidate_pair_failure_cooldown(pair)?;
    let failure_age = pair.failure_age()?;
    Some(retry_after.saturating_sub(failure_age))
}

fn candidate_pair_send_rank(pair: &CandidatePair) -> u8 {
    if is_successful_low_latency_private_pair(pair) {
        return 0;
    }

    if is_recent_successful_direct_trial_pair(pair) {
        return 2;
    }

    match pair.state {
        CandidatePairState::Selected => 1,
        CandidatePairState::Succeeded | CandidatePairState::Probing
            if pair.source == CandidatePairSource::PeerReflexive
                && pair.last_probe_at.is_some_and(|last_probe| {
                    last_probe.elapsed() <= PEER_REFLEXIVE_STICKY_WINDOW
                }) =>
        {
            2
        }
        CandidatePairState::Succeeded => 3,
        CandidatePairState::Probing => 4,
        CandidatePairState::Waiting => 5,
        CandidatePairState::Failed => 6,
        CandidatePairState::Degraded => 7,
        CandidatePairState::Frozen => 8,
    }
}

fn is_recent_successful_direct_trial_pair(pair: &CandidatePair) -> bool {
    if matches!(
        pair.source,
        CandidatePairSource::Predicted | CandidatePairSource::Birthday
    ) || !is_public_probe_endpoint(pair.remote_endpoint)
        || pair.last_error_code.as_deref() == Some(REASON_DIRECT_TRIAL_EXPIRED)
        || pair.consecutive_failures > RECENT_DIRECT_TRIAL_FAILURE_TOLERANCE
    {
        return false;
    }

    pair.success_age()
        .is_some_and(|age| age <= DIRECT_TRIAL_WINDOW)
}

fn is_successful_low_latency_private_pair(pair: &CandidatePair) -> bool {
    matches!(
        pair.state,
        CandidatePairState::Selected | CandidatePairState::Succeeded
    ) && is_low_latency_direct_endpoint(pair.remote_endpoint)
        && pair.consecutive_failures == 0
        && pair
            .success_age()
            .is_some_and(|age| age <= RELAY_PEER_CONFIRMATION_MAX_AGE)
        && pair
            .rtt_ewma_ms
            .or(pair.rtt_ms)
            .is_some_and(|rtt| rtt <= PRIVATE_DIRECT_RETAIN_MAX_RTT_MS)
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn format_log_endpoint(endpoint: Option<SocketAddr>) -> String {
    endpoint
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn log_candidate_pair_state_changed(
    peer_id: &str,
    pair: &CandidatePair,
    old_state: CandidatePairState,
    reason: &str,
) {
    if old_state == pair.state {
        return;
    }

    info!(
        event = "candidate_pair_state_changed",
        peer_id = %peer_id,
        local_endpoint = %format_log_endpoint(pair.local_endpoint),
        remote_endpoint = %pair.remote_endpoint,
        candidate_source = ?pair.source,
        old_state = ?old_state,
        new_state = ?pair.state,
        rtt_ms = ?pair.rtt_ewma_ms.or(pair.rtt_ms),
        reason = %reason,
        "candidate_pair_state_changed peer_id={} remote_endpoint={} old_state={:?} new_state={:?} reason={}",
        peer_id,
        pair.remote_endpoint,
        old_state,
        pair.state,
        reason
    );

    match pair.state {
        CandidatePairState::Selected => info!(
            event = "candidate_pair_selected",
            peer_id = %peer_id,
            local_endpoint = %format_log_endpoint(pair.local_endpoint),
            remote_endpoint = %pair.remote_endpoint,
            candidate_source = ?pair.source,
            rtt_ms = ?pair.rtt_ewma_ms.or(pair.rtt_ms),
            reason = %reason,
            "candidate_pair_selected peer_id={} remote_endpoint={} reason={}",
            peer_id,
            pair.remote_endpoint,
            reason
        ),
        CandidatePairState::Degraded => info!(
            event = "candidate_pair_degraded",
            peer_id = %peer_id,
            local_endpoint = %format_log_endpoint(pair.local_endpoint),
            remote_endpoint = %pair.remote_endpoint,
            candidate_source = ?pair.source,
            rtt_ms = ?pair.rtt_ewma_ms.or(pair.rtt_ms),
            reason = %reason,
            "candidate_pair_degraded peer_id={} remote_endpoint={} reason={}",
            peer_id,
            pair.remote_endpoint,
            reason
        ),
        CandidatePairState::Failed => info!(
            event = "candidate_pair_failed",
            peer_id = %peer_id,
            local_endpoint = %format_log_endpoint(pair.local_endpoint),
            remote_endpoint = %pair.remote_endpoint,
            candidate_source = ?pair.source,
            rtt_ms = ?pair.rtt_ewma_ms.or(pair.rtt_ms),
            reason = %reason,
            "candidate_pair_failed peer_id={} remote_endpoint={} reason={}",
            peer_id,
            pair.remote_endpoint,
            reason
        ),
        _ => {}
    }
}

fn log_candidate_pair_nominated(peer_id: &str, pair: &CandidatePair, reason: &str) {
    info!(
        event = "candidate_pair_nominated",
        peer_id = %peer_id,
        local_endpoint = %format_log_endpoint(pair.local_endpoint),
        remote_endpoint = %pair.remote_endpoint,
        candidate_source = ?pair.source,
        pair_state = ?pair.state,
        rtt_ms = ?pair.rtt_ewma_ms.or(pair.rtt_ms),
        reason = %reason,
        "candidate_pair_nominated peer_id={} remote_endpoint={} reason={}",
        peer_id,
        pair.remote_endpoint,
        reason
    );
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
        Some(ms) if ms <= 500 => -20,
        Some(ms) if ms <= 1000 => -50,
        Some(_) => -70,
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
#[path = "peer/tests.rs"]
mod tests;
