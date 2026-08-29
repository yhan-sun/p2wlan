//! Peer connection manager.
//!
//! Manages connections to other nodes in the virtual network:
//! - Tracks active peer tunnels (WireGuard sessions)
//! - Handles ICE candidate exchange for NAT traversal
//! - Falls back to relay when direct connection fails
//! - Routes packets between TUN device and peer tunnels

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_crypto::{hmac, NodeIdentity};
use p2pnet_nat::{
    parse_nat_hint, plan_traversal, LocalNetwork, MappingBehavior, NatCapabilities, NatProfile,
    ProbeMacKey, RemoteNatProfile, TraversalContext, TraversalPlan,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

// WebSocket signals do not include a server-time offset.  A bounded grace
// period prevents a peer with a modestly fast system clock from rejecting an
// otherwise fresh server-issued candidate set.  Generation ordering still
// prevents old sets from replacing newer ones.
pub(crate) const CANDIDATE_EXPIRY_CLOCK_SKEW_GRACE_MS: u64 = 120_000;

use crate::config::Config;
use crate::connection_timeline::ConnectionTimeline;
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
/// punch window must keep trying during the bounded fast-recovery window. The
/// peer-level backoff is deliberately capped at 8s: a 64s retry gap made a
/// healthy relay hide Direct recovery for most of the user's acceptance
/// window. Recovery epoch budgets and per-peer probe admission remain the
/// safety limits; this cap does not create an unbounded probe storm.
pub const DIRECT_RETRY_BASE_INTERVAL: Duration = Duration::from_secs(1);
/// Maximum time to reserve the first business packet for the relay probe
/// after a per-peer relay transport becomes ready.  Direct validation keeps
/// running during this window; if the relay peer ACK does not arrive, a
/// genuinely encrypted-confirmed Direct path is the bounded fallback.
pub(crate) const RELAY_FIRST_CONFIRMATION_GRACE: Duration = Duration::from_secs(3);
const DIRECT_RETRY_BACKOFF_MAX_EXPONENT: u32 = 3;
const DIRECT_TO_RELAY_HYSTERESIS_MARGIN: i32 = 15;
const DIRECT_CONFIRMED_MIN_SCORE: i32 = 60;
const REMOTE_NAT_PROFILE_MAX_AGE: Duration = Duration::from_secs(60);
const PRIVATE_DIRECT_RETAIN_MAX_RTT_MS: u64 = 250;
const DIRECT_KEEPALIVE_FAILURE_THRESHOLD: u32 = 3;
const PEER_REFLEXIVE_SAME_IP_RETAINED_PORTS: usize = 3;
/// Probe budgets per cycle.  Kept `pub(crate)` so a stability test can pin
/// them against accidental regression while this work changes the relay-first
/// data path.
pub(crate) const PREDICTED_PROBE_BUDGET_PER_CYCLE: usize = 96;
const PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 96;
const PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE: usize = 96;
const PREDICTED_PROBE_FAILURE_BUDGET_PER_CYCLE: usize = 48;
pub(crate) const BIRTHDAY_PROBE_BUDGET_PER_CYCLE: usize = 192;
pub(crate) const BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 256;
const BIRTHDAY_PROBE_COOLDOWN_BUDGET_PER_CYCLE: usize = 192;
pub(crate) const BIRTHDAY_PROBE_FAILURE_BUDGET_PER_CYCLE: usize = 192;
const BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE: usize = 4;
const BIRTHDAY_PROBE_NEAR_MAX_DELTA: i32 = 96;
/// Advertised-endpoint neighborhood merged into the latency-sensitive fast
/// prefix when NO fresh prediction window exists.
///
/// Field evidence (dual-CGNAT, 2026-08-16): the stable side's fast prefix
/// carried only the exact advertised/learned ports, and after a UDP black
/// hole cleared the first probe that matched was a neighboring port of an
/// advertised base — the dt-precise trigger window was the neighborhood, not
/// the exact port.  Merging ±8 around advertised authoritative bases into
/// the bounded fast prefix (still capped by DIRECT_FAST_PROBE_MAX_CANDIDATES)
/// makes the first post-hole probe land the hit instead of waiting for the
/// slow birthday wide sweep.
const FAST_PREFIX_ADVERTISED_NEAR_DELTA: i32 = 8;
/// Reserve a small portion of the immediate probe prefix for a Host candidate
/// that is proven to be on one of this daemon's directly-connected networks.
const ON_LINK_HOST_FAST_LANE_MAX_CANDIDATES: usize = 4;
/// The largest immediate prefix used by the direct runtime when a trusted
/// prediction/learned window is present. Keeping the reserve inside this
/// bound prevents a large prediction window from crowding out Public + LAN.
const PREFERRED_FAST_CANDIDATE_CAP: usize = 32;
const BIRTHDAY_PROBE_PORT_SPACE: usize = u16::MAX as usize;
const BIRTHDAY_PROBE_WIDE_STRIDE: usize = 251;
/// Stable/easy peers should spend the remote-scatter session cap on distinct
/// remote ports instead of repeating every port from each local pool socket.
const STABLE_WIDE_SCATTER_UNIQUE_TARGET_BUDGET: usize = 3_072;
/// A peer can advertise a small set of authoritative public mappings when it
/// uses a UDP socket pool.  That is still a stable remote role for a local
/// hard NAT: keep one peer-specific binding warm toward the stable peer while
/// the stable peer scans this side's predicted window.  Larger same-IP
/// authoritative groups look like NAT port churn and should keep the wider
/// birthday strategy.
const STABLE_PUBLIC_POOL_MAX_PORTS_PER_IP: usize = 4;
const REMOTE_SCATTER_POOL_MIN_PUBLIC_PORTS: usize = 16;
/// The asymmetric stable role must cover EVERY advertised stable public
/// mapping of the easy peer in the first bounded burst, never only the
/// top-ranked one.  A multi-socket easy peer may have exactly one live
/// mapping at any instant (the other socket bindings expire while its pool is
/// dormant), so locking onto `public.first()` freezes the punch on a stale
/// port while the live mapping is never probed.
const ASYMMETRIC_STABLE_MAX_PUBLIC_ENDPOINTS: usize = 4;
/// Per-plan slice of the wide stable-side unique-target scatter window.
///
/// The full `STABLE_WIDE_SCATTER_UNIQUE_TARGET_BUDGET` window is still
/// reachable, but only rank-by-rank: each plan generates (and persists) at
/// most this many birthday candidates, the session sends them, and the cursor
/// advances to the next slice.  This keeps the resident candidate-pair state
/// bounded to what is actually scanned in one recovery session instead of
/// persisting 3,072 pairs while the stage caps truncate the real scan.
const STABLE_SCATTER_PLAN_SLICE: usize = 512;
/// Per-plan slice of ordinary per-base birthday windows (non-stable side).
const BIRTHDAY_PLAN_SLICE: usize = 512;
/// Hard bound on resident candidate pairs per peer.  The prune path retires
/// the oldest non-selected pairs (never pairs with success history) whenever
/// the bound is exceeded, so birthday/predicted state can never balloon.
const MAX_CANDIDATE_PAIRS_PER_PEER: usize = 640;
const CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE: Duration = Duration::from_secs(1);
const CANDIDATE_PAIR_FAILURE_COOLDOWN_MAX_EXPONENT: u32 = 3;
const PRIORITY_OUTBOUND_PROBE_FAILURE_COOLDOWN: Duration = Duration::from_secs(1);
pub(crate) const SLOW_DIRECT_RELAY_VALIDATION_RTT_MS: u64 = 300;
/// Do not immediately retry a candidate that proved reachable only through a
/// delayed mapping while the confirmed relay is available.  This is a
/// peer/generation quarantine, not a send timeout: it prevents repeated
/// validation owners while the confirmed relay is healthy, and a new network
/// generation clears it so a rejoin can start fresh.
pub(crate) const SLOW_DIRECT_RELAY_RETRY_COOLDOWN: Duration = Duration::from_secs(5);
const PATH_SELECTION_EVENT_LIMIT: usize = 16;
const DIRECT_TRAVERSAL_EVENT_LIMIT: usize = 32;
const RELAY_PEER_CONFIRMATION_MAX_AGE: Duration = Duration::from_secs(30);
const PROBE_MAC_KEY_DOMAIN: &[u8] = b"p2wlan udp probe v2 mac key";
const PROBE_MAC_SESSION_KEY_DOMAIN: &[u8] = b"p2wlan udp probe v2 session key";
const PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN: &[u8] = b"p2wlan udp probe v2 ephemeral session key";
const PROBE_SESSION_BINDING_OVERLAP: Duration = Duration::from_secs(90);
/// Keep a responder Probe binding alive for the full wide NAT-scatter window.
/// An authenticated Probe packet is also a WireGuard adoption proof, so this
/// is deliberately longer than the 10-15s control-plane retry timers.
const PENDING_PROBE_SESSION_BINDING_GRACE: Duration = Duration::from_secs(60);
const MAX_PENDING_PROBE_SESSION_BINDINGS_PER_PEER: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProbeKeyRole {
    Active,
    Pending { token: String },
    Previous,
    Compatibility,
}

/// Process-local identity of one peer lifecycle.
///
/// This is deliberately separate from network and candidate generations: a
/// peer can leave and rejoin under the same node ID, rotate its public key, go
/// offline and come back, or restart while reusing otherwise identical
/// candidates.  Authenticated UDP work snapshots this value together with the
/// key that verified the packet and must re-check it before adopting evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct PeerSessionGeneration(u64);

impl PeerSessionGeneration {
    /// Bootstrap identity used only by an unattached `PeerConnection`.
    /// Production peers are rebound to a strictly positive generation by
    /// `PeerMembershipState::publish` before path work is admitted.
    pub(crate) const UNBOUND: Self = Self(0);

    #[cfg(test)]
    pub(crate) const fn for_test(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerMembershipEntry {
    session_generation: PeerSessionGeneration,
    online: bool,
}

#[derive(Debug, Default)]
struct PeerMembershipState {
    peers: HashMap<String, PeerMembershipEntry>,
    next_session_generation: u64,
}

impl PeerMembershipState {
    /// Publish a fully initialized peer, rotating its lifecycle identity when
    /// requested.  Exhaustion fails closed instead of reusing a generation.
    fn publish(
        &mut self,
        node_id: &str,
        online: bool,
        rotate: bool,
    ) -> Option<PeerSessionGeneration> {
        if !rotate {
            if let Some(entry) = self.peers.get_mut(node_id) {
                entry.online = online;
                return Some(entry.session_generation);
            }
        }

        let Some(next) = self.next_session_generation.checked_add(1) else {
            self.peers.remove(node_id);
            return None;
        };
        self.next_session_generation = next;
        self.peers.insert(
            node_id.to_string(),
            PeerMembershipEntry {
                session_generation: PeerSessionGeneration(next),
                online,
            },
        );
        Some(PeerSessionGeneration(next))
    }

    fn remove(&mut self, node_id: &str) {
        self.peers.remove(node_id);
    }

    fn contains(&self, node_id: &str) -> bool {
        self.peers.contains_key(node_id)
    }

    fn active_generation(&self, node_id: &str) -> Option<PeerSessionGeneration> {
        self.peers
            .get(node_id)
            .filter(|entry| entry.online)
            .map(|entry| entry.session_generation)
    }

    fn generation(&self, node_id: &str) -> Option<PeerSessionGeneration> {
        self.peers
            .get(node_id)
            .map(|entry| entry.session_generation)
    }

    fn active_generation_is_current(&self, node_id: &str, expected: PeerSessionGeneration) -> bool {
        self.active_generation(node_id) == Some(expected)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeKeyCandidate {
    pub(crate) key: ProbeMacKey,
    pub(crate) role: ProbeKeyRole,
    /// Peer lifecycle that owned this key when it was snapshotted.
    pub(crate) session_generation: PeerSessionGeneration,
    /// Probe session that derived this key. This is diagnostics metadata only:
    /// authentication still relies exclusively on the MAC key and existing
    /// pending-binding transaction checks.
    pub(crate) session_id: Option<String>,
}

/// Deterministic one-shot pause after Probe-v2 MAC verification.  Production
/// builds contain neither the field nor the branch; UDP tests use this to put
/// a lifecycle transition exactly between verification and adoption.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct AuthenticatedProbeVerifyGate {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Barrier,
    pub(crate) pending_emit_wait_started: tokio::sync::Notify,
}

#[cfg(test)]
impl AuthenticatedProbeVerifyGate {
    pub(crate) fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Barrier::new(2),
            pending_emit_wait_started: tokio::sync::Notify::new(),
        }
    }
}

/// Deterministic one-shot pause inside the real Relay target snapshot.  This
/// is test-only instrumentation for reproducing the startup ordering in which
/// Relay probing owns a connection reader while initiator publication needs
/// the writer; production builds contain neither the field nor the branch.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct RelayProbeSnapshotTestGate {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
}

#[cfg(test)]
impl RelayProbeSnapshotTestGate {
    pub(crate) fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeBindingStage {
    Staged,
    ReplayableDuplicate,
    StaleDuplicate,
    Busy,
    PeerMissing,
}

/// Outcome of applying a versioned candidate signal from the control plane.
///
/// Callers use this to avoid starting a synchronized punch for a signal whose
/// candidates were rejected before they changed any peer state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateSetApplyResult {
    Applied,
    IgnoredEmpty,
    IgnoredStale,
    IgnoredExpired,
    PeerMissing,
}

/// Admission result for the identity-bound remote-incarnation preflight.
///
/// A signal whose server-bound sender key no longer matches the peer's current
/// public key is terminally rejected before it can reset transport state.  A
/// legacy signal without sender identity remains compatible and simply has no
/// restart work when its generation is unencoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteCandidateIncarnationClaim {
    IdentityMismatch,
    NoReset,
    Reset {
        old_incarnation: u64,
        new_incarnation: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeTargetMode {
    /// The synchronized offer/answer punch window. Keep the first attempt
    /// compact, then permit a wider fallback after every explicit prediction
    /// has failed so both peers probe during the same NAT mapping window.
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

    fn allows_failed_prediction_fallback(self) -> bool {
        matches!(self, Self::Synchronized | Self::Background | Self::Reclaim)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BirthdayProbePlan {
    pub local_generation: u64,
    pub stable_side_unique_scatter: bool,
    pub bases: Vec<SocketAddr>,
    pub public_ips: Vec<IpAddr>,
    pub start_rank: usize,
    pub end_rank: usize,
    pub generated_candidates: usize,
    /// Total candidate count after birthday generation, before the adaptive
    /// probe budgets filter endpoints out.  The cursor must only advance when
    /// nothing planned was dropped by cooldown/budget filtering.
    pub planned_candidates: usize,
    pub selected_candidates: usize,
    pub selected_birthday_candidates: usize,
    pub unique_target_ports: usize,
    pub wrapped: bool,
}

/// Stable reason code emitted when a local network generation changes.
pub const REASON_NETWORK_GENERATION_CHANGED: &str = "network_generation_changed";
/// Stable reason code emitted when a peer publishes a newer remote candidate set.
pub const REASON_REMOTE_CANDIDATE_GENERATION_CHANGED: &str = "remote_candidate_generation_changed";
/// Stable reason code for direct path probe timeout/failure.
pub const REASON_DIRECT_PROBE_FAILED: &str = "direct_probe_failed";
/// Stable reason code for direct path send failure.
pub const REASON_DIRECT_SEND_FAILED: &str = "direct_send_failed";
/// Stable reason code: a ScatterExtended wide scan exhausted with 0 matched
/// ACKs AND outbound-UDP liveness probed Blocked (every DNS target silent
/// across every round) — outbound egress is firewalled, not a window miss /
/// C=0.  Distinct from `REASON_DIRECT_PROBE_FAILED` (a silent scan alone,
/// whose cause is still unknown) so the operator can tell a firewall apart
/// from a plain NAT miss.
pub const REASON_DIRECT_FIREWALL_BLOCKED: &str = "firewall_blocked";
/// A direct probe ACK arrived, but its RTT was too slow to displace a
/// same-generation confirmed relay.
pub const REASON_DIRECT_PROBE_SLOW_RELAY_RETAINED: &str = "direct_probe_slow_relay_retained";
/// A direct candidate was bidirectionally reachable but was retained only as
/// slow evidence while the confirmed relay remained active.
pub const REASON_DIRECT_SLOW_RELAY_RETAINED: &str = "direct_slow_relay_retained";
/// Direct UDP keepalive did not receive a matching authenticated ACK.
pub const REASON_DIRECT_KEEPALIVE_TIMEOUT: &str = "direct_keepalive_timeout";
/// A nominated Direct trial did not receive encrypted data confirmation in time.
pub const REASON_DIRECT_TRIAL_EXPIRED: &str = "direct_trial_expired";
/// Stable reason code for WireGuard handshake timeout.
pub const REASON_HANDSHAKE_TIMEOUT: &str = "handshake_timeout";
/// Path selector chose a confirmed Direct UDP pair.
pub const REASON_PATH_DIRECT_CONFIRMED: &str = "path_direct_confirmed";
/// Path selector kept an encrypted-confirmed Direct pair under the
/// `direct-sticky` policy.
pub const REASON_PATH_DIRECT_STICKY: &str = "path_direct_sticky";
/// Path selector selected Direct because the configured score policy ranked
/// it at least as well as the confirmed Relay path.
pub const REASON_PATH_SCORE_DIRECT: &str = "path_score_direct";
/// Path selector selected Relay because the configured score policy ranked it
/// materially better than the encrypted-confirmed Direct path.
pub const REASON_PATH_SCORE_RELAY: &str = "path_score_relay";
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
/// An encrypted Direct validation succeeded, but its measured RTT exceeded
/// the relay-retention quality floor while the same-generation relay was
/// already peer-confirmed. The proof remains authoritative, while the
/// existing quality fallback keeps Relay active.
pub const REASON_PATH_DIRECT_SLOW_RELAY_RETAINED: &str = "path_direct_slow_relay_retained";
/// Reserved startup-gate reason for a path that has not yet received an
/// authoritative current-generation Direct confirmation.
pub const REASON_PATH_RELAY_FIRST_PENDING: &str = "path_relay_first_pending";
/// Reserved relay-first business-gate reason for pre-authoritative/trial
/// selection. A current authoritative Direct pair bypasses this marker.
pub const REASON_PATH_RELAY_FIRST_BUSINESS: &str = "path_relay_first_business";
/// Relay was confirmed, but the bidirectional first-business evidence did not
/// arrive before the bounded relay-first grace.  Direct remains eligible only
/// because it has its own same-generation encrypted confirmation; this is an
/// observable fallback, never a relay confirmation.
pub const REASON_PATH_DIRECT_AFTER_RELAY_BUSINESS_DEADLINE: &str =
    "path_direct_after_relay_business_deadline";
/// A Direct business packet arrived before an authoritative current Direct
/// commit and before the bidirectional relay-first evidence was complete; it
/// may be delivered, but it cannot win first usable.
pub const REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS: &str = "first_direct_before_relay_business";
/// Direct became first usable after the bounded relay-business gate expired.
/// This is deliberately distinct from a relay-first result in acceptance
/// artifacts and diagnostics.
pub const REASON_FIRST_DIRECT_AFTER_RELAY_BUSINESS_DEADLINE: &str =
    "first_direct_after_relay_business_deadline";
/// A decrypted relay business packet arrived before the same-generation relay
/// peer ACK.  It is a health observation only, never relay-first evidence.
pub const REASON_FIRST_RELAY_BEFORE_CONFIRMATION: &str = "first_relay_before_peer_confirmation";
/// Path selector found no usable Direct or Relay path.
pub const REASON_PATH_UNAVAILABLE: &str = "path_unavailable";

mod birthday;
mod candidate_ranking;
mod diagnostics;
mod endpoint;
mod probe_budget;
mod types;
use birthday::{
    advertised_neighborhood_endpoint, birthday_probe_endpoint_plan_for_bases_from_rank,
    birthday_probe_wide_rank_count, peer_candidates_need_port_scatter,
    stable_public_ip_probe_plan_from_rank,
};
#[cfg(test)]
use birthday::{
    birthday_probe_endpoints, birthday_probe_endpoints_for_bases,
    birthday_probe_endpoints_for_bases_from_rank, birthday_probe_near_rank_count,
};
use candidate_ranking::{
    birthday_base_rank, candidate_pair_dynamic_probe_rank, candidate_pair_freshness_rank_at,
    candidate_pair_source_observed_age_ms, candidate_pair_source_quality_rank,
    candidate_pair_source_rank, discovered_endpoint_probe_rank, is_hard_nat_profile,
    peer_reflexive_retention_rank, should_retain_peer_reflexive_pair,
    speculative_probe_rotation_rank, speculative_probe_source_rank_for_mode,
};
use diagnostics::candidate_pair_source_stats;
pub use diagnostics::{
    CandidatePairDiagnostics, CandidatePairSourceStats, DirectTraversalEventDiagnostics,
    PathHealthDiagnostics, PathSelectionEventDiagnostics, PeerDiagnostics, PeerManagerStats,
    RecoveryEpochDiagnostics,
};
pub(crate) use endpoint::is_overlay_endpoint;
pub(crate) use endpoint::is_public_probe_endpoint;
use endpoint::{
    candidate_pair_failure_cooldown, candidate_pair_probe_allowed_at, candidate_pair_probe_due,
    candidate_pair_probe_rank_for_mode, classify_candidate_pair_path_with_on_link_host,
    classify_confirmed_direct_endpoint_with_on_link_host, endpoint_probe_rank,
    is_low_latency_direct_endpoint, should_retain_confirmed_direct_pair_on_candidate_refresh,
    should_retain_private_direct_pair,
};
#[cfg(test)]
use probe_budget::birthday_probe_budget_for_base_count;
use probe_budget::{
    apply_adaptive_probe_budgets, birthday_probe_budget, candidate_pair_source_probe_budget,
    is_priority_outbound_probe_pair, is_speculative_probe_source, outbound_probe_priority_rank,
};
pub use types::{
    ActivePathSnapshot, CandidatePair, CandidatePairSource, CandidatePairState, ConnectionState,
    DirectPathType, DirectTraversalEvent, DirectValidationEventMetadata, NetworkPath, PathHealth,
    PathScore, PathScoreDiagnostics, PathSelection, PathSelectionDiagnostics, PathSelectionEvent,
};

mod path_state_machine;
pub(crate) use path_state_machine::{
    ActiveBusinessPath, DirectAttemptNumber, DirectCandidateContinuity, DirectValidationIdentity,
    PathEpoch, PathEvent, PathRetention, PathStateMachine, PathStateMachineSnapshot,
    PathTransitionOutcome, PeerPathLifecycle, RelayBusinessObservation, RelayConnectionIdentity,
    RelayHealthObservationIdentity,
};

include!("peer/connection/core.rs");
include!("peer/connection/candidates.rs");
include!("peer/connection/selection.rs");
include!("peer/connection/health.rs");
include!("peer/connection/events.rs");
include!("peer/connection/nat_hint.rs");
include!("peer/manager/state.rs");
include!("peer/manager/core.rs");
include!("peer/manager/peers.rs");
include!("peer/manager/candidates.rs");
include!("peer/manager/path.rs");
include!("peer/manager/direct_success.rs");
include!("peer/manager/direct_failure.rs");
include!("peer/manager/relay.rs");
include!("peer/manager/fresh_mapping.rs");
include!("peer/manager/hard_hard.rs");
include!("peer/manager/recovery_epoch.rs");
include!("peer/manager/outbound_liveness.rs");
include!("peer/manager/c0_coordination.rs");
include!("peer/manager/quarantine.rs");
include!("peer/manager/diagnostics.rs");
include!("peer/utils.rs");

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[path = "peer/tests.rs"]
mod tests;
