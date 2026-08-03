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
/// punch window should retry quickly after a Direct path falls apart. The
/// peer-level backoff below yields 1s through 64s retries; generation-change
/// reclaim still bypasses this cooldown for a recently working Direct path.
pub const DIRECT_RETRY_BASE_INTERVAL: Duration = Duration::from_secs(1);
const DIRECT_RETRY_BACKOFF_MAX_EXPONENT: u32 = 6;
const DIRECT_TO_RELAY_HYSTERESIS_MARGIN: i32 = 15;
const DIRECT_CONFIRMED_MIN_SCORE: i32 = 60;
const PRIVATE_DIRECT_RETAIN_MAX_RTT_MS: u64 = 250;
const DIRECT_KEEPALIVE_FAILURE_THRESHOLD: u32 = 3;
const PEER_REFLEXIVE_SAME_IP_RETAINED_PORTS: usize = 3;
const PREDICTED_PROBE_BUDGET_PER_CYCLE: usize = 96;
const PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 96;
const PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE: usize = 96;
const PREDICTED_PROBE_FAILURE_BUDGET_PER_CYCLE: usize = 48;
const BIRTHDAY_PROBE_BUDGET_PER_CYCLE: usize = 192;
const BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE: usize = 256;
const BIRTHDAY_PROBE_COOLDOWN_BUDGET_PER_CYCLE: usize = 192;
const BIRTHDAY_PROBE_FAILURE_BUDGET_PER_CYCLE: usize = 192;
const BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE: usize = 4;
const BIRTHDAY_PROBE_NEAR_MAX_DELTA: i32 = 96;
const BIRTHDAY_PROBE_WIDE_MAX_DELTA: i32 = 32_768;
const BIRTHDAY_PROBE_WIDE_STRIDE: i32 = 251;
const REMOTE_SCATTER_POOL_MIN_PUBLIC_PORTS: usize = 16;
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
    birthday_base_rank, candidate_pair_dynamic_probe_rank, candidate_pair_freshness_rank,
    candidate_pair_source_observed_age_ms, candidate_pair_source_quality_rank,
    candidate_pair_source_rank, discovered_endpoint_probe_rank, is_hard_nat_profile,
    peer_reflexive_retention_rank, should_retain_peer_reflexive_pair,
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

include!("peer/connection/core.rs");
include!("peer/connection/candidates.rs");
include!("peer/connection/selection.rs");
include!("peer/connection/health.rs");
include!("peer/connection/events.rs");
include!("peer/manager/state.rs");
include!("peer/manager/core.rs");
include!("peer/manager/peers.rs");
include!("peer/manager/candidates.rs");
include!("peer/manager/path.rs");
include!("peer/manager/direct_success.rs");
include!("peer/manager/direct_failure.rs");
include!("peer/manager/relay.rs");
include!("peer/manager/diagnostics.rs");
include!("peer/utils.rs");

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[path = "peer/tests.rs"]
mod tests;
