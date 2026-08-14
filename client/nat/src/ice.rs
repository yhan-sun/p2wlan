//! ICE candidate gathering and prioritization (RFC 5245).
//!
//! ## Candidate Types
//!
//! - **Host**: Local network interface address (highest priority)
//! - **Server Reflexive (srflx)**: Public address discovered via STUN
//! - **Peer Reflexive (prflx)**: Discovered during ICE connectivity checks
//! - **Relay**: DERP/TURN relay address (lowest priority)
//!
//! ## Priority Formula (RFC 5245)
//!
//! `priority = 2^24 * type_preference + 2^8 * local_preference + component_id`
//!
//! | Type | Preference |
//! |------|-----------|
//! | Host | 126 |
//! | PeerReflexive | 110 |
//! | ServerReflexive | 100 |
//! | Relay | 0 |

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use if_addrs::IfAddr;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::time::{sleep, timeout};
use tracing::{debug, info};

use crate::client::StunClient;
use crate::error::Result;
use crate::{CandidateType, IceCandidate};

/// Type preference values (RFC 5245 Section 4.1.2.1).
const PREF_HOST: u32 = 126;
const PREF_PEER_REFLEXIVE: u32 = 110;
const PREF_SERVER_REFLEXIVE: u32 = 100;
const PREF_RELAY: u32 = 0;

/// Local preference (use max for all interfaces equally).
const LOCAL_PREF: u32 = 65535;

/// Component ID (1 for the only component in our P2P tunnel).
const COMPONENT_ID: u32 = 1;

/// Short timeout for best-effort active NAT behavior probes.
///
/// These probes run on the same UDP socket after ordinary STUN gathering. Keep
/// them intentionally small so diagnostics never turn startup into a long NAT
/// lab run when public STUN servers do not support CHANGE-REQUEST.
const ACTIVE_BEHAVIOR_PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// Short idle delay before re-checking whether the mapped endpoint is stable.
const MAPPING_LIFETIME_PROBE_DELAY: Duration = Duration::from_millis(250);

/// Prefix for self-addressed UDP hairpin probes.
const HAIRPIN_PROBE_PREFIX: &[u8] = b"P2WLAN_HAIRPIN_V1";

/// Maximum bounded predicted server-reflexive candidates to advertise.
///
/// Linear symmetric NATs often advance by one or two ports per outbound
/// destination, but TURN/ICE checks can consume several mappings before the
/// peer-reflexive path is nominated. Keep this window bounded for signaling,
/// while covering the observed 15-20 port jumps produced by WebRTC-style
/// relay-first / direct-chase ICE checks on hard NATs.
const MAX_PREDICTED_REFLEXIVE_CANDIDATES: usize = 96;

/// Configuration for ICE candidate gathering.
#[derive(Debug, Clone)]
pub struct IceConfig {
    /// STUN servers for server-reflexive candidate discovery.
    pub stun_servers: Vec<SocketAddr>,
    /// Timeout for STUN queries.
    pub stun_timeout: Duration,
    /// Whether to gather host candidates.
    pub gather_host: bool,
    /// Whether to gather server-reflexive candidates.
    pub gather_srflx: bool,
}

impl Default for IceConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            stun_timeout: Duration::from_secs(3),
            gather_host: true,
            gather_srflx: true,
        }
    }
}

/// One STUN observation collected from a single external observer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StunObservation {
    /// STUN server queried.
    pub server: String,
    /// Public mapped address seen by the server.
    pub mapped_address: Option<String>,
    /// Query round-trip time in milliseconds.
    pub rtt_ms: Option<u64>,
    /// Error, if the query failed.
    pub error: Option<String>,
}

/// Behavioral NAT mapping classification based on multiple STUN observers.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingBehavior {
    /// No STUN data was collected.
    #[default]
    Unknown,
    /// STUN was configured but no server replied.
    UdpBlocked,
    /// Mapped address matches the local socket address.
    OpenInternet,
    /// Multiple observers saw the same public address and port.
    EndpointIndependent,
    /// Observers returned different public addresses or ports.
    AddressOrPortDependent,
}

/// Best-effort NAT filtering classification.
///
/// `NAT-01b-a` intentionally exposes this as a diagnostic foundation before
/// adding active RFC 5780 / multi-socket filtering probes. Values are therefore
/// conservative unless a future active probe can prove them directly.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilteringBehavior {
    /// No filtering behavior could be inferred.
    #[default]
    Unknown,
    /// CHANGE-REQUEST proved endpoint-independent filtering.
    EndpointIndependent,
    /// Mapping observations suggest endpoint-independent behavior.
    LikelyEndpointIndependent,
    /// CHANGE-REQUEST proved address-dependent filtering.
    AddressDependent,
    /// Mapping observations suggest address or port dependent behavior.
    AddressOrPortDependent,
    /// STUN was configured but no server replied.
    UdpBlocked,
}

/// Local NAT hairpin behavior.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HairpinBehavior {
    /// Hairpin behavior has not been probed yet.
    #[default]
    Unknown,
    /// A self-addressed UDP probe returned through the mapped endpoint.
    Supported,
    /// A self-addressed UDP probe did not return within the bounded probe budget.
    Unsupported,
    /// Hairpin does not matter for a public/open endpoint.
    NotApplicable,
}

/// Observed NAT mapping lifetime.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MappingLifetime {
    /// Lifetime has not been measured yet.
    #[default]
    Unknown,
    /// The mapped endpoint stayed stable for at least this many milliseconds.
    LowerBoundMs(u64),
}

/// Local NAT profile inferred from candidate gathering.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NatProfile {
    /// Local UDP socket address used for STUN and direct traffic.
    pub local_addr: String,
    /// STUN observations used to infer this profile.
    pub observations: Vec<StunObservation>,
    /// True when STUN was configured but every request failed.
    pub udp_blocked: bool,
    /// Best public endpoint discovered from STUN, if any.
    pub public_endpoint: Option<String>,
    /// Whether all successful observations shared the same public IP.
    pub public_ip_stable: Option<bool>,
    /// Whether all successful observations shared the same public port.
    pub public_port_stable: Option<bool>,
    /// Whether the NAT preserved the local UDP port in the first observation.
    pub port_preserved: Option<bool>,
    /// Stable consecutive port delta, when observable.
    pub port_delta: Option<i32>,
    /// Conservative symmetric/address-dependent indicator.
    pub likely_symmetric: Option<bool>,
    /// Behavioral mapping summary.
    pub mapping_behavior: MappingBehavior,
    /// Best-effort filtering behavior summary.
    #[serde(default)]
    pub filtering_behavior: FilteringBehavior,
    /// Hairpin behavior summary.
    #[serde(default)]
    pub hairpin_behavior: HairpinBehavior,
    /// NAT mapping lifetime summary.
    #[serde(default)]
    pub mapping_lifetime: MappingLifetime,
    /// Whether this profile is a good candidate for bounded port prediction.
    #[serde(default)]
    pub prediction_candidate: bool,
    /// Bounded predicted public endpoints derived from a stable mapping delta.
    #[serde(default)]
    pub predicted_endpoints: Vec<String>,
    /// Whether this profile is a good candidate for bounded birthday probing.
    #[serde(default)]
    pub birthday_candidate: bool,
    /// Confidence score from 0-100.
    pub confidence: u8,
}

impl NatProfile {
    /// Compact, backward-compatible NAT behavior label for the control plane.
    ///
    /// The existing `nat_type` field is capped by the server and historically
    /// carried display-only values.  Keep this deliberately short and stable
    /// so a newer daemon can tell its peer whether a prediction/scatter plan
    /// is worthwhile, while older daemons continue to treat it as an opaque
    /// display string.  This is a hint only; authenticated candidate and
    /// encrypted path evidence remain the authority for promotion.
    pub fn control_label(&self) -> String {
        let mapping = match self.mapping_behavior {
            MappingBehavior::Unknown => "unknown",
            MappingBehavior::UdpBlocked => "blocked",
            MappingBehavior::OpenInternet => "open",
            MappingBehavior::EndpointIndependent => "endpoint_independent",
            MappingBehavior::AddressOrPortDependent => "address_or_port_dependent",
        };
        let allocation = if self.udp_blocked {
            "blocked"
        } else if self.prediction_candidate && self.port_delta.is_some() {
            "linear"
        } else if matches!(
            self.mapping_behavior,
            MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
        ) {
            "stable"
        } else if self.likely_symmetric == Some(true) {
            "random"
        } else {
            "unknown"
        };
        let delta = self
            .port_delta
            .map(|delta| delta.to_string())
            .unwrap_or_else(|| "?".to_string());
        format!(
            "p2:m={mapping};a={allocation};d={delta};c={}",
            self.confidence
        )
    }

    fn unknown(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: local_addr.to_string(),
            observations: Vec::new(),
            udp_blocked: false,
            public_endpoint: None,
            public_ip_stable: None,
            public_port_stable: None,
            port_preserved: None,
            port_delta: None,
            likely_symmetric: None,
            mapping_behavior: MappingBehavior::Unknown,
            filtering_behavior: FilteringBehavior::Unknown,
            hairpin_behavior: HairpinBehavior::Unknown,
            mapping_lifetime: MappingLifetime::Unknown,
            prediction_candidate: false,
            predicted_endpoints: Vec::new(),
            birthday_candidate: false,
            confidence: 0,
        }
    }
}

/// Candidate gathering output with STUN observations and inferred NAT behavior.
#[derive(Debug, Clone)]
pub struct CandidateGatherReport {
    /// Gathered ICE candidates.
    pub candidates: Vec<IceCandidate>,
    /// Inferred NAT profile.
    pub nat_profile: NatProfile,
}

include!("ice/interfaces.rs");
include!("ice/gather.rs");
include!("ice/profile.rs");
include!("ice/active_probes.rs");
include!("ice/utils.rs");

#[cfg(test)]
mod tests;
