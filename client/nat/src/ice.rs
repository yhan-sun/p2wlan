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
use crate::mapping::{infer_allocation_model, AllocationModelKind, MappingObservation};
use crate::{CandidateType, IceCandidate};

/// Type preference values (RFC 5245 Section 4.1.2.1).
const PREF_HOST: u32 = 126;
const PREF_PORT_MAPPED: u32 = 120;
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

/// Reason an observer could not supply a usable mapping on this socket.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StunFailureKind {
    LocalIo,
    ResponseTimeout,
    InvalidResponse,
    NoMapping,
    WrongAddressFamily,
}

impl From<&crate::NatError> for StunFailureKind {
    fn from(error: &crate::NatError) -> Self {
        match error {
            crate::NatError::Timeout(_) => Self::ResponseTimeout,
            crate::NatError::Stun(_)
            | crate::NatError::InvalidStunMessage(_)
            | crate::NatError::InvalidAttribute(_) => Self::InvalidResponse,
            _ => Self::LocalIo,
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
    /// Older observations carry only free-text errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_kind: Option<StunFailureKind>,
    /// Error, if the query failed.
    pub error: Option<String>,
}

impl StunObservation {
    pub fn reply(server: SocketAddr, mapped: Option<SocketAddr>, rtt: Duration) -> Self {
        let failure_kind = match mapped {
            Some(address) if address.is_ipv4() != server.is_ipv4() => {
                Some(StunFailureKind::WrongAddressFamily)
            }
            None => Some(StunFailureKind::NoMapping),
            _ => None,
        };
        Self {
            server: server.to_string(),
            mapped_address: mapped
                .filter(|_| failure_kind.is_none())
                .map(|address| address.to_string()),
            rtt_ms: Some(duration_millis(rtt)),
            failure_kind,
            error: failure_kind
                .map(|kind| format!("STUN reply without a usable mapping ({kind:?})")),
        }
    }

    pub fn failed(server: SocketAddr, kind: StunFailureKind, error: String) -> Self {
        Self {
            server: server.to_string(),
            mapped_address: None,
            rtt_ms: None,
            failure_kind: Some(kind),
            error: Some(error),
        }
    }
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
    /// True when UDP blocking has corroborating evidence. Observer timeouts alone leave it unknown.
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
    /// Coarse discovery evidence score from 0-100, not a measured probability
    /// of predicting the peer-facing port. Concurrent allocation observations
    /// are capped at 60; a fresh ordered PortModel owns execution confidence.
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
        } else if matches!(
            self.mapping_behavior,
            MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
        ) {
            "stable"
        } else if self.prediction_candidate
            && self.port_delta.is_some()
            && !self.predicted_endpoints.is_empty()
        {
            // This is an already materialized model/window from a previous
            // complete measurement or a trusted remote hint. It is not a
            // random classification derived from two differing ports.
            "linear"
        } else {
            match self.allocation_model_hint() {
                AllocationModelKind::FixedStep { .. } | AllocationModelKind::SmallWindow { .. } => {
                    "linear"
                }
                AllocationModelKind::HighEntropy => "random",
                AllocationModelKind::Stable => "stable",
                AllocationModelKind::Unknown => "unknown",
            }
        };
        let delta = self
            .port_delta
            .map(|delta| delta.to_string())
            .unwrap_or_else(|| "?".to_string());
        // `f=`/`h=` use the serde names (not the display tokens `m=` uses) so
        // the receiver can reverse-map them straight to the behavioral enums.
        // They are purely additive: `m=`/`a=`/`d=`/`c=` are byte-for-byte
        // unchanged from the historical `p2:` label, and `p2:` remains a
        // substring of `p2v2:` — so an older daemon's `.contains("a=linear")`
        // / `.contains("address_or_port_dependent")` heuristics still match
        // exactly as before. `f=`/`h=` carry no legacy `a=`/`m=` token except
        // `f=address_or_port_dependent`, which the wide `.contains` would have
        // matched anyway. This is what makes the prefix upgrade + additive
        // fields free of backward-compat regressions.
        let filtering = match self.filtering_behavior {
            FilteringBehavior::Unknown => "unknown",
            FilteringBehavior::EndpointIndependent => "endpoint_independent",
            FilteringBehavior::LikelyEndpointIndependent => "likely_endpoint_independent",
            FilteringBehavior::AddressDependent => "address_dependent",
            FilteringBehavior::AddressOrPortDependent => "address_or_port_dependent",
            FilteringBehavior::UdpBlocked => "udp_blocked",
        };
        let hairpin = match self.hairpin_behavior {
            HairpinBehavior::Unknown => "unknown",
            HairpinBehavior::Supported => "supported",
            HairpinBehavior::Unsupported => "unsupported",
            HairpinBehavior::NotApplicable => "not_applicable",
        };
        format!(
            "p2v2:m={mapping};a={allocation};d={delta};c={};f={filtering};h={hairpin}",
            self.confidence
        )
    }

    /// Reconstruct the allocation evidence from the observer records. A
    /// profile with only two different ports is deliberately `unknown`: the
    /// direction, repeatability and entropy of the allocator are not
    /// identifiable from one delta.
    fn allocation_model_hint(&self) -> AllocationModelKind {
        let observations =
            self.observations
                .iter()
                .enumerate()
                .filter_map(|(sequence, observation)| {
                    let observed = observation.mapped_address.as_deref()?.parse().ok()?;
                    let observer = observation
                        .server
                        .parse()
                        .unwrap_or_else(|_| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
                    Some(MappingObservation {
                        sequence: sequence as u16,
                        observer,
                        observed,
                        sent_at_ms: sequence as u64,
                        responded_at_ms: sequence as u64 + 1,
                        local_endpoint: self.local_addr.parse().unwrap_or_else(|_| {
                            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
                        }),
                    })
                })
                .collect::<Vec<_>>();
        infer_allocation_model(&observations).kind
    }

    /// Add the local evidence generation to the compact control-plane hint.
    ///
    /// `control_label` remains byte-compatible for existing callers and
    /// tests.  The generation is an additive fence used by newer peers to
    /// reject delayed profile updates after a network transition.
    pub fn control_label_with_generation(&self, generation: u64) -> String {
        format!("{};g={generation}", self.control_label())
    }

    /// Add an independently monotonic, *real measurement* sequence to the
    /// control-plane NAT hint.
    ///
    /// `g` describes a change in the usable NAT capability. It deliberately
    /// does not change for a stable mapping whose STUN RTT merely varies. A
    /// receiver still needs to learn that a new STUN transaction actually
    /// succeeded, however: otherwise it must either let good evidence expire
    /// after one minute or let cached heartbeat metadata keep it fresh forever.
    /// `o` is that proof-of-new-observation fence. Callers must only provide
    /// it after a live gather has produced a successful server-reflexive
    /// observation; cached heartbeat publication reuses the prior label.
    ///
    /// The device `nat_type` field is capped at 128 bytes. The normal label is
    /// much shorter, but maximal `g` and `o` values combined with the longest
    /// diagnostics fields can exceed the cap. In that exceptional case drop
    /// optional hairpin then confidence diagnostics while retaining every
    /// traversal-affecting field (`m`, `a`, `d`, `f`) and both ordering fences.
    /// Never truncate a field: malformed labels must stay malformed rather
    /// than silently changing traversal behavior.
    pub fn control_label_with_generation_and_observation(
        &self,
        generation: u64,
        observation: Option<u64>,
    ) -> String {
        self.control_label_with_evidence(generation, observation, None)
    }

    /// Build the fully fenced NAT label used by the control plane.
    ///
    /// `l` is a server-issued registration lifecycle. It resets `g`/`o`
    /// ordering after a daemon re-registers, while preventing endpoint PATCHes
    /// from an earlier process incarnation from overwriting the new one.
    pub fn control_label_with_evidence(
        &self,
        generation: u64,
        observation: Option<u64>,
        lifecycle: Option<u64>,
    ) -> String {
        if observation.is_none() && lifecycle.is_none() {
            return self.control_label_with_generation(generation);
        }

        const CONTROL_LABEL_MAX_BYTES: usize = 128;
        let mut suffix = format!(";g={generation}");
        if let Some(observation) = observation {
            suffix.push_str(&format!(";o={observation}"));
        }
        if let Some(lifecycle) = lifecycle {
            suffix.push_str(&format!(";l={lifecycle}"));
        }
        let mut label = self.control_label();
        if label.len() + suffix.len() > CONTROL_LABEL_MAX_BYTES {
            label = remove_control_label_field(&label, "h");
        }
        if label.len() + suffix.len() > CONTROL_LABEL_MAX_BYTES {
            label = remove_control_label_field(&label, "c");
        }
        if label.len() + suffix.len() > CONTROL_LABEL_MAX_BYTES {
            // `f` is an additive refinement. Mapping/allocation/delta remain
            // sufficient for the conservative legacy-compatible planner.
            label = remove_control_label_field(&label, "f");
        }

        debug_assert!(
            label.len() + suffix.len() <= CONTROL_LABEL_MAX_BYTES,
            "NAT control label must fit the server cap"
        );
        format!("{label}{suffix}")
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

/// Remove exactly one complete `;key=value` field from a compact control
/// label. This is deliberately field-aware instead of byte truncation so the
/// parser either receives a valid conservative label or rejects it entirely.
fn remove_control_label_field(label: &str, key: &str) -> String {
    let needle = format!(";{key}=");
    let Some(start) = label.find(&needle) else {
        return label.to_string();
    };
    let value_start = start + needle.len();
    let end = label[value_start..]
        .find(';')
        .map(|offset| value_start + offset)
        .unwrap_or(label.len());
    let mut compact = String::with_capacity(label.len().saturating_sub(end - start));
    compact.push_str(&label[..start]);
    compact.push_str(&label[end..]);
    compact
}

/// Parsed value of the `a=` (allocation) token in a [`control_label`].
///
/// `allocation` is DERIVED in `NatProfile::control_label` (it is not stored as
/// its own enum), so the receiver parses it back into this enum rather than
/// serde. `Stable`/`Linear` correspond to the RFC 5780 names endpoint/linear
/// `port dependent`; `Random` is the symmetric case.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NatAllocation {
    #[default]
    Unknown,
    Linear,
    Stable,
    Random,
    Blocked,
}

/// Structured view of a peer `nat_type` control label
/// (`p2:`/`p2v2:m=..;a=..;d=..;c=..;f=..;h=..[;g=..][;o=..][;l=..]`).
///
/// Receiver-side counterpart to [`NatProfile::control_label`]: the daemon
/// advertises the label through the relay and the peer parses it back into
/// these fields to drive the bounded port-scatter decision. `parsed` is the
/// gate for that decision — when it is `false` (bare `"symmetric"`, empty, or
/// a corrupted label from any client) the consumer MUST fall back to the
/// legacy `.contains` classifier so behavior is byte-identical to pre-R1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatFingerprintHint {
    /// Parsed `m=` (mapping behavior), `Unknown` if absent/unrecognized.
    pub mapping: MappingBehavior,
    /// Parsed `a=` (allocation), `Unknown` if absent/unrecognized.
    pub allocation: NatAllocation,
    /// Parsed `d=` port delta, `None` if absent, `?`, or non-numeric.
    pub port_delta: Option<i32>,
    /// Parsed `c=` confidence, `None` if absent or non-numeric.
    pub confidence: Option<u8>,
    /// Parsed `f=` (filtering behavior); `Unknown` for old `p2:` labels.
    pub filtering: FilteringBehavior,
    /// Parsed `h=` (hairpin behavior); `Unknown` for old `p2:` labels.
    pub hairpin: HairpinBehavior,
    /// Parsed `g=` profile/evidence generation, if advertised.
    pub profile_generation: Option<u64>,
    /// Parsed `o=` real STUN observation sequence, if advertised.
    ///
    /// This is independent of `g=`: a stable NAT capability may receive many
    /// live observations without invalidating an established Direct session.
    pub observation_sequence: Option<u64>,
    /// Parsed `l=` server-issued registration lifecycle, if advertised.
    ///
    /// A newer lifecycle permits a producer to restart its local `g`/`o`
    /// counters; an older lifecycle must never overwrite a newer one.
    pub registration_lifecycle: Option<u64>,
    /// `true` only when a well-formed `p2:`/`p2v2:` label was recognized.
    pub parsed: bool,
    /// The trimmed, lower-cased input, retained for the legacy fallback.
    pub raw: String,
}

/// Reverse-map a `m=` token to its [`MappingBehavior`].
///
/// Accepts both the display tokens `control_label` emits AND the serde names,
/// so a future emitter that switches `m=` to serde (or that R1b-era probe
/// fills) still round-trips. The serde aliases must stay in lockstep with
/// `#[serde(rename_all = "snake_case")]`.  Returns `None` for an unrecognized
/// value: a *present* token whose value we don't know means the label is
/// corrupted, and the caller MUST fall back to the legacy classifier — it must
/// not silently read as `Unknown`, which could under-scatter relative to the
/// legacy wide-substring match (e.g. truncated `m=address_or_port_dependentX`).
fn mapping_behavior_from_token(token: &str) -> Option<MappingBehavior> {
    match token {
        "unknown" => Some(MappingBehavior::Unknown),
        "blocked" | "udp_blocked" => Some(MappingBehavior::UdpBlocked),
        "open" | "open_internet" => Some(MappingBehavior::OpenInternet),
        "endpoint_independent" => Some(MappingBehavior::EndpointIndependent),
        "address_or_port_dependent" => Some(MappingBehavior::AddressOrPortDependent),
        _ => None,
    }
}

/// Reverse-map an `a=` token to its [`NatAllocation`].
///
/// Returns `None` for an unrecognized value (see `mapping_behavior_from_token`
/// for why a bad value must fall back to legacy rather than read as Unknown).
fn allocation_from_token(token: &str) -> Option<NatAllocation> {
    match token {
        "unknown" => Some(NatAllocation::Unknown),
        "linear" => Some(NatAllocation::Linear),
        "stable" => Some(NatAllocation::Stable),
        "random" => Some(NatAllocation::Random),
        "blocked" => Some(NatAllocation::Blocked),
        _ => None,
    }
}

/// Reverse-map an `f=` token to its [`FilteringBehavior`].
///
/// `f=` uses serde names end-to-end (no separate display token), so accept the
/// six serde variants and return `None` for anything else.
fn filtering_behavior_from_token(token: &str) -> Option<FilteringBehavior> {
    match token {
        "unknown" => Some(FilteringBehavior::Unknown),
        "endpoint_independent" => Some(FilteringBehavior::EndpointIndependent),
        "likely_endpoint_independent" => Some(FilteringBehavior::LikelyEndpointIndependent),
        "address_dependent" => Some(FilteringBehavior::AddressDependent),
        "address_or_port_dependent" => Some(FilteringBehavior::AddressOrPortDependent),
        "udp_blocked" => Some(FilteringBehavior::UdpBlocked),
        _ => None,
    }
}

/// Reverse-map an `h=` token to its [`HairpinBehavior`].
fn hairpin_behavior_from_token(token: &str) -> Option<HairpinBehavior> {
    match token {
        "unknown" => Some(HairpinBehavior::Unknown),
        "supported" => Some(HairpinBehavior::Supported),
        "unsupported" => Some(HairpinBehavior::Unsupported),
        "not_applicable" => Some(HairpinBehavior::NotApplicable),
        _ => None,
    }
}

/// Parse a peer `nat_type` control label into a [`NatFingerprintHint`].
///
/// Prefix-agnostic: both legacy `p2:` and the R1 `p2v2:` label parse. Missing
/// `f=`/`h=` tokens (i.e. any `p2:` label) become `Unknown`, so a new client
/// consuming an old label reproduces the pre-R1 decision exactly. Any input
/// that does not start with `p2:`/`p2v2:` (bare words, empty, corrupted)
/// yields `parsed == false` and the caller falls back to the legacy
/// classifier. Pure: no I/O, no panic on malformed input.
pub fn parse_nat_hint(input: &str) -> NatFingerprintHint {
    let raw = input.trim().to_ascii_lowercase();
    let Some(payload) = raw
        .strip_prefix("p2v2:")
        .or_else(|| raw.strip_prefix("p2:"))
    else {
        return unparsed_hint(&raw);
    };
    // A well-formed label is one or more `key=value` fields joined by `;`,
    // each with a recognized key (m/a/d/c/f/h/g/o/l) AND a recognized value
    // (d/c numeric where applicable).  Being strict here is the conservative
    // direction: any malformed segment (no `=`), unrecognized key, or bad
    // value yields `parsed == false` and the caller falls back to the legacy
    // `.contains` classifier — which is always a safe superset.  The failure
    // mode of over-strictness is merely "under-use the structured path",
    // never a behavior change from legacy.  (A present-but-unrecognized
    // `m=`/`f=` value in particular must NOT read as `Unknown`: that could
    // under-scatter relative to the legacy wide-substring match on a
    // truncated token.)
    let mut mapping = MappingBehavior::Unknown;
    let mut allocation = NatAllocation::Unknown;
    let mut port_delta: Option<i32> = None;
    let mut confidence: Option<u8> = None;
    let mut filtering = FilteringBehavior::Unknown;
    let mut hairpin = HairpinBehavior::Unknown;
    let mut profile_generation: Option<u64> = None;
    let mut observation_sequence: Option<u64> = None;
    let mut registration_lifecycle: Option<u64> = None;
    let mut fields = 0u8;
    for field in payload.split(';') {
        if field.is_empty() {
            continue; // tolerate stray/leading/trailing `;`
        }
        let Some((key, value)) = field.split_once('=') else {
            return unparsed_hint(&raw);
        };
        match key {
            "m" => {
                mapping = match mapping_behavior_from_token(value) {
                    Some(mb) => mb,
                    None => return unparsed_hint(&raw),
                };
                fields += 1;
            }
            "a" => {
                allocation = match allocation_from_token(value) {
                    Some(a) => a,
                    None => return unparsed_hint(&raw),
                };
                fields += 1;
            }
            "d" => {
                // `control_label` emits `d=?` when there is no port delta, and
                // a signed allocation stride otherwise. Reverse allocators must
                // preserve the entire label, including generation/lifecycle fences.
                port_delta = if value == "?" {
                    None
                } else {
                    match value.parse::<i32>() {
                        Ok(d) => Some(d),
                        _ => return unparsed_hint(&raw),
                    }
                };
                fields += 1;
            }
            "c" => {
                // `confidence` is 0-100; out-of-range or non-numeric is
                // treated as corruption → legacy fallback.
                match value.parse::<u8>() {
                    Ok(c) => confidence = Some(c),
                    _ => return unparsed_hint(&raw),
                }
                fields += 1;
            }
            "f" => {
                filtering = match filtering_behavior_from_token(value) {
                    Some(fb) => fb,
                    None => return unparsed_hint(&raw),
                };
                fields += 1;
            }
            "h" => {
                hairpin = match hairpin_behavior_from_token(value) {
                    Some(h) => h,
                    None => return unparsed_hint(&raw),
                };
                fields += 1;
            }
            "g" => {
                profile_generation = match value.parse::<u64>() {
                    Ok(generation) => Some(generation),
                    Err(_) => return unparsed_hint(&raw),
                };
                fields += 1;
            }
            "o" => {
                observation_sequence = match value.parse::<u64>() {
                    Ok(observation) => Some(observation),
                    Err(_) => return unparsed_hint(&raw),
                };
                fields += 1;
            }
            "l" => {
                registration_lifecycle = match value.parse::<u64>() {
                    Ok(lifecycle) => Some(lifecycle),
                    Err(_) => return unparsed_hint(&raw),
                };
                fields += 1;
            }
            _ => return unparsed_hint(&raw), // unrecognized key → corrupted
        }
    }
    if fields == 0 {
        return unparsed_hint(&raw);
    }
    NatFingerprintHint {
        mapping,
        allocation,
        port_delta,
        confidence,
        filtering,
        hairpin,
        profile_generation,
        observation_sequence,
        registration_lifecycle,
        parsed: true,
        raw,
    }
}

/// Build a `parsed == false` hint: no structured fields were recovered, so the
/// consumer falls back to the legacy classifier on `raw`.
fn unparsed_hint(raw: &str) -> NatFingerprintHint {
    NatFingerprintHint {
        mapping: MappingBehavior::Unknown,
        allocation: NatAllocation::Unknown,
        port_delta: None,
        confidence: None,
        filtering: FilteringBehavior::Unknown,
        hairpin: HairpinBehavior::Unknown,
        profile_generation: None,
        observation_sequence: None,
        registration_lifecycle: None,
        parsed: false,
        raw: raw.to_string(),
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
