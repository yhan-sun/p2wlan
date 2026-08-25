//! Authoritative NAT capabilities and pairwise traversal planning.
//!
//! This module is deliberately a pure decision layer.  It consumes measured
//! NAT evidence and a small amount of already-proven path context, then emits
//! an explainable traversal strategy.  It does not bind sockets, run STUN,
//! schedule probes, manage peer connections, or select an already-validated
//! data path.  Those responsibilities stay with the existing UDP runtime and
//! `PathSelector`.

use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::ice::{
    FilteringBehavior, HairpinBehavior, LocalNetwork, MappingBehavior, NatAllocation,
    NatFingerprintHint, NatProfile,
};
use crate::mapping::{
    infer_allocation_model, AllocationModelKind, MappingObservation, ModelRejection, PortModelKind,
};

/// The network type is an operational hint, never NAT truth.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkHint {
    #[default]
    Unknown,
    Ethernet,
    Wifi,
    Cellular,
}

impl NetworkHint {
    pub const fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Ethernet => "ethernet",
            Self::Wifi => "wifi",
            Self::Cellular => "cellular",
        }
    }
}

/// Measured NAT behavior used by the planner.
///
/// `NatType` and the legacy `nat_type` string remain display/compatibility
/// surfaces.  This structure is the authoritative input for new traversal
/// decisions.  In particular, address+port-dependent mapping is not itself a
/// proof that P2P is impossible: the allocation model and its confidence are
/// separate fields.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatCapabilities {
    pub mapping_behavior: MappingBehavior,
    pub filtering_behavior: FilteringBehavior,
    /// Reuses the existing mapping learner model. `None` means the allocation
    /// behavior was not measured; `Unpredictable` is an explicit measured
    /// result and is not the same as unknown.
    #[serde(default)]
    pub allocation_model: Option<PortModelKind>,
    pub public_ip_stable: Option<bool>,
    pub public_port_stable: Option<bool>,
    /// A public endpoint already known to be usable for this peer role.
    #[serde(default)]
    pub stable_public_endpoint: Option<String>,
    #[serde(default)]
    pub prediction_candidate: bool,
    #[serde(default)]
    pub prediction_confidence: u8,
    #[serde(default)]
    pub prediction_window: usize,
    #[serde(default)]
    pub birthday_candidate: bool,
    #[serde(default)]
    pub hairpin_behavior: HairpinBehavior,
    #[serde(default)]
    pub udp_blocked: bool,
    /// The old label is retained for diagnostics only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_nat_type: Option<String>,
    /// Generation owned by the daemon that produced this profile.  It is not
    /// `remote_candidate_epoch`; the latter fences actual Direct proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_generation: Option<u64>,
}

impl NatCapabilities {
    /// Convert the currently measured local profile without changing the
    /// profile's wire-compatible shape.
    pub fn from_profile(profile: &NatProfile) -> Self {
        let allocation_model = allocation_model_from_profile(profile);
        Self {
            mapping_behavior: profile.mapping_behavior,
            filtering_behavior: profile.filtering_behavior,
            allocation_model,
            public_ip_stable: profile.public_ip_stable,
            public_port_stable: profile.public_port_stable,
            stable_public_endpoint: stable_endpoint_from_profile(profile),
            prediction_candidate: profile.prediction_candidate,
            prediction_confidence: profile.confidence,
            prediction_window: profile.predicted_endpoints.len(),
            birthday_candidate: profile.birthday_candidate,
            hairpin_behavior: profile.hairpin_behavior,
            udp_blocked: profile.udp_blocked,
            legacy_nat_type: None,
            profile_generation: None,
        }
    }

    /// Convert a structured peer label. Endpoint evidence is supplied by the
    /// existing peer metadata/candidate path rather than fabricated here.
    pub fn from_fingerprint_hint(
        hint: &NatFingerprintHint,
        stable_public_endpoint: Option<SocketAddr>,
    ) -> Self {
        let allocation_model = allocation_model_from_hint(hint);
        let udp_blocked = hint.mapping == MappingBehavior::UdpBlocked
            || hint.filtering == FilteringBehavior::UdpBlocked
            || hint.allocation == NatAllocation::Blocked;
        Self {
            mapping_behavior: hint.mapping,
            filtering_behavior: hint.filtering,
            allocation_model,
            public_ip_stable: stable_public_endpoint.map(|_| true),
            public_port_stable: stable_public_endpoint.map(|_| true),
            stable_public_endpoint: stable_public_endpoint.map(|endpoint| endpoint.to_string()),
            prediction_candidate: matches!(hint.allocation, NatAllocation::Linear),
            prediction_confidence: hint.confidence.unwrap_or_default(),
            // The compact control label intentionally does not carry the full
            // candidate window. A non-zero value records that prediction is
            // available without pretending to know its width.
            prediction_window: usize::from(matches!(hint.allocation, NatAllocation::Linear)),
            birthday_candidate: hint.mapping == MappingBehavior::AddressOrPortDependent
                && matches!(
                    hint.allocation,
                    NatAllocation::Random | NatAllocation::Linear | NatAllocation::Unknown
                ),
            hairpin_behavior: hint.hairpin,
            udp_blocked,
            legacy_nat_type: Some(hint.raw.clone()),
            profile_generation: hint.profile_generation,
        }
    }

    pub fn is_hard_nat(&self) -> bool {
        !self.udp_blocked && self.mapping_behavior == MappingBehavior::AddressOrPortDependent
    }

    pub fn is_stable_endpoint(&self) -> bool {
        !self.udp_blocked
            && self.stable_public_endpoint.is_some()
            && self.mapping_behavior != MappingBehavior::Unknown
            && self.mapping_behavior != MappingBehavior::AddressOrPortDependent
    }

    pub fn allocation_is_predictable(&self) -> bool {
        self.allocation_model
            .as_ref()
            .is_some_and(|model| model.clone().is_predictable())
    }

    pub fn hard_allocation_is_predictable(&self) -> bool {
        self.is_hard_nat()
            && self.prediction_candidate
            && self.prediction_confidence >= MIN_PREDICTION_CONFIDENCE
            && self.allocation_is_predictable()
    }

    pub fn hard_allocation_is_unpredictable(&self) -> bool {
        self.is_hard_nat()
            && self
                .allocation_model
                .as_ref()
                .is_some_and(|model| matches!(model, PortModelKind::Unpredictable { .. }))
    }

    pub fn udp_filtering_allows_attempt(&self) -> bool {
        !self.udp_blocked && self.filtering_behavior != FilteringBehavior::UdpBlocked
    }

    pub fn with_profile_generation(mut self, generation: u64) -> Self {
        self.profile_generation = Some(generation);
        self
    }
}

/// Minimum confidence for treating a hard-NAT allocation model as a planned
/// direct attempt. Lower-confidence models remain useful as bounded
/// speculative evidence, but are not called deterministic.
pub const MIN_PREDICTION_CONFIDENCE: u8 = 60;

fn stable_endpoint_from_profile(profile: &NatProfile) -> Option<String> {
    let endpoint = profile.public_endpoint.clone()?;
    let stable_ip = profile.public_ip_stable != Some(false);
    let stable_port = profile.public_port_stable != Some(false)
        || matches!(
            profile.mapping_behavior,
            MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
        );
    (stable_ip && stable_port).then_some(endpoint)
}

fn allocation_model_from_profile(profile: &NatProfile) -> Option<PortModelKind> {
    if profile.udp_blocked {
        return None;
    }
    if matches!(
        profile.mapping_behavior,
        MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
    ) {
        return Some(PortModelKind::Stable);
    }
    let local_endpoint = profile
        .local_addr
        .parse::<SocketAddr>()
        .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("valid fallback endpoint"));
    let observations = profile
        .observations
        .iter()
        .enumerate()
        .filter_map(|(sequence, observation)| {
            let observed = observation.mapped_address.as_deref()?.parse().ok()?;
            let observer = observation
                .server
                .parse()
                .unwrap_or_else(|_| "0.0.0.0:0".parse().expect("valid fallback observer"));
            Some(MappingObservation {
                sequence: sequence as u16,
                observer,
                observed,
                sent_at_ms: sequence as u64,
                responded_at_ms: sequence as u64 + 1,
                local_endpoint,
            })
        })
        .collect::<Vec<_>>();
    match infer_allocation_model(&observations).kind {
        AllocationModelKind::Stable => Some(PortModelKind::Stable),
        AllocationModelKind::FixedStep { step } => Some(PortModelKind::FixedStep { step }),
        AllocationModelKind::SmallWindow { direction, .. } => {
            Some(PortModelKind::MonotonicWindow { direction })
        }
        AllocationModelKind::HighEntropy => Some(PortModelKind::Unpredictable {
            reason: ModelRejection::NarrowRandom,
        }),
        AllocationModelKind::Unknown
            if (observations.is_empty() || observations.len() >= 3)
                && profile.prediction_candidate
                && profile.port_delta.is_some()
                && !profile.predicted_endpoints.is_empty() =>
        {
            profile.port_delta.map(|delta| PortModelKind::FixedStep {
                step: delta.clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
            })
        }
        AllocationModelKind::Unknown => None,
    }
}

fn allocation_model_from_hint(hint: &NatFingerprintHint) -> Option<PortModelKind> {
    match hint.allocation {
        NatAllocation::Stable => Some(PortModelKind::Stable),
        NatAllocation::Linear => Some(PortModelKind::FixedStep {
            step: hint
                .port_delta
                .unwrap_or(1)
                .clamp(i32::from(i16::MIN), i32::from(i16::MAX)) as i16,
        }),
        NatAllocation::Random => Some(PortModelKind::Unpredictable {
            reason: ModelRejection::NoConsistentStep,
        }),
        NatAllocation::Blocked | NatAllocation::Unknown => None,
    }
}

/// A small, serializable freshness envelope for local or remote profile
/// evidence. The generation belongs to the profile producer, while the
/// receive timestamp belongs to this process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatProfileEvidence {
    pub capabilities: NatCapabilities,
    pub generation: u64,
    pub observed_at_ms: u64,
}

impl NatProfileEvidence {
    pub fn is_fresh_for(&self, generation: u64, now_ms: u64, max_age: Duration) -> bool {
        self.generation == generation
            && now_ms >= self.observed_at_ms
            && now_ms.saturating_sub(self.observed_at_ms) <= max_age.as_millis() as u64
    }
}

/// Remote profile state after it crossed the compatibility signaling path.
/// A missing generation is intentionally not authoritative, even though the
/// parsed legacy fields remain useful for diagnostics and safe generic tries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteNatProfile {
    pub capabilities: NatCapabilities,
    pub generation: Option<u64>,
    pub received_at_ms: u64,
}

impl RemoteNatProfile {
    pub fn is_fresh(&self, now_ms: u64, max_age: Duration) -> bool {
        self.generation.is_some()
            && now_ms >= self.received_at_ms
            && now_ms.saturating_sub(self.received_at_ms) <= max_age.as_millis() as u64
    }
}

/// The minimum context needed by the pure planner. All evidence here is
/// computed by existing gathering/connection code; the planner only consumes
/// the booleans and never rediscovers interfaces or candidates itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalContext {
    pub on_link_lan: bool,
    pub global_ipv6_direct_available: bool,
    pub peer_reflexive_evidence: bool,
    pub learned_endpoint_evidence: bool,
    pub local_stable_endpoint_available: bool,
    pub remote_stable_endpoint_available: bool,
    pub fresh_mapping_available: bool,
    pub remote_profile_fresh: bool,
    pub relay_available: bool,
    pub bounded_birthday_allowed: bool,
    pub network_hint: NetworkHint,
}

impl Default for TraversalContext {
    fn default() -> Self {
        Self {
            on_link_lan: false,
            global_ipv6_direct_available: false,
            peer_reflexive_evidence: false,
            learned_endpoint_evidence: false,
            local_stable_endpoint_available: false,
            remote_stable_endpoint_available: false,
            fresh_mapping_available: false,
            // A caller that has a profile but cannot establish freshness must
            // explicitly set this false. This keeps the pure API convenient
            // while preserving a fail-safe integration path.
            remote_profile_fresh: true,
            relay_available: true,
            bounded_birthday_allowed: true,
            network_hint: NetworkHint::Unknown,
        }
    }
}

/// Check an already-proven on-link relation using the repository's existing
/// `LocalNetwork` prefix matcher. This helper does not classify private IPs as
/// LAN; an interface proof is required.
pub fn confirmed_on_link_lan(
    local_networks: &[LocalNetwork],
    remote_candidates: &[SocketAddr],
) -> bool {
    remote_candidates.iter().any(|remote| {
        local_networks
            .iter()
            .any(|network| network.contains(remote.ip()))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalCapability {
    DirectLikely,
    DirectPossible,
    DirectSpeculative,
    RelayPreferred,
    RelayRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalStrategy {
    LanFastPath,
    Ipv6Direct,
    AuthenticatedPeerReflexive,
    StandardUdpPunch,
    StablePeerAnchoredFreshMapping,
    PredictivePunch,
    HardHardSynchronizedCandidate,
    BirthdaySpeculative,
    RelayWithBackgroundReclaim,
    RelayOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalFallback {
    Relay,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TraversalReason {
    ConfirmedOnLinkLan,
    GlobalIpv6Evidence,
    AuthenticatedPeerEvidence,
    UdpBlocked,
    EasyUdpBothSides,
    HardPredictableLocalStableRemote,
    StableLocalHardPredictableRemote,
    BothPredictableHardNat,
    HardHardBoundedBirthday,
    MixedHardNatBoundedSpeculation,
    BothUnpredictableHardNat,
    HardNatWithoutBoundedEvidence,
    UnknownRemoteProfile,
    UnknownCapabilitiesSafeAttempt,
}

impl TraversalReason {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ConfirmedOnLinkLan => "confirmed_on_link_lan",
            Self::GlobalIpv6Evidence => "global_ipv6_evidence",
            Self::AuthenticatedPeerEvidence => "authenticated_peer_evidence",
            Self::UdpBlocked => "udp_blocked",
            Self::EasyUdpBothSides => "easy_udp_both_sides",
            Self::HardPredictableLocalStableRemote => "local_predictable_hard_remote_stable",
            Self::StableLocalHardPredictableRemote => "local_stable_remote_predictable_hard",
            Self::BothPredictableHardNat => "both_predictable_hard_nat",
            Self::HardHardBoundedBirthday => "hard_hard_bounded_birthday",
            Self::MixedHardNatBoundedSpeculation => "mixed_hard_nat_bounded_speculation",
            Self::BothUnpredictableHardNat => "both_unpredictable_hard_nat",
            Self::HardNatWithoutBoundedEvidence => "hard_nat_without_bounded_evidence",
            Self::UnknownRemoteProfile => "unknown_or_stale_remote_profile",
            Self::UnknownCapabilitiesSafeAttempt => "unknown_capabilities_safe_attempt",
        }
    }
}

/// Deterministic output of [`plan_traversal`]. `strategy` is an attempt plan,
/// not an active path decision. The already-validated path remains owned by
/// the existing selector/handover state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraversalPlan {
    pub strategy: TraversalStrategy,
    pub capability: TraversalCapability,
    pub attempts: Vec<TraversalStrategy>,
    pub fallback: TraversalFallback,
    pub background_reclaim: bool,
    pub reason: String,
    pub reason_code: TraversalReason,
    pub relay_available: bool,
    pub remote_profile_fresh: bool,
    pub network_hint: NetworkHint,
}

impl TraversalPlan {
    pub fn fallback_label(&self) -> &'static str {
        match self.fallback {
            TraversalFallback::Relay => "relay",
            TraversalFallback::None => "none",
        }
    }

    pub fn strategy_label(&self) -> &'static str {
        strategy_label(self.strategy)
    }
}

fn strategy_label(strategy: TraversalStrategy) -> &'static str {
    match strategy {
        TraversalStrategy::LanFastPath => "lan_fast_path",
        TraversalStrategy::Ipv6Direct => "ipv6_direct",
        TraversalStrategy::AuthenticatedPeerReflexive => "authenticated_peer_reflexive",
        TraversalStrategy::StandardUdpPunch => "standard_udp_punch",
        TraversalStrategy::StablePeerAnchoredFreshMapping => "stable_peer_anchored_fresh_mapping",
        TraversalStrategy::PredictivePunch => "predictive_punch",
        TraversalStrategy::HardHardSynchronizedCandidate => "hard_hard_synchronized_candidate",
        TraversalStrategy::BirthdaySpeculative => "birthday_speculative",
        TraversalStrategy::RelayWithBackgroundReclaim => "relay_with_background_reclaim",
        TraversalStrategy::RelayOnly => "relay_only",
    }
}

fn plan(
    strategy: TraversalStrategy,
    capability: TraversalCapability,
    attempts: Vec<TraversalStrategy>,
    reason_code: TraversalReason,
    context: &TraversalContext,
    background_reclaim: bool,
) -> TraversalPlan {
    let direct_attempt = !matches!(
        strategy,
        TraversalStrategy::RelayOnly | TraversalStrategy::RelayWithBackgroundReclaim
    );
    TraversalPlan {
        strategy,
        capability,
        attempts,
        fallback: if direct_attempt && context.relay_available {
            TraversalFallback::Relay
        } else {
            TraversalFallback::None
        },
        background_reclaim,
        reason: reason_code.code().to_string(),
        reason_code,
        relay_available: context.relay_available,
        remote_profile_fresh: context.remote_profile_fresh,
        network_hint: context.network_hint,
    }
}

/// Plan the bounded traversal strategies for one peer pair.
///
/// The ordering is evidence-first: on-link LAN, proven IPv6, authenticated
/// learned evidence, easy UDP, hard↔stable fresh mapping, predictable
/// hard↔hard candidate, then bounded speculation/relay. No branch claims that
/// a packet scheduler exists for `HardHardSynchronizedCandidate`.
pub fn plan_traversal(
    local: &NatCapabilities,
    remote: &NatCapabilities,
    context: &TraversalContext,
) -> TraversalPlan {
    let stale_remote = !context.remote_profile_fresh;
    let remote_for_decision = if stale_remote {
        NatCapabilities::default()
    } else {
        remote.clone()
    };

    if context.on_link_lan {
        return plan(
            TraversalStrategy::LanFastPath,
            TraversalCapability::DirectLikely,
            vec![TraversalStrategy::LanFastPath],
            TraversalReason::ConfirmedOnLinkLan,
            context,
            false,
        );
    }

    if context.global_ipv6_direct_available {
        return plan(
            TraversalStrategy::Ipv6Direct,
            TraversalCapability::DirectLikely,
            vec![TraversalStrategy::Ipv6Direct],
            TraversalReason::GlobalIpv6Evidence,
            context,
            false,
        );
    }

    if context.peer_reflexive_evidence || context.learned_endpoint_evidence {
        return plan(
            TraversalStrategy::AuthenticatedPeerReflexive,
            TraversalCapability::DirectLikely,
            vec![TraversalStrategy::AuthenticatedPeerReflexive],
            TraversalReason::AuthenticatedPeerEvidence,
            context,
            false,
        );
    }

    if local.udp_blocked || remote_for_decision.udp_blocked {
        return plan(
            TraversalStrategy::RelayOnly,
            TraversalCapability::RelayRequired,
            vec![TraversalStrategy::RelayOnly],
            TraversalReason::UdpBlocked,
            context,
            false,
        );
    }

    // A delayed or generation-mismatched remote profile must not authorize a
    // hard-NAT strategy.  Keep the attempt conservative while the normal
    // candidate exchange refreshes the peer evidence.
    if stale_remote {
        return plan(
            TraversalStrategy::StandardUdpPunch,
            TraversalCapability::DirectSpeculative,
            vec![TraversalStrategy::StandardUdpPunch],
            TraversalReason::UnknownRemoteProfile,
            context,
            false,
        );
    }

    let local_hard = local.is_hard_nat();
    let remote_hard = remote_for_decision.is_hard_nat();
    let local_predictable = local.hard_allocation_is_predictable();
    let remote_predictable = remote_for_decision.hard_allocation_is_predictable();
    let local_stable = local.is_stable_endpoint() || context.local_stable_endpoint_available;
    let remote_stable =
        remote_for_decision.is_stable_endpoint() || context.remote_stable_endpoint_available;

    if local_hard && remote_hard && local_predictable && remote_predictable {
        return plan(
            TraversalStrategy::HardHardSynchronizedCandidate,
            TraversalCapability::DirectSpeculative,
            vec![TraversalStrategy::HardHardSynchronizedCandidate],
            TraversalReason::BothPredictableHardNat,
            context,
            true,
        );
    }

    if local_hard && local_predictable && remote_stable {
        let mut attempts = vec![TraversalStrategy::StablePeerAnchoredFreshMapping];
        if local.prediction_candidate {
            attempts.push(TraversalStrategy::PredictivePunch);
        }
        return plan(
            TraversalStrategy::StablePeerAnchoredFreshMapping,
            TraversalCapability::DirectPossible,
            attempts,
            TraversalReason::HardPredictableLocalStableRemote,
            context,
            true,
        );
    }

    if remote_hard && remote_predictable && local_stable {
        let mut attempts = vec![TraversalStrategy::StablePeerAnchoredFreshMapping];
        if remote_for_decision.prediction_candidate {
            attempts.push(TraversalStrategy::PredictivePunch);
        }
        return plan(
            TraversalStrategy::StablePeerAnchoredFreshMapping,
            TraversalCapability::DirectPossible,
            attempts,
            TraversalReason::StableLocalHardPredictableRemote,
            context,
            true,
        );
    }

    if local_hard && remote_hard {
        if local_predictable && remote_predictable {
            return plan(
                TraversalStrategy::HardHardSynchronizedCandidate,
                TraversalCapability::DirectSpeculative,
                vec![TraversalStrategy::HardHardSynchronizedCandidate],
                TraversalReason::BothPredictableHardNat,
                context,
                true,
            );
        }
        let bounded = context.bounded_birthday_allowed
            && (local.birthday_candidate || remote_for_decision.birthday_candidate);
        if bounded {
            return plan(
                TraversalStrategy::HardHardSynchronizedCandidate,
                TraversalCapability::DirectSpeculative,
                vec![TraversalStrategy::HardHardSynchronizedCandidate],
                TraversalReason::HardHardBoundedBirthday,
                context,
                true,
            );
        }
        if !local_predictable && !remote_predictable {
            return plan(
                TraversalStrategy::RelayWithBackgroundReclaim,
                TraversalCapability::RelayPreferred,
                vec![TraversalStrategy::RelayWithBackgroundReclaim],
                TraversalReason::BothUnpredictableHardNat,
                context,
                true,
            );
        }
        return plan(
            TraversalStrategy::RelayWithBackgroundReclaim,
            TraversalCapability::RelayPreferred,
            vec![TraversalStrategy::RelayWithBackgroundReclaim],
            TraversalReason::HardNatWithoutBoundedEvidence,
            context,
            true,
        );
    }

    if context.bounded_birthday_allowed
        && ((local_hard && local.birthday_candidate)
            || (remote_hard && remote_for_decision.birthday_candidate))
    {
        return plan(
            TraversalStrategy::BirthdaySpeculative,
            TraversalCapability::DirectSpeculative,
            vec![TraversalStrategy::BirthdaySpeculative],
            TraversalReason::MixedHardNatBoundedSpeculation,
            context,
            true,
        );
    }

    let local_easy = local.udp_filtering_allows_attempt()
        && matches!(
            local.mapping_behavior,
            MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
        );
    let remote_easy = remote_for_decision.udp_filtering_allows_attempt()
        && matches!(
            remote_for_decision.mapping_behavior,
            MappingBehavior::OpenInternet | MappingBehavior::EndpointIndependent
        );

    if local_easy && remote_easy {
        return plan(
            TraversalStrategy::StandardUdpPunch,
            TraversalCapability::DirectLikely,
            vec![TraversalStrategy::StandardUdpPunch],
            TraversalReason::EasyUdpBothSides,
            context,
            false,
        );
    }

    plan(
        TraversalStrategy::StandardUdpPunch,
        TraversalCapability::DirectPossible,
        vec![TraversalStrategy::StandardUdpPunch],
        TraversalReason::UnknownCapabilitiesSafeAttempt,
        context,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ice::{MappingLifetime, StunObservation};

    fn caps(
        mapping: MappingBehavior,
        allocation_model: Option<PortModelKind>,
        prediction_candidate: bool,
        confidence: u8,
        stable_endpoint: Option<&str>,
        birthday_candidate: bool,
    ) -> NatCapabilities {
        NatCapabilities {
            mapping_behavior: mapping,
            filtering_behavior: FilteringBehavior::EndpointIndependent,
            allocation_model,
            public_ip_stable: stable_endpoint.map(|_| true),
            public_port_stable: stable_endpoint.map(|_| true),
            stable_public_endpoint: stable_endpoint.map(str::to_string),
            prediction_candidate,
            prediction_confidence: confidence,
            prediction_window: usize::from(prediction_candidate),
            birthday_candidate,
            hairpin_behavior: HairpinBehavior::Unknown,
            udp_blocked: false,
            legacy_nat_type: None,
            profile_generation: Some(7),
        }
    }

    fn easy(endpoint: Option<&str>) -> NatCapabilities {
        caps(
            MappingBehavior::EndpointIndependent,
            Some(PortModelKind::Stable),
            false,
            90,
            endpoint,
            false,
        )
    }

    fn predictable_hard(endpoint: Option<&str>) -> NatCapabilities {
        caps(
            MappingBehavior::AddressOrPortDependent,
            Some(PortModelKind::FixedStep { step: 4 }),
            true,
            90,
            endpoint,
            true,
        )
    }

    fn random_hard() -> NatCapabilities {
        caps(
            MappingBehavior::AddressOrPortDependent,
            Some(PortModelKind::Unpredictable {
                reason: ModelRejection::NoConsistentStep,
            }),
            false,
            20,
            None,
            true,
        )
    }

    #[test]
    fn same_lan_uses_existing_on_link_proof_only() {
        let networks = [LocalNetwork::new("192.168.31.10".parse().unwrap(), 24)];
        assert!(confirmed_on_link_lan(
            &networks,
            &["192.168.31.20:51820".parse().unwrap()]
        ));
        assert!(!confirmed_on_link_lan(
            &networks,
            &["192.168.50.20:51820".parse().unwrap()]
        ));
        let plan = plan_traversal(
            &easy(Some("203.0.113.10:40000")),
            &easy(Some("203.0.113.11:40000")),
            &TraversalContext {
                on_link_lan: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.strategy, TraversalStrategy::LanFastPath);
    }

    #[test]
    fn easy_easy_is_standard_udp_punch() {
        let plan = plan_traversal(&easy(None), &easy(None), &TraversalContext::default());
        assert_eq!(plan.strategy, TraversalStrategy::StandardUdpPunch);
        assert_eq!(plan.capability, TraversalCapability::DirectLikely);
    }

    #[test]
    fn hard_predictable_and_stable_is_direction_symmetric() {
        let context = TraversalContext {
            remote_stable_endpoint_available: true,
            local_stable_endpoint_available: true,
            ..Default::default()
        };
        let first = plan_traversal(
            &predictable_hard(None),
            &easy(Some("203.0.113.11:40000")),
            &context,
        );
        let reverse = plan_traversal(
            &easy(Some("203.0.113.11:40000")),
            &predictable_hard(None),
            &context,
        );
        assert_eq!(
            first.strategy,
            TraversalStrategy::StablePeerAnchoredFreshMapping
        );
        assert_eq!(first.strategy, reverse.strategy);
        assert!(first.attempts.contains(&TraversalStrategy::PredictivePunch));
    }

    #[test]
    fn legacy_symmetric_label_does_not_override_predictable_capability() {
        let mut air = predictable_hard(None);
        air.legacy_nat_type = Some("symmetric".to_string());
        let plan = plan_traversal(
            &air,
            &easy(Some("203.0.113.11:40000")),
            &TraversalContext {
                remote_stable_endpoint_available: true,
                ..Default::default()
            },
        );
        assert_eq!(
            plan.strategy,
            TraversalStrategy::StablePeerAnchoredFreshMapping
        );
        assert_ne!(plan.strategy, TraversalStrategy::RelayOnly);
    }

    #[test]
    fn predictable_hard_pair_is_phase_two_candidate_not_relay_only() {
        let plan = plan_traversal(
            &predictable_hard(None),
            &predictable_hard(None),
            &TraversalContext::default(),
        );
        assert_eq!(
            plan.strategy,
            TraversalStrategy::HardHardSynchronizedCandidate
        );
        assert_eq!(plan.fallback, TraversalFallback::Relay);
        assert_eq!(plan.capability, TraversalCapability::DirectSpeculative);
    }

    #[test]
    fn random_hard_pair_uses_bounded_hard_hard_rendezvous() {
        let plan = plan_traversal(&random_hard(), &random_hard(), &TraversalContext::default());
        assert_eq!(
            plan.strategy,
            TraversalStrategy::HardHardSynchronizedCandidate
        );
        assert_eq!(plan.reason_code, TraversalReason::HardHardBoundedBirthday);
        assert_eq!(plan.capability, TraversalCapability::DirectSpeculative);
    }

    #[test]
    fn mixed_random_and_predictable_hard_uses_same_hard_hard_rendezvous() {
        let plan = plan_traversal(
            &random_hard(),
            &predictable_hard(None),
            &TraversalContext::default(),
        );
        assert_eq!(
            plan.strategy,
            TraversalStrategy::HardHardSynchronizedCandidate
        );
        assert_eq!(plan.fallback, TraversalFallback::Relay);
    }

    #[test]
    fn stale_remote_profile_is_not_used_as_authoritative_hard_truth() {
        let plan = plan_traversal(
            &predictable_hard(None),
            &easy(Some("203.0.113.11:40000")),
            &TraversalContext {
                remote_profile_fresh: false,
                ..Default::default()
            },
        );
        assert_eq!(plan.strategy, TraversalStrategy::StandardUdpPunch);
        assert_eq!(plan.reason_code, TraversalReason::UnknownRemoteProfile);
        assert_eq!(plan.capability, TraversalCapability::DirectSpeculative);
    }

    #[test]
    fn cellular_hint_does_not_change_an_easy_nat_plan() {
        let wifi = plan_traversal(
            &easy(None),
            &easy(None),
            &TraversalContext {
                network_hint: NetworkHint::Wifi,
                ..Default::default()
            },
        );
        let cellular = plan_traversal(
            &easy(None),
            &easy(None),
            &TraversalContext {
                network_hint: NetworkHint::Cellular,
                ..Default::default()
            },
        );
        assert_eq!(wifi.strategy, cellular.strategy);
        assert_eq!(wifi.capability, cellular.capability);
    }

    #[test]
    fn unknown_is_a_safe_attempt_with_relay_fallback() {
        let plan = plan_traversal(
            &NatCapabilities::default(),
            &easy(Some("203.0.113.11:40000")),
            &TraversalContext::default(),
        );
        assert_eq!(plan.strategy, TraversalStrategy::StandardUdpPunch);
        assert_eq!(plan.fallback, TraversalFallback::Relay);

        let no_relay = plan_traversal(
            &NatCapabilities::default(),
            &easy(Some("203.0.113.11:40000")),
            &TraversalContext {
                relay_available: false,
                ..Default::default()
            },
        );
        assert_eq!(no_relay.strategy, TraversalStrategy::StandardUdpPunch);
        assert_eq!(no_relay.fallback, TraversalFallback::None);
    }

    #[test]
    fn authenticated_evidence_precedes_nat_guess() {
        let plan = plan_traversal(
            &random_hard(),
            &random_hard(),
            &TraversalContext {
                peer_reflexive_evidence: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.strategy, TraversalStrategy::AuthenticatedPeerReflexive);
        assert_eq!(plan.capability, TraversalCapability::DirectLikely);
    }

    #[test]
    fn global_ipv6_evidence_is_explicit() {
        let plan = plan_traversal(
            &NatCapabilities::default(),
            &NatCapabilities::default(),
            &TraversalContext {
                global_ipv6_direct_available: true,
                ..Default::default()
            },
        );
        assert_eq!(plan.strategy, TraversalStrategy::Ipv6Direct);
    }

    #[test]
    fn profile_conversion_keeps_apdm_and_allocation_separate() {
        let profile = NatProfile {
            local_addr: "192.168.1.2:5000".to_string(),
            observations: vec![
                StunObservation {
                    server: "stun-a.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40001".to_string()),
                    rtt_ms: Some(10),
                    error: None,
                },
                StunObservation {
                    server: "stun-b.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40005".to_string()),
                    rtt_ms: Some(11),
                    error: None,
                },
                StunObservation {
                    server: "stun-c.example:3478".to_string(),
                    mapped_address: Some("203.0.113.10:40009".to_string()),
                    rtt_ms: Some(12),
                    error: None,
                },
            ],
            udp_blocked: false,
            public_endpoint: Some("203.0.113.10:40001".to_string()),
            public_ip_stable: Some(true),
            public_port_stable: Some(false),
            port_preserved: Some(false),
            port_delta: Some(4),
            likely_symmetric: Some(true),
            mapping_behavior: MappingBehavior::AddressOrPortDependent,
            filtering_behavior: FilteringBehavior::AddressDependent,
            hairpin_behavior: HairpinBehavior::Unknown,
            mapping_lifetime: MappingLifetime::Unknown,
            prediction_candidate: true,
            predicted_endpoints: vec!["203.0.113.10:40005".to_string()],
            birthday_candidate: true,
            confidence: 90,
        };
        let capabilities = NatCapabilities::from_profile(&profile);
        assert!(capabilities.is_hard_nat());
        assert!(capabilities.hard_allocation_is_predictable());
        assert_eq!(
            capabilities.filtering_behavior,
            FilteringBehavior::AddressDependent
        );
        assert_ne!(capabilities.allocation_model, None);
    }

    #[test]
    fn freshness_envelope_requires_generation_and_age() {
        let evidence = NatProfileEvidence {
            capabilities: easy(None),
            generation: 7,
            observed_at_ms: 100,
        };
        assert!(evidence.is_fresh_for(7, 500, Duration::from_secs(1)));
        assert!(!evidence.is_fresh_for(8, 500, Duration::from_secs(1)));
        assert!(!evidence.is_fresh_for(7, 2_000, Duration::from_secs(1)));
    }
}
