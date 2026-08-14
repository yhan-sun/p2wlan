use super::*;

pub(crate) fn is_public_probe_endpoint(endpoint: SocketAddr) -> bool {
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

fn is_private_direct_endpoint(endpoint: SocketAddr) -> bool {
    match endpoint.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => {
            let first_segment = ip.segments()[0];
            let is_unique_local = (first_segment & 0xfe00) == 0xfc00;
            let is_link_local = (first_segment & 0xffc0) == 0xfe80;
            is_unique_local || is_link_local
        }
    }
}

pub(super) fn should_retain_private_direct_pair(pair: &CandidatePair) -> bool {
    if pair.state != CandidatePairState::Selected
        || !is_low_latency_direct_endpoint(pair.remote_endpoint)
        || pair.consecutive_failures > 0
        || pair
            .success_age()
            .is_none_or(|age| age > RELAY_PEER_CONFIRMATION_MAX_AGE)
    {
        return false;
    }

    pair.rtt_ewma_ms
        .or(pair.rtt_ms)
        .is_some_and(|rtt| rtt <= PRIVATE_DIRECT_RETAIN_MAX_RTT_MS)
}

pub(super) fn should_retain_confirmed_direct_pair_on_candidate_refresh(
    pair: &CandidatePair,
) -> bool {
    if should_retain_private_direct_pair(pair) {
        return true;
    }

    if pair.state != CandidatePairState::Selected
        || pair.consecutive_failures > 0
        || pair
            .success_age()
            .is_none_or(|age| age > RELAY_PEER_CONFIRMATION_MAX_AGE)
    {
        return false;
    }

    is_public_probe_endpoint(pair.remote_endpoint)
        && (pair.source == CandidatePairSource::PeerReflexive
            || is_public_udp_direct_source(pair.source))
}

pub(super) fn is_low_latency_direct_endpoint(endpoint: SocketAddr) -> bool {
    is_private_direct_endpoint(endpoint) && !is_overlay_endpoint(endpoint)
}

pub(crate) fn is_overlay_endpoint(endpoint: SocketAddr) -> bool {
    match endpoint.ip() {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            (octets[0] == 10 && octets[1] == 20) || is_shared_ipv4(ip)
        }
        IpAddr::V6(ip) => {
            let first_segment = ip.segments()[0];
            (first_segment & 0xfe00) == 0xfc00
        }
    }
}

pub(super) fn classify_candidate_pair_path(
    active_path: Option<NetworkPath>,
    pair: Option<&CandidatePair>,
    direct_confirmed: bool,
) -> DirectPathType {
    if active_path == Some(NetworkPath::Relay) {
        return DirectPathType::Relay;
    }

    let Some(pair) = pair else {
        return if active_path == Some(NetworkPath::Direct) {
            DirectPathType::Probing
        } else {
            DirectPathType::Unknown
        };
    };

    if active_path != Some(NetworkPath::Direct) || !direct_confirmed {
        return if matches!(
            pair.state,
            CandidatePairState::Waiting
                | CandidatePairState::Probing
                | CandidatePairState::Succeeded
                | CandidatePairState::Selected
        ) {
            DirectPathType::Probing
        } else {
            DirectPathType::Unknown
        };
    }

    if is_overlay_endpoint(pair.remote_endpoint) {
        return DirectPathType::Overlay;
    }

    if is_private_direct_endpoint(pair.remote_endpoint) {
        return DirectPathType::Lan;
    }

    if is_public_probe_endpoint(pair.remote_endpoint)
        && pair.source == CandidatePairSource::PeerReflexive
    {
        DirectPathType::PeerReflexive
    } else if is_public_probe_endpoint(pair.remote_endpoint)
        && is_public_udp_direct_source(pair.source)
    {
        DirectPathType::PublicUdp
    } else {
        DirectPathType::Unknown
    }
}

pub(super) fn classify_confirmed_direct_endpoint(
    endpoint: SocketAddr,
    source: CandidatePairSource,
) -> DirectPathType {
    if is_overlay_endpoint(endpoint) {
        DirectPathType::Overlay
    } else if is_private_direct_endpoint(endpoint) {
        DirectPathType::Lan
    } else if is_public_probe_endpoint(endpoint) && source == CandidatePairSource::PeerReflexive {
        DirectPathType::PeerReflexive
    } else if is_public_probe_endpoint(endpoint) && is_public_udp_direct_source(source) {
        DirectPathType::PublicUdp
    } else {
        DirectPathType::Unknown
    }
}

pub(super) fn is_public_udp_direct_source(source: CandidatePairSource) -> bool {
    matches!(
        source,
        CandidatePairSource::StunObserved
            | CandidatePairSource::Signaled
            | CandidatePairSource::Upnp
            | CandidatePairSource::Pcp
            | CandidatePairSource::NatPmp
            | CandidatePairSource::Predicted
            | CandidatePairSource::Birthday
            | CandidatePairSource::Learned
    )
}

fn is_shared_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

pub(super) fn endpoint_probe_rank(endpoint: SocketAddr) -> u8 {
    if is_overlay_endpoint(endpoint) {
        return 3;
    }

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

pub(super) fn candidate_pair_probe_rank_for_mode(
    state: CandidatePairState,
    source: CandidatePairSource,
    mode: ProbeTargetMode,
) -> u8 {
    if mode.prioritizes_predicted()
        && source == CandidatePairSource::Predicted
        && matches!(
            state,
            CandidatePairState::Failed | CandidatePairState::Degraded
        )
    {
        return 0;
    }
    candidate_pair_probe_rank(state)
}

pub(super) fn candidate_pair_probe_due(pair: &CandidatePair) -> bool {
    if pair.slow_validation_is_recent_at(Instant::now(), SLOW_DIRECT_RELAY_RETRY_COOLDOWN) {
        return false;
    }
    let Some(retry_after) = candidate_pair_failure_cooldown(pair) else {
        return true;
    };
    let Some(failure_age) = pair.failure_age() else {
        return true;
    };
    failure_age >= retry_after
}

/// Decide whether a pair may enter this probe window.  Synchronized and
/// reclaim windows intentionally bypass ordinary failure backoff, but they do
/// not bypass the slow-validation quarantine: otherwise a 500ms+ ACK can be
/// retried in every window and starve newly refreshed NAT mappings.
pub(super) fn candidate_pair_probe_allowed_at(
    pair: &CandidatePair,
    mode: ProbeTargetMode,
    now: Instant,
) -> bool {
    !pair.slow_validation_is_recent_at(now, SLOW_DIRECT_RELAY_RETRY_COOLDOWN)
        && (mode.bypasses_pair_cooldown() || candidate_pair_probe_due(pair))
}

pub(super) fn candidate_pair_failure_cooldown(pair: &CandidatePair) -> Option<Duration> {
    if !matches!(
        pair.state,
        CandidatePairState::Failed | CandidatePairState::Degraded
    ) {
        return None;
    }
    if is_priority_outbound_probe_pair(pair) {
        return Some(PRIORITY_OUTBOUND_PROBE_FAILURE_COOLDOWN);
    }
    let exponent = pair
        .consecutive_failures
        .saturating_sub(1)
        .min(CANDIDATE_PAIR_FAILURE_COOLDOWN_MAX_EXPONENT);
    Some(
        CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE
            .checked_mul(1_u32 << exponent)
            .unwrap_or(Duration::MAX),
    )
}
