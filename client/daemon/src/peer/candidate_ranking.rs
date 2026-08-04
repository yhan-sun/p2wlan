use super::*;

pub(super) fn candidate_pair_source_quality_rank(
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

pub(super) fn candidate_pair_source_rank(source: CandidatePairSource) -> u8 {
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

pub(super) fn is_hard_nat_profile(profile: &NatProfile) -> bool {
    !profile.udp_blocked
        && profile.likely_symmetric == Some(true)
        && profile.mapping_behavior == MappingBehavior::AddressOrPortDependent
}

/// An endpoint observed from an authenticated packet is more valuable than
/// address-family ranking: it already proves that the peer can reach us.
/// Everything else is ordered by public-vs-private reachability first.
pub(super) fn discovered_endpoint_probe_rank(source: CandidatePairSource) -> u8 {
    match source {
        CandidatePairSource::PeerReflexive => 0,
        CandidatePairSource::Learned => 1,
        _ => 2,
    }
}

pub(super) fn candidate_pair_source_observed_age_ms(pair: &CandidatePair) -> Option<u64> {
    pair.source_observed_at
        .map(|observed_at| duration_millis(observed_at.elapsed()))
}

pub(super) fn candidate_pair_freshness_rank_at(pair: &CandidatePair, now: Instant) -> u8 {
    if pair.last_success_at.is_some()
        || matches!(
            pair.state,
            CandidatePairState::Selected | CandidatePairState::Succeeded
        )
    {
        return 0;
    }

    match pair
        .source_observed_at
        .map(|observed_at| now.saturating_duration_since(observed_at))
    {
        Some(age) if age <= Duration::from_secs(3) => 0,
        Some(age) if age <= Duration::from_secs(10) => 1,
        Some(age) if age <= Duration::from_secs(30) => 2,
        Some(_) => 3,
        None => 4,
    }
}

fn candidate_pair_source_observed_sort_key(
    pair: &CandidatePair,
) -> std::cmp::Reverse<Option<Instant>> {
    std::cmp::Reverse(pair.source_observed_at)
}

pub(super) fn candidate_pair_dynamic_probe_rank(
    pair: &CandidatePair,
    active_endpoint: Option<SocketAddr>,
) -> (u8, u64, std::cmp::Reverse<Option<Instant>>) {
    if active_endpoint == Some(pair.remote_endpoint)
        && is_public_probe_endpoint(pair.remote_endpoint)
        && matches!(
            pair.source,
            CandidatePairSource::PeerReflexive
                | CandidatePairSource::Learned
                | CandidatePairSource::StunObserved
                | CandidatePairSource::Signaled
        )
    {
        return (0, 0, candidate_pair_source_observed_sort_key(pair));
    }

    match pair.source {
        CandidatePairSource::PeerReflexive => (1, 0, candidate_pair_source_observed_sort_key(pair)),
        CandidatePairSource::Learned => (2, 0, candidate_pair_source_observed_sort_key(pair)),
        CandidatePairSource::StunObserved => (3, 0, candidate_pair_source_observed_sort_key(pair)),
        CandidatePairSource::Signaled => (4, 0, candidate_pair_source_observed_sort_key(pair)),
        CandidatePairSource::Birthday => {
            if let Some(active_endpoint) = active_endpoint {
                if active_endpoint.ip() == pair.remote_endpoint.ip()
                    && is_public_probe_endpoint(active_endpoint)
                {
                    return (
                        5,
                        u64::from(pair.remote_endpoint.port().abs_diff(active_endpoint.port())),
                        candidate_pair_source_observed_sort_key(pair),
                    );
                }
            }
            (5, u64::MAX, candidate_pair_source_observed_sort_key(pair))
        }
        _ => (6, 0, candidate_pair_source_observed_sort_key(pair)),
    }
}

pub(super) fn birthday_base_rank(
    conn: &PeerConnection,
    endpoint: SocketAddr,
    local_generation: u64,
) -> (u8, u8, std::cmp::Reverse<Option<Instant>>, u64) {
    let pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.local_generation == local_generation && pair.remote_endpoint == endpoint);
    let source = conn.candidate_source_for_endpoint(endpoint);
    let active_rank = if conn.endpoint == Some(endpoint) {
        0
    } else {
        1
    };
    let source_rank = match source {
        CandidatePairSource::PeerReflexive => 0,
        CandidatePairSource::Learned => 1,
        CandidatePairSource::StunObserved => 2,
        CandidatePairSource::Signaled => 3,
        _ => 4,
    };
    let observed_key = pair
        .map(candidate_pair_source_observed_sort_key)
        .unwrap_or(std::cmp::Reverse(None));
    let probe_count = pair.map(|pair| pair.probe_count).unwrap_or(0);
    (active_rank, source_rank, observed_key, probe_count)
}

pub(super) fn peer_reflexive_retention_rank(
    conn: &PeerConnection,
    endpoint: SocketAddr,
    fresh_endpoint: SocketAddr,
    local_generation: u64,
) -> (u8, std::cmp::Reverse<Option<Instant>>, u64) {
    let pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.local_generation == local_generation && pair.remote_endpoint == endpoint);
    let fresh_rank = if endpoint == fresh_endpoint { 0 } else { 1 };
    let observed_key = pair
        .map(candidate_pair_source_observed_sort_key)
        .unwrap_or(std::cmp::Reverse(None));
    let probe_count = pair.map(|pair| pair.probe_count).unwrap_or(0);
    (fresh_rank, observed_key, probe_count)
}

pub(super) fn should_retain_peer_reflexive_pair(pair: &CandidatePair) -> bool {
    matches!(
        pair.state,
        CandidatePairState::Selected | CandidatePairState::Succeeded
    ) || is_recent_successful_direct_trial_pair(pair)
}

pub(super) fn speculative_probe_rotation_rank(pair: &CandidatePair) -> u64 {
    if is_speculative_probe_source(pair.source) {
        pair.probe_count
    } else {
        0
    }
}

pub(super) fn speculative_probe_source_rank_for_mode(
    source: CandidatePairSource,
    mode: ProbeTargetMode,
) -> u8 {
    if !mode.prioritizes_predicted() {
        return 0;
    }
    match source {
        CandidatePairSource::Predicted => 0,
        CandidatePairSource::Birthday => 1,
        _ => 0,
    }
}
