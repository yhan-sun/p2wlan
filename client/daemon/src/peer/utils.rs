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
    if label.starts_with(crate::FRESH_PREDICTION_SOURCE_LABEL_PREFIX) {
        return Some(CandidatePairSource::Predicted);
    }
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

fn candidate_pair_send_rank_at(pair: &CandidatePair, now: Instant, on_link_host: bool) -> u8 {
    if is_successful_low_latency_private_pair_at(pair, now)
        || (on_link_host && is_successful_low_latency_on_link_host_pair_at(pair, now))
    {
        return 0;
    }

    if is_recent_successful_direct_trial_pair_at(pair, now) {
        return 2;
    }

    match pair.state {
        CandidatePairState::Selected => 1,
        CandidatePairState::Succeeded | CandidatePairState::Probing
            if pair.source == CandidatePairSource::PeerReflexive
                && pair.last_probe_at.is_some_and(|last_probe| {
                    now.saturating_duration_since(last_probe) <= PEER_REFLEXIVE_STICKY_WINDOW
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
    is_recent_successful_direct_trial_pair_at(pair, Instant::now())
}

fn is_recent_successful_direct_trial_pair_at(pair: &CandidatePair, now: Instant) -> bool {
    if matches!(
        pair.source,
        CandidatePairSource::Predicted | CandidatePairSource::Birthday
    ) || !is_public_probe_endpoint(pair.remote_endpoint)
        || pair.last_error_code.as_deref() == Some(REASON_DIRECT_TRIAL_EXPIRED)
        || pair.consecutive_failures > RECENT_DIRECT_TRIAL_FAILURE_TOLERANCE
    {
        return false;
    }

    pair.last_success_at
        .is_some_and(|last_success| now.saturating_duration_since(last_success) <= DIRECT_TRIAL_WINDOW)
}

fn is_successful_low_latency_private_pair_at(pair: &CandidatePair, now: Instant) -> bool {
    matches!(
        pair.state,
        CandidatePairState::Selected | CandidatePairState::Succeeded
    ) && is_low_latency_direct_endpoint(pair.remote_endpoint)
        && pair.consecutive_failures == 0
        && pair
            .last_success_at
            .is_some_and(|last_success| now.saturating_duration_since(last_success) <= RELAY_PEER_CONFIRMATION_MAX_AGE)
        && pair
            .rtt_ewma_ms
            .or(pair.rtt_ms)
            .is_some_and(|rtt| rtt <= PRIVATE_DIRECT_RETAIN_MAX_RTT_MS)
}

fn is_successful_low_latency_on_link_host_pair_at(pair: &CandidatePair, now: Instant) -> bool {
    pair.source == CandidatePairSource::Host
        && matches!(
            pair.state,
            CandidatePairState::Selected | CandidatePairState::Succeeded
        )
        && pair.consecutive_failures == 0
        && pair
            .last_success_at
            .is_some_and(|last_success| now.saturating_duration_since(last_success) <= RELAY_PEER_CONFIRMATION_MAX_AGE)
        && pair
            .rtt_ewma_ms
            .or(pair.rtt_ms)
            .is_some_and(|rtt| rtt <= PRIVATE_DIRECT_RETAIN_MAX_RTT_MS)
}

fn candidate_pair_last_success_sort_key(
    pair: &CandidatePair,
) -> (bool, std::cmp::Reverse<Option<Instant>>) {
    (pair.last_success_at.is_none(), std::cmp::Reverse(pair.last_success_at))
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

    debug!(
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
        CandidatePairState::Failed => debug!(
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
