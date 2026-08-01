pub(super) fn candidate_pair_source_stats(
    pairs: &[CandidatePair],
    local_generation: u64,
    history: Option<&TraversalHistory>,
) -> Vec<CandidatePairSourceStats> {
    let mut stats = [
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
    .filter_map(|source| candidate_pair_source_stats_for(pairs, local_generation, source, history))
    .collect::<Vec<_>>();

    if let Some(history) = history {
        let stats_snapshot = stats.clone();
        for source_stats in &mut stats {
            source_stats.source_quality_rank = Some(candidate_pair_source_quality_rank(
                &stats_snapshot,
                history,
                source_stats.source,
            ));
            let (budget, reason) =
                candidate_pair_source_probe_budget(&stats_snapshot, history, source_stats.source);
            source_stats.probe_budget_per_cycle = budget;
            source_stats.probe_budget_reason = Some(reason.to_string());
        }
    }

    stats
}

fn candidate_pair_source_stats_for(
    pairs: &[CandidatePair],
    local_generation: u64,
    source: CandidatePairSource,
    history: Option<&TraversalHistory>,
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

    let history_entry = history.and_then(|history| history.source(source));

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
        history_success_count: history_entry.map(|entry| entry.success_count),
        history_failure_count: history_entry.map(|entry| entry.failure_count),
        history_consecutive_failures: history_entry.map(|entry| entry.consecutive_failures),
        history_success_rate_per_mille: history_entry
            .and_then(|entry| entry.success_rate_per_mille()),
        history_cooldown_remaining_ms: history
            .and_then(|history| history.source_cooldown_remaining_ms(source)),
        source_quality_rank: None,
        probe_budget_per_cycle: None,
        probe_budget_reason: None,
    })
}
