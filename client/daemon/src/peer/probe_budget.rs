use super::*;

pub(super) fn apply_adaptive_probe_budgets<'a>(
    pairs: Vec<&'a CandidatePair>,
    stats: &[CandidatePairSourceStats],
    history: &TraversalHistory,
    mode: ProbeTargetMode,
    birthday_budget_override: Option<usize>,
) -> Vec<&'a CandidatePair> {
    let predicted_budget = predicted_probe_budget_for_mode(stats, history, mode);
    let birthday_budget = birthday_budget_override
        .unwrap_or_else(|| birthday_probe_budget_for_pairs(history, &pairs));
    let mut predicted_used = 0usize;
    let mut birthday_used = 0usize;

    let mut guaranteed_pairs = Vec::new();
    let mut budgeted_pairs = Vec::new();
    for pair in pairs {
        if is_priority_outbound_probe_pair(pair) {
            guaranteed_pairs.push(pair);
        } else {
            budgeted_pairs.push(pair);
        }
    }

    guaranteed_pairs.extend(budgeted_pairs.into_iter().filter(|pair| {
        apply_speculative_probe_budget(
            pair.source,
            predicted_budget,
            birthday_budget,
            &mut predicted_used,
            &mut birthday_used,
        )
    }));
    guaranteed_pairs
}

pub(super) fn is_priority_outbound_probe_pair(pair: &CandidatePair) -> bool {
    matches!(
        pair.source,
        CandidatePairSource::PeerReflexive
            | CandidatePairSource::Learned
            | CandidatePairSource::Host
    ) || is_stable_public_probe_pair(pair)
}

fn is_stable_public_probe_pair(pair: &CandidatePair) -> bool {
    is_public_probe_endpoint(pair.remote_endpoint)
        && matches!(
            pair.source,
            CandidatePairSource::PeerReflexive
                | CandidatePairSource::StunObserved
                | CandidatePairSource::Signaled
                | CandidatePairSource::Learned
                | CandidatePairSource::Upnp
                | CandidatePairSource::Pcp
                | CandidatePairSource::NatPmp
        )
}

pub(super) fn outbound_probe_priority_rank(pair: &CandidatePair) -> u8 {
    if is_priority_outbound_probe_pair(pair) {
        0
    } else if is_speculative_probe_source(pair.source) {
        2
    } else {
        1
    }
}

pub(super) fn is_speculative_probe_source(source: CandidatePairSource) -> bool {
    matches!(
        source,
        CandidatePairSource::Predicted | CandidatePairSource::Birthday
    )
}

fn apply_speculative_probe_budget(
    source: CandidatePairSource,
    predicted_budget: usize,
    birthday_budget: usize,
    predicted_used: &mut usize,
    birthday_used: &mut usize,
) -> bool {
    match source {
        CandidatePairSource::Predicted => {
            if *predicted_used < predicted_budget {
                *predicted_used += 1;
                true
            } else {
                false
            }
        }
        CandidatePairSource::Birthday => {
            if *birthday_used < birthday_budget {
                *birthday_used += 1;
                true
            } else {
                false
            }
        }
        _ => true,
    }
}

fn predicted_probe_budget(stats: &[CandidatePairSourceStats], history: &TraversalHistory) -> usize {
    predicted_probe_budget_with_reason(stats, history).0
}

fn predicted_probe_budget_for_mode(
    stats: &[CandidatePairSourceStats],
    history: &TraversalHistory,
    mode: ProbeTargetMode,
) -> usize {
    let budget = predicted_probe_budget(stats, history);
    if mode.refreshes_speculative_budget() {
        return budget.max(PREDICTED_PROBE_BUDGET_PER_CYCLE);
    }
    budget
}

fn predicted_probe_budget_with_reason(
    stats: &[CandidatePairSourceStats],
    history: &TraversalHistory,
) -> (usize, &'static str) {
    if history.source_in_cooldown(CandidatePairSource::Predicted) {
        return (
            PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE,
            "history_cooldown",
        );
    }
    if history
        .source(CandidatePairSource::Predicted)
        .is_some_and(|entry| entry.consecutive_failures >= 3)
    {
        return (PREDICTED_PROBE_FAILURE_BUDGET_PER_CYCLE, "history_failures");
    }
    if history
        .source(CandidatePairSource::Predicted)
        .is_some_and(|entry| {
            entry.success_count >= 2 && entry.success_rate_per_mille().unwrap_or(0) >= 500
        })
    {
        return (PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE, "history_success");
    }
    if stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .is_some_and(|stats| stats.success_count > 0)
    {
        return (PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE, "current_success");
    }
    (PREDICTED_PROBE_BUDGET_PER_CYCLE, "default")
}

pub(super) fn birthday_probe_budget(history: &TraversalHistory) -> usize {
    birthday_probe_budget_with_reason(history).0
}

pub(super) fn birthday_probe_budget_for_base_count(
    history: &TraversalHistory,
    base_count: usize,
) -> usize {
    if base_count == 0 {
        return 0;
    }
    birthday_probe_budget(history)
        .saturating_mul(base_count.min(BIRTHDAY_PROBE_MAX_BASES_PER_CYCLE))
}

fn birthday_probe_budget_for_pairs(history: &TraversalHistory, pairs: &[&CandidatePair]) -> usize {
    let birthday_pair_count = pairs
        .iter()
        .filter(|pair| pair.source == CandidatePairSource::Birthday)
        .count();
    if birthday_pair_count == 0 {
        return 0;
    }
    let per_base_budget = birthday_probe_budget(history).max(1);
    let base_count = birthday_pair_count.div_ceil(per_base_budget);
    birthday_probe_budget_for_base_count(history, base_count)
}

fn birthday_probe_budget_with_reason(history: &TraversalHistory) -> (usize, &'static str) {
    if history.source_in_cooldown(CandidatePairSource::Birthday) {
        return (BIRTHDAY_PROBE_COOLDOWN_BUDGET_PER_CYCLE, "history_cooldown");
    }
    if history
        .source(CandidatePairSource::Birthday)
        .is_some_and(|entry| entry.consecutive_failures >= 3)
    {
        return (BIRTHDAY_PROBE_FAILURE_BUDGET_PER_CYCLE, "history_failures");
    }
    if history
        .source(CandidatePairSource::Birthday)
        .is_some_and(|entry| {
            entry.success_count > 0 && entry.success_rate_per_mille().unwrap_or(0) >= 500
        })
    {
        return (BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE, "history_success");
    }
    (BIRTHDAY_PROBE_BUDGET_PER_CYCLE, "default")
}

pub(super) fn candidate_pair_source_probe_budget(
    stats: &[CandidatePairSourceStats],
    history: &TraversalHistory,
    source: CandidatePairSource,
) -> (Option<usize>, &'static str) {
    match source {
        CandidatePairSource::Predicted => {
            let (budget, reason) = predicted_probe_budget_with_reason(stats, history);
            (Some(budget), reason)
        }
        CandidatePairSource::Birthday => {
            let (budget, reason) = birthday_probe_budget_with_reason(history);
            (Some(budget), reason)
        }
        _ => (None, "guaranteed"),
    }
}
