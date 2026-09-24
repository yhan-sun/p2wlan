use super::*;

pub(super) fn record_birthday_worker_result(
    wave_report: &mut PunchSendReport,
    wave_fully_completed: &mut bool,
    failure_kind: &mut Option<BirthdaySweepFailureKind>,
    joined: std::result::Result<(usize, Result<PunchSendReport>), tokio::task::JoinError>,
) {
    match joined {
        Ok((_assigned_count, Ok(report))) => {
            *wave_fully_completed &=
                report.target_processing_completed && report.failure_kind.is_none();
            *failure_kind = combine_birthday_failure_kind(*failure_kind, report.failure_kind);
            merge_punch_send_reports(wave_report, report);
        }
        Ok((assigned_count, Err(_error))) => {
            *wave_fully_completed = false;
            *failure_kind = combine_birthday_failure_kind(
                *failure_kind,
                Some(BirthdaySweepFailureKind::from_probe_failure(
                    ProbeSendFailureKind::ProbeRegistrationFailed,
                )),
            );
            wave_report.probe_path_errors = wave_report.probe_path_errors.saturating_add(1);
            wave_report.targets_cancelled = wave_report
                .targets_cancelled
                .saturating_add(u32::try_from(assigned_count).unwrap_or(u32::MAX));
        }
        Err(_join_error) => {
            *wave_fully_completed = false;
            *failure_kind = combine_birthday_failure_kind(
                *failure_kind,
                Some(BirthdaySweepFailureKind::WorkerJoin),
            );
            wave_report.worker_failed = true;
        }
    }
}

pub(super) fn combine_birthday_failure_kind(
    left: Option<BirthdaySweepFailureKind>,
    right: Option<BirthdaySweepFailureKind>,
) -> Option<BirthdaySweepFailureKind> {
    match (left, right) {
        (None, value) | (value, None) => value,
        (Some(left), Some(right)) => {
            if birthday_failure_priority(right) > birthday_failure_priority(left) {
                Some(right)
            } else {
                Some(left)
            }
        }
    }
}

pub(super) const fn birthday_failure_priority(kind: BirthdaySweepFailureKind) -> u8 {
    match kind {
        BirthdaySweepFailureKind::WorkerJoin => 100,
        BirthdaySweepFailureKind::NetworkGenerationChanged => 90,
        BirthdaySweepFailureKind::CandidateEpochChanged => 80,
        BirthdaySweepFailureKind::ProfileGenerationChanged => 70,
        BirthdaySweepFailureKind::PeerSessionChanged => 60,
        BirthdaySweepFailureKind::SessionRetired => 50,
        BirthdaySweepFailureKind::SocketRevoked => 40,
        BirthdaySweepFailureKind::SocketUnavailable => 30,
        BirthdaySweepFailureKind::ProbeRegistrationFailed => 20,
        BirthdaySweepFailureKind::ProbeEncodingFailed => 10,
        BirthdaySweepFailureKind::Send => 1,
    }
}

pub(super) fn merge_punch_send_reports(destination: &mut PunchSendReport, source: PunchSendReport) {
    let source_logical_sent = source.logical_probes_sent.max(source.packets_sent);
    let source_logical_attempted = source.logical_probes_attempted.max(source_logical_sent);
    let source_targets_examined = source.targets_examined.max(source.targets_attempted);
    let source_physical_datagrams_sent = source
        .physical_datagrams_sent
        .max(source.per_socket_sent.iter().map(|(_, sent)| *sent).sum());
    destination.packets_sent = destination.packets_sent.saturating_add(source_logical_sent);
    destination.logical_probes_sent = destination
        .logical_probes_sent
        .saturating_add(source_logical_sent);
    destination.logical_probes_attempted = destination
        .logical_probes_attempted
        .saturating_add(source_logical_attempted);
    destination.logical_probe_send_failures = destination
        .logical_probe_send_failures
        .saturating_add(source.logical_probe_send_failures);
    destination.physical_datagrams_sent = destination
        .physical_datagrams_sent
        .saturating_add(source_physical_datagrams_sent);
    destination.physical_bytes_sent = destination
        .physical_bytes_sent
        .saturating_add(source.physical_bytes_sent);
    destination.physical_send_errors = destination
        .physical_send_errors
        .saturating_add(source.physical_send_errors);
    destination.physical_send_error_bytes = destination
        .physical_send_error_bytes
        .saturating_add(source.physical_send_error_bytes);
    destination.partial_physical_send_errors = destination
        .partial_physical_send_errors
        .saturating_add(source.partial_physical_send_errors);
    destination.probe_path_errors = destination
        .probe_path_errors
        .saturating_add(source.probe_path_errors);
    destination.budget_skipped = destination
        .budget_skipped
        .saturating_add(source.budget_skipped);
    destination.targets_assigned = destination
        .targets_assigned
        .saturating_add(source.targets_assigned);
    destination.targets_examined = destination
        .targets_examined
        .saturating_add(source_targets_examined);
    destination.targets_attempted = destination
        .targets_attempted
        .saturating_add(source.targets_attempted);
    destination.targets_cancelled = destination
        .targets_cancelled
        .saturating_add(source.targets_cancelled);
    if destination.targets_assigned == 0 {
        destination.target_processing_completed = source.target_processing_completed;
    } else {
        destination.target_processing_completed &= source.target_processing_completed;
    }
    destination.worker_failed |=
        source.worker_failed || source.failure_kind == Some(BirthdaySweepFailureKind::WorkerJoin);
    destination.failure_kind =
        combine_birthday_failure_kind(destination.failure_kind, source.failure_kind);
    destination.epoch_budget_exhausted |= source.epoch_budget_exhausted;
    destination.candidate_iteration_capped |= source.candidate_iteration_capped;
    destination.first_send_at_ms = match (destination.first_send_at_ms, source.first_send_at_ms) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, right) => right,
        (left, None) => left,
    };
    destination.last_send_at_ms = match (destination.last_send_at_ms, source.last_send_at_ms) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (None, right) => right,
        (left, None) => left,
    };
    for endpoint in source.sent_target_endpoints {
        if !destination.sent_target_endpoints.contains(&endpoint) {
            destination.sent_target_endpoints.push(endpoint);
        }
    }
    for (socket_index, sent) in source.per_socket_sent {
        if let Some((_, existing)) = destination
            .per_socket_sent
            .iter_mut()
            .find(|(index, _)| *index == socket_index)
        {
            *existing = existing.saturating_add(sent);
        } else {
            destination.per_socket_sent.push((socket_index, sent));
        }
    }
    normalize_physical_send_dimensions(destination);
}

/// Keep the terminal/live physical-send invariant exact after reports from
/// several workers have been merged.  Every production Hard↔Hard physical
/// send records the actual socket, so the histogram is the authoritative
/// successful-datagram total rather than a lower/upper-bound diagnostic.
pub(super) fn normalize_physical_send_dimensions(report: &mut PunchSendReport) {
    report
        .per_socket_sent
        .sort_unstable_by_key(|(socket_index, _)| *socket_index);
    report.physical_datagrams_sent = report.per_socket_sent.iter().map(|(_, sent)| *sent).sum();
}

pub(crate) fn update_birthday_sweep_counters(
    birthday: &mut BirthdaySweepReport,
    aggregate: &PunchSendReport,
) {
    birthday.targets_assigned = birthday
        .targets_assigned
        .max(aggregate.targets_assigned as usize);
    birthday.targets_attempted = aggregate.targets_attempted as usize;
    birthday.targets_examined =
        aggregate.targets_examined.max(aggregate.targets_attempted) as usize;
    let logical_probes_sent = aggregate.logical_probes_sent.max(aggregate.packets_sent);
    birthday.logical_probes_attempted =
        aggregate.logical_probes_attempted.max(logical_probes_sent) as usize;
    birthday.logical_probes_sent = logical_probes_sent as usize;
    birthday.logical_probe_send_failures = aggregate.logical_probe_send_failures as usize;
    birthday.physical_datagrams_sent = aggregate
        .per_socket_sent
        .iter()
        .map(|(_, sent)| *sent)
        .sum::<u32>() as usize;
    birthday.physical_send_errors = aggregate.physical_send_errors as usize;
    birthday.partial_physical_send_errors = aggregate.partial_physical_send_errors as usize;
    birthday.targets_budget_skipped = aggregate.budget_skipped as usize;
    birthday.targets_cancelled = aggregate.targets_cancelled as usize;
}

pub(super) fn update_live_birthday_counters(
    live: &Option<Arc<StdMutex<LiveBirthdayProgress>>>,
    update: impl FnOnce(&mut LiveBirthdayCounters),
) {
    update_live_birthday_progress(live, |progress| update(&mut progress.counters));
}

pub(super) fn update_live_birthday_progress(
    live: &Option<Arc<StdMutex<LiveBirthdayProgress>>>,
    update: impl FnOnce(&mut LiveBirthdayProgress),
) {
    let Some(live) = live else {
        return;
    };
    let mut progress = live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    update(&mut progress);
}

pub(crate) fn apply_live_birthday_counters(
    report: &mut PunchSendReport,
    live: &LiveBirthdayProgress,
) {
    let counters = &live.counters;
    report.targets_assigned = report.targets_assigned.max(counters.targets_assigned);
    report.targets_examined = report.targets_examined.max(counters.targets_examined);
    report.targets_attempted = report.targets_attempted.max(counters.targets_attempted);
    report.targets_cancelled = report.targets_cancelled.max(counters.targets_cancelled);
    report.budget_skipped = report.budget_skipped.max(counters.budget_skipped);
    report.logical_probes_sent = report
        .logical_probes_sent
        .max(counters.logical_probes_sent)
        .max(report.packets_sent);
    report.logical_probes_attempted = report
        .logical_probes_attempted
        .max(counters.logical_probes_attempted)
        .max(report.logical_probes_sent);
    report.logical_probe_send_failures = report
        .logical_probe_send_failures
        .max(counters.logical_probe_send_failures);
    report.packets_sent = report.packets_sent.max(report.logical_probes_sent);
    report.physical_datagrams_sent = report
        .physical_datagrams_sent
        .max(counters.physical_datagrams_sent);
    report.physical_bytes_sent = report.physical_bytes_sent.max(counters.physical_bytes_sent);
    report.physical_send_errors = report
        .physical_send_errors
        .max(counters.physical_send_errors);
    report.physical_send_error_bytes = report
        .physical_send_error_bytes
        .max(counters.physical_send_error_bytes);
    report.partial_physical_send_errors = report
        .partial_physical_send_errors
        .max(counters.partial_physical_send_errors);
    report.probe_path_errors = report.probe_path_errors.max(counters.probe_path_errors);
    for endpoint in &live.sent_target_endpoints {
        if !report.sent_target_endpoints.contains(endpoint) {
            report.sent_target_endpoints.push(*endpoint);
        }
    }
    report.unique_target_endpoints =
        u32::try_from(report.sent_target_endpoints.len()).unwrap_or(u32::MAX);
    for (socket_index, sent) in &live.per_socket_sent {
        if let Some((_, existing)) = report
            .per_socket_sent
            .iter_mut()
            .find(|(index, _)| index == socket_index)
        {
            *existing = (*existing).max(*sent);
        } else {
            report.per_socket_sent.push((*socket_index, *sent));
        }
    }
    report.first_send_at_ms = match (report.first_send_at_ms, live.first_send_at_ms) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, right) => right,
        (left, None) => left,
    };
    report.last_send_at_ms = match (report.last_send_at_ms, live.last_send_at_ms) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (None, right) => right,
        (left, None) => left,
    };
    normalize_physical_send_dimensions(report);
}

pub(super) async fn publish_birthday_sweep_progress(
    progress: &Option<Arc<Mutex<BirthdaySweepProgress>>>,
    birthday: &BirthdaySweepReport,
    aggregate: &PunchSendReport,
) {
    let Some(progress) = progress else {
        return;
    };
    let live = {
        let current = progress.lock().await;
        current.live.clone()
    };
    let live_snapshot = live
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let mut published_aggregate = aggregate.clone();
    apply_live_birthday_counters(&mut published_aggregate, &live_snapshot);
    let mut published_birthday = birthday.clone();
    published_birthday.targets_assigned = published_birthday
        .targets_assigned
        .max(published_aggregate.targets_assigned as usize);
    update_birthday_sweep_counters(&mut published_birthday, &published_aggregate);
    let mut current = progress.lock().await;
    current.birthday = published_birthday;
    current.aggregate = published_aggregate;
}
