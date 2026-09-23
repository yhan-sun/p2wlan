fn hard_hard_socket_identity(
    peer_id: &str,
    session_token: &str,
    result: &FreshMappingResult,
    plan: crate::peer::HardHardPlanSnapshot,
) -> crate::peer::HardHardFreshSocketIdentity {
    crate::peer::HardHardFreshSocketIdentity {
        peer_id: peer_id.to_string(),
        session_token: session_token.to_string(),
        network_generation: result.network_generation,
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.local_profile_generation,
        remote_profile_generation: plan.remote_profile_generation,
        punch_generation: result.punch_generation,
        socket_index: result.socket_index,
        socket_local_endpoint: result.socket_local_endpoint,
    }
}

enum HardHardLocalMeasurement {
    Predictable {
        result: Box<FreshMappingResult>,
        handoff: Box<ProvisionalSocketGuard>,
    },
    Birthday(Box<HardHardBirthdayResult>),
}

struct HardHardMeasurementPayload {
    candidates: Vec<String>,
    candidate_sources: HashMap<String, String>,
    local_confidence: u8,
    local_model: String,
    strategy_candidate_cap: usize,
    candidate_contract: crate::candidate_refresh::SignalCandidateContract,
}

fn hard_hard_bounded_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

fn hard_hard_measurement_stats(
    measurement: &HardHardLocalMeasurement,
) -> crate::udp::HardHardMeasurementStats {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => result.measurement,
        HardHardLocalMeasurement::Birthday(result) => result.measurement,
    }
}

fn hard_hard_measurement_observation(
    peers: &PeerManager,
    measurement: &HardHardLocalMeasurement,
    measurement_completed_at_ms: Option<u64>,
    punch_at_ms: u64,
) -> crate::peer::HardHardMeasurementObservation {
    let stats = hard_hard_measurement_stats(measurement);
    let timeline_now_ms = peers.timeline_uptime_ms();
    let transport_now_ms = crate::udp::monotonic_millis();
    let measurement_started_at_ms = hard_hard_translate_transport_time(
        stats.measurement_started_at_ms,
        transport_now_ms,
        timeline_now_ms,
    );
    let last_measurement_send_at_ms = hard_hard_translate_transport_time(
        stats.last_measurement_send_at_ms,
        transport_now_ms,
        timeline_now_ms,
    );
    let measurement_completed_at_ms = hard_hard_translate_transport_time(
        stats.measurement_completed_at_ms,
        transport_now_ms,
        timeline_now_ms,
    )
    .or(measurement_completed_at_ms);
    let wall_now_ms = hard_hard_now_ms();
    let planned_send_at_ms = timeline_now_ms.map(|timeline_now| {
        if punch_at_ms >= wall_now_ms {
            timeline_now.saturating_add(punch_at_ms - wall_now_ms)
        } else {
            timeline_now.saturating_sub(wall_now_ms - punch_at_ms)
        }
    });
    crate::peer::HardHardMeasurementObservation {
        measurement_started_at_ms,
        last_measurement_send_at_ms,
        measurement_completed_at_ms,
        planned_send_at_ms,
        stun_datagrams_sent: stats.stun_datagrams_sent,
        stun_bytes_sent: stats.stun_bytes_sent,
        stun_send_errors: stats.stun_send_errors,
        stun_send_error_bytes: stats.stun_send_error_bytes,
        stun_responses: stats.stun_responses,
        ..crate::peer::HardHardMeasurementObservation::default()
    }
}

fn hard_hard_apply_candidate_contract(
    observation: &mut crate::peer::HardHardMeasurementObservation,
    contract: &crate::candidate_refresh::SignalCandidateContract,
    strategy_candidate_cap: usize,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) {
    observation.requested_candidate_count = contract.requested_candidate_count;
    observation.generated_candidate_count = contract.generated_candidate_count;
    observation.deduplicated_candidate_count = contract.deduplicated_candidate_count;
    // A normalized payload is not advertised until the existing control API
    // accepts it. The accepted count is committed to the exact session only
    // after that await succeeds.
    observation.advertised_candidate_count = 0;
    // Report the strategy cap which actually bounded this attempt (8/16/32
    // for predictable Hard<->Hard), not the wider shared serialization
    // ceiling. Keeping both values in the candidate-contract event prevents a
    // six-candidate attempt from being misread as a 96-port scan.
    observation.candidate_cap = strategy_candidate_cap.min(contract.cap);
    observation.truncation_reason = contract.reason.to_string();
    observation.candidate_signal_payload_logic_bytes = candidates
        .iter()
        .map(|candidate| candidate.len() as u64)
        .chain(
            candidate_sources
                .iter()
                .map(|(candidate, source)| candidate.len().saturating_add(source.len()) as u64),
        )
        .fold(0u64, u64::saturating_add);
}

fn hard_hard_safe_experiment_label(experiment_only: bool, name: &str) -> Option<String> {
    if !experiment_only {
        return None;
    }
    let value = std::env::var(name).ok()?;
    (!value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    .then_some(value)
}

fn hard_hard_experiment_signal_delay_ms(
    experiment_only: bool,
    configured_value: Option<&str>,
) -> u64 {
    if !experiment_only {
        return 0;
    }
    configured_value
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value <= 2_000)
        .unwrap_or(0)
}

/// Optional local-only experiment hook used by the NAT matrix to hold a
/// measured offer before it enters the existing signaling API. The default is
/// exactly zero and the bounded delay is never inferred from production
/// state, so ordinary traversal policy, budgets, and the canonical punch time
/// are unchanged. A delayed offer can therefore become late and be rejected
/// by the same production fences it is intended to measure.
async fn hard_hard_experiment_signal_delay(experiment_only: bool) {
    let delay_ms = hard_hard_experiment_signal_delay_ms(
        experiment_only,
        std::env::var("P2WLAN_EXPERIMENT_SIGNAL_DELAY_MS")
            .ok()
            .as_deref(),
    );
    if delay_ms > 0 {
        sleep(Duration::from_millis(delay_ms)).await;
    }
}

fn hard_hard_anonymized_tag(session_token: &str, value: impl std::fmt::Display) -> String {
    use sha2::Digest as _;

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"p2wlan-hard-hard-report-v1\0");
    hasher.update(session_token.as_bytes());
    hasher.update(b"\0");
    hasher.update(value.to_string().as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..16].to_string()
}

/// The current hh1 ledger owner holds exactly one rendezvous plan. Derive a
/// separate tag for that plan so logs can pair both roles without exposing the
/// opaque signaling token or comparing endpoint-local attempt counters.
fn hard_hard_rendezvous_plan_tag(session_token: &str) -> String {
    hard_hard_anonymized_tag(session_token, "rendezvous-plan")
}

fn hard_hard_translate_transport_time(
    transport_at_ms: Option<u64>,
    transport_now_ms: u64,
    timeline_now_ms: Option<u64>,
) -> Option<u64> {
    transport_at_ms
        .zip(timeline_now_ms)
        .map(|(at, timeline_now)| timeline_now.saturating_sub(transport_now_ms.saturating_sub(at)))
}

fn hard_hard_elapsed_ms(start_at_ms: Option<u64>, end_at_ms: Option<u64>) -> Option<u64> {
    start_at_ms
        .zip(end_at_ms)
        .and_then(|(start, end)| end.checked_sub(start))
}

fn hard_hard_attempt_failure_class(
    report: &PunchSendReport,
    probe_rx: UdpProbeRxSnapshot,
    direct_confirmed: bool,
    terminal_reason: &str,
) -> &'static str {
    if direct_confirmed {
        return "encrypted_validation_completed";
    }
    if matches!(
        terminal_reason,
        "network_generation_changed"
            | "candidate_epoch_changed"
            | "profile_generation_changed"
            | "peer_session_changed"
            | "session_retired"
            | "session_cancelled"
    ) {
        return "cancelled_generation_changed";
    }
    if report.budget_skipped > 0 && report.logical_probes_attempted == 0 {
        return "budget_rejected";
    }
    if report.physical_send_errors > 0 && report.physical_datagrams_sent == 0 {
        return "send_error";
    }
    if report.logical_probes_attempted == 0 {
        return if terminal_reason == "deadline" {
            "missed_schedule"
        } else {
            "candidate_not_executed"
        };
    }
    if probe_rx.authenticated_probe_packets_received > 0 || probe_rx.probe_acks_received > 0 {
        return "probe_hit_validation_failed";
    }
    if report.physical_datagrams_sent > 0 {
        return "no_response";
    }
    "unknown"
}

fn hard_hard_measurement_failure_class(rejection: &FreshMappingRejection) -> &'static str {
    match rejection {
        FreshMappingRejection::UnpredictableSequence => "model_unpredictable",
        FreshMappingRejection::CapacityRejected => "budget_rejected",
        FreshMappingRejection::Superseded => "cancelled_generation_changed",
        FreshMappingRejection::InsufficientSamples
        | FreshMappingRejection::InconsistentBatch
        | FreshMappingRejection::BatchStale
        | FreshMappingRejection::PublicIpChanged
        | FreshMappingRejection::NoProbesSent => "measurement_insufficient",
        FreshMappingRejection::StableLocalNat
        | FreshMappingRejection::NoStablePeerEndpoint
        | FreshMappingRejection::BindFailed
        | FreshMappingRejection::MissingProbeKey => "unknown",
    }
}

#[allow(clippy::too_many_arguments)]
fn build_hard_hard_pre_session_attempt_report(
    experiment_only: bool,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    plan: crate::peer::HardHardPlanSnapshot,
    session_token: &str,
    role: &'static str,
    attempt: u8,
    measurement: Option<&crate::peer::HardHardMeasurementObservation>,
    failure_class: &'static str,
    terminal_reason: &str,
) -> crate::peer::HardHardAttemptReport {
    let measurement = measurement.cloned().unwrap_or_default();
    crate::peer::HardHardAttemptReport {
        schema_version: crate::peer::HARD_HARD_ATTEMPT_REPORT_SCHEMA_VERSION,
        baseline_git_commit: hard_hard_safe_experiment_label(
            experiment_only,
            "P2WLAN_EXPERIMENT_BASELINE_SHA",
        )
        .unwrap_or_else(|| crate::build_info::GIT_COMMIT.to_string()),
        source_git_commit: crate::build_info::GIT_COMMIT.to_string(),
        build_id: crate::build_info::BUILD_ID.to_string(),
        experiment_variant: hard_hard_safe_experiment_label(
            experiment_only,
            "P2WLAN_EXPERIMENT_VARIANT",
        ),
        scenario_id: hard_hard_safe_experiment_label(experiment_only, "P2WLAN_EXPERIMENT_SCENARIO"),
        seed: experiment_only
            .then(|| std::env::var("P2WLAN_EXPERIMENT_SEED").ok())
            .flatten()
            .and_then(|value| value.parse().ok()),
        role: role.to_string(),
        mode: "measurement".to_string(),
        session_tag: hard_hard_anonymized_tag(session_token, "session"),
        plan_tag: hard_hard_rendezvous_plan_tag(session_token),
        network_generation: plan.local_network_generation,
        peer_session_generation: peer_session_generation.value(),
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.local_profile_generation,
        remote_profile_generation: plan.remote_profile_generation,
        punch_generation: 0,
        socket_index: None,
        attempt,
        counts: crate::peer::HardHardAttemptCounts {
            requested: hard_hard_bounded_u32(measurement.requested_candidate_count),
            generated: hard_hard_bounded_u32(measurement.generated_candidate_count),
            unique: hard_hard_bounded_u32(measurement.deduplicated_candidate_count),
            advertised: hard_hard_bounded_u32(measurement.advertised_candidate_count),
            stun_send_success_datagrams: measurement.stun_datagrams_sent,
            stun_send_success_bytes: measurement.stun_bytes_sent,
            stun_send_errors: measurement.stun_send_errors,
            stun_send_error_bytes: measurement.stun_send_error_bytes,
            stun_responses: measurement.stun_responses,
            candidate_signal_payload_logic_bytes: measurement.candidate_signal_payload_logic_bytes,
            ..crate::peer::HardHardAttemptCounts::default()
        },
        candidate_cap: hard_hard_bounded_u32(measurement.candidate_cap),
        truncation_reason: if measurement.truncation_reason.is_empty() {
            terminal_reason.to_string()
        } else {
            measurement.truncation_reason.clone()
        },
        target_order_tags: Vec::new(),
        timeline: crate::peer::HardHardAttemptTimeline {
            measurement_started_at_ms: measurement.measurement_started_at_ms,
            last_measurement_send_at_ms: measurement.last_measurement_send_at_ms,
            measurement_completed_at_ms: measurement.measurement_completed_at_ms,
            candidate_signal_accepted_at_ms: measurement.candidate_signal_accepted_at_ms,
            planned_send_at_ms: measurement.planned_send_at_ms,
            ..crate::peer::HardHardAttemptTimeline::default()
        },
        direct_confirmed: false,
        failure_class: failure_class.to_string(),
        terminal_reason: terminal_reason.to_string(),
        ..crate::peer::HardHardAttemptReport::default()
    }
}

#[allow(clippy::too_many_arguments)]
async fn record_hard_hard_pre_session_failure(
    peers: &PeerManager,
    peer_id: &str,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    plan: crate::peer::HardHardPlanSnapshot,
    session_token: &str,
    role: &'static str,
    attempt: u8,
    measurement: Option<&crate::peer::HardHardMeasurementObservation>,
    failure_class: &'static str,
    terminal_reason: &str,
) -> bool {
    peers
        .record_hard_hard_pre_session_attempt_report(
            peer_id,
            build_hard_hard_pre_session_attempt_report(
                peers.hard_hard_experiment_only(),
                peer_session_generation,
                plan,
                session_token,
                role,
                attempt,
                measurement,
                failure_class,
                terminal_reason,
            ),
        )
        .await
}

#[allow(clippy::too_many_arguments)]
fn build_hard_hard_attempt_report(
    peers: &PeerManager,
    experiment_only: bool,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    fresh_socket: &crate::peer::HardHardFreshSocketIdentity,
    session_token: &str,
    role: &'static str,
    birthday: bool,
    attempt: u8,
    measurement: &crate::peer::HardHardMeasurementObservation,
    targets: &[SocketAddr],
    planned_sockets: usize,
    planned_socket_target_combinations: usize,
    planned_logical_probes: usize,
    send_dispatch_at_ms: Option<u64>,
    punch_report: &PunchSendReport,
    probe_rx: UdpProbeRxSnapshot,
    direct_confirmed: bool,
    business_attribution_identity: Option<crate::peer::HardHardBusinessAttributionIdentity>,
    encrypted_validation_completed_at_ms: Option<u64>,
    confirmed_target_rank: Option<u32>,
    terminal_reason: &str,
) -> crate::peer::HardHardAttemptReport {
    let timeline_now_ms = peers.timeline_uptime_ms();
    let transport_now_ms = crate::udp::monotonic_millis();
    let actual_first_send_at_ms = hard_hard_translate_transport_time(
        punch_report.first_send_at_ms,
        transport_now_ms,
        timeline_now_ms,
    );
    let (probe_last_hit_transport_ms, probe_last_hit_source) =
        if let Some(at_ms) = probe_rx.last_authenticated_at_ms {
            (Some(at_ms), Some("last_authenticated_probe".to_string()))
        } else if let Some(at_ms) = probe_rx.last_matched_ack_at_ms {
            (Some(at_ms), Some("last_matched_ack".to_string()))
        } else {
            (None, None)
        };
    let probe_last_hit_at_ms = hard_hard_translate_transport_time(
        probe_last_hit_transport_ms,
        transport_now_ms,
        timeline_now_ms,
    );
    let measurement_age_at_send_ms = hard_hard_elapsed_ms(
        measurement.last_measurement_send_at_ms,
        actual_first_send_at_ms,
    );
    let measurement_to_first_send_ms = hard_hard_elapsed_ms(
        measurement.measurement_started_at_ms,
        actual_first_send_at_ms,
    );
    let schedule_deviation_ms = actual_first_send_at_ms
        .zip(measurement.planned_send_at_ms)
        .map(|(actual, planned)| {
            let deviation = i128::from(actual) - i128::from(planned);
            deviation.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
        });
    let last_probe_hit_to_validation_ms =
        hard_hard_elapsed_ms(probe_last_hit_at_ms, encrypted_validation_completed_at_ms);
    let planned_logical_probes_not_attempted = hard_hard_bounded_u32(planned_logical_probes)
        .saturating_sub(punch_report.logical_probes_attempted);
    crate::peer::HardHardAttemptReport {
        schema_version: crate::peer::HARD_HARD_ATTEMPT_REPORT_SCHEMA_VERSION,
        baseline_git_commit: hard_hard_safe_experiment_label(
            experiment_only,
            "P2WLAN_EXPERIMENT_BASELINE_SHA",
        )
        .unwrap_or_else(|| crate::build_info::GIT_COMMIT.to_string()),
        source_git_commit: crate::build_info::GIT_COMMIT.to_string(),
        build_id: crate::build_info::BUILD_ID.to_string(),
        experiment_variant: hard_hard_safe_experiment_label(
            experiment_only,
            "P2WLAN_EXPERIMENT_VARIANT",
        ),
        scenario_id: hard_hard_safe_experiment_label(experiment_only, "P2WLAN_EXPERIMENT_SCENARIO"),
        seed: experiment_only
            .then(|| std::env::var("P2WLAN_EXPERIMENT_SEED").ok())
            .flatten()
            .and_then(|value| value.parse().ok()),
        role: role.to_string(),
        mode: if birthday { "birthday" } else { "predictable" }.to_string(),
        session_tag: hard_hard_anonymized_tag(session_token, "session"),
        plan_tag: hard_hard_rendezvous_plan_tag(session_token),
        business_attribution_identity,
        network_generation: fresh_socket.network_generation,
        peer_session_generation: peer_session_generation.value(),
        remote_candidate_epoch: fresh_socket.remote_candidate_epoch,
        local_profile_generation: fresh_socket.local_profile_generation,
        remote_profile_generation: fresh_socket.remote_profile_generation,
        punch_generation: fresh_socket.punch_generation,
        socket_index: Some(fresh_socket.socket_index),
        attempt,
        counts: crate::peer::HardHardAttemptCounts {
            requested: hard_hard_bounded_u32(measurement.requested_candidate_count),
            generated: hard_hard_bounded_u32(measurement.generated_candidate_count),
            unique: hard_hard_bounded_u32(measurement.deduplicated_candidate_count),
            advertised: hard_hard_bounded_u32(measurement.advertised_candidate_count),
            parsed_targets_for_plan: hard_hard_bounded_u32(targets.len()),
            planned_targets: hard_hard_bounded_u32(targets.len()),
            planned_sockets: hard_hard_bounded_u32(planned_sockets),
            planned_socket_target_combinations: hard_hard_bounded_u32(
                planned_socket_target_combinations,
            ),
            planned_logical_probes: hard_hard_bounded_u32(planned_logical_probes),
            planned_physical_datagram_cap: hard_hard_bounded_u32(
                planned_logical_probes.saturating_mul(2),
            ),
            // `targets_attempted` in the sender report counts target visits
            // across repeated waves.  The attempt schema keeps that logical
            // work in `logical_probes_attempted`; this field is the distinct
            // target dimension promised by the experiment contract.
            attempted_targets: punch_report.unique_target_endpoints,
            logical_probes_attempted: punch_report.logical_probes_attempted,
            logical_probes_sent: punch_report.logical_probes_sent,
            send_success_datagrams: punch_report.physical_datagrams_sent,
            send_success_bytes: punch_report.physical_bytes_sent,
            send_errors: punch_report.physical_send_errors,
            send_error_bytes: punch_report.physical_send_error_bytes,
            budget_skipped: punch_report.budget_skipped,
            planned_logical_probes_not_attempted,
            stun_send_success_datagrams: measurement.stun_datagrams_sent,
            stun_send_success_bytes: measurement.stun_bytes_sent,
            stun_send_errors: measurement.stun_send_errors,
            stun_send_error_bytes: measurement.stun_send_error_bytes,
            stun_responses: measurement.stun_responses,
            candidate_signal_payload_logic_bytes: measurement.candidate_signal_payload_logic_bytes,
        },
        candidate_cap: hard_hard_bounded_u32(measurement.candidate_cap),
        truncation_reason: measurement.truncation_reason.clone(),
        target_order_tags: targets
            .iter()
            .map(|target| hard_hard_anonymized_tag(session_token, target))
            .collect(),
        confirmed_target_rank,
        timeline: crate::peer::HardHardAttemptTimeline {
            measurement_started_at_ms: measurement.measurement_started_at_ms,
            last_measurement_send_at_ms: measurement.last_measurement_send_at_ms,
            measurement_completed_at_ms: measurement.measurement_completed_at_ms,
            candidate_signal_accepted_at_ms: measurement.candidate_signal_accepted_at_ms,
            planned_send_at_ms: measurement.planned_send_at_ms,
            send_dispatch_at_ms,
            actual_first_send_at_ms,
            probe_last_hit_at_ms,
            probe_last_hit_source,
            encrypted_validation_completed_at_ms,
            measurement_age_at_send_ms,
            measurement_to_first_send_ms,
            schedule_deviation_ms,
            last_probe_hit_to_validation_ms,
            ..crate::peer::HardHardAttemptTimeline::default()
        },
        probe_packets_received: probe_rx.known_peer_ip_datagrams_received,
        matched_probe_acks: probe_rx.probe_acks_received,
        authenticated_probe_packets_received: probe_rx.authenticated_probe_packets_received,
        authenticated_probe_acks_unmatched: probe_rx.authenticated_probe_acks_unmatched,
        direct_confirmed,
        failure_class: hard_hard_attempt_failure_class(
            punch_report,
            probe_rx,
            direct_confirmed,
            terminal_reason,
        )
        .to_string(),
        terminal_reason: terminal_reason.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
async fn record_hard_hard_terminal_attempt(
    peers: &PeerManager,
    peer_id: &str,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    fresh_socket: &crate::peer::HardHardFreshSocketIdentity,
    session_token: &str,
    role: &'static str,
    birthday: bool,
    attempt: u8,
    measurement: &crate::peer::HardHardMeasurementObservation,
    targets: &[SocketAddr],
    planned_sockets: usize,
    planned_socket_target_combinations: usize,
    planned_logical_probes: usize,
    send_dispatch_at_ms: Option<u64>,
    punch_report: &PunchSendReport,
    probe_rx: UdpProbeRxSnapshot,
    direct_confirmed: bool,
    business_attribution_identity: Option<crate::peer::HardHardBusinessAttributionIdentity>,
    terminal_reason: &str,
) -> bool {
    let encrypted_validation_completed_at_ms = direct_confirmed
        .then(|| peers.direct_commit_pair_snapshot_sync(peer_id))
        .flatten()
        .filter(|snapshot| {
            snapshot.generation == fresh_socket.network_generation
                && snapshot.remote_candidate_epoch == fresh_socket.remote_candidate_epoch
                && snapshot.local_endpoint == Some(fresh_socket.socket_local_endpoint)
        })
        .and_then(|snapshot| snapshot.confirmed_at_ms);
    let confirmed_target_rank = if direct_confirmed {
        peers
            .selected_direct_endpoint_for_consent(peer_id)
            .await
            .and_then(|selected| targets.iter().position(|target| *target == selected))
            .and_then(|rank| u32::try_from(rank).ok())
    } else {
        None
    };
    let report = build_hard_hard_attempt_report(
        peers,
        peers.hard_hard_experiment_only(),
        peer_session_generation,
        fresh_socket,
        session_token,
        role,
        birthday,
        attempt,
        measurement,
        targets,
        planned_sockets,
        planned_socket_target_combinations,
        planned_logical_probes,
        send_dispatch_at_ms,
        punch_report,
        probe_rx,
        direct_confirmed,
        business_attribution_identity,
        encrypted_validation_completed_at_ms,
        confirmed_target_rank,
        terminal_reason,
    );
    peers
        .record_hard_hard_attempt_report(peer_id, session_token, report)
        .await
}

/// Record a live-session response which was consumed before its bounded UDP
/// sweep could begin. The session ledger remains the authority for every
/// identity field, so a delayed rejection cannot be attached to a replacement
/// peer, candidate epoch, profile, socket, or attempt.
async fn record_hard_hard_unexecuted_session_attempt(
    peers: &PeerManager,
    peer_id: &str,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    record: &HardHardSessionRecord,
    role: &'static str,
    targets: &[SocketAddr],
    terminal_reason: &str,
) -> bool {
    let planned_sockets = if record.birthday {
        record.requested_socket_indices.len()
    } else {
        1
    };
    let planned_logical_probes = if record.birthday {
        targets
            .len()
            .saturating_mul(hard_hard_birthday_wave_count(planned_sockets))
    } else {
        targets
            .len()
            .saturating_mul(HARD_HARD_SWEEP_ATTEMPTS as usize)
    };
    let planned_socket_target_combinations = if record.birthday {
        planned_logical_probes
    } else {
        targets.len()
    };
    let punch_report = PunchSendReport {
        targets_assigned: hard_hard_bounded_u32(targets.len()),
        targets_cancelled: hard_hard_bounded_u32(targets.len()),
        ..PunchSendReport::default()
    };
    record_hard_hard_terminal_attempt(
        peers,
        peer_id,
        peer_session_generation,
        &record.fresh_socket,
        &record.session_token,
        role,
        record.birthday,
        record.attempt_count,
        &record.measurement,
        targets,
        planned_sockets,
        planned_socket_target_combinations,
        planned_logical_probes,
        None,
        &punch_report,
        UdpProbeRxSnapshot::default(),
        false,
        None,
        terminal_reason,
    )
    .await
}

fn hard_hard_measurement_target_limit(measurement: &HardHardLocalMeasurement) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => HARD_HARD_MAX_PREDICTION_TARGETS,
        HardHardLocalMeasurement::Birthday(result) => {
            result.level.min(HARD_HARD_MAX_BIRTHDAY_TARGETS)
        }
    }
}

fn hard_hard_measurement_is_birthday(measurement: &HardHardLocalMeasurement) -> bool {
    matches!(measurement, HardHardLocalMeasurement::Birthday(_))
}

fn hard_hard_measurement_requested_level(measurement: &HardHardLocalMeasurement) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => 0,
        HardHardLocalMeasurement::Birthday(result) => result.requested_level,
    }
}

fn hard_hard_measurement_socket_indices(measurement: &HardHardLocalMeasurement) -> Vec<usize> {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => vec![result.socket_index],
        HardHardLocalMeasurement::Birthday(result) => result
            .sockets
            .iter()
            .map(|socket| socket.socket_index)
            .collect(),
    }
}

fn hard_hard_measurement_requested_socket_count(measurement: &HardHardLocalMeasurement) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => 1,
        HardHardLocalMeasurement::Birthday(result) => result.requested_socket_count,
    }
}

fn hard_hard_measurement_planned_dimensions(
    measurement: &HardHardLocalMeasurement,
    target_count: usize,
) -> (usize, usize, usize) {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => (
            1,
            target_count,
            target_count.saturating_mul(HARD_HARD_SWEEP_ATTEMPTS as usize),
        ),
        HardHardLocalMeasurement::Birthday(result) => {
            let sockets = result.sockets.len();
            let waves = hard_hard_birthday_wave_count(sockets);
            let combinations = target_count.saturating_mul(waves);
            (sockets, combinations, combinations)
        }
    }
}

fn hard_hard_measurement_summary(measurement: &HardHardLocalMeasurement) -> String {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => format!(
            "mode=predictable model={} confidence={} public_ip={:?} public_port_samples={:?} socket_count=1 sample_count={} target_count={}",
            hard_hard_model_label(&result.model.kind),
            result.model.confidence,
            result.public_ip,
            result.model.sequence,
            result.model.sequence.len(),
            result.predicted_ports.len(),
        ),
        HardHardLocalMeasurement::Birthday(result) => format!(
            "mode=birthday model={} strategy=bounded_birthday confidence={} level={} requested_level={} requested_socket_count={} public_ip={} public_port_samples={:?} socket_count={} sample_count={} target_count={}",
            result.model_label,
            result.model_confidence,
            result.level,
            result.requested_level,
            result.requested_socket_count,
            result.public_ip,
            result.public_port_samples,
            result.sockets.len(),
            result.observation_count,
            result.candidate_endpoints.len(),
        ),
    }
}

/// Make every speculative socket durable only after the control-plane offer
/// has succeeded. A birthday result owns one guard per socket; finalizing all
/// of them is what keeps the non-winning candidates alive until authenticated
/// peer-reflexive evidence selects one.
async fn finalize_hard_hard_measurement(measurement: &mut HardHardLocalMeasurement) -> bool {
    match measurement {
        HardHardLocalMeasurement::Predictable { handoff, .. } => handoff.finalize().await,
        HardHardLocalMeasurement::Birthday(result) => {
            let mut finalized = true;
            for socket in &result.sockets {
                if !socket.guard.finalize().await {
                    finalized = false;
                }
            }
            finalized
        }
    }
}

fn hard_hard_birthday_level_for_stage(
    android_platform: bool,
    stage: crate::peer::RecoveryStage,
) -> usize {
    let desktop_level = match stage {
        crate::peer::RecoveryStage::Initial => 64,
        crate::peer::RecoveryStage::Predicted | crate::peer::RecoveryStage::ScatterSmall => 128,
        crate::peer::RecoveryStage::ScatterExtended | crate::peer::RecoveryStage::RelayBackoff => {
            256
        }
    };
    if android_platform {
        desktop_level.min(128)
    } else {
        desktop_level
    }
}

async fn hard_hard_birthday_level(peers: &PeerManager, peer_id: &str) -> usize {
    hard_hard_birthday_level_for_stage(
        peers.is_android_platform(),
        peers.recovery_stage_for(peer_id).await,
    )
}

async fn run_hard_hard_local_measurement(
    udp: &UdpTransport,
    peers: &PeerManager,
    peer_id: &str,
    observers: &[SocketAddr],
    stun_timeout: Duration,
    session_token: &str,
    cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
) -> std::result::Result<HardHardLocalMeasurement, FreshMappingRejection> {
    if peers
        .hard_hard_plan_uses_birthday(peer_id)
        .await
        .unwrap_or(false)
    {
        let level = hard_hard_birthday_level(peers, peer_id).await;
        return udp
            .run_hard_hard_birthday_generation(
                peer_id,
                observers,
                stun_timeout,
                level,
                session_token,
                cancellation,
            )
            .await
            .map(|result| HardHardLocalMeasurement::Birthday(Box::new(result)));
    }
    match udp
        .run_hard_hard_fresh_mapping_generation(peer_id, observers, stun_timeout, cancellation)
        .await
    {
        FreshMappingOutcome::Accepted(result, handoff) => {
            if !udp
                .tag_hard_hard_socket(peer_id, result.socket_index, session_token)
                .await
            {
                return Err(FreshMappingRejection::Superseded);
            }
            Ok(HardHardLocalMeasurement::Predictable { result, handoff })
        }
        FreshMappingOutcome::Rejected(rejection) => Err(rejection),
    }
}

fn hard_hard_measurement_payload(
    measurement: &HardHardLocalMeasurement,
    boot_epoch_ms: u64,
) -> Option<HardHardMeasurementPayload> {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => {
            let strategy_candidate_cap =
                hard_hard_prediction_limit(&result.model.kind, result.model.confidence);
            let (candidates, sources) = hard_hard_prediction_payload(result, boot_epoch_ms)?;
            let (candidates, sources, candidate_contract) =
                crate::candidate_refresh::normalize_signal_candidates_with_counts(
                    &candidates,
                    &sources,
                    result.predicted_ports.len(),
                    result.predicted_ports.len(),
                );
            (!candidates.is_empty()).then_some(HardHardMeasurementPayload {
                candidates,
                candidate_sources: sources,
                local_confidence: result.model.confidence,
                local_model: hard_hard_model_label(&result.model.kind).to_string(),
                strategy_candidate_cap,
                candidate_contract,
            })
        }
        HardHardLocalMeasurement::Birthday(result) => {
            let fresh_id = FreshPredictionId {
                boot_epoch: boot_epoch_ms,
                generation: result
                    .sockets
                    .first()
                    .map(|socket| socket.punch_generation)?,
            };
            let source = fresh_prediction_source_label(fresh_id);
            let mut candidates = Vec::with_capacity(result.candidate_endpoints.len());
            let mut sources = HashMap::with_capacity(result.candidate_endpoints.len());
            for endpoint in &result.candidate_endpoints {
                let endpoint = endpoint.to_string();
                if sources.contains_key(&endpoint) {
                    continue;
                }
                sources.insert(endpoint.clone(), source.clone());
                candidates.push(endpoint);
            }
            let (candidates, sources, candidate_contract) =
                crate::candidate_refresh::normalize_signal_candidates_with_counts(
                    &candidates,
                    &sources,
                    result.requested_level,
                    candidates.len(),
                );
            (!candidates.is_empty()).then_some(HardHardMeasurementPayload {
                candidates,
                candidate_sources: sources,
                local_confidence: result.model_confidence,
                local_model: result.model_label.clone(),
                strategy_candidate_cap: result.level.min(crate::MAX_SIGNAL_CANDIDATES),
                candidate_contract,
            })
        }
    }
}

async fn record_hard_hard_candidate_contract(
    peers: &PeerManager,
    peer_id: &str,
    contract: crate::candidate_refresh::SignalCandidateContract,
    strategy_candidate_cap: usize,
    signaling_accepted: bool,
) {
    peers
        .record_direct_event(
            peer_id,
            "hard_hard_candidate_contract",
            None,
            Some(contract.signaled_candidate_count),
            None,
            format!(
                "requested_candidate_count={} generated_candidate_count={} deduplicated_candidate_count={} signaled_candidate_count={} strategy_cap={} signal_cap={} capped={} input_candidate_count={} pre_normalization_reduced_count={} candidate_source_count={} reason={} signaling_result={}",
                contract.requested_candidate_count,
                contract.generated_candidate_count,
                contract.deduplicated_candidate_count,
                contract.signaled_candidate_count,
                strategy_candidate_cap.min(contract.cap),
                contract.cap,
                contract.capped,
                contract.input_candidate_count,
                contract.pre_normalization_reduced_count,
                contract.candidate_source_count,
                contract.reason,
                if signaling_accepted { "accepted" } else { "failed" },
            ),
        )
        .await;
}

fn hard_hard_measurement_primary_socket(
    peer_id: &str,
    token: &str,
    measurement: &HardHardLocalMeasurement,
    plan: crate::peer::HardHardPlanSnapshot,
) -> Option<crate::peer::HardHardFreshSocketIdentity> {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => {
            Some(hard_hard_socket_identity(peer_id, token, result, plan))
        }
        HardHardLocalMeasurement::Birthday(result) => {
            result
                .sockets
                .first()
                .map(|socket| crate::peer::HardHardFreshSocketIdentity {
                    peer_id: peer_id.to_string(),
                    session_token: token.to_string(),
                    network_generation: plan.local_network_generation,
                    remote_candidate_epoch: plan.remote_candidate_epoch,
                    local_profile_generation: plan.local_profile_generation,
                    remote_profile_generation: plan.remote_profile_generation,
                    punch_generation: socket.punch_generation,
                    socket_index: socket.socket_index,
                    socket_local_endpoint: socket.socket_local_endpoint,
                })
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn hard_hard_wait_and_sweep(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    session: PunchSessionPermit,
    peer_id: String,
    peer_session_generation: crate::peer::PeerSessionGeneration,
    fresh_socket: crate::peer::HardHardFreshSocketIdentity,
    birthday_socket_indices: Option<Vec<usize>>,
    session_token: String,
    targets: Vec<SocketAddr>,
    requested_level: usize,
    generated_candidate_count: usize,
    signaled_candidate_count: usize,
    punch_at_ms: u64,
    network_generation: u64,
    profile_generations: (u64, u64),
    probe_session_id: Option<String>,
    origin: &'static str,
    attempt: u8,
    measurement: crate::peer::HardHardMeasurementObservation,
) -> bool {
    let socket_index = fresh_socket.socket_index;
    let birthday_waves_planned = birthday_socket_indices
        .as_ref()
        .map_or(1, |indices| hard_hard_birthday_wave_count(indices.len()));
    let planned_sockets = birthday_socket_indices.as_ref().map_or(1, Vec::len);
    let planned_logical_probes = if birthday_socket_indices.is_some() {
        targets.len().saturating_mul(birthday_waves_planned)
    } else {
        targets
            .len()
            .saturating_mul(HARD_HARD_SWEEP_ATTEMPTS as usize)
    };
    let planned_socket_target_combinations = if birthday_socket_indices.is_some() {
        planned_logical_probes
    } else {
        targets.len()
    };
    let birthday_progress = birthday_socket_indices.as_ref().map(|_| {
        Arc::new(tokio::sync::Mutex::new(BirthdaySweepProgress {
            birthday: BirthdaySweepReport {
                requested_level,
                generated_candidate_count,
                signaled_candidate_count,
                effective_target_count: targets.len().min(crate::MAX_SIGNAL_CANDIDATES),
                requested_socket_count: hard_hard_birthday_socket_count(requested_level),
                ..BirthdaySweepReport::default()
            },
            aggregate: PunchSendReport::default(),
            ..BirthdaySweepProgress::default()
        }))
    });
    let delay = punch_at_ms.saturating_sub(hard_hard_now_ms());
    if delay > 0 {
        tokio::select! {
            _ = sleep(Duration::from_millis(delay)) => {}
            _ = session.cancelled() => {
                let report = PunchSendReport {
                    targets_assigned: hard_hard_bounded_u32(targets.len()),
                    targets_cancelled: hard_hard_bounded_u32(targets.len()),
                    ..PunchSendReport::default()
                };
                let _ = record_hard_hard_terminal_attempt(
                    &peers,
                    &peer_id,
                    peer_session_generation,
                    &fresh_socket,
                    &session_token,
                    origin,
                    birthday_socket_indices.is_some(),
                    attempt,
                    &measurement,
                    &targets,
                    planned_sockets,
                    planned_socket_target_combinations,
                    planned_logical_probes,
                    None,
                    &report,
                    UdpProbeRxSnapshot::default(),
                    false,
                    None,
                    "session_cancelled",
                )
                .await;
                return false;
            },
        }
    }
    let preflight_reason = if peers.is_direct_sync(&peer_id) {
        Some("superseded_by_other_direct")
    } else if peers.current_network_generation_sync() != network_generation {
        Some("network_generation_changed")
    } else if birthday_socket_indices.is_none()
        && !udp
            .hard_hard_socket_identity_is_current(&fresh_socket)
            .await
    {
        Some("socket_revoked")
    } else if session.is_cancelled() {
        Some("session_cancelled")
    } else if !peers.peer_session_is_current_sync(&peer_id, peer_session_generation) {
        Some("peer_session_changed")
    } else {
        None
    };
    if let Some(reason) = preflight_reason {
        let report = PunchSendReport {
            targets_assigned: hard_hard_bounded_u32(targets.len()),
            targets_cancelled: hard_hard_bounded_u32(targets.len()),
            ..PunchSendReport::default()
        };
        let _ = record_hard_hard_terminal_attempt(
            &peers,
            &peer_id,
            peer_session_generation,
            &fresh_socket,
            &session_token,
            origin,
            birthday_socket_indices.is_some(),
            attempt,
            &measurement,
            &targets,
            planned_sockets,
            planned_socket_target_combinations,
            planned_logical_probes,
            None,
            &report,
            UdpProbeRxSnapshot::default(),
            false,
            None,
            reason,
        )
        .await;
        return false;
    }
    // Capture receive/commit baselines before the lifecycle marker. The
    // marker is intentionally nonblocking, and no diagnostics-map write is
    // allowed to sit in front of the first scheduled UDP send.
    let direct_commit_seq = peers.direct_commit_seq_sync(&peer_id);
    let probe_rx_before = udp
        .probe_rx_snapshot_for_peer_session(
            &peer_id,
            network_generation,
            probe_session_id.as_deref(),
        )
        .await;
    let dispatch_monotonic = Instant::now();
    let dispatch_at_ms = session.mark_first_send_started();
    peers
        .record_direct_event(
            &peer_id,
            "hard_hard_sweep_started",
            targets.first().copied(),
            Some(targets.len()),
            None,
            format!(
                "origin={origin} mode={} socket_count={} target_count={} attempt={} waves_planned={} punch_at_ms={} local_clock_ms={} sweep_deadline_ms={}",
                if birthday_socket_indices.is_some() { "birthday" } else { "predictable" },
                birthday_socket_indices.as_ref().map_or(1, Vec::len),
                targets.len(),
                if birthday_socket_indices.is_some() { 1 } else { HARD_HARD_SWEEP_ATTEMPTS },
                birthday_waves_planned,
                punch_at_ms,
                hard_hard_now_ms(),
                HARD_HARD_SWEEP_DEADLINE.as_millis(),
            ),
        )
        .await;
    let mut report = None;
    let birthday_progress_for_work = birthday_progress.clone();
    let outcome =
        run_owned_punch_session_with_deadline(&session, HARD_HARD_SWEEP_DEADLINE, async {
            report = Some(
                if let Some(socket_indices) = birthday_socket_indices.clone() {
                    udp.punch_hard_hard_birthday_candidates_with_metadata(
                        &peer_id,
                        socket_indices,
                        targets.clone(),
                        requested_level,
                        generated_candidate_count,
                        signaled_candidate_count,
                        peer_session_generation,
                        profile_generations,
                        &session_token,
                        birthday_progress_for_work,
                    )
                    .await
                } else {
                    udp.punch_candidates_from_dynamic_socket_index_with_profile_fence_and_session(
                        &peer_id,
                        socket_index,
                        targets.clone(),
                        HARD_HARD_SWEEP_INTERVAL,
                        HARD_HARD_SWEEP_ATTEMPTS,
                        Some(profile_generations),
                        Some(&session_token),
                    )
                    .await
                },
            );
        })
        .await;
    let probe_rx_after = udp
        .probe_rx_snapshot_for_peer_session(
            &peer_id,
            network_generation,
            probe_session_id.as_deref(),
        )
        .await;
    let probe_rx_delta = probe_rx_after.delta_since(probe_rx_before);
    let mut terminal_punch_report = PunchSendReport {
        targets_assigned: hard_hard_bounded_u32(targets.len()),
        targets_cancelled: hard_hard_bounded_u32(targets.len()),
        ..PunchSendReport::default()
    };
    let mut terminal_reason = "unknown".to_string();
    let mut terminal_direct_confirmed = false;
    let direct_result = match (outcome, report) {
        (PunchSessionOutcome::Completed, Some(Ok(mut report))) => {
            let worker_failure_reason = report
                .failure_kind
                .map(BirthdaySweepFailureKind::stop_reason)
                .or_else(|| {
                    report.birthday.as_ref().and_then(|birthday| {
                        match birthday.stop_reason.as_deref() {
                            Some(reason)
                                if BirthdaySweepFailureKind::from_stop_reason(reason).is_some() =>
                            {
                                Some(reason)
                            }
                            _ => None,
                        }
                    })
                });
            let worker_failed = worker_failure_reason.is_some();
            let confirmation_identity = if birthday_socket_indices.is_some() {
                peers
                    .hard_hard_fresh_socket_for_token(&peer_id, &session_token)
                    .await
                    .unwrap_or_else(|| fresh_socket.clone())
            } else {
                fresh_socket.clone()
            };
            let authenticated_winner_evidence = udp
                .hard_hard_socket_identity_has_authenticated_evidence(&confirmation_identity)
                .await;
            let authenticated_winner_selected = peers
                .hard_hard_winner_for_token(&peer_id, &session_token)
                .await
                .is_some_and(|winner| winner == confirmation_identity.socket_index);
            // An authenticated exact-socket Probe can select the winner while
            // the local worker is still before its first send.  A zero local
            // send is not proof of failure when that evidence already exists;
            // the bounded confirmation below still requires the authoritative
            // Direct commit, selected pair, and every session fence.
            let direct_confirmed = if worker_failed
                || (report.packets_sent == 0
                    && !authenticated_winner_evidence
                    && !authenticated_winner_selected)
            {
                false
            } else {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_direct_validation_started",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} socket_index={} local_endpoint={} grace_ms={} local_clock_ms={}",
                            confirmation_identity.socket_index,
                            confirmation_identity.socket_local_endpoint,
                            HARD_HARD_DIRECT_CONFIRMATION_GRACE.as_millis(),
                            hard_hard_now_ms(),
                        ),
                    )
                    .await;
                let confirmed = tokio::time::timeout(
                    HARD_HARD_DIRECT_CONFIRMATION_GRACE + Duration::from_millis(250),
                    hard_hard_wait_for_exact_direct_confirmation(
                        &udp,
                        &peers,
                        &session,
                        &confirmation_identity,
                        direct_commit_seq,
                    ),
                )
                .await
                .unwrap_or(false);
                // The Direct commit wakes the waiter from inside the path
                // transition, before the synchronous Direct mirror and the
                // recovery-owner cancellation are necessarily both visible.
                // Re-read the same authoritative exact-socket proof at the
                // terminal boundary so that expected commit/cancel ordering
                // cannot turn a completed encrypted validation into a false
                // `no_response`.  This is not a peer-global Direct fallback:
                // the helper still requires the selected pair plus the
                // token-tagged socket's own authenticated evidence.
                confirmed
                    || hard_hard_exact_direct_confirmation_is_current(
                        &udp,
                        &peers,
                        &confirmation_identity,
                    )
                    .await
            };
            let session_stop_reason = if let Some(reason) = worker_failure_reason {
                Some(reason.to_string())
            } else if direct_confirmed {
                None
            } else {
                Some("no_authenticated_direct_confirmation".to_string())
            };
            if let (Some(reason), Some(birthday)) =
                (session_stop_reason.as_deref(), report.birthday.as_mut())
            {
                birthday.stop_reason = Some(reason.to_string());
            }
            terminal_reason = session_stop_reason
                .clone()
                .unwrap_or_else(|| "direct_confirmed".to_string());
            terminal_direct_confirmed = direct_confirmed;
            terminal_punch_report = report.clone();
            let mut per_socket_counts = report.per_socket_sent.clone();
            per_socket_counts.sort_by_key(|(socket_index, _)| *socket_index);
            let per_socket_sent = per_socket_counts
                .iter()
                .map(|(socket_index, sent)| format!("{socket_index}:{sent}"))
                .collect::<Vec<_>>()
                .join(",");
            let birthday_detail = birthday_sweep_detail(&report);
            peers
                .record_direct_event_for_generation_with_socket(
                    &peer_id,
                    network_generation,
                    "hard_hard_probe_summary",
                    targets.first().copied(),
                    Some(socket_index),
                    Some(report.unique_target_endpoints as usize),
                    Some(report.logical_probes_sent.max(report.packets_sent)),
                    format!(
                        "origin={origin} mode={} sent={} logical_probes_attempted={} logical_probes_sent={} logical_probe_send_failures={} physical_datagrams_sent={} physical_send_errors={} partial_physical_send_errors={} probe_path_errors={} targets_assigned={} targets_examined={} targets_attempted={} targets_cancelled={} received={} matched_ack={} authenticated_rx={} authenticated_ack_unmatched={} target_count={} unique_targets={} budget_skipped={} first_send_at_ms={:?} last_send_at_ms={:?} per_socket_sent={}{}",
                        if birthday_detail.is_some() { "birthday" } else { "predictable" },
                        report.packets_sent,
                        report.logical_probes_attempted,
                        report.logical_probes_sent.max(report.packets_sent),
                        report.logical_probe_send_failures,
                        report.physical_datagrams_sent,
                        report.physical_send_errors,
                        report.partial_physical_send_errors,
                        report.probe_path_errors,
                        report.targets_assigned,
                        report.targets_examined,
                        report.targets_attempted,
                        report.targets_cancelled,
                        probe_rx_delta.known_peer_ip_datagrams_received,
                        probe_rx_delta.probe_acks_received,
                        probe_rx_delta.authenticated_probe_packets_received,
                        probe_rx_delta.authenticated_probe_acks_unmatched,
                        targets.len(),
                        report.unique_target_endpoints,
                        report.budget_skipped,
                        report.first_send_at_ms,
                        report.last_send_at_ms,
                        per_socket_sent,
                        birthday_detail
                            .as_deref()
                            .map(|detail| format!(" {detail}"))
                            .unwrap_or_default(),
                    ),
                )
                .await;
            record_hard_hard_birthday_sweep_summary(
                &peers,
                &peer_id,
                network_generation,
                socket_index,
                targets.first().copied(),
                report.unique_target_endpoints as usize,
                report.packets_sent,
                origin,
                &report,
                probe_rx_delta,
            )
            .await;
            if direct_confirmed {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_direct_confirmed",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} socket_index={} local_clock_ms={} exact_socket=true",
                            socket_index,
                            hard_hard_now_ms(),
                        ),
                    )
                    .await;
                peers
                    .record_direct_event_for_generation_with_socket(
                        &peer_id,
                        network_generation,
                        "hard_hard_sweep_completed",
                        targets.first().copied(),
                        Some(socket_index),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} dispatch_at_ms={dispatch_at_ms} actual_first_send_at_ms={:?} punch_at_ms={} unique_targets={} budget_skipped={} exact_socket=true direct_confirmed=true",
                            report.first_send_at_ms,
                            punch_at_ms,
                            report.unique_target_endpoints,
                            report.budget_skipped,
                        ),
                    )
                    .await;
            } else {
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_sweep_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} stop_reason={} exact-socket sweep found no authenticated Direct confirmation within {:?}",
                            session_stop_reason.as_deref().unwrap_or("no_authenticated_direct_confirmation"),
                            HARD_HARD_DIRECT_CONFIRMATION_GRACE,
                        ),
                    )
                    .await;
                peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        Some(report.packets_sent),
                        format!(
                            "origin={origin} stage=sweep reason={} stop_reason={} budget_used={}",
                            session_stop_reason
                                .as_deref()
                                .unwrap_or("no_authenticated_direct_confirmation"),
                            session_stop_reason
                                .as_deref()
                                .unwrap_or("no_authenticated_direct_confirmation"),
                            report.packets_sent,
                        ),
                    )
                    .await;
            }
            direct_confirmed
        }
        (PunchSessionOutcome::Completed, Some(Err(_error))) => {
            let partial_report = birthday_terminal_report(&birthday_progress, "send_error").await;
            let stop_reason = partial_report
                .as_ref()
                .and_then(|report| report.birthday.as_ref())
                .and_then(|birthday| birthday.stop_reason.as_deref())
                .unwrap_or("send_error")
                .to_string();
            terminal_reason = stop_reason.clone();
            if let Some(partial_report) = partial_report {
                terminal_punch_report = partial_report.clone();
                record_hard_hard_birthday_sweep_summary(
                    &peers,
                    &peer_id,
                    network_generation,
                    socket_index,
                    targets.first().copied(),
                    partial_report.unique_target_endpoints as usize,
                    partial_report.packets_sent,
                    origin,
                    &partial_report,
                    probe_rx_delta,
                )
                .await;
            }
            peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_sweep_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} stop_reason={} exact-socket sweep failed before confirmation",
                            stop_reason.as_str(),
                        ),
                    )
                    .await;
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_failed",
                    targets.first().copied(),
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} exact-socket sweep error stop_reason={}",
                        stop_reason.as_str(),
                    ),
                )
                .await;
            false
        }
        (PunchSessionOutcome::DeadlineExceeded, _) => {
            let partial_report = birthday_terminal_report(&birthday_progress, "deadline").await;
            let stop_reason = partial_report
                .as_ref()
                .and_then(|report| report.birthday.as_ref())
                .and_then(|birthday| birthday.stop_reason.as_deref())
                .unwrap_or("deadline")
                .to_string();
            terminal_reason = stop_reason.clone();
            if let Some(partial_report) = partial_report {
                terminal_punch_report = partial_report.clone();
                record_hard_hard_birthday_sweep_summary(
                    &peers,
                    &peer_id,
                    network_generation,
                    socket_index,
                    targets.first().copied(),
                    partial_report.unique_target_endpoints as usize,
                    partial_report.packets_sent,
                    origin,
                    &partial_report,
                    probe_rx_delta,
                )
                .await;
            }
            peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_sweep_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} mode={} requested_level={} effective_target_count={} waves_planned={} stop_reason={} exact-socket sweep deadline elapsed before authenticated Direct confirmation",
                            if birthday_socket_indices.is_some() { "birthday" } else { "predictable" },
                            requested_level,
                            targets.len(),
                            birthday_waves_planned,
                            stop_reason.as_str(),
                        ),
                    )
                    .await;
            peers
                    .record_direct_event(
                        &peer_id,
                        "hard_hard_failed",
                        targets.first().copied(),
                        Some(targets.len()),
                        None,
                        format!(
                            "origin={origin} mode={} stage=sweep reason={} stop_reason={} requested_level={} effective_target_count={} budget_ms={}",
                            if birthday_socket_indices.is_some() { "birthday" } else { "predictable" },
                            stop_reason.as_str(),
                            stop_reason.as_str(),
                            requested_level,
                            targets.len(),
                            HARD_HARD_SWEEP_DEADLINE.as_millis(),
                        ),
                    )
                    .await;
            false
        }
        (PunchSessionOutcome::Cancelled, _) => {
            let cancellation_reason = session
                .cancellation_reason()
                .map(PunchCancellationReason::label)
                .unwrap_or("unknown");
            let partial_report =
                birthday_terminal_report(&birthday_progress, "session_cancelled").await;
            let stop_reason = partial_report
                .as_ref()
                .and_then(|report| report.birthday.as_ref())
                .and_then(|birthday| birthday.stop_reason.as_deref())
                .unwrap_or("session_cancelled")
                .to_string();
            terminal_reason = stop_reason.clone();
            if let Some(partial_report) = partial_report {
                terminal_punch_report = partial_report.clone();
                record_hard_hard_birthday_sweep_summary(
                    &peers,
                    &peer_id,
                    network_generation,
                    socket_index,
                    targets.first().copied(),
                    partial_report.unique_target_endpoints as usize,
                    partial_report.packets_sent,
                    origin,
                    &partial_report,
                    probe_rx_delta,
                )
                .await;
            }
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_sweep_failed",
                    targets.first().copied(),
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} mode={} requested_level={} effective_target_count={} waves_planned={} stop_reason={} cancellation_reason={cancellation_reason}",
                        if birthday_socket_indices.is_some() {
                            "birthday"
                        } else {
                            "predictable"
                        },
                        requested_level,
                        targets.len(),
                        birthday_waves_planned,
                        stop_reason.as_str(),
                    ),
                )
                .await;
            peers
                .record_direct_event(
                    &peer_id,
                    "hard_hard_failed",
                    targets.first().copied(),
                    Some(targets.len()),
                    None,
                    format!(
                        "origin={origin} mode={} stage=sweep reason={} stop_reason={} cancellation_reason={cancellation_reason}",
                        if birthday_socket_indices.is_some() {
                            "birthday"
                        } else {
                            "predictable"
                        },
                        stop_reason.as_str(),
                        stop_reason.as_str(),
                    ),
                )
                .await;
            false
        }
        _ => false,
    };
    let send_dispatch_at_ms = peers.timeline_uptime_ms().map(|now| {
        now.saturating_sub(
            dispatch_monotonic
                .elapsed()
                .as_millis()
                .min(u64::MAX as u128) as u64,
        )
    });
    // Birthday evidence can select a socket other than the first measured
    // socket. The manager deliberately fences reports to the current winner,
    // so stamp the terminal report with that same authoritative identity.
    let terminal_socket_identity = if birthday_socket_indices.is_some() {
        peers
            .hard_hard_fresh_socket_for_token(&peer_id, &session_token)
            .await
            .unwrap_or_else(|| fresh_socket.clone())
    } else {
        fresh_socket.clone()
    };
    let business_attribution_identity = terminal_direct_confirmed
        .then(|| udp.hard_hard_business_attribution_identity(&peer_id))
        .flatten();
    let _ = record_hard_hard_terminal_attempt(
        &peers,
        &peer_id,
        peer_session_generation,
        &terminal_socket_identity,
        &session_token,
        origin,
        birthday_socket_indices.is_some(),
        attempt,
        &measurement,
        &targets,
        planned_sockets,
        planned_socket_target_combinations,
        planned_logical_probes,
        send_dispatch_at_ms,
        &terminal_punch_report,
        probe_rx_delta,
        terminal_direct_confirmed,
        business_attribution_identity,
        &terminal_reason,
    )
    .await;
    direct_result
}

fn birthday_sweep_detail(report: &PunchSendReport) -> Option<String> {
    let birthday = report.birthday.as_ref()?;
    let mut per_socket_counts = report.per_socket_sent.clone();
    per_socket_counts.sort_by_key(|(socket_index, _)| *socket_index);
    let per_socket_sent = per_socket_counts
        .iter()
        .map(|(socket_index, sent)| format!("{socket_index}:{sent}"))
        .collect::<Vec<_>>()
        .join(",");
    let physical_datagrams_sent = per_socket_counts
        .iter()
        .map(|(_, sent)| *sent as usize)
        .sum::<usize>();
    Some(format!(
        "requested_level={} generated_candidate_count={} signaled_candidate_count={} effective_target_count={} requested_socket_count={} attached_socket_count={} usable_socket_count={} unavailable_socket_count={} socket_count={} degraded_reason={} waves_planned={} waves_started={} waves_fully_completed={} waves_completed={} targets_assigned={} targets_examined={} targets_attempted={} logical_probes_attempted={} logical_probes_sent={} logical_probe_send_failures={} physical_datagrams_sent={} physical_send_errors={} partial_physical_send_errors={} probe_path_errors={} failure_kind={:?} targets_budget_skipped={} targets_cancelled={} packets_planned={} packets_sent={} unique_target_endpoints={} budget_skipped={} per_socket_sent={} first_send_at_ms={:?} last_send_at_ms={:?} stop_reason={}",
        birthday.requested_level,
        birthday.generated_candidate_count,
        birthday.signaled_candidate_count,
        birthday.effective_target_count,
        birthday.requested_socket_count,
        birthday.attached_socket_count,
        birthday.usable_socket_count,
        birthday.unavailable_socket_count,
        birthday.socket_count,
        birthday.degraded_reason.as_deref().unwrap_or("none"),
        birthday.waves_planned,
        birthday.waves_started,
        birthday.waves_fully_completed,
        birthday.waves_completed,
        birthday.targets_assigned,
        birthday.targets_examined,
        birthday.targets_attempted,
        birthday.logical_probes_attempted,
        birthday.logical_probes_sent,
        birthday.logical_probe_send_failures,
        physical_datagrams_sent,
        birthday.physical_send_errors,
        birthday.partial_physical_send_errors,
        report.probe_path_errors,
        report.failure_kind,
        birthday.targets_budget_skipped,
        birthday.targets_cancelled,
        birthday.packets_planned,
        report.packets_sent,
        report.unique_target_endpoints,
        report.budget_skipped,
        per_socket_sent,
        report.first_send_at_ms,
        report.last_send_at_ms,
        birthday.stop_reason.as_deref().unwrap_or("unknown"),
    ))
}

#[allow(clippy::too_many_arguments)]
async fn record_hard_hard_birthday_sweep_summary(
    peers: &PeerManager,
    peer_id: &str,
    network_generation: u64,
    socket_index: usize,
    target: Option<SocketAddr>,
    unique_target_count: usize,
    packets_sent: u32,
    origin: &str,
    report: &PunchSendReport,
    probe_rx_delta: UdpProbeRxSnapshot,
) {
    let Some(detail) = birthday_sweep_detail(report) else {
        return;
    };
    peers
        .record_direct_event_for_generation_with_socket(
            peer_id,
            network_generation,
            "hard_hard_birthday_sweep_summary",
            target,
            Some(socket_index),
            Some(unique_target_count),
            Some(packets_sent),
            format!(
                "origin={origin} mode=birthday {detail} known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} matched_probe_ack_rx_delta={} authenticated_probe_ack_unmatched_delta={}",
                probe_rx_delta.known_peer_ip_datagrams_received,
                probe_rx_delta.authenticated_probe_packets_received,
                probe_rx_delta.probe_acks_received,
                probe_rx_delta.authenticated_probe_acks_unmatched,
            ),
        )
        .await;
}

async fn birthday_terminal_report(
    progress: &Option<Arc<tokio::sync::Mutex<BirthdaySweepProgress>>>,
    stop_reason: &str,
) -> Option<PunchSendReport> {
    let progress = progress.as_ref()?;
    let (mut report, mut birthday, live) = {
        let current = progress.lock().await;
        (
            current.aggregate.clone(),
            current.birthday.clone(),
            current.live.clone(),
        )
    };
    let live_snapshot = live
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    apply_live_birthday_counters(&mut report, &live_snapshot);
    report.unique_target_endpoints =
        u32::try_from(report.sent_target_endpoints.len()).unwrap_or(u32::MAX);
    if birthday.stop_reason.is_none() {
        birthday.stop_reason = Some(
            report
                .failure_kind
                .map(BirthdaySweepFailureKind::stop_reason)
                .unwrap_or(stop_reason)
                .to_string(),
        );
    }
    birthday.waves_completed = birthday.waves_fully_completed;
    report.targets_assigned = report
        .targets_assigned
        .max(u32::try_from(birthday.targets_assigned).unwrap_or(u32::MAX));
    report.targets_cancelled = report.targets_cancelled.max(
        report
            .targets_assigned
            .saturating_sub(report.targets_attempted),
    );
    update_birthday_sweep_counters(&mut birthday, &report);
    report.birthday = Some(birthday);
    Some(report)
}
