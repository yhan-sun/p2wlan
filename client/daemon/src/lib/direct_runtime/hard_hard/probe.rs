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
    candidate_contract: crate::candidate_refresh::SignalCandidateContract,
}

fn hard_hard_measurement_target_limit(measurement: &HardHardLocalMeasurement) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => HARD_HARD_MAX_PREDICTION_TARGETS,
        HardHardLocalMeasurement::Birthday(result) => result
            .level
            .min(HARD_HARD_MAX_BIRTHDAY_TARGETS),
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

fn hard_hard_measurement_requested_socket_count(
    measurement: &HardHardLocalMeasurement,
) -> usize {
    match measurement {
        HardHardLocalMeasurement::Predictable { .. } => 1,
        HardHardLocalMeasurement::Birthday(result) => result.requested_socket_count,
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
) -> Option<HardHardLocalMeasurement> {
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
            .ok()
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
                return None;
            }
            Some(HardHardLocalMeasurement::Predictable { result, handoff })
        }
        FreshMappingOutcome::Rejected(_) => None,
    }
}

fn hard_hard_measurement_payload(
    measurement: &HardHardLocalMeasurement,
    boot_epoch_ms: u64,
) -> Option<HardHardMeasurementPayload> {
    match measurement {
        HardHardLocalMeasurement::Predictable { result, .. } => {
            let (candidates, sources) = hard_hard_prediction_payload(result, boot_epoch_ms)?;
            let (candidates, sources, candidate_contract) =
                crate::candidate_refresh::normalize_signal_candidates_with_counts(
                    &candidates,
                    &sources,
                    result
                        .predicted_ports
                        .len()
                        .min(HARD_HARD_MAX_PREDICTION_TARGETS),
                    candidates.len(),
                );
            (!candidates.is_empty()).then_some(HardHardMeasurementPayload {
                candidates,
                candidate_sources: sources,
                local_confidence: result.model.confidence,
                local_model: hard_hard_model_label(&result.model.kind).to_string(),
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
                candidate_contract,
            })
        }
    }
}

async fn record_hard_hard_candidate_contract(
    peers: &PeerManager,
    peer_id: &str,
    contract: crate::candidate_refresh::SignalCandidateContract,
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
                "requested_candidate_count={} generated_candidate_count={} deduplicated_candidate_count={} signaled_candidate_count={} cap={} capped={} candidate_source_count={} reason={} signaling_result={}",
                contract.requested_candidate_count,
                contract.generated_candidate_count,
                contract.deduplicated_candidate_count,
                contract.signaled_candidate_count,
                contract.cap,
                contract.capped,
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
        HardHardLocalMeasurement::Birthday(result) => result.sockets.first().map(|socket| {
            crate::peer::HardHardFreshSocketIdentity {
                peer_id: peer_id.to_string(),
                session_token: token.to_string(),
                network_generation: plan.local_network_generation,
                remote_candidate_epoch: plan.remote_candidate_epoch,
                local_profile_generation: plan.local_profile_generation,
                remote_profile_generation: plan.remote_profile_generation,
                punch_generation: socket.punch_generation,
                socket_index: socket.socket_index,
                socket_local_endpoint: socket.socket_local_endpoint,
            }
        }),
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
) -> bool {
    let socket_index = fresh_socket.socket_index;
    let birthday_waves_planned = birthday_socket_indices.as_ref().map_or(1, |indices| {
        hard_hard_birthday_wave_count(indices.len())
    });
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
            _ = session.cancelled() => return false,
        }
    }
    if peers.is_direct_sync(&peer_id)
        || peers.current_network_generation_sync() != network_generation
        || (birthday_socket_indices.is_none()
            && !udp
                .hard_hard_socket_identity_is_current(&fresh_socket)
                .await)
        || session.is_cancelled()
        || !peers.peer_session_is_current_sync(&peer_id, peer_session_generation)
    {
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
    let outcome = run_owned_punch_session_with_deadline(&session, HARD_HARD_SWEEP_DEADLINE, async {
        report = Some(if let Some(socket_indices) = birthday_socket_indices.clone() {
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
        });
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
    match (outcome, report) {
        (PunchSessionOutcome::Completed, Some(Ok(mut report))) => {
            let worker_failure_reason = report
                .failure_kind
                .map(BirthdaySweepFailureKind::stop_reason)
                .or_else(|| {
                    report.birthday.as_ref().and_then(|birthday| match birthday
                        .stop_reason
                        .as_deref()
                    {
                        Some(reason) if BirthdaySweepFailureKind::from_stop_reason(reason).is_some() => {
                            Some(reason)
                        }
                        _ => None,
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
                confirmed
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
                            session_stop_reason.as_deref().unwrap_or("no_authenticated_direct_confirmation"),
                            session_stop_reason.as_deref().unwrap_or("no_authenticated_direct_confirmation"),
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
            if let Some(partial_report) = partial_report {
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
            if let Some(partial_report) = partial_report {
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
            if let Some(partial_report) = partial_report {
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
    }
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
