async fn run_direct_probe_loop(
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    local_candidates: Arc<RwLock<Vec<String>>>,
    punch_deduplicator: PunchAttemptDeduplicator,
    retry_after: Duration,
    probe_interval: Duration,
    attempts: u32,
) {
    if retry_after.is_zero() || attempts == 0 {
        return;
    }

    let mut ticker = interval(retry_after);
    loop {
        ticker.tick().await;

        let Some(udp) = udp_transport.read().await.clone() else {
            continue;
        };

        if local_candidates.read().await.is_empty() {
            debug!("Local UDP candidates are not ready; delaying background Direct probe cycle");
            continue;
        }

        for (peer_id, candidates) in peers.direct_probe_targets_due(retry_after).await {
            let reclaim_active = peers.direct_reclaim_active(&peer_id).await;
            let dedup_window = if reclaim_active {
                DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW
            } else {
                PUNCH_SESSION_DEDUP_WINDOW
            };
            let Some(session) = punch_deduplicator
                .claim_with_window(&peer_id, dedup_window)
                .await
            else {
                peers
                    .record_direct_event(
                        &peer_id,
                        if reclaim_active {
                            "direct_reclaim_punch_suppressed"
                        } else {
                            "retry_punch_suppressed"
                        },
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        if reclaim_active {
                            "suppressed overlapping UDP Direct reclaim session for this peer"
                        } else {
                            "suppressed overlapping UDP retry session for this peer"
                        },
                    )
                    .await;
                continue;
            };
            let udp = udp.clone();
            let peers = peers.clone();
            let attempts = peers.recommended_punch_attempts(attempts).await;
            let generation = peers.current_network_generation().await;
            tokio::spawn(async move {
                let outcome = run_owned_punch_session(&session, async {
                    let punch_started_stage = if reclaim_active {
                        "direct_reclaim_punch_started"
                    } else {
                        "retry_punch_started"
                    };
                    let probes_sent_stage = if reclaim_active {
                        "direct_reclaim_probes_sent"
                    } else {
                        "retry_probes_sent"
                    };
                    let ack_timeout_stage = if reclaim_active {
                        "direct_reclaim_ack_timeout"
                    } else {
                        "retry_ack_timeout"
                    };
                    let probe_succeeded_stage = if reclaim_active {
                        "direct_reclaim_probe_succeeded"
                    } else {
                        "retry_probe_succeeded"
                    };
                    let send_error_stage = if reclaim_active {
                        "direct_reclaim_send_error"
                    } else {
                        "retry_send_error"
                    };
                    let retry_label = if reclaim_active {
                        "generation-change Direct reclaim"
                    } else {
                        "background UDP retry"
                    };
                    let success_count_before = peers
                        .direct_probe_success_count_for_generation(&peer_id, generation)
                        .await;
                    peers
                        .record_direct_event(
                            &peer_id,
                            punch_started_stage,
                            candidates.first().copied(),
                            Some(candidates.len()),
                            None,
                            format!(
                                "starting {retry_label} across {} candidates",
                                candidates.len()
                            ),
                        )
                        .await;
                    match udp
                        .punch_candidates(&peer_id, candidates.clone(), probe_interval, attempts)
                        .await
                    {
                        Ok(0) => {}
                        Ok(sent) => {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    probes_sent_stage,
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    Some(sent),
                                    format!("sent {sent} {retry_label} probes"),
                                )
                                .await;
                            sleep(direct_probe_ack_grace(probe_interval)).await;
                            let success_count_after = peers
                                .direct_probe_success_count_for_generation(&peer_id, generation)
                                .await;
                            if success_count_after == success_count_before {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        ack_timeout_stage,
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        Some(sent),
                                        format!(
                                            "no direct probe ACK after {sent} {retry_label} probes"
                                        ),
                                    )
                                    .await;
                                peers
                                    .record_direct_failure_for_generation(
                                        &peer_id,
                                        generation,
                                        REASON_DIRECT_PROBE_FAILED,
                                        format!(
                                            "no direct probe ACK after {sent} {retry_label} probes"
                                        ),
                                    )
                                    .await;
                                debug!(
                                    "Direct UDP retry probes for peer {peer_id} received no ACK"
                                );
                            } else {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        probe_succeeded_stage,
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        Some(sent),
                                        format!(
                                            "{retry_label} received an ACK; awaiting encrypted validation"
                                        ),
                                    )
                                    .await;
                                debug!(
                                    "Direct UDP retry probes reached peer {peer_id}; awaiting encrypted validation"
                                );
                            }
                        }
                        Err(err) => {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    send_error_stage,
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    None,
                                    format!("{retry_label} failed: {err}"),
                                )
                                .await;
                            peers
                                .record_direct_failure_for_generation(
                                    &peer_id,
                                    generation,
                                    REASON_DIRECT_PROBE_FAILED,
                                    format!("{retry_label} failed: {err}"),
                                )
                                .await;
                            warn!("Failed to retry direct UDP probes for peer {peer_id}: {err}");
                        }
                    }
                })
                .await;

                match outcome {
                    PunchSessionOutcome::Completed => {}
                    PunchSessionOutcome::Cancelled => {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "retry_session_cancelled",
                                None,
                                None,
                                None,
                                "cancelled background UDP retry for a synchronized punch",
                            )
                            .await;
                    }
                    PunchSessionOutcome::DeadlineExceeded => {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "retry_session_deadline",
                                None,
                                None,
                                None,
                                format!(
                                    "stopped background UDP retry after {}ms hard deadline",
                                    PUNCH_SESSION_HARD_DEADLINE.as_millis()
                                ),
                            )
                            .await;
                    }
                }
            });
        }
    }
}
