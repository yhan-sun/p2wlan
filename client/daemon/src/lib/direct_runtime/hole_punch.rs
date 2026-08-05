async fn spawn_hole_punch_task(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    probe_interval: Duration,
    attempts: u32,
    punch_at_ms: Option<u64>,
) {
    let Some(session) = punch_deduplicator.claim(&peer_id).await else {
        peers
            .record_direct_event(
                &peer_id,
                "punch_suppressed",
                None,
                None,
                None,
                "suppressed overlapping UDP punch session for this peer",
            )
            .await;
        debug!("Suppressing overlapping UDP punch session for {peer_id}");
        return;
    };
    let punch_delay = relay_assisted_punch_delay(punch_at_ms);
    if !punch_delay.is_zero() {
        debug!(
            "Scheduling relay-assisted UDP punch to peer {peer_id} in {}ms",
            punch_delay.as_millis()
        );
    }

    tokio::spawn(async move {
        peers
            .record_direct_event(
                &peer_id,
                "punch_scheduled",
                None,
                None,
                None,
                format!(
                    "scheduled relay-assisted UDP punch delay_ms={} punch_at_ms={punch_at_ms:?}",
                    punch_delay.as_millis()
                ),
            )
            .await;
        if !punch_delay.is_zero() {
            sleep(punch_delay).await;
        }

        let generation = peers.current_network_generation().await;
        let Some(target) = peers.direct_probe_target_set_for(&peer_id).await else {
            if peers.is_direct(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_skipped_already_direct",
                        None,
                        None,
                        None,
                        "skipped UDP punch because Direct path is already confirmed",
                    )
                    .await;
                debug!("Skipping UDP punch for {peer_id}; Direct path is already confirmed");
                return;
            }
            debug!("No UDP candidates for {peer_id}; skipping hole punch");
            peers
                .record_direct_failure_for_generation(
                    &peer_id,
                    generation,
                    REASON_DIRECT_PROBE_FAILED,
                    "no UDP candidates for hole punching",
                )
                .await;
            return;
        };
        let candidates = target.candidates;
        let remote_scatter_pool = target.remote_scatter_pool;
        let stable_remote_scatter = target.stable_remote_scatter;
        let birthday_plan = target.birthday_plan;
        if candidates.is_empty() {
            if peers.is_direct(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_skipped_already_direct",
                        None,
                        None,
                        None,
                        "skipped UDP punch because Direct path is already confirmed",
                    )
                    .await;
                debug!("Skipping UDP punch for {peer_id}; Direct path is already confirmed");
                return;
            }
            debug!("No UDP candidates for {peer_id}; skipping hole punch");
            peers
                .record_direct_failure_for_generation(
                    &peer_id,
                    generation,
                    REASON_DIRECT_PROBE_FAILED,
                    "no UDP candidates for hole punching",
                )
                .await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "punch_started",
                candidates.first().copied(),
                Some(candidates.len()),
                None,
                format!(
                    "starting synchronized UDP punch across {} candidates",
                    candidates.len()
                ),
            )
            .await;
        if let Some(plan) = birthday_plan.as_ref() {
            peers
                .record_birthday_probe_plan_started(&peer_id, plan)
                .await;
        }

        for endpoint in peers.direct_nat_maintainer_targets_for(&peer_id).await {
            udp.spawn_nat_binding_maintainer(
                &peer_id,
                endpoint,
                HARD_NAT_MAINTAINER_CONNECTING_INTERVAL,
                HARD_NAT_MAINTAINER_CONNECTING_DURATION,
            )
            .await;
        }

        let success_count_before = peers
            .direct_probe_success_count_for_generation(&peer_id, generation)
            .await;

        let rx_before = udp.probe_rx_snapshot().await;
        let deadline = punch_session_deadline(
            &candidates,
            probe_interval,
            attempts,
            remote_scatter_pool,
            if stable_remote_scatter {
                1
            } else {
                udp.socket_count()
            },
        );
        let outcome = run_owned_punch_session_with_deadline(&session, deadline, async {
            let punch_result = if stable_remote_scatter {
                udp.punch_candidates_stable_unique_scatter(
                    &peer_id,
                    candidates.clone(),
                    probe_interval,
                    attempts,
                )
                .await
            } else if remote_scatter_pool {
                udp.punch_candidates_remote_scatter_pool(
                    &peer_id,
                    candidates.clone(),
                    probe_interval,
                    attempts,
                )
                .await
                .map(|sent| PunchSendReport {
                    packets_sent: sent,
                    unique_target_endpoints: 0,
                })
            } else {
                udp.punch_candidates(&peer_id, candidates.clone(), probe_interval, attempts)
                    .await
                    .map(|sent| PunchSendReport {
                        packets_sent: sent,
                        unique_target_endpoints: 0,
                    })
            };

            match punch_result {
                Ok(report) => {
                    let sent = report.packets_sent;
                    let birthday_window_completion = if let Some(plan) =
                        birthday_plan.as_ref().filter(|_| stable_remote_scatter)
                    {
                        let covered_all_selected_candidates = stable_remote_scatter
                            && report.unique_target_endpoints as usize >= candidates.len();
                        let cursor_advanced = peers
                            .commit_birthday_probe_cursor(
                                &peer_id,
                                plan,
                                covered_all_selected_candidates,
                            )
                            .await;
                        peers
                            .record_direct_event(
                                &peer_id,
                                "birthday_probe_plan_completed",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                format!(
                                    "stable_side={} unique_target_endpoints={} covered_all_selected_candidates={} cursor_advanced={} start_rank={} end_rank={}",
                                    stable_remote_scatter,
                                    report.unique_target_endpoints,
                                    covered_all_selected_candidates,
                                    cursor_advanced,
                                    plan.start_rank,
                                    plan.end_rank
                                ),
                            )
                            .await;
                        Some((cursor_advanced, plan.wrapped))
                    } else {
                        None
                    };
                    info!("Sent {sent} UDP punch probes to peer {peer_id}");
                    peers
                        .record_direct_event(
                            &peer_id,
                            "punch_probes_sent",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            Some(sent),
                            format!(
                                "sent {sent} UDP punch probes across {} candidates",
                                candidates.len()
                            ),
                        )
                        .await;
                    sleep(direct_probe_ack_grace(probe_interval)).await;
                    let success_count_after = peers
                        .direct_probe_success_count_for_generation(&peer_id, generation)
                        .await;
                    let rx_delta = udp.probe_rx_snapshot().await.delta_since(rx_before);
                    if sent > 0 && success_count_after == success_count_before {
                        let timeout_detail = format!(
                            "no matched UDP punch ACK after {sent} probes; known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
                            rx_delta.known_peer_ip_datagrams_received,
                            rx_delta.authenticated_probe_packets_received,
                            rx_delta.authenticated_probe_acks_observed,
                            rx_delta.authenticated_probe_acks_unmatched,
                            rx_delta.legacy_probe_acks_observed,
                            rx_delta.legacy_probe_acks_unmatched,
                            rx_delta.probe_acks_received
                        );
                        peers
                            .record_direct_event(
                                &peer_id,
                                "punch_ack_timeout",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                timeout_detail.clone(),
                            )
                            .await;
                        match birthday_window_completion {
                            Some((true, completed_epoch)) => {
                                peers
                                    .record_expected_birthday_window_miss_for_generation(
                                        &peer_id,
                                        generation,
                                        &candidates,
                                        completed_epoch,
                                        timeout_detail,
                                    )
                                    .await;
                            }
                            Some((false, _)) => {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "birthday_probe_window_incomplete",
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        Some(sent),
                                        "stable-side birthday window was not fully sent or its cursor became stale; retaining short retry cadence without peer backoff",
                                    )
                                    .await;
                            }
                            None if peers.has_relay_safety_net(&peer_id).await => {
                                peers
                                    .record_direct_probe_batch_failure_for_generation(
                                        &peer_id,
                                        generation,
                                        timeout_detail,
                                    )
                                    .await;
                            }
                            None => {}
                        }
                    }
                }
                Err(err) => {
                    peers
                        .record_direct_event(
                            &peer_id,
                            "punch_send_error",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            None,
                            format!("hole punch failed: {err}"),
                        )
                        .await;
                    peers
                        .record_direct_failure_for_generation(
                            &peer_id,
                            generation,
                            REASON_DIRECT_PROBE_FAILED,
                            format!("hole punch failed: {err}"),
                        )
                        .await;
                    warn!("Failed to punch peer {peer_id}: {err}");
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
                        "punch_session_cancelled",
                        None,
                        None,
                        None,
                        "cancelled stale UDP punch session before replacement",
                    )
                    .await;
            }
            PunchSessionOutcome::DeadlineExceeded => {
                let rx_delta = udp.probe_rx_snapshot().await.delta_since(rx_before);
                let timeout_detail = format!(
                    "synchronized UDP punch session stopped after {}ms deadline; known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
                    deadline.as_millis(),
                    rx_delta.known_peer_ip_datagrams_received,
                    rx_delta.authenticated_probe_packets_received,
                    rx_delta.authenticated_probe_acks_observed,
                    rx_delta.authenticated_probe_acks_unmatched,
                    rx_delta.legacy_probe_acks_observed,
                    rx_delta.legacy_probe_acks_unmatched,
                    rx_delta.probe_acks_received
                );
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_session_deadline",
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        timeout_detail.clone(),
                    )
                    .await;
                if stable_remote_scatter && birthday_plan.is_some() {
                    peers
                        .record_direct_event(
                            &peer_id,
                            "birthday_probe_window_incomplete",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            None,
                            "stable-side birthday session hit its deadline before a complete send report; cursor and peer backoff were left unchanged",
                        )
                        .await;
                } else if peers.has_relay_safety_net(&peer_id).await {
                    peers
                        .record_direct_probe_batch_failure_for_generation(
                            &peer_id,
                            generation,
                            timeout_detail,
                        )
                        .await;
                }
            }
        }
    });
}
