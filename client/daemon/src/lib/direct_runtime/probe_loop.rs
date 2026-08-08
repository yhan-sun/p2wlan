#[allow(clippy::too_many_arguments)]
async fn run_direct_probe_loop(
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    punch_deduplicator: PunchAttemptDeduplicator,
    control: ControlClient,
    stun_servers: Arc<RwLock<Vec<SocketAddr>>>,
    stun_timeout: Arc<RwLock<Duration>>,
    boot_epoch_ms: u64,
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

        for target in peers.direct_probe_targets_due(retry_after).await {
            let peer_id = target.peer_id;
            let candidates = target.candidates;
            let remote_scatter_pool = target.remote_scatter_pool;
            let stable_remote_scatter = target.stable_remote_scatter;
            let birthday_plan = target.birthday_plan;
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
            let signal = {
                let stun_servers = stun_servers.read().await.clone();
                let stun_timeout = *stun_timeout.read().await;
                HolePunchSignalContext {
                    control: control.clone(),
                    local_candidates: local_candidates.clone(),
                    local_candidate_sources: local_candidate_sources.clone(),
                    stun_servers,
                    stun_timeout,
                    boot_epoch_ms,
                }
            };
            let attempts = peers.recommended_punch_attempts(attempts).await;
            let generation = peers.current_network_generation().await;
            tokio::spawn(async move {
                let rx_before = udp.probe_rx_snapshot().await;
                let mut last_punch_report: Option<PunchSendReport> = None;
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
                    if session.is_cancelled() {
                        return;
                    }
                    // Direct may have been confirmed between target selection
                    // and this cycle: the bounded retry must not send into a
                    // confirmed path.  Recovery re-enters this loop through the
                    // reclaim window after a Direct health failure or a
                    // network-generation change.
                    if peers.is_direct(&peer_id).await {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "retry_skipped_direct_confirmed",
                                None,
                                None,
                                None,
                                "skipped background UDP retry because Direct was confirmed after target selection",
                            )
                            .await;
                        return;
                    }
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
                    if let Some(plan) = birthday_plan.as_ref() {
                        peers
                            .record_birthday_probe_plan_started(&peer_id, plan)
                            .await;
                    }

                    // Fresh-mapping generation: measure a fresh socket and
                    // create a predictable peer-facing mapping before the
                    // ordinary candidate sweep.
                    let fresh_generation = {
                        let targets = peers.stable_remote_punch_targets_for(&peer_id).await;
                        let mut generation = udp
                            .run_fresh_mapping_generation(
                                &peer_id,
                                &signal.stun_servers,
                                signal.stun_timeout,
                                &targets,
                                probe_interval,
                                attempts.min(2),
                                Some(&session.cancellation_handle()),
                            )
                            .await;
                        match &mut generation {
                            FreshMappingOutcome::Accepted(result, handoff) => {
                                if session.is_cancelled() {
                                    peers
                                        .record_direct_event(
                                            &peer_id,
                                            "fresh_mapping_skipped",
                                            None,
                                            None,
                                            None,
                                            "fresh-mapping generation completed but its punch session was superseded; not advertising the prediction",
                                        )
                                        .await;
                                } else {
                                    // The durable handoff happens only after
                                    // the prediction is really advertised: a
                                    // send failure or a cancellation during
                                    // the advertise keeps the socket
                                    // rollable.
                                    let advertised = advertise_fresh_mapping_prediction(
                                        &signal,
                                        &peers,
                                        &peer_id,
                                        &*result,
                                        &session.cancellation_handle(),
                                    )
                                    .await;
                                    if advertised {
                                        if !handoff.finalize().await {
                                            peers
                                                .record_direct_event(
                                                    &peer_id,
                                                    "fresh_mapping_skipped",
                                                    None,
                                                    None,
                                                    None,
                                                    "fresh-mapping prediction was advertised but the socket was rolled back before the durable handoff; continuing with ordinary punching",
                                                )
                                                .await;
                                        }
                                    } else {
                                        peers
                                            .record_direct_event(
                                                &peer_id,
                                                "fresh_mapping_skipped",
                                                None,
                                                None,
                                                None,
                                                "fresh-mapping prediction was not advertised; the generation's socket rolls back to the previous path",
                                            )
                                            .await;
                                    }
                                }
                            }
                            FreshMappingOutcome::Rejected(reason) => {
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "fresh_mapping_skipped",
                                        None,
                                        None,
                                        None,
                                        format!(
                                            "fresh-mapping generation skipped: {}",
                                            reason.label()
                                        ),
                                    )
                                    .await;
                            }
                        }
                        generation
                    };

                    for endpoint in peers.direct_nat_maintainer_targets_for(&peer_id).await {
                        udp.spawn_nat_binding_maintainer(
                            &peer_id,
                            endpoint,
                            HARD_NAT_MAINTAINER_CONNECTING_INTERVAL,
                            HARD_NAT_MAINTAINER_CONNECTING_DURATION,
                        )
                        .await;
                    }
                    let punch_result = if matches!(fresh_generation, FreshMappingOutcome::Accepted(..))
                        && udp.has_dynamic_socket_for_peer(&peer_id).await
                    {
                        udp.punch_candidates_from_dynamic_socket(
                            &peer_id,
                            candidates.clone(),
                            probe_interval,
                            attempts,
                        )
                        .await
                    } else if stable_remote_scatter {
                        udp.punch_candidates_stable_unique_scatter_until_not_direct(
                            &peer_id,
                            candidates.clone(),
                            probe_interval,
                            attempts,
                        )
                        .await
                    } else if remote_scatter_pool {
                        udp.punch_candidates_remote_scatter_pool_until_not_direct(
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
                        udp.punch_candidates_until_not_direct(
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
                    };

                    match punch_result {
                        Ok(report) if report.packets_sent == 0 => {}
                        Ok(report) => {
                            last_punch_report = Some(report);
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
                            let rx_delta = udp.probe_rx_snapshot().await.delta_since(rx_before);
                            if success_count_after == success_count_before {
                                let timeout_detail = format!(
                                    "no matched direct probe ACK after {sent} {retry_label} probes; known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
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
                                        ack_timeout_stage,
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
                                    None => {
                                        peers
                                            .record_direct_probe_batch_failure_for_generation(
                                                &peer_id,
                                                generation,
                                                timeout_detail,
                                            )
                                            .await;
                                    }
                                }
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
                                .record_direct_probe_batch_failure_for_generation(
                                    &peer_id,
                                    generation,
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
                        let rx_delta = udp.probe_rx_snapshot().await.delta_since(rx_before);
                        let timeout_detail = format!(
                            "background UDP retry stopped after {}ms deadline; known_peer_ip_rx_delta={} authenticated_probe_rx_delta={} authenticated_probe_ack_observed_delta={} authenticated_probe_ack_unmatched_delta={} legacy_probe_ack_observed_delta={} legacy_probe_ack_unmatched_delta={} matched_probe_ack_rx_delta={}",
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
                                "retry_session_deadline",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                None,
                                timeout_detail.clone(),
                            )
                            .await;
                        if let (true, Some(plan)) = (stable_remote_scatter, birthday_plan.as_ref()) {
                            // The deadline can cut the session short even
                            // though the whole planned window was already
                            // sent (the session was only waiting out the ACK
                            // grace): advance the cursor so the next cycle
                            // does not rescan the same 3,000 ports.
                            let covered_all = last_punch_report
                                .is_some_and(|report| {
                                    report.unique_target_endpoints as usize >= candidates.len()
                                });
                            if covered_all {
                                let cursor_advanced = peers
                                    .commit_birthday_probe_cursor(
                                        &peer_id,
                                        plan,
                                        true,
                                    )
                                    .await;
                                peers
                                    .record_direct_event(
                                        &peer_id,
                                        "birthday_probe_plan_completed",
                                        candidates.first().copied(),
                                        Some(candidates.len()),
                                        last_punch_report.map(|report| report.packets_sent),
                                        format!(
                                            "stable-side birthday session deadline after a complete send report; cursor_advanced={cursor_advanced} start_rank={} end_rank={}",
                                            plan.start_rank,
                                            plan.end_rank
                                        ),
                                    )
                                    .await;
                            } else {
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
                            }
                        } else {
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
    }
}
