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
        let outcome = run_owned_punch_session(&session, async {
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
            let candidates = peers.direct_probe_targets_for(&peer_id).await;
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
            let punch_result = udp
                .punch_candidates(&peer_id, candidates.clone(), probe_interval, attempts)
                .await;

            match punch_result {
                Ok(sent) => {
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
                        peers
                            .record_direct_event(
                                &peer_id,
                                "punch_ack_timeout",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                format!(
                                    "no matched UDP punch ACK after {sent} probes; local_authenticated_probe_rx_delta={} local_probe_ack_rx_delta={}",
                                    rx_delta.authenticated_probe_packets_received,
                                    rx_delta.probe_acks_received
                                ),
                            )
                            .await;
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
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_session_deadline",
                        None,
                        None,
                        None,
                        format!(
                            "stopped UDP punch session after {}ms hard deadline",
                            PUNCH_SESSION_HARD_DEADLINE.as_millis()
                        ),
                    )
                    .await;
            }
        }
    });
}
