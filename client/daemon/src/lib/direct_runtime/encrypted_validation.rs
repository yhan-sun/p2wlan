async fn run_direct_encrypted_validation(
    observation: PeerReflexiveObservation,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: &str,
) {
    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; local virtual IP '{}' is not IPv4",
            observation.peer_id, local_virtual_ip
        );
        return;
    };
    let Some(connection) = peers.get_connection(&observation.peer_id).await else {
        return;
    };
    let Ok(peer_ip) = connection.virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; peer virtual IP '{}' is not IPv4",
            observation.peer_id, connection.virtual_ip
        );
        return;
    };

    let generation = peers.current_network_generation().await;
    peers
        .record_direct_event(
            &observation.peer_id,
            "encrypted_trial_started",
            Some(observation.observed_endpoint),
            None,
            None,
            "starting bounded WireGuard validation on authenticated UDP endpoint",
        )
        .await;

    if peers
        .is_direct_for_generation(&observation.peer_id, generation)
        .await
    {
        peers
            .record_direct_event(
                &observation.peer_id,
                "encrypted_trial_skipped",
                Some(observation.observed_endpoint),
                None,
                Some(0),
                "skipped bounded WireGuard validation because Direct is already confirmed for this network generation",
            )
            .await;
        return;
    }

    let validation_id = unix_time_millis() as u16;
    let session_wait_started = Instant::now();
    let mut waiting_for_session = false;
    loop {
        if peers
            .is_direct_for_generation(&observation.peer_id, generation)
            .await
        {
            peers
                .record_direct_event(
                    &observation.peer_id,
                    "encrypted_trial_skipped",
                    Some(observation.observed_endpoint),
                    None,
                    Some(0),
                    "skipped bounded WireGuard validation because Direct became confirmed while waiting for the WireGuard session",
                )
                .await;
            return;
        }

        let status = transport.session_status(&observation.peer_id).await;
        if status.has_active && !status.expired {
            if waiting_for_session {
                peers
                    .record_direct_event(
                        &observation.peer_id,
                        "encrypted_trial_session_ready",
                        Some(observation.observed_endpoint),
                        None,
                        Some(0),
                        format!(
                            "WireGuard session became ready after {}ms",
                            session_wait_started.elapsed().as_millis()
                        ),
                    )
                    .await;
            }
            break;
        } else {
                if !waiting_for_session {
                    waiting_for_session = true;
                    peers
                        .record_direct_event(
                            &observation.peer_id,
                            "encrypted_trial_waiting_for_session",
                            Some(observation.observed_endpoint),
                            None,
                            Some(0),
                            "peer-reflexive endpoint arrived before the WireGuard session; waiting for the handshake",
                        )
                        .await;
                }

                let elapsed = session_wait_started.elapsed();
                if elapsed >= DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT {
                    debug!(
                        "Skipping encrypted Direct validation for {}; WireGuard session was not ready within {}ms",
                        observation.peer_id,
                        DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.as_millis()
                    );
                    peers
                        .record_direct_event(
                            &observation.peer_id,
                            "encrypted_trial_skipped",
                            Some(observation.observed_endpoint),
                            None,
                            Some(0),
                            format!(
                                "timed out after {}ms waiting for the WireGuard session",
                                DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.as_millis()
                            ),
                        )
                        .await;
                    return;
                }

                sleep(
                    DIRECT_ENCRYPTED_VALIDATION_SESSION_POLL.min(
                        DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.saturating_sub(elapsed),
                    ),
                )
                .await;
        }
    }

    let mut sent = 0u32;
    for (sequence, delay) in DIRECT_ENCRYPTED_VALIDATION_DELAYS.into_iter().enumerate() {
        if !delay.is_zero() {
            sleep(delay).await;
        }
        if peers
            .is_direct_for_generation(&observation.peer_id, generation)
            .await
        {
            break;
        }

        let packet = Ipv4Packet::build_icmp_echo_request(
            local_ip,
            peer_ip,
            validation_id,
            sequence as u16,
            DIRECT_ENCRYPTED_VALIDATION_PAYLOAD,
        );
        let send_udp = udp.clone();
        match transport
            .encrypt_and_emit_outbound(
                OutboundPacket {
                    peer_id: observation.peer_id.clone(),
                    dst_ip: connection.virtual_ip.clone(),
                    packet,
                },
                move |encrypted| async move {
                    send_udp
                        .send_packet_to(&encrypted, observation.observed_endpoint)
                        .await
                        .map(|_| ())
                },
            )
            .await
        {
                Ok(true) => sent = sent.saturating_add(1),
                Ok(false) => {
                    debug!(
                        "Stopping encrypted Direct validation for {}; WireGuard session is no longer ready",
                        observation.peer_id
                    );
                    peers
                        .record_direct_event(
                            &observation.peer_id,
                            "encrypted_trial_skipped",
                            Some(observation.observed_endpoint),
                            None,
                            Some(sent),
                            "stopped bounded WireGuard validation because the WireGuard session became unavailable",
                        )
                        .await;
                    return;
                }
                Err(err) => {
                    warn!(
                        "Failed to send encrypted Direct validation to {} at {}: {err}",
                        observation.peer_id, observation.observed_endpoint
                    );
                    peers
                        .record_direct_event(
                            &observation.peer_id,
                            "encrypted_trial_failed",
                            Some(observation.observed_endpoint),
                            None,
                            Some(sent),
                            format!("failed to emit bounded WireGuard validation packet: {err}"),
                        )
                        .await;
                    break;
                }
            }
    }

    peers
        .record_direct_event(
            &observation.peer_id,
            "encrypted_trial_sent",
            Some(observation.observed_endpoint),
            None,
            Some(sent),
            format!("sent {sent} bounded WireGuard validation packets"),
        )
        .await;
}
