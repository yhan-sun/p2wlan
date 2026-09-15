use super::*;

pub(crate) async fn run_relay_peer_validation_loop(
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    local_virtual_ip: String,
) {
    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!("Skipping relay peer validation; local virtual IP '{local_virtual_ip}' is not IPv4");
        return;
    };
    let mut ticker = interval(RELAY_PEER_VALIDATION_READY_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_validation_at: Option<Instant> = None;
    let mut last_relay_endpoint: Option<String> = None;

    loop {
        ticker.tick().await;
        let Some(relay) = relay_transport.read().await.clone() else {
            last_relay_endpoint = None;
            continue;
        };
        let relay_endpoint = relay.endpoint().to_string();
        let relay_changed = last_relay_endpoint.as_deref() != Some(relay_endpoint.as_str());
        if !relay_changed
            && last_validation_at.is_some_and(|at| at.elapsed() < RELAY_PEER_VALIDATION_INTERVAL)
        {
            continue;
        }

        let targets = peers
            .relay_validation_targets(RELAY_PEER_VALIDATION_MAX_AGE)
            .await;
        if targets.is_empty() {
            last_relay_endpoint = Some(relay_endpoint);
            continue;
        }
        last_relay_endpoint = Some(relay_endpoint.clone());

        let generation = peers.current_network_generation().await;
        let validation_id = unix_time_millis() as u16;
        let validation_owner = unix_time_millis();
        let mut sends = Vec::new();
        for (sequence, (peer_id, peer_virtual_ip)) in targets.into_iter().enumerate() {
            let Ok(peer_ip) = peer_virtual_ip.parse::<Ipv4Addr>() else {
                debug!(
                    "Skipping relay peer validation for {peer_id}; peer virtual IP '{peer_virtual_ip}' is not IPv4"
                );
                continue;
            };
            let send_transport = transport.clone();
            let send_relay = relay.clone();
            let send_peer_id = peer_id;
            let send_peer_virtual_ip = peer_virtual_ip;
            let send_sequence = sequence as u16;
            let request_id = validation_id.wrapping_add(send_sequence);
            let owner_token = validation_owner.wrapping_add(sequence as u64);
            let send_generation = generation;
            let send_relay_endpoint = relay_endpoint.clone();
            let send_connection_id = relay.connection_id();
            let send_peers = Arc::clone(&peers);
            let expectation_peer_id = send_peer_id.clone();
            let expectation_endpoint = send_relay_endpoint.clone();
            sends.push(async move {
                let deadline_permit = RelayWriteBoundaryPermit::new();
                let boundary_permit = deadline_permit.clone();
                // Periodic health uses the same authenticated request/ACK
                // protocol as forced confirmation.  Its wire token is only an
                // identity; RTT is measured with the local Instant installed
                // at the relay writer boundary below, never at local enqueue
                // time and never with the wall-clock payload.
                let payload = crate::relay_probe::build_relay_probe_payload(
                    crate::relay_probe::RelayProbeKind::Request,
                    send_generation,
                    request_id,
                    owner_token,
                );
                let packet = Ipv4Packet::build_icmp_echo_request(
                    local_ip,
                    peer_ip,
                    request_id,
                    send_sequence,
                    &payload,
                );
                let result = tokio::time::timeout(
                    RELAY_CONTROL_SEND_TIMEOUT,
                    send_transport.encrypt_and_emit_outbound(
                        OutboundPacket {
                            room_authorization: None,
                            peer_id: send_peer_id.clone(),
                            dst_ip: send_peer_virtual_ip,
                            packet,
                            trace: None,
                        },
                        move |encrypted| async move {
                            let Some(peer_session_generation) = send_peers
                                .relay_validation_write_permit_for_transport(
                                    &expectation_peer_id,
                                    send_generation,
                                    &expectation_endpoint,
                                    send_connection_id,
                                )
                                .await
                            else {
                                return Err(DaemonError::Peer(format!(
                                    "peer {} is no longer confirmed on relay connection {}",
                                    expectation_peer_id, send_connection_id
                                )));
                            };
                            send_relay
                                .send_packet_with_write_boundary(&encrypted, move |sent_at| {
                                    boundary_permit.commit(|| {
                                        send_peers.register_relay_validation_expectation_at_write_boundary(
                                            &expectation_peer_id,
                                            send_generation,
                                            request_id,
                                            owner_token,
                                            &expectation_endpoint,
                                            send_connection_id,
                                            peer_session_generation,
                                            sent_at,
                                        )
                                    })
                                })
                                .await
                        },
                    ),
                )
                .await;
                (
                    send_peer_id,
                    send_generation,
                    request_id,
                    owner_token,
                    send_connection_id,
                    deadline_permit,
                    result,
                )
            });
        }

        let mut sent_count = 0usize;
        let mut transport_failed = false;
        for (
            peer_id,
            generation,
            request_id,
            owner_token,
            connection_id,
            deadline_permit,
            result,
        ) in join_all(sends).await
        {
            match result {
                Ok(Ok(true)) => sent_count = sent_count.saturating_add(1),
                Ok(Ok(false)) => {
                    deadline_permit.revoke();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    debug!(
                        "Relay peer validation skipped for {peer_id}: WireGuard session is not ready"
                    );
                }
                Ok(Err(err)) => {
                    deadline_permit.revoke();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    debug!("Relay peer validation skipped for {peer_id}: {err}");
                }
                Err(_) => {
                    deadline_permit.revoke();
                    relay.abort_writer();
                    peers.cancel_relay_probe_expectation_if_matches(
                        &peer_id,
                        generation,
                        request_id,
                        owner_token,
                        Some(connection_id),
                    );
                    transport_failed = true;
                    warn!(
                        event = "relay_validation_send_timeout",
                        peer_id = %peer_id,
                        relay_endpoint = %relay_endpoint,
                        timeout_ms = RELAY_CONTROL_SEND_TIMEOUT.as_millis(),
                        "relay validation writer completion timed out; relay transport invalidated"
                    );
                }
            }
        }
        if sent_count > 0 && !transport_failed {
            last_validation_at = Some(Instant::now());
        }
    }
}

#[cfg(test)]
pub(crate) struct RelayValidationPacket<'a> {
    pub(crate) peer_id: &'a str,
    pub(crate) peer_virtual_ip: &'a str,
    pub(crate) local_ip: Ipv4Addr,
    pub(crate) peer_ip: Ipv4Addr,
    pub(crate) validation_id: u16,
    pub(crate) sequence: u16,
}

#[cfg(test)]
pub(crate) async fn send_relay_validation_packet(
    validation: RelayValidationPacket<'_>,
    transport: &WireGuardTransport,
    relay: &RelayTransport,
) -> Result<()> {
    let payload = build_relay_validation_payload(unix_time_millis());
    let packet = Ipv4Packet::build_icmp_echo_request(
        validation.local_ip,
        validation.peer_ip,
        validation.validation_id,
        validation.sequence,
        &payload,
    );
    let sent = transport
        .encrypt_and_emit_outbound(
            OutboundPacket {
                room_authorization: None,
                peer_id: validation.peer_id.to_string(),
                dst_ip: validation.peer_virtual_ip.to_string(),
                packet,
                trace: None,
            },
            |encrypted| async move { relay.send_packet(&encrypted).await },
        )
        .await?;
    if !sent {
        return Err(DaemonError::Peer(format!(
            "WireGuard session for peer {} is not ready",
            validation.peer_id
        )));
    }
    Ok(())
}
