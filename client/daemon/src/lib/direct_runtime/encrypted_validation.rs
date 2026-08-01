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
        let encrypted = match transport
            .encrypt_outbound(OutboundPacket {
                peer_id: observation.peer_id.clone(),
                dst_ip: connection.virtual_ip.clone(),
                packet,
            })
            .await
        {
            Ok(Some(encrypted)) => encrypted,
            Ok(None) => {
                debug!(
                    "Skipping encrypted Direct validation for {}; WireGuard session is not ready",
                    observation.peer_id
                );
                peers
                    .record_direct_event(
                        &observation.peer_id,
                        "encrypted_trial_skipped",
                        Some(observation.observed_endpoint),
                        None,
                        Some(sent),
                        "skipped bounded WireGuard validation because WireGuard session is not ready",
                    )
                    .await;
                return;
            }
            Err(err) => {
                warn!(
                    "Failed to encrypt Direct validation packet for {}: {err}",
                    observation.peer_id
                );
                peers
                    .record_direct_event(
                        &observation.peer_id,
                        "encrypted_trial_failed",
                        Some(observation.observed_endpoint),
                        None,
                        Some(sent),
                        format!("failed to encrypt bounded WireGuard validation packet: {err}"),
                    )
                    .await;
                return;
            }
        };

        match udp
            .send_packet_to(&encrypted, observation.observed_endpoint)
            .await
        {
            Ok(_) => sent = sent.saturating_add(1),
            Err(err) => {
                warn!(
                    "Failed to send encrypted Direct validation to {} at {}: {err}",
                    observation.peer_id, observation.observed_endpoint
                );
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
