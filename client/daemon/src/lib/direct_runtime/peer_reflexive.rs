async fn run_peer_reflexive_signal_loop(
    mut rx: mpsc::Receiver<PeerReflexiveObservation>,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
) {
    while let Some(observation) = rx.recv().await {
        let validation_observation = observation.clone();
        let validation_udp = udp.clone();
        let validation_peers = peers.clone();
        let validation_transport = transport.clone();
        let validation_local_ip = local_virtual_ip.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(
                validation_observation,
                validation_udp,
                validation_peers,
                validation_transport,
                &validation_local_ip,
            )
            .await;
        });

        let fast_punch_udp = udp.clone();
        let fast_punch_peers = peers.clone();
        let fast_punch_peer_id = observation.peer_id.clone();
        let fast_punch_endpoint = observation.observed_endpoint;
        tokio::spawn(async move {
            let generation = fast_punch_peers.current_network_generation().await;
            let success_count_before = fast_punch_peers
                .direct_probe_success_count_for_generation(&fast_punch_peer_id, generation)
                .await;
            fast_punch_peers
                .record_direct_event(
                    &fast_punch_peer_id,
                    "peer_reflexive_fast_punch_started",
                    Some(fast_punch_endpoint),
                    Some(1),
                    None,
                    "probing freshly observed peer-reflexive endpoint immediately",
                )
                .await;
            match fast_punch_udp
                .punch_candidates(
                    &fast_punch_peer_id,
                    vec![fast_punch_endpoint],
                    PEER_REFLEXIVE_FAST_PUNCH_INTERVAL,
                    PEER_REFLEXIVE_FAST_PUNCH_ATTEMPTS,
                )
                .await
            {
                Ok(sent) => {
                    fast_punch_peers
                        .record_direct_event(
                            &fast_punch_peer_id,
                            "peer_reflexive_fast_punch_sent",
                            Some(fast_punch_endpoint),
                            Some(1),
                            Some(sent),
                            format!("sent {sent} probes to freshly observed peer-reflexive endpoint"),
                        )
                        .await;
                    sleep(direct_probe_ack_grace(PEER_REFLEXIVE_FAST_PUNCH_INTERVAL)).await;
                    let success_count_after = fast_punch_peers
                        .direct_probe_success_count_for_generation(&fast_punch_peer_id, generation)
                        .await;
                    if sent > 0 && success_count_after == success_count_before {
                        fast_punch_peers
                            .record_direct_event(
                                &fast_punch_peer_id,
                                "peer_reflexive_fast_punch_ack_timeout",
                                Some(fast_punch_endpoint),
                                Some(1),
                                Some(sent),
                                "fresh peer-reflexive endpoint did not ACK before encrypted validation",
                            )
                            .await;
                    }
                }
                Err(err) => {
                    fast_punch_peers
                        .record_direct_event(
                            &fast_punch_peer_id,
                            "peer_reflexive_fast_punch_error",
                            Some(fast_punch_endpoint),
                            Some(1),
                            None,
                            format!("failed to probe freshly observed peer-reflexive endpoint: {err}"),
                        )
                        .await;
                    debug!(
                        "Peer-reflexive fast punch to {fast_punch_peer_id} at {fast_punch_endpoint} failed: {err}"
                    );
                }
            }
        });

        let control = control.clone();
        tokio::spawn(async move {
            let observed_endpoint = observation.observed_endpoint.to_string();
            for delay in PEER_REFLEXIVE_SIGNAL_DELAYS {
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                let punch_at_ms = Some(relay_assisted_punch_at_ms());
                match control
                    .send_peer_reflexive(&observation.peer_id, &observed_endpoint, punch_at_ms)
                    .await
                {
                    Ok(()) => debug!(
                        "Relayed peer-reflexive observation to {}: {} punch_at_ms={punch_at_ms:?}",
                        observation.peer_id, observed_endpoint
                    ),
                    Err(err) => warn!(
                        "Failed to relay peer-reflexive observation to {} at {}: {err}",
                        observation.peer_id, observed_endpoint
                    ),
                }
            }
        });
    }
}
