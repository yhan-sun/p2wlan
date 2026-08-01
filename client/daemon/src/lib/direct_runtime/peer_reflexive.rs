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
