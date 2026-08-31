// ============================================================
// Relay first-packet liveness: non-queuing commit interleavings
// ============================================================

#[tokio::test]
async fn relay_first_packet_transactions_survive_128_controlled_interleavings() {
    let manager = PeerManager::new(test_config());
    let peer_id = "peer-relay-first-packet-model";
    manager
        .add_peer(&test_peer(
            peer_id,
            "220.165.178.32:9090".parse().unwrap(),
        ))
        .await;
    let generation = manager.current_network_generation_sync();
    let endpoint = "relay.test:443";

    // Exercise more than the requested 100 schedules. Each round models a
    // responder grace refresh, pending-binding promotion, relay-ready commit,
    // and observation arriving while a production connection snapshot owns a
    // reader. None may register a fair-queue writer; a second reader remains
    // admissible, and the exact lifecycle transaction succeeds after release.
    for interleaving in 0..128u64 {
        let token = format!("responder-owner-{interleaving}");
        assert_eq!(
            manager
                .stage_probe_session_binding(
                    peer_id,
                    token.clone(),
                    Some(format!("probe-session-{interleaving}")),
                    Some([interleaving as u8; 32]),
                    true,
                )
                .await,
            ProbeBindingStage::Staged
        );

        let reader = manager.connection_map_for_test().read_owned().await;
        // Factoradic selection walks all 4! orderings of the four contended
        // transactions across every 24 rounds; 128 rounds therefore cover
        // each ordering at least five times with distinct lifecycle owners.
        let mut schedule = [0u8, 1, 2, 3];
        let mut rank = (interleaving as usize) % 24;
        for position in 0..schedule.len() {
            let remaining = schedule.len() - position;
            let choice = rank % remaining;
            rank /= remaining;
            schedule.swap(position, position + choice);
        }
        for step in schedule {
            match step {
                0 => assert_eq!(
                    manager.try_mark_relay_transport_ready_with_transport(
                        peer_id,
                        endpoint,
                        generation,
                        Some(interleaving + 1),
                    ),
                    RelayReadyCommitOutcome::ContendedConnections
                ),
                1 => assert_eq!(
                    manager.try_refresh_pending_probe_session_binding_grace(peer_id, &token),
                    PendingProbeBindingCommitOutcome::ContendedConnections
                ),
                2 => assert_eq!(
                    manager.try_confirm_pending_probe_session_binding(peer_id, &token),
                    PendingProbeBindingCommitOutcome::ContendedConnections
                ),
                3 => manager.record_relay_observation(peer_id, endpoint).await,
                _ => unreachable!("four-step schedule is closed"),
            }
            assert!(
                manager.try_all_connections().is_some(),
                "interleaving {interleaving} step {step} queued a writer and fairly blocked readers"
            );
        }
        drop(reader);

        assert_eq!(
            manager.try_refresh_pending_probe_session_binding_grace(peer_id, &token),
            PendingProbeBindingCommitOutcome::Committed
        );
        assert_eq!(
            manager.try_mark_relay_transport_ready_with_transport(
                peer_id,
                endpoint,
                generation,
                Some(interleaving + 1),
            ),
            RelayReadyCommitOutcome::Committed
        );
        assert_eq!(
            manager.try_confirm_pending_probe_session_binding(peer_id, &token),
            PendingProbeBindingCommitOutcome::Committed
        );
        assert_eq!(
            manager
                .get_connection(peer_id)
                .await
                .unwrap()
                .probe_binding_token
                .as_deref(),
            Some(token.as_str())
        );
    }

    // The same non-queuing entry point must still preserve the epoch and peer
    // lifecycle fences: an old task cannot publish into a new generation.
    let next_generation = manager
        .advance_network_generation("relay first-packet stale-event fence")
        .await;
    assert!(next_generation > generation);
    assert_eq!(
        manager.try_mark_relay_transport_ready_with_transport(
            peer_id,
            endpoint,
            generation,
            Some(999),
        ),
        RelayReadyCommitOutcome::Rejected
    );
    let connection = manager.get_connection(peer_id).await.unwrap();
    assert_eq!(connection.relay_ready_generation, None);
    assert_ne!(connection.state, ConnectionState::Direct);
}
