use super::path_state_machine::{PathRecoveryState, PathTransitionDecision};

#[tokio::test]
async fn candidate_refresh_relay_only_retention_commits_relay_fallback_mirror() {
    let manager = PeerManager::new(test_config());
    let direct_endpoint: SocketAddr = "198.51.100.90:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18081";
    manager
        .add_peer(&test_peer("peer-relay-retention", direct_endpoint))
        .await;
    let generation = manager.current_network_generation().await;
    assert!(manager
        .confirm_relay_peer("peer-relay-retention", relay_endpoint, generation)
        .await);
    manager
        .record_direct_probe_success_with_latency(
            "peer-relay-retention",
            direct_endpoint,
            Some(Duration::from_millis(8)),
        )
        .await;
    manager
        .record_direct_success("peer-relay-retention", Some(direct_endpoint))
        .await;
    assert_eq!(
        manager
            .get_connection("peer-relay-retention")
            .await
            .unwrap()
            .active_path(),
        Some(NetworkPath::Direct)
    );

    {
        let mut connections = manager.connections.write().await;
        let connection = connections.get_mut("peer-relay-retention").unwrap();
        let pair = connection
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == direct_endpoint)
            .unwrap();
        pair.consecutive_failures = 1;
    }

    let next_generation = manager
        .advance_candidate_refresh_generation("relay-only retention acceptance")
        .await;
    let connection = manager
        .get_connection("peer-relay-retention")
        .await
        .unwrap();
    let state = connection.path_state_snapshot().state;
    assert_eq!(connection.state, ConnectionState::Relay);
    assert_eq!(connection.active_path(), Some(NetworkPath::Relay));
    assert_eq!(connection.relay_confirmed_generation, Some(next_generation));
    assert_eq!(
        state.recovery,
        PathRecoveryState::Degraded {
            epoch: PathEpoch::new(
                next_generation,
                manager
                    .peer_session_generation_sync("peer-relay-retention")
                    .unwrap(),
                connection.remote_candidate_epoch(),
            ),
            from: NetworkPath::Direct,
            fallback: Some(NetworkPath::Relay),
        }
    );

    let committed = manager
        .committed_business_path_snapshots_sync()
        .into_iter()
        .find(|snapshot| snapshot.peer_id == "peer-relay-retention")
        .expect("committed path mirror must contain the peer");
    assert!(matches!(
        committed.active,
        ActiveBusinessPath::Relay(ref relay) if relay.epoch.network_generation == next_generation
    ));
}

#[tokio::test]
async fn duplicate_path_events_preserve_revision_counters_timestamps_and_markers() {
    let manager = PeerManager::new(test_config());
    let peer_id = "peer-idempotent-path-events";
    let direct_endpoint: SocketAddr = "198.51.100.91:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18082";
    let relay_connection_id = 91;
    manager.add_peer(&test_peer(peer_id, direct_endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport(
            peer_id,
            relay_endpoint,
            generation,
            Some(relay_connection_id),
        )
        .await;
    assert!(manager
        .confirm_relay_peer_with_transport(
            peer_id,
            relay_endpoint,
            generation,
            Some(relay_connection_id),
        )
        .await);

    let before_relay_duplicate = manager.get_connection(peer_id).await.unwrap();
    assert!(!manager
        .confirm_relay_peer_with_transport(
            peer_id,
            relay_endpoint,
            generation,
            Some(relay_connection_id),
        )
        .await);
    let after_relay_duplicate = manager.get_connection(peer_id).await.unwrap();
    assert_eq!(
        after_relay_duplicate.path_state_snapshot(),
        before_relay_duplicate.path_state_snapshot()
    );
    assert_eq!(
        after_relay_duplicate.relay_confirm_seq,
        before_relay_duplicate.relay_confirm_seq
    );
    assert_eq!(
        after_relay_duplicate.relay_confirmed_at,
        before_relay_duplicate.relay_confirmed_at
    );
    assert_eq!(
        after_relay_duplicate.relay_health.success_count,
        before_relay_duplicate.relay_health.success_count
    );
    assert_eq!(
        after_relay_duplicate.relay_health.last_success_at,
        before_relay_duplicate.relay_health.last_success_at
    );

    assert!(manager
        .mark_relay_first_business_sent_for_generation_with_transport(
            peer_id,
            generation,
            relay_endpoint,
            Some(relay_connection_id),
        )
        .await);
    let after_first_sent = manager.get_connection(peer_id).await.unwrap();
    assert!(!manager
        .mark_relay_first_business_sent_for_generation_with_transport(
            peer_id,
            generation,
            relay_endpoint,
            Some(relay_connection_id),
        )
        .await);
    let after_duplicate_sent = manager.get_connection(peer_id).await.unwrap();
    assert_eq!(
        after_duplicate_sent.path_state_snapshot(),
        after_first_sent.path_state_snapshot()
    );
    assert_eq!(
        after_duplicate_sent.relay_first.business_sent_generation,
        after_first_sent.relay_first.business_sent_generation
    );
    assert_eq!(
        after_duplicate_sent.relay_first.business_exchange_generation,
        after_first_sent.relay_first.business_exchange_generation
    );

    assert!(manager
        .mark_relay_first_business_received_for_generation_with_transport(
            peer_id,
            relay_endpoint,
            generation,
            Some(relay_connection_id),
        )
        .await);
    let after_first_received = manager.get_connection(peer_id).await.unwrap();
    assert!(!manager
        .mark_relay_first_business_received_for_generation_with_transport(
            peer_id,
            relay_endpoint,
            generation,
            Some(relay_connection_id),
        )
        .await);
    let after_duplicate_received = manager.get_connection(peer_id).await.unwrap();
    assert_eq!(
        after_duplicate_received.path_state_snapshot(),
        after_first_received.path_state_snapshot()
    );
    assert_eq!(
        after_duplicate_received
            .relay_first
            .business_received_generation,
        after_first_received
            .relay_first
            .business_received_generation
    );
    assert_eq!(
        after_duplicate_received
            .relay_first
            .business_exchange_generation,
        after_first_received
            .relay_first
            .business_exchange_generation
    );
    assert_eq!(
        after_duplicate_received
            .relay_first
            .business_gate_completed_generation,
        after_first_received
            .relay_first
            .business_gate_completed_generation
    );

    manager
        .record_direct_probe_success_with_latency(
            peer_id,
            direct_endpoint,
            Some(Duration::from_millis(8)),
        )
        .await;
    manager
        .record_direct_success(peer_id, Some(direct_endpoint))
        .await;
    let before_direct_duplicate = manager.get_connection(peer_id).await.unwrap();
    let before_pair = before_direct_duplicate
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == direct_endpoint)
        .unwrap()
        .clone();
    let before_committed_mirror = manager.committed_business_path_snapshots_sync();

    manager
        .record_direct_success(peer_id, Some(direct_endpoint))
        .await;
    let after_direct_duplicate = manager.get_connection(peer_id).await.unwrap();
    let after_pair = after_direct_duplicate
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == direct_endpoint)
        .unwrap();
    assert_eq!(
        after_direct_duplicate.path_state_snapshot(),
        before_direct_duplicate.path_state_snapshot()
    );
    assert_eq!(
        after_direct_duplicate.direct_health.success_count,
        before_direct_duplicate.direct_health.success_count
    );
    assert_eq!(
        after_direct_duplicate.direct_health.last_success_at,
        before_direct_duplicate.direct_health.last_success_at
    );
    assert_eq!(
        after_direct_duplicate.direct_commit_seq,
        before_direct_duplicate.direct_commit_seq
    );
    assert_eq!(after_pair.success_count, before_pair.success_count);
    assert_eq!(after_pair.last_success_at, before_pair.last_success_at);
    assert_eq!(after_pair.selected_at, before_pair.selected_at);
    assert_eq!(
        after_direct_duplicate.direct_events.len(),
        before_direct_duplicate.direct_events.len()
    );
    assert_eq!(
        after_direct_duplicate.path_events.len(),
        before_direct_duplicate.path_events.len()
    );
    assert_eq!(
        after_direct_duplicate.connected_at,
        before_direct_duplicate.connected_at
    );
    assert_eq!(
        manager.committed_business_path_snapshots_sync(),
        before_committed_mirror
    );

    let epoch = after_direct_duplicate
        .path_state_snapshot()
        .state
        .epoch
        .unwrap();
    let mut connections = manager.connections.write().await;
    let connection = connections.get_mut(peer_id).unwrap();
    let revision = connection.path_state_snapshot().revision;
    let bytes_sent = connection.bytes_sent;
    let direct_success_count = connection.direct_health.success_count;
    let direct_event_count = connection.direct_events.len();
    let peer_online_duplicate = connection.commit_path_transition(
        PathEvent::PeerOnline { epoch },
        |connection| {
            connection.bytes_sent = connection.bytes_sent.saturating_add(1);
            connection.direct_health.record_success();
            connection.record_direct_event(
                generation,
                "duplicate_peer_online_side_effect",
                None,
                None,
                None,
                "must not execute",
            );
        },
    );
    assert_eq!(peer_online_duplicate.decision, PathTransitionDecision::Duplicate);
    assert_eq!(connection.path_state_snapshot().revision, revision);
    assert_eq!(connection.bytes_sent, bytes_sent);
    assert_eq!(connection.direct_health.success_count, direct_success_count);
    assert_eq!(connection.direct_events.len(), direct_event_count);

    let first_generation_observation = connection.commit_path_transition(
        PathEvent::NetworkGenerationAdvanced {
            epoch,
            retained: PathRetention::DirectAndRelay,
        },
        |_| {},
    );
    assert_eq!(
        first_generation_observation.decision,
        PathTransitionDecision::AcceptedObservation
    );
    let generation_revision = connection.path_state_snapshot().revision;
    let generation_duplicate = connection.commit_path_transition(
        PathEvent::NetworkGenerationAdvanced {
            epoch,
            retained: PathRetention::DirectAndRelay,
        },
        |connection| {
            connection.bytes_sent = connection.bytes_sent.saturating_add(1);
            connection.direct_health.record_success();
        },
    );
    assert_eq!(generation_duplicate.decision, PathTransitionDecision::Duplicate);
    assert_eq!(
        connection.path_state_snapshot().revision,
        generation_revision
    );
    assert_eq!(connection.bytes_sent, bytes_sent);
    assert_eq!(connection.direct_health.success_count, direct_success_count);
}

#[tokio::test]
async fn independent_relay_health_observations_apply_once_each() {
    let manager = PeerManager::new(test_config());
    let peer_id = "peer-independent-relay-health";
    let direct_endpoint: SocketAddr = "198.51.100.92:51831".parse().unwrap();
    let relay_endpoint = "tcp://relay.test:18083";
    let relay_connection_id = 92;
    manager.add_peer(&test_peer(peer_id, direct_endpoint)).await;
    let generation = manager.current_network_generation().await;
    manager
        .mark_relay_transport_ready_with_transport(
            peer_id,
            relay_endpoint,
            generation,
            Some(relay_connection_id),
        )
        .await;
    assert!(manager
        .confirm_relay_peer_with_transport(
            peer_id,
            relay_endpoint,
            generation,
            Some(relay_connection_id),
        )
        .await);
    let peer_session_generation = manager.peer_session_generation_sync(peer_id).unwrap();

    let observe = |request_id, owner_token| crate::relay_probe::RelayProbeToken {
        kind: crate::relay_probe::RelayProbeKind::Ack,
        generation,
        request_id,
        owner_token,
    };
    assert!(manager.register_relay_validation_expectation_at_write_boundary(
        peer_id,
        generation,
        1,
        101,
        relay_endpoint,
        relay_connection_id,
        peer_session_generation,
        Instant::now(),
    ));
    assert!(manager
        .consume_relay_probe_ack_with_transport(
            peer_id,
            observe(1, 101),
            relay_endpoint,
            Some(relay_connection_id),
        )
        .await);
    let first = manager.get_connection(peer_id).await.unwrap();
    let first_revision = first.path_state_snapshot().revision;
    let first_success_count = first.relay_health.success_count;
    let first_success_at = first.relay_health.last_success_at;

    assert!(!manager
        .consume_relay_probe_ack_with_transport(
            peer_id,
            observe(1, 101),
            relay_endpoint,
            Some(relay_connection_id),
        )
        .await);
    let duplicate = manager.get_connection(peer_id).await.unwrap();
    assert_eq!(duplicate.path_state_snapshot().revision, first_revision);
    assert_eq!(duplicate.relay_health.success_count, first_success_count);
    assert_eq!(duplicate.relay_health.last_success_at, first_success_at);

    assert!(manager.register_relay_validation_expectation_at_write_boundary(
        peer_id,
        generation,
        2,
        102,
        relay_endpoint,
        relay_connection_id,
        peer_session_generation,
        Instant::now(),
    ));
    assert!(manager
        .consume_relay_probe_ack_with_transport(
            peer_id,
            observe(2, 102),
            relay_endpoint,
            Some(relay_connection_id),
        )
        .await);
    let independent = manager.get_connection(peer_id).await.unwrap();
    assert_eq!(independent.path_state_snapshot().revision, first_revision + 1);
    assert_eq!(
        independent.relay_health.success_count,
        first_success_count + 1
    );
    assert!(independent.relay_health.last_success_at >= first_success_at);
}
