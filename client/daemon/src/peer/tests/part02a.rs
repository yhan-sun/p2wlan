#[test]
fn test_connection_state_display() {
    assert_eq!(ConnectionState::Idle.to_string(), "idle");
    assert_eq!(ConnectionState::Direct.to_string(), "direct");
    assert_eq!(ConnectionState::Relay.to_string(), "relay");
}

#[test]
fn test_peer_connection_new() {
    let conn = PeerConnection::new("peer1", "10.20.0.2");
    assert_eq!(conn.node_id, "peer1");
    assert_eq!(conn.virtual_ip, "10.20.0.2");
    assert!(!conn.is_active());
    assert!(!conn.is_relay());
}

#[test]
fn test_peer_connection_transition() {
    let mut conn = PeerConnection::new("peer1", "10.20.0.2");
    assert_eq!(conn.state, ConnectionState::Idle);

    conn.transition(ConnectionState::Connecting);
    assert_eq!(conn.state, ConnectionState::Connecting);
    assert!(conn.connected_at.is_none());

    conn.transition(ConnectionState::Direct);
    assert!(conn.is_active());
    assert!(!conn.is_relay());
    let first_connected_at = conn.connected_at.expect("Direct starts the active-session clock");

    conn.transition(ConnectionState::Relay);
    assert_eq!(
        conn.connected_at,
        Some(first_connected_at),
        "Direct-to-Relay fallback remains one continuously usable session"
    );

    conn.transition(ConnectionState::FallbackToRelay);
    assert!(
        conn.connected_at.is_none(),
        "every non-active state must clear the prior connection clock"
    );
    conn.transition(ConnectionState::Direct);
    assert!(
        conn.connected_at
            .is_some_and(|reconnected_at| reconnected_at >= first_connected_at),
        "the first active state after an outage must start a fresh clock"
    );
}

#[test]
fn test_peer_connection_relay() {
    let mut conn = PeerConnection::new("peer1", "10.20.0.2");
    conn.transition(ConnectionState::Relay);
    assert!(conn.is_active());
    assert!(conn.is_relay());
}

#[test]
fn test_peer_connection_bytes() {
    let mut conn = PeerConnection::new("peer1", "10.20.0.2");
    conn.record_sent(100);
    conn.record_sent(50);
    conn.record_received(200);
    assert_eq!(conn.bytes_sent, 150);
    assert_eq!(conn.bytes_received, 200);
}

#[tokio::test]
async fn test_peer_manager_add_remove() {
    let config = test_config();
    let manager = PeerManager::new(config);

    let peer_info = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: "Office Mac".to_string(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: "1.2.3.4:5000".to_string(),
        nat_type: "FullCone".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    manager.add_peer(&peer_info).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.virtual_ip, "10.20.0.2");
    assert_eq!(conn.device_name, "Office Mac");
    assert!(manager.peer_exists_sync("peer1"));
    let initial_session = manager
        .peer_session_snapshot_for_test("peer1")
        .expect("new online peer must publish an active lifecycle");
    assert!(initial_session.1);

    // An unrelated connection-map writer must not turn a registered peer into
    // a false negative for control ingress or UDP lifecycle fencing.
    let connection_writer = manager.connections.write().await;
    assert!(manager.peer_exists_sync("peer1"));
    drop(connection_writer);

    let mut updated_peer_info = peer_info.clone();
    updated_peer_info.device_name = "Office Mac Updated".to_string();
    let update = manager.add_peer(&updated_peer_info).await;
    assert!(!update.is_new);
    assert!(manager.peer_exists_sync("peer1"));
    assert_eq!(
        manager.peer_session_snapshot_for_test("peer1"),
        Some(initial_session),
        "ordinary metadata refresh must retain the authenticated lifecycle"
    );

    let mut offline_peer_info = updated_peer_info.clone();
    offline_peer_info.online = false;
    manager.add_peer(&offline_peer_info).await;
    let offline_session = manager
        .peer_session_snapshot_for_test("peer1")
        .expect("offline peers remain structurally present");
    assert_ne!(offline_session.0, initial_session.0);
    assert!(!offline_session.1);
    assert!(manager.peer_exists_sync("peer1"));
    assert!(manager
        .probe_key_candidates_for_peer("peer1")
        .await
        .is_empty());

    manager.add_peer(&updated_peer_info).await;
    let reonline_session = manager
        .peer_session_snapshot_for_test("peer1")
        .expect("online transition must republish the peer");
    assert_ne!(reonline_session.0, offline_session.0);
    assert!(reonline_session.1);

    // Resolve virtual IP
    let node_id = manager.resolve_virtual_ip("10.20.0.2").await.unwrap();
    assert_eq!(node_id, "peer1");

    manager.remove_peer("peer1").await;
    assert!(manager.get_connection("peer1").await.is_none());
    assert!(!manager.peer_exists_sync("peer1"));
    assert!(manager.peer_session_snapshot_for_test("peer1").is_none());

    manager.add_peer(&updated_peer_info).await;
    let readded_session = manager
        .peer_session_snapshot_for_test("peer1")
        .expect("same-ID readd must publish a lifecycle");
    assert_ne!(readded_session.0, reonline_session.0);
}

#[tokio::test]
async fn offline_control_peer_remains_visible_without_active_path() {
    let config = test_config();
    let manager = PeerManager::new(config);

    manager
        .add_peer(&PeerInfo {
            node_id: "peer-offline".to_string(),
            device_name: "Travel Laptop".to_string(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: "203.0.113.10:5000".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.9".to_string(),
            online: false,
            last_seen: 1_785_320_000,
            relay_rtt_ms: None,
        })
        .await;

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].node_id, "peer-offline");
    assert_eq!(diagnostics[0].device_name, "Travel Laptop");
    assert!(!diagnostics[0].online);
    assert_eq!(diagnostics[0].last_seen, 1_785_320_000);
    assert_eq!(diagnostics[0].state, ConnectionState::Closed);
    assert_eq!(diagnostics[0].active_path, None);
    assert!(manager
        .direct_probe_targets_for("peer-offline")
        .await
        .is_empty());
    assert!(manager.direct_probe_targets().await.is_empty());
    assert!(manager
        .direct_probe_targets_due(Duration::ZERO)
        .await
        .is_empty());
}

#[tokio::test]
async fn late_direct_results_cannot_revive_offline_or_rejoined_peer_lifecycle() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "203.0.113.20:5000".parse().unwrap();
    let mut peer = test_peer("peer-late-direct", endpoint);
    manager.add_peer(&peer).await;
    let generation = manager.current_network_generation_sync();
    let old_peer_session_generation = manager
        .peer_session_generation_sync(&peer.node_id)
        .expect("online peer publishes a lifecycle");

    peer.online = false;
    manager.add_peer(&peer).await;
    assert!(
        !manager
            .record_direct_success_for_generation(&peer.node_id, Some(endpoint), generation)
            .await,
        "late Direct success must not promote an offline Closed peer"
    );
    assert!(
        !manager
            .record_direct_failure_for_generation(
                &peer.node_id,
                generation,
                REASON_DIRECT_PROBE_FAILED,
                "late failure after offline",
            )
            .await,
        "late Direct failure must not rewrite an offline Closed peer"
    );
    assert_eq!(
        manager.get_connection(&peer.node_id).await.unwrap().state,
        ConnectionState::Closed
    );

    peer.online = true;
    manager.add_peer(&peer).await;
    let replacement_generation = manager
        .peer_session_generation_sync(&peer.node_id)
        .expect("rejoined peer publishes a replacement lifecycle");
    assert_ne!(replacement_generation, old_peer_session_generation);
    assert!(
        !manager
            .record_direct_failure_for_generation_and_peer_session_with_local_endpoint(
                &peer.node_id,
                generation,
                old_peer_session_generation,
                REASON_DIRECT_PROBE_FAILED,
                "old lifecycle timeout after same-node rejoin",
                None,
            )
            .await,
        "an old timeout owner must not commit against the replacement lifecycle"
    );
    assert_eq!(
        manager.get_connection(&peer.node_id).await.unwrap().state,
        ConnectionState::Idle
    );
}

#[tokio::test]
async fn peer_update_removes_old_virtual_ip_and_clears_signaled_endpoint() {
    let manager = PeerManager::new(test_config());
    let mut peer = test_peer("peer1", "1.2.3.4:5000".parse().unwrap());
    manager.add_peer(&peer).await;

    peer.virtual_ip = "10.20.0.9".to_string();
    peer.endpoint.clear();
    let update = manager.add_peer(&peer).await;

    assert!(update.virtual_ip_changed);
    assert!(update.endpoint_changed);
    assert_eq!(manager.resolve_virtual_ip("10.20.0.2").await, None);
    assert_eq!(
        manager.resolve_virtual_ip("10.20.0.9").await.as_deref(),
        Some("peer1")
    );
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.signaled_endpoint, None);
    assert_eq!(conn.endpoint, None);
}

#[tokio::test]
async fn clearing_signaled_endpoint_preserves_authenticated_peer_reflexive_endpoint() {
    let manager = PeerManager::new(test_config());
    let mut peer = test_peer("peer1", "1.2.3.4:5000".parse().unwrap());
    manager.add_peer(&peer).await;
    let learned: SocketAddr = "5.6.7.8:6000".parse().unwrap();
    assert!(manager.learn_authenticated_endpoint("peer1", learned).await);

    peer.endpoint.clear();
    manager.add_peer(&peer).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.signaled_endpoint, None);
    assert_eq!(conn.endpoint, Some(learned));
}

#[tokio::test]
async fn correlated_legacy_probe_endpoint_is_not_marked_authenticated() {
    let manager = PeerManager::new(test_config());
    let peer = test_peer("peer1", "1.2.3.4:5000".parse().unwrap());
    manager.add_peer(&peer).await;
    let learned: SocketAddr = "1.2.3.4:6001".parse().unwrap();

    assert!(
        manager
            .learn_correlated_probe_endpoint("peer1", learned)
            .await
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.endpoint, Some(learned));
    assert_eq!(
        conn.candidate_sources.get(&learned.to_string()),
        Some(&CandidatePairSource::Learned)
    );
}

#[tokio::test]
async fn candidate_signal_replaces_old_signaled_set_but_preserves_learned_endpoint() {
    let manager = PeerManager::new(test_config());
    let peer = test_peer("peer1", "1.2.3.4:5000".parse().unwrap());
    manager.add_peer(&peer).await;
    manager
        .add_candidates("peer1", &["2.2.2.2:5000".to_string()])
        .await;
    let learned: SocketAddr = "3.3.3.3:5000".parse().unwrap();
    assert!(manager.learn_authenticated_endpoint("peer1", learned).await);

    manager
        .add_candidates("peer1", &["4.4.4.4:5000".to_string()])
        .await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(!conn.candidates.contains(&"2.2.2.2:5000".to_string()));
    assert!(conn.candidates.contains(&"4.4.4.4:5000".to_string()));
    assert!(conn.candidates.contains(&learned.to_string()));
}

#[tokio::test]
async fn public_key_change_resets_confirmed_paths() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:5000".parse().unwrap();
    let mut peer = test_peer("peer1", endpoint);
    manager.add_peer(&peer).await;
    let old_session = manager.peer_session_snapshot_for_test("peer1").unwrap();
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;

    peer.public_key = "new-key".to_string();
    let update = manager.add_peer(&peer).await;
    assert!(update.public_key_changed);
    assert_ne!(
        manager.peer_session_snapshot_for_test("peer1").unwrap().0,
        old_session.0,
        "public-key identity change must rotate authenticated lifecycle"
    );
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Idle);
    assert_eq!(conn.active_path(), None);
    assert_eq!(conn.relay_server, None);
    assert!(conn.direct_health.last_success_at.is_none());
    assert!(conn.relay_health.last_success_at.is_none());
}

#[tokio::test]
async fn endpoint_churn_does_not_reset_existing_path() {
    let manager = PeerManager::new(test_config());
    let old_endpoint: SocketAddr = "1.2.3.4:5000".parse().unwrap();
    let peer = test_peer("peer-restart", old_endpoint);
    manager.add_peer(&peer).await;
    let old_session = manager
        .peer_session_snapshot_for_test("peer-restart")
        .unwrap();
    manager
        .record_direct_success("peer-restart", Some(old_endpoint))
        .await;
    manager.set_relay("peer-restart", "relay.test:443").await;

    let mut updated = peer.clone();
    updated.endpoint = "1.2.3.4:6000".to_string();
    let update = manager.add_peer(&updated).await;
    assert!(update.endpoint_changed);
    assert_eq!(
        manager.peer_session_snapshot_for_test("peer-restart"),
        Some(old_session),
        "source/endpoint-only refresh must not look like an identity handover"
    );

    let connection = manager.get_connection("peer-restart").await.unwrap();
    assert_eq!(connection.public_key, peer.public_key);
    assert_eq!(
        connection.signaled_endpoint,
        Some("1.2.3.4:6000".parse().unwrap())
    );
    assert_eq!(connection.endpoint, Some(old_endpoint));
    assert_eq!(connection.state, ConnectionState::Direct);
    assert!(connection.direct_health.last_success_at.is_some());
}

#[tokio::test]
async fn remote_incarnation_change_resets_but_same_boot_candidate_refresh_does_not() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "1.2.3.4:5000".parse().unwrap();
    let peer = test_peer("peer-incarnation", endpoint);
    manager.add_peer(&peer).await;

    // Keep this test independent of the candidate-generation implementation's
    // wall clock. The flag/high-field layout is the wire compatibility
    // contract: incarnation is above the 21-bit per-boot counter.
    let old_generation = 0x4000_0000_0000_0000u64 | (1000u64 << 21) | 1;
    let same_boot_refresh = 0x4000_0000_0000_0000u64 | (1000u64 << 21) | 2;
    let new_boot_generation = 0x4000_0000_0000_0000u64 | (1001u64 << 21) | 1;
    let replayed_old_boot_generation = 0x4000_0000_0000_0000u64 | (999u64 << 21) | 99;
    manager
        .add_candidates_with_metadata(
            "peer-incarnation",
            &[endpoint.to_string()],
            &HashMap::new(),
            old_generation,
            None,
        )
        .await;
    let old_session = manager
        .peer_session_snapshot_for_test("peer-incarnation")
        .unwrap();
    manager
        .record_direct_success("peer-incarnation", Some(endpoint))
        .await;
    assert!(
        !manager
            .reset_peer_session_if_remote_incarnation_changed(
                "peer-incarnation",
                same_boot_refresh,
                "same_boot_candidate_refresh",
            )
            .await
    );
    assert_eq!(
        manager
            .get_connection("peer-incarnation")
            .await
            .unwrap()
            .state,
        ConnectionState::Direct
    );
    assert_eq!(
        manager.peer_session_snapshot_for_test("peer-incarnation"),
        Some(old_session),
        "same remote incarnation candidate refresh must retain lifecycle"
    );
    assert!(
        !manager
            .reset_peer_session_if_remote_incarnation_changed(
                "peer-incarnation",
                replayed_old_boot_generation,
                "replayed_old_incarnation",
            )
            .await,
        "an older remote incarnation is a replay, not a restart"
    );
    assert_eq!(
        manager.peer_session_snapshot_for_test("peer-incarnation"),
        Some(old_session),
        "old-incarnation replay must not rotate the current lifecycle"
    );

    assert!(
        manager
            .reset_peer_session_if_remote_incarnation_changed(
                "peer-incarnation",
                new_boot_generation,
                "remote_incarnation_changed",
            )
            .await
    );
    assert_ne!(
        manager
            .peer_session_snapshot_for_test("peer-incarnation")
            .unwrap()
            .0,
        old_session.0,
        "remote daemon incarnation reset must fence old authenticated work"
    );
    let connection = manager.get_connection("peer-incarnation").await.unwrap();
    assert_eq!(connection.state, ConnectionState::Idle);
    assert!(connection.direct_health.last_success_at.is_none());
    assert!(connection.relay_confirmed_at.is_none());
}

#[tokio::test]
async fn test_peer_manager_candidates() {
    let config = test_config();
    let manager = PeerManager::new(config);

    let peer_info = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: "1.2.3.4:5000".to_string(),
        nat_type: "FullCone".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    manager.add_peer(&peer_info).await;
    manager
        .add_candidates(
            "peer1",
            &["10.0.0.1:5000".to_string(), "192.168.1.1:5000".to_string()],
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.candidates.len(), 2);
    assert_eq!(conn.candidate_pairs.len(), 3);
    assert_eq!(
        conn.candidate_pairs
            .iter()
            .find(|pair| pair.remote_endpoint == "1.2.3.4:5000".parse().unwrap())
            .map(|pair| pair.state),
        Some(CandidatePairState::Degraded)
    );
    assert!(conn
        .candidate_pairs
        .iter()
        .filter(|pair| pair.remote_endpoint != "1.2.3.4:5000".parse().unwrap())
        .all(|pair| pair.local_generation == 0 && pair.state == CandidatePairState::Waiting));
}

#[tokio::test]
async fn candidate_pairs_track_probe_success_failure_and_generation() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51826".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let targets = manager.direct_probe_targets().await;
    assert_eq!(targets, vec![("peer1".to_string(), vec![endpoint])]);
    assert!(manager.record_direct_probe_sent("peer1", endpoint).await);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.candidate_pairs.len(), 1);
    assert_eq!(conn.candidate_pairs[0].state, CandidatePairState::Probing);

    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                endpoint,
                Some(Duration::from_millis(9)),
                0,
            )
            .await
    );
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.candidate_pairs[0].state, CandidatePairState::Succeeded);
    assert_eq!(conn.candidate_pairs[0].rtt_ms, Some(9));

    let generation = manager.advance_network_generation("wifi_to_hotspot").await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(generation, 1);
    assert_eq!(conn.candidate_pairs.len(), 2);
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == 0
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Degraded
            && pair.last_error_code.as_deref() == Some(REASON_NETWORK_GENERATION_CHANGED)
    }));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == 1
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Waiting
    }));

    assert!(
        manager
            .record_direct_failure_for_generation(
                "peer1",
                generation,
                REASON_DIRECT_PROBE_FAILED,
                "no ACK",
            )
            .await
    );
    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Failed
            && pair.last_error.as_deref() == Some("no ACK")
    }));
}
