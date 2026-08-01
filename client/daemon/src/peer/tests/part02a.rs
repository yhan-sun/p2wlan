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
    assert!(conn.connected_at.is_some());
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

    // Resolve virtual IP
    let node_id = manager.resolve_virtual_ip("10.20.0.2").await.unwrap();
    assert_eq!(node_id, "peer1");

    manager.remove_peer("peer1").await;
    assert!(manager.get_connection("peer1").await.is_none());
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
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;

    peer.public_key = "new-key".to_string();
    let update = manager.add_peer(&peer).await;
    assert!(update.public_key_changed);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Idle);
    assert_eq!(conn.active_path(), None);
    assert_eq!(conn.relay_server, None);
    assert!(conn.direct_health.last_success_at.is_none());
    assert!(conn.relay_health.last_success_at.is_none());
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
    assert!(conn
        .candidate_pairs
        .iter()
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
