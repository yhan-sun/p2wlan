use super::*;

#[test]
fn unlabelled_private_candidates_do_not_beat_public_candidates() {
    let private: SocketAddr = "192.168.1.188:51820".parse().unwrap();
    let public: SocketAddr = "203.0.113.10:51820".parse().unwrap();
    assert!(endpoint_probe_rank(public) < endpoint_probe_rank(private));
}

fn test_config() -> Config {
    Config::generate_default("https://ctrl.test", "net1").unwrap()
}

fn birthday_nat_profile() -> NatProfile {
    NatProfile {
        local_addr: "0.0.0.0:60207".to_string(),
        observations: Vec::new(),
        udp_blocked: false,
        public_endpoint: Some("203.0.113.10:40007".to_string()),
        public_ip_stable: Some(true),
        public_port_stable: Some(false),
        port_preserved: Some(false),
        port_delta: None,
        likely_symmetric: Some(true),
        mapping_behavior: p2pnet_nat::MappingBehavior::AddressOrPortDependent,
        filtering_behavior: p2pnet_nat::FilteringBehavior::AddressOrPortDependent,
        hairpin_behavior: p2pnet_nat::HairpinBehavior::Unknown,
        mapping_lifetime: p2pnet_nat::MappingLifetime::Unknown,
        prediction_candidate: false,
        predicted_endpoints: Vec::new(),
        birthday_candidate: true,
        confidence: 70,
    }
}

fn test_peer(node_id: &str, endpoint: SocketAddr) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: endpoint.to_string(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

#[tokio::test]
async fn probe_mac_key_becomes_session_bound_with_static_fallback() {
    let config = test_config();
    let manager = PeerManager::new(config.clone());
    let remote_identity = NodeIdentity::generate();
    let remote_public_key = hex::encode(remote_identity.public_key());
    let mut peer = test_peer("peer-session", "8.8.8.8:12293".parse().unwrap());
    peer.public_key = remote_public_key.clone();
    manager.add_peer(&peer).await;

    let base_key = derive_probe_mac_key(&config, &remote_public_key).unwrap();
    assert_eq!(
        manager.probe_key_for_peer("peer-session").await,
        Some(base_key)
    );
    assert_eq!(
        manager.probe_keys_for_peer("peer-session").await,
        vec![base_key]
    );

    assert!(
        manager
            .set_probe_session_id("peer-session", Some("sess-1".to_string()))
            .await
    );
    let session_key = manager.probe_key_for_peer("peer-session").await.unwrap();
    assert_ne!(session_key, base_key);
    assert_eq!(
        manager.probe_keys_for_peer("peer-session").await,
        vec![session_key, base_key]
    );

    let local_ephemeral = p2pnet_crypto::DhKeyPair::generate();
    let remote_ephemeral = p2pnet_crypto::DhKeyPair::generate();
    let local_shared = local_ephemeral
        .diffie_hellman(&remote_ephemeral.public_key())
        .unwrap();
    let remote_shared = remote_ephemeral
        .diffie_hellman(&local_ephemeral.public_key())
        .unwrap();
    assert_eq!(local_shared, remote_shared);
    assert!(
        manager
            .set_probe_session_binding(
                "peer-session",
                Some("sess-1".to_string()),
                Some(local_shared),
            )
            .await
    );
    let ephemeral_key = manager.probe_key_for_peer("peer-session").await.unwrap();
    assert_ne!(ephemeral_key, session_key);
    assert_ne!(ephemeral_key, base_key);
    assert_eq!(
        manager.probe_keys_for_peer("peer-session").await,
        vec![ephemeral_key, session_key, base_key]
    );

    assert!(manager.set_probe_session_id("peer-session", None).await);
    assert_eq!(
        manager.probe_key_for_peer("peer-session").await,
        Some(base_key)
    );
    assert!(
        !manager
            .set_probe_session_id("missing", Some("sess-2".to_string()))
            .await
    );
}

#[tokio::test]
async fn diagnostics_classifies_public_udp_direct_selected_pair() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[remote.to_string()],
            &HashMap::from([(remote.to_string(), "stun_observed".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(18)),
            Some(local),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(remote), Some(local))
        .await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, false, Duration::from_secs(5), Some(local))
        .await;
    let peer = &diagnostics[0];
    let selected = peer.selected_pair.as_ref().unwrap();

    assert_eq!(peer.active_path, Some(NetworkPath::Direct));
    assert_eq!(peer.direct_type, DirectPathType::PublicUdp);
    assert!(peer.is_public_udp_direct);
    assert!(!peer.is_overlay_direct);
    assert!(!peer.is_relay);
    assert_eq!(peer.consent_endpoint.as_deref(), Some("8.8.8.8:12293"));
    assert_eq!(
        selected.local_endpoint.as_deref(),
        Some("192.168.1.10:51820")
    );
    assert_eq!(selected.remote_endpoint, "8.8.8.8:12293");
    assert_eq!(
        selected.remote_candidate_type,
        CandidatePairSource::StunObserved
    );
    assert_eq!(selected.pair_state, CandidatePairState::Selected);
    assert!(selected.selected);
    assert!(selected.nominated);
    assert!(selected.probe_due);
    assert_eq!(selected.probe_retry_after_ms, None);
    assert_eq!(selected.probe_retry_remaining_ms, None);
    assert_eq!(selected.rtt_ms, Some(18));
    assert!(selected.last_success_age_ms.is_some());
    assert_eq!(peer.warning, None);
}

#[tokio::test]
async fn diagnostics_keeps_probe_success_as_probing_until_direct_confirmed() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[remote.to_string()],
            &HashMap::from([(remote.to_string(), "stun_observed".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(18)),
            Some(local),
        )
        .await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), Some(local))
        .await;
    let peer = &diagnostics[0];

    assert_ne!(peer.active_path, Some(NetworkPath::Direct));
    assert_eq!(peer.direct_type, DirectPathType::Probing);
    assert!(!peer.is_public_udp_direct);
    assert!(!peer.is_overlay_direct);
    assert!(peer.selected_pair.is_none());
    assert_eq!(
        peer.current_direct_pair.as_ref().unwrap().direct_type,
        DirectPathType::Probing
    );
    assert_eq!(
        peer.current_direct_pair
            .as_ref()
            .unwrap()
            .local_endpoint
            .as_deref(),
        Some("192.168.1.10:51820")
    );
}

#[tokio::test]
async fn probe_ack_is_not_nominated_until_selector_trials_direct() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[remote.to_string()],
            &HashMap::from([(remote.to_string(), "stun_observed".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(18)),
            Some(local),
        )
        .await;

    let before = manager.diagnostics().await;
    let before_pair = before[0].current_direct_pair.as_ref().unwrap();
    assert_eq!(before_pair.pair_state, CandidatePairState::Succeeded);
    assert!(!before_pair.nominated);
    assert!(!before_pair.selected);

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert!(!selection.direct_confirmed);

    let conn = manager.get_connection("peer1").await.unwrap();
    let pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == remote)
        .unwrap();
    assert_eq!(pair.state, CandidatePairState::Succeeded);
    assert!(pair.nominated);
    assert!(pair.nominated_at.is_some());
    assert!(pair.selected_at.is_none());
}

#[tokio::test]
async fn stale_nominated_trial_expires_and_falls_back_to_relay() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[remote.to_string()],
            &HashMap::from([(remote.to_string(), "stun_observed".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(18)),
            Some(local),
        )
        .await;

    let trial = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(trial.path, Some(NetworkPath::Direct));
    assert_eq!(trial.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert!(!trial.direct_confirmed);

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == remote)
            .unwrap();
        pair.nominated_at = Some(Instant::now() - DIRECT_TRIAL_WINDOW - Duration::from_secs(1));
    }

    let fallback = manager
        .select_path_for_data_with_local_endpoint("peer1", true, true, Some(local))
        .await;
    assert_eq!(fallback.path, Some(NetworkPath::Relay));
    assert_eq!(fallback.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(!fallback.direct_confirmed);

    let conn = manager.get_connection("peer1").await.unwrap();
    let pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == remote)
        .unwrap();
    assert_eq!(pair.state, CandidatePairState::Degraded);
    assert!(!pair.nominated);
    assert!(pair.nominated_at.is_none());
    assert!(pair.selected_at.is_none());
    assert_eq!(
        pair.last_error_code.as_deref(),
        Some(REASON_DIRECT_TRIAL_EXPIRED)
    );
    assert_eq!(pair.local_endpoint, Some(local));

    let diagnostics = manager.diagnostics().await;
    let pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == remote.to_string())
        .unwrap();
    assert_eq!(pair.pair_state, CandidatePairState::Degraded);
    assert!(!pair.nominated);
    assert!(!pair.selected);
    assert_eq!(
        pair.last_error_code.as_deref(),
        Some(REASON_DIRECT_TRIAL_EXPIRED)
    );
    assert!(!pair.probe_due);
}

#[tokio::test]
async fn remote_use_candidate_check_allows_hedged_trial_without_selecting_direct() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .record_direct_probe_success_with_local_endpoint("peer1", remote, Some(local))
        .await;

    let before_nomination = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(before_nomination.path, Some(NetworkPath::Relay));
    assert_eq!(
        before_nomination.reason_code,
        REASON_PATH_DIRECT_NOT_CONFIRMED
    );

    assert!(
        manager
            .record_direct_nomination_check_with_local_endpoint("peer1", remote, Some(local))
            .await
    );

    let trial = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(trial.path, Some(NetworkPath::Direct));
    assert_eq!(trial.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert!(!trial.direct_confirmed);
    assert!(trial.relay_hedged);

    let diagnostics = manager.diagnostics().await;
    let pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == remote.to_string())
        .unwrap();
    assert_eq!(pair.pair_state, CandidatePairState::Probing);
    assert!(pair.nominated);
    assert!(!pair.selected);
    assert_eq!(pair.local_endpoint.as_deref(), Some("192.168.1.10:51820"));
}

#[tokio::test]
async fn selected_pair_stays_selected_when_probe_ack_refreshes_it() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(18)),
            Some(local),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(remote), Some(local))
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(16)),
            Some(local),
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    let pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == remote)
        .unwrap();
    assert_eq!(pair.state, CandidatePairState::Selected);
    assert!(pair.nominated);
    assert!(pair.selected_at.is_some());
    assert_eq!(pair.rtt_ms, Some(16));
}

#[tokio::test]
async fn diagnostics_does_not_report_overlay_endpoint_as_active_direct() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "10.20.0.5:51820".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(3)),
            Some(local),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(remote), Some(local))
        .await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, false, Duration::from_secs(5), Some(local))
        .await;
    let peer = &diagnostics[0];

    assert_eq!(peer.active_path, None);
    assert_eq!(peer.direct_type, DirectPathType::Probing);
    assert!(!peer.is_public_udp_direct);
    assert!(!peer.is_overlay_direct);
    assert!(!peer.is_relay);
    assert_eq!(peer.warning, None);
    assert_eq!(
        peer.selected_pair.as_ref().unwrap().direct_type,
        DirectPathType::Probing
    );
}

#[test]
fn shared_cgn_and_ula_endpoints_are_overlay_direct() {
    for endpoint in ["tailscale.example.com:63169", "[fd7a:115c:a1e0::b936:4102]:63167"] {
        let endpoint: SocketAddr = endpoint.parse().unwrap();
        assert!(is_overlay_endpoint(endpoint));
        assert_eq!(
            classify_confirmed_direct_endpoint(endpoint, CandidatePairSource::Host),
            DirectPathType::Overlay
        );
    }

    let lan: SocketAddr = "192.168.2.11:56250".parse().unwrap();
    assert!(!is_overlay_endpoint(lan));
    assert_eq!(
        classify_confirmed_direct_endpoint(lan, CandidatePairSource::Host),
        DirectPathType::Lan
    );
}

#[tokio::test]
async fn diagnostics_classifies_lan_direct_for_private_remote_endpoint() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "192.168.2.11:56250".parse().unwrap();
    let local: SocketAddr = "192.168.2.14:59435".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(7)),
            Some(local),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(remote), Some(local))
        .await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, false, Duration::from_secs(5), Some(local))
        .await;
    let peer = &diagnostics[0];

    assert_eq!(peer.active_path, Some(NetworkPath::Direct));
    assert_eq!(peer.direct_type, DirectPathType::Lan);
    assert!(!peer.is_public_udp_direct);
    assert!(!peer.is_overlay_direct);
    assert!(!peer.is_relay);
    assert_eq!(
        peer.selected_pair.as_ref().unwrap().direct_type,
        DirectPathType::Lan
    );
}

#[tokio::test]
async fn diagnostics_classifies_relay_without_reporting_direct() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.4.4:40000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", remote)).await;
    manager.set_relay("peer1", "relay.test:443").await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    let peer = &diagnostics[0];

    assert_eq!(peer.active_path, Some(NetworkPath::Relay));
    assert_eq!(peer.direct_type, DirectPathType::Relay);
    assert!(peer.is_relay);
    assert!(!peer.is_public_udp_direct);
    assert!(!peer.is_overlay_direct);
}

#[tokio::test]
async fn selected_peer_reflexive_pair_is_reported_first() {
    let manager = PeerManager::new(test_config());
    let signaled: SocketAddr = "8.8.4.4:40000".parse().unwrap();
    let peer_reflexive: SocketAddr = "1.1.1.1:41000".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();
    manager.add_peer(&test_peer("peer1", signaled)).await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(signaled, 0, CandidatePairSource::StunObserved)
            .record_success(Some(Duration::from_millis(30)), true, Some(local));
        conn.ensure_candidate_pair_with_source(
            peer_reflexive,
            0,
            CandidatePairSource::PeerReflexive,
        )
        .record_success(Some(Duration::from_millis(24)), true, Some(local));
        conn.endpoint = Some(peer_reflexive);
        conn.direct_generation = 0;
        conn.direct_health
            .record_success_with_latency(Duration::from_millis(24));
        conn.transition(ConnectionState::Direct);
    }

    let diagnostics = manager.diagnostics().await;
    let selected = diagnostics[0].selected_pair.as_ref().unwrap();

    assert_eq!(selected.remote_endpoint, "1.1.1.1:41000");
    assert_eq!(
        selected.remote_candidate_type,
        CandidatePairSource::PeerReflexive
    );
    assert_eq!(selected.pair_state, CandidatePairState::Selected);
}

#[tokio::test]
async fn diagnostics_json_contains_direct_candidate_pair_fields() {
    let manager = PeerManager::new(test_config());
    let remote: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:51820".parse().unwrap();

    manager.add_peer(&test_peer("peer1", remote)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[remote.to_string()],
            &HashMap::from([(remote.to_string(), "peer_reflexive".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer1",
            remote,
            Some(Duration::from_millis(18)),
            Some(local),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer1", Some(remote), Some(local))
        .await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, false, Duration::from_secs(5), Some(local))
        .await;
    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    let pair = &json["selected_pair"];

    assert_eq!(json["active_path"], "direct");
    assert_eq!(json["direct_type"], "public_udp");
    assert_eq!(json["consent_endpoint"], "8.8.8.8:12293");
    assert_eq!(json["is_public_udp_direct"], true);
    assert_eq!(json["is_overlay_direct"], false);
    assert_eq!(json["is_relay"], false);
    assert_eq!(pair["local_endpoint"], "192.168.1.10:51820");
    assert_eq!(pair["remote_endpoint"], "8.8.8.8:12293");
    assert_eq!(pair["local_candidate_type"], "host");
    assert_eq!(pair["remote_candidate_type"], "peer_reflexive");
    assert_eq!(pair["remote_source"], "peer_reflexive");
    assert_eq!(pair["pair_state"], "selected");
    assert_eq!(pair["nominated"], true);
    assert_eq!(pair["selected"], true);
    assert_eq!(pair["probe_due"], true);
    assert!(pair["probe_retry_after_ms"].is_null());
    assert!(pair["probe_retry_remaining_ms"].is_null());
    assert_eq!(pair["rtt_ms"], 18);
    assert!(pair.get("last_success_age_ms").is_some());
    assert!(pair.get("last_probe_age_ms").is_some());
    assert!(pair.get("failure_count").is_some());
    assert!(pair.get("last_error").is_some());
}

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

#[tokio::test]
async fn direct_failure_only_marks_sent_probe_candidates_when_some_were_sent() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();
    let predicted_endpoint: SocketAddr = "8.8.8.8:40001".parse().unwrap();
    let birthday_endpoint: SocketAddr = "8.8.8.8:40002".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    let candidates = vec![
        predicted_endpoint.to_string(),
        birthday_endpoint.to_string(),
    ];
    manager
        .add_candidates_with_sources(
            "peer1",
            &candidates,
            &HashMap::from([
                (predicted_endpoint.to_string(), "predicted".to_string()),
                (birthday_endpoint.to_string(), "birthday".to_string()),
            ]),
        )
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert!(targets.contains(&predicted_endpoint));
    assert!(targets.contains(&birthday_endpoint));
    assert!(
        manager
            .record_direct_probe_sent("peer1", predicted_endpoint)
            .await
    );

    assert!(
        manager
            .record_direct_failure_for_generation("peer1", 0, REASON_DIRECT_PROBE_FAILED, "no ACK",)
            .await
    );

    let conn = manager.get_connection("peer1").await.unwrap();
    let predicted_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == predicted_endpoint)
        .unwrap();
    let birthday_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == birthday_endpoint)
        .unwrap();

    assert_eq!(predicted_pair.state, CandidatePairState::Failed);
    assert_eq!(predicted_pair.failure_count, 1);
    assert_eq!(birthday_pair.state, CandidatePairState::Waiting);
    assert_eq!(birthday_pair.failure_count, 0);
    assert!(birthday_pair.last_error_code.is_none());

    let history = manager.traversal_history_diagnostics().await;
    assert!(history
        .sources
        .iter()
        .any(|source| source.source == "predicted" && source.failure_count == 1));
    assert!(!history
        .sources
        .iter()
        .any(|source| source.source == "birthday"));
}

#[tokio::test]
async fn candidate_pair_selection_prefers_selected_endpoint_for_send() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let old_endpoint: SocketAddr = "127.0.0.1:51827".parse().unwrap();
    let new_endpoint: SocketAddr = "127.0.0.1:51828".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: old_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    manager
        .add_candidates("peer1", &[new_endpoint.to_string()])
        .await;

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(old_endpoint)
    );

    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                new_endpoint,
                Some(Duration::from_millis(4)),
                0,
            )
            .await
    );

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(new_endpoint)
    );
    assert!(manager.direct_endpoints().await.is_empty());
    manager
        .record_direct_success("peer1", Some(new_endpoint))
        .await;
    assert_eq!(
        manager.direct_endpoints().await,
        vec![("peer1".to_string(), new_endpoint)]
    );
}

#[tokio::test]
async fn confirmed_public_direct_still_probes_waiting_private_candidate() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let public_endpoint: SocketAddr = "8.8.8.8:51842".parse().unwrap();
    let private_endpoint: SocketAddr = "192.168.2.11:51842".parse().unwrap();

    manager.add_peer(&test_peer("peer1", public_endpoint)).await;
    let candidates = vec![public_endpoint.to_string(), private_endpoint.to_string()];
    let sources = HashMap::from([
        (public_endpoint.to_string(), "peer_reflexive".to_string()),
        (private_endpoint.to_string(), "host".to_string()),
    ]);
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            public_endpoint,
            Some(Duration::from_millis(620)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(public_endpoint))
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;

    assert!(
        targets.contains(&private_endpoint),
        "waiting LAN candidate should still be probed while slow public Direct is active"
    );
}

#[tokio::test]
async fn low_latency_private_candidate_beats_selected_public_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let public_endpoint: SocketAddr = "8.8.8.8:51843".parse().unwrap();
    let private_endpoint: SocketAddr = "192.168.2.11:51843".parse().unwrap();

    manager.add_peer(&test_peer("peer1", public_endpoint)).await;
    let candidates = vec![public_endpoint.to_string(), private_endpoint.to_string()];
    let sources = HashMap::from([
        (public_endpoint.to_string(), "peer_reflexive".to_string()),
        (private_endpoint.to_string(), "host".to_string()),
    ]);
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            public_endpoint,
            Some(Duration::from_millis(620)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(public_endpoint))
        .await;

    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            private_endpoint,
            Some(Duration::from_millis(7)),
        )
        .await;

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(private_endpoint)
    );

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(selection.direct_endpoint, Some(private_endpoint));

    manager
        .record_direct_success("peer1", Some(private_endpoint))
        .await;
    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    let peer = diagnostics
        .iter()
        .find(|peer| peer.node_id == "peer1")
        .expect("peer diagnostics should be present");
    let private_endpoint_text = private_endpoint.to_string();

    assert_eq!(peer.direct_type, DirectPathType::Lan);
    assert_eq!(
        peer.selected_pair
            .as_ref()
            .map(|pair| pair.remote_endpoint.as_str()),
        Some(private_endpoint_text.as_str())
    );
    assert_eq!(
        peer.current_direct_pair
            .as_ref()
            .map(|pair| pair.remote_endpoint.as_str()),
        Some(private_endpoint_text.as_str())
    );
}

#[tokio::test]
async fn candidate_pair_stats_aggregate_real_outcomes_by_source() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let signaled_endpoint: SocketAddr = "127.0.0.1:51836".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51837".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(signaled_endpoint, 0, CandidatePairSource::Signaled)
            .record_success(Some(Duration::from_millis(12)), false, None);
        let peer_reflexive = conn.ensure_candidate_pair_with_source(
            peer_reflexive_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        );
        peer_reflexive.record_success(Some(Duration::from_millis(9)), false, None);
        peer_reflexive.record_failure(REASON_DIRECT_PROBE_FAILED, "no ACK", None);
    }

    let diagnostics = manager.diagnostics().await;
    let stats = &diagnostics[0].candidate_pair_stats;
    let signaled = stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Signaled)
        .unwrap();
    assert_eq!(signaled.pair_count, 1);
    assert_eq!(signaled.current_pair_count, 1);
    assert_eq!(signaled.success_count, 1);
    assert_eq!(signaled.failure_count, 0);
    assert_eq!(signaled.success_rate_per_mille, Some(1000));

    let peer_reflexive = stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::PeerReflexive)
        .unwrap();
    assert_eq!(peer_reflexive.pair_count, 1);
    assert_eq!(peer_reflexive.degraded_count, 1);
    assert_eq!(peer_reflexive.success_count, 1);
    assert_eq!(peer_reflexive.failure_count, 1);
    assert_eq!(peer_reflexive.success_rate_per_mille, Some(500));

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    assert_eq!(json["candidate_pair_stats"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn candidate_pairs_record_predicted_source_from_signal_metadata() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &["203.0.113.10:40007".to_string()],
            &HashMap::from([("203.0.113.10:40007".to_string(), "predicted".to_string())]),
        )
        .await;

    let diagnostics = manager.diagnostics().await;
    let predicted = diagnostics[0]
        .candidate_pair_stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .unwrap();
    assert_eq!(predicted.current_pair_count, 1);
    assert!(diagnostics[0].candidate_pairs.iter().any(|pair| {
        pair.remote_endpoint == "203.0.113.10:40007"
            && pair.source == CandidatePairSource::Predicted
    }));
}

#[tokio::test]
async fn candidate_pair_stats_include_history_budget_diagnostics() {
    let mut history = TraversalHistory::default();
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let endpoint: SocketAddr = "127.0.0.1:51848".parse().unwrap();
    let predicted_endpoint = "203.0.113.10:40007".to_string();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            std::slice::from_ref(&predicted_endpoint),
            &HashMap::from([(predicted_endpoint.clone(), "predicted".to_string())]),
        )
        .await;

    let diagnostics = manager.diagnostics().await;
    let predicted = diagnostics[0]
        .candidate_pair_stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .unwrap();

    assert_eq!(predicted.current_pair_count, 1);
    assert_eq!(predicted.history_success_count, Some(0));
    assert_eq!(predicted.history_failure_count, Some(3));
    assert_eq!(predicted.history_consecutive_failures, Some(3));
    assert_eq!(predicted.history_success_rate_per_mille, Some(0));
    assert!(predicted
        .history_cooldown_remaining_ms
        .is_some_and(|remaining| remaining > 0));
    assert_eq!(predicted.source_quality_rank, Some(1100));
    assert_eq!(
        predicted.probe_budget_per_cycle,
        Some(PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE)
    );
    assert_eq!(
        predicted.probe_budget_reason.as_deref(),
        Some("history_cooldown")
    );

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    let predicted_json = json["candidate_pair_stats"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stats| stats["source"] == "predicted")
        .unwrap();
    assert_eq!(predicted_json["probe_budget_reason"], "history_cooldown");
}

#[tokio::test]
async fn fresh_candidate_signal_replaces_stale_registry_endpoint() {
    let manager = PeerManager::new(test_config());
    let stale: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let fresh: SocketAddr = "203.0.113.10:42000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", stale)).await;

    manager
        .add_candidates("peer1", &["203.0.113.10:41500".to_string()])
        .await;
    manager.add_candidates("peer1", &[fresh.to_string()]).await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.signaled_endpoint, None);
    assert!(!conn.candidates.contains(&stale.to_string()));
    assert!(conn.candidates.contains(&fresh.to_string()));
    assert_eq!(conn.endpoint, Some(fresh));
}

#[tokio::test]
async fn versioned_candidates_reject_stale_and_expired_sets() {
    let manager = PeerManager::new(test_config());
    let initial: SocketAddr = "203.0.113.10:42000".parse().unwrap();
    let stale: SocketAddr = "203.0.113.10:41000".parse().unwrap();
    let expired: SocketAddr = "203.0.113.10:43000".parse().unwrap();
    manager.add_peer(&test_peer("peer1", initial)).await;

    manager
        .add_candidates_with_metadata(
            "peer1",
            &[initial.to_string()],
            &HashMap::new(),
            10,
            Some(u64::MAX),
        )
        .await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[stale.to_string()],
            &HashMap::new(),
            9,
            Some(u64::MAX),
        )
        .await;
    manager
        .add_candidates_with_metadata(
            "peer1",
            &[expired.to_string()],
            &HashMap::new(),
            11,
            Some(1),
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.last_candidate_generation, 10);
    assert!(conn.candidates.contains(&initial.to_string()));
    assert!(!conn.candidates.contains(&stale.to_string()));
    assert!(!conn.candidates.contains(&expired.to_string()));
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "candidates_stale"));
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "candidates_expired"));
}

#[tokio::test]
async fn punch_rounds_follow_observed_nat_behavior() {
    let manager = PeerManager::new(test_config());
    assert_eq!(manager.recommended_punch_attempts(10).await, 6);

    let mut endpoint_independent = birthday_nat_profile();
    endpoint_independent.mapping_behavior = MappingBehavior::EndpointIndependent;
    manager.update_nat_profile(endpoint_independent).await;
    assert_eq!(manager.recommended_punch_attempts(10).await, 4);

    manager.update_nat_profile(birthday_nat_profile()).await;
    assert_eq!(manager.recommended_punch_attempts(10).await, 8);
}

#[tokio::test]
async fn predicted_candidates_have_independent_probe_budget() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let candidates = (0..24)
        .map(|index| format!("203.0.113.10:{}", 40_007 + index * 2))
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_count = targets
        .iter()
        .filter(|endpoint| endpoint.ip().to_string() == "203.0.113.10")
        .count();
    assert_eq!(predicted_count, PREDICTED_PROBE_BUDGET_PER_CYCLE);
}

#[tokio::test]
async fn stable_public_candidate_precedes_predicted_budget_in_synchronized_punch() {
    let mut history = TraversalHistory::default();
    history.record_success(CandidatePairSource::Predicted);
    history.record_success(CandidatePairSource::Predicted);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    let candidates = (0..24)
        .map(|index| format!("8.8.8.8:{}", 41_000 + index))
        .collect::<Vec<_>>();
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    let predicted_endpoints = candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_count = targets
        .iter()
        .filter(|target| predicted_endpoints.contains(target))
        .count();

    assert_eq!(targets.first().copied(), Some(stable_endpoint));
    assert!(targets.contains(&stable_endpoint));
    assert_eq!(predicted_count, PREDICTED_PROBE_SUCCESS_BUDGET_PER_CYCLE);
}

#[tokio::test]
async fn synchronized_punch_keeps_predicted_budget_during_history_cooldown() {
    let mut history = TraversalHistory::default();
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    history.record_failure(CandidatePairSource::Predicted);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let predicted_candidates = (0..24)
        .map(|index| format!("8.8.8.8:{}", 41_000 + index))
        .collect::<Vec<_>>();
    let predicted_endpoints = predicted_candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    let sources = predicted_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &predicted_candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_positions = targets
        .iter()
        .enumerate()
        .filter_map(|(index, target)| predicted_endpoints.contains(target).then_some(index))
        .collect::<Vec<_>>();
    let first_birthday_position = targets
        .iter()
        .position(|target| {
            target.ip() == stable_endpoint.ip()
                && !predicted_endpoints.contains(target)
                && *target != stable_endpoint
        })
        .expect("birthday target should still be present");

    assert_eq!(predicted_positions.len(), PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert!(predicted_positions
        .iter()
        .all(|position| *position < first_birthday_position));

    let diagnostics = manager.diagnostics().await;
    let predicted = diagnostics[0]
        .candidate_pair_stats
        .iter()
        .find(|stats| stats.source == CandidatePairSource::Predicted)
        .unwrap();
    assert_eq!(
        predicted.probe_budget_per_cycle,
        Some(PREDICTED_PROBE_COOLDOWN_BUDGET_PER_CYCLE)
    );
    assert_eq!(
        predicted.probe_budget_reason.as_deref(),
        Some("history_cooldown")
    );
}

#[tokio::test]
async fn synchronized_punch_prioritizes_failed_predicted_before_birthday() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "8.8.8.8:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let predicted_candidates = (0..24)
        .map(|index| format!("8.8.8.8:{}", 41_000 + index))
        .collect::<Vec<_>>();
    let predicted_endpoints = predicted_candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .collect::<HashSet<_>>();
    let sources = predicted_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &predicted_candidates, &sources)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        for endpoint in &predicted_endpoints {
            conn.ensure_candidate_pair_with_source(*endpoint, 0, CandidatePairSource::Predicted)
                .record_failure(REASON_DIRECT_PROBE_FAILED, "recent predicted miss", None);
        }
    }

    let targets = manager.direct_probe_targets_for("peer1").await;
    let predicted_positions = targets
        .iter()
        .enumerate()
        .filter_map(|(index, target)| predicted_endpoints.contains(target).then_some(index))
        .collect::<Vec<_>>();
    let first_birthday_position = targets
        .iter()
        .position(|target| {
            target.ip() == stable_endpoint.ip()
                && !predicted_endpoints.contains(target)
                && *target != stable_endpoint
        })
        .expect("birthday target should still be present");

    assert_eq!(predicted_positions.len(), PREDICTED_PROBE_BUDGET_PER_CYCLE);
    assert!(predicted_positions
        .iter()
        .all(|position| *position < first_birthday_position));
}

#[test]
fn birthday_probe_endpoints_cover_layered_port_window() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let endpoints = birthday_probe_endpoints(base);
    let ports = endpoints
        .iter()
        .map(SocketAddr::port)
        .collect::<HashSet<_>>();

    assert_eq!(endpoints.len(), birthday_probe_near_rank_count());
    for port in [
        39999, 40001, 39996, 40004, 39990, 40010, 39983, 40017, 39981, 40019, 39968, 40032, 39904,
        40096,
    ] {
        assert!(ports.contains(&port), "missing birthday port {port}");
    }
}

#[test]
fn birthday_probe_endpoints_for_bases_interleaves_public_ports() {
    let bases = vec![
        "203.0.113.10:40000".parse::<SocketAddr>().unwrap(),
        "203.0.113.10:40100".parse::<SocketAddr>().unwrap(),
        "203.0.113.10:40200".parse::<SocketAddr>().unwrap(),
    ];

    let endpoints = birthday_probe_endpoints_for_bases(&bases, 6);
    let ports = endpoints
        .iter()
        .map(SocketAddr::port)
        .collect::<HashSet<_>>();

    assert_eq!(endpoints.len(), 6);
    for port in [40001, 39999, 40101, 40099, 40201, 40199] {
        assert!(
            ports.contains(&port),
            "missing interleaved birthday port {port}"
        );
    }
}

#[test]
fn birthday_probe_endpoints_for_bases_spreads_beyond_near_window() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let budget = birthday_probe_near_rank_count() + 4;
    let endpoints = birthday_probe_endpoints_for_bases(&[base], budget);
    let ports = endpoints
        .iter()
        .map(SocketAddr::port)
        .collect::<HashSet<_>>();

    assert_eq!(endpoints.len(), budget);
    assert!(ports.contains(&39904));
    assert!(ports.contains(&40096));
    assert!(ports.contains(&40251));
    assert!(ports.contains(&39749));
    assert!(ports
        .iter()
        .all(|port| port.abs_diff(40000) <= BIRTHDAY_PROBE_WIDE_MAX_DELTA as u16));
    assert!(ports.iter().any(|port| port.abs_diff(40000) > 64));
}

#[test]
fn birthday_probe_endpoints_for_bases_rotates_bounded_window() {
    let base: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let first = birthday_probe_endpoints_for_bases_from_rank(&[base], 64, 0);
    let second =
        birthday_probe_endpoints_for_bases_from_rank(&[base], 64, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);
    let first_ports = first.iter().map(SocketAddr::port).collect::<HashSet<_>>();
    let second_ports = second.iter().map(SocketAddr::port).collect::<HashSet<_>>();

    assert_eq!(first.len(), 64);
    assert_eq!(second.len(), 64);
    assert!(first_ports.is_disjoint(&second_ports));
}

#[tokio::test]
async fn birthday_candidates_use_wider_default_probe_budget() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let initial_targets = manager.direct_probe_targets_for("peer1").await;
    let initial_birthday_count = initial_targets
        .iter()
        .filter(|target| **target != endpoint && target.ip() == endpoint.ip())
        .count();
    assert!(initial_targets.contains(&endpoint));
    assert_eq!(initial_birthday_count, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);

    let background_targets = manager.direct_probe_targets().await;
    assert_eq!(background_targets.len(), 1);
    let targets = &background_targets[0].1;
    let birthday_count = targets
        .iter()
        .filter(|target| **target != endpoint && target.ip() == endpoint.ip())
        .count();

    assert!(targets.contains(&endpoint));
    assert_eq!(birthday_count, BIRTHDAY_PROBE_BUDGET_PER_CYCLE);
}

#[tokio::test]
async fn remote_port_churn_triggers_birthday_probe_targets() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let registry_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let candidates = vec![
        "203.0.113.10:41001".to_string(),
        "203.0.113.10:41037".to_string(),
        "203.0.113.10:41113".to_string(),
    ];
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let background_targets = manager.direct_probe_targets().await;
    assert_eq!(background_targets.len(), 1);
    let targets = &background_targets[0].1;
    let birthday_targets = targets
        .iter()
        .filter(|target| {
            target.ip().to_string() == "203.0.113.10"
                && !candidates.contains(&target.to_string())
                && **target != registry_endpoint
        })
        .collect::<Vec<_>>();
    let bases = candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .chain(std::iter::once(registry_endpoint))
        .collect::<Vec<_>>();
    let expected_birthday_targets = birthday_probe_endpoints_for_bases(
        &bases,
        birthday_probe_budget_for_base_count(&TraversalHistory::default(), bases.len()),
    )
    .into_iter()
    .filter(|target| {
        target.ip().to_string() == "203.0.113.10"
            && !candidates.contains(&target.to_string())
            && *target != registry_endpoint
    })
    .count();

    assert!(targets.contains(&registry_endpoint));
    assert_eq!(birthday_targets.len(), expected_birthday_targets);
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41001) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41037) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41113) <= 2));
}

#[tokio::test]
async fn remote_port_churn_triggers_birthday_targets_in_synchronized_punch() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let registry_endpoint: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let candidates = vec![
        "203.0.113.10:41001".to_string(),
        "203.0.113.10:41037".to_string(),
        "203.0.113.10:41113".to_string(),
    ];
    let sources = candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();

    manager
        .add_peer(&test_peer("peer1", registry_endpoint))
        .await;
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    let birthday_targets = targets
        .iter()
        .filter(|target| {
            target.ip().to_string() == "203.0.113.10"
                && !candidates.contains(&target.to_string())
                && **target != registry_endpoint
        })
        .collect::<Vec<_>>();
    let bases = candidates
        .iter()
        .map(|candidate| candidate.parse::<SocketAddr>().unwrap())
        .chain(std::iter::once(registry_endpoint))
        .collect::<Vec<_>>();
    let expected_birthday_targets = birthday_probe_endpoints_for_bases(
        &bases,
        birthday_probe_budget_for_base_count(&TraversalHistory::default(), bases.len()),
    )
    .into_iter()
    .filter(|target| {
        target.ip().to_string() == "203.0.113.10"
            && !candidates.contains(&target.to_string())
            && *target != registry_endpoint
    })
    .count();

    assert!(targets.contains(&registry_endpoint));
    assert_eq!(birthday_targets.len(), expected_birthday_targets);
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41001) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41037) <= 2));
    assert!(birthday_targets
        .iter()
        .any(|target| target.port().abs_diff(41113) <= 2));
}

#[tokio::test]
async fn stale_birthday_pairs_are_pruned_when_signaled_ports_move() {
    let manager = PeerManager::new(test_config());
    manager
        .add_peer(&test_peer("peer1", "127.0.0.1:51820".parse().unwrap()))
        .await;

    let first_candidates = vec!["8.8.8.8:41000".to_string(), "8.8.8.8:41037".to_string()];
    let first_sources = first_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &first_candidates, &first_sources)
        .await;

    let first_targets = manager.direct_probe_targets_for("peer1").await;
    let stale_birthday: SocketAddr = "8.8.8.8:41001".parse().unwrap();
    assert!(first_targets.contains(&stale_birthday));

    let next_candidates = vec!["8.8.8.8:42000".to_string(), "8.8.8.8:42037".to_string()];
    let next_sources = next_candidates
        .iter()
        .map(|candidate| (candidate.clone(), "stun_observed".to_string()))
        .collect::<HashMap<_, _>>();
    manager
        .add_candidates_with_sources("peer1", &next_candidates, &next_sources)
        .await;

    let next_targets = manager.direct_probe_targets_for("peer1").await;
    assert!(!next_targets.contains(&stale_birthday));

    let diagnostics = manager.diagnostics().await;
    assert!(!diagnostics[0]
        .candidate_pairs
        .iter()
        .any(|pair| pair.remote_endpoint == stale_birthday.to_string()));
}

#[tokio::test]
async fn stable_public_candidate_precedes_birthday_budget_in_due_targets() {
    let mut history = TraversalHistory::default();
    history.record_success(CandidatePairSource::Birthday);
    let manager = PeerManager::new_with_history(test_config(), None, history);
    let stable_endpoint: SocketAddr = "8.8.4.4:40000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let due_targets = manager
        .direct_probe_targets_due(Duration::from_secs(0))
        .await;
    assert_eq!(due_targets.len(), 1);
    assert_eq!(due_targets[0].0, "peer1");

    let targets = &due_targets[0].1;
    let birthday_count = targets
        .iter()
        .filter(|target| **target != stable_endpoint && target.ip() == stable_endpoint.ip())
        .count();

    assert_eq!(targets.first().copied(), Some(stable_endpoint));
    assert!(targets.contains(&stable_endpoint));
    assert_eq!(birthday_count, BIRTHDAY_PROBE_SUCCESS_BUDGET_PER_CYCLE);
}

#[tokio::test]
async fn failed_stable_public_candidate_gets_short_background_retry() {
    let manager = PeerManager::new(test_config());
    let stable_endpoint: SocketAddr = "8.8.4.4:40000".parse().unwrap();
    let peer = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    manager.add_peer(&peer).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[stable_endpoint.to_string()],
            &HashMap::from([(stable_endpoint.to_string(), "stun_observed".to_string())]),
        )
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == stable_endpoint)
            .unwrap();
        for _ in 0..4 {
            pair.record_failure(REASON_DIRECT_PROBE_FAILED, "old failure", None);
        }
        pair.last_failure_at = Some(
            Instant::now() - PRIORITY_OUTBOUND_PROBE_FAILURE_COOLDOWN - Duration::from_secs(1),
        );
    }

    let due_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert_eq!(due_targets.len(), 1);
    assert_eq!(due_targets[0].1, vec![stable_endpoint]);
}

#[tokio::test]
async fn failed_speculative_candidate_keeps_exponential_background_cooldown() {
    let manager = PeerManager::new(test_config());
    let predicted_endpoint: SocketAddr = "8.8.4.4:41000".parse().unwrap();
    let peer = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    manager.add_peer(&peer).await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[predicted_endpoint.to_string()],
            &HashMap::from([(predicted_endpoint.to_string(), "predicted".to_string())]),
        )
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == predicted_endpoint)
            .unwrap();
        for _ in 0..4 {
            pair.record_failure(REASON_DIRECT_PROBE_FAILED, "old failure", None);
        }
        pair.last_failure_at = Some(
            Instant::now() - PRIORITY_OUTBOUND_PROBE_FAILURE_COOLDOWN - Duration::from_secs(1),
        );
    }

    let due_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert!(due_targets.is_empty());
}

#[tokio::test]
async fn candidate_pair_probe_targets_use_source_success_feedback() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let signaled_endpoint: SocketAddr = "8.8.8.8:51838".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51839".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
            .await
    );

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let signaled = conn.ensure_candidate_pair_with_source(
            signaled_endpoint,
            0,
            CandidatePairSource::Signaled,
        );
        signaled.success_count = 2;
        signaled.state = CandidatePairState::Waiting;

        let peer_reflexive = conn.ensure_candidate_pair_with_source(
            peer_reflexive_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        );
        peer_reflexive.failure_count = 2;
        peer_reflexive.state = CandidatePairState::Waiting;
    }

    let targets = manager.direct_probe_targets().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert_eq!(
        targets[0].1,
        vec![signaled_endpoint, peer_reflexive_endpoint]
    );
}

#[tokio::test]
async fn candidate_pair_probe_targets_prioritize_non_failed_pairs() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51829".parse().unwrap();
    let waiting_endpoint: SocketAddr = "127.0.0.1:51830".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: failed_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    manager
        .add_candidates("peer1", &[waiting_endpoint.to_string()])
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair(failed_endpoint, 0)
            .record_failure(REASON_DIRECT_PROBE_FAILED, "no ACK", None);
    }

    let targets = manager.direct_probe_targets().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert_eq!(targets[0].1, vec![waiting_endpoint]);
}

#[tokio::test]
async fn candidate_pair_probe_targets_reallow_failed_pair_after_cooldown() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51845".parse().unwrap();

    manager.add_peer(&test_peer("peer1", failed_endpoint)).await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn.ensure_candidate_pair_with_source(
            failed_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        );
        pair.record_failure(REASON_DIRECT_PROBE_FAILED, "old failure", None);
        pair.last_failure_at =
            Some(Instant::now() - CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE - Duration::from_secs(1));
    }

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![failed_endpoint]);
}

#[tokio::test]
async fn synchronized_probe_targets_bypass_failure_cooldown() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51846".parse().unwrap();

    manager.add_peer(&test_peer("peer1", failed_endpoint)).await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "no ACK")
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "still no ACK")
        .await;

    let background_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert!(background_targets.is_empty());

    let synchronized_targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(synchronized_targets, vec![failed_endpoint]);
}

#[test]
fn direct_retry_backoff_uses_one_two_four_eight_seconds() {
    let mut health = PathHealth::default();
    let base = DIRECT_RETRY_BASE_INTERVAL;

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "first failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(1));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "second failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(2));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "third failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(4));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "fourth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(8));

    health.record_failure(REASON_DIRECT_PROBE_FAILED, "fifth failure");
    assert_eq!(health.retry_after(base), Duration::from_secs(8));
}

#[tokio::test]
async fn hard_local_and_scattered_peer_without_history_skip_background_retry() {
    let manager = PeerManager::new(test_config());
    let endpoint_a: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let endpoint_b: SocketAddr = "203.0.113.10:40037".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint_a)).await;
    manager
        .add_candidates("peer1", &[endpoint_b.to_string()])
        .await;
    manager.update_nat_profile(birthday_nat_profile()).await;

    let targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert!(targets.is_empty());

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(conn.direct_events.iter().any(|event| {
        event.stage == "retry_skipped_no_viable_nat_window" && event.network_generation == 0
    }));
}

#[tokio::test]
async fn previous_direct_success_fast_retries_even_when_nat_now_looks_hard() {
    let manager = PeerManager::new(test_config());
    let endpoint_a: SocketAddr = "203.0.113.10:40000".parse().unwrap();
    let endpoint_b: SocketAddr = "203.0.113.10:40037".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint_a)).await;
    manager
        .add_candidates("peer1", &[endpoint_b.to_string()])
        .await;
    manager.update_nat_profile(birthday_nat_profile()).await;
    manager
        .record_direct_success("peer1", Some(endpoint_a))
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "lost direct")
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.last_failure_at =
            Some(Instant::now() - DIRECT_RETRY_BASE_INTERVAL - Duration::from_millis(10));
        for pair in &mut conn.candidate_pairs {
            pair.last_failure_at = Some(
                Instant::now() - CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE - Duration::from_millis(10),
            );
        }
    }

    let targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert!(targets[0].1.contains(&endpoint_a));
}

#[tokio::test]
async fn generation_change_opens_immediate_direct_reclaim_window() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "203.0.113.20:41000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let generation = manager.advance_network_generation("hotspot_handover").await;
    assert_eq!(generation, 1);
    assert!(manager.direct_reclaim_active("peer1").await);

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_NETWORK_GENERATION_CHANGED)
    );
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_reclaim_window_started"));

    let targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].0, "peer1");
    assert!(targets[0].1.contains(&endpoint));
}

#[tokio::test]
async fn direct_reclaim_window_bypasses_retry_and_pair_cooldowns() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "203.0.113.21:41000".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let generation = manager.advance_network_generation("hotspot_handover").await;

    let first_targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(first_targets.len(), 1);

    assert!(
        manager
            .record_direct_failure_for_generation(
                "peer1",
                generation,
                REASON_DIRECT_PROBE_FAILED,
                "no reclaim ACK yet",
            )
            .await
    );

    let second_targets = manager
        .direct_probe_targets_due(DIRECT_RETRY_BASE_INTERVAL)
        .await;
    assert_eq!(second_targets.len(), 1);
    assert_eq!(second_targets[0].0, "peer1");
    assert!(second_targets[0].1.contains(&endpoint));

    let conn = manager.get_connection("peer1").await.unwrap();
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "direct_reclaim_targets_due"));
}

#[tokio::test]
async fn diagnostics_reports_candidate_pair_probe_cooldown_remaining() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let failed_endpoint: SocketAddr = "127.0.0.1:51847".parse().unwrap();

    manager.add_peer(&test_peer("peer1", failed_endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(
            failed_endpoint,
            0,
            CandidatePairSource::PeerReflexive,
        )
        .record_failure(REASON_DIRECT_PROBE_FAILED, "recent failure", None);
    }

    let diagnostics = manager.diagnostics().await;
    let pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == failed_endpoint.to_string())
        .unwrap();
    assert!(!pair.probe_due);
    assert_eq!(pair.probe_retry_after_ms, Some(1_000));
    assert!(pair.probe_retry_remaining_ms.unwrap() > 0);
    assert!(pair.probe_retry_remaining_ms.unwrap() <= 1_000);

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == failed_endpoint)
            .unwrap();
        pair.last_failure_at =
            Some(Instant::now() - CANDIDATE_PAIR_FAILURE_COOLDOWN_BASE - Duration::from_secs(1));
    }

    let diagnostics = manager.diagnostics().await;
    let pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == failed_endpoint.to_string())
        .unwrap();
    assert!(pair.probe_due);
    assert_eq!(pair.probe_retry_after_ms, Some(1_000));
    assert_eq!(pair.probe_retry_remaining_ms, Some(0));
}

#[tokio::test]
async fn candidate_pair_probe_targets_promote_authenticated_peer_reflexive() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let signaled_endpoint: SocketAddr = "8.8.8.8:51830".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51831".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: signaled_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    assert!(
        manager
            .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
            .await
    );

    let targets = manager.direct_probe_targets().await;
    assert_eq!(targets.len(), 1);
    assert_eq!(
        targets[0].1,
        vec![peer_reflexive_endpoint, signaled_endpoint]
    );
    for endpoint in &targets[0].1 {
        assert!(manager.record_direct_probe_sent("peer1", *endpoint).await);
    }

    let conn = manager.get_connection("peer1").await.unwrap();
    let peer_reflexive_pair = conn
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == peer_reflexive_endpoint)
        .unwrap();
    assert_eq!(
        peer_reflexive_pair.source,
        CandidatePairSource::PeerReflexive
    );
    assert_eq!(peer_reflexive_pair.probe_count, 2);
    assert!(peer_reflexive_pair.last_probe_at.is_some());

    let diagnostics = manager.diagnostics().await;
    let diagnostic_pair = diagnostics[0]
        .candidate_pairs
        .iter()
        .find(|pair| pair.remote_endpoint == peer_reflexive_endpoint.to_string())
        .unwrap();
    assert_eq!(diagnostic_pair.source, CandidatePairSource::PeerReflexive);
    assert_eq!(diagnostic_pair.probe_count, 2);
    assert!(diagnostic_pair.last_probe_age_ms.is_some());
}

#[tokio::test]
async fn direct_send_prefers_fresh_authenticated_peer_reflexive_endpoint() {
    let manager = PeerManager::new(test_config());
    let signaled_endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();
    let peer_reflexive_endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();
    manager
        .add_peer(&test_peer("peer1", signaled_endpoint))
        .await;

    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            signaled_endpoint,
            Some(Duration::from_millis(1)),
        )
        .await;
    assert!(
        manager
            .learn_authenticated_endpoint("peer1", peer_reflexive_endpoint)
            .await
    );

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(peer_reflexive_endpoint)
    );
}

#[tokio::test]
async fn test_peer_manager_selects_endpoint_from_candidates() {
    let config = test_config();
    let manager = PeerManager::new(config);

    let peer_info = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    manager.add_peer(&peer_info).await;
    manager
        .add_candidates(
            "peer1",
            &[
                "not-a-socket".to_string(),
                "127.0.0.1:51820".to_string(),
                "10.0.0.1:51820".to_string(),
            ],
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.endpoint, Some("127.0.0.1:51820".parse().unwrap()));
}

#[tokio::test]
async fn test_peer_manager_learns_endpoint_from_probe_source_without_confirming_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);

    let peer_info = PeerInfo {
        node_id: "peer1".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: "pk".to_string(),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    let selected_endpoint: SocketAddr = "127.0.0.1:51821".parse().unwrap();

    manager.add_peer(&peer_info).await;
    manager
        .add_candidates("peer1", &[selected_endpoint.to_string()])
        .await;

    let selected = manager.learn_endpoint_from_addr(selected_endpoint).await;
    assert_eq!(selected, Some("peer1".to_string()));

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.endpoint, Some(selected_endpoint));
    assert_eq!(conn.state, ConnectionState::Idle);
    assert!(manager.direct_endpoints().await.is_empty());
}

#[tokio::test]
async fn path_selector_prefers_relay_until_direct_is_confirmed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51831".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let waiting = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(waiting.path, Some(NetworkPath::Relay));
    assert_eq!(waiting.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert_eq!(waiting.direct_endpoint, None);

    let no_relay = manager.select_path_for_data("peer1", true, false).await;
    assert_eq!(no_relay.path, Some(NetworkPath::Direct));
    assert_eq!(no_relay.reason_code, REASON_PATH_RELAY_UNAVAILABLE);
    assert_eq!(no_relay.direct_endpoint, Some(endpoint));
    assert!(!no_relay.direct_confirmed);

    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(6)))
        .await;
    let provisional = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(provisional.path, Some(NetworkPath::Direct));
    assert!(!provisional.direct_confirmed);
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().active_path(),
        None
    );
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let confirmed = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(confirmed.path, Some(NetworkPath::Direct));
    assert_eq!(confirmed.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert_eq!(confirmed.direct_endpoint, Some(endpoint));
    assert!(confirmed.direct_confirmed);
    assert!(
        confirmed.direct_score.as_ref().unwrap().score
            > confirmed.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_uses_scores_and_hysteresis_for_degraded_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51836".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    let healthy = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(healthy.path, Some(NetworkPath::Direct));
    assert_eq!(healthy.reason_code, REASON_PATH_DIRECT_CONFIRMED);

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 3;
        conn.direct_health.failure_count = 3;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let degraded = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(degraded.path, Some(NetworkPath::Relay));
    assert_eq!(degraded.reason_code, REASON_PATH_DIRECT_DEGRADED);
    assert!(!degraded.direct_confirmed);
    assert!(!degraded.relay_hedged);
    assert!(
        degraded.direct_score.as_ref().unwrap().score + DIRECT_TO_RELAY_HYSTERESIS_MARGIN
            < degraded.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_retains_low_latency_private_direct_over_relay() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "192.168.2.11:51839".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(6)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 3;
        conn.direct_health.failure_count = 5;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selected.direct_confirmed);
    let direct_score = selected.direct_score.as_ref().unwrap().score;
    let relay_score = selected.relay_score.as_ref().unwrap().score;
    assert!(direct_score < DIRECT_CONFIRMED_MIN_SCORE);
    assert!(direct_score < relay_score);
}

#[tokio::test]
async fn candidate_refresh_retains_low_latency_private_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "192.168.2.11:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    assert_eq!(manager.current_network_generation().await, 0);

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;
    assert_eq!(generation, 1);

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.direct_generation, generation);
    assert_eq!(conn.endpoint, Some(endpoint));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == 0
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Degraded
            && pair.last_error_code.as_deref() == Some(REASON_NETWORK_GENERATION_CHANGED)
    }));
    assert!(conn.candidate_pairs.iter().any(|pair| {
        pair.local_generation == generation
            && pair.remote_endpoint == endpoint
            && pair.state == CandidatePairState::Selected
            && pair.rtt_ewma_ms.or(pair.rtt_ms) == Some(7)
    }));
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(endpoint)
    );
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn candidate_refresh_still_invalidates_public_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:51841".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(7)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;

    let generation = manager
        .advance_candidate_refresh_generation("refreshed UDP candidates")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(generation, 1);
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_NETWORK_GENERATION_CHANGED)
    );
    assert!(
        !manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn path_selector_prefers_relay_when_confirmed_direct_quality_is_poor() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51838".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 1;
        conn.direct_health.failure_count = 1;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Relay));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);
    assert!(!selected.direct_confirmed);
    assert!(!selected.relay_hedged);
    let direct_score = selected.direct_score.as_ref().unwrap().score;
    let relay_score = selected.relay_score.as_ref().unwrap().score;
    assert!(direct_score < DIRECT_CONFIRMED_MIN_SCORE);
    assert!(direct_score < relay_score);
}

#[tokio::test]
async fn degraded_direct_is_retained_until_relay_peer_path_is_confirmed() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51842".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 2;
        conn.direct_health.failure_count = 2;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert!(selected.direct_confirmed);
    assert!(selected.relay_hedged);
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Direct));
    assert!(
        diagnostics[0]
            .current_path_selection
            .as_ref()
            .unwrap()
            .relay_hedged
    );
}

#[tokio::test]
async fn very_slow_public_direct_is_hedged_with_unconfirmed_relay() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "8.8.8.8:51842".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(570)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.rtt_ewma_ms = Some(570);
        conn.direct_health.jitter_ms = Some(0);
        conn.direct_health.success_count = 100;
        conn.direct_health.failure_count = 0;
        conn.direct_health.consecutive_failures = 0;
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert!(selected.direct_confirmed);
    assert!(selected.relay_hedged);
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_DEGRADED);
    assert!(
        selected.direct_score.as_ref().unwrap().score
            < selected.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_uses_hedged_trial_direct_when_relay_scores_higher() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51839".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.relay_health.rtt_ewma_ms = Some(10);
        conn.relay_health.success_count = 5;
    }

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert!(selected.relay_hedged);
    assert!(!selected.direct_confirmed);
    assert!(
        selected.direct_score.as_ref().unwrap().score
            < selected.relay_score.as_ref().unwrap().score
    );
}

#[tokio::test]
async fn path_selector_keeps_relay_for_inbound_only_probe_without_ack() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    manager.record_direct_probe_success("peer1", endpoint).await;

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Relay));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(!selected.direct_confirmed);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    let pair = diagnostics[0].current_direct_pair.as_ref().unwrap();
    assert_eq!(diagnostics[0].direct_type, DirectPathType::Relay);
    assert_eq!(pair.pair_state, CandidatePairState::Probing);
    assert!(!pair.nominated);
    assert!(!pair.selected);
    assert_ne!(pair.direct_type, DirectPathType::PublicUdp);
}

#[tokio::test]
async fn recent_public_probe_success_stays_trial_candidate_after_single_timeout() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let stable_endpoint: SocketAddr = "8.8.8.8:60207".parse().unwrap();
    let birthday_endpoint: SocketAddr = "8.8.8.8:60183".parse().unwrap();

    manager.add_peer(&test_peer("peer1", stable_endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[stable_endpoint.to_string()],
            &HashMap::from([(stable_endpoint.to_string(), "peer_reflexive".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            stable_endpoint,
            Some(Duration::from_millis(45)),
        )
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.ensure_candidate_pair_with_source(birthday_endpoint, 0, CandidatePairSource::Birthday)
            .record_probing(None);
        let stable_pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == stable_endpoint)
            .unwrap();
        stable_pair.record_failure(REASON_DIRECT_PROBE_FAILED, "one missed batch", None);
        conn.direct_health
            .record_failure(REASON_DIRECT_PROBE_FAILED, "one missed batch");
    }

    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(stable_endpoint),
        "a recently successful public endpoint should stay ahead of speculative birthday ports"
    );

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.path, Some(NetworkPath::Direct));
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert_eq!(selected.direct_endpoint, Some(stable_endpoint));
    assert!(selected.relay_hedged);
    assert!(!selected.direct_confirmed);

    let diagnostics = manager.diagnostics().await;
    let current = diagnostics[0].current_direct_pair.as_ref().unwrap();
    assert_eq!(current.remote_endpoint, stable_endpoint.to_string());
    assert!(current.nominated);
}

#[tokio::test]
async fn path_selector_does_not_treat_unselected_succeeded_pair_as_confirmed_direct() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let selected_endpoint: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let trial_endpoint: SocketAddr = "1.1.1.1:41000".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", selected_endpoint))
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[selected_endpoint.to_string(), trial_endpoint.to_string()],
            &HashMap::from([
                (selected_endpoint.to_string(), "stun_observed".to_string()),
                (trial_endpoint.to_string(), "peer_reflexive".to_string()),
            ]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            selected_endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(selected_endpoint))
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            trial_endpoint,
            Some(Duration::from_millis(12)),
        )
        .await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        let pair = conn
            .candidate_pairs
            .iter_mut()
            .find(|pair| pair.remote_endpoint == selected_endpoint)
            .unwrap();
        pair.record_failure(REASON_DIRECT_KEEPALIVE_TIMEOUT, "selected pair stale", None);
    }

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(selection.direct_endpoint, Some(trial_endpoint));
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert!(!selection.direct_confirmed);
    assert!(selection.relay_hedged);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_ne!(diagnostics[0].direct_type, DirectPathType::PublicUdp);
    assert!(!diagnostics[0].is_public_udp_direct);
    assert_eq!(diagnostics[0].direct_type, DirectPathType::Relay);
    assert_eq!(
        diagnostics[0]
            .current_direct_pair
            .as_ref()
            .unwrap()
            .pair_state,
        CandidatePairState::Succeeded
    );
    assert_eq!(
        diagnostics[0]
            .current_direct_pair
            .as_ref()
            .unwrap()
            .direct_type,
        DirectPathType::Relay
    );
}

#[tokio::test]
async fn direct_keepalive_targets_selected_pair_not_unselected_trial_pair() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let selected_endpoint: SocketAddr = "8.8.8.8:12293".parse().unwrap();
    let trial_endpoint: SocketAddr = "1.1.1.1:41000".parse().unwrap();

    manager
        .add_peer(&test_peer("peer1", selected_endpoint))
        .await;
    manager
        .add_candidates_with_sources(
            "peer1",
            &[selected_endpoint.to_string(), trial_endpoint.to_string()],
            &HashMap::from([
                (selected_endpoint.to_string(), "stun_observed".to_string()),
                (trial_endpoint.to_string(), "peer_reflexive".to_string()),
            ]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            selected_endpoint,
            Some(Duration::from_millis(18)),
        )
        .await;
    manager
        .record_direct_success("peer1", Some(selected_endpoint))
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            trial_endpoint,
            Some(Duration::from_millis(12)),
        )
        .await;

    assert_eq!(
        manager.direct_endpoints().await,
        vec![("peer1".to_string(), selected_endpoint)]
    );

    assert!(
        manager
            .record_direct_keepalive_timeout_for_generation("peer1", selected_endpoint, 0,)
            .await
    );
    assert_eq!(
        manager.direct_endpoint_for_send("peer1").await,
        Some(trial_endpoint)
    );
    assert_eq!(
        manager.direct_endpoints().await,
        vec![("peer1".to_string(), selected_endpoint)]
    );
}

#[tokio::test]
async fn path_selection_timeline_records_only_real_changes() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51837".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let first = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(first.path, Some(NetworkPath::Relay));
    let repeated = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(repeated.path, Some(NetworkPath::Relay));

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].path_events.len(), 1);
    assert_eq!(diagnostics[0].path_events[0].previous_path, None);
    assert_eq!(
        diagnostics[0].path_events[0].selected_path,
        Some(NetworkPath::Relay)
    );
    assert_eq!(
        diagnostics[0].path_events[0].reason_code,
        REASON_PATH_DIRECT_NOT_CONFIRMED
    );

    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(9)))
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    let direct = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(direct.path, Some(NetworkPath::Direct));

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].path_events.len(), 2);
    assert_eq!(
        diagnostics[0].path_events[1].previous_path,
        Some(NetworkPath::Relay)
    );
    assert_eq!(
        diagnostics[0].path_events[1].selected_path,
        Some(NetworkPath::Direct)
    );
    assert_eq!(
        diagnostics[0].path_events[1].reason_code,
        REASON_PATH_DIRECT_CONFIRMED
    );

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    assert_eq!(json["path_events"].as_array().unwrap().len(), 2);
    assert!(json["path_events"][1]["direct_score"]["score"].is_i64());
}

#[tokio::test]
async fn direct_traversal_timeline_records_probe_flow() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "203.0.113.10:60207".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let candidates = vec![endpoint.to_string()];
    let sources = HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]);
    manager
        .add_candidates_with_sources("peer1", &candidates, &sources)
        .await;

    let targets = manager.direct_probe_targets_for("peer1").await;
    assert_eq!(targets, vec![endpoint]);

    manager
        .record_direct_event(
            "peer1",
            "punch_probes_sent",
            Some(endpoint),
            Some(targets.len()),
            Some(3),
            "sent test probes",
        )
        .await;

    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                endpoint,
                Some(Duration::from_millis(42)),
                generation,
            )
            .await
    );

    let diagnostics = manager.diagnostics().await;
    let stages = diagnostics[0]
        .direct_events
        .iter()
        .map(|event| event.stage.as_str())
        .collect::<Vec<_>>();

    assert!(stages.contains(&"candidates_received"));
    assert!(stages.contains(&"probe_targets_selected"));
    assert!(stages.contains(&"punch_probes_sent"));
    assert!(stages.contains(&"probe_ack_received"));
    assert_eq!(
        diagnostics[0]
            .direct_events
            .iter()
            .find(|event| event.stage == "probe_ack_received")
            .and_then(|event| event.endpoint.as_deref()),
        Some("203.0.113.10:60207")
    );
}

#[tokio::test]
async fn path_selector_honors_relay_policy_and_reports_no_path() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51832".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    let relay_policy = manager.select_path_for_data("peer1", false, true).await;
    assert_eq!(relay_policy.path, Some(NetworkPath::Relay));
    assert_eq!(relay_policy.reason_code, REASON_PATH_DIRECT_DISABLED);

    let no_state = manager.select_path_for_data("missing", true, false).await;
    assert_eq!(no_state.path, None);
    assert_eq!(no_state.reason_code, REASON_PATH_UNAVAILABLE);
}

#[tokio::test]
async fn path_selection_diagnostics_exposes_current_and_last_selection() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51833".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].active_path, None);
    let current = diagnostics[0].current_path_selection.as_ref().unwrap();
    assert_eq!(current.path, Some(NetworkPath::Relay));
    assert_eq!(current.direct_endpoint, None);
    assert_eq!(current.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(
        current.direct_score.as_ref().unwrap().score < current.relay_score.as_ref().unwrap().score
    );
    assert_eq!(diagnostics[0].last_path_selection, None);

    let selected = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selected.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, None);
    let current = diagnostics[0].current_path_selection.as_ref().unwrap();
    let last = diagnostics[0].last_path_selection.as_ref().unwrap();
    assert_eq!(current.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert_eq!(last.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);

    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    assert_eq!(
        json["current_path_selection"]["reason_code"],
        REASON_PATH_DIRECT_NOT_CONFIRMED
    );
    assert_eq!(
        json["last_path_selection"]["reason_code"],
        REASON_PATH_DIRECT_NOT_CONFIRMED
    );
    assert!(json["current_path_selection"]["direct_score"]["score"].is_i64());
    assert!(json["current_path_selection"]["relay_score"]["score"].is_i64());
}

#[tokio::test]
async fn relay_failure_clears_confirmed_active_path() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51841".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    let before = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(before[0].active_path, Some(NetworkPath::Relay));

    manager
        .record_relay_failure("peer1", "peer_not_found", "peer not found: peer1")
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    let after = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(after[0].active_path, None);
    assert_eq!(
        after[0].relay.last_error_code.as_deref(),
        Some("peer_not_found")
    );
}

#[tokio::test]
async fn stale_relay_confirmation_is_not_reported_active_but_remains_available() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51844".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay.test:443").await;
    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.relay_health.last_success_at =
            Some(Instant::now() - RELAY_PEER_CONFIRMATION_MAX_AGE - Duration::from_secs(1));
    }

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].state, ConnectionState::Relay);
    assert_eq!(diagnostics[0].active_path, None);
    assert!(diagnostics[0]
        .relay
        .last_success_age_ms
        .is_some_and(|age| age > duration_millis(RELAY_PEER_CONFIRMATION_MAX_AGE)));

    let selection = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(selection.path, Some(NetworkPath::Relay));

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].active_path, None);
    assert_eq!(
        diagnostics[0]
            .current_path_selection
            .as_ref()
            .and_then(|selection| selection.path),
        Some(NetworkPath::Relay)
    );
}

#[tokio::test]
async fn relay_validation_targets_include_slow_direct_but_skip_fast_direct() {
    let manager = PeerManager::new(test_config());
    let fast_endpoint: SocketAddr = "127.0.0.1:51845".parse().unwrap();
    let slow_endpoint: SocketAddr = "127.0.0.1:51846".parse().unwrap();

    manager.add_peer(&test_peer("fast", fast_endpoint)).await;
    manager.add_peer(&test_peer("slow", slow_endpoint)).await;
    {
        let mut conns = manager.connections.write().await;
        let fast = conns.get_mut("fast").unwrap();
        fast.transition(ConnectionState::Direct);
        fast.direct_health
            .record_success_with_latency(Duration::from_millis(20));

        let slow = conns.get_mut("slow").unwrap();
        slow.transition(ConnectionState::Direct);
        slow.direct_health
            .record_success_with_latency(Duration::from_millis(
                SLOW_DIRECT_RELAY_VALIDATION_RTT_MS,
            ));
    }

    let targets = manager
        .relay_validation_targets(Duration::from_secs(15))
        .await;

    assert!(!targets.iter().any(|(node_id, _)| node_id == "fast"));
    assert!(targets.iter().any(|(node_id, _)| node_id == "slow"));
}

#[tokio::test]
async fn relay_transport_invalidation_clears_all_matching_peer_confirmations() {
    let manager = PeerManager::new(test_config());
    let endpoint: SocketAddr = "127.0.0.1:51843".parse().unwrap();
    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager.set_relay("peer1", "relay-a.test:443").await;

    manager
        .invalidate_relay_transport(
            "relay-a.test:443",
            "relay_transport_closed",
            "relay disconnected",
        )
        .await;

    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(conn.relay_server, None);
    assert!(!conn.relay_health.is_confirmed());
    assert_eq!(
        conn.relay_health.last_error_code.as_deref(),
        Some("relay_transport_closed")
    );
}

#[tokio::test]
async fn peer_manager_stats_can_follow_selected_path_not_stale_state() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51840".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(700)),
        )
        .await;
    manager.record_direct_success("peer1", Some(endpoint)).await;
    manager
        .record_relay_success("peer1", "relay.test:443", false)
        .await;

    {
        let mut conns = manager.connections.write().await;
        let conn = conns.get_mut("peer1").unwrap();
        conn.direct_health.consecutive_failures = 1;
        conn.direct_health.failure_count = 1;
        conn.direct_health.rtt_ewma_ms = Some(650);
        conn.direct_health.jitter_ms = Some(120);
    }

    let stale_stats = manager.stats().await;
    assert_eq!(stale_stats.direct_connections, 1);

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].state, ConnectionState::Direct);
    assert_eq!(diagnostics[0].active_path, Some(NetworkPath::Relay));

    let selected_stats = PeerManagerStats::from_diagnostics(&diagnostics);
    assert_eq!(selected_stats.direct_connections, 0);
    assert_eq!(selected_stats.relay_connections, 1);
}

#[tokio::test]
async fn direct_probe_targets_due_respects_backoff_without_false_probing() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51834".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;

    let first_targets = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert_eq!(first_targets, vec![("peer1".to_string(), vec![endpoint])]);

    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "no ACK")
        .await;
    manager
        .record_direct_failure_with_code("peer1", REASON_DIRECT_PROBE_FAILED, "still no ACK")
        .await;

    let suppressed = manager
        .direct_probe_targets_due(Duration::from_secs(5))
        .await;
    assert!(suppressed.is_empty());

    let diagnostics = manager
        .diagnostics_with_path_selection(true, true, Duration::from_secs(5), None)
        .await;
    assert_eq!(diagnostics[0].direct_retry_after_ms, Some(10_000));
    assert!(diagnostics[0].direct_retry_remaining_ms.unwrap() > 0);
    assert_eq!(diagnostics[0].direct.failure_count, 2);
    assert!(diagnostics[0].candidate_pairs.iter().all(|pair| {
        pair.state != CandidatePairState::Probing
            && pair.failure_count == 2
            && pair.last_error_code.as_deref() == Some(REASON_DIRECT_PROBE_FAILED)
    }));
}

#[tokio::test]
async fn direct_path_latency_tracks_ewma_and_jitter() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51835".parse().unwrap();

    manager.add_peer(&test_peer("peer1", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency("peer1", endpoint, Some(Duration::from_millis(8)))
        .await;
    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(24)),
        )
        .await;

    let diagnostics = manager.diagnostics().await;
    assert_eq!(diagnostics[0].direct.success_count, 2);
    assert_eq!(diagnostics[0].direct.latency_ms, Some(24));
    assert_eq!(diagnostics[0].direct.rtt_ewma_ms, Some(10));
    assert_eq!(diagnostics[0].direct.jitter_ms, Some(4));
    assert_eq!(diagnostics[0].candidate_pairs[0].success_count, 2);
    assert_eq!(diagnostics[0].candidate_pairs[0].rtt_ewma_ms, Some(10));
    assert_eq!(diagnostics[0].candidate_pairs[0].jitter_ms, Some(4));
}

#[tokio::test]
async fn test_peer_manager_path_health_drives_data_path() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51822".parse().unwrap();

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

    assert!(
        !manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, false)
            .await
    );

    manager
        .record_direct_failure("peer1", "probe timeout")
        .await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(conn.direct_health.consecutive_failures, 1);
    assert_eq!(
        conn.direct_health.last_error.as_deref(),
        Some("probe timeout")
    );
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_DIRECT_PROBE_FAILED)
    );

    manager.set_relay("peer1", "127.0.0.1:9000").await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Relay);
    assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
    assert!(conn.relay_health.last_success_at.is_some());

    manager.record_direct_probe_success("peer1", endpoint).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Relay);
    assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
    assert!(conn.direct_health.last_success_at.is_some());
    let trial = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(trial.path, Some(NetworkPath::Relay));
    assert_eq!(trial.reason_code, REASON_PATH_DIRECT_NOT_CONFIRMED);
    assert!(!trial.direct_confirmed);
    assert!(
        !manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );

    manager
        .record_direct_probe_success_with_latency(
            "peer1",
            endpoint,
            Some(Duration::from_millis(12)),
        )
        .await;
    let trial = manager.select_path_for_data("peer1", true, true).await;
    assert_eq!(trial.path, Some(NetworkPath::Direct));
    assert_eq!(trial.reason_code, REASON_PATH_DIRECT_TRIAL);
    assert!(trial.relay_hedged);
    assert!(!trial.direct_confirmed);
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );

    manager.record_direct_success("peer1", Some(endpoint)).await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.active_path(), Some(NetworkPath::Direct));
    assert_eq!(conn.direct_health.consecutive_failures, 0);
    assert!(
        manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );
}

#[tokio::test]
async fn network_generation_invalidates_direct_and_ignores_stale_results() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let old_endpoint: SocketAddr = "127.0.0.1:51824".parse().unwrap();
    let new_endpoint: SocketAddr = "127.0.0.1:51825".parse().unwrap();

    manager
        .add_peer(&PeerInfo {
            node_id: "peer1".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: old_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    assert_eq!(manager.current_network_generation().await, 0);
    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                old_endpoint,
                Some(Duration::from_millis(8)),
                0,
            )
            .await
    );
    manager
        .record_direct_success("peer1", Some(old_endpoint))
        .await;
    assert!(manager.is_direct_for_generation("peer1", 0).await);

    let generation = manager.advance_network_generation("wifi_to_hotspot").await;
    assert_eq!(generation, 1);
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::FallbackToRelay);
    assert_eq!(
        conn.direct_health.last_error_code.as_deref(),
        Some(REASON_NETWORK_GENERATION_CHANGED)
    );
    assert!(
        !manager
            .should_use_direct_for_data("peer1", true, true)
            .await
    );

    assert!(
        !manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                old_endpoint,
                Some(Duration::from_millis(5)),
                0,
            )
            .await
    );
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().state,
        ConnectionState::FallbackToRelay
    );

    assert!(
        manager
            .record_direct_probe_success_with_latency_for_generation(
                "peer1",
                new_endpoint,
                Some(Duration::from_millis(7)),
                generation,
            )
            .await
    );
    assert_eq!(
        manager.get_connection("peer1").await.unwrap().state,
        ConnectionState::HolePunching
    );
    manager
        .record_direct_success_for_generation("peer1", Some(new_endpoint), generation)
        .await;
    let conn = manager.get_connection("peer1").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Direct);
    assert_eq!(conn.endpoint, Some(new_endpoint));
    assert_eq!(conn.direct_generation, generation);
}

#[test]
fn test_diagnostics_enums_serialize_as_snake_case() {
    assert_eq!(
        serde_json::to_string(&ConnectionState::HolePunching).unwrap(),
        "\"hole_punching\""
    );
    assert_eq!(
        serde_json::to_string(&NetworkPath::Direct).unwrap(),
        "\"direct\""
    );
}

#[tokio::test]
async fn test_peer_manager_direct_probe_targets_exclude_direct_peers() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let endpoint: SocketAddr = "127.0.0.1:51823".parse().unwrap();

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

    assert_eq!(
        manager.direct_probe_targets().await,
        vec![("peer1".to_string(), vec![endpoint])]
    );

    manager.record_direct_success("peer1", Some(endpoint)).await;
    assert!(manager.direct_probe_targets().await.is_empty());
}

#[tokio::test]
async fn test_peer_manager_stats() {
    let config = test_config();
    let manager = PeerManager::new(config);

    // Add two peers
    for (id, ip) in [("p1", "10.20.0.2"), ("p2", "10.20.0.3")] {
        let peer_info = PeerInfo {
            node_id: id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: ip.to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        };
        manager.add_peer(&peer_info).await;
    }

    manager.update_state("p1", ConnectionState::Direct).await;
    manager.update_state("p2", ConnectionState::Relay).await;

    manager.record_sent("p1", 1000).await;
    manager.record_received("p2", 500).await;

    let stats = manager.stats().await;
    assert_eq!(stats.total_peers, 2);
    assert_eq!(stats.direct_connections, 1);
    assert_eq!(stats.relay_connections, 1);
    assert_eq!(stats.total_bytes_sent, 1000);
    assert_eq!(stats.total_bytes_received, 500);
}

#[tokio::test]
async fn test_peer_manager_active_connections() {
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

    // Initially no active connections
    assert!(manager.active_connections().await.is_empty());

    manager.update_state("peer1", ConnectionState::Direct).await;
    assert_eq!(manager.active_connections().await.len(), 1);
}
