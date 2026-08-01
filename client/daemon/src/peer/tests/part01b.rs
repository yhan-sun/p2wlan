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
    for endpoint in ["100.74.65.1:63169", "[fd7a:115c:a1e0::b936:4102]:63167"] {
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
