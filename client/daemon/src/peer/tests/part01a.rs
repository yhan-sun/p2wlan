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
async fn staged_probe_binding_keeps_outbound_old_until_authenticated_promotion() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let remote_identity = NodeIdentity::generate();
    let remote_public_key = hex::encode(remote_identity.public_key());
    let mut peer = test_peer("peer-probe-rekey", "8.8.8.8:12294".parse().unwrap());
    peer.public_key = remote_public_key;
    manager.add_peer(&peer).await;

    let old_shared = [1u8; 32];
    let new_shared = [2u8; 32];
    manager
        .set_probe_session_binding(
            "peer-probe-rekey",
            Some("old-session".to_string()),
            Some(old_shared),
        )
        .await;
    let old_key = manager.probe_key_for_peer("peer-probe-rekey").await.unwrap();

    assert_eq!(
        manager
            .stage_probe_session_binding(
                "peer-probe-rekey",
                "new-token".to_string(),
                Some("new-session".to_string()),
                Some(new_shared),
                true,
            )
            .await,
        ProbeBindingStage::Staged
    );
    assert_eq!(
        manager.probe_key_for_peer("peer-probe-rekey").await,
        Some(old_key)
    );

    let candidates = manager
        .probe_key_candidates_for_peer("peer-probe-rekey")
        .await;
    assert!(candidates.iter().any(|candidate| {
        candidate.role == ProbeKeyRole::Active && candidate.key == old_key
    }));
    assert!(candidates.iter().any(|candidate| {
        matches!(candidate.role, ProbeKeyRole::Pending { ref token } if token == "new-token")
    }));

    assert!(manager
        .confirm_pending_probe_session_binding("peer-probe-rekey", "new-token")
        .await);
    let new_key = manager.probe_key_for_peer("peer-probe-rekey").await.unwrap();
    assert_ne!(new_key, old_key);
    let inbound_keys = manager.probe_keys_for_peer("peer-probe-rekey").await;
    assert!(inbound_keys.contains(&old_key));
    assert!(inbound_keys.contains(&new_key));
}

#[tokio::test]
async fn multiple_probe_tokens_are_retained_until_exact_token_promotion() {
    let manager = PeerManager::new(test_config());
    let remote_identity = NodeIdentity::generate();
    let mut peer = test_peer("peer-probe-multi", "8.8.8.8:12296".parse().unwrap());
    peer.public_key = hex::encode(remote_identity.public_key());
    manager.add_peer(&peer).await;
    manager
        .set_probe_session_binding(
            "peer-probe-multi",
            Some("old-session".to_string()),
            Some([1u8; 32]),
        )
        .await;

    for (token, session, shared) in [
        ("token-a", "session-a", [2u8; 32]),
        ("token-b", "session-b", [3u8; 32]),
    ] {
        assert_eq!(
            manager
                .stage_probe_session_binding(
                    "peer-probe-multi",
                    token.to_string(),
                    Some(session.to_string()),
                    Some(shared),
                    true,
                )
                .await,
            ProbeBindingStage::Staged
        );
    }
    let candidates = manager
        .probe_key_candidates_for_peer("peer-probe-multi")
        .await;
    for token in ["token-a", "token-b"] {
        assert!(candidates.iter().any(|candidate| {
            matches!(&candidate.role, ProbeKeyRole::Pending { token: candidate_token } if candidate_token == token)
        }));
    }

    assert!(manager
        .confirm_pending_probe_session_binding("peer-probe-multi", "token-b")
        .await);
    let candidates = manager
        .probe_key_candidates_for_peer("peer-probe-multi")
        .await;
    assert!(!candidates.iter().any(|candidate| {
        matches!(candidate.role, ProbeKeyRole::Pending { .. })
    }));
}

#[tokio::test]
async fn failed_initiator_probe_stage_does_not_promote_on_inbound_match() {
    let config = test_config();
    let manager = PeerManager::new(config);
    let remote_identity = NodeIdentity::generate();
    let mut peer = test_peer("peer-probe-pending", "8.8.8.8:12295".parse().unwrap());
    peer.public_key = hex::encode(remote_identity.public_key());
    manager.add_peer(&peer).await;
    manager
        .set_probe_session_id("peer-probe-pending", Some("old-session".to_string()))
        .await;
    let old_key = manager.probe_key_for_peer("peer-probe-pending").await.unwrap();

    assert_eq!(
        manager
            .stage_probe_session_binding(
                "peer-probe-pending",
                "pending-token".to_string(),
                Some("pending-session".to_string()),
                None,
                false,
            )
            .await,
        ProbeBindingStage::Staged
    );
    assert!(!manager
        .confirm_pending_probe_session_binding("peer-probe-pending", "pending-token")
        .await);
    assert_eq!(
        manager.probe_key_for_peer("peer-probe-pending").await,
        Some(old_key)
    );
    assert!(manager
        .discard_pending_probe_session_binding("peer-probe-pending", "pending-token")
        .await);
    assert_eq!(
        manager.probe_key_for_peer("peer-probe-pending").await,
        Some(old_key)
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
    assert!(!peer.is_peer_reflexive_direct);
    assert!(peer.public_mapping_stable);
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

#[test]
fn diagnostics_keeps_non_current_peer_reflexive_pair_provisional() {
    let selected_remote: SocketAddr = "8.8.8.8:32794".parse().unwrap();
    let current_remote: SocketAddr = "8.8.8.8:32798".parse().unwrap();
    let local: SocketAddr = "192.168.1.10:54006".parse().unwrap();
    let mut conn = PeerConnection::new("peer1", "10.20.0.2");
    conn.state = ConnectionState::Direct;
    conn.endpoint = Some(current_remote);

    let mut selected_pair =
        CandidatePair::new_with_source(selected_remote, 0, CandidatePairSource::PeerReflexive);
    selected_pair.record_success(Some(Duration::from_millis(3)), true, Some(local));

    let mut current_pair =
        CandidatePair::new_with_source(current_remote, 0, CandidatePairSource::PeerReflexive);
    current_pair.record_success(Some(Duration::from_millis(10)), true, Some(local));

    conn.candidate_pairs = vec![current_pair, selected_pair];

    let current_selection =
        PathSelection::direct(current_remote, "test_direct", "test direct", true);
    let diagnostics = PeerDiagnostics::from_connection_with_path_selection(
        &conn,
        Some(&current_selection),
        None,
        0,
        Some(local),
        None,
        None,
    );
    let selected = diagnostics.selected_pair.as_ref().unwrap();
    let current = diagnostics.current_direct_pair.as_ref().unwrap();

    assert_eq!(diagnostics.direct_type, DirectPathType::PeerReflexive);
    // A peer-reflexive pair over a real public endpoint is public UDP direct.
    assert!(diagnostics.is_public_udp_direct);
    assert!(diagnostics.is_peer_reflexive_direct);
    assert!(!diagnostics.public_mapping_stable);
    assert_eq!(diagnostics.warning, None);
    assert_eq!(selected.remote_endpoint, selected_remote.to_string());
    assert_eq!(current.remote_endpoint, current_remote.to_string());
    assert_eq!(selected.direct_type, DirectPathType::PeerReflexive);
    assert!(selected.is_public_udp_direct);
    assert!(selected.is_peer_reflexive_direct);
    assert!(!selected.public_mapping_stable);
    assert_eq!(selected.warning, None);
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
