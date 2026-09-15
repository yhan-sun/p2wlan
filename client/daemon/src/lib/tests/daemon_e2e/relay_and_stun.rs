// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;

#[tokio::test]
async fn relay_supervisor_reconnects_after_stream_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let (reconnected_tx, mut reconnected_rx) = mpsc::channel(1);
    let server = tokio::spawn(async move {
        let first = accept_relay_registration(&listener, "node-a").await;
        drop(first);

        let _second = accept_relay_registration(&listener, "node-a").await;
        reconnected_tx.send(()).await.unwrap();
        std::future::pending::<()>().await;
    });

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let relay_transport = Arc::new(RwLock::new(None));
    let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let (relay_available_tx, _relay_available_rx) = tokio::sync::watch::channel(false);
    let supervisor = tokio::spawn(
        RelaySupervisor {
            relay_candidates: vec![RelayCandidateConfig::legacy(endpoint)],
            preferred_regions: Vec::new(),
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: relay_transport.clone(),
            relay_selection: relay_selection.clone(),
            relay_available_tx: relay_available_tx.clone(),
            timeline: crate::connection_timeline::ConnectionTimeline::new("node-a", 0),
            inbound_tx,
            android_network_change_rx: None,
            ticket_cache: None,
            relay_ticket: None,
            allow_insecure_plaintext: true, // test
            ca_cert_path: None,
        }
        .run(),
    );

    tokio::time::timeout(Duration::from_secs(4), reconnected_rx.recv())
        .await
        .expect("relay supervisor did not reconnect")
        .expect("relay test server stopped");
    tokio::time::timeout(Duration::from_secs(1), async {
        while relay_transport.read().await.is_none() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("reconnected relay was not published");
    assert!(relay_selection.read().await.last_error.is_none());

    supervisor.abort();
    server.abort();
}

#[tokio::test]
async fn relay_supervisor_fails_over_to_standby_after_runtime_disconnect() {
    let primary = RelayServer::start_random().await.unwrap();
    let standby = RelayServer::start_random().await.unwrap();
    let primary_endpoint = primary.addr.to_string();
    let standby_endpoint = standby.addr.to_string();

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let peers = Arc::new(PeerManager::new(config));
    let relay_transport = Arc::new(RwLock::new(None));
    let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
    let (inbound_tx, _inbound_rx) = mpsc::channel(4);
    let (relay_available_tx, _relay_available_rx) = tokio::sync::watch::channel(false);
    let supervisor = tokio::spawn(
        RelaySupervisor {
            relay_candidates: vec![
                RelayCandidateConfig::legacy(format!("primary@{primary_endpoint}")),
                RelayCandidateConfig::legacy(format!("standby@{standby_endpoint}")),
            ],
            preferred_regions: vec!["primary".to_string()],
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: relay_transport.clone(),
            relay_selection: relay_selection.clone(),
            relay_available_tx: relay_available_tx.clone(),
            timeline: crate::connection_timeline::ConnectionTimeline::new("node-a", 0),
            inbound_tx,
            android_network_change_rx: None,
            ticket_cache: None,
            relay_ticket: None,
            allow_insecure_plaintext: true,
            ca_cert_path: None,
        }
        .run(),
    );

    wait_for_relay_endpoint(relay_transport.clone(), &primary_endpoint).await;
    primary.shutdown().await;
    wait_for_relay_endpoint(relay_transport, &standby_endpoint).await;

    let diagnostics = relay_selection.read().await.clone();
    assert_eq!(
        diagnostics.selected_endpoint.as_deref(),
        Some(standby_endpoint.as_str())
    );
    let primary_candidate = diagnostics
        .candidates
        .iter()
        .find(|candidate| candidate.endpoint == primary_endpoint)
        .expect("primary relay candidate should remain in diagnostics");
    assert_eq!(
        primary_candidate.error_code.as_deref(),
        Some("cooling_down")
    );
    assert!(primary_candidate.cooldown_remaining_ms.is_some());

    supervisor.abort();
    standby.shutdown().await;
}

#[test]
fn test_infer_default_relay_servers_skips_local_and_test_hosts() {
    assert!(infer_default_relay_servers("http://127.0.0.1:18080").is_empty());
    assert!(infer_default_relay_servers("http://localhost:18080").is_empty());
    assert!(infer_default_relay_servers("https://ctrl.test").is_empty());
}

#[tokio::test]
async fn test_parse_stun_servers() {
    let servers = parse_stun_servers(
        &["127.0.0.1:3478".to_string(), " 10.0.0.1:3478 ".to_string()],
        Duration::from_millis(100),
    )
    .await
    .unwrap();
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0], "127.0.0.1:3478".parse().unwrap());
    assert_eq!(servers[1], "10.0.0.1:3478".parse().unwrap());
}

#[tokio::test]
async fn test_parse_stun_servers_resolves_hostname() {
    let servers = parse_stun_servers(&["localhost:3478".to_string()], Duration::from_secs(1))
        .await
        .unwrap();
    assert!(servers
        .iter()
        .any(|server| server.ip().is_loopback() && server.port() == 3478));
}

#[tokio::test]
async fn test_parse_stun_servers_resolves_sources_concurrently() {
    // The resolver timeout is intentionally much shorter than the two
    // sequential waits this test would require.  A numeric endpoint must
    // still survive while the dead hostname times out in parallel.
    let started = std::time::Instant::now();
    let servers = super::resolve_stun_specs(
        vec![
            "203.0.113.1:3478".to_string(),
            "does-not-exist.invalid:3478".to_string(),
            "198.51.100.2:3478".to_string(),
        ],
        true,
        Duration::from_millis(100),
    )
    .await
    .unwrap();

    assert!(servers.contains(&"203.0.113.1:3478".parse().unwrap()));
    assert!(servers.contains(&"198.51.100.2:3478".parse().unwrap()));
    assert!(
        started.elapsed() < Duration::from_millis(250),
        "STUN DNS resolution serialized: elapsed={:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn test_parse_stun_servers_can_be_disabled() {
    assert!(
        parse_stun_servers(&["off".to_string()], Duration::from_millis(100))
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn test_parse_stun_servers_rejects_invalid_endpoint() {
    let err = parse_stun_servers(&["not-a-socket".to_string()], Duration::from_millis(100))
        .await
        .unwrap_err();
    assert!(err
        .to_string()
        .contains("invalid or unresolved STUN server"));
}

#[test]
fn maintenance_offer_cancellation_keeps_rekey_initiation_alive() {
    assert!(should_cancel_maintenance_offer(
        false, true, false, false, false
    ));
    assert!(!should_cancel_maintenance_offer(
        false, false, false, false, false
    ));
    assert!(!should_cancel_maintenance_offer(
        true, true, true, false, false
    ));
    assert!(!should_cancel_maintenance_offer(
        true, true, false, true, false
    ));
    assert!(!should_cancel_maintenance_offer(
        true, false, false, false, false
    ));
    assert!(should_cancel_maintenance_offer(
        true, true, false, false, false
    ));
    assert!(should_cancel_maintenance_offer(
        false, false, false, false, true
    ));
    assert!(should_cancel_maintenance_offer(
        true, true, true, false, true
    ));
}

#[test]
fn rekey_session_install_preserves_established_path_state() {
    assert!(!should_mark_connecting_after_session_install(
        true,
        Some(ConnectionState::Direct)
    ));
    assert!(!should_mark_connecting_after_session_install(
        true,
        Some(ConnectionState::Relay)
    ));
    assert!(!should_mark_connecting_after_session_install(
        true,
        Some(ConnectionState::HolePunching)
    ));
    assert!(!should_mark_connecting_after_session_install(
        false,
        Some(ConnectionState::Direct)
    ));
    assert!(should_mark_connecting_after_session_install(
        false,
        Some(ConnectionState::Idle)
    ));
    assert!(should_mark_connecting_after_session_install(
        false,
        Some(ConnectionState::Failed)
    ));
}

#[tokio::test]
async fn initiator_rekey_keeps_peer_in_direct_state() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-direct-rekey";
    let peer_identity = NodeIdentity::generate();
    let peer_public_key = peer_identity.public_key();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_public_key),
            endpoint: "203.0.113.20:42000".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    daemon
        .peers
        .update_state(peer_id, ConnectionState::Direct)
        .await;

    let old_local_identity = NodeIdentity::generate();
    let old_remote_identity = NodeIdentity::generate();
    let mut old_initiator =
        HandshakeInitiator::new(old_local_identity, old_remote_identity.public_key(), None);
    let old_initiation = old_initiator.create_initiation().unwrap();
    let mut old_responder = HandshakeResponder::new(old_remote_identity, None);
    let (old_response, _) = old_responder
        .consume_initiation_and_respond(&old_initiation)
        .unwrap();
    let old_local_keys = old_initiator.consume_response(&old_response).unwrap();
    daemon
        .transport
        .add_session(peer_id, TransportSession::new(old_local_keys))
        .await;

    let mut initiator =
        HandshakeInitiator::new(daemon.local_identity().unwrap(), peer_public_key, None);
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    {
        let mut state = daemon.pending_handshakes.lock();
        state.insert(peer_id.to_string(), initiator, None, None);
    }

    daemon
        .handle_peer_answer(peer_id, &response.to_bytes(), None, None)
        .await
        .unwrap();

    assert_eq!(
        daemon.peers.get_connection(peer_id).await.unwrap().state,
        ConnectionState::Direct
    );
}

#[tokio::test]
async fn peer_answer_from_new_remote_incarnation_rebinds_pending_initiator() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-answer-remote-restart";
    let peer_identity = NodeIdentity::generate();
    let endpoint = "203.0.113.20:42100";
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_identity.public_key()),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.21".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let old_candidate_generation = encoded_generation(100, 1);
    let new_candidate_generation = encoded_generation(101, 1);
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                &[endpoint.to_string()],
                &HashMap::new(),
                old_candidate_generation,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    daemon
        .peers
        .update_state(peer_id, ConnectionState::Direct)
        .await;
    let old_peer_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();

    let (old_local_session, _) = part03_establish_sessions();
    daemon
        .transport
        .add_session(peer_id, old_local_session)
        .await;

    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    daemon.pending_handshakes.lock().insert_with_generation(
        peer_id.to_string(),
        initiator,
        None,
        None,
        None,
        daemon.peers.current_network_generation_sync(),
        old_peer_session_generation,
    );

    assert!(
        daemon
            .reset_peer_for_remote_incarnation_if_needed(
                peer_id,
                new_candidate_generation,
                RemoteIncarnationResetWork::PreserveInitiator,
            )
            .await
    );
    let new_peer_session_generation = daemon.peers.peer_session_generation_sync(peer_id).unwrap();
    assert_ne!(new_peer_session_generation, old_peer_session_generation);
    {
        let pending = daemon.pending_handshakes.lock();
        assert!(pending.pending.contains_key(peer_id));
        assert_eq!(
            pending.peer_session_generation(peer_id),
            Some(new_peer_session_generation),
            "the exact answer transaction must be rebound to the restart lifecycle"
        );
    }
    assert!(!daemon.transport.has_session(peer_id).await);
    assert_eq!(
        daemon.peers.get_connection(peer_id).await.unwrap().state,
        ConnectionState::Idle
    );

    assert!(daemon
        .handle_peer_answer(peer_id, &response.to_bytes(), None, None)
        .await
        .unwrap());
    assert!(daemon.transport.has_session(peer_id).await);
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                &[endpoint.to_string()],
                &HashMap::new(),
                new_candidate_generation,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    // A delayed signal from the retired boot is different but not newer. It
    // must not tear down the newly installed answer session or rotate the
    // lifecycle backwards.
    assert!(
        !daemon
            .reset_peer_for_remote_incarnation_if_needed(
                peer_id,
                old_candidate_generation,
                RemoteIncarnationResetWork::ClearAll,
            )
            .await
    );
    assert_eq!(
        daemon.peers.peer_session_generation_sync(peer_id),
        Some(new_peer_session_generation)
    );
    assert!(daemon.transport.has_session(peer_id).await);
}

#[tokio::test(flavor = "current_thread")]
async fn responder_remote_incarnation_reset_does_not_self_lock_lifecycle_arbiter() {
    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-responder-reset-no-self-lock";
    let endpoint = "203.0.113.31:43100";
    let peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_identity.public_key()),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.31".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let old_candidate_generation = encoded_generation(200, 1);
    let new_candidate_generation = encoded_generation(201, 1);
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                &[endpoint.to_string()],
                &HashMap::new(),
                old_candidate_generation,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    *daemon.udp_transport.write().await = Some(udp.clone());

    // Force the reset to suspend only after it owns the lifecycle arbiter. In
    // the old inline implementation the serial control-loop future itself held
    // that arbiter here, so ceasing to poll it made a concurrent PeerLeft wait
    // forever even after UDP cleanup became runnable.
    let adoption_guard = udp.lock_peer_adoption_for_direct_validation(peer_id).await;
    let reset = daemon.reset_peer_for_remote_incarnation_if_needed(
        peer_id,
        new_candidate_generation,
        RemoteIncarnationResetWork::PreserveResponder,
    );
    tokio::pin!(reset);
    tokio::select! {
        changed = &mut reset => {
            panic!("reset unexpectedly bypassed the held UDP adoption lock: {changed}");
        }
        _ = sleep(Duration::from_millis(25)) => {}
    }
    drop(adoption_guard);

    let lifecycle_guard = timeout(
        Duration::from_millis(500),
        daemon.handshake_arbiter.acquire_with_timeout(
            HandshakeLeaseIdentity::new(
                peer_id,
                HandshakeOwnerKind::Cleanup,
                None,
                daemon.peers.current_network_generation_sync(),
                daemon.peers.peer_session_generation_sync(peer_id),
                "test_reset_probe",
            ),
            Duration::from_millis(100),
        ),
    )
    .await
    .expect("responder reset retained an unpolled lifecycle-arbiter owner")
    .expect("lifecycle mutation turn remained contended");
    drop(lifecycle_guard);
    assert!(timeout(Duration::from_millis(500), &mut reset)
        .await
        .expect("independent responder reset task did not complete"));
}

#[tokio::test]
async fn remote_incarnation_replay_republishes_unchanged_local_candidates() {
    use crate::control::TestControlSignal;
    use std::sync::{Arc as StdArc, Mutex as StdMutex};

    fn encoded_generation(incarnation: u64, counter: u64) -> u64 {
        0x4000_0000_0000_0000 | (incarnation << 21) | counter
    }

    let mut daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let peer_id = "peer-remote-replay-candidates";
    let peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_identity.public_key()),
            endpoint: "203.0.113.90:49000".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.90".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let local_candidates = vec![
        "203.0.113.91:49001".to_string(),
        "203.0.113.91:49002".to_string(),
    ];
    let local_sources = HashMap::from([
        (local_candidates[0].clone(), "stun_observed".to_string()),
        (local_candidates[1].clone(), "predicted".to_string()),
    ]);
    daemon
        .publish_candidate_snapshot(local_candidates.clone(), local_sources, Vec::new())
        .await;
    let before_replay = daemon.current_local_candidate_set().await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), daemon.peers.clone())
        .await
        .unwrap();
    *daemon.udp_transport.write().await = Some(udp);

    let signals = StdArc::new(StdMutex::new(Vec::<TestControlSignal>::new()));
    let signals_for_forwarder = signals.clone();
    let local_public_key = daemon.local_identity().unwrap().public_key();
    daemon.control.set_test_signal_forwarder(
        daemon.config.node.node_id.clone(),
        hex::encode(local_public_key),
        StdArc::new(move |signal| {
            signals_for_forwarder
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(signal);
        }),
    );

    let old_generation = encoded_generation(300, 1);
    let new_generation = encoded_generation(301, 1);
    assert_eq!(
        daemon
            .peers
            .add_candidates_with_metadata(
                peer_id,
                &["203.0.113.90:49000".to_string()],
                &HashMap::new(),
                old_generation,
                Some(u64::MAX),
            )
            .await,
        CandidateSetApplyResult::Applied
    );
    assert!(
        daemon
            .reset_peer_for_remote_incarnation_if_needed(
                peer_id,
                new_generation,
                RemoteIncarnationResetWork::ClearAll,
            )
            .await
    );

    // Simulate the lifecycle replay scheduled by the control-event path. The
    // local snapshot/hash is unchanged, so this publication must come from
    // the explicit replay rather than a candidate-refresh hash transition.
    daemon
        .publish_current_candidates_to_peer(peer_id, "test remote incarnation replay")
        .await;

    let signal = signals
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .pop()
        .expect("remote incarnation replay must publish a candidate-only offer");
    assert_eq!(signal.to_node_id, peer_id);
    assert!(signal.handshake_init.is_empty());
    assert_eq!(signal.candidates, local_candidates);
    assert_eq!(daemon.current_local_candidate_set().await, before_replay);
}

#[tokio::test]
async fn stale_wireguard_answer_does_not_clear_pending_handshake() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-stale-answer";

    let peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_identity.public_key()),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();

    {
        let mut state = daemon.pending_handshakes.lock();
        state.insert(peer_id.to_string(), initiator, None, None);
        state.attempts.insert(peer_id.to_string(), 1);
    }

    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (mut stale_response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    stale_response.receiver_index ^= 0x1111_0001;

    daemon
        .handle_peer_answer(peer_id, &stale_response.to_bytes(), None, None)
        .await
        .unwrap();

    let state = daemon.pending_handshakes.lock();
    assert!(state.pending.contains_key(peer_id));
    assert_eq!(state.attempts.get(peer_id), Some(&1));
}

#[tokio::test]
async fn wireguard_answer_from_previous_network_generation_cannot_install_session() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-old-network-generation-answer";
    let peer_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_identity.public_key()),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();

    let (pending_cancellation_tx, mut pending_cancellation) = watch::channel(false);
    {
        let mut state = daemon.pending_handshakes.lock();
        state.insert_with_generation(
            peer_id.to_string(),
            initiator,
            None,
            None,
            Some(pending_cancellation_tx),
            0,
            daemon.peers.peer_session_generation_sync(peer_id).unwrap(),
        );
    }
    assert_eq!(
        daemon
            .peers
            .advance_network_generation("late handshake answer test")
            .await,
        1
    );
    assert!(*pending_cancellation.borrow_and_update());
    assert!(
        !daemon
            .pending_handshakes
            .lock()
            .pending
            .contains_key(peer_id),
        "the generation transaction must synchronously cancel the old pending owner"
    );

    daemon
        .handle_peer_answer(peer_id, &response.to_bytes(), None, None)
        .await
        .unwrap();

    assert!(
        !daemon
            .pending_handshakes
            .lock()
            .pending
            .contains_key(peer_id),
        "a stale answer must not recreate the cancelled pending transaction"
    );
    assert!(
        !daemon.transport.has_session(peer_id).await,
        "a stale answer must not install WireGuard key material"
    );
}

#[tokio::test]
async fn responder_offer_from_previous_network_generation_cannot_stage_session() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-old-network-generation-offer";
    let offer = PendingPeerOffer {
        from_node_id: peer_id.to_string(),
        candidates: Vec::new(),
        candidate_sources: HashMap::new(),
        candidate_generation: 0,
        network_generation: 0,
        peer_session_generation: None,
        candidates_expires_at_ms: None,
        sender_public_key: None,
        handshake_init: Vec::new(),
        punch_at_ms: None,
        punch_at_server_ms: None,
        session_id: None,
        probe_ephemeral_public_key: None,
        delivery_receipt: None,
    };
    let (reservation, offer) = daemon
        .pending_handshakes
        .lock()
        .enqueue_responder_work(offer)
        .expect("the offer must acquire a responder worker");

    daemon
        .peers
        .advance_network_generation("late responder offer test")
        .await;
    let mut cancellation = reservation.cancellation;
    daemon
        .handle_admitted_responder_offer(&offer, reservation.owner, &mut cancellation)
        .await;

    let status = daemon.transport.session_status(peer_id).await;
    assert!(!status.has_active);
    assert!(!status.has_pending_responder);
}

#[tokio::test]
async fn incomplete_modern_answer_preserves_pending_handshake_and_old_session() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-incomplete-modern-answer";

    let old_local_identity = NodeIdentity::generate();
    let old_remote_identity = NodeIdentity::generate();
    let mut old_initiator =
        HandshakeInitiator::new(old_local_identity, old_remote_identity.public_key(), None);
    let old_initiation = old_initiator.create_initiation().unwrap();
    let mut old_responder = HandshakeResponder::new(old_remote_identity, None);
    let (old_response, old_remote_keys) = old_responder
        .consume_initiation_and_respond(&old_initiation)
        .unwrap();
    let old_local_keys = old_initiator.consume_response(&old_response).unwrap();
    let mut old_remote_session = TransportSession::new(old_remote_keys);
    daemon
        .transport
        .install_active_session(
            peer_id,
            Some("old-session".to_string()),
            TransportSession::new(old_local_keys),
        )
        .await;

    let new_remote_identity = NodeIdentity::generate();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(new_remote_identity.public_key()),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let mut new_initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        new_remote_identity.public_key(),
        None,
    );
    let new_initiation = new_initiator.create_initiation().unwrap();
    let mut new_responder = HandshakeResponder::new(new_remote_identity, None);
    let (new_response, _) = new_responder
        .consume_initiation_and_respond(&new_initiation)
        .unwrap();
    let session_id = "modern-session".to_string();
    {
        let mut state = daemon.pending_handshakes.lock();
        state.insert(
            peer_id.to_string(),
            new_initiator,
            Some(session_id.clone()),
            Some(DhKeyPair::generate()),
        );
        state.attempts.insert(peer_id.to_string(), 2);
    }

    for invalid_probe_key in [None, Some("not-a-valid-x25519-key".to_string())] {
        daemon
            .handle_peer_answer(
                peer_id,
                &new_response.to_bytes(),
                Some(session_id.clone()),
                invalid_probe_key,
            )
            .await
            .unwrap();

        let state = daemon.pending_handshakes.lock();
        assert!(state.pending.contains_key(peer_id));
        assert!(state.pending_probe_ephemeral.contains_key(peer_id));
        assert_eq!(state.attempts.get(peer_id), Some(&2));
    }

    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x7103,
        1,
        b"old-session-still-active",
    );
    let encrypted = daemon
        .transport
        .encrypt_outbound(OutboundPacket {
            room_authorization: None,
            trace: None,
            peer_id: peer_id.to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: packet.clone(),
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        old_remote_session
            .decrypt_from_bytes(&encrypted.wire_bytes)
            .unwrap(),
        packet
    );
}

#[tokio::test]
async fn modern_offer_rejects_missing_or_malformed_probe_ephemeral_key() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-invalid-modern-offer";
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let peer_public = peer_identity.public_key();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_public),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let mut initiator = HandshakeInitiator::new(peer_identity, local_public, None);
    let initiation = initiator.create_initiation().unwrap().to_bytes();

    let missing = daemon
        .handle_peer_offer(
            peer_id,
            &[],
            &initiation,
            None,
            None,
            Some("modern-missing-key".to_string()),
            None,
        )
        .await
        .unwrap_err();
    assert!(missing
        .to_string()
        .contains("missing probe ephemeral public key"));

    let malformed = daemon
        .handle_peer_offer(
            peer_id,
            &[],
            &initiation,
            None,
            None,
            Some("modern-malformed-key".to_string()),
            Some("00".repeat(32)),
        )
        .await
        .unwrap_err();
    assert!(malformed.to_string().contains("probe ephemeral"));

    assert!(daemon.pending_handshakes.lock().responder_cache.is_empty());
    let status = daemon.transport.session_status(peer_id).await;
    assert!(!status.has_active);
    assert!(!status.has_pending_responder);
}
