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
    let supervisor = tokio::spawn(
        RelaySupervisor {
            relay_candidates: vec![RelayCandidateConfig::legacy(endpoint)],
            preferred_regions: Vec::new(),
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: relay_transport.clone(),
            relay_selection: relay_selection.clone(),
            inbound_tx,
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
            inbound_tx,
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
    let mut old_initiator = HandshakeInitiator::new(
        old_local_identity,
        old_remote_identity.public_key(),
        None,
    );
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

    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_public_key,
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity, None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    {
        let mut state = daemon.pending_handshakes.lock().await;
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
async fn stale_wireguard_answer_does_not_clear_pending_handshake() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-stale-answer";

    let peer_identity = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();

    {
        let mut state = daemon.pending_handshakes.lock().await;
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

    let state = daemon.pending_handshakes.lock().await;
    assert!(state.pending.contains_key(peer_id));
    assert_eq!(state.attempts.get(peer_id), Some(&1));
}

#[tokio::test]
async fn incomplete_modern_answer_preserves_pending_handshake_and_old_session() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-incomplete-modern-answer";

    let old_local_identity = NodeIdentity::generate();
    let old_remote_identity = NodeIdentity::generate();
    let mut old_initiator = HandshakeInitiator::new(
        old_local_identity,
        old_remote_identity.public_key(),
        None,
    );
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
        let mut state = daemon.pending_handshakes.lock().await;
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

        let state = daemon.pending_handshakes.lock().await;
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
    let mut initiator = HandshakeInitiator::new(
        peer_identity,
        local_public,
        None,
    );
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

    assert!(daemon
        .pending_handshakes
        .lock()
        .await
        .responder_cache
        .is_empty());
    let status = daemon.transport.session_status(peer_id).await;
    assert!(!status.has_active);
    assert!(!status.has_pending_responder);
}

#[test]
fn handshake_start_reservation_prevents_concurrent_initiators() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-race";

    assert!(state.reserve_start(peer_id));
    assert!(state.starting.contains(peer_id));
    assert!(
        !state.reserve_start(peer_id),
        "a second trigger must not start an initiator while the first gathers candidates"
    );

    state.cancel_reservation(peer_id);
    assert!(state.reserve_start(peer_id));
}

#[test]
fn stale_handshake_start_owner_cannot_clear_replacement_reservation() {
    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-owner-replacement";

    let old = state
        .reserve_start_with_owner(peer_id)
        .expect("first reservation must be admitted");
    state.clear_peer(peer_id);
    let replacement = state
        .reserve_start_with_owner(peer_id)
        .expect("peer rejoin must admit a replacement reservation");

    assert_ne!(old.owner, replacement.owner);
    assert!(
        !state.cancel_reservation_if_current(peer_id, old.owner),
        "a late task from the old peer incarnation must not clear the replacement"
    );
    assert!(state.starting.contains(peer_id));
    assert_eq!(state.starting_ids.get(peer_id), Some(&replacement.owner));
}

#[test]
fn deferred_unknown_peer_offer_is_newest_wins_and_owner_scoped() {
    fn offer(peer_id: &str, endpoint: &str) -> PendingPeerOffer {
        PendingPeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![endpoint.to_string()],
            candidate_sources: HashMap::from([(endpoint.to_string(), "stun".to_string())]),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            sender_public_key: None,
            handshake_init: vec![1, 2, 3],
            punch_at_ms: None,
            punch_at_server_ms: None,
            session_id: None,
            probe_ephemeral_public_key: None,
        }
    }

    let mut state = PendingHandshakeState::default();
    let (reservation, first) = state
        .enqueue_responder_work(offer("peer-deferred", "127.0.0.1:41000"))
        .expect("first unknown offer starts one bounded waiter");
    assert!(state
        .enqueue_responder_work(offer("peer-deferred", "127.0.0.1:41001"))
        .is_none());

    let queued = state
        .take_queued_responder_work("peer-deferred", reservation.owner)
        .expect("newest offer replaces the deferred value before it is processed");
    assert_eq!(queued.candidates, vec!["127.0.0.1:41001"]);
    assert_eq!(first.candidates, vec!["127.0.0.1:41000"]);
    assert!(
        state
            .finish_responder_work("peer-deferred", reservation.owner)
            .is_none(),
        "taking the newest queued offer must retain then release the same owner only once"
    );

    // A peer lifecycle cleanup invalidates the owner.  A late worker cannot
    // consume a replacement slot after the peer rejoins.
    state.clear_peer("peer-deferred");
    assert!(state
        .finish_responder_work("peer-deferred", reservation.owner)
        .is_none());
    let replacement = state
        .enqueue_responder_work(offer("peer-deferred", "127.0.0.1:41002"))
        .expect("rejoined peer gets a fresh owner");
    assert_ne!(replacement.0.owner, reservation.owner);
}

#[test]
fn peer_reflexive_work_is_newest_wins_and_owner_scoped() {
    fn observation(peer_id: &str, endpoint: &str) -> PendingPeerReflexive {
        PendingPeerReflexive {
            from_node_id: peer_id.to_string(),
            observed_endpoint: endpoint.to_string(),
            punch_at_ms: None,
        }
    }

    let mut state = PendingHandshakeState::default();
    let peer_id = "peer-reflexive-owner";
    let (reservation, first) = state
        .enqueue_peer_reflexive_work(observation(peer_id, "198.51.100.10:41000"))
        .expect("first observation starts one bounded worker");
    assert!(state
        .enqueue_peer_reflexive_work(observation(peer_id, "198.51.100.10:41001"))
        .is_none());

    let newest = state
        .finish_peer_reflexive_work(peer_id, reservation.owner)
        .expect("the worker must consume only the newest queued endpoint next");
    assert_eq!(first.observed_endpoint, "198.51.100.10:41000");
    assert_eq!(newest.observed_endpoint, "198.51.100.10:41001");

    // Peer lifecycle cleanup cancels the old owner. A late completion cannot
    // release or consume the replacement slot after a rejoin.
    state.clear_peer(peer_id);
    assert!(state
        .finish_peer_reflexive_work(peer_id, reservation.owner)
        .is_none());
    let replacement = state
        .enqueue_peer_reflexive_work(observation(peer_id, "198.51.100.10:41002"))
        .expect("rejoined peer gets a fresh peer-reflexive owner");
    assert_ne!(replacement.0.owner, reservation.owner);
}

#[tokio::test]
async fn deferred_unknown_peer_offer_replays_candidate_admission_after_peer_join() {
    let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let peer_identity = NodeIdentity::generate();
    let peer_id = "peer-deferred-replay";
    let candidate = "198.51.100.77:47000";
    let offer = PendingPeerOffer {
        from_node_id: peer_id.to_string(),
        candidates: vec![candidate.to_string()],
        candidate_sources: HashMap::from([(candidate.to_string(), "stun".to_string())]),
        candidate_generation: 1,
        candidates_expires_at_ms: None,
        sender_public_key: Some(hex::encode(peer_identity.public_key())),
        handshake_init: Vec::new(),
        punch_at_ms: None,
        punch_at_server_ms: None,
        session_id: None,
        probe_ephemeral_public_key: None,
    };
    let (reservation, offer) = daemon
        .pending_handshakes
        .lock()
        .await
        .enqueue_responder_work(offer)
        .expect("unknown offer must acquire one deferred owner");

    let join = async {
        sleep(Duration::from_millis(25)).await;
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
    };
    tokio::join!(
        daemon.run_deferred_peer_offer_worker(offer, reservation),
        join
    );

    let connection = daemon.peers.get_connection(peer_id).await.unwrap();
    assert!(
        connection.candidates.iter().any(|value| value == candidate),
        "candidate admission must run after the peer exists"
    );
    assert!(!daemon
        .pending_handshakes
        .lock()
        .await
        .responder_workers
        .contains_key(peer_id));
}

#[tokio::test]
async fn control_event_loop_processes_critical_event_while_candidate_refresh_is_blocked() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: "peer-slow-candidate-refresh".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: hex::encode(peer_identity.public_key()),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };

    // The event worker will block acquiring this lock inside
    // `local_candidate_set_for_signal`.  A serial inline handshake would keep
    // the next ControlHealthy event behind that wait; the bounded work set must
    // let the receiver consume it immediately.
    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let control = daemon.control.clone();
    let health = daemon.health.clone();
    let shutdown = daemon.shutdown_sender();
    control
        .event_sender()
        .send(ControlEvent::PeerJoined(peer_info))
        .unwrap();
    control
        .event_sender()
        .send(ControlEvent::ControlHealthy)
        .unwrap();

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    tokio::time::timeout(Duration::from_millis(250), async {
        loop {
            if health.snapshot(&[]).await.control_connected {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("ControlHealthy must not wait for the blocked candidate refresh");

    drop(candidate_guard);
    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn control_event_loop_processes_peer_answer_while_peer_reflexive_work_waits() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-reflexive-blocked-answer";
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

    // Install a genuine pending initiator so the following PeerAnswer has to
    // cross the real inbound answer handler and install a session. If
    // PeerReflexive waited inline on candidate_refresh_lock, this answer would
    // remain queued and the assertion below would time out.
    let mut initiator = HandshakeInitiator::new(
        daemon.local_identity().unwrap(),
        peer_identity.public_key(),
        None,
    );
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(peer_identity.clone(), None);
    let (response, _) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    daemon
        .pending_handshakes
        .lock()
        .await
        .insert(peer_id.to_string(), initiator, None, None);

    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let control = daemon.control.clone();
    let transport = daemon.transport.clone();
    let shutdown = daemon.shutdown_sender();
    control
        .event_sender()
        .send(ControlEvent::PeerReflexive {
            from_node_id: peer_id.to_string(),
            observed_endpoint: "198.51.100.10:41000".to_string(),
            punch_at_ms: None,
        })
        .unwrap();
    control
        .event_sender()
        .send(ControlEvent::PeerAnswer {
            from_node_id: peer_id.to_string(),
            candidates: Vec::new(),
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            candidate_generation: 0,
            candidates_expires_at_ms: None,
            handshake_response: response.to_bytes(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    tokio::time::timeout(Duration::from_millis(350), async {
        while !transport.has_session(peer_id).await {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("PeerAnswer must not wait for blocked peer-reflexive candidate work");

    drop(candidate_guard);
    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn control_event_loop_processes_peer_offer_while_peer_reflexive_work_waits() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-reflexive-blocked-offer";
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

    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let control = daemon.control.clone();
    let peers = daemon.peers.clone();
    let shutdown = daemon.shutdown_sender();
    let offered_candidate = "198.51.100.11:42000".to_string();
    control
        .event_sender()
        .send(ControlEvent::PeerReflexive {
            from_node_id: peer_id.to_string(),
            observed_endpoint: "198.51.100.10:41000".to_string(),
            punch_at_ms: None,
        })
        .unwrap();
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec![offered_candidate.clone()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::from([(offered_candidate.clone(), "stun".to_string())]),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();

    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    tokio::time::timeout(Duration::from_millis(350), async {
        loop {
            let installed = peers
                .get_connection(peer_id)
                .await
                .is_some_and(|connection| connection.candidates.contains(&offered_candidate));
            if installed {
                break;
            }
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("PeerOffer candidate admission must not wait for blocked peer-reflexive work");

    drop(candidate_guard);
    let _ = shutdown.send(true);
    tokio::time::timeout(Duration::from_secs(1), loop_task)
        .await
        .expect("control event loop did not stop")
        .expect("control event loop task panicked");
}

#[tokio::test]
async fn initiator_arbiter_is_released_before_candidate_refresh_wait() {
    use std::future::Future;
    use std::task::Poll;

    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if local_public < identity.public_key() {
            break identity;
        }
    };
    let peer_info = control::PeerInfo {
        node_id: "peer-arbiter-candidate-wait".to_string(),
        device_name: String::new(),
        app_version: String::new(),
        public_key: hex::encode(peer_identity.public_key()),
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: "10.20.0.2".to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    };
    let candidate_refresh_lock = daemon.candidate_refresh_lock.clone();
    let candidate_guard = candidate_refresh_lock.lock().await;
    let mut reservation = daemon
        .reserve_event_initiator_handshake(&peer_info.node_id)
        .await
        .expect("event initiator reservation must be admitted");
    let mut worker = Box::pin(daemon.run_reserved_initiator_handshake(
        &peer_info,
        &mut reservation,
    ));

    // A direct poll reaches the blocked candidate lock. If the initiator still
    // held its arbiter guard at this point, the acquisition below would time
    // out; a crossing offer/answer could not make progress.
    std::future::poll_fn(|context| match worker.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(()),
        Poll::Ready(result) => panic!("candidate-blocked worker completed unexpectedly: {result:?}"),
    })
    .await;
    let guard = tokio::time::timeout(
        Duration::from_millis(100),
        daemon.handshake_arbiter.acquire(&peer_info.node_id),
    )
    .await
    .expect("arbiter must be free while candidate gathering waits");
    drop(guard);

    daemon
        .pending_handshakes
        .lock()
        .await
        .clear_peer(&peer_info.node_id);
    drop(candidate_guard);
    tokio::time::timeout(Duration::from_secs(1), &mut worker)
        .await
        .expect("cancelled candidate worker did not return")
        .expect("cancelled candidate worker returned an error");
}

#[tokio::test]
async fn committed_initiator_offer_wait_is_cancelled_when_pending_is_removed() {
    let peer_id = "peer-cancelled-initiator-offer";
    let mut state = PendingHandshakeState::default();
    let reservation = state
        .reserve_start_with_owner(peer_id)
        .expect("initiator reservation must be admitted");
    let local_identity = NodeIdentity::generate();
    let peer_identity = NodeIdentity::generate();
    let initiator = HandshakeInitiator::new(local_identity, peer_identity.public_key(), None);
    let pending_id = state
        .insert_reserved_if_current(
            peer_id.to_string(),
            reservation.owner,
            initiator,
            None,
            None,
        )
        .expect("reservation must commit into a pending initiator");
    assert!(state.is_current(peer_id, pending_id));
    assert!(
        state.pending_cancellations.contains_key(peer_id),
        "committing the initiator must retain the reservation cancellation sender"
    );

    let mut cancellation = reservation.cancellation.clone();
    let (offer_started_tx, offer_started_rx) = tokio::sync::oneshot::channel();
    let offer_wait = tokio::spawn(async move {
        await_initiator_offer_or_cancellation(
            async move {
                let _ = offer_started_tx.send(());
                std::future::pending::<Result<()>>().await
            },
            &mut cancellation,
        )
        .await
    });
    offer_started_rx
        .await
        .expect("offer waiter must reach the slow control-plane wait");

    // `handle_peer_answer` uses this exact removal path after it consumes a
    // matching answer; `clear_peer` reaches it for PeerLeft. Both must wake
    // the committed initiator rather than leave a control-event slot pending.
    assert!(state.remove(peer_id).is_some());
    let outcome = tokio::time::timeout(Duration::from_millis(100), offer_wait)
        .await
        .expect("removing a pending initiator must cancel its offer wait")
        .expect("offer waiter task must not panic");
    assert!(outcome.is_none());
}

#[test]
fn handshake_role_is_deterministic_from_decoded_static_public_keys() {
    let lower = [0x11; 32];
    let higher = [0x22; 32];

    assert!(local_is_designated_handshake_initiator(&lower, &higher));
    assert!(!local_is_designated_handshake_initiator(&higher, &lower));
    assert!(!local_is_designated_handshake_initiator(&lower, &lower));
}

#[tokio::test]
async fn handshake_arbiter_prunes_dead_peer_locks_on_churn() {
    let arbiter = HandshakeArbiter::default();
    let first = arbiter.acquire("peer-old").await;
    drop(first);
    let second = arbiter.acquire("peer-new").await;
    drop(second);

    assert!(!arbiter.peer_locks.lock().await.contains_key("peer-old"));
}

#[test]
fn responder_handshake_cache_replays_exact_answer_and_rejects_token_reuse() {
    let initiator_identity = NodeIdentity::generate();
    let initiator_public = initiator_identity.public_key();
    let responder_identity = NodeIdentity::generate();
    let mut initiator =
        HandshakeInitiator::new(initiator_identity, responder_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let initiation_bytes = initiation.to_bytes();
    let mut responder = HandshakeResponder::new(responder_identity, None);
    let (response, keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let response_bytes = response.to_bytes();
    let request_probe_public_key = hex::encode([0xabu8; 32]);
    let differently_cased_probe_public_key =
        format!("  {}  ", request_probe_public_key.to_ascii_uppercase());

    let mut state = PendingHandshakeState::default();
    state.cache_responder_handshake(
        "peer-cache",
        "session-cache",
        CachedResponderHandshake {
            handshake_init: initiation_bytes.clone(),
            initiator_static_public_key: initiator_public,
            request_probe_ephemeral_public_key: Some(differently_cased_probe_public_key),
            response_bytes: response_bytes.clone(),
            transport_keys: keys,
            response_probe_ephemeral_public_key: Some("probe-public".to_string()),
            probe_ephemeral_shared: Some([7u8; 32]),
            expires_at: Instant::now() + RESPONDER_HANDSHAKE_CACHE_TTL,
        },
    );

    let ResponderHandshakeCacheLookup::Hit(cached) = state.responder_cache_lookup(
        "peer-cache",
        "session-cache",
        &initiation_bytes,
        Some(&request_probe_public_key),
        &initiator_public,
    ) else {
        panic!("exact duplicate offer should hit responder cache");
    };
    assert_eq!(cached.response_bytes, response_bytes);
    assert_eq!(
        cached.response_probe_ephemeral_public_key.as_deref(),
        Some("probe-public")
    );

    let mut mismatched = initiation_bytes;
    *mismatched.last_mut().unwrap() ^= 1;
    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            &mismatched,
            Some(&request_probe_public_key),
            &initiator_public,
        ),
        ResponderHandshakeCacheLookup::FingerprintMismatch
    ));

    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            &initiation.to_bytes(),
            Some(&hex::encode([0xcdu8; 32])),
            &initiator_public,
        ),
        ResponderHandshakeCacheLookup::FingerprintMismatch
    ));

    assert!(matches!(
        state.responder_cache_lookup(
            "peer-cache",
            "session-cache",
            &initiation.to_bytes(),
            Some(&request_probe_public_key),
            &[0xee; 32],
        ),
        ResponderHandshakeCacheLookup::FingerprintMismatch
    ));
}

#[tokio::test]
async fn responder_cache_rejects_offer_after_peer_static_key_rotation() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-cache-key-rotation";
    let token = "rotated-static-key-token";
    let local_public = daemon.local_identity().unwrap().public_key();
    let old_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let old_public = old_identity.public_key();
    let new_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public && identity.public_key() != old_public {
            break identity;
        }
    };
    let new_public = new_identity.public_key();

    let mut old_initiator = HandshakeInitiator::new(old_identity, local_public, None);
    let initiation = old_initiator.create_initiation().unwrap();
    let initiation_bytes = initiation.to_bytes();
    let mut responder = HandshakeResponder::new(daemon.local_identity().unwrap(), None);
    let (response, keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let request_probe_public_key = hex::encode(DhKeyPair::generate().public_key());
    daemon
        .pending_handshakes
        .lock()
        .await
        .cache_responder_handshake(
            peer_id,
            token,
            CachedResponderHandshake {
                handshake_init: initiation_bytes.clone(),
                initiator_static_public_key: old_public,
                request_probe_ephemeral_public_key: Some(request_probe_public_key.clone()),
                response_bytes: response.to_bytes(),
                transport_keys: keys,
                response_probe_ephemeral_public_key: Some(hex::encode(
                    DhKeyPair::generate().public_key(),
                )),
                probe_ephemeral_shared: Some([0x42; 32]),
                expires_at: Instant::now() + RESPONDER_HANDSHAKE_CACHE_TTL,
            },
        );
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(new_public),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let error = daemon
        .handle_peer_offer(
            peer_id,
            &[],
            &initiation_bytes,
            None,
            None,
            Some(token.to_string()),
            Some(request_probe_public_key),
        )
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("different handshake or Probe key material"));
    assert!(!daemon
        .transport
        .session_status(peer_id)
        .await
        .has_pending_responder);
}

#[tokio::test]
async fn expired_responder_cache_conflict_does_not_poison_active_token() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);
    let peer_id = "peer-expired-cache-conflict";
    let token = "same-active-token";

    let active_initiator_identity = NodeIdentity::generate();
    let active_responder_identity = NodeIdentity::generate();
    let mut active_initiator = HandshakeInitiator::new(
        active_initiator_identity,
        active_responder_identity.public_key(),
        None,
    );
    let active_initiation = active_initiator.create_initiation().unwrap();
    let mut active_responder = HandshakeResponder::new(active_responder_identity, None);
    let (active_response, _) = active_responder
        .consume_initiation_and_respond(&active_initiation)
        .unwrap();
    let active_keys = active_initiator.consume_response(&active_response).unwrap();
    daemon
        .transport
        .install_active_session(
            peer_id,
            Some(token.to_string()),
            TransportSession::new(active_keys),
        )
        .await;

    let local_public = daemon.local_identity().unwrap().public_key();
    let offer_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let offer_public = offer_identity.public_key();
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(offer_public),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let mut offer_initiator = HandshakeInitiator::new(
        offer_identity,
        local_public,
        None,
    );
    let offer_initiation = offer_initiator.create_initiation().unwrap();
    let offer_bytes = offer_initiation.to_bytes();
    let request_probe_public_key = hex::encode(DhKeyPair::generate().public_key());

    let mut expired_responder = HandshakeResponder::new(daemon.local_identity().unwrap(), None);
    let (expired_response, expired_keys) = expired_responder
        .consume_initiation_and_respond(&offer_initiation)
        .unwrap();
    daemon
        .pending_handshakes
        .lock()
        .await
        .cache_responder_handshake(
            peer_id,
            token,
            CachedResponderHandshake {
                handshake_init: offer_bytes.clone(),
                initiator_static_public_key: offer_public,
                request_probe_ephemeral_public_key: Some(request_probe_public_key.clone()),
                response_bytes: expired_response.to_bytes(),
                transport_keys: expired_keys,
                response_probe_ephemeral_public_key: Some(hex::encode(
                    DhKeyPair::generate().public_key(),
                )),
                probe_ephemeral_shared: Some([9u8; 32]),
                expires_at: Instant::now(),
            },
        );

    for _ in 0..2 {
        let error = daemon
            .handle_peer_offer(
                peer_id,
                &[],
                &offer_bytes,
                None,
                None,
                Some(token.to_string()),
                Some(request_probe_public_key.clone()),
            )
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("exact cached answer is unavailable"));
        assert!(!daemon
            .pending_handshakes
            .lock()
            .await
            .responder_cache
            .contains_key(&(peer_id.to_string(), token.to_string())));
    }
}

#[tokio::test]
async fn test_network_outbound_uses_relay_when_udp_unavailable() {
    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();

    let udp_transport = Arc::new(RwLock::new(None));
    let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
    let worker = tokio::spawn(run_network_outbound(
        encrypted_rx,
        peers,
        true,
        udp_transport,
        relay_transport,
    ));

    let payload = vec![4, 9, 8, 7, 6];
    encrypted_tx
        .send(
            OrderedEncryptedPeerPacket::for_test(EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await,
        )
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "node-a");
        assert_eq!(data, payload);
    } else {
        panic!("Expected Data message, got {:?}", received);
    }

    worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_network_outbound_uses_relay_until_direct_is_verified() {
    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let direct_sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let direct_endpoint = direct_sink.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: direct_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();

    let udp_transport = Arc::new(RwLock::new(Some(udp)));
    let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
    let worker = tokio::spawn(run_network_outbound(
        encrypted_rx,
        peers.clone(),
        true,
        udp_transport,
        relay_transport,
    ));

    let payload = vec![9, 8, 7, 6, 5];
    encrypted_tx
        .send(
            OrderedEncryptedPeerPacket::for_test(EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await,
        )
        .await
        .unwrap();

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "node-a");
        assert_eq!(data, payload);
    } else {
        panic!("Expected Data message, got {:?}", received);
    }

    let mut buf = [0u8; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), direct_sink.recv_from(&mut buf))
            .await
            .is_err()
    );

    let conn = peers.get_connection("node-b").await.unwrap();
    assert_eq!(conn.state, ConnectionState::Idle);
    assert_eq!(conn.active_path(), None);
    assert_eq!(conn.relay_server, Some(relay_endpoint));
    let selection = peers.select_path_for_data("node-b", true, true).await;
    assert_eq!(selection.path, Some(peer::NetworkPath::Relay));

    worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_network_outbound_waits_for_relay_when_direct_is_unconfirmed() {
    let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
    let relay_endpoint = server.addr.to_string();
    let direct_sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let direct_endpoint = direct_sink.local_addr().unwrap();

    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "pk".to_string(),
            endpoint: direct_endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers
        .record_direct_probe_success_with_latency(
            "node-b",
            direct_endpoint,
            Some(Duration::from_millis(8)),
        )
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
        .await
        .unwrap();
    let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
        .await
        .unwrap();

    let udp_transport = Arc::new(RwLock::new(Some(udp)));
    let relay_transport = Arc::new(RwLock::new(None));
    let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
    let worker = tokio::spawn(run_network_outbound(
        encrypted_rx,
        peers,
        true,
        udp_transport,
        relay_transport.clone(),
    ));

    let payload = vec![1, 2, 3, 5, 8, 13];
    encrypted_tx
        .send(
            OrderedEncryptedPeerPacket::for_test(EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await,
        )
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_millis(150), rx_b.recv())
        .await
        .expect_err("relay should not receive before relay transport is published");

    *relay_transport.write().await = Some(relay_a);

    let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
        .await
        .unwrap()
        .unwrap();
    if let RelayMessage::Data { from_node, data } = received {
        assert_eq!(from_node, "node-a");
        assert_eq!(data, payload);
    } else {
        panic!("Expected Data message, got {:?}", received);
    }

    worker.abort();
    server.shutdown().await;
}

#[tokio::test]
async fn test_daemon_acl_check() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);

    // Default ACL allows everything
    assert!(daemon.check_acl("node1", "node2", "tcp", 80).await);
}

#[tokio::test]
async fn test_daemon_dns() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.dns.enabled = true;
    let daemon = Daemon::new(config);

    daemon
        .dns()
        .register("test", "10.20.0.5", Some("node1"))
        .await;
    let ip = daemon.dns().resolve("test").await;
    assert_eq!(ip, Some("10.20.0.5".to_string()));
}

#[tokio::test]
async fn test_daemon_port_mapping() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let daemon = Daemon::new(config);

    let mapping =
        port_mapping::PortMapping::new(port_mapping::Protocol::Tcp, "127.0.0.1", 8080, 30000);
    daemon.port_mappings().create(mapping).await.unwrap();
    let list = daemon.port_mappings().list().await;
    assert_eq!(list.len(), 1);
}

/// A responder answer must use the cached candidate snapshot: while the
/// candidate refresh lock is held (simulating a blocked live STUN refresh),
/// the answer still reaches the control server with the cached candidates
/// within a strict short timeout.  STUN/refresh and the endpoint update are
/// NOT prerequisites of the answer.
#[tokio::test]
async fn responder_answer_uses_cached_candidates_while_refresh_is_blocked() {
    use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
    use std::sync::{Arc as StdArc, Mutex as StdMutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let answer_bodies = StdArc::new(StdMutex::new(Vec::<String>::new()));
    let registered = StdArc::new(AtomicBool::new(false));
    let server = {
        let answer_bodies = answer_bodies.clone();
        let registered = registered.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let answer_bodies = answer_bodies.clone();
                let registered = registered.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 8192];
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) => return,
                            Ok(n) => {
                                buf.extend_from_slice(&chunk[..n]);
                                if buf.windows(4).any(|window| window == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let head = String::from_utf8_lossy(&buf).into_owned();
                    let is_register =
                        head.starts_with("POST") && head.contains("/api/v1/devices");
                    let is_poll = head.starts_with("GET") && head.contains("/api/v1/signals");
                    let is_signal =
                        head.starts_with("POST") && head.contains("/api/v1/signals");
                    let body = if is_signal {
                        let content_length = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|value| value.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        let head_end = buf
                            .windows(4)
                            .position(|window| window == b"\r\n\r\n")
                            .unwrap_or(0)
                            + 4;
                        while buf.len() < head_end + content_length {
                            match stream.read(&mut chunk).await {
                                Ok(0) => break,
                                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                                Err(_) => break,
                            }
                        }
                        String::from_utf8_lossy(&buf[head_end..head_end + content_length])
                            .into_owned()
                    } else {
                        String::new()
                    };
                    if is_register {
                        registered.store(true, AtomicOrdering::SeqCst);
                        let body = r#"{"success":true,"node_id":"node-a","virtual_ip":"10.20.0.1","cidr":"10.20.0.0/16","relay_servers":[]}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    } else if is_poll {
                        let body = r#"{"signals":[],"server_time_ms":0}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    } else if is_signal {
                        answer_bodies.lock().unwrap().push(body);
                        let body = r#"{"success":true,"protocol_version":1}"#;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                    }
                });
            }
        })
    };

    let mut config = Config::generate_default(&format!("http://{address}"), "net1").unwrap();
    config.control.auth_token = "test-token".to_string();
    config.node.node_id = "node-a".to_string();
    let daemon = Daemon::new(config);

    // The local node is the designated responder for this peer.
    let local_public = daemon.local_identity().unwrap().public_key();
    let peer_identity = loop {
        let identity = NodeIdentity::generate();
        if identity.public_key() < local_public {
            break identity;
        }
    };
    let peer_id = "peer-cached-answer";
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: peer_id.to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(peer_identity.public_key()),
            endpoint: String::new(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    // The cached candidate snapshot the answer must use.
    let cached = vec![
        "203.0.113.120:55001".to_string(),
        "127.0.0.1:55002".to_string(),
    ];
    *daemon.local_candidates.write().await = cached.clone();
    *daemon.local_candidate_sources.write().await = HashMap::from([
        (cached[0].clone(), "stun_observed".to_string()),
        (cached[1].clone(), "host".to_string()),
    ]);

    // A blocked live refresh: any STUN/candidate refresh would stall here.
    // The answer must not wait for it.
    let refresh_guard = daemon.candidate_refresh_lock.clone().lock_owned().await;

    let mut initiator = HandshakeInitiator::new(peer_identity.clone(), local_public, None);
    let initiation = initiator.create_initiation().unwrap().to_bytes();
    daemon
        .control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: peer_id.to_string(),
            candidates: vec!["198.51.100.9:44001".to_string()],
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: HashMap::new(),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: initiation,
            punch_at_ms: Some(relay_assisted_punch_at_ms()),
            punch_at_server_ms: None,
            sender_public_key: Some(hex::encode(peer_identity.public_key())),
        })
        .unwrap();

    let shutdown = daemon.shutdown_sender();
    let (network_tx, _network_rx) = mpsc::channel(8);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let loop_task = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, network_tx)
            .await;
    });

    // Registration must land before the critical lane publishes auth.
    timeout(Duration::from_secs(5), async {
        while !registered.load(AtomicOrdering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("daemon must register against the mock control server");

    // The answer must arrive with the CACHED candidates within a strict
    // short timeout while the refresh lock is still held.
    let answer_body = timeout(Duration::from_secs(5), async {
        loop {
            let bodies = answer_bodies.lock().unwrap().clone();
            if let Some(body) = bodies
                .iter()
                .find(|body| body.contains("\"type\":\"peer_answer\""))
            {
                break body.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the responder answer must be sent while the refresh is blocked");

    assert!(
        answer_body.contains("203.0.113.120:55001"),
        "the answer must carry the cached candidate, got: {answer_body}"
    );
    assert!(
        answer_body.contains("127.0.0.1:55002"),
        "the answer must carry the cached host candidate, got: {answer_body}"
    );
    assert!(
        !answer_body.contains("198.51.100.9"),
        "the answer must not mix the offer's remote candidates into its own set: {answer_body}"
    );

    // Release the refresh lock so the daemon can wind down.
    drop(refresh_guard);
    let _ = shutdown.send(true);
    let _ = timeout(Duration::from_secs(3), loop_task).await;
    server.abort();
}
