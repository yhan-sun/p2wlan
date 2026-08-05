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
    let mut daemon = Daemon::new(config);
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
    let mut daemon = Daemon::new(config);
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
    let mut daemon = Daemon::new(config);
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
    let mut daemon = Daemon::new(config);
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
    let mut daemon = Daemon::new(config);
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
    let mut daemon = Daemon::new(config);
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
