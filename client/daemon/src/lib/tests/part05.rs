/// Dual-end convergence: a daemon-internal direct-validation request/ACK
/// exchange must bring BOTH sides to Direct with no TUN device and no user
/// traffic.
///
/// Both sides run the owned encrypted validation worker.  An inbound request
/// is only ingress evidence and an idempotent ACK response; each side must
/// complete its own request/ACK transaction before promotion.
#[tokio::test]
async fn dual_end_direct_validation_converges_without_tun_or_user_traffic() {
    let a_identity = NodeIdentity::generate();
    let b_identity = NodeIdentity::generate();
    let a_public_key = hex::encode(a_identity.public_key());
    let b_public_key = hex::encode(b_identity.public_key());
    let mut a_initiator = HandshakeInitiator::new(a_identity, b_identity.public_key(), None);
    let initiation = a_initiator.create_initiation().unwrap();
    let mut b_responder = HandshakeResponder::new(b_identity, None);
    let (response, b_local_keys) = b_responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let a_local_keys = a_initiator.consume_response(&response).unwrap();

    let peers_a = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let peers_b = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers_a
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: b_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers_b
        .add_peer(&control::PeerInfo {
            node_id: "node-a".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: a_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.1".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    // --- Side A wiring: UDP reader -> WireGuard inbound (no TUN: the IP
    // packet channel receiver is dropped, exactly like P2WLAN_DISABLE_TUN=1).
    let (udp_inbound_tx_a, udp_inbound_rx_a) = mpsc::channel(64);
    let udp_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .unwrap()
        .with_inbound_channel(udp_inbound_tx_a.clone());
    let udp_a_worker = tokio::spawn(udp_a.clone().run_inbound(udp_inbound_tx_a));
    let (inbound_tx_a, _inbound_rx_a) = mpsc::channel(64);
    let (wg_a, _encrypted_rx_a) = WireGuardTransport::new();
    wg_a.add_session("node-b", TransportSession::new(a_local_keys))
        .await;
    let wg_a_worker = {
        let wg = wg_a.clone();
        let peers = peers_a.clone();
        let udp = udp_a.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_a, inbound_tx_a, Some(peers), Some(udp))
                .await;
        })
    };

    // --- Side B wiring. The responder must feed an inbound validation request
    // into its own worker; receiving the other side's request is not local
    // request/ACK proof.
    let (udp_inbound_tx_b, udp_inbound_rx_b) = mpsc::channel(64);
    let (wg_b, _encrypted_rx_b) = WireGuardTransport::new();
    wg_b.add_session("node-a", TransportSession::new(b_local_keys))
        .await;
    let udp_b_base = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wg_b.clone())
        .with_inbound_channel(udp_inbound_tx_b.clone());
    let trigger_udp_b = udp_b_base.clone();
    let trigger_peers_b = peers_b.clone();
    let trigger_wg_b = wg_b.clone();
    let udp_b = udp_b_base.with_validation_trigger(Arc::new(move |observation| {
        let udp = trigger_udp_b.clone();
        let peers = trigger_peers_b.clone();
        let wg = trigger_wg_b.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(observation, udp, peers, wg, "10.20.0.2")
                .await;
        });
    }));
    let udp_b_addr = udp_b.local_addr().unwrap();
    let udp_b_worker = tokio::spawn(udp_b.clone().run_inbound(udp_inbound_tx_b));
    let (inbound_tx_b, _inbound_rx_b) = mpsc::channel(64);
    let wg_b_worker = {
        let wg = wg_b.clone();
        let peers = peers_b.clone();
        let udp = udp_b.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_b, inbound_tx_b, Some(peers), Some(udp))
                .await;
        })
    };

    // A validates its observed endpoint for node-b with the daemon-internal
    // request/ACK exchange.  No user traffic, no TUN, no control plane.
    run_direct_encrypted_validation(
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint: udp_b_addr,
        },
        udp_a.clone(),
        peers_a.clone(),
        wg_a.clone(),
        "10.20.0.1",
    )
    .await;

    // BOTH sides must converge to Direct within a reasonable bound.
    timeout(Duration::from_secs(10), async {
        loop {
            let a_direct = peers_a.is_direct("node-b").await;
            let b_direct = peers_b.is_direct("node-a").await;
            if a_direct && b_direct {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("both sides must converge to Direct via the validation request/ACK exchange");

    let diagnostics_a = peers_a.diagnostics().await;
    let validation_ack = diagnostics_a[0]
        .direct_events
        .iter()
        .find(|event| event.stage == "direct_validation_ack_received")
        .expect("the initiator must record the matched validation ACK");
    assert!(
        validation_ack.validation_session_id.is_some(),
        "the promotion ACK must remain tied to its owned encrypted validation worker"
    );
    assert_eq!(validation_ack.socket_index, Some(0));
    assert!(
        validation_ack.detail.contains("socket_index=0"),
        "the promotion ACK event must retain the UDP socket that carried the encrypted ACK: {}",
        validation_ack.detail
    );
    let diagnostics_b = peers_b.diagnostics().await;
    assert!(
        diagnostics_b[0]
            .direct_events
            .iter()
            .any(|event| event.stage == "direct_validation_request_received"),
        "the responder must record the validated request"
    );
    for (label, diagnostics) in [("initiator", diagnostics_a), ("responder", diagnostics_b)] {
        let events = &diagnostics[0].direct_events;
        let request = events
            .iter()
            .find(|event| event.stage == "direct_validation_request_sent")
            .unwrap_or_else(|| panic!("{label} must send its own validation request"));
        let ack = events
            .iter()
            .find(|event| event.stage == "direct_validation_ack_received")
            .unwrap_or_else(|| panic!("{label} must consume its own matching validation ACK"));
        let promoted = events
            .iter()
            .find(|event| event.stage == "direct_validation_promoted")
            .unwrap_or_else(|| panic!("{label} promotion must be tied to validation"));
        assert_eq!(request.validation_session_id, ack.validation_session_id);
        assert_eq!(ack.validation_session_id, promoted.validation_session_id);
        assert_eq!(ack.endpoint, promoted.endpoint);
        assert_eq!(ack.socket_index, promoted.socket_index);
    }

    udp_a_worker.abort();
    udp_b_worker.abort();
    wg_a_worker.abort();
    wg_b_worker.abort();
}

/// The daemon wires a matched-ACK convergence trigger into the UDP transport:
/// whenever the UDP reader matches an authenticated probe ACK it must fire the
/// registered trigger, which spawns the daemon-internal validation exchange.
/// This test replicates that exact wiring (observer channel + trigger with a
/// firing counter) and drives REAL punch+ACK traffic: BOTH sides must converge
/// to Direct and the trigger must have fired on at least the initiator.
#[tokio::test]
async fn matched_ack_fires_validation_trigger_and_both_sides_converge() {
    let a_identity = NodeIdentity::generate();
    let b_identity = NodeIdentity::generate();
    let a_public_key = hex::encode(a_identity.public_key());
    let b_public_key = hex::encode(b_identity.public_key());
    let mut a_initiator = HandshakeInitiator::new(a_identity, b_identity.public_key(), None);
    let initiation = a_initiator.create_initiation().unwrap();
    let mut b_responder = HandshakeResponder::new(b_identity, None);
    let (response, b_local_keys) = b_responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let a_local_keys = a_initiator.consume_response(&response).unwrap();

    let peers_a = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let peers_b = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers_a
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: b_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers_b
        .add_peer(&control::PeerInfo {
            node_id: "node-a".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: a_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.1".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (udp_inbound_tx_a, udp_inbound_rx_a) = mpsc::channel(64);
    let (wg_a, _encrypted_rx_a) = WireGuardTransport::new();
    wg_a.add_session("node-b", TransportSession::new(a_local_keys))
        .await;
    // Daemon wiring: observer channel (unused here) + the validation trigger.
    let peer_reflexive_ingress = PeerReflexiveIngress::new();
    let trigger_fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let udp_a_base = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wg_a.clone())
        .with_inbound_channel(udp_inbound_tx_a.clone())
        .with_peer_reflexive_observer(peer_reflexive_ingress);
    let trigger_peers = peers_a.clone();
    let trigger_wg = wg_a.clone();
    let fired = trigger_fired.clone();
    let trigger_udp = udp_a_base.clone();
    let udp_a = udp_a_base.with_validation_trigger(Arc::new(move |observation| {
        fired.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let udp = trigger_udp.clone();
        let peers = trigger_peers.clone();
        let wg = trigger_wg.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(observation, udp, peers, wg, "10.20.0.1")
                .await;
        });
    }));
    let udp_a_worker = tokio::spawn(udp_a.clone().run_inbound(udp_inbound_tx_a));
    let (inbound_tx_a, _inbound_rx_a) = mpsc::channel(64);
    let wg_a_worker = {
        let wg = wg_a.clone();
        let peers = peers_a.clone();
        let udp = udp_a.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_a, inbound_tx_a, Some(peers), Some(udp))
                .await;
        })
    };

    let (udp_inbound_tx_b, udp_inbound_rx_b) = mpsc::channel(64);
    let (wg_b, _encrypted_rx_b) = WireGuardTransport::new();
    wg_b.add_session("node-a", TransportSession::new(b_local_keys))
        .await;
    let udp_b_base = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wg_b.clone())
        .with_inbound_channel(udp_inbound_tx_b.clone());
    let trigger_udp_b = udp_b_base.clone();
    let trigger_peers_b = peers_b.clone();
    let trigger_wg_b = wg_b.clone();
    let udp_b = udp_b_base.with_validation_trigger(Arc::new(move |observation| {
        let udp = trigger_udp_b.clone();
        let peers = trigger_peers_b.clone();
        let wg = trigger_wg_b.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(observation, udp, peers, wg, "10.20.0.2")
                .await;
        });
    }));
    let udp_b_addr = udp_b.local_addr().unwrap();
    let udp_b_worker = tokio::spawn(udp_b.clone().run_inbound(udp_inbound_tx_b));
    let (inbound_tx_b, _inbound_rx_b) = mpsc::channel(64);
    let wg_b_worker = {
        let wg = wg_b.clone();
        let peers = peers_b.clone();
        let udp = udp_b.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_b, inbound_tx_b, Some(peers), Some(udp))
                .await;
        })
    };

    // Drive real authenticated punch traffic both ways: each side ACKs the
    // other's punches, and every matched ACK must fire the daemon trigger.
    udp_a
        .punch_candidates(
            "node-b",
            vec![udp_b_addr],
            Duration::from_millis(50),
            3,
        )
        .await
        .expect("A must send its punches");
    udp_b
        .punch_candidates(
            "node-a",
            vec![udp_a.local_addr().unwrap()],
            Duration::from_millis(50),
            3,
        )
        .await
        .expect("B must send its punches");

    let converged = timeout(Duration::from_secs(10), async {
        loop {
            let a_direct = peers_a.is_direct("node-b").await;
            let b_direct = peers_b.is_direct("node-a").await;
            if a_direct && b_direct {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok();
    eprintln!(
        "DEBUG: converged={converged} trigger_fired={} a_direct={} b_direct={} a_acks={} b_acks={}",
        trigger_fired.load(std::sync::atomic::Ordering::SeqCst),
        peers_a.is_direct("node-b").await,
        peers_b.is_direct("node-a").await,
        peers_a.direct_probe_success_count_for_generation("node-b", 0).await,
        peers_b.direct_probe_success_count_for_generation("node-a", 0).await,
    );
    assert!(
        converged,
        "both sides must converge to Direct via the matched-ACK trigger"
    );
    assert!(
        trigger_fired.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "the daemon validation trigger must fire on a matched ACK"
    );

    udp_a_worker.abort();
    udp_b_worker.abort();
    wg_a_worker.abort();
    wg_b_worker.abort();
}

/// Network generations are PER-SIDE counters: the responder's generation must
/// never gate the initiator's request.  Even when the responder advanced its
/// own generation (candidate refresh) while the initiator's request still
/// carries an older generation, the authenticated request must promote the
/// responder — otherwise one refresh on either side makes the pair unable to
/// converge until both counters happen to align again.
#[tokio::test]
async fn responder_promotes_on_request_with_different_local_generation() {
    let a_identity = NodeIdentity::generate();
    let b_identity = NodeIdentity::generate();
    let a_public_key = hex::encode(a_identity.public_key());
    let b_public_key = hex::encode(b_identity.public_key());
    let mut a_initiator = HandshakeInitiator::new(a_identity, b_identity.public_key(), None);
    let initiation = a_initiator.create_initiation().unwrap();
    let mut b_responder = HandshakeResponder::new(b_identity, None);
    let (response, b_local_keys) = b_responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let a_local_keys = a_initiator.consume_response(&response).unwrap();

    let peers_a = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let peers_b = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers_a
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: b_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers_b
        .add_peer(&control::PeerInfo {
            node_id: "node-a".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: a_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.1".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (udp_inbound_tx_a, udp_inbound_rx_a) = mpsc::channel(64);
    let (wg_a, _encrypted_rx_a) = WireGuardTransport::new();
    wg_a.add_session("node-b", TransportSession::new(a_local_keys))
        .await;
    let udp_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wg_a.clone())
        .with_inbound_channel(udp_inbound_tx_a.clone());
    let udp_a_worker = tokio::spawn(udp_a.clone().run_inbound(udp_inbound_tx_a));
    let (inbound_tx_a, _inbound_rx_a) = mpsc::channel(64);
    let wg_a_worker = {
        let wg = wg_a.clone();
        let peers = peers_a.clone();
        let udp = udp_a.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_a, inbound_tx_a, Some(peers), Some(udp))
                .await;
        })
    };

    let (udp_inbound_tx_b, udp_inbound_rx_b) = mpsc::channel(64);
    let (wg_b, _encrypted_rx_b) = WireGuardTransport::new();
    wg_b.add_session("node-a", TransportSession::new(b_local_keys))
        .await;
    let udp_b_base = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wg_b.clone())
        .with_inbound_channel(udp_inbound_tx_b.clone());
    let trigger_udp_b = udp_b_base.clone();
    let trigger_peers_b = peers_b.clone();
    let trigger_wg_b = wg_b.clone();
    let udp_b = udp_b_base.with_validation_trigger(Arc::new(move |observation| {
        let udp = trigger_udp_b.clone();
        let peers = trigger_peers_b.clone();
        let wg = trigger_wg_b.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(observation, udp, peers, wg, "10.20.0.2")
                .await;
        });
    }));
    let udp_b_addr = udp_b.local_addr().unwrap();
    let udp_b_worker = tokio::spawn(udp_b.clone().run_inbound(udp_inbound_tx_b));
    let (inbound_tx_b, _inbound_rx_b) = mpsc::channel(64);
    let wg_b_worker = {
        let wg = wg_b.clone();
        let peers = peers_b.clone();
        let udp = udp_b.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_b, inbound_tx_b, Some(peers), Some(udp))
                .await;
        })
    };

    // The responder's local generation is bumped AFTER the initiator is
    // already probing: the initiator's request token keeps generation 0.
    let b_generation = peers_b.advance_network_generation("test candidate refresh").await;
    assert!(b_generation > 0);

    run_direct_encrypted_validation(
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint: udp_b_addr,
        },
        udp_a.clone(),
        peers_a.clone(),
        wg_a.clone(),
        "10.20.0.1",
    )
    .await;

    timeout(Duration::from_secs(10), async {
        loop {
            let a_direct = peers_a.is_direct("node-b").await;
            let b_direct = peers_b.is_direct("node-a").await;
            if a_direct && b_direct {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect(
        "the responder must promote on an authenticated request even when its own generation differs",
    );

    udp_a_worker.abort();
    udp_b_worker.abort();
    wg_a_worker.abort();
    wg_b_worker.abort();
}

#[tokio::test]
async fn peer_reflexive_ingress_drops_observation_for_direct_peer() {
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

    let observed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_addr = observed.local_addr().unwrap();
    peers
        .record_direct_success("node-b", Some(observed_addr))
        .await;
    assert!(peers.is_direct("node-b").await);

    let ingress = PeerReflexiveIngress::new();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let permits = Arc::new(tokio::sync::Semaphore::new(2));
    let loop_worker = tokio::spawn(run_peer_reflexive_signal_loop_with_worker_permits(
        ingress.clone(),
        ControlClient::disabled_for_test(),
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        permits,
    ));
    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: observed_addr,
    });

    // The loop consumes the observation and drops it without scheduling any
    // signal work: no fast punch, no HTTP signal, no worker events.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if ingress.pending_len() == 0 {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the signal loop must consume the Direct peer's observation");

    let conn = peers.get_connection("node-b").await.unwrap();
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "peer_reflexive_fast_punch_started"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "peer_reflexive_fast_punch_sent"));

    let mut buf = [0u8; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(250), observed.recv_from(&mut buf))
            .await
            .is_err(),
        "a Direct peer's observation must not trigger a peer-reflexive fast punch"
    );

    loop_worker.abort();
}

#[tokio::test]
async fn peer_reflexive_worker_rechecks_direct_before_http_and_fast_punch() {
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

    let observed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_addr = observed.local_addr().unwrap();

    // Seed the slot table directly (bypassing the ingress gate) and promote
    // the peer to Direct BEFORE the worker picks the observation up: the
    // worker's own fence must refuse the HTTP signal and the fast punch.
    let slots: PeerReflexiveSignalSlots = Arc::new(Mutex::new(HashMap::new()));
    slots.lock().await.insert(
        "node-b".to_string(),
        PeerReflexiveSignalSlot {
            latest: Some(PeerReflexiveObservation {
                peer_id: "node-b".to_string(),
                observed_endpoint: observed_addr,
            }),
            ..PeerReflexiveSignalSlot::default()
        },
    );
    peers
        .record_direct_success("node-b", Some(observed_addr))
        .await;

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    run_peer_reflexive_signal_worker(
        "node-b".to_string(),
        slots,
        ControlClient::disabled_for_test(),
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
    )
    .await;

    let conn = peers.get_connection("node-b").await.unwrap();
    assert!(conn
        .direct_events
        .iter()
        .any(|event| event.stage == "peer_reflexive_signal_skipped_direct"));
    assert!(!conn
        .direct_events
        .iter()
        .any(|event| event.stage == "peer_reflexive_fast_punch_started"));

    let mut buf = [0u8; 512];
    assert!(
        tokio::time::timeout(Duration::from_millis(250), observed.recv_from(&mut buf))
            .await
            .is_err(),
        "a Direct peer must not receive the peer-reflexive fast punch"
    );
}

#[tokio::test]
async fn peer_reflexive_signal_worker_fast_punches_a_non_direct_peer() {
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
    assert!(!peers.is_direct("node-b").await);

    let observed = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let observed_addr = observed.local_addr().unwrap();
    let ingress = PeerReflexiveIngress::new();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let permits = Arc::new(tokio::sync::Semaphore::new(2));
    let loop_worker = tokio::spawn(run_peer_reflexive_signal_loop_with_worker_permits(
        ingress.clone(),
        ControlClient::disabled_for_test(),
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        permits,
    ));
    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: observed_addr,
    });

    let mut buf = [0u8; 512];
    tokio::time::timeout(Duration::from_secs(2), observed.recv_from(&mut buf))
        .await
        .expect("a non-Direct peer's observation must reach the fast punch")
        .expect("socket read failed");
    assert_eq!(buf[0], b'P');
    assert_eq!(&buf[..4], b"PNCH");

    loop_worker.abort();
}

#[tokio::test]
async fn peer_reflexive_fast_punch_does_not_block_endpoint_signal_on_ack_grace() {
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

    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("node-a");
    let observation = PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: receiver.local_addr().unwrap(),
    };

    let started = Instant::now();
    timeout(
        Duration::from_millis(500),
        run_peer_reflexive_fast_punch(&udp, &peers, &observation),
    )
    .await
    .expect("the fast NAT warmer must not wait for the one-second ACK grace window");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "the peer-reflexive fast punch must return before its diagnostic ACK grace window"
    );

    let mut packet = [0u8; 512];
    timeout(Duration::from_millis(250), receiver.recv_from(&mut packet))
        .await
        .expect("the fast punch must still send a real UDP probe")
        .expect("the UDP receiver must accept the probe");
}

#[tokio::test]
async fn peer_reflexive_micro_window_is_deduplicated_bounded_and_records_actual_send() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            // Avoid a legacy compatibility copy: this test's cap is the
            // logical micro-window send count as seen by the UDP receiver.
            app_version: "0.1.25".to_string(),
            public_key: "pk".to_string(),
            endpoint: endpoint.to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("node-a");
    let deduplicator = PunchAttemptDeduplicator::default();
    let punch_at_ms = unix_time_millis().saturating_add(400);

    spawn_peer_reflexive_micro_window(
        udp,
        peers.clone(),
        deduplicator.clone(),
        "node-b".to_string(),
        vec![endpoint, endpoint],
        Some(punch_at_ms),
        "test_observer",
    )
    .await;
    // The same relay window must fold rather than create a second owner or a
    // second two-attempt burst.
    spawn_peer_reflexive_micro_window(
        UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_local_node_id("node-a"),
        peers.clone(),
        deduplicator,
        "node-b".to_string(),
        vec![endpoint],
        Some(punch_at_ms),
        "test_duplicate",
    )
    .await;

    let mut buf = [0u8; 512];
    timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
        .await
        .expect("the scheduled micro-window must emit a probe")
        .unwrap();
    let mut received = 1u32;
    while let Ok(Ok(_)) = timeout(Duration::from_millis(80), receiver.recv_from(&mut buf)).await {
        received = received.saturating_add(1);
    }
    assert!(
        received <= PEER_REFLEXIVE_MICRO_WINDOW_ATTEMPTS,
        "one endpoint/one owner micro-window must stay bounded, got {received} packets"
    );
    let events = peers.get_connection("node-b").await.unwrap().direct_events;
    assert!(events
        .iter()
        .any(|event| event.stage == "peer_reflexive_micro_window_scheduled"));
    let sent = events
        .iter()
        .find(|event| event.stage == "peer_reflexive_micro_window_first_packet_sent")
        .expect("actual kernel send must be recorded separately from dispatch");
    assert_eq!(sent.socket_index, Some(0));
    assert!(sent.detail.contains("actual_first_send_at_ms=Some"));
    assert!(events
        .iter()
        .any(|event| event.stage == "peer_reflexive_micro_window_deferred"));
    assert!(
        !peers.is_direct("node-b").await,
        "a probe micro-window is only validation ingress, never Direct promotion"
    );
}

#[tokio::test]
async fn post_direct_inbound_punch_and_matched_ack_create_no_new_traversal_work() {
    // Dual-end harness: both sides converge to Direct through real
    // authenticated punches and the daemon-internal encrypted validation,
    // then post-convergence inbound traffic (punches, matched ACKs,
    // peer-reflexive observations) must create no new validation session,
    // expectation, trigger or probe.
    let a_identity = NodeIdentity::generate();
    let b_identity = NodeIdentity::generate();
    let a_public_key = hex::encode(a_identity.public_key());
    let b_public_key = hex::encode(b_identity.public_key());
    let mut a_initiator = HandshakeInitiator::new(a_identity, b_identity.public_key(), None);
    let initiation = a_initiator.create_initiation().unwrap();
    let mut b_responder = HandshakeResponder::new(b_identity, None);
    let (response, b_local_keys) = b_responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let a_local_keys = a_initiator.consume_response(&response).unwrap();

    let peers_a = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let peers_b = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers_a
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: b_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    peers_b
        .add_peer(&control::PeerInfo {
            node_id: "node-a".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: a_public_key.clone(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.1".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let (udp_inbound_tx_a, udp_inbound_rx_a) = mpsc::channel(64);
    let (wg_a, _encrypted_rx_a) = WireGuardTransport::new();
    wg_a.add_session("node-b", TransportSession::new(a_local_keys))
        .await;
    let peer_reflexive_ingress_a = PeerReflexiveIngress::new();
    let trigger_a_fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let udp_a_base = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wg_a.clone())
        .with_inbound_channel(udp_inbound_tx_a.clone())
        .with_peer_reflexive_observer(peer_reflexive_ingress_a.clone());
    let trigger_peers = peers_a.clone();
    let trigger_wg = wg_a.clone();
    let fired = trigger_a_fired.clone();
    let trigger_udp = udp_a_base.clone();
    let udp_a = udp_a_base.with_validation_trigger(Arc::new(move |observation| {
        fired.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let udp = trigger_udp.clone();
        let peers = trigger_peers.clone();
        let wg = trigger_wg.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(observation, udp, peers, wg, "10.20.0.1")
                .await;
        });
    }));
    let udp_a_worker = tokio::spawn(udp_a.clone().run_inbound(udp_inbound_tx_a));
    let (inbound_tx_a, _inbound_rx_a) = mpsc::channel(64);
    let wg_a_worker = {
        let wg = wg_a.clone();
        let peers = peers_a.clone();
        let udp = udp_a.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_a, inbound_tx_a, Some(peers), Some(udp))
                .await;
        })
    };

    let (udp_inbound_tx_b, udp_inbound_rx_b) = mpsc::channel(64);
    let (wg_b, _encrypted_rx_b) = WireGuardTransport::new();
    wg_b.add_session("node-a", TransportSession::new(b_local_keys))
        .await;
    let peer_reflexive_ingress_b = PeerReflexiveIngress::new();
    let trigger_b_fired = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let udp_b_base = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .unwrap()
        .with_wireguard_transport(wg_b.clone())
        .with_inbound_channel(udp_inbound_tx_b.clone())
        .with_peer_reflexive_observer(peer_reflexive_ingress_b.clone());
    let trigger_b_peers = peers_b.clone();
    let trigger_b_wg = wg_b.clone();
    let fired_b = trigger_b_fired.clone();
    let trigger_b_udp = udp_b_base.clone();
    let udp_b = udp_b_base.with_validation_trigger(Arc::new(move |observation| {
        fired_b.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let udp = trigger_b_udp.clone();
        let peers = trigger_b_peers.clone();
        let wg = trigger_b_wg.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(observation, udp, peers, wg, "10.20.0.2")
                .await;
        });
    }));
    let udp_b_addr = udp_b.local_addr().unwrap();
    let udp_b_worker = tokio::spawn(udp_b.clone().run_inbound(udp_inbound_tx_b));
    let (inbound_tx_b, _inbound_rx_b) = mpsc::channel(64);
    let wg_b_worker = {
        let wg = wg_b.clone();
        let peers = peers_b.clone();
        let udp = udp_b.clone();
        tokio::spawn(async move {
            let _ = wg
                .run_inbound_with_peers(udp_inbound_rx_b, inbound_tx_b, Some(peers), Some(udp))
                .await;
        })
    };

    // Converge both sides to Direct via real punches and encrypted validation.
    udp_a
        .punch_candidates("node-b", vec![udp_b_addr], Duration::from_millis(50), 3)
        .await
        .unwrap();
    udp_b
        .punch_candidates(
            "node-a",
            vec![udp_a.local_addr().unwrap()],
            Duration::from_millis(50),
            3,
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(10), async {
        loop {
            if peers_a.is_direct("node-b").await && peers_b.is_direct("node-a").await {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("both sides must converge to Direct");

    let triggers_a_before = trigger_a_fired.load(std::sync::atomic::Ordering::SeqCst);
    let triggers_b_before = trigger_b_fired.load(std::sync::atomic::Ordering::SeqCst);
    // Convergence may have been driven purely by encrypted validation (no
    // matched UDP probe ACK required), so the counters themselves are not
    // asserted; what matters is that they are frozen after the promotion.

    // Drain observations that were queued DURING convergence (this harness
    // runs no peer-reflexive signal consumer), so the post-Direct traffic can
    // be judged strictly: any new ingress entry after this point is a gate
    // violation.
    while timeout(Duration::from_millis(100), peer_reflexive_ingress_a.next())
        .await
        .is_ok()
    {}
    while timeout(Duration::from_millis(100), peer_reflexive_ingress_b.next())
        .await
        .is_ok()
    {}

    // Post-Direct: A punches B again; B answers only with ACK bursts.  The
    // ACKs and the punches must not create validation sessions, expectations,
    // peer-reflexive observations or reverse checks on either side.
    udp_a
        .punch_candidates("node-b", vec![udp_b_addr], Duration::from_millis(20), 4)
        .await
        .unwrap();
    udp_b
        .punch_candidates(
            "node-a",
            vec![udp_a.local_addr().unwrap()],
            Duration::from_millis(20),
            4,
        )
        .await
        .unwrap();
    sleep(Duration::from_millis(600)).await;

    assert_eq!(
        trigger_a_fired.load(std::sync::atomic::Ordering::SeqCst),
        triggers_a_before,
        "post-Direct matched ACKs at A must not enqueue direct validation"
    );
    assert_eq!(
        trigger_b_fired.load(std::sync::atomic::Ordering::SeqCst),
        triggers_b_before,
        "post-Direct inbound punches at B must not enqueue direct validation"
    );
    assert_eq!(
        peer_reflexive_ingress_a.pending_len(),
        0,
        "post-Direct observations at A must not be queued for the peer-reflexive signal loop"
    );
    assert_eq!(
        peer_reflexive_ingress_b.pending_len(),
        0,
        "post-Direct observations at B must not be queued for the peer-reflexive signal loop"
    );
    assert!(!udp_a.has_direct_validation_expectation("node-b").await);
    assert!(udp_a.direct_validation_target("node-b").await.is_none());
    assert!(!udp_b.has_direct_validation_expectation("node-a").await);
    assert!(udp_b.direct_validation_target("node-a").await.is_none());

    // No daemon-driven scan may have started after the promotion.
    let conn_a = peers_a.get_connection("node-b").await.unwrap();
    let direct_index_a = conn_a
        .direct_events
        .iter()
        .rposition(|event| event.stage == "direct_path_promoted")
        .unwrap_or(0);
    assert!(!conn_a.direct_events[direct_index_a..]
        .iter()
        .any(|event| event.stage == "punch_started" || event.stage == "punch_probes_sent"));
    let conn_b = peers_b.get_connection("node-a").await.unwrap();
    let direct_index_b = conn_b
        .direct_events
        .iter()
        .rposition(|event| event.stage == "direct_path_promoted")
        .unwrap_or(0);
    assert!(!conn_b.direct_events[direct_index_b..]
        .iter()
        .any(|event| event.stage == "punch_started" || event.stage == "punch_probes_sent"));

    udp_a_worker.abort();
    udp_b_worker.abort();
    wg_a_worker.abort();
    wg_b_worker.abort();
}

/// A stale (old-generation) validation ACK must never confirm a new session:
/// the ACK token is only trusted when it matches the outstanding expectation's
/// request id AND generation.
#[tokio::test]
async fn stale_validation_ack_cannot_confirm_a_new_generation() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "peer-public-key".to_string(),
            endpoint: String::new(),
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

    // The validation task registered an expectation for generation 0.
    udp.expect_direct_validation_ack("node-b", 7, 0).await;
    assert!(udp.has_direct_validation_expectation("node-b").await);

    // A stale-generation ACK is refused and the expectation survives.
    assert!(
        !udp.confirm_direct_validation_ack("node-b", 7, 1).await,
        "an ACK from a different generation must never confirm the request"
    );
    assert!(
        udp.has_direct_validation_expectation("node-b").await,
        "the expectation must survive a mismatched ACK"
    );
    // A wrong request id is refused too.
    assert!(
        !udp.confirm_direct_validation_ack("node-b", 8, 0).await,
        "an ACK for a different request must never confirm the path"
    );
    assert!(udp.has_direct_validation_expectation("node-b").await);

    // The matching ACK confirms exactly once and consumes the expectation.
    assert!(udp.confirm_direct_validation_ack("node-b", 7, 0).await);
    assert!(!udp.has_direct_validation_expectation("node-b").await);
    assert!(
        !udp.confirm_direct_validation_ack("node-b", 7, 0).await,
        "a duplicate ACK is a no-op"
    );
}

/// A signal bound by the control server to a STALE sender identity (the peer
/// changed its public key and this signal was queued before the change) must
/// never enter the NEW identity's fresh-prediction high-water space: its
/// fresh label is treated as stale and its candidates are not applied.
#[tokio::test]
async fn stale_sender_identity_fresh_signal_never_enters_new_high_water() {
    let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
    let daemon = Daemon::new(config);
    daemon
        .peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: "current-identity-key".to_string(),
            endpoint: "203.0.113.10:51839".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    let boot = 1_742_987_654_321u64;
    let label = fresh_prediction_source_label(FreshPredictionId {
        boot_epoch: boot,
        generation: 1,
    });
    let candidates = vec!["203.0.113.10:45393".to_string()];
    let sources = HashMap::from([("203.0.113.10:45393".to_string(), label.clone())]);

    let peers = daemon.peers.clone();
    let control = daemon.control.clone();
    let (net_tx, _net_rx) = mpsc::channel(64);
    let mut relay_started = false;
    let mut daemon_task = daemon;
    let handle = tokio::spawn(async move {
        daemon_task
            .run_control_event_loop(&mut relay_started, net_tx)
            .await;
    });

    // The signal is bound to the OLD identity fingerprint while the peer's
    // current public key is different: the fresh label must be rejected.
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: "node-b".to_string(),
            candidates: candidates.clone(),
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: sources.clone(),
            candidate_generation: 1,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some("old-identity-key".to_string()),
        })
        .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-b")
                .await
                .unwrap()
                .direct_events
                .iter()
                .any(|event| event.stage == "fresh_prediction_stale_identity")
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the stale-identity signal must be observed and rejected");
    let conn = peers.get_connection("node-b").await.unwrap();
    assert!(
        !conn.candidates.contains(&"203.0.113.10:45393".to_string()),
        "stale-identity fresh candidates must never be applied"
    );

    // The same signal bound to the CURRENT identity is accepted.
    control
        .event_sender()
        .send(ControlEvent::PeerOffer {
            from_node_id: "node-b".to_string(),
            candidates: candidates.clone(),
            session_id: None,
            probe_ephemeral_public_key: None,
            candidate_sources: sources.clone(),
            candidate_generation: 2,
            candidates_expires_at_ms: None,
            handshake_init: Vec::new(),
            punch_at_ms: None,
            punch_at_server_ms: None,
            sender_public_key: Some("current-identity-key".to_string()),
        })
        .unwrap();
    timeout(Duration::from_secs(2), async {
        loop {
            if peers
                .get_connection("node-b")
                .await
                .unwrap()
                .candidates
                .contains(&"203.0.113.10:45393".to_string())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the current-identity fresh signal must apply");
    handle.abort();
}

#[tokio::test]
async fn direct_validation_registry_single_flight_merges_newest_endpoint() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    for (node_id, virtual_ip) in [("node-b", "10.20.0.2"), ("node-c", "10.20.0.3")] {
        peers
            .add_peer(&control::PeerInfo {
                node_id: node_id.to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: String::new(),
                endpoint: String::new(),
                nat_type: "Unknown".to_string(),
                virtual_ip: virtual_ip.to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
    }
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let first_endpoint: SocketAddr = "127.0.0.1:41001".parse().unwrap();
    let newest_endpoint: SocketAddr = "127.0.0.1:41002".parse().unwrap();

    let first = udp
        .begin_or_merge_direct_validation("node-b", first_endpoint, 0)
        .await;
    let owner_token = match first {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        crate::udp::DirectValidationSessionStart::Merged => {
            panic!("the first observation must receive the worker lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
            panic!("the current generation must receive the worker lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredInactive => {
            panic!("an active non-Direct peer must receive the worker lease")
        }
    };
    // Register an expectation while the first endpoint is still the active
    // target, then publish a fresher observation while that request is in
    // flight.  The ACK for the request already sent to `first_endpoint` must
    // remain consumable.
    assert!(udp
        .expect_direct_validation_ack_owned(
            "node-b",
            0x4201,
            0,
            owner_token,
            first_endpoint,
        )
        .await);
    assert!(matches!(
        udp.begin_or_merge_direct_validation("node-b", newest_endpoint, 0)
            .await,
        crate::udp::DirectValidationSessionStart::Merged
    ));

    let target = udp
        .direct_validation_target("node-b")
        .await
        .expect("the first session must remain active");
    assert_eq!(target.owner_token, owner_token);
    assert_eq!(target.generation, 0);
    assert_eq!(target.endpoint, newest_endpoint);
    assert!(!target.cancelled);

    // Candidate refresh may replace the next target without revoking a
    // request that has already left this daemon. The exact
    // request/owner/generation/endpoint tuple remains valid until its ACK,
    // timeout, or lifecycle cancellation.
    assert!(udp
        .consume_direct_validation_ack(
            "node-b",
            0x4201,
            0,
            owner_token,
            0,
            first_endpoint,
            None,
            false,
        )
        .await
        .is_some());

    assert!(udp
        .finish_direct_validation_session("node-b", owner_token)
        .await);
    assert!(udp.direct_validation_target("node-b").await.is_none());

    let concurrent_spawns = (0..32u16)
        .map(|offset| {
            let udp = udp.clone();
            tokio::spawn(async move {
                matches!(
                    udp.begin_or_merge_direct_validation(
                        "node-c",
                        SocketAddr::from(([127, 0, 0, 1], 41_100u16 + offset)),
                        0,
                    )
                    .await,
                    crate::udp::DirectValidationSessionStart::Spawn(_)
                )
            })
        })
        .collect::<Vec<_>>();
    let mut spawn_count = 0usize;
    for task in concurrent_spawns {
        if task.await.unwrap() {
            spawn_count += 1;
        }
    }
    assert_eq!(
        spawn_count, 1,
        "concurrent observations may receive only one worker lease per peer/generation"
    );
}

#[tokio::test]
async fn finishing_direct_validation_session_cancels_worker_receiver() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers)
        .await
        .unwrap();
    let endpoint: SocketAddr = "127.0.0.1:43011".parse().unwrap();
    let lease = match udp
        .begin_or_merge_direct_validation("node-b", endpoint, 0)
        .await
    {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease,
        crate::udp::DirectValidationSessionStart::Merged => {
            panic!("the first observation must receive the worker lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
            panic!("the current generation must receive the worker lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredInactive => {
            panic!("an active non-Direct peer must receive the worker lease")
        }
    };
    let target_rx = lease.target_rx;
    assert!(!target_rx.borrow().cancelled);

    assert!(udp
        .finish_direct_validation_session("node-b", lease.owner_token)
        .await);
    assert!(
        target_rx.borrow().cancelled,
        "finishing the owner must wake the worker's watch receiver with terminal cancellation"
    );
    assert!(
        udp.direct_validation_target("node-b").await.is_none(),
        "the completed owner must be removed from the registry"
    );
}

#[tokio::test]
async fn slow_relay_validation_cooldown_blocks_replacement_until_generation_changes() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
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
    let endpoint: SocketAddr = "127.0.0.1:43012".parse().unwrap();
    let owner_token = match udp
        .begin_or_merge_direct_validation("node-b", endpoint, 0)
        .await
    {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        crate::udp::DirectValidationSessionStart::Merged => {
            panic!("the first observation must receive the worker lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
            panic!("the current generation must receive the worker lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredInactive => {
            panic!("an active non-Direct peer must receive the worker lease")
        }
    };

    udp.suppress_direct_validation_for_slow_relay("node-b", 0)
        .await;
    assert!(
        udp.direct_validation_suppressed_by_slow_relay("node-b", 0)
            .await,
        "a slow ACK behind a confirmed relay must suppress replacement owners"
    );
    assert!(udp
        .finish_direct_validation_session("node-b", owner_token)
        .await);
    assert!(matches!(
        udp.begin_or_merge_direct_validation("node-b", endpoint, 0)
            .await,
        crate::udp::DirectValidationSessionStart::IgnoredInactive
    ));

    assert_eq!(
        peers
            .advance_network_generation("clear slow relay validation cooldown")
            .await,
        1
    );
    let next = udp.begin_or_merge_direct_validation("node-b", endpoint, 1).await;
    assert!(
        matches!(next, crate::udp::DirectValidationSessionStart::Spawn(_)),
        "a new network generation must be able to restart relay-first Direct validation"
    );
}

#[tokio::test]
async fn direct_validation_owner_cleanup_cannot_remove_newer_expectation() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
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
    let first_endpoint: SocketAddr = "127.0.0.1:42001".parse().unwrap();
    let newest_endpoint: SocketAddr = "127.0.0.1:42002".parse().unwrap();

    let first_owner = match udp
        .begin_or_merge_direct_validation("node-b", first_endpoint, 0)
        .await
    {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        crate::udp::DirectValidationSessionStart::Merged => panic!("unexpected merged first lease"),
        crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
            panic!("unexpected stale first lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredInactive => {
            panic!("unexpected inactive first lease")
        }
    };
    assert!(udp
        .expect_direct_validation_ack_owned("node-b", 11, 0, first_owner, first_endpoint)
        .await);

    assert_eq!(
        peers
            .advance_network_generation("replace validation owner")
            .await,
        1
    );

    let newest_owner = match udp
        .begin_or_merge_direct_validation("node-b", newest_endpoint, 1)
        .await
    {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        crate::udp::DirectValidationSessionStart::Merged => {
            panic!("a new generation must replace the old validation owner")
        }
        crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
            panic!("the advanced current generation must receive a lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredInactive => {
            panic!("the advanced active peer must receive a lease")
        }
    };
    assert_ne!(first_owner, newest_owner);
    assert!(udp
        .expect_direct_validation_ack_owned("node-b", 12, 1, newest_owner, newest_endpoint)
        .await);

    assert!(
        !udp.clear_direct_validation_expectation_if_owned("node-b", first_owner)
            .await,
        "old worker cleanup must not remove the newer owner's expectation"
    );
    assert!(udp.has_direct_validation_expectation("node-b").await);
    assert!(udp
        .clear_direct_validation_expectation_if_owned("node-b", newest_owner)
        .await);
    assert!(!udp.has_direct_validation_expectation("node-b").await);
}

#[tokio::test]
async fn network_generation_advance_cancels_old_validation_registry_owner() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
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
    let endpoint: SocketAddr = "127.0.0.1:43001".parse().unwrap();
    let owner_token = match udp
        .begin_or_merge_direct_validation("node-b", endpoint, 0)
        .await
    {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
        crate::udp::DirectValidationSessionStart::Merged => panic!("unexpected merged first lease"),
        crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
            panic!("unexpected stale first lease")
        }
        crate::udp::DirectValidationSessionStart::IgnoredInactive => {
            panic!("unexpected inactive first lease")
        }
    };
    assert!(udp
        .expect_direct_validation_ack_owned("node-b", 23, 0, owner_token, endpoint)
        .await);

    assert_eq!(peers.advance_network_generation("test validation registry").await, 1);
    assert!(
        udp.direct_validation_target("node-b").await.is_none(),
        "advance must remove every old-generation worker owner"
    );
    assert!(
        !udp.has_direct_validation_expectation("node-b").await,
        "advance must clear old-generation ACK expectations with the owner"
    );
}

#[tokio::test]
async fn direct_validation_ingress_coalesces_to_the_newest_endpoint() {
    let ingress = DirectValidationIngress::new();
    let first: SocketAddr = "127.0.0.1:44001".parse().unwrap();
    let newest: SocketAddr = "127.0.0.1:44099".parse().unwrap();

    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: first,
    });
    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: newest,
    });

    assert_eq!(
        ingress.pending_len(),
        1,
        "endpoint churn for one peer must use one coalesced ingress slot"
    );
    assert_eq!(
        ingress.next().await.observed_endpoint,
        newest,
        "the scheduler must receive the newest endpoint rather than an arbitrary stale queue entry"
    );
}

#[tokio::test]
async fn direct_validation_ingress_skips_replaced_peer_and_preserves_fifo() {
    let ingress = DirectValidationIngress::new();

    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: "127.0.0.1:44101".parse().unwrap(),
    });
    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-c".to_string(),
        observed_endpoint: "127.0.0.1:44102".parse().unwrap(),
    });
    // This replacement leaves the original node-b order key stale only when
    // the scheduler has already taken node-b for lease handoff.  Exercise
    // that exact shape directly through the test-only helper.
    assert_eq!(
        ingress.take_latest_for_peer("node-b").unwrap().observed_endpoint,
        "127.0.0.1:44101".parse::<SocketAddr>().unwrap()
    );

    assert_eq!(
        ingress.next().await.observed_endpoint,
        "127.0.0.1:44102".parse::<SocketAddr>().unwrap(),
        "a stale order key must not hide the next peer"
    );

    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: "127.0.0.1:44199".parse().unwrap(),
    });
    assert_eq!(
        ingress.next().await.observed_endpoint,
        "127.0.0.1:44199".parse::<SocketAddr>().unwrap(),
        "a replaced peer must re-enter FIFO after its previous handoff"
    );
}

#[tokio::test]
async fn direct_validation_scheduler_enforces_global_worker_cap() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    for (node_id, virtual_ip) in [("node-b", "10.20.0.2"), ("node-c", "10.20.0.3")] {
        peers
            .add_peer(&control::PeerInfo {
                node_id: node_id.to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: String::new(),
                endpoint: String::new(),
                nat_type: "Unknown".to_string(),
                virtual_ip: virtual_ip.to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
    }
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (wireguard, _encrypted_rx) = WireGuardTransport::new();
    let ingress = DirectValidationIngress::new();
    let scheduler = tokio::spawn(run_direct_validation_scheduler_with_worker_limit(
        ingress.clone(),
        udp.clone(),
        peers.clone(),
        wireguard,
        "10.20.0.1".to_string(),
        1,
    ));

    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: "127.0.0.1:45001".parse().unwrap(),
    });
    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-c".to_string(),
        observed_endpoint: "127.0.0.1:45002".parse().unwrap(),
    });

    timeout(Duration::from_secs(2), async {
        loop {
            let sessions = usize::from(udp.direct_validation_target("node-b").await.is_some())
                + usize::from(udp.direct_validation_target("node-c").await.is_some());
            let started = peers
                .diagnostics()
                .await
                .iter()
                .flat_map(|peer| peer.direct_events.iter())
                .filter(|event| event.stage == "encrypted_trial_started")
                .count();
            if sessions == 2 && started == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both leases must be retained while exactly one capped worker starts");

    let sessions = usize::from(udp.direct_validation_target("node-b").await.is_some())
        + usize::from(udp.direct_validation_target("node-c").await.is_some());
    assert_eq!(
        sessions, 2,
        "the unstarted peer must retain its owner/target instead of losing its only observation"
    );
    let started = peers
        .diagnostics()
        .await
        .iter()
        .flat_map(|peer| peer.direct_events.iter())
        .filter(|event| event.stage == "encrypted_trial_started")
        .count();
    assert_eq!(started, 1, "the global validation worker cap must be hard");

    udp.cancel_all_direct_validation_sessions().await;
    scheduler.abort();
    let _ = scheduler.await;
}

/// UDP rebinding replaces the scheduler before an old validation worker can
/// necessarily reach its next cancellation poll. The capacity must be shared
/// across both transport instances: the replacement may retain its lease, but
/// it cannot start a second worker until the retired scheduler has cancelled
/// and joined its first one.
#[tokio::test]
async fn direct_validation_worker_cap_survives_udp_transport_replacement() {
    let old_peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    old_peers
        .add_peer(&control::PeerInfo {
            node_id: "node-old".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;
    let replacement_peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    replacement_peers
        .add_peer(&control::PeerInfo {
            node_id: "node-new".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.3".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        })
        .await;

    // These are distinct UDP transports just as they are before and after a
    // bind replacement. Separate peer managers keep the retired registry
    // alive long enough to deterministically model an old worker unwinding;
    // the asserted invariant is the one production scheduler pool shares.
    let old_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), old_peers.clone())
        .await
        .unwrap();
    let replacement_udp = UdpTransport::bind(
        "127.0.0.1:0".parse().unwrap(),
        replacement_peers.clone(),
    )
    .await
    .unwrap();
    let (old_wireguard, _old_encrypted_rx) = WireGuardTransport::new();
    let (replacement_wireguard, _replacement_encrypted_rx) = WireGuardTransport::new();
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let old_ingress = DirectValidationIngress::new();
    let replacement_ingress = DirectValidationIngress::new();
    let old_scheduler = tokio::spawn(run_direct_validation_scheduler_with_worker_permits(
        old_ingress.clone(),
        old_udp.clone(),
        old_peers.clone(),
        old_wireguard,
        "10.20.0.1".to_string(),
        permits.clone(),
    ));

    old_ingress.submit(PeerReflexiveObservation {
        peer_id: "node-old".to_string(),
        observed_endpoint: "127.0.0.1:46001".parse().unwrap(),
    });
    timeout(Duration::from_secs(2), async {
        loop {
            let old_started = old_peers
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == "node-old")
                .is_some_and(|peer| {
                    peer.direct_events
                        .iter()
                        .any(|event| event.stage == "encrypted_trial_started")
                });
            if old_started {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the retired transport must have one live validation worker");

    let replacement_scheduler = tokio::spawn(run_direct_validation_scheduler_with_worker_permits(
        replacement_ingress.clone(),
        replacement_udp.clone(),
        replacement_peers.clone(),
        replacement_wireguard,
        "10.20.0.1".to_string(),
        permits.clone(),
    ));
    replacement_ingress.submit(PeerReflexiveObservation {
        peer_id: "node-new".to_string(),
        observed_endpoint: "127.0.0.1:46002".parse().unwrap(),
    });

    timeout(Duration::from_secs(2), async {
        loop {
            let replacement_started = replacement_peers
                .diagnostics()
                .await
                .iter()
                .flat_map(|peer| peer.direct_events.iter())
                .filter(|event| event.stage == "encrypted_trial_started")
                .count();
            if replacement_udp
                .direct_validation_target("node-new")
                .await
                .is_some()
                && replacement_started == 0
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the replacement lease must queue behind the retired worker");
    assert_eq!(
        permits.available_permits(),
        0,
        "the retired scheduler's worker must still account against the shared daemon cap"
    );

    // This is the real replacement teardown order: revoke all old owners and
    // then stop the retired scheduler. Dropping its JoinSet aborts/reaps any
    // child that has not yet noticed the cancellation, releasing the shared
    // permit before the replacement can start.
    old_udp.cancel_all_direct_validation_sessions().await;
    old_scheduler.abort();
    let _ = old_scheduler.await;

    timeout(Duration::from_secs(2), async {
        loop {
            let replacement_started = replacement_peers
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == "node-new")
                .is_some_and(|peer| {
                    peer.direct_events
                        .iter()
                        .any(|event| event.stage == "encrypted_trial_started")
                });
            if replacement_started {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the replacement worker must start after retired scheduler teardown releases its permit");

    replacement_udp.cancel_all_direct_validation_sessions().await;
    replacement_scheduler.abort();
    let _ = replacement_scheduler.await;
}

#[tokio::test]
async fn direct_validation_scheduler_merges_queued_endpoint_and_starts_after_permit_release() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    for (node_id, virtual_ip) in [("node-b", "10.20.0.2"), ("node-c", "10.20.0.3")] {
        peers
            .add_peer(&control::PeerInfo {
                node_id: node_id.to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: String::new(),
                endpoint: String::new(),
                nat_type: "Unknown".to_string(),
                virtual_ip: virtual_ip.to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;
    }
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let (wireguard, _encrypted_rx) = WireGuardTransport::new();
    let ingress = DirectValidationIngress::new();
    let scheduler = tokio::spawn(run_direct_validation_scheduler_with_worker_limit(
        ingress.clone(),
        udp.clone(),
        peers.clone(),
        wireguard,
        "10.20.0.1".to_string(),
        1,
    ));

    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-b".to_string(),
        observed_endpoint: "127.0.0.1:45101".parse().unwrap(),
    });
    ingress.submit(PeerReflexiveObservation {
        peer_id: "node-c".to_string(),
        observed_endpoint: "127.0.0.1:45102".parse().unwrap(),
    });

    let started_peer = timeout(Duration::from_secs(2), async {
        loop {
            let diagnostics = peers.diagnostics().await;
            let started: Vec<_> = diagnostics
                .iter()
                .filter(|peer| {
                    peer.direct_events
                        .iter()
                        .any(|event| event.stage == "encrypted_trial_started")
                })
                .map(|peer| peer.node_id.clone())
                .collect();
            if started.len() == 1
                && udp.direct_validation_target("node-b").await.is_some()
                && udp.direct_validation_target("node-c").await.is_some()
            {
                break started[0].clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("one worker must start while the other lease remains queued");
    let queued_peer = if started_peer == "node-b" {
        "node-c"
    } else {
        "node-b"
    };
    let newest_endpoint: SocketAddr = if queued_peer == "node-b" {
        "127.0.0.1:45199".parse().unwrap()
    } else {
        "127.0.0.1:45299".parse().unwrap()
    };
    ingress.submit(PeerReflexiveObservation {
        peer_id: queued_peer.to_string(),
        observed_endpoint: newest_endpoint,
    });

    timeout(Duration::from_secs(2), async {
        loop {
            if udp
                .direct_validation_target(queued_peer)
                .await
                .is_some_and(|target| target.endpoint == newest_endpoint)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a queued lease must merge the newest endpoint without waiting for a permit");
    let started_before_release = peers
        .diagnostics()
        .await
        .iter()
        .flat_map(|peer| peer.direct_events.iter())
        .filter(|event| event.stage == "encrypted_trial_started")
        .count();
    assert_eq!(
        started_before_release, 1,
        "merging a queued endpoint must not spawn a second worker above the cap"
    );

    peers
        .cancel_active_direct_validation_for_peer(&started_peer)
        .await;
    timeout(Duration::from_secs(2), async {
        loop {
            let queued_started = peers
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == queued_peer)
                .is_some_and(|peer| {
                    peer.direct_events
                        .iter()
                        .any(|event| event.stage == "encrypted_trial_started")
                });
            if queued_started {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("queued validation lease must start once the capped worker releases its permit");

    udp.cancel_all_direct_validation_sessions().await;
    scheduler.abort();
    let _ = scheduler.await;
}

#[tokio::test]
async fn peer_reflexive_worker_cap_retains_coalesced_peers() {
    let slots: PeerReflexiveSignalSlots = Arc::new(Mutex::new(HashMap::new()));
    let first_endpoint: SocketAddr = "127.0.0.1:45301".parse().unwrap();
    let newest_endpoint: SocketAddr = "127.0.0.1:45399".parse().unwrap();
    assert!(
        enqueue_peer_reflexive_signal_observation(
            &slots,
            PeerReflexiveObservation {
                peer_id: "node-b".to_string(),
                observed_endpoint: first_endpoint,
            },
        )
        .await
    );
    assert!(
        enqueue_peer_reflexive_signal_observation(
            &slots,
            PeerReflexiveObservation {
                peer_id: "node-b".to_string(),
                observed_endpoint: newest_endpoint,
            },
        )
        .await
    );
    assert!(
        enqueue_peer_reflexive_signal_observation(
            &slots,
            PeerReflexiveObservation {
                peer_id: "node-c".to_string(),
                observed_endpoint: "127.0.0.1:45401".parse().unwrap(),
            },
        )
        .await
    );

    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let (first_peer, first_permit) = claim_pending_peer_reflexive_signal_worker(&slots, &permits)
        .await
        .expect("one worker must claim the first pending peer");
    let queued_peer = if first_peer == "node-b" {
        "node-c"
    } else {
        "node-b"
    };
    assert!(
        claim_pending_peer_reflexive_signal_worker(&slots, &permits)
            .await
            .is_none(),
        "the semaphore must prevent a second peer worker while the first permit is held"
    );
    {
        let slots_guard = slots.lock().await;
        assert_eq!(
            slots_guard
                .get("node-b")
                .and_then(|slot| slot.latest.as_ref())
                .map(|observation| observation.observed_endpoint),
            Some(newest_endpoint),
            "same-peer endpoint churn must retain newest-wins state"
        );
        assert!(
            slots_guard
                .get(queued_peer)
                .is_some_and(|slot| !slot.active && slot.latest.is_some()),
            "a peer that could not claim a permit must remain queued"
        );
    }

    // Model the first worker consuming its slot and releasing its permit;
    // the scheduler's completion path performs this transition in the real
    // loop before it calls the claim helper again.
    {
        let mut slots_guard = slots.lock().await;
        let first_slot = slots_guard
            .get_mut(&first_peer)
            .expect("claimed peer slot must remain present");
        first_slot.latest = None;
        first_slot.active = false;
    }
    drop(first_permit);
    let (next_peer, next_permit) = claim_pending_peer_reflexive_signal_worker(&slots, &permits)
        .await
        .expect("queued peer must claim the permit after the first worker exits");
    assert_eq!(next_peer, queued_peer);
    drop(next_permit);
}

/// A UDP replacement may be published while a retired peer-reflexive worker
/// still owns the last daemon-wide permit. The replacement must remain
/// queued below that same cap, then wake and claim capacity as soon as the
/// retired worker releases it without requiring another endpoint observation.
#[tokio::test]
async fn peer_reflexive_worker_cap_survives_udp_transport_replacement() {
    let permits = Arc::new(tokio::sync::Semaphore::new(1));
    let retired_slots: PeerReflexiveSignalSlots = Arc::new(Mutex::new(HashMap::new()));
    enqueue_peer_reflexive_signal_observation(
        &retired_slots,
        PeerReflexiveObservation {
            peer_id: "node-retired".to_string(),
            observed_endpoint: "127.0.0.1:45451".parse().unwrap(),
        },
    )
    .await;
    let (retired_peer, retired_permit) =
        claim_pending_peer_reflexive_signal_worker(&retired_slots, &permits)
            .await
            .expect("the retired UDP instance must claim the only worker permit");
    assert_eq!(retired_peer, "node-retired");

    let replacement_slots: PeerReflexiveSignalSlots = Arc::new(Mutex::new(HashMap::new()));
    enqueue_peer_reflexive_signal_observation(
        &replacement_slots,
        PeerReflexiveObservation {
            peer_id: "node-replacement".to_string(),
            observed_endpoint: "127.0.0.1:45452".parse().unwrap(),
        },
    )
    .await;
    let replacement_work = Arc::new(tokio::sync::Notify::new());
    let replacement_wait = wait_for_pending_peer_reflexive_signal_worker(
        &replacement_slots,
        &replacement_work,
        &permits,
    );
    tokio::pin!(replacement_wait);

    assert!(
        timeout(Duration::from_millis(100), replacement_wait.as_mut())
            .await
            .is_err(),
        "the replacement instance must not exceed the retired instance's worker cap"
    );
    assert_eq!(permits.available_permits(), 0);

    drop(retired_permit);
    let (replacement_peer, replacement_permit) =
        timeout(Duration::from_secs(1), replacement_wait.as_mut())
            .await
            .expect("the replacement waiter must wake when the retired permit is released")
            .expect("the replacement endpoint must still be queued");
    assert_eq!(replacement_peer, "node-replacement");
    drop(replacement_permit);
}

#[tokio::test]
async fn peer_reflexive_slot_keeps_newest_endpoint_during_rate_limit_backoff() {
    let slots: PeerReflexiveSignalSlots = Arc::new(Mutex::new(HashMap::new()));
    let old_endpoint: SocketAddr = "127.0.0.1:45501".parse().unwrap();
    let newest_endpoint: SocketAddr = "127.0.0.1:45599".parse().unwrap();
    enqueue_peer_reflexive_signal_observation(
        &slots,
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint: old_endpoint,
        },
    )
    .await;
    let now = Instant::now();
    let (next_signal_at, next_backoff) = peer_reflexive_rate_limit_window(Duration::ZERO, now);
    {
        let mut slots_guard = slots.lock().await;
        let slot = slots_guard.get_mut("node-b").unwrap();
        slot.active = false;
        slot.latest = None;
        slot.next_signal_at = Some(next_signal_at);
        slot.rate_limit_backoff = next_backoff;
    }
    enqueue_peer_reflexive_signal_observation(
        &slots,
        PeerReflexiveObservation {
            peer_id: "node-b".to_string(),
            observed_endpoint: newest_endpoint,
        },
    )
    .await;
    let slots_guard = slots.lock().await;
    let slot = slots_guard.get("node-b").unwrap();
    assert_eq!(
        slot.latest
            .as_ref()
            .map(|observation| observation.observed_endpoint),
        Some(newest_endpoint)
    );
    assert_eq!(slot.rate_limit_backoff, PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL * 2);
    assert!(slot.next_signal_at.is_some_and(|next| next > now));
}

#[test]
fn peer_reflexive_rate_limit_backoff_doubles_and_caps() {
    let now = Instant::now();
    let (first_retry, first_next) = peer_reflexive_rate_limit_window(Duration::ZERO, now);
    assert_eq!(
        first_retry.duration_since(now),
        PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL
    );
    assert_eq!(
        first_next,
        PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL * 2
    );
    let (_, capped_next) =
        peer_reflexive_rate_limit_window(PEER_REFLEXIVE_SIGNAL_BACKOFF_MAX, now);
    assert_eq!(capped_next, PEER_REFLEXIVE_SIGNAL_BACKOFF_MAX);
}

#[tokio::test]
async fn withdrawn_validation_registry_rejects_late_scheduler_observation() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&control::PeerInfo {
            node_id: "node-b".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: String::new(),
            endpoint: String::new(),
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
    udp.cancel_all_direct_validation_sessions().await;

    assert!(matches!(
        udp.begin_or_merge_direct_validation(
            "node-b",
            "127.0.0.1:46001".parse().unwrap(),
            peers.current_network_generation().await,
        )
        .await,
        crate::udp::DirectValidationSessionStart::IgnoredInactive
    ));
}
