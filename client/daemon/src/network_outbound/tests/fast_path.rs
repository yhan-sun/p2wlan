use super::super::test_support::*;
use super::*;
use crate::config::Config;

#[tokio::test]
async fn lan_direct_snapshot_is_generation_and_commit_bound() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let endpoint: SocketAddr = "192.168.2.11:51850".parse().unwrap();
    let local: SocketAddr = "192.168.2.10:51820".parse().unwrap();
    manager.add_peer(&test_peer("peer-lan", endpoint)).await;
    manager
        .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
            "192.168.2.10".parse().unwrap(),
            24,
        )])
        .await;
    manager
        .add_candidates_with_sources(
            "peer-lan",
            &[endpoint.to_string()],
            &std::collections::HashMap::from([(endpoint.to_string(), "host".to_string())]),
        )
        .await;
    manager
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer-lan",
            endpoint,
            Some(Duration::from_millis(2)),
            Some(local),
        )
        .await;
    manager
        .record_direct_success_with_local_endpoint("peer-lan", Some(endpoint), Some(local))
        .await;

    let generation = manager.current_network_generation_sync();
    let snapshot = manager
        .active_direct_path_snapshot("peer-lan", generation, true)
        .await
        .expect("healthy on-link Direct should publish a fast-path snapshot");
    assert_eq!(snapshot.path, NetworkPath::Direct);
    assert_eq!(snapshot.endpoint, endpoint);
    assert!(manager.active_direct_path_snapshot_is_current_sync("peer-lan", snapshot));

    manager
        .advance_network_generation("fast-path-generation-fence")
        .await;
    assert!(!manager.active_direct_path_snapshot_is_current_sync("peer-lan", snapshot));
}

#[tokio::test]
async fn public_direct_does_not_enter_lan_fast_path() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let endpoint: SocketAddr = "198.51.100.50:51850".parse().unwrap();
    manager.add_peer(&test_peer("peer-public", endpoint)).await;
    manager
        .record_direct_probe_success_with_latency(
            "peer-public",
            endpoint,
            Some(Duration::from_millis(8)),
        )
        .await;
    manager
        .record_direct_success("peer-public", Some(endpoint))
        .await;

    let generation = manager.current_network_generation_sync();
    assert!(
        manager
            .active_direct_path_snapshot("peer-public", generation, true)
            .await
            .is_none(),
        "Public Direct remains on the existing selector path"
    );
}

#[tokio::test]
async fn lan_direct_fast_path_sends_with_cached_session_and_socket() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    let local_network = p2pnet_nat::LocalNetwork::new("127.0.0.1".parse().unwrap(), 8);
    peers.add_peer(&test_peer("peer-fast", endpoint)).await;
    peers
        .set_local_interface_networks(vec![local_network])
        .await;
    peers
        .add_candidates_with_sources(
            "peer-fast",
            &[endpoint.to_string()],
            &std::collections::HashMap::from([(endpoint.to_string(), "host".to_string())]),
        )
        .await;
    let local_transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        !local_transport.peer_requires_direct_business_budget("peer-fast"),
        "legacy peers must remain unmanaged and use the existing Direct fast path"
    );
    let local_endpoint = local_transport.local_addr().unwrap();
    peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer-fast",
            endpoint,
            Some(Duration::from_millis(1)),
            Some(local_endpoint),
        )
        .await;
    peers
        .record_direct_success_with_local_endpoint(
            "peer-fast",
            Some(endpoint),
            Some(local_endpoint),
        )
        .await;

    let (transport, _outbound_rx) = WireGuardTransport::new();
    let (local_session, _remote_session) = establish_sessions();
    transport.add_session("peer-fast", local_session).await;
    let (_, socket) = local_transport
        .socket_for_peer_endpoint(Some("peer-fast"), Some(endpoint))
        .await
        .unwrap();
    socket.writable().await.unwrap();
    let udp_transport = RwLock::new(Some(local_transport));
    let mut fast_paths = HashMap::new();
    let mut ineligible = HashMap::new();
    let counters_before = global_dataplane_profiler().fast_path_counters();
    let attempt = try_lan_direct_fast_path(
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-fast".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![0x45, 0, 0, 20],
            trace: None,
        },
        &transport,
        &peers,
        true,
        &udp_transport,
        &mut fast_paths,
        &mut ineligible,
    );
    assert!(matches!(attempt, FastPathAttempt::Sent));
    assert_eq!(fast_paths.len(), 1);
    let counters_after_send = global_dataplane_profiler().fast_path_counters();
    assert!(counters_after_send.hits > counters_before.hits);
    assert!(counters_after_send.misses > counters_before.misses);

    let mut received = [0u8; 2048];
    let (received_len, source) =
        tokio::time::timeout(Duration::from_secs(1), receiver.recv_from(&mut received))
            .await
            .expect("LAN Direct fast path must hand the ciphertext to the exact socket")
            .unwrap();
    assert!(received_len > 0);
    assert_eq!(source.ip(), local_endpoint.ip());

    let (replacement_session, _replacement_remote) = establish_sessions();
    transport
        .replace_session("peer-fast", replacement_session)
        .await;
    let stale_session_attempt = try_lan_direct_fast_path(
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-fast".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![0x45, 0, 0, 20],
            trace: None,
        },
        &transport,
        &peers,
        true,
        &udp_transport,
        &mut fast_paths,
        &mut ineligible,
    );
    assert!(matches!(
        stale_session_attempt,
        FastPathAttempt::Fallback(_)
    ));
    assert!(fast_paths.is_empty());
    assert!(
        global_dataplane_profiler().fast_path_counters().invalidated
            > counters_after_send.invalidated
    );
}

struct LanWorkerFixture {
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    receiver_a: tokio::net::UdpSocket,
    receiver_b: tokio::net::UdpSocket,
    remote_a: p2pnet_wireguard::TransportSession,
    remote_b: p2pnet_wireguard::TransportSession,
    _relay_available_tx: watch::Sender<bool>,
    relay_available_rx: watch::Receiver<bool>,
}

impl LanWorkerFixture {
    async fn new() -> Self {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let receiver_a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let local_endpoint = udp.local_addr().unwrap();
        for (peer_id, receiver) in [("peer-a", &receiver_a), ("peer-b", &receiver_b)] {
            let endpoint = receiver.local_addr().unwrap();
            peers.add_peer(&test_peer(peer_id, endpoint)).await;
            // The manager copies this evidence into existing connections;
            // publish it after add_peer so each new connection is on-link.
            peers
                .set_local_interface_networks(vec![p2pnet_nat::LocalNetwork::new(
                    "127.0.0.1".parse().unwrap(),
                    8,
                )])
                .await;
            peers
                .add_candidates_with_sources(
                    peer_id,
                    &[endpoint.to_string()],
                    &HashMap::from([(endpoint.to_string(), "host".to_string())]),
                )
                .await;
            peers
                .record_direct_probe_success_with_latency_and_local_endpoint(
                    peer_id,
                    endpoint,
                    Some(Duration::from_millis(1)),
                    Some(local_endpoint),
                )
                .await;
            peers
                .record_direct_success_with_local_endpoint(
                    peer_id,
                    Some(endpoint),
                    Some(local_endpoint),
                )
                .await;
            assert!(!udp.peer_requires_direct_business_budget(peer_id));
            assert!(
                peers
                    .active_direct_path_snapshot(
                        peer_id,
                        peers.current_network_generation_sync(),
                        true,
                    )
                    .await
                    .is_some()
            );
        }
        let (transport, _unused_outbound_rx) = WireGuardTransport::new();
        let (local_a, remote_a) = establish_sessions();
        let (local_b, remote_b) = establish_sessions();
        transport.add_session("peer-a", local_a).await;
        transport.add_session("peer-b", local_b).await;
        let (_relay_available_tx, relay_available_rx) = watch::channel(false);
        Self {
            peers,
            transport,
            udp_transport: Arc::new(RwLock::new(Some(udp))),
            receiver_a,
            receiver_b,
            remote_a,
            remote_b,
            _relay_available_tx,
            relay_available_rx,
        }
    }

    fn spawn(&self) -> (mpsc::Sender<OutboundPacket>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(8);
        let (probe_kick_tx, _probe_kick_rx) = watch::channel(0u64);
        let worker = tokio::spawn(run_network_outbound(
            rx,
            self.transport.clone(),
            self.peers.clone(),
            true,
            self.udp_transport.clone(),
            Arc::new(RwLock::new(None)),
            self.relay_available_rx.clone(),
            RelayStartupWait {
                relay_expected: false,
                timeout: None,
            },
            probe_kick_tx,
            ConnectionTimeline::new("fast-path-isolation", 0),
        ));
        (tx, worker)
    }
}

fn isolated_packet(peer_id: &str, sequence: u8) -> OutboundPacket {
    OutboundPacket {
        room_authorization: None,
        peer_id: peer_id.to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: vec![0x45, 0, 0, sequence],
        trace: None,
    }
}

async fn receive_wire(
    receiver: &tokio::net::UdpSocket,
) -> std::result::Result<Vec<u8>, tokio::time::error::Elapsed> {
    timeout(Duration::from_secs(1), async {
        let mut bytes = [0u8; 2048];
        let (len, _) = receiver.recv_from(&mut bytes).await.unwrap();
        bytes[..len].to_vec()
    })
    .await
}

#[tokio::test]
async fn lan_fast_path_contended_peer_does_not_block_other_peer_and_preserves_fifo() {
    let mut fixture = LanWorkerFixture::new().await;
    // Hold an actual protocol-ordering guard before either packet enters the
    // shared actor. No scheduling delay or socket-buffer saturation is needed
    // to keep A blocked throughout B's complete physical handoff.
    let emit_a = fixture
        .transport
        .acquire_outbound_emit_guard("peer-a")
        .await;
    let (tx, mut worker) = fixture.spawn();
    tx.send(isolated_packet("peer-a", 1)).await.unwrap();
    tx.send(isolated_packet("peer-b", 9)).await.unwrap();
    tx.send(isolated_packet("peer-a", 2)).await.unwrap();
    let wire_b = receive_wire(&fixture.receiver_b).await;
    if wire_b.is_err() {
        worker.abort();
        let _ = (&mut worker).await;
    }
    let wire_b = wire_b.expect("peer B must send while peer A's emit guard is still held");
    assert_eq!(
        fixture.remote_b.decrypt_from_bytes(&wire_b).unwrap(),
        isolated_packet("peer-b", 9).packet,
    );
    assert!(fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err());

    drop(emit_a);
    let first = receive_wire(&fixture.receiver_a).await.unwrap();
    let second = receive_wire(&fixture.receiver_a).await.unwrap();
    assert_eq!(
        fixture.remote_a.decrypt_from_bytes(&first).unwrap(),
        isolated_packet("peer-a", 1).packet
    );
    assert_eq!(
        fixture.remote_a.decrypt_from_bytes(&second).unwrap(),
        isolated_packet("peer-a", 2).packet
    );
    assert!(
        crate::transport::wire_counter(&first).unwrap()
            < crate::transport::wire_counter(&second).unwrap()
    );
    drop(tx);
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(
        fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err(),
        "a deferred plaintext packet must never replay an earlier ciphertext"
    );
}

#[tokio::test]
async fn lan_fast_path_deferred_peer_is_cancelled_by_network_generation_change() {
    let fixture = LanWorkerFixture::new().await;
    let emit_a = fixture
        .transport
        .acquire_outbound_emit_guard("peer-a")
        .await;
    let (tx, mut worker) = fixture.spawn();
    tx.send(isolated_packet("peer-a", 1)).await.unwrap();
    tx.send(isolated_packet("peer-b", 9)).await.unwrap();
    let wire_b = receive_wire(&fixture.receiver_b).await;
    if wire_b.is_err() {
        worker.abort();
        let _ = (&mut worker).await;
    }
    wire_b.expect("peer B's handoff must prove A was deferred without blocking ingress");
    fixture
        .peers
        .advance_network_generation("deferred-fast-path-cancellation")
        .await;
    drop(emit_a);
    timeout(Duration::from_secs(1), async {
        loop {
            let loss = fixture.peers.outbound_loss_stats().await;
            if loss
                .drops
                .get(REASON_OUTBOUND_GENERATION_CHANGED)
                .is_some_and(|drop| drop.packets == 1)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the old-generation plaintext must terminate with a counted cancellation");
    drop(tx);
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(
        fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err(),
        "a generation-cancelled peer must never allocate or emit stale ciphertext"
    );
}

#[tokio::test]
async fn lan_fast_path_socket_backpressure_does_not_block_other_peer_or_replay_ciphertext() {
    let mut fixture = LanWorkerFixture::new().await;
    let udp = fixture.udp_transport.read().await.clone().unwrap();
    let mut attempts = udp.inject_udp_send_pending_for_test("peer-a");
    let (tx, mut worker) = fixture.spawn();
    tx.send(isolated_packet("peer-a", 1)).await.unwrap();
    timeout(Duration::from_secs(1), attempts.changed())
        .await
        .unwrap()
        .unwrap();
    assert!(
        *attempts.borrow() > 0,
        "A must reach the exact physical send seam"
    );
    tx.send(isolated_packet("peer-b", 9)).await.unwrap();
    tx.send(isolated_packet("peer-a", 2)).await.unwrap();
    let wire_b = receive_wire(&fixture.receiver_b).await;
    if wire_b.is_err() {
        worker.abort();
        let _ = (&mut worker).await;
    }
    let wire_b = wire_b.expect("B must send while A's socket remains backpressured");
    assert_eq!(
        fixture.remote_b.decrypt_from_bytes(&wire_b).unwrap(),
        isolated_packet("peer-b", 9).packet
    );
    assert!(fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err());
    udp.release_udp_send_pending_for_test("peer-a");
    let first = receive_wire(&fixture.receiver_a).await.unwrap();
    let second = receive_wire(&fixture.receiver_a).await.unwrap();
    assert_eq!(
        fixture.remote_a.decrypt_from_bytes(&first).unwrap(),
        isolated_packet("peer-a", 1).packet
    );
    assert_eq!(
        fixture.remote_a.decrypt_from_bytes(&second).unwrap(),
        isolated_packet("peer-a", 2).packet
    );
    assert!(
        crate::transport::wire_counter(&first).unwrap()
            < crate::transport::wire_counter(&second).unwrap()
    );
    drop(tx);
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err());
}

#[tokio::test]
async fn lan_fast_path_accepted_handoff_ignores_diagnostics_contention_without_replay() {
    let mut fixture = LanWorkerFixture::new().await;
    let udp = fixture.udp_transport.read().await.clone().unwrap();
    let diagnostics = udp.hold_primary_socket_diagnostics_for_test().await;
    let (tx, mut worker) = fixture.spawn();
    tx.send(isolated_packet("peer-a", 1)).await.unwrap();
    // A really crossed the UDP handoff boundary before B enters the actor.
    // Cancelling a pending post-send diagnostics future and re-parking A1
    // would therefore replay application plaintext and fail the FIFO checks.
    let first = receive_wire(&fixture.receiver_a).await.unwrap();
    assert_eq!(
        fixture.remote_a.decrypt_from_bytes(&first).unwrap(),
        isolated_packet("peer-a", 1).packet
    );
    tx.send(isolated_packet("peer-b", 9)).await.unwrap();
    tx.send(isolated_packet("peer-a", 2)).await.unwrap();
    let wire_b = receive_wire(&fixture.receiver_b).await;
    if wire_b.is_err() {
        worker.abort();
        let _ = (&mut worker).await;
    }
    wire_b.expect("B must send while accepted A1's diagnostics mutex remains held");
    drop(diagnostics);
    let second = receive_wire(&fixture.receiver_a).await.unwrap();
    assert_eq!(
        fixture.remote_a.decrypt_from_bytes(&second).unwrap(),
        isolated_packet("peer-a", 2).packet
    );
    assert!(
        crate::transport::wire_counter(&first).unwrap()
            < crate::transport::wire_counter(&second).unwrap()
    );
    drop(tx);
    timeout(Duration::from_secs(1), worker)
        .await
        .unwrap()
        .unwrap();
    assert!(
        fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err(),
        "A1 was already accepted and must never be re-encrypted or replayed"
    );
}

fn install_loss_sink(
    fixture: &LanWorkerFixture,
) -> Arc<tokio::sync::Mutex<crate::peer::OutboundLossCounters>> {
    let sink = Arc::new(tokio::sync::Mutex::new(
        crate::peer::OutboundLossCounters::default(),
    ));
    fixture.transport.set_outbound_loss_sink(Some(sink.clone()));
    fixture.peers.set_outbound_loss_sink(sink.clone());
    sink
}

#[tokio::test(start_paused = true)]
async fn lan_terminal_report_deadline_does_not_claim_blocked_accounting() {
    let fixture = LanWorkerFixture::new().await;
    let sink = install_loss_sink(&fixture);
    let held = sink.lock().await;
    let timeline = ConnectionTimeline::new("terminal-accounting-deadline", 0);
    let report = tokio::spawn({
        let transport = fixture.transport.clone();
        let peers = fixture.peers.clone();
        let timeline = timeline.clone();
        async move {
            super::super::queue::report_fast_path_terminal(
                &transport,
                &peers,
                "peer-a",
                peers.current_network_generation_sync(),
                4,
                REASON_OUTBOUND_ENCRYPT_FAILED,
                "test terminal".into(),
                &timeline,
                None,
            )
            .await;
        }
    });
    tokio::task::yield_now().await;
    assert!(!report.is_finished());
    tokio::time::advance(OUTBOUND_SEND_TIMEOUT).await;
    report.await.unwrap();
    assert!(held.drops.is_empty());
    let events = timeline.snapshot().events;
    assert!(events.iter().any(|event| event
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("accounting_complete=false")
            && detail.contains("phase=loss_accounting"))));
}

#[tokio::test(start_paused = true)]
async fn lan_terminal_report_counts_loss_before_bounded_health_wait() {
    let fixture = LanWorkerFixture::new().await;
    let sink = install_loss_sink(&fixture);
    let generation = fixture.peers.current_network_generation_sync();
    let path = fixture
        .peers
        .active_direct_path_snapshot("peer-a", generation, true)
        .await
        .unwrap();
    let epoch = fixture.peers.network_epoch_gate();
    let held = epoch.lock().await;
    let timeline = ConnectionTimeline::new("terminal-health-deadline", 0);
    let report = tokio::spawn({
        let transport = fixture.transport.clone();
        let peers = fixture.peers.clone();
        let timeline = timeline.clone();
        async move {
            super::super::queue::report_fast_path_terminal(
                &transport,
                &peers,
                "peer-a",
                generation,
                4,
                REASON_DIRECT_DELIVERY_UNCERTAIN,
                "test terminal".into(),
                &timeline,
                Some((path, None)),
            )
            .await;
        }
    });
    tokio::task::yield_now().await;
    assert_eq!(
        sink.lock().await.drops[REASON_DIRECT_DELIVERY_UNCERTAIN].packets,
        1
    );
    assert!(!report.is_finished());
    tokio::time::advance(OUTBOUND_SEND_TIMEOUT).await;
    report.await.unwrap();
    let events = timeline.snapshot().events;
    assert!(events.iter().any(|event| event
        .detail
        .as_deref()
        .is_some_and(|detail| detail.contains("accounting_complete=true")
            && detail.contains("phase=path_health"))));
    drop(held);
    assert!(fixture
        .peers
        .active_direct_path_snapshot_is_current_sync("peer-a", path));
}

#[tokio::test]
async fn lan_business_handoff_rejects_a_detached_dynamic_socket() {
    let fixture = LanWorkerFixture::new().await;
    let (inbound_tx, _inbound_rx) = mpsc::channel(8);
    let udp = fixture
        .udp_transport
        .read()
        .await
        .clone()
        .unwrap()
        .with_inbound_channel(inbound_tx);
    let generation = fixture.peers.current_network_generation_sync();
    let (index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
    let lease = udp
        .attach_dynamic_punch_socket("peer-a", index, socket.clone(), generation, 1, None)
        .await
        .unwrap();
    assert!(
        lease
            .commit_and_pin_for_test(&udp, "peer-a", index, generation, 1)
            .await
    );
    assert!(lease.finalize().await);
    socket.writable().await.unwrap();
    let endpoint = fixture.receiver_a.local_addr().unwrap();
    let encrypted = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![4, 0, 1, 2],
        is_business: true,
    };
    let epoch = fixture.peers.network_epoch_gate();
    let held = epoch.lock().await;
    assert!(udp
        .try_send_lan_business_packet_on_socket(
            &socket,
            index,
            &encrypted,
            endpoint,
            udp.inbound_publication_owner()
        )
        .is_ok());
    drop(held);
    assert_eq!(
        receive_wire(&fixture.receiver_a).await.unwrap(),
        encrypted.wire_bytes
    );
    udp.detach_dynamic_socket_by_index(index, "test-retained-business-arc")
        .await;
    let held = epoch.lock().await;
    assert!(matches!(
        udp.try_send_lan_business_packet_on_socket(
            &socket,
            index,
            &encrypted,
            endpoint,
            udp.inbound_publication_owner()
        ),
        Err(DirectBusinessUdpSendError::StaleToken)
    ));
    drop(held);
    assert!(fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err());
}

#[tokio::test]
async fn lan_business_publication_contention_returns_known_not_sent() {
    let fixture = LanWorkerFixture::new().await;
    let udp = fixture.udp_transport.read().await.clone().unwrap();
    let endpoint = fixture.receiver_a.local_addr().unwrap();
    let (index, socket) = udp
        .socket_for_peer_endpoint(Some("peer-a"), Some(endpoint))
        .await
        .unwrap();
    socket.writable().await.unwrap();
    let encrypted = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.2".into(),
        wire_bytes: vec![4, 0, 1, 2],
        is_business: true,
    };
    let runtime = udp.dplpmtud_runtime();
    runtime.with_business_publication_gate(|| {
        assert!(matches!(
            udp.try_send_lan_business_packet_on_socket(
                &socket,
                index,
                &encrypted,
                endpoint,
                udp.inbound_publication_owner()
            ),
            Err(DirectBusinessUdpSendError::WouldBlock)
        ));
    });
    assert!(fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err());
}

#[tokio::test]
async fn lan_fast_path_emsgsize_reports_local_mtu_without_degrading_direct() {
    let fixture = LanWorkerFixture::new().await;
    let udp = fixture.udp_transport.read().await.clone().unwrap();
    let endpoint = fixture.receiver_a.local_addr().unwrap();
    let (_, socket) = udp
        .socket_for_peer_endpoint(Some("peer-a"), Some(endpoint))
        .await
        .unwrap();
    socket.writable().await.unwrap();
    let generation = fixture.peers.current_network_generation_sync();
    let path = fixture
        .peers
        .active_direct_path_snapshot("peer-a", generation, true)
        .await
        .unwrap();
    let mut feedback_rx = fixture.peers.subscribe_local_mtu_feedback();
    let mut packet = isolated_packet("peer-a", 1);
    packet.packet = Ipv4Packet::build_icmp_echo_request(
        "10.20.0.1".parse().unwrap(),
        "10.20.0.2".parse().unwrap(),
        1,
        1,
        &[7; 128],
    );
    let expected_mtu = (packet.packet.len() - 1) as u16;
    udp.inject_direct_business_emsgsize_once_for_test();
    let outcome = try_lan_direct_fast_path(
        packet,
        &fixture.transport,
        &fixture.peers,
        true,
        &fixture.udp_transport,
        &mut HashMap::new(),
        &mut HashMap::new(),
    );
    assert!(matches!(
        outcome,
        FastPathAttempt::Terminal {
            reason_code: REASON_DIRECT_BUSINESS_EMSGSIZE,
            ..
        }
    ));
    let feedback = feedback_rx.try_recv().unwrap();
    assert_eq!(&feedback[20..22], &[3, 4]);
    assert_eq!(
        u16::from_be_bytes([feedback[26], feedback[27]]),
        expected_mtu
    );
    assert!(fixture
        .peers
        .active_direct_path_snapshot_is_current_sync("peer-a", path));
    assert!(fixture.receiver_a.try_recv(&mut [0u8; 2048]).is_err());
}

#[tokio::test]
async fn delayed_terminal_report_cannot_degrade_a_replacement_direct_commit() {
    let fixture = LanWorkerFixture::new().await;
    let sink = install_loss_sink(&fixture);
    let generation = fixture.peers.current_network_generation_sync();
    let old = fixture
        .peers
        .active_direct_path_snapshot("peer-a", generation, true)
        .await
        .unwrap();
    let endpoint = fixture.receiver_b.local_addr().unwrap();
    let udp = fixture.udp_transport.read().await.clone().unwrap();
    let local = udp.local_addr().unwrap();
    fixture
        .peers
        .add_candidates_with_sources(
            "peer-a",
            &[endpoint.to_string()],
            &HashMap::from([(endpoint.to_string(), "host".to_string())]),
        )
        .await;
    fixture
        .peers
        .record_direct_probe_success_with_latency_and_local_endpoint(
            "peer-a",
            endpoint,
            Some(Duration::from_millis(1)),
            Some(local),
        )
        .await;
    fixture
        .peers
        .record_direct_success_with_local_endpoint("peer-a", Some(endpoint), Some(local))
        .await;
    let current = fixture
        .peers
        .active_direct_path_snapshot("peer-a", generation, true)
        .await
        .unwrap();
    assert_ne!(old.direct_commit_seq, current.direct_commit_seq);
    assert_ne!(old.endpoint, current.endpoint);
    super::super::queue::report_fast_path_terminal(
        &fixture.transport,
        &fixture.peers,
        "peer-a",
        generation,
        4,
        REASON_DIRECT_DELIVERY_UNCERTAIN,
        "late old-path terminal".into(),
        &ConnectionTimeline::new("delayed-terminal-fence", 0),
        Some((old, Some(local))),
    )
    .await;
    assert_eq!(
        sink.lock().await.drops[REASON_DIRECT_DELIVERY_UNCERTAIN].packets,
        1
    );
    assert!(fixture
        .peers
        .active_direct_path_snapshot_is_current_sync("peer-a", current));
    assert!(
        fixture
            .peers
            .record_direct_failure_for_active_path_snapshot(
                "peer-a",
                current,
                REASON_DIRECT_SEND_FAILED,
                "current-path failure",
                Some(local)
            )
            .await
    );
    assert!(!fixture.peers.is_direct_sync("peer-a"));
}
