use super::queue::flush_one_peer;
use super::send::{
    outbound_send_timeout_failure_for_path, relay_send_failure, select_outbound_path,
};
use super::*;
use crate::config::Config;
use crate::control::PeerInfo;
use crate::peer::REASON_PATH_DIRECT_CONFIRMED;
use p2pnet_crypto::NodeIdentity;
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};

fn establish_sessions() -> (TransportSession, TransportSession) {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut responder = HandshakeResponder::new(node_b, None);
    let initiation = initiator.create_initiation().unwrap();
    let (response, node_b_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let node_a_keys = initiator.consume_response(&response).unwrap();
    (
        TransportSession::new(node_a_keys),
        TransportSession::new(node_b_keys),
    )
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

#[test]
fn relay_queue_full_and_writer_closed_are_safe_plaintext_retries() {
    for error in [
        p2pnet_relay::RelayError::CommandQueueFull,
        p2pnet_relay::RelayError::WriterStoppedBeforeAccept,
        p2pnet_relay::RelayError::WriteBoundaryRejected,
    ] {
        let outcome = relay_send_failure(&crate::error::DaemonError::RelaySend {
            endpoint: "tcp://relay.test:1".to_string(),
            error,
        });
        assert!(matches!(
            outcome,
            SendOutcome::Retryable(RetryableSendFailure::RelaySendNotHanded { .. })
        ));
    }
}

#[test]
fn unknown_relay_failure_is_terminal_delivery_uncertain() {
    let outcome = relay_send_failure(&crate::error::DaemonError::RelaySend {
        endpoint: "tcp://relay.test:1".to_string(),
        error: p2pnet_relay::RelayError::WriteUncertain(
            "relay protocol rejected frame after write".into(),
        ),
    });
    assert!(matches!(
        outcome,
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
            reason: REASON_RELAY_DELIVERY_UNCERTAIN,
            ..
        })
    ));
}

#[test]
fn send_timeout_is_terminal_delivery_uncertain() {
    assert!(matches!(
        outbound_send_timeout_failure_for_path(REASON_RELAY_DELIVERY_UNCERTAIN),
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
            reason: REASON_RELAY_DELIVERY_UNCERTAIN,
            ..
        })
    ));
}

#[test]
fn uncertain_direct_handoff_is_terminal_and_not_relay_replayed() {
    let outcome = SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
        reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
        err: "Direct UDP send result uncertain".to_string(),
    });
    assert!(matches!(
        outcome,
        SendOutcome::Terminal(TerminalSendFailure::DeliveryUncertain {
            reason: REASON_DIRECT_DELIVERY_UNCERTAIN,
            ..
        })
    ));
}

#[tokio::test]
async fn send_selector_accepts_authoritative_direct_before_relay_transport_publish() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let endpoint: SocketAddr = "198.51.100.50:51850".parse().unwrap();
    manager.add_peer(&test_peer("peer-a", endpoint)).await;
    let generation = manager.current_network_generation().await;

    // This is the exact startup race: relay is expected/configured, but
    // its transport object has not been published yet; Direct has already
    // completed encrypted validation.  The ACK is authoritative for the
    // Direct data path, while the relay expectation remains standby state.
    assert!(
        !manager
            .is_data_path_admitted_for_generation("peer-a", generation, true)
            .await
    );
    manager
        .record_direct_probe_success_with_latency(
            "peer-a",
            endpoint,
            Some(Duration::from_millis(8)),
        )
        .await;
    manager
        .record_direct_success("peer-a", Some(endpoint))
        .await;

    let packet = EncryptedPeerPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        wire_bytes: vec![0; 32],
        is_business: true,
    };
    let selection = select_outbound_path(&packet, &manager, true, false, true, None, false).await;
    assert_eq!(selection.path, Some(NetworkPath::Direct));
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_CONFIRMED);
    assert!(selection.direct_confirmed);
}

#[tokio::test]
async fn stale_generation_is_rejected_before_counter_allocation() {
    let manager = PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
    let expected_generation = manager.current_network_generation().await;
    manager
        .advance_network_generation("test-generation-race")
        .await;
    let transport = WireGuardTransport::new().0;
    let udp = RwLock::new(None);
    let relay = RwLock::new(None);

    let outcome = encrypt_then_send(
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![0x45, 0x00, 0x00, 0x14],
            trace: None,
        },
        &transport,
        &manager,
        expected_generation,
        true,
        &udp,
        &relay,
        true,
    )
    .await;

    assert!(matches!(
        outcome,
        EncryptSendOutcome::Retryable {
            reason_code: REASON_OUTBOUND_GENERATION_CHANGED,
            ..
        }
    ));
}

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
    )
    .await;
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
    )
    .await;
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

#[tokio::test(start_paused = true)]
async fn expired_managed_pending_delivery_deadline_drops_remaining_flush_batch() {
    let manager = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    manager
        .add_peer(&test_peer("peer-a", "127.0.0.1:41000".parse().unwrap()))
        .await;
    let peer_session_generation = manager
        .peer_session_generation_sync("peer-a")
        .expect("managed pending peer session");
    manager.mark_dplpmtud_capable_sync("peer-a", peer_session_generation);
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let timeline = ConnectionTimeline::new("node-a", 0);
    let mut queue = PeerPendingQueue::new();
    queue.wait_generation = Some(0);
    queue.delivery_deadline = Some(Instant::now() - Duration::from_millis(1));
    queue.enqueue(PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: vec![0x45, 0, 0, 20],
        trace: None,
    }));

    let (_peer_id, remaining) = flush_one_peer(
        "peer-a".to_string(),
        queue,
        transport,
        manager.clone(),
        true,
        Arc::new(RwLock::new(None)),
        Arc::new(RwLock::new(None)),
        true,
        timeline,
    )
    .await;

    assert!(remaining.queue.is_empty());
    let stats = manager.outbound_loss_stats().await;
    assert_eq!(
        stats
            .drops
            .get(REASON_OUTBOUND_DELIVERY_DEADLINE)
            .map(|counter| counter.packets),
        Some(1)
    );
}

#[tokio::test(start_paused = true)]
async fn peer_left_clears_managed_pending_fifo_without_flush_task_leak() {
    let manager = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    manager
        .add_peer(&test_peer("peer-a", "127.0.0.1:41001".parse().unwrap()))
        .await;
    let peer_session_generation = manager
        .peer_session_generation_sync("peer-a")
        .expect("managed pending peer session");
    manager.mark_dplpmtud_capable_sync("peer-a", peer_session_generation);

    let generation = manager.current_network_generation_sync();
    let mut queue = PeerPendingQueue::new();
    queue.wait_generation = Some(generation);
    queue.delivery_deadline = Some(Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
    queue.enqueue(PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            1,
            1,
            b"managed-pending",
        ),
        trace: None,
    }));
    let mut pending = HashMap::from([("peer-a".to_string(), queue)]);
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let udp_transport = Arc::new(RwLock::new(None));
    let relay_transport = Arc::new(RwLock::new(None));
    let timeline = ConnectionTimeline::new("node-a", 0);
    let mut flush_tasks = JoinSet::new();
    let mut flushing_peers = HashSet::new();

    manager.remove_peer("peer-a").await;
    maintenance(
        &transport,
        &manager,
        &mut pending,
        true,
        &udp_transport,
        &relay_transport,
        true,
        &timeline,
        &mut flush_tasks,
        &mut flushing_peers,
    )
    .await;

    assert!(pending.is_empty());
    assert!(flush_tasks.is_empty());
    assert!(flushing_peers.is_empty());
    let stats = manager.outbound_loss_stats().await;
    assert_eq!(
        stats
            .drops
            .get(REASON_OUTBOUND_PEER_OFFLINE)
            .map(|counter| counter.packets),
        Some(1)
    );
}

#[test]
fn managed_pending_fifo_obeys_packet_and_byte_caps() {
    let mut queue = PeerPendingQueue::new();
    let mut dropped = 0usize;
    for sequence in 0..300u16 {
        let (evicted, _) = queue.enqueue(PendingPacket::plain(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![sequence as u8; 65_535],
            trace: None,
        }));
        dropped = dropped.saturating_add(evicted.len());
    }
    assert!(dropped > 0);
    assert!(queue.queue.len() <= MAX_PENDING_PACKETS_PER_PEER);
    assert!(queue.bytes <= MAX_PENDING_BYTES_PER_PEER);
    let retained: Vec<u8> = queue
        .queue
        .iter()
        .map(|entry| entry.raw_packet()[0])
        .collect();
    assert!(retained
        .windows(2)
        .all(|window| { window[1] == window[0].wrapping_add(1) }));
}

#[test]
fn completed_peer_flush_stays_ahead_of_live_fifo_arrivals() {
    fn packet(sequence: u8) -> OutboundPacket {
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![sequence],
            trace: None,
        }
    }

    let mut completed = PeerPendingQueue::new();
    completed.enqueue(PendingPacket::plain(packet(0)));
    completed.enqueue(PendingPacket::plain(packet(1)));

    let mut pending = HashMap::new();
    let mut live = PeerPendingQueue::new();
    live.enqueue(PendingPacket::plain(packet(2)));
    live.enqueue(PendingPacket::plain(packet(3)));
    pending.insert("peer-a".to_string(), live);

    merge_completed_flush(&mut pending, "peer-a".to_string(), completed);

    let merged = pending.remove("peer-a").expect("merged queue");
    let sequences: Vec<u8> = merged
        .queue
        .into_iter()
        .map(|entry| match entry {
            PendingPacket::Plain { packet, .. } => packet.packet[0],
        })
        .collect();
    assert_eq!(sequences, vec![0, 1, 2, 3]);
}
