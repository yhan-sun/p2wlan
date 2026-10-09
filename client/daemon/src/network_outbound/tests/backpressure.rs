use super::super::test_support::*;
use super::*;
use crate::config::Config;
use tokio::net::UdpSocket;

async fn confirmed_direct(
    peers: &Arc<PeerManager>,
    udp: &UdpTransport,
    endpoint: SocketAddr,
) -> crate::dplpmtud::DplpmtudWorkerLease {
    let generation = peers.current_network_generation_sync();
    let session = peers.peer_session_generation_sync("peer-a").unwrap();
    let candidate_epoch = peers
        .current_remote_candidate_epoch("peer-a")
        .await
        .unwrap();
    let epoch = crate::peer::PathEpoch::new(generation, session, candidate_epoch);
    assert!(
        peers
            .mark_direct_validation_started(
                "peer-a",
                crate::peer::DirectValidationIdentity::owned(epoch, 101, Some(103), Some(endpoint)),
            )
            .await
    );
    let validation = crate::peer::DirectValidationIdentity::authenticated_ack(
        epoch,
        101,
        103,
        Some(endpoint),
        endpoint,
    );
    let local = udp.local_addr().unwrap();
    let gate = peers.network_epoch_gate();
    let guard = gate.lock().await;
    assert!(
        peers
            .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(
                &guard,
                "peer-a",
                Some(endpoint),
                generation,
                Some(local),
                None,
                Some(candidate_epoch),
                Some(validation),
            )
            .await
    );
    drop(guard);
    let identity = crate::dplpmtud::DplpmtudPathIdentity::from_committed_validation(
        "peer-a",
        validation,
        endpoint,
        local,
        udp.transport_instance_id(),
        0,
    )
    .unwrap();
    assert!(udp.mark_peer_dplpmtud_supported("peer-a", session));
    let runtime = udp.dplpmtud_runtime();
    let now = tokio::time::Instant::now();
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    let probe = runtime
        .schedule_probe("peer-a", &identity, lease.worker_owner_token, now)
        .unwrap();
    assert!(runtime.begin_probe_send(&probe, now));
    runtime.finish_probe_send(&probe, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            "peer-a",
            &identity,
            probe.wire_token,
            crate::dplpmtud::DplpmtudAckIngress {
                remote_endpoint: endpoint,
                local_endpoint: local,
                socket: identity.socket,
            },
            now + Duration::from_millis(2),
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Applied,
    );
    let DirectBusinessBudgetGate::Ready(prepared) =
        udp.prepare_direct_business_send("peer-a", endpoint).await
    else {
        panic!("the confirmed Direct fixture must have a business send budget");
    };
    timeout(Duration::from_secs(2), prepared.socket.writable())
        .await
        .expect("the loopback UDP socket must become writable")
        .unwrap();
    lease
}

fn packet_queue(generation: u64, deadline: Instant) -> (PeerPendingQueue, Vec<Vec<u8>>) {
    let mut queue = PeerPendingQueue::new();
    queue.wait_generation = Some(generation);
    queue.delivery_deadline = Some(deadline);
    let packets: Vec<_> = (1..=2)
        .map(|sequence| {
            Ipv4Packet::build_icmp_echo_request(
                "10.20.0.1".parse().unwrap(),
                "10.20.0.2".parse().unwrap(),
                0x2b2b,
                sequence,
                b"direct-backpressure",
            )
        })
        .collect();
    for packet in &packets {
        let (dropped, _) = queue.enqueue(PendingPacket::plain(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".into(),
            dst_ip: "10.20.0.2".into(),
            packet: packet.clone(),
            trace: None,
        }));
        assert!(dropped.is_empty());
    }
    (queue, packets)
}

#[tokio::test]
async fn transient_direct_backpressure_drains_without_maintenance() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    peers.add_peer(&test_peer("peer-a", endpoint)).await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    udp.set_inbound_publication_owner(601);
    let _lease = confirmed_direct(&peers, &udp, endpoint).await;
    let runtime = udp.dplpmtud_runtime();
    let budget = runtime.direct_business_budget_entry("peer-a");
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let (local_session, mut remote_session) = establish_sessions();
    transport.add_session("peer-a", local_session).await;

    // A ready socket that reports one transient WouldBlock must drain this
    // FIFO in the same flush. No actor, timer tick, or later packet can wake
    // the flush for this test, so it cannot pass via the maintenance fallback.
    let _attempts = udp.inject_direct_business_would_block_for_test("peer-a", 1);
    let (queue, packets) = packet_queue(
        peers.current_network_generation_sync(),
        Instant::now() + OUTBOUND_DELIVERY_DEADLINE,
    );
    let (_, remaining) = timeout(
        Duration::from_secs(2),
        flush_one_peer(
            "peer-a".into(),
            queue,
            transport,
            peers.clone(),
            true,
            Arc::new(RwLock::new(Some(udp.clone()))),
            Arc::new(RwLock::new(None)),
            false,
            ConnectionTimeline::new("node-a", 0),
        ),
    )
    .await
    .expect("a writable socket must not stall the per-peer flush");
    assert!(
        remaining.queue.is_empty(),
        "transient WouldBlock left packets waiting for the 100ms maintenance timer"
    );
    assert!(remaining.retry_after.is_none());
    let mut wire = vec![0u8; 2048];
    for (index, expected) in packets.iter().enumerate() {
        let (size, _) = timeout(Duration::from_secs(2), receiver.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            crate::transport::wire_counter(&wire[..size]),
            Some(index as u64 + 1)
        );
        assert_eq!(
            remote_session.decrypt_from_bytes(&wire[..size]).unwrap(),
            *expected
        );
    }
    assert_eq!(runtime.direct_business_budget_entry("peer-a"), budget);
    let connection = peers.get_connection("peer-a").await.unwrap();
    assert_eq!(connection.active_path(), Some(NetworkPath::Direct));
    assert_eq!(connection.direct_health.failure_count, 0);
    assert_eq!(connection.relay_health.failure_count, 0);
    runtime.cancel_peer("peer-a", "test_complete", tokio::time::Instant::now());
    assert_eq!(runtime.active_worker_count(), 0);
}

#[tokio::test]
async fn repeated_direct_writable_false_positives_preserve_fifo_and_deadline() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    peers.add_peer(&test_peer("peer-a", endpoint)).await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    udp.set_inbound_publication_owner(601);
    let _lease = confirmed_direct(&peers, &udp, endpoint).await;
    let runtime = udp.dplpmtud_runtime();
    let budget = runtime.direct_business_budget_entry("peer-a");
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let (local_session, _remote_session) = establish_sessions();
    transport.add_session("peer-a", local_session).await;
    let attempts = udp.inject_direct_business_would_block_for_test("peer-a", 1024);
    let deadline = Instant::now() + OUTBOUND_DELIVERY_DEADLINE;
    let (queue, packets) = packet_queue(peers.current_network_generation_sync(), deadline);

    // The kernel socket stays writable, but every guarded send reports
    // WouldBlock. Readiness alone must not create a tight retry loop or let
    // the second packet overtake the blocked head.
    let (_, remaining) = timeout(
        Duration::from_secs(2),
        flush_one_peer(
            "peer-a".into(),
            queue,
            transport.clone(),
            peers.clone(),
            true,
            Arc::new(RwLock::new(Some(udp.clone()))),
            Arc::new(RwLock::new(None)),
            false,
            ConnectionTimeline::new("node-a", 0),
        ),
    )
    .await
    .expect("false readiness must return to paced maintenance");
    let attempted = *attempts.borrow();
    assert!(
        attempted > 1,
        "a writable socket should be retried promptly"
    );
    assert!(attempted <= 1 + MAX_DIRECT_WRITABLE_RETRIES_PER_FLUSH);
    assert_eq!(remaining.delivery_deadline, Some(deadline));
    assert!(remaining.retry_after.is_some());
    assert_eq!(remaining.queue.len(), packets.len());
    assert_eq!(remaining.bytes, packets.iter().map(Vec::len).sum::<usize>());
    for (index, (pending, expected)) in remaining.queue.iter().zip(&packets).enumerate() {
        let PendingPacket::Plain {
            packet,
            direct_budget_reroutes,
            local_backpressure_retries,
        } = pending;
        assert_eq!(&packet.packet, expected);
        assert_eq!(*direct_budget_reroutes, 0);
        assert_eq!(
            *local_backpressure_retries,
            if index == 0 { attempted as u32 } else { 0 }
        );
    }
    assert_eq!(runtime.direct_business_budget_entry("peer-a"), budget);
    assert!(transport
        .try_acquire_outbound_emit_guard("peer-a")
        .is_some());
    assert!(peers.network_epoch_gate().try_lock().is_ok());
    let mut wire = [0u8; 2048];
    assert_eq!(
        receiver.try_recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    runtime.cancel_peer("peer-a", "test_complete", tokio::time::Instant::now());
    assert_eq!(runtime.active_worker_count(), 0);
}

#[tokio::test]
async fn generation_change_after_direct_backpressure_cancels_plaintext_retry() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    peers.add_peer(&test_peer("peer-a", endpoint)).await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    udp.set_inbound_publication_owner(601);
    let _lease = confirmed_direct(&peers, &udp, endpoint).await;
    let runtime = udp.dplpmtud_runtime();
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let (local_session, _remote_session) = establish_sessions();
    transport.add_session("peer-a", local_session).await;
    let losses = Arc::new(tokio::sync::Mutex::new(
        crate::peer::OutboundLossCounters::default(),
    ));
    peers.set_outbound_loss_sink(losses.clone());
    transport.set_outbound_loss_sink(Some(losses.clone()));
    let loss_guard = losses.lock().await;
    let mut attempts = udp.inject_direct_business_would_block_for_test("peer-a", 1);
    let generation = peers.current_network_generation_sync();
    let (queue, packets) = packet_queue(generation, Instant::now() + OUTBOUND_DELIVERY_DEADLINE);

    // Pause at the real asynchronous failure accounting boundary, after the
    // exact send reports WouldBlock. A network replacement must be able to
    // proceed, and readiness must never authorize the retired send token.
    let flush = tokio::spawn(flush_one_peer(
        "peer-a".into(),
        queue,
        transport.clone(),
        peers.clone(),
        true,
        Arc::new(RwLock::new(Some(udp.clone()))),
        Arc::new(RwLock::new(None)),
        false,
        ConnectionTimeline::new("node-a", 0),
    ));
    timeout(Duration::from_secs(2), attempts.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*attempts.borrow(), 1);
    assert!(transport
        .try_acquire_outbound_emit_guard("peer-a")
        .is_some());
    let new_generation = timeout(
        Duration::from_secs(2),
        peers.advance_network_generation("backpressure-network-replacement"),
    )
    .await
    .expect("readiness retry must not retain the network epoch guard");
    assert!(new_generation > generation);
    drop(loss_guard);
    let (_, remaining) = timeout(Duration::from_secs(2), flush)
        .await
        .unwrap()
        .unwrap();
    assert!(remaining.queue.is_empty());
    let stats = peers.outbound_loss_stats().await;
    assert_eq!(
        stats.drops[REASON_OUTBOUND_GENERATION_CHANGED].packets,
        packets.len() as u64
    );
    assert_eq!(*attempts.borrow(), 1);
    let mut wire = [0u8; 2048];
    assert_eq!(
        receiver.try_recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    runtime.cancel_peer("peer-a", "test_complete", tokio::time::Instant::now());
    assert_eq!(runtime.active_worker_count(), 0);
}
