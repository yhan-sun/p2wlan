// ============================================================
// v0.1.115: relay-backoff heartbeat quit handshake
//
// Deterministic regression tests for the no-overlap invariant: at any
// instant at most ONE heartbeat worker per peer may actually send UDP
// packets.  Cancellation moves the lease to the quitting set BEFORE the
// worker is signalled; a replacement can only become send-capable after the
// old worker confirmed it stopped sending, and a recovery trigger arriving
// during the quit handshake is remembered as a pending restart so exactly
// one new worker takes over.
//
// The tests use the heartbeat send gate (a real barrier) to park the old
// worker immediately before an actual UDP send, then cancel, request a
// replacement, and assert with real receiver packet counts plus registry
// ownership assertions that no packet is ever emitted by the cancelled
// worker and none by a worker that was not yet the sole owner.
// ============================================================

async fn add_heartbeat_peer(peers: &Arc<PeerManager>, node_id: &str, endpoint: SocketAddr) {
    let mut info = peer(node_id, "10.20.0.9", Some(endpoint));
    // Avoid the compatibility second datagram so packet counts match kernel
    // sends exactly.
    info.app_version = "0.1.25".to_string();
    peers.add_peer(&info).await;
    peers
        .add_candidates_with_sources(
            node_id,
            &[endpoint.to_string()],
            &HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]),
        )
        .await;
    peers.update_state(node_id, ConnectionState::Relay).await;
}

async fn active_owner_token(
    transport: &UdpTransport,
    peer_id: &str,
) -> Option<u64> {
    transport
        .relay_backoff_heartbeats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .active
        .get(peer_id)
        .map(|lease| lease.owner_token)
}

async fn count_pending_receiver_datagrams(receiver: &UdpSocket) -> usize {
    let mut buf = [0u8; 256];
    let mut count = 0usize;
    while let Ok(Ok(_)) = timeout(Duration::from_millis(10), receiver.recv_from(&mut buf)).await {
        count += 1;
    }
    count
}

#[tokio::test]
async fn cancel_then_immediate_replacement_never_overlaps_sending() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    add_heartbeat_peer(&peers, "peer-b", receiver_addr).await;

    let gate = Arc::new(HeartbeatSendGate::new());
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_heartbeat_send_gate(gate.clone());

    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );
    let first_owner = active_owner_token(&transport, "peer-b").await.unwrap();

    // The old worker parks at the gate right before its first UDP send.
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the old worker must reach the pre-send gate");
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        0,
        "the parked worker must not have sent anything yet"
    );

    // Cancel the old worker and immediately request a replacement: the
    // replacement must NOT become send-capable while the old owner is
    // quitting.
    assert!(transport.cancel_relay_backoff_heartbeat("peer-b"));
    assert!(
        !transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await,
        "a replacement must not start while the old worker is still quitting"
    );
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(registry.active.is_empty());
        assert!(
            registry
                .quitting
                .get("peer-b")
                .is_some_and(|lease| lease.owner_token == first_owner)
        );
        assert!(registry.pending_restarts.contains_key("peer-b"));
    }
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        0,
        "no worker may send while the old owner is quitting"
    );

    // Release the gate: the old worker re-validates its ownership, fails,
    // aborts the beat WITHOUT sending, and confirms exit.  The pending
    // restart then starts exactly one new worker, which parks at the same
    // gate before its first send.
    gate.release.wait().await;
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the replacement worker must park at the pre-send gate");
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(
            registry.quitting.is_empty() && registry.pending_restarts.is_empty(),
            "the old worker must have confirmed exit before the replacement parks"
        );
        assert_eq!(registry.active.len(), 1);
        let replacement_owner = registry
            .active
            .get("peer-b")
            .map(|lease| lease.owner_token)
            .unwrap();
        assert_ne!(
            replacement_owner, first_owner,
            "the replacement must be a fresh owner token"
        );
    }
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        0,
        "the cancelled old worker must never emit a post-cancel packet"
    );

    // Release the replacement: it becomes the sole send-capable owner and
    // its first beat reaches the receiver.
    gate.release.wait().await;
    let mut buf = [0u8; 256];
    let (n, _from) = timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
        .await
        .expect("the replacement worker must send after becoming the owner")
        .unwrap();
    assert_eq!(
        decode_punch_packet(&buf[..n]).unwrap().kind,
        PunchPacketKind::Punch
    );
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            registry.active.len(),
            1,
            "exactly one send-capable owner may exist after the handshake"
        );
    }
    transport.cancel_relay_backoff_heartbeat("peer-b");
}

#[tokio::test]
async fn cancel_mid_beat_old_worker_stops_before_next_send() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    add_heartbeat_peer(&peers, "peer-b", receiver_addr).await;

    let gate = Arc::new(HeartbeatSendGate::new());
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_heartbeat_send_gate(gate.clone());

    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(50))
            .await
    );

    // Let the old worker run one full beat without the gate: park it, then
    // release so the packet actually goes out.
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the first beat must reach the pre-send gate");
    gate.release.wait().await;
    {
        let mut buf = [0u8; 256];
        timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
            .await
            .expect("the first beat must reach the receiver")
            .unwrap();
    }
    let before_cancel = count_pending_receiver_datagrams(&receiver).await;

    // A production heartbeat is admitted once per three-second service slot.
    // This test uses a short worker interval only to make the ownership race
    // deterministic, so advance the test clock before requesting its next
    // real service beat rather than accidentally asserting that a second
    // candidate sweep is allowed inside the same slot.
    transport
        .relay_backoff_heartbeat_budget
        .set_service_slot_for_test(1);

    // The next beat parks the worker at the pre-send gate.
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the worker must park at the pre-send gate on a later beat");

    // Cancel while the worker is parked mid-beat and request a replacement.
    assert!(transport.cancel_relay_backoff_heartbeat("peer-b"));
    assert!(!transport
        .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(50))
        .await);
    let first_owner = {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry
            .quitting
            .get("peer-b")
            .map(|lease| lease.owner_token)
    };
    assert!(first_owner.is_some());

    // Release: the cancelled worker must abort without sending one more
    // packet; the pending restart then starts the replacement, which also
    // parks before its first send.
    gate.release.wait().await;
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the replacement worker must park at the pre-send gate");
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        before_cancel,
        "the cancelled worker must not emit any packet after cancellation"
    );
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(registry.quitting.is_empty() && registry.pending_restarts.is_empty());
        assert_eq!(registry.active.len(), 1);
    }

    // Release the replacement: it sends, and from then on all packets belong
    // to the single new owner.
    gate.release.wait().await;
    let mut buf = [0u8; 256];
    timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
        .await
        .expect("the replacement must send after becoming the sole owner")
        .unwrap();
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(registry.active.len(), 1);
    }
    transport.cancel_relay_backoff_heartbeat("peer-b");
}

#[tokio::test]
async fn quit_handshake_ignores_direct_transition_during_cancel() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    add_heartbeat_peer(&peers, "peer-b", receiver_addr).await;

    let gate = Arc::new(HeartbeatSendGate::new());
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_heartbeat_send_gate(gate.clone());
    let cancel_transport = transport.clone();
    peers.set_relay_backoff_heartbeat_cancel_hook(Arc::new(move |peer_id| {
        cancel_transport.cancel_relay_backoff_heartbeat(peer_id);
    }));

    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the worker must park at the pre-send gate");

    // The peer turns Direct while the worker is quitting: the replacement
    // must not start, because the Direct transition already closed the
    // recovery loop.  The pending restart's spawned worker exits at its
    // loop-top Direct check without sending.  (The Direct transition itself
    // revokes the active lease through the registered cancel hook, so no
    // explicit cancel is needed here.)
    peers.update_state("peer-b", ConnectionState::Direct).await;
    assert!(!transport
        .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
        .await);

    gate.release.wait().await;
    // Wait for the pending-restart worker to observe Direct and exit.
    let mut registry_state = None;
    for _ in 0..100 {
        sleep(Duration::from_millis(10)).await;
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.active.is_empty() && registry.quitting.is_empty() {
            registry_state = Some((
                registry.pending_restarts.is_empty(),
                registry.closed.load(std::sync::atomic::Ordering::Acquire),
            ));
            break;
        }
    }
    let (pending_empty, closed) =
        registry_state.expect("all workers must exit after the Direct transition");
    assert!(pending_empty, "the pending restart must be consumed exactly once");
    assert!(!closed);
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        0,
        "no heartbeat packet may be sent after the peer turned Direct"
    );
}

#[tokio::test]
async fn quit_handshake_ignores_peer_removal_during_cancel() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    add_heartbeat_peer(&peers, "peer-b", receiver_addr).await;

    let gate = Arc::new(HeartbeatSendGate::new());
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_heartbeat_send_gate(gate.clone());
    let cancel_transport = transport.clone();
    peers.set_relay_backoff_heartbeat_cancel_hook(Arc::new(move |peer_id| {
        cancel_transport.cancel_relay_backoff_heartbeat(peer_id);
    }));

    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the worker must park at the pre-send gate");

    // The peer is removed while the worker is quitting: no replacement may
    // probe a peer that no longer exists.
    peers.remove_peer("peer-b").await;
    assert!(!transport
        .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
        .await);

    gate.release.wait().await;
    for _ in 0..100 {
        sleep(Duration::from_millis(10)).await;
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.active.is_empty() && registry.quitting.is_empty() {
            assert!(registry.pending_restarts.is_empty());
            break;
        }
    }
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        0,
        "no heartbeat packet may be sent after the peer was removed"
    );
}

#[tokio::test]
async fn quit_handshake_ignores_relay_loss_during_cancel() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    add_heartbeat_peer(&peers, "peer-b", receiver_addr).await;
    peers.set_relay("peer-b", "relay-a.test:28081").await;

    let gate = Arc::new(HeartbeatSendGate::new());
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_heartbeat_send_gate(gate.clone());
    let cancel_transport = transport.clone();
    peers.set_relay_backoff_heartbeat_cancel_hook(Arc::new(move |peer_id| {
        cancel_transport.cancel_relay_backoff_heartbeat(peer_id);
    }));

    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the worker must park at the pre-send gate");

    // The relay safety net closes while the worker is quitting: the
    // heartbeat has nothing to keep warm and must not restart.
    peers
        .invalidate_relay_transport("relay-a.test:28081", "transport_closed", "test loss")
        .await;
    assert!(!transport
        .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
        .await);

    gate.release.wait().await;
    for _ in 0..100 {
        sleep(Duration::from_millis(10)).await;
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.active.is_empty() && registry.quitting.is_empty() {
            assert!(registry.pending_restarts.is_empty());
            break;
        }
    }
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        0,
        "no heartbeat packet may be sent after the relay safety net closed"
    );
}

#[tokio::test]
async fn multiple_restart_triggers_during_quit_start_exactly_one_worker() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    add_heartbeat_peer(&peers, "peer-b", receiver_addr).await;

    let gate = Arc::new(HeartbeatSendGate::new());
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_heartbeat_send_gate(gate.clone());

    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("the worker must park at the pre-send gate");

    assert!(transport.cancel_relay_backoff_heartbeat("peer-b"));
    // Several recovery triggers arrive during the quit handshake; they all
    // coalesce into ONE pending restart.
    for _ in 0..5 {
        assert!(!transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await);
    }
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(registry.pending_restarts.len(), 1);
        assert!(registry.active.is_empty());
    }

    gate.release.wait().await;
    timeout(Duration::from_secs(2), gate.reached.notified())
        .await
        .expect("exactly one replacement worker must start");
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(
            registry.active.len(),
            1,
            "multiple triggers must coalesce into exactly one replacement worker"
        );
        assert!(registry.pending_restarts.is_empty());
    }
    gate.release.wait().await;
    {
        let mut buf = [0u8; 256];
        timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
            .await
            .expect("the single replacement must send after becoming owner")
            .unwrap();
    }
    transport.cancel_relay_backoff_heartbeat("peer-b");
}

#[tokio::test]
async fn shutdown_closes_heartbeat_registry_permanently() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    add_heartbeat_peer(&peers, "peer-b", receiver_addr).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(20))
            .await
    );
    transport.cancel_all_relay_backoff_heartbeats();

    // A withdrawn transport must never start or restart a worker.
    assert!(
        !transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(20))
            .await
    );
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(registry.closed.load(std::sync::atomic::Ordering::Acquire));
        assert!(registry.active.is_empty() && registry.quitting.is_empty());
    }
    // And no packet may arrive after shutdown.
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        count_pending_receiver_datagrams(&receiver).await,
        0,
        "no heartbeat packet may be sent after the transport was withdrawn"
    );
}
