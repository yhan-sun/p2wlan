// ============================================================
// v0.1.114: NAT binding maintainer budget isolation
// ============================================================

use crate::udp::probe_budget::{
    RELAY_BACKOFF_HEARTBEAT_GLOBAL_PER_WINDOW,
    RELAY_BACKOFF_HEARTBEAT_PER_REMOTE_IP_PER_WINDOW,
};

#[tokio::test]
async fn nat_maintainer_never_consumes_recovery_epoch_probe_credit() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;

    // Exhaust the peer's recovery-epoch probe credit completely: the old
    // maintainer path would now be starved, freezing the epoch while the
    // maintainer's bindings go dead.
    peers.recovery_epoch_admit("peer-b").await;
    let mut accepted = 0u32;
    while peers.try_consume_recovery_probe_credit("peer-b").await {
        accepted += 1;
    }
    assert_eq!(accepted, crate::peer::RECOVERY_EPOCH_PROBE_CREDIT);
    assert!(!peers.try_consume_recovery_probe_credit("peer-b").await);

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        transport
            .spawn_nat_binding_maintainer(
                "peer-b",
                receiver_addr,
                Duration::from_millis(2),
                Duration::from_millis(25),
            )
            .await
    );

    // The maintainer must still send probes with zero epoch credit left: the
    // dedicated budget is fully isolated from the traversal credit.
    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(1), receiver.recv_from(&mut buf))
        .await
        .expect("maintainer must keep sending with exhausted epoch credit")
        .unwrap();
    assert_eq!(
        decode_punch_packet(&buf[..n]).unwrap().kind,
        PunchPacketKind::Punch
    );

    // And the traversal credit remains exhausted: the maintainer did not
    // steal a single unit from the recovery path.
    assert!(
        !peers.try_consume_recovery_probe_credit("peer-b").await,
        "maintainer probes must never consume recovery-epoch probe credit"
    );
}

#[tokio::test]
async fn nat_maintainer_dedicated_budget_is_bounded_and_recovers() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();

    // Saturate the dedicated per-(peer, socket) budget.
    let saturated = {
        let mut budget = transport.nat_maintainer_budget.lock().await;
        let now = Instant::now();
        let key = ("peer-b".to_string(), 0usize);
        let sent = budget.entry(key).or_default();
        for _ in 0..NAT_MAINTAINER_BUDGET_PER_PEER_SOCKET {
            sent.push_back(now);
        }
        true
    };
    assert!(saturated);

    assert!(
        !transport
            .admit_nat_maintainer_probe("peer-b", 0)
            .await,
        "a saturated dedicated budget must reject the maintainer probe"
    );
    assert!(
        transport
            .admit_nat_maintainer_probe("peer-b", 1)
            .await,
        "a different socket has its own independent budget"
    );
    assert!(
        transport.admit_outbound_connectivity_probe("peer-b", receiver_addr, 0).await
            == OutboundProbeAdmission::Accepted,
        "the dedicated maintainer budget must never affect ordinary probes"
    );
}

#[tokio::test]
async fn relay_backoff_heartbeat_never_consumes_recovery_epoch_credit() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    peers
        .add_candidates_with_sources(
            "peer-b",
            &[receiver_addr.to_string()],
            &HashMap::from([(receiver_addr.to_string(), "stun_observed".to_string())]),
        )
        .await;
    peers
        .update_state("peer-b", crate::peer::ConnectionState::Relay)
        .await;

    // Exhaust the peer's recovery-epoch probe credit completely: a heartbeat
    // that consumed the epoch credit would be starved immediately.
    peers.recovery_epoch_admit("peer-b").await;
    let mut accepted = 0u32;
    while peers.try_consume_recovery_probe_credit("peer-b").await {
        accepted += 1;
    }
    assert_eq!(accepted, crate::peer::RECOVERY_EPOCH_PROBE_CREDIT);

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(20))
            .await,
        "the first heartbeat task must start"
    );
    assert!(
        !transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(20))
            .await,
        "overlapping heartbeat tasks must be deduplicated"
    );

    let mut buf = [0u8; 64];
    let (n, _from) = timeout(Duration::from_secs(2), receiver.recv_from(&mut buf))
        .await
        .expect("the heartbeat must send probes with exhausted epoch credit")
        .unwrap();
    assert_eq!(
        decode_punch_packet(&buf[..n]).unwrap().kind,
        PunchPacketKind::Punch
    );
    assert!(
        !peers.try_consume_recovery_probe_credit("peer-b").await,
        "heartbeat probes must never consume recovery-epoch probe credit"
    );

    // The heartbeat stops when the peer turns Direct.
    peers
        .record_direct_success("peer-b", Some(receiver_addr))
        .await;
    sleep(Duration::from_millis(100)).await;
    let registry = transport
        .relay_backoff_heartbeats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        !registry.active.contains_key("peer-b"),
        "the heartbeat task must remove itself once Direct is confirmed"
    );
}

#[tokio::test]
async fn relay_backoff_heartbeat_stays_single_after_legacy_dedupe_window() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    peers
        .add_candidates_with_sources(
            "peer-b",
            &[receiver_addr.to_string()],
            &HashMap::from([(receiver_addr.to_string(), "stun_observed".to_string())]),
        )
        .await;
    peers.update_state("peer-b", ConnectionState::Relay).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );

    // Age only the test metadata beyond the old 30-second startup dedupe
    // window. The production lease never uses this timestamp for ownership.
    transport.age_relay_backoff_heartbeat_for_test("peer-b", Duration::from_secs(31));
    tokio::task::yield_now().await;
    assert!(
        !transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await,
        "an active worker must retain its owner after the legacy time window"
    );
    assert_eq!(
        transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .active
            .len(),
        1
    );
    transport.cancel_relay_backoff_heartbeat("peer-b");
}

#[tokio::test]
async fn cancelled_heartbeat_is_replaced_only_after_old_worker_quit() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", Some(receiver_addr))).await;
    peers
        .add_candidates_with_sources(
            "peer-b",
            &[receiver_addr.to_string()],
            &HashMap::from([(receiver_addr.to_string(), "stun_observed".to_string())]),
        )
        .await;
    peers.update_state("peer-b", ConnectionState::Relay).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );
    let first_owner = transport
        .relay_backoff_heartbeats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .active
        .get("peer-b")
        .map(|lease| lease.owner_token)
        .unwrap();

    // Cancellation revokes send capability immediately: the lease moves to
    // the quitting set and a replacement cannot be requested before the old
    // worker confirms it stopped sending.
    assert!(transport.cancel_relay_backoff_heartbeat("peer-b"));
    assert!(
        !transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await,
        "a replacement must wait for the old worker's quit handshake"
    );
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert!(registry.active.is_empty(), "no worker may be send-capable while the old owner is quitting");
        assert!(
            registry.quitting.get("peer-b").is_some_and(|lease| lease.owner_token == first_owner),
            "the cancelled owner must stay registered as quitting"
        );
        assert!(
            registry.pending_restarts.contains_key("peer-b"),
            "the replacement trigger must be recorded as a pending restart"
        );
    }

    // Once the old worker confirms exit, exactly one replacement takes over
    // with a fresh owner token.
    let replacement_owner = loop {
        sleep(Duration::from_millis(20)).await;
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(lease) = registry.active.get("peer-b") {
            assert_ne!(lease.owner_token, first_owner, "the replacement must be a new owner");
            assert!(
                registry.quitting.is_empty() && registry.pending_restarts.is_empty(),
                "no quitting worker or pending restart may remain after the handshake"
            );
            break lease.owner_token;
        }
    };
    {
        let registry = transport
            .relay_backoff_heartbeats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(registry.active.len(), 1, "exactly one send-capable owner may exist");
        assert!(
            registry.active.get("peer-b").is_some_and(|lease| lease.owner_token == replacement_owner),
            "the sole owner must be the replacement"
        );
    }
    transport.cancel_relay_backoff_heartbeat("peer-b");
}

#[tokio::test]
async fn heartbeat_lifecycle_cancellation_handles_direct_removal_and_relay_loss() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", Some(receiver_addr))).await;
    peers
        .add_candidates_with_sources(
            "peer-b",
            &[receiver_addr.to_string()],
            &HashMap::from([(receiver_addr.to_string(), "stun_observed".to_string())]),
        )
        .await;
    peers.update_state("peer-b", ConnectionState::Relay).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let cancel_transport = transport.clone();
    peers.set_relay_backoff_heartbeat_cancel_hook(Arc::new(move |peer_id| {
        cancel_transport.cancel_relay_backoff_heartbeat(peer_id);
    }));

    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await
    );
    peers.update_state("peer-b", ConnectionState::Direct).await;
    assert!(transport
        .relay_backoff_heartbeats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .active
        .is_empty());

    peers.update_state("peer-b", ConnectionState::Relay).await;
    // The previous owner may still be confirming its quit after the Direct
    // cancellation; the pending-restart handshake must converge to exactly
    // one send-capable worker.  The registry guard must NOT outlive this
    // block: it is held across an await, and the worker task runs on this
    // same current-thread runtime while the test sleeps.
    let mut started = false;
    for _ in 0..100 {
        let spawn_succeeded = transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await;
        let active = {
            let registry = transport
                .relay_backoff_heartbeats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.active.contains_key("peer-b")
        };
        if spawn_succeeded || active {
            started = true;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(started, "a heartbeat worker must take over after the peer re-enters Relay");
    peers.remove_peer("peer-b").await;
    assert!(transport
        .relay_backoff_heartbeats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .active
        .is_empty());

    peers.add_peer(&peer("peer-b", "10.20.0.9", Some(receiver_addr))).await;
    peers
        .add_candidates_with_sources(
            "peer-b",
            &[receiver_addr.to_string()],
            &HashMap::from([(receiver_addr.to_string(), "stun_observed".to_string())]),
        )
        .await;
    peers.set_relay("peer-b", "relay-a.test:28081").await;
    // The owner cancelled by remove_peer may still be confirming its quit;
    // the handshake must converge to exactly one send-capable worker.
    let mut restarted = false;
    for _ in 0..100 {
        let spawn_succeeded = transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_secs(1))
            .await;
        let active = {
            let registry = transport
                .relay_backoff_heartbeats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            registry.active.contains_key("peer-b")
        };
        if spawn_succeeded || active {
            restarted = true;
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(restarted, "a heartbeat worker must take over after the peer is re-added");
    peers
        .invalidate_relay_transport("relay-a.test:28081", "transport_closed", "test loss")
        .await;
    assert!(transport
        .relay_backoff_heartbeats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .active
        .is_empty());
}

#[tokio::test]
async fn heartbeat_without_trusted_target_releases_its_owner() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = receiver.local_addr().unwrap();
    let peers = peer_manager();
    peers.add_peer(&peer("peer-b", "10.20.0.9", None)).await;
    peers.update_state("peer-b", ConnectionState::Relay).await;

    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(5))
            .await
    );
    sleep(Duration::from_millis(25)).await;
    assert!(transport
        .relay_backoff_heartbeats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .active
        .is_empty());

    peers
        .add_candidates_with_sources(
            "peer-b",
            &[receiver_addr.to_string()],
            &HashMap::from([(receiver_addr.to_string(), "stun_observed".to_string())]),
        )
        .await;
    assert!(
        transport
            .spawn_relay_backoff_heartbeat("peer-b", Duration::from_millis(5))
            .await,
        "a later trusted candidate signal must be able to start a new owner"
    );
    transport.cancel_relay_backoff_heartbeat("peer-b");
}

#[tokio::test]
async fn relay_backoff_heartbeat_global_budget_counts_actual_packets_across_peers() {
    // One wildcard socket accepts the four loopback destinations while the
    // destination IPs remain distinct budget keys on platforms that do not
    // allow binding every 127/8 alias separately.
    let receiver = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let receiver_port = receiver.local_addr().unwrap().port();
    let endpoints = (1..=4)
        .map(|host_octet| format!("127.0.0.{host_octet}:{receiver_port}").parse().unwrap())
        .collect::<Vec<SocketAddr>>();
    let peers = peer_manager();
    for index in 0..20 {
        let endpoint = endpoints[index % endpoints.len()];
        let node_id = format!("heartbeat-{index}");
        let mut info = peer(&node_id, &format!("10.20.1.{index}"), Some(endpoint));
        // Avoid the compatibility second datagram so this test can compare
        // the budget directly with kernel-received packet counts.
        info.app_version = "0.1.25".to_string();
        peers.add_peer(&info).await;
        peers
            .add_candidates_with_sources(
                &node_id,
                &[endpoint.to_string()],
                &HashMap::from([(endpoint.to_string(), "stun_observed".to_string())]),
            )
            .await;
        peers.update_state(&node_id, ConnectionState::Relay).await;
    }

    let global_budget = Arc::new(GlobalRelayBackoffHeartbeatBudget::new());
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_global_heartbeat_budget(global_budget);
    let mut reported_packets = 0u32;
    for _ in 0..30 {
        for index in 0..20 {
            let node_id = format!("heartbeat-{index}");
            reported_packets = reported_packets.saturating_add(
                transport
                    .punch_candidates_relay_backoff_heartbeat(
                        &node_id,
                        vec![endpoints[index % endpoints.len()]],
                        1,
                    )
                    .await
                    .unwrap()
                    .packets_sent,
            );
        }
    }

    let mut buf = [0u8; 256];
    let mut received_total = 0usize;
    while let Ok(Ok(_)) = timeout(Duration::from_millis(20), receiver.recv_from(&mut buf)).await {
        received_total += 1;
    }
    let diagnostics_sent = transport
        .socket_pool_diagnostics()
        .await
        .into_iter()
        .map(|member| member.probes_sent)
        .sum::<u64>();
    assert_eq!(diagnostics_sent, reported_packets as u64);
    assert!(received_total > 0, "at least one heartbeat packet must reach the local receiver");
    assert!(
        diagnostics_sent as usize <= RELAY_BACKOFF_HEARTBEAT_GLOBAL_PER_WINDOW,
        "actual successful UDP sends must obey the process cap: {diagnostics_sent}"
    );
    let heartbeat_state = transport.relay_backoff_heartbeat_budget.state.lock().await;
    for endpoint in &endpoints {
        let key = crate::udp::probe_budget::RelayBackoffHeartbeatBudgetKey::RemoteIp(endpoint.ip());
        assert!(
            heartbeat_state.get(&key).map_or(0, VecDeque::len)
                <= RELAY_BACKOFF_HEARTBEAT_PER_REMOTE_IP_PER_WINDOW,
            "remote IP {} exceeded its heartbeat cap",
            endpoint.ip()
        );
    }
    assert_eq!(
        diagnostics_sent as usize,
        RELAY_BACKOFF_HEARTBEAT_GLOBAL_PER_WINDOW,
        "round-robin peer triggers should fill, but not exceed, the global reserve"
    );
}

#[tokio::test]
async fn heartbeat_yields_to_foreground_probe_budget() {
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    let peers = peer_manager();
    let mut info = peer("foreground-peer", "10.20.0.9", Some(endpoint));
    info.app_version = "0.1.25".to_string();
    peers.add_peer(&info).await;

    let foreground_budget = Arc::new(GlobalOutboundProbeBudget::new());
    {
        let now = Instant::now();
        let mut state = foreground_budget.state.lock().await;
        state.insert(
            OutboundProbeBudgetKey::Network,
            std::iter::repeat_n(
                now,
                OUTBOUND_PROBE_BUDGET_PER_NETWORK
                    .saturating_sub(RELAY_BACKOFF_HEARTBEAT_FOREGROUND_RESERVE),
            )
            .collect(),
        );
    }
    let transport = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_global_probe_budget(foreground_budget)
        .with_global_heartbeat_budget(Arc::new(GlobalRelayBackoffHeartbeatBudget::new()));

    assert!(
        !transport
            .admit_relay_backoff_heartbeat_probe("foreground-peer", endpoint)
            .await,
        "heartbeat must yield while the foreground global burst is active"
    );
    assert_eq!(
        transport
            .admit_outbound_connectivity_probe("foreground-peer", endpoint, 0)
            .await,
        OutboundProbeAdmission::Accepted,
        "foreground traversal must retain priority and its own admission capacity"
    );
}
