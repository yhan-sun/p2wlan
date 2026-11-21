use super::*;
use p2pnet_nat::engine::{
    CompactFrame, CompactSession, FrameKind, NatKind, PunchProfile, FRAME_SIZE,
};

async fn negotiated_receiver(
    linear: bool,
    configure: impl FnOnce(&mut Config),
) -> (UdpTransport, UdpSocket, CompactSession) {
    let local = NodeIdentity::generate();
    let remote = NodeIdentity::generate();
    let public_key = hex::encode(remote.public_key());
    let mut config = config_for_identity(&local, "peer-a");
    configure(&mut config);
    let peers = Arc::new(PeerManager::new(config));
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id("peer-a");
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = remote_socket.local_addr().unwrap();
    peers
        .add_peer(&peer_with_public_key(
            "peer-b",
            "10.20.0.2",
            public_key.clone(),
            Some(address),
        ))
        .await;
    let expires = Some(crate::gateway_mapping::now_ms() + 45_000);
    let candidate = address.to_string();
    peers
        .add_candidates_with_metadata(
            "peer-b",
            std::slice::from_ref(&candidate),
            &HashMap::from([(candidate.clone(), "host".into())]),
            7,
            expires,
        )
        .await;
    let observed = (1..=3)
        .map(|id| {
            StunObservation::reply(
                ([192, 0, 2, id], 3478).into(),
                Some(if linear {
                    SocketAddr::new(address.ip(), 27000 + u16::from(id))
                } else {
                    address
                }),
                Duration::from_millis(5),
            )
        })
        .collect();
    let local_profile =
        candidate_report_from_observations(udp.local_addr().unwrap(), false, observed).nat_profile;
    peers.update_nat_profile(local_profile).await;
    let owner = (
        peers.current_network_generation_sync(),
        peers.peer_session_generation_sync("peer-b"),
    );
    let profile = PunchProfile {
        nat_type: if linear {
            NatKind::LinearSymmetric
        } else {
            NatKind::Cone
        },
        port_step: i32::from(linear),
        port_hint: address.port(),
        supports_sym_punch: true,
        ..PunchProfile::default()
    };
    peers
        .stage_punch_profile(
            "peer-b",
            profile.clone(),
            Some("foreign-key"),
            7,
            expires,
            owner,
        )
        .await;
    assert!(peers.negotiated_profile("peer-b").await.is_none());
    peers
        .stage_punch_profile(
            "peer-b",
            profile.clone(),
            Some(&public_key),
            6,
            expires,
            owner,
        )
        .await;
    assert!(peers.negotiated_profile("peer-b").await.is_none());
    peers
        .stage_punch_profile(
            "peer-b",
            profile.clone(),
            Some(&public_key),
            7,
            expires,
            owner,
        )
        .await;
    assert_eq!(peers.negotiated_profile("peer-b").await, Some(profile));
    assert!(
        peers
            .set_probe_session_id("peer-b", Some("bound-session".into()))
            .await
    );
    let key = peers.probe_key_for_peer("peer-b").await.unwrap();
    let wire = CompactSession::new(&key, "bound-session", "peer-b", "peer-a").unwrap();
    (udp, remote_socket, wire)
}

async fn read_compact(socket: &UdpSocket, session: &CompactSession) -> CompactFrame {
    let mut buffer = [0; 512];
    let (n, _) = timeout(Duration::from_secs(4), socket.recv_from(&mut buffer))
        .await
        .expect("scheduled compact frame")
        .unwrap();
    assert_eq!(n, FRAME_SIZE);
    session.decode(&buffer[..n]).expect("peer and session MAC")
}

#[tokio::test]
async fn negotiated_udp_reader_authenticates_replies_and_requires_two_distinct_challenges() {
    let (udp, remote, wire) = negotiated_receiver(false, |_| {}).await;
    let peers = &udp.peers;
    let lifecycle = peers.peer_session_generation_sync("peer-b").unwrap();
    let generation = peers.current_network_generation_sync();
    let (stop_tx, stop_rx) = watch::channel(false);
    let (tx, _rx) = mpsc::channel(4);
    let inbound = tokio::spawn(udp.clone().run_inbound(tx));
    assert!(
        udp.start_negotiated("peer-b", generation, lifecycle, Some(stop_rx))
            .await
    );
    let dest = udp.local_addr().unwrap();
    let source = remote.local_addr().unwrap();
    let request = CompactFrame {
        kind: FrameKind::Request,
        nominate: false,
        epoch: 1,
        nonce: 29,
    };
    let mut forged = wire.encode(request);
    forged[35] ^= 1;
    remote.send_to(&forged, dest).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while udp.socket_pool_diagnostics().await[0].authenticated_probe_invalid_mac == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("invalid MAC accounted");
    let mut silence = [0; 64];
    assert!(
        timeout(Duration::from_millis(30), remote.recv_from(&mut silence))
            .await
            .is_err()
    );
    let mut challenge = read_compact(&remote, &wire).await;
    assert_eq!(challenge.kind, FrameKind::Request);
    let initial = peers
        .get_connection("peer-b")
        .await
        .unwrap()
        .direct_health
        .success_count;
    let first = wire.encode(CompactFrame {
        kind: FrameKind::Response,
        nominate: false,
        ..challenge
    });
    remote.send_to(&first, dest).await.unwrap();
    let next = read_compact(&remote, &wire).await;
    assert_eq!(next.kind, FrameKind::Request);
    assert_eq!(next.epoch, challenge.epoch);
    assert_ne!(next.nonce, challenge.nonce);
    assert_eq!(
        peers
            .get_connection("peer-b")
            .await
            .unwrap()
            .direct_health
            .success_count,
        initial
    );
    remote.send_to(&first, dest).await.unwrap();
    challenge = next;
    remote
        .send_to(
            &wire.encode(CompactFrame {
                kind: FrameKind::Response,
                nominate: false,
                ..challenge
            }),
            dest,
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(1), async {
        while peers
            .get_connection("peer-b")
            .await
            .unwrap()
            .direct_health
            .success_count
            <= initial
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("second matched response submitted for encrypted validation");
    remote.send_to(&wire.encode(request), dest).await.unwrap();
    let reply = read_compact(&remote, &wire).await;
    assert_eq!(
        reply,
        CompactFrame {
            kind: FrameKind::Response,
            nominate: false,
            ..request
        }
    );
    let diagnostics = peers.diagnostics().await;
    let json = serde_json::to_value(&diagnostics[0]).unwrap();
    assert_eq!(json["remote_nat_profile"]["port_hint"], source.port());
    assert_eq!(json["punch_mode"], 1);
    assert!(json["punch_epoch"].as_u64().unwrap() > 0);
    assert_eq!(json["active_punch_sockets"], 0);
    assert_eq!(json["udp_firewall_status"], "unknown");
    for key in [
        "queue_a_len",
        "queue_b_len",
        "actual_pps",
        "active_path",
        "active_path_type",
        "path_cost",
        "reason_code",
    ] {
        assert!(json.get(key).is_some(), "{key}");
    }
    stop_tx.send(true).unwrap();
    timeout(Duration::from_secs(1), async {
        while peers.current_punch_epoch("peer-b").is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let stopped = peers.diagnostics().await.remove(0);
    assert_eq!(stopped.punch_metrics.queue_a_len, 0);
    assert_eq!(stopped.punch_metrics.queue_b_len, 0);
    assert_eq!(stopped.punch_metrics.active_punch_sockets, 0);
    inbound.abort();
    assert!(inbound.await.unwrap_err().is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn negotiated_round_timeout_releases_pool_lanes_and_all_transport_fds() {
    let (udp, _remote, _wire) =
        negotiated_receiver(true, |c| c.network.traversal.max_punch_sockets = 2).await;
    let udp = udp.with_socket_pool(4).await.unwrap();
    let peers = udp.peers.clone();
    let owner = peers.peer_session_generation_sync("peer-b").unwrap();
    let network = peers.current_network_generation_sync();
    let (_stop, rx) = watch::channel(false);
    assert!(
        udp.start_negotiated("peer-b", network, owner, Some(rx))
            .await
    );
    tokio::task::yield_now().await;
    let initial = peers.current_punch_epoch("peer-b").unwrap();
    tokio::time::advance(Duration::from_millis(250)).await;
    tokio::task::yield_now().await;
    let first = peers.diagnostics().await.remove(0);
    assert_eq!(first.punch_mode, Some(6));
    assert_eq!(first.punch_metrics.active_punch_sockets, 1);
    assert!(first.punch_metrics.queue_a_len + first.punch_metrics.queue_b_len <= 2);
    tokio::time::advance(Duration::from_secs(20)).await;
    tokio::task::yield_now().await;
    assert_eq!(peers.current_punch_epoch("peer-b"), Some(initial + 1));
    tokio::time::advance(Duration::from_secs(100)).await;
    tokio::task::yield_now().await;
    assert!(peers.current_punch_epoch("peer-b").is_none());
    let end = peers.diagnostics().await.remove(0);
    assert_eq!(end.punch_metrics.active_punch_sockets, 0);
    assert_eq!(
        end.punch_metrics.queue_a_len + end.punch_metrics.queue_b_len,
        0
    );
    let bound: Vec<_> = udp
        .active_sockets()
        .iter()
        .map(|s| s.local_addr().unwrap())
        .collect();
    drop(udp);
    for endpoint in bound {
        assert!(
            UdpSocket::bind(endpoint).await.is_ok(),
            "retained socket at {endpoint}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn negotiated_lazy_punch_wakes_for_business_then_stops_for_blocked_observers() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (udp, remote, _wire) = negotiated_receiver(false, |c| {
        c.network.traversal.lazy_p2p = true;
        c.network.traversal.firewall_probe_addresses = vec![silent.local_addr().unwrap()];
    })
    .await;
    let peers = &udp.peers;
    let owner = peers.peer_session_generation_sync("peer-b").unwrap();
    let network = peers.current_network_generation_sync();
    let (_stop, rx) = watch::channel(false);
    assert!(
        udp.start_negotiated("peer-b", network, owner, Some(rx))
            .await
    );
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    let mut buf = [0; 128];
    assert!(remote.try_recv(&mut buf).is_err());
    assert_eq!(peers.diagnostics().await[0].punch_metrics.actual_pps, 0);
    peers.record_sent("peer-b", 100).await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(2250)).await;
    tokio::task::yield_now().await;
    // Observe a real compact request before the first firewall interval.
    assert_eq!(remote.recv(&mut buf).await.unwrap(), FRAME_SIZE);
    let initial = peers.current_punch_epoch("peer-b").unwrap();
    tokio::time::advance(Duration::from_secs(8)).await;
    assert!(silent.recv(&mut buf).await.unwrap() >= 20);
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let status = peers.diagnostics().await.remove(0);
    assert_eq!(
        status.udp_firewall_status,
        p2pnet_nat::engine::UdpReachability::Blocked
    );
    assert_eq!(status.reason_code.as_deref(), Some("UDP_BLOCKED"));
    assert!(status.punch_metrics.punch_epoch > initial);
    assert_eq!(
        status.punch_metrics.queue_a_len + status.punch_metrics.queue_b_len,
        0
    );
    assert!(peers.current_punch_epoch("peer-b").is_none());
    assert!(peers
        .claim_punch_run("peer-b", network, owner)
        .await
        .is_none());
    peers.record_sent("peer-b", 100).await;
    assert!(peers
        .claim_punch_run("peer-b", network, owner)
        .await
        .is_some());
}
