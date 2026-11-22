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
async fn negotiated_round_releases_real_temporary_ports_while_transport_remains_bound() {
    let (udp, remote, _) =
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
    assert_eq!(first.punch_metrics.active_punch_sockets, 0);
    assert!(first.punch_metrics.queue_a_len + first.punch_metrics.queue_b_len <= 2);
    async fn alternate_port(remote: &UdpSocket, primary: SocketAddr) -> SocketAddr {
        let mut bytes = [0; 128];
        timeout(Duration::from_secs(3), async {
            loop {
                let (n, src) = remote.recv_from(&mut bytes).await.unwrap();
                if src != primary && n == FRAME_SIZE {
                    break src;
                }
            }
        })
        .await
        .expect("datagram from actual temporary socket")
    }
    let primary = udp.local_addr().unwrap();
    tokio::time::advance(Duration::from_secs(5)).await;
    let first_port = alternate_port(&remote, primary).await;
    assert!(UdpSocket::bind(first_port).await.is_err());
    assert_eq!(
        peers.diagnostics().await[0]
            .punch_metrics
            .active_punch_sockets,
        1
    );
    assert_eq!(udp.negotiated_socket_slots.available_permits(), 0);
    tokio::time::advance(Duration::from_secs(15)).await;
    tokio::task::yield_now().await;
    assert_eq!(peers.current_punch_epoch("peer-b"), Some(initial + 1));
    let rebound = UdpSocket::bind(first_port)
        .await
        .expect("old FD closed at epoch change");
    assert_eq!(udp.negotiated_socket_slots.available_permits(), 1);
    tokio::time::advance(Duration::from_secs(6)).await;
    let second = alternate_port(&remote, primary).await;
    assert_ne!(second, rebound.local_addr().unwrap());
    assert!(UdpSocket::bind(second).await.is_err());
    tokio::time::advance(Duration::from_secs(100)).await;
    tokio::task::yield_now().await;
    assert!(peers.current_punch_epoch("peer-b").is_none());
    assert!(
        UdpSocket::bind(second).await.is_ok(),
        "timeout kept the unpromoted FD"
    );
    assert!(
        UdpSocket::bind(primary).await.is_err(),
        "main transport should still be live"
    );
    assert_eq!(udp.negotiated_socket_slots.available_permits(), 1);
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

#[tokio::test]
async fn negotiated_alternate_port_requires_distinct_matching_answers_on_the_same_socket() {
    let (udp, remote, wire) = negotiated_receiver(true, |_| {}).await;
    let (tx, _rx) = mpsc::channel(4);
    let udp = udp.with_inbound_channel(tx.clone());
    let main = udp.local_addr().unwrap();
    let peers = &udp.peers;
    let reader = tokio::spawn(udp.clone().run_inbound(tx));
    let (stop, running) = watch::channel(false);
    assert!(
        udp.start_negotiated(
            "peer-b",
            peers.current_network_generation_sync(),
            peers.peer_session_generation_sync("peer-b").unwrap(),
            Some(running)
        )
        .await
    );
    async fn next(
        socket: &UdpSocket,
        wire: &CompactSession,
        main: SocketAddr,
        stage: &str,
    ) -> (CompactFrame, SocketAddr) {
        let mut packet = [0; 256];
        timeout(Duration::from_secs(7), async {
            loop {
                let (n, source) = socket.recv_from(&mut packet).await.unwrap();
                if source != main {
                    if let Some(frame) = wire.decode(&packet[..n]) {
                        if frame.kind == FrameKind::Request {
                            break (frame, source);
                        }
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("missing {stage} challenge from alternate port"))
    }
    let (first, alternate) = next(&remote, &wire, main, "first").await;
    let reverse = CompactFrame {
        kind: FrameKind::Request,
        nominate: false,
        epoch: 1,
        nonce: 331,
    };
    remote
        .send_to(&wire.encode(reverse), alternate)
        .await
        .unwrap();
    let mut packet = [0; 128];
    timeout(Duration::from_secs(1), async {
        loop {
            let (n, addr) = remote.recv_from(&mut packet).await.unwrap();
            if addr == alternate {
                assert_eq!(
                    wire.decode(&packet[..n]),
                    Some(CompactFrame {
                        kind: FrameKind::Response,
                        ..reverse
                    })
                );
                break;
            }
        }
    })
    .await
    .expect("return proof from the contacted alternate port");
    assert_eq!(udp.dynamic_socket_count().await, 0);
    let answer = |request: CompactFrame| {
        wire.encode(CompactFrame {
            kind: FrameKind::Response,
            nominate: false,
            ..request
        })
    };
    let wrong_source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    wrong_source
        .send_to(&answer(first), alternate)
        .await
        .unwrap();
    remote
        .send_to(
            &answer(CompactFrame {
                nonce: first.nonce.wrapping_add(10),
                ..first
            }),
            alternate,
        )
        .await
        .unwrap();
    remote.send_to(&answer(first), alternate).await.unwrap();
    let (second, source) = next(&remote, &wire, main, "confirmation").await;
    assert_eq!(source, alternate);
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(udp.dynamic_socket_count().await, 0);
    remote.send_to(&answer(first), alternate).await.unwrap();
    sleep(Duration::from_millis(30)).await;
    assert_eq!(udp.dynamic_socket_count().await, 0);
    remote.send_to(&answer(second), alternate).await.unwrap();
    let (third, source) = next(&remote, &wire, main, "registered reader").await;
    assert_eq!(source, alternate);
    assert_ne!(third.nonce, second.nonce);
    assert!(udp.dynamic_socket_index_for_peer("peer-b").await.is_some());
    assert_eq!(
        peers.diagnostics().await[0]
            .punch_metrics
            .active_punch_sockets,
        0
    );
    remote.send_to(&answer(third), alternate).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while peers
            .get_connection("peer-b")
            .await
            .unwrap()
            .direct_health
            .success_count
            == 0
        {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("normal socket reader accepted the registered pair");
    stop.send_replace(true);
    reader.abort();
    assert!(reader.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn negotiated_udp_block_preserves_bidirectional_business_on_authenticated_tls_relay() {
    use super::negotiated_relay::TlsRelayPair;
    use p2pnet_nat::engine::UdpReachability;
    let mut relay = TlsRelayPair::connect(["peer-a", "peer-b"]).await;
    let (a, b) = establish_sessions();
    let mut wg = [a, b];
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (udp, remote, _wire) = negotiated_receiver(false, |c| {
        c.network.traversal.firewall_probe_addresses = vec![silent.local_addr().unwrap()];
    })
    .await;
    let peers = &udp.peers;
    let network = peers.current_network_generation_sync();
    let owner = peers.peer_session_generation_sync("peer-b").unwrap();
    relay.exchange(&mut wg, 0, b"relay before discovery").await;
    assert!(
        peers
            .confirm_relay_peer_from_business_ingress("peer-b", &relay.endpoint, network, None)
            .await
    );
    let (stop, _) = watch::channel(false);
    assert!(
        udp.start_negotiated("peer-b", network, owner, Some(stop.subscribe()))
            .await
    );
    let mut sequence = 0u16;
    let start = tokio::time::Instant::now();
    timeout(Duration::from_secs(15), async {
        loop {
            assert_eq!(
                peers.select_path_for_data("peer-b", true, true).await.path,
                Some(crate::peer::NetworkPath::Relay)
            );
            sequence += 1;
            relay
                .exchange(&mut wg, sequence, b"numbered packet during UDP outage")
                .await;
            peers.record_sent("peer-b", 64).await;
            let diagnostic = peers.diagnostics().await.remove(0);
            if diagnostic.udp_firewall_status == UdpReachability::Blocked {
                assert_eq!(diagnostic.reason_code.as_deref(), Some("UDP_BLOCKED"));
                break;
            }
            sleep(Duration::from_millis(120)).await;
        }
    })
    .await
    .expect("configured observer timed out and published UDP_BLOCKED");
    assert!(start.elapsed() >= Duration::from_secs(10));
    let mut packet = [0; 256];
    let len = silent.try_recv(&mut packet).unwrap();
    assert_eq!(
        StunMessage::decode(&packet[..len]).unwrap().msg_type,
        p2pnet_nat::stun::BINDING_REQUEST
    );
    assert_eq!(remote.try_recv(&mut packet).unwrap(), FRAME_SIZE);
    while let Ok(size) = remote.try_recv(&mut packet) {
        assert_eq!(size, FRAME_SIZE);
    }
    peers.record_sent("peer-b", 64).await;
    assert!(
        udp.start_negotiated("peer-b", network, owner, Some(stop.subscribe()))
            .await
    );
    for _ in 0..5 {
        sequence += 1;
        assert_eq!(
            peers.select_path_for_data("peer-b", true, true).await.path,
            Some(crate::peer::NetworkPath::Relay)
        );
        relay
            .exchange(&mut wg, sequence, b"numbered packet after fallback")
            .await;
        sleep(Duration::from_millis(60)).await;
    }
    assert_eq!(
        remote.try_recv(&mut packet).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    eprintln!("UDP_BLOCKED; exchanged {sequence} numbered WireGuard payload pairs over TLS relay");
    stop.send_replace(true);
    relay.shutdown().await;
}

#[tokio::test]
async fn negotiated_blocked_network_shares_one_observation_and_recovers_on_valid_stun() {
    use p2pnet_nat::engine::UdpReachability;
    let observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (udp, _, _) = negotiated_receiver(false, |c| {
        c.network.traversal.firewall_probe_addresses = vec![observer.local_addr().unwrap()];
    })
    .await;
    let network = udp.peers.current_network_generation_sync();
    let (first, second) =
        tokio::join!(udp.firewall_verdict(network), udp.firewall_verdict(network));
    assert_eq!(
        (first, second),
        (UdpReachability::Blocked, UdpReachability::Blocked)
    );
    let mut packet = [0; 128];
    assert!(observer.recv(&mut packet).await.unwrap() >= 20);
    assert_eq!(
        observer.try_recv(&mut packet).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    tokio::time::sleep_until(udp.blocked_recheck_at(network).unwrap()).await;
    let answer = async {
        let (n, source) = observer.recv_from(&mut packet).await.unwrap();
        let query = StunMessage::decode(&packet[..n]).unwrap();
        let mut reply = StunMessage::with_transaction_id(BINDING_RESPONSE, query.transaction_id);
        reply.add_attribute(StunAttribute::XorMappedAddress(source));
        observer.send_to(&reply.encode(), source).await.unwrap();
    };
    let ((), first, second) = tokio::join!(
        answer,
        udp.firewall_verdict(network),
        udp.firewall_verdict(network)
    );
    assert_eq!(
        (first, second),
        (UdpReachability::Available, UdpReachability::Available)
    );
    assert!(udp.blocked_recheck_at(network).is_none());
    assert_eq!(
        observer.try_recv(&mut packet).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test(start_paused = true)]
async fn negotiated_single_socket_budget_and_cancellation_release() {
    for budget in [0, 1, 2, 250] {
        let (udp, remote, _) =
            negotiated_receiver(true, |c| c.network.traversal.max_punch_sockets = budget).await;
        let peers = &udp.peers;
        let (stop, rx) = watch::channel(false);
        assert!(
            udp.start_negotiated(
                "peer-b",
                peers.current_network_generation_sync(),
                peers.peer_session_generation_sync("peer-b").unwrap(),
                Some(rx)
            )
            .await
        );
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(250)).await;
        tokio::time::advance(Duration::from_secs(5)).await;
        for _ in 0..8 {
            tokio::time::advance(Duration::from_millis(10)).await;
        }
        let mut packet = [0; 128];
        let primary = udp.local_addr().unwrap();
        let mut sources = std::collections::HashSet::new();
        while let Ok((n, addr)) = remote.try_recv_from(&mut packet) {
            assert_eq!(n, FRAME_SIZE);
            sources.insert(addr);
        }
        assert!(sources.remove(&primary));
        assert_eq!(sources.len(), usize::from(budget > 1));
        assert_eq!(
            peers.diagnostics().await[0]
                .punch_metrics
                .active_punch_sockets,
            sources.len()
        );
        stop.send_replace(true);
        tokio::task::yield_now().await;
        assert!(peers.current_punch_epoch("peer-b").is_none());
        for source in sources {
            UdpSocket::bind(source)
                .await
                .expect("cancellation released the actual alternate port");
        }
        assert_eq!(
            udp.negotiated_socket_slots.available_permits(),
            usize::from(budget.min(30).saturating_sub(1))
        );
        let metrics = &peers.diagnostics().await[0].punch_metrics;
        assert_eq!(
            (
                metrics.active_punch_sockets,
                metrics.queue_a_len,
                metrics.queue_b_len
            ),
            (0, 0, 0)
        );
    }
}

#[tokio::test]
async fn negotiated_concurrent_peers_share_the_transport_socket_limit() {
    use super::super::negotiated_socket::RoundSocket;
    for (configured, spare) in [(3, 2usize), (250, 29)] {
        let (udp, _primary_peer, _) =
            negotiated_receiver(true, |c| c.network.traversal.max_punch_sockets = configured).await;
        let peers = &udp.peers;
        let network = peers.current_network_generation_sync();
        let profile = peers.negotiated_profile("peer-b").await.unwrap();
        let mut owners = Vec::new();
        for i in 0..=spare {
            let peer = format!("budget-peer-{i}");
            let key = hex::encode(NodeIdentity::generate().public_key());
            let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let endpoint = remote.local_addr().unwrap();
            let address = endpoint.to_string();
            let expires = Some(crate::gateway_mapping::now_ms() + 45_000);
            peers
                .add_peer(&peer_with_public_key(
                    &peer,
                    &format!("10.20.1.{}", i + 1),
                    key.clone(),
                    Some(endpoint),
                ))
                .await;
            peers
                .add_candidates_with_metadata(
                    &peer,
                    std::slice::from_ref(&address),
                    &HashMap::from([(address.clone(), "host".into())]),
                    1,
                    expires,
                )
                .await;
            let lifecycle = peers.peer_session_generation_sync(&peer).unwrap();
            peers
                .stage_punch_profile(
                    &peer,
                    PunchProfile {
                        port_hint: endpoint.port(),
                        ..profile.clone()
                    },
                    Some(&key),
                    1,
                    expires,
                    (network, Some(lifecycle)),
                )
                .await;
            let run = peers
                .claim_punch_run(&peer, network, lifecycle)
                .await
                .unwrap();
            owners.push((peer, run, remote));
        }
        let mut participants = JoinSet::new();
        for (peer, run, remote) in &owners {
            let (udp, peer, address, run) = (
                udp.clone(),
                peer.clone(),
                remote.local_addr().unwrap(),
                run.clone(),
            );
            participants.spawn(async move {
                RoundSocket::open(&udp, &peer, &run, run.pacer.epoch(), address).await
            });
        }
        let mut sockets = Vec::new();
        while let Some(participant) = participants.join_next().await {
            if let Some(socket) = participant.unwrap() {
                sockets.push(socket);
            }
        }
        assert_eq!(sockets.len(), spare);
        assert_eq!(udp.negotiated_socket_slots.available_permits(), 0);
        assert_eq!(
            owners
                .iter()
                .map(|(_, run, _)| run.sockets.load(Ordering::Acquire))
                .sum::<usize>(),
            spare
        );
        drop(sockets);
        assert_eq!(udp.negotiated_socket_slots.available_permits(), spare);
        assert!(owners
            .iter()
            .all(|(_, run, _)| run.sockets.load(Ordering::Acquire) == 0));
    }
}
