use super::negotiated_relay::LocalTlsRelay;
use super::*;
use crate::config::{PathPolicy, TcpDirectConfig};
use crate::dataplane::{InboundPacket, OutboundPacket};
use crate::peer::NetworkPath;
use crate::relay::RelayTransport;
use std::collections::BTreeMap;
use tokio::net::TcpListener;

const IDS: [&str; 2] = ["tcp-a", "tcp-b"];
const IPS: [&str; 2] = ["10.20.0.1", "10.20.0.2"];

struct Node {
    manager: Arc<PeerManager>,
    wg: WireGuardTransport,
    relay: RelayTransport,
    encrypted: mpsc::Receiver<ReceivedEncryptedPacket>,
    decrypt: mpsc::Sender<ReceivedEncryptedPacket>,
    plaintext: mpsc::Receiver<InboundPacket>,
}

impl Node {
    async fn expect_packet(&mut self, remote: &str, expected: &[u8], path: NetworkPath) {
        let packet = timeout(Duration::from_secs(3), self.encrypted.recv())
            .await
            .unwrap()
            .unwrap();
        let link = packet.physical_ingress.as_ref().and_then(|p| p.tcp_link());
        assert_eq!(link.is_some(), path == NetworkPath::TcpDirect);
        assert_eq!(packet.relay_endpoint.is_some(), path == NetworkPath::Relay);
        assert!(packet.source.is_none() && packet.udp_transport_owner.is_none());
        if let Some(id) = link {
            assert!(self.manager.tcp_ingress_current(remote, id).await);
            assert!(!self.manager.tcp_ingress_current("different-peer", id).await);
        }
        self.decrypt.send(packet).await.unwrap();
        let delivered = timeout(Duration::from_secs(3), self.plaintext.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(delivered.peer_id, remote);
        assert_eq!(delivered.packet, expected);
    }
}

fn business(i: usize, n: u16) -> OutboundPacket {
    let j = 1 - i;
    let bytes = Ipv4Packet::build_icmp_echo_request(
        IPS[i].parse().unwrap(),
        IPS[j].parse().unwrap(),
        i as u16,
        n,
        &n.to_be_bytes(),
    );
    OutboundPacket {
        room_authorization: None,
        peer_id: IDS[j].to_owned(),
        dst_ip: IPS[j].into(),
        packet: bytes,
        trace: None,
    }
}

async fn exchange(nodes: &mut [Node], n: u16, path: NetworkPath) {
    for i in 0..2 {
        let j = 1 - i;
        let packet = business(i, n);
        let generation = nodes[i].manager.current_network_generation_sync();
        assert!(
            crate::network_outbound::send_original_slow_for_test(
                packet.clone().into(),
                &nodes[i].wg,
                &nodes[i].manager,
                generation,
                true,
                &tokio::sync::RwLock::new(None),
                &tokio::sync::RwLock::new(Some(nodes[i].relay.clone())),
                true
            )
            .await
        );
        nodes[j].expect_packet(IDS[i], &packet.packet, path).await;
    }
}

#[tokio::test]
async fn negotiated_configured_tcp_carries_wg_then_returns_to_tls_relay() {
    tcp_business([false, false]).await;
}

#[tokio::test]
async fn negotiated_simultaneous_tcp_carries_wg_then_returns_to_tls_relay() {
    tcp_business([true, true]).await;
}

#[tokio::test]
async fn negotiated_tcp_legacy_peer_uses_the_authenticated_ordinary_stream() {
    tcp_business([true, false]).await;
}

async fn tcp_business(enabled: [bool; 2]) {
    let simultaneous = enabled == [true, true];
    let mut tasks = JoinSet::new();
    let server = LocalTlsRelay::start().await;
    let endpoint = server.endpoint();
    let reservations = [
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
        TcpListener::bind("127.0.0.1:0").await.unwrap(),
    ];
    let addresses = reservations.each_ref().map(|s| s.local_addr().unwrap());
    let silent_observer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let keys = [NodeIdentity::generate(), NodeIdentity::generate()];
    let mut initiator = HandshakeInitiator::new(keys[0].clone(), keys[1].public_key(), None);
    let mut responder = HandshakeResponder::new(keys[1].clone(), None);
    let initiation = initiator.create_initiation().unwrap();
    let (reply, server_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let a = TransportSession::new(initiator.consume_response(&reply).unwrap());
    let b = TransportSession::new(server_keys);
    let stop = [watch::channel(false).0, watch::channel(false).0];
    let mut nodes = Vec::new();
    let mut sinks = Vec::new();
    for (i, session) in [a, b].into_iter().enumerate() {
        let j = 1 - i;
        let mut config = config_for_identity(&keys[i], IDS[i]);
        config.relay.path_policy = PathPolicy::Auto;
        config.network.traversal.firewall_probe_addresses =
            vec![silent_observer.local_addr().unwrap()];
        config.network.tcp_direct = Some(TcpDirectConfig {
            listen: addresses[i],
            advertise: None,
            simultaneous_open: enabled[i],
            peers: BTreeMap::from([(IDS[j].into(), addresses[j])]),
        });
        let manager = Arc::new(PeerManager::new(config));
        manager
            .add_peer(&peer_with_public_key(
                IDS[j],
                IPS[j],
                hex::encode(keys[j].public_key()),
                None,
            ))
            .await;
        manager
            .set_probe_session_id(IDS[j], Some("direct-tcp-session".into()))
            .await;
        let (relay, messages) = RelayTransport::connect_secure(
            &endpoint,
            "local",
            IDS[i],
            manager.clone(),
            Some(server.ticket(IDS[i])),
            false,
            Some(server.cert.path().to_str().unwrap().into()),
        )
        .await
        .unwrap();
        manager.configure_relay_first(true).await;
        manager
            .mark_relay_transport_ready_with_transport(
                IDS[j],
                &endpoint,
                manager.current_network_generation_sync(),
                Some(relay.connection_id()),
            )
            .await;
        let (wg, _) = WireGuardTransport::new();
        wg.add_session(IDS[j], session).await;
        assert!(wg.has_session(IDS[j]).await);
        let (tx, encrypted) = mpsc::channel(8);
        let (decrypt, to_wg) = mpsc::channel(8);
        let (plain, plaintext) = mpsc::channel(8);
        let relay_reader = relay.clone();
        let relay_sink = tx.clone();
        tasks.spawn(async move {
            relay_reader
                .run_inbound(messages, relay_sink, None)
                .await
                .unwrap();
        });
        let (reader, owner) = (wg.clone(), manager.clone());
        let evidence = crate::transport::InboundEvidenceFeed {
            relay_transport: Arc::new(tokio::sync::RwLock::new(Some(relay.clone()))),
            timeline: None,
            overlay_ingress_tx: None,
        };
        tasks.spawn(async move {
            let (_published, udp) = watch::channel(None);
            reader
                .run_inbound_with_peers_live_udp_and_relay(
                    to_wg,
                    plain,
                    Some(owner),
                    udp,
                    Some(evidence),
                )
                .await
                .unwrap();
        });
        sinks.push(tx);
        nodes.push(Node {
            manager,
            wg,
            relay,
            encrypted,
            decrypt,
            plaintext,
        });
    }
    // Bootstrap through the real TLS readers and normal WG decrypt worker.
    // Only authenticated plaintext observed at the receiver can confirm Relay.
    for i in [0, 1] {
        let packet = business(i, 0);
        let wire = nodes[i]
            .wg
            .encrypt_outbound(packet.clone())
            .await
            .unwrap()
            .unwrap();
        nodes[i].relay.send_packet(&wire).await.unwrap();
        nodes[1 - i]
            .expect_packet(IDS[i], &packet.packet, NetworkPath::Relay)
            .await;
    }
    exchange(&mut nodes, 1, NetworkPath::Relay).await;
    for node in &nodes {
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), node.manager.clone())
            .await
            .unwrap();
        assert_eq!(
            udp.firewall_verdict(node.manager.current_network_generation_sync())
                .await,
            p2pnet_nat::engine::UdpReachability::Blocked
        );
        let mut buf = [0; 512];
        let n = timeout(Duration::from_secs(1), silent_observer.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            StunMessage::decode(&buf[..n]).unwrap().msg_type,
            p2pnet_nat::BINDING_REQUEST
        );
    }
    // No UDP transport is installed. The initial signal has no measured UDP
    // profile. Both listeners must publish before a TCP-only offer is possible.
    drop(reservations);
    for (i, tx) in sinks.into_iter().enumerate() {
        tasks.spawn(crate::peer::tcp_direct::serve(
            nodes[i].manager.clone(),
            IDS[i].into(),
            IPS[i].into(),
            Arc::new(crate::rooms::RoomAuthorization::new("default")),
            tx.into(),
            stop[i].subscribe(),
        ));
    }
    for i in 0..2 {
        let j = 1 - i;
        let offer = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(offer) =
                    nodes[i]
                        .manager
                        .punch_profile_for_peer_signal(IDS[j], &[], &Default::default())
                {
                    break offer;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(offer.tcp_candidates, vec![addresses[i]]);
        assert_eq!(
            offer.tcp_simultaneous_open,
            enabled[i]
                && cfg!(any(
                    target_vendor = "apple",
                    target_os = "linux",
                    target_os = "android",
                    target_os = "freebsd"
                ))
        );
        assert_eq!(offer.port_hint, 0);
        assert!(!offer.supports_sym_punch);
        assert!(nodes[i]
            .manager
            .punch_profile_for_peer_signal("unlisted", &[], &Default::default())
            .is_none());
        let remote = &nodes[j].manager;
        let expiry = Some(crate::gateway_mapping::now_ms() + 60_000);
        remote
            .add_candidates_with_metadata(IDS[i], &[], &Default::default(), 1, expiry)
            .await;
        remote
            .stage_candidate_punch_signal(
                IDS[i],
                (Some(offer), true),
                Some(&hex::encode(keys[i].public_key())),
                1,
                expiry,
                (
                    remote.current_network_generation_sync(),
                    remote.peer_session_generation_sync(IDS[i]),
                ),
            )
            .await;
        assert!(
            remote.negotiated_profile(IDS[i]).await.is_some(),
            "TCP-only offer must survive an empty UDP candidate list"
        );
    }
    let a = nodes[0]
        .manager
        .probe_key_and_session_for_peer(IDS[1])
        .await
        .unwrap();
    let b = nodes[1]
        .manager
        .probe_key_and_session_for_peer(IDS[0])
        .await
        .unwrap();
    assert!(
        a == b && a.1.is_some(),
        "peers must share the same authenticated probe session"
    );
    let ready = timeout(Duration::from_secs(8), async {
        loop {
            let mut ready = true;
            for i in 0..2 {
                ready &= nodes[i]
                    .manager
                    .select_path_for_data(IDS[1 - i], true, true)
                    .await
                    .path
                    == Some(NetworkPath::TcpDirect);
            }
            if ready {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if ready.is_err() {
        for i in 0..2 {
            let manager = &nodes[i].manager;
            let conn = manager.get_connection(IDS[1 - i]).await.unwrap();
            let diag = manager.diagnostics().await.remove(0);
            eprintln!("peer {i}: tcp={:?} relay_confirmed={:?} sent={:?} received={:?} exchange={:?} gate={:?} reason={:?}",
                conn.tcp_path, conn.relay_confirmed_generation, diag.relay_first_business_sent_generation,
                diag.relay_first_business_received_generation, diag.relay_first_business_exchange_generation,
                diag.relay_first_business_gate_completed_generation, diag.reason_code);
        }
        panic!("authorized TCP stream did not become usable");
    }
    let mut endpoints = Vec::new();
    let mut openings = Vec::new();
    for i in 0..2 {
        let conn = nodes[i].manager.get_connection(IDS[1 - i]).await.unwrap();
        let path = conn.tcp_path.unwrap();
        endpoints.push(path.socket_endpoints().unwrap());
        openings.push(path.opening);
    }
    assert_eq!(openings[0], openings[1]);
    assert_eq!(endpoints[0], (endpoints[1].1, endpoints[1].0));
    use crate::peer::tcp_direct::TcpOpening;
    if simultaneous && std::env::var_os("P2WLAN_TEST_REQUIRE_TCP_SIMULTANEOUS").is_some() {
        assert_eq!(
            openings[0],
            TcpOpening::Simultaneous,
            "both active sockets must carry the business traffic"
        );
    }
    if openings[0] == TcpOpening::Simultaneous {
        assert!(simultaneous);
        assert_eq!(endpoints[0], (addresses[0], addresses[1]));
    } else {
        assert_ne!(endpoints[0].0, addresses[0]);
        assert_eq!(endpoints[0].1, addresses[1]);
    }
    let (_, diagnostics) = nodes[0]
        .manager
        .diagnostic_with_path_selection(IDS[1], true, true, Duration::from_secs(1), None)
        .await
        .unwrap();
    assert_eq!(diagnostics.active_path_type.as_deref(), Some("tcp_direct"));
    assert_eq!(
        diagnostics.tcp_open_method.as_deref(),
        Some(match openings[0] {
            TcpOpening::DialListen => "dial_listen",
            TcpOpening::Simultaneous => "simultaneous",
        })
    );
    assert_eq!(diagnostics.path_cost, Some(4));
    assert!(
        crate::network_outbound::send_original_slow_for_test(
            business(0, 99).into(),
            &nodes[0].wg,
            &nodes[0].manager,
            nodes[0].manager.current_network_generation_sync(),
            true,
            &tokio::sync::RwLock::new(None),
            &tokio::sync::RwLock::new(Some(nodes[0].relay.clone())),
            true
        )
        .await
    );
    let stale = timeout(Duration::from_secs(1), nodes[1].encrypted.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(stale
        .physical_ingress
        .as_ref()
        .and_then(|p| p.tcp_link())
        .is_some());

    // Application traffic owns this clock. The sender never polls routing or
    // waits for path retirement before submitting the next numbered packet.
    let mut cadence = tokio::time::interval(Duration::from_millis(20));
    cadence.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    for sequence in 2..=5 {
        cadence.tick().await;
        exchange(&mut nodes, sequence, NetworkPath::TcpDirect).await;
    }
    let disconnected = Instant::now();
    stop[1].send_replace(true);
    cadence.tick().await;
    exchange(&mut nodes, 6, NetworkPath::Relay).await;
    let fallback = disconnected.elapsed();
    // This captured wire packet belongs to the retired reader. If delivered,
    // it would appear before the next numbered plaintext on this same tunnel.
    nodes[1].decrypt.send(stale).await.unwrap();
    for sequence in 7..=11 {
        cadence.tick().await;
        exchange(&mut nodes, sequence, NetworkPath::Relay).await;
    }
    let (_, recovered) = nodes[0]
        .manager
        .diagnostic_with_path_selection(IDS[1], true, true, Duration::from_secs(1), None)
        .await
        .unwrap();
    assert_eq!(recovered.active_path_type.as_deref(), Some("tls_relay"));
    assert!(recovered.tcp_open_method.is_none());
    eprintln!("TCP open measurement enabled={simultaneous} left={:?} right={:?} left_socket={}→{} right_socket={}→{} decrypted_per_direction=12", openings[0], openings[1], endpoints[0].0, endpoints[0].1, endpoints[1].0, endpoints[1].1);
    eprintln!("TLS Relay → configured direct TCP → TLS Relay: 12 numbered WireGuard payloads decrypted per direction; first post-disconnect pair on the 20 ms cadence delivered in {} ms", fallback.as_millis());
    tasks.shutdown().await;
    for node in nodes {
        node.relay.abort_writer();
    }
    server.server.shutdown().await;
}

#[tokio::test]
async fn negotiated_tcp_only_revisions_bind_pin_identity_expiry_and_withdrawal() {
    let pin: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    let keys = [NodeIdentity::generate(), NodeIdentity::generate()];
    let mut config = config_for_identity(&keys[0], IDS[0]);
    config.network.tcp_direct = Some(TcpDirectConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        advertise: None,
        simultaneous_open: false,
        peers: BTreeMap::from([(IDS[1].into(), pin)]),
    });
    let manager = PeerManager::new(config);
    let public = hex::encode(keys[1].public_key());
    manager
        .add_peer(&peer_with_public_key(IDS[1], IPS[1], public.clone(), None))
        .await;
    let offer = |addr| {
        Some(p2pnet_nat::engine::PunchProfile {
            tcp_candidates: vec![addr],
            ..Default::default()
        })
    };
    let owner = (
        manager.current_network_generation_sync(),
        manager.peer_session_generation_sync(IDS[1]),
    );
    let expiry = Some(crate::gateway_mapping::now_ms() + 15_000);
    for (endpoint, key, rev, expires, empty) in [
        (
            "127.0.0.1:4243".parse().unwrap(),
            public.as_str(),
            8,
            expiry,
            true,
        ),
        (pin, "retired-key", 8, expiry, true),
        (pin, public.as_str(), 8, Some(1), true),
        (pin, public.as_str(), 0, expiry, true),
        (pin, public.as_str(), 8, expiry, false),
    ] {
        manager
            .stage_candidate_punch_signal(
                IDS[1],
                (offer(endpoint), empty),
                Some(key),
                rev,
                expires,
                owner,
            )
            .await;
        assert!(manager.negotiated_profile(IDS[1]).await.is_none());
    }
    manager
        .stage_candidate_punch_signal(IDS[1], (offer(pin), true), Some(&public), 8, expiry, owner)
        .await;
    assert!(manager.negotiated_profile(IDS[1]).await.unwrap().tcp_only());
    for rev in [7, 8] {
        manager
            .stage_candidate_punch_signal(IDS[1], (None, true), Some(&public), rev, expiry, owner)
            .await;
        assert!(manager.negotiated_profile(IDS[1]).await.is_some());
    }
    manager
        .stage_candidate_punch_signal(IDS[1], (None, true), Some(&public), 9, expiry, owner)
        .await;
    for rev in [8, 9] {
        manager
            .stage_candidate_punch_signal(
                IDS[1],
                (offer(pin), true),
                Some(&public),
                rev,
                expiry,
                owner,
            )
            .await;
        assert!(manager.negotiated_profile(IDS[1]).await.is_none());
    }
}
