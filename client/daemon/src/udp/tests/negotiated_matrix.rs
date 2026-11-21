//! Loopback-only gateways with real UDP sockets. A datagram addressed to an
//! outside mapping is routed from the sender's destination-specific mapping
//! only when the receiver's NAT filter admits that source tuple.
use super::*;
use p2pnet_nat::engine::{NatKind, PunchProfile};
use p2pnet_relay::{RelayClient, RelayMessage, RelayServer};

const PEERS: [&str; 2] = ["matrix-a", "matrix-b"];
const VIP: [&str; 2] = ["10.20.0.1", "10.20.0.2"];

struct Gateway {
    nat: NatKind,
    sockets: Vec<Arc<UdpSocket>>,
    destinations: std::sync::Mutex<Vec<SocketAddr>>,
}

impl Gateway {
    async fn new(nat: NatKind) -> Self {
        // Reserve a contiguous block locally so the measured linear steps are
        // independent of the host kernel's ephemeral-port allocator.
        for _ in 0..32 {
            let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let base = first.local_addr().unwrap().port();
            if base > 65527 {
                continue;
            }
            let mut sockets = vec![Arc::new(first)];
            for i in 1..8 {
                if let Ok(s) = UdpSocket::bind((Ipv4Addr::LOCALHOST, base + i)).await {
                    sockets.push(Arc::new(s));
                } else {
                    break;
                }
            }
            if sockets.len() == 8 {
                return Self {
                    nat,
                    sockets,
                    destinations: Default::default(),
                };
            }
        }
        panic!("loopback NAT fixture could not reserve eight local ports")
    }

    fn port_index(&self, allocation: usize) -> usize {
        match self.nat {
            NatKind::Cone => 0,
            NatKind::LinearSymmetric => allocation,
            NatKind::RandomSymmetric => [0, 3, 1, 6, 4, 2, 7, 5][allocation],
            NatKind::None => unreachable!("matrix gateways all perform NAT"),
        }
    }

    fn outbound(&self, to: SocketAddr) -> Arc<UdpSocket> {
        let mut destinations = self.destinations.lock().unwrap();
        let index = destinations
            .iter()
            .position(|dest| *dest == to)
            .unwrap_or_else(|| {
                destinations.push(to);
                destinations.len() - 1
            });
        self.sockets[self.port_index(index)].clone()
    }

    fn admits(&self, index: usize, from: SocketAddr) -> bool {
        let destinations = self.destinations.lock().unwrap();
        if self.nat == NatKind::Cone {
            return index == 0 && !destinations.is_empty();
        }
        destinations
            .iter()
            .position(|addr| *addr == from)
            .is_some_and(|pos| self.port_index(pos) == index)
    }
}

struct LoopbackNetwork {
    gateways: [Gateway; 2],
    inside: [SocketAddr; 2],
    transit: Duration,
    lose_first_challenge: bool,
    lost: [std::sync::atomic::AtomicBool; 2],
    stop_direct: std::sync::atomic::AtomicBool,
    requests: std::sync::atomic::AtomicUsize,
}

impl LoopbackNetwork {
    async fn run(self: &Arc<Self>, tasks: &mut JoinSet<()>) -> Vec<SocketAddr> {
        for side in 0..2 {
            for (index, public) in self.gateways[side].sockets.iter().enumerate() {
                let public = public.clone();
                let net = self.clone();
                tasks.spawn(async move {
                    let mut packet = [0; 2048];
                    while let Ok((size, inside_from)) = public.recv_from(&mut packet).await {
                        let sender = 1 - side;
                        if inside_from != net.inside[sender] {
                            continue;
                        }
                        let challenge = size == p2pnet_nat::engine::FRAME_SIZE
                            && packet[..size].starts_with(b"P3")
                            && packet[2] == 1;
                        if challenge {
                            net.requests.fetch_add(1, Ordering::Relaxed);
                        }
                        let source = net.gateways[sender].outbound(public.local_addr().unwrap());
                        if net.stop_direct.load(Ordering::Acquire)
                            || !net.gateways[side].admits(index, source.local_addr().unwrap())
                            || (challenge
                                && net.lose_first_challenge
                                && !net.lost[sender].swap(true, Ordering::AcqRel))
                        {
                            continue;
                        }
                        sleep(net.transit).await;
                        source
                            .send_to(&packet[..size], net.inside[side])
                            .await
                            .unwrap();
                    }
                });
            }
        }
        let mut addresses = Vec::new();
        for _ in 0..3 {
            let observer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = observer.local_addr().unwrap();
            addresses.push(addr);
            let net = self.clone();
            tasks.spawn(async move {
                let mut buf = [0; 1024];
                while let Ok((n, source)) = observer.recv_from(&mut buf).await {
                    let Some(side) = net.inside.iter().position(|inside| *inside == source) else {
                        continue;
                    };
                    let req = StunMessage::decode(&buf[..n]).unwrap();
                    let outward = net.gateways[side].outbound(addr).local_addr().unwrap();
                    let mut reply =
                        StunMessage::with_transaction_id(BINDING_RESPONSE, req.transaction_id);
                    reply.add_attribute(StunAttribute::XorMappedAddress(outward));
                    observer.send_to(&reply.encode(), source).await.unwrap();
                }
            });
        }
        addresses
    }
}

async fn relay_payload(
    source: &RelayClient,
    target: &mut mpsc::Receiver<RelayMessage>,
    sender: &mut TransportSession,
    receiver: &mut TransportSession,
    payload: &[u8],
) {
    source
        .send_data(PEERS[1], &sender.encrypt_to_bytes(payload).unwrap())
        .await
        .unwrap();
    let message = timeout(Duration::from_secs(1), target.recv())
        .await
        .unwrap()
        .unwrap();
    let RelayMessage::Data { from_node, data } = message else {
        panic!("expected relay data")
    };
    assert_eq!(from_node, PEERS[0]);
    assert_eq!(receiver.decrypt_from_bytes(&data).unwrap(), payload);
}

async fn matrix_case(kinds: [NatKind; 2], transit: Duration, lose_first_challenge: bool) {
    let keys = [NodeIdentity::generate(), NodeIdentity::generate()];
    let peers = [0, 1].map(|i| Arc::new(PeerManager::new(config_for_identity(&keys[i], PEERS[i]))));
    let bind = (Ipv4Addr::LOCALHOST, 0).into();
    let udp = [
        UdpTransport::bind(bind, peers[0].clone())
            .await
            .unwrap()
            .with_local_node_id(PEERS[0]),
        UdpTransport::bind(bind, peers[1].clone())
            .await
            .unwrap()
            .with_local_node_id(PEERS[1]),
    ];
    let mut tasks = JoinSet::new();
    let (tx_a, rx_a) = mpsc::channel(16);
    let (tx_b, rx_b) = mpsc::channel(16);
    let mut wire_rx = [rx_a, rx_b];
    for (i, tx) in [tx_a, tx_b].into_iter().enumerate() {
        let transport = udp[i].clone();
        tasks.spawn(async move {
            let _ = transport.run_inbound(tx).await;
        });
    }
    let network = Arc::new(LoopbackNetwork {
        gateways: [Gateway::new(kinds[0]).await, Gateway::new(kinds[1]).await],
        inside: [udp[0].local_addr().unwrap(), udp[1].local_addr().unwrap()],
        transit,
        lose_first_challenge,
        lost: Default::default(),
        stop_direct: Default::default(),
        requests: Default::default(),
    });
    let stun = network.run(&mut tasks).await;
    let mut signals = Vec::new();
    for i in 0..2 {
        let measured = udp[i]
            .gather_candidate_report_live(stun.clone(), Duration::from_millis(300))
            .await
            .unwrap()
            .nat_profile;
        let profile = PunchProfile::from_primary(&measured).unwrap();
        assert_eq!(profile.nat_type, kinds[i]);
        let candidates: Vec<_> = measured
            .observations
            .iter()
            .filter_map(|sample| sample.mapped_address.clone())
            .collect();
        peers[i].update_nat_profile(measured).await;
        let wire = serde_json::to_vec(&(profile, candidates)).unwrap();
        signals.push(wire);
    }
    let relay = RelayServer::start_random().await.unwrap();
    let relay_endpoint = relay.addr.to_string();
    let (relay_a, _rx_a) = RelayClient::connect(&relay_endpoint, PEERS[0])
        .await
        .unwrap();
    let (_relay_b, mut relay_rx) = RelayClient::connect(&relay_endpoint, PEERS[1])
        .await
        .unwrap();
    let (a, b) = establish_sessions();
    let mut wg = [a, b];
    let (stop, _) = watch::channel(false);
    for i in 0..2 {
        let j = 1 - i;
        let public_key = hex::encode(keys[j].public_key());
        let (offer, candidates): (PunchProfile, Vec<String>) =
            serde_json::from_slice(&signals[j]).unwrap();
        peers[i]
            .add_peer(&peer_with_public_key(
                PEERS[j],
                VIP[j],
                public_key.clone(),
                None,
            ))
            .await;
        let sources = candidates
            .iter()
            .cloned()
            .map(|s| (s, "stun_observed".to_string()))
            .collect();
        let expires = Some(crate::gateway_mapping::now_ms() + 45_000);
        peers[i]
            .add_candidates_with_metadata(PEERS[j], &candidates, &sources, 8, expires)
            .await;
        let generation = peers[i].current_network_generation_sync();
        let owner = peers[i].peer_session_generation_sync(PEERS[j]);
        peers[i]
            .stage_punch_profile(
                PEERS[j],
                offer,
                Some(&public_key),
                8,
                expires,
                (generation, owner),
            )
            .await;
        assert!(
            peers[i]
                .set_probe_session_id(PEERS[j], Some("matrix-session".into()))
                .await
        );
        assert!(
            peers[i]
                .confirm_relay_peer(PEERS[j], &relay_endpoint, generation)
                .await
        );
        assert_eq!(
            peers[i]
                .select_path_for_data(PEERS[j], true, true)
                .await
                .path,
            Some(crate::peer::NetworkPath::Relay)
        );
        assert!(
            udp[i]
                .start_negotiated(PEERS[j], generation, owner.unwrap(), Some(stop.subscribe()))
                .await
        );
    }
    let [a, b] = &mut wg;
    relay_payload(&relay_a, &mut relay_rx, a, b, b"first packet over relay").await;
    let window = if lose_first_challenge {
        Duration::from_secs(12)
    } else {
        Duration::from_millis(3400)
    };
    let pair = timeout(window, async {
        loop {
            let left = peers[0].get_connection(PEERS[1]).await.unwrap();
            let right = peers[1].get_connection(PEERS[0]).await.unwrap();
            if left.direct_health.success_count > 0 && right.direct_health.success_count > 0 {
                break [left.endpoint.unwrap(), right.endpoint.unwrap()];
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .ok();
    if let Some(endpoints) = pair {
        for i in 0..2 {
            let j = 1 - i;
            let payload = Ipv4Packet::build_icmp_echo_request(
                VIP[i].parse().unwrap(),
                VIP[j].parse().unwrap(),
                123,
                i as u16,
                b"authenticated direct business",
            );
            let sealed = EncryptedPeerPacket {
                room_authorization: None,
                peer_id: PEERS[j].to_owned(),
                dst_ip: VIP[j].to_owned(),
                wire_bytes: wg[i].encrypt_to_bytes(&payload).unwrap(),
                is_business: true,
            };
            udp[i].send_packet_to(&sealed, endpoints[i]).await.unwrap();
            let received = timeout(Duration::from_secs(1), wire_rx[j].recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(received.source, Some(endpoints[j]));
            assert_eq!(
                wg[j].decrypt_from_bytes(&received.wire_bytes).unwrap(),
                payload
            );
            // Commit the witnessed endpoint only after receiving and decrypting
            // a real WG packet from it, then query the actual path selector.
            peers[j]
                .record_direct_success_with_local_endpoint(
                    PEERS[i],
                    received.source,
                    received.local_endpoint,
                )
                .await;
            assert_eq!(
                peers[j]
                    .select_path_for_data(PEERS[i], true, true)
                    .await
                    .path,
                Some(crate::peer::NetworkPath::Direct)
            );
        }
    }
    let packets = network.requests.load(Ordering::Relaxed);
    eprintln!(
        "NAT matrix {:?} x {:?} result={} UDP challenges={packets}",
        kinds[0],
        kinds[1],
        if pair.is_some() {
            "bidirectional authenticated UDP"
        } else {
            "relay"
        }
    );
    if kinds.contains(&NatKind::Cone) {
        assert!(pair.is_some(), "missing direct path for {kinds:?}");
    }
    for lost in &network.lost {
        assert_eq!(lost.load(Ordering::Acquire), lose_first_challenge);
    }
    assert!(
        (1..=32).contains(&packets),
        "{kinds:?} sent {packets} challenges"
    );
    network.stop_direct.store(true, Ordering::Release);
    if pair.is_some() {
        // The gateways now drop every direct packet. Exercise the normal consent
        // sender, actual UDP timeout, consecutive-loss reducer and path selector.
        for _ in 0..3 {
            tokio::join!(
                udp[0].run_keepalive_round(Duration::from_millis(25)),
                udp[1].run_keepalive_round(Duration::from_millis(25))
            );
        }
    }
    for i in 0..2 {
        assert_eq!(
            peers[i]
                .select_path_for_data(PEERS[1 - i], true, true)
                .await
                .path,
            Some(crate::peer::NetworkPath::Relay)
        );
    }
    let [a, b] = &mut wg;
    relay_payload(&relay_a, &mut relay_rx, a, b, b"relay after UDP loss").await;
    stop.send_replace(true);
    tasks.shutdown().await;
    relay.shutdown().await;
}

#[tokio::test]
async fn negotiated_rootless_nat_matrix() {
    for a in [
        NatKind::Cone,
        NatKind::LinearSymmetric,
        NatKind::RandomSymmetric,
    ] {
        for b in [
            NatKind::Cone,
            NatKind::LinearSymmetric,
            NatKind::RandomSymmetric,
        ] {
            matrix_case([a, b], Duration::from_millis(3), false).await;
        }
    }
}

#[tokio::test]
async fn negotiated_delayed_udp_retries_after_first_challenge_is_lost_in_each_direction() {
    matrix_case([NatKind::Cone; 2], Duration::from_millis(120), true).await;
}
