//! Loopback-only gateways with real UDP sockets. A datagram addressed to an
//! outside mapping is routed from the sender's destination-specific mapping
//! only when the receiver's NAT filter admits that source tuple.
use super::negotiated_relay::TlsRelayPair;
use super::*;
use p2pnet_nat::engine::{NatKind, PunchProfile};

const PEERS: [&str; 2] = ["matrix-a", "matrix-b"];
const VIP: [&str; 2] = ["10.20.0.1", "10.20.0.2"];
const PORTS: usize = 16;
// Bind and gather one topology at a time. Different test runtimes can then
// spend their traversal windows concurrently without racing port reservations.
static MATRIX_SETUP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Clone, Copy, Eq, PartialEq)]
enum GatewayLease {
    None,
    Pcp,
    NatPmp,
}

impl GatewayLease {
    fn source(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pcp => "pcp",
            Self::NatPmp => "nat_pmp",
        }
    }
}

struct Gateway {
    nat: NatKind,
    sockets: Vec<Arc<UdpSocket>>,
    mappings: std::sync::Mutex<Vec<(SocketAddr, SocketAddr)>>,
    mapped_socket: Arc<UdpSocket>,
    lease_until: std::sync::Mutex<Option<tokio::time::Instant>>,
}

impl Gateway {
    async fn new(nat: NatKind) -> Self {
        // Reserve a contiguous block locally so the measured linear steps are
        // independent of the host kernel's ephemeral-port allocator.
        for _ in 0..32 {
            let first = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let base = first.local_addr().unwrap().port();
            if base > u16::MAX - PORTS as u16 {
                continue;
            }
            let mut sockets = vec![Arc::new(first)];
            for i in 1..PORTS as u16 {
                if let Ok(s) = UdpSocket::bind((Ipv4Addr::LOCALHOST, base + i)).await {
                    sockets.push(Arc::new(s));
                } else {
                    break;
                }
            }
            if sockets.len() == PORTS {
                return Self {
                    nat,
                    sockets,
                    mappings: Default::default(),
                    mapped_socket: Arc::new(
                        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
                    ),
                    lease_until: Default::default(),
                };
            }
        }
        panic!("loopback NAT fixture could not reserve its mapping ports")
    }

    fn port_index(&self, allocation: usize) -> usize {
        match self.nat {
            NatKind::Cone | NatKind::LinearSymmetric => allocation,
            NatKind::RandomSymmetric => {
                [0, 3, 1, 6, 4, 2, 7, 5, 11, 15, 8, 12, 9, 14, 10, 13][allocation]
            }
            NatKind::None => unreachable!("matrix gateways all perform NAT"),
        }
    }

    fn has_lease(&self) -> bool {
        self.lease_until
            .lock()
            .unwrap()
            .is_some_and(|expiry| tokio::time::Instant::now() < expiry)
    }

    fn grant(&self, requested: u32) -> u32 {
        let seconds = requested.min(30);
        *self.lease_until.lock().unwrap() =
            Some(tokio::time::Instant::now() + Duration::from_secs(seconds.into()));
        seconds
    }

    fn outbound(
        &self,
        inside: SocketAddr,
        to: SocketAddr,
        lease_owner: SocketAddr,
    ) -> Option<Arc<UdpSocket>> {
        if inside == lease_owner && self.has_lease() {
            return Some(self.mapped_socket.clone());
        }
        let mut mappings = self.mappings.lock().unwrap();
        let index = mappings.iter().position(|&(local, remote)| {
            local == inside && (self.nat == NatKind::Cone || remote == to)
        });
        let index = match index {
            Some(index) => index,
            None if mappings.len() < PORTS => {
                mappings.push((inside, to));
                mappings.len() - 1
            }
            None => return None,
        };
        Some(self.sockets[self.port_index(index)].clone())
    }

    fn inbound(
        &self,
        index: usize,
        from: SocketAddr,
        lease_owner: SocketAddr,
    ) -> std::result::Result<SocketAddr, MappingDrop> {
        if index == self.sockets.len() {
            return self
                .has_lease()
                .then_some(lease_owner)
                .ok_or(MappingDrop::NoMapping);
        }
        let mappings = self.mappings.lock().unwrap();
        let (_, &(inside, remote)) = mappings
            .iter()
            .enumerate()
            .find(|(allocation, _)| self.port_index(*allocation) == index)
            .ok_or(MappingDrop::NoMapping)?;
        if self.nat == NatKind::Cone || remote == from {
            Ok(inside)
        } else {
            Err(MappingDrop::SourceMismatch(remote))
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum MappingDrop {
    NoMapping,
    SourceMismatch(SocketAddr),
}

#[derive(Default)]
struct ChallengeTrace {
    attempted: usize,
    admitted: usize,
    no_source_port: usize,
    no_mapping: usize,
    source_mismatch: usize,
    first_mismatch: Option<(SocketAddr, SocketAddr, SocketAddr)>,
}

struct InFlight {
    arrives: tokio::time::Instant,
    source: Arc<UdpSocket>,
    destination: SocketAddr,
    bytes: Vec<u8>,
}

struct LoopbackNetwork {
    gateways: [Gateway; 2],
    inside: [SocketAddr; 2],
    transit: Duration,
    lose_first_challenge: bool,
    lost: [std::sync::atomic::AtomicBool; 2],
    stop_direct: std::sync::atomic::AtomicBool,
    traces: [std::sync::Mutex<ChallengeTrace>; 2],
}

impl LoopbackNetwork {
    // A single gateway independently authorizes the port of its own internal
    // peer. The other gateway retains its original destination-based filter.
    async fn start_pcp(self: &Arc<Self>, tasks: &mut JoinSet<()>) -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let net = self.clone();
        tasks.spawn(async move {
            let mut request = [0; 128];
            while let Ok((n, from)) = socket.recv_from(&mut request).await {
                if n != 60
                    || request[..2] != [2, 1]
                    || request[36] != 17
                    || from.ip() != net.inside[0].ip()
                    || request[18..24] != [255, 255, 127, 0, 0, 1]
                    || u16::from_be_bytes([request[40], request[41]]) != net.inside[0].port()
                {
                    continue;
                }
                let gateway = &net.gateways[0];
                let granted = gateway.grant(u32::from_be_bytes(request[4..8].try_into().unwrap()));
                let mut response = [0u8; 60];
                response[0..2].copy_from_slice(&[2, 0x81]);
                response[4..8].copy_from_slice(&granted.to_be_bytes());
                response[24..42].copy_from_slice(&request[24..42]);
                response[42..44].copy_from_slice(
                    &gateway
                        .mapped_socket
                        .local_addr()
                        .unwrap()
                        .port()
                        .to_be_bytes(),
                );
                response[54..60].copy_from_slice(&[255, 255, 127, 0, 0, 1]);
                socket.send_to(&response, from).await.unwrap();
            }
        });
        address
    }

    async fn start_nat_pmp(self: &Arc<Self>, tasks: &mut JoinSet<()>) -> SocketAddr {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = socket.local_addr().unwrap();
        let net = self.clone();
        tasks.spawn(async move {
            let mut request = [0; 64];
            while let Ok((n, from)) = socket.recv_from(&mut request).await {
                if from.ip() != net.inside[0].ip() {
                    continue;
                }
                if request[..n] == [0, 0] {
                    let mut response = [0u8; 12];
                    response[1] = 128;
                    response[8..12].copy_from_slice(&Ipv4Addr::LOCALHOST.octets());
                    socket.send_to(&response, from).await.unwrap();
                } else if n == 12
                    && request[..4] == [0, 1, 0, 0]
                    && request[4..6] == net.inside[0].port().to_be_bytes()
                {
                    let gateway = &net.gateways[0];
                    let seconds =
                        gateway.grant(u32::from_be_bytes(request[8..12].try_into().unwrap()));
                    let mut response = [0u8; 16];
                    response[1] = 129;
                    response[8..10].copy_from_slice(&request[4..6]);
                    response[10..12].copy_from_slice(
                        &gateway
                            .mapped_socket
                            .local_addr()
                            .unwrap()
                            .port()
                            .to_be_bytes(),
                    );
                    response[12..16].copy_from_slice(&seconds.to_be_bytes());
                    socket.send_to(&response, from).await.unwrap();
                }
            }
        });
        address
    }

    async fn run(self: &Arc<Self>, tasks: &mut JoinSet<()>) -> Vec<SocketAddr> {
        for side in 0..2 {
            let gateway = &self.gateways[side];
            for (index, public) in gateway
                .sockets
                .iter()
                .chain([&gateway.mapped_socket])
                .enumerate()
            {
                let public = public.clone();
                let net = self.clone();
                tasks.spawn(async move {
                    let mut packet = [0; 2048];
                    let mut flight = std::collections::VecDeque::<InFlight>::new();
                    loop {
                        // Propagation delay starts at the socket read. A second
                        // datagram may already be in flight before the first
                        // one arrives. Each mapping retains at most 96 packets.
                        let next = flight.front().map(|d| d.arrives);
                        let read = tokio::select! {
                            biased;
                            () = async {
                                if let Some(time) = next { tokio::time::sleep_until(time).await }
                                else { std::future::pending().await }
                            } => {
                                let due = flight.pop_front().expect("scheduled datagram");
                                if !net.stop_direct.load(Ordering::Acquire) {
                                    due.source.send_to(&due.bytes, due.destination).await.unwrap();
                                }
                                continue;
                            }
                            read = public.recv_from(&mut packet), if flight.len() < 96 => read,
                        };
                        let Ok((size, inside_from)) = read else { break };
                        let arrives = tokio::time::Instant::now() + net.transit;
                        let sender = 1 - side;
                        if !inside_from.ip().is_loopback() || inside_from == net.inside[side] {
                            continue;
                        }
                        let challenge = size == p2pnet_nat::engine::FRAME_SIZE
                            && packet[..size].starts_with(b"P3")
                            && packet[2] == 1;
                        let destination = public.local_addr().unwrap();
                        let Some(source) = net.gateways[sender].outbound(
                            inside_from,
                            destination,
                            net.inside[sender],
                        ) else {
                            if challenge {
                                let mut trace = net.traces[sender].lock().unwrap();
                                trace.attempted += 1;
                                trace.no_source_port += 1;
                            }
                            continue;
                        };
                        let observed = source.local_addr().unwrap();
                        let decision =
                            net.gateways[side].inbound(index, observed, net.inside[side]);
                        if challenge {
                            let mut trace = net.traces[sender].lock().unwrap();
                            trace.attempted += 1;
                            match decision {
                                Ok(_) => trace.admitted += 1,
                                Err(MappingDrop::NoMapping) => trace.no_mapping += 1,
                                Err(MappingDrop::SourceMismatch(expected)) => {
                                    trace.source_mismatch += 1;
                                    trace.first_mismatch.get_or_insert((
                                        destination,
                                        observed,
                                        expected,
                                    ));
                                }
                            }
                        }
                        let Ok(destination) = decision else {
                            continue;
                        };
                        if net.stop_direct.load(Ordering::Acquire)
                            || (challenge
                                && net.lose_first_challenge
                                && !net.lost[sender].swap(true, Ordering::AcqRel))
                        {
                            continue;
                        }
                        flight.push_back(InFlight {
                            arrives,
                            source,
                            destination,
                            bytes: packet[..size].to_vec(),
                        });
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
                    let outward = net.gateways[side]
                        .outbound(source, addr, net.inside[side])
                        .unwrap()
                        .local_addr()
                        .unwrap();
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

async fn matrix_case(
    kinds: [NatKind; 2],
    transit: Duration,
    lose_first_challenge: bool,
    lease: GatewayLease,
) -> bool {
    let setup = MATRIX_SETUP.lock().await;
    let keys = [NodeIdentity::generate(), NodeIdentity::generate()];
    let peers = [0, 1].map(|i| Arc::new(PeerManager::new(config_for_identity(&keys[i], PEERS[i]))));
    let bind = (Ipv4Addr::LOCALHOST, 0).into();
    let (tx_a, rx_a) = mpsc::channel(16);
    let (tx_b, rx_b) = mpsc::channel(16);
    let udp = [
        UdpTransport::bind(bind, peers[0].clone())
            .await
            .unwrap()
            .with_local_node_id(PEERS[0])
            .with_inbound_channel(tx_a.clone()),
        UdpTransport::bind(bind, peers[1].clone())
            .await
            .unwrap()
            .with_local_node_id(PEERS[1])
            .with_inbound_channel(tx_b.clone()),
    ];
    let mut tasks = JoinSet::new();
    let mut wire_rx = [rx_a, rx_b];
    for (i, tx) in [tx_a, tx_b].into_iter().enumerate() {
        let transport = udp[i].clone();
        let (ready, wait) = oneshot::channel();
        tasks.spawn(async move {
            transport
                .run_inbound_with_reader_ready_for_test(tx, ready)
                .await
                .unwrap();
        });
        assert!(timeout(Duration::from_secs(3), wait)
            .await
            .unwrap()
            .unwrap());
    }
    let network = Arc::new(LoopbackNetwork {
        gateways: [Gateway::new(kinds[0]).await, Gateway::new(kinds[1]).await],
        inside: [udp[0].local_addr().unwrap(), udp[1].local_addr().unwrap()],
        transit,
        lose_first_challenge,
        lost: Default::default(),
        stop_direct: Default::default(),
        traces: Default::default(),
    });
    let stun = network.run(&mut tasks).await;
    let mut signals = Vec::new();
    for i in 0..2 {
        let measured = udp[i]
            .gather_candidate_report_live(stun.clone(), Duration::from_secs(2))
            .await
            .unwrap()
            .nat_profile;
        let profile = PunchProfile::from_primary(&measured).unwrap();
        assert_eq!(profile.nat_type, kinds[i], "side {i} measured {measured:?}");
        let mut candidates: Vec<_> = measured
            .observations
            .iter()
            .filter_map(|sample| sample.mapped_address.clone())
            .collect();
        peers[i].update_nat_profile(measured).await;
        let mut sources: HashMap<String, String> = candidates
            .iter()
            .map(|s| (s.clone(), "stun_observed".into()))
            .collect();
        if i == 0 && lease != GatewayLease::None {
            assert!(!network.gateways[i].has_lease());
            let port = network.inside[i].port();
            let (endpoint, granted) = if lease == GatewayLease::Pcp {
                let server = network.start_pcp(&mut tasks).await;
                crate::candidate_refresh::request_pcp_udp_mapping(
                    Ipv4Addr::LOCALHOST,
                    port,
                    server,
                    (rand::random(), None),
                )
                .await
            } else {
                let server = network.start_nat_pmp(&mut tasks).await;
                crate::candidate_refresh::request_nat_pmp_udp_mapping(
                    Ipv4Addr::LOCALHOST,
                    port,
                    server,
                )
                .await
            }
            .unwrap();
            assert_eq!(granted, 30);
            assert!(network.gateways[i].has_lease());
            crate::candidate_refresh::prefer_gateway_candidate(
                &endpoint.to_string(),
                lease.source(),
                &mut candidates,
                &mut sources,
            );
        }
        let offer = peers[i]
            .punch_profile_for_signal(&candidates, &sources)
            .unwrap();
        assert_eq!(offer.nat_type, kinds[i]);
        assert_eq!(
            offer.upnp_mapped_addr.is_some(),
            i == 0 && lease != GatewayLease::None
        );
        let wire = serde_json::to_vec(&(offer, candidates, sources)).unwrap();
        signals.push(wire);
    }
    let mut relay = TlsRelayPair::connect(PEERS).await;
    let (a, b) = establish_sessions();
    let mut wg = [a, b];
    relay.exchange(&mut wg, 0, b"first packet over relay").await;
    let (stop, _) = watch::channel(false);
    for i in 0..2 {
        let j = 1 - i;
        let public_key = hex::encode(keys[j].public_key());
        let (offer, candidates, sources): (PunchProfile, Vec<String>, HashMap<String, String>) =
            serde_json::from_slice(&signals[j]).unwrap();
        peers[i]
            .add_peer(&peer_with_public_key(
                PEERS[j],
                VIP[j],
                public_key.clone(),
                None,
            ))
            .await;
        let expires = Some(crate::gateway_mapping::now_ms() + 150_000);
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
                .confirm_relay_peer_from_business_ingress(
                    PEERS[j],
                    &relay.endpoint,
                    generation,
                    None
                )
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
    drop(setup);
    let started = tokio::time::Instant::now();
    let pair = timeout(Duration::from_secs(125), async {
        loop {
            let left = peers[0].get_connection(PEERS[1]).await.unwrap();
            let right = peers[1].get_connection(PEERS[0]).await.unwrap();
            if left.direct_health.success_count > 0 && right.direct_health.success_count > 0 {
                break Some([left.endpoint.unwrap(), right.endpoint.unwrap()]);
            }
            if [left, right].iter().all(|conn| {
                conn.punch_run
                    .as_ref()
                    .is_some_and(|run| run.ended.load(Ordering::Acquire))
            }) {
                break None;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("each worker must find a pair or stop within the traversal budget");
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
    let mut packets = 0;
    for (side, trace) in network.traces.iter().enumerate() {
        let trace = trace.lock().unwrap();
        packets += trace.attempted;
        assert_eq!(
            trace.attempted,
            trace.admitted + trace.no_source_port + trace.no_mapping + trace.source_mismatch
        );
        if pair.is_none() {
            eprintln!("NAT filter {:?} x {:?} sender={} attempted={} admitted={} no_source_port={} no_mapping={} source_mismatch={}",
                kinds[0], kinds[1], PEERS[side], trace.attempted, trace.admitted, trace.no_source_port, trace.no_mapping, trace.source_mismatch);
            if let Some((target, source, expected)) = trace.first_mismatch {
                eprintln!("first filtered request sender={} destination={target} observed_source={source} allowed_source={expected} allowed_source_is_observer={}",
                    PEERS[side], stun.contains(&expected));
            }
        }
    }
    eprintln!(
        "NAT matrix {:?} x {:?} result={} UDP challenges={packets} gateway_pcp={} gateway_lease={} elapsed_ms={}",
        kinds[0],
        kinds[1],
        if pair.is_some() {
            "bidirectional authenticated UDP"
        } else {
            "relay"
        }, lease == GatewayLease::Pcp, lease.source(), started.elapsed().as_millis()
    );
    if lease != GatewayLease::None || kinds.contains(&NatKind::Cone) {
        if pair.is_none() {
            for (i, manager) in peers.iter().enumerate() {
                let connection = manager.get_connection(PEERS[1 - i]).await.unwrap();
                let d = manager.diagnostics().await.remove(0);
                eprintln!("side {i} successes={} endpoint={:?} epoch={} mode={:?} reason={:?} receive={:?} elapsed={:?}",
                    connection.direct_health.success_count, connection.endpoint, d.punch_metrics.punch_epoch, d.punch_mode, d.reason_code,
                    udp[i].probe_rx_snapshot().await, started.elapsed());
            }
        }
        assert!(pair.is_some(), "missing direct path for {kinds:?}");
    }
    for lost in &network.lost {
        assert_eq!(lost.load(Ordering::Acquire), lose_first_challenge);
    }
    assert!(
        (1..=if pair.is_some() { 32 } else { 96 }).contains(&packets),
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
    relay.exchange(&mut wg, 1, b"relay after UDP loss").await;
    stop.send_replace(true);
    tasks.shutdown().await;
    relay.shutdown().await;
    pair.is_some()
}

#[tokio::test]
async fn negotiated_rootless_nat_matrix() {
    let mut cases = JoinSet::new();
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
            cases.spawn(matrix_case(
                [a, b],
                Duration::from_millis(3),
                false,
                GatewayLease::None,
            ));
        }
    }
    let mut direct = 0;
    let mut total = 0;
    while let Some(case) = cases.join_next().await {
        direct += usize::from(case.unwrap());
        total += 1;
    }
    assert_eq!(total, 9);
    eprintln!("Unassisted NAT matrix: {direct}/{total} bidirectional authenticated UDP");
}

#[tokio::test]
async fn negotiated_delayed_udp_retries_after_first_challenge_is_lost_in_each_direction() {
    matrix_case(
        [NatKind::Cone; 2],
        Duration::from_millis(120),
        true,
        GatewayLease::None,
    )
    .await;
}

#[tokio::test]
async fn negotiated_nat_matrix_with_one_authorized_pcp_gateway() {
    leased_matrix(GatewayLease::Pcp).await;
}

#[tokio::test]
async fn negotiated_nat_matrix_without_pcp_with_one_nat_pmp_gateway() {
    leased_matrix(GatewayLease::NatPmp).await;
}

async fn leased_matrix(lease: GatewayLease) {
    let kinds = [
        NatKind::Cone,
        NatKind::LinearSymmetric,
        NatKind::RandomSymmetric,
    ];
    let mut direct = 0;
    for local in kinds {
        for remote in kinds {
            direct += usize::from(
                matrix_case([local, remote], Duration::from_millis(3), false, lease).await,
            );
        }
    }
    assert_eq!(direct, 9);
}
