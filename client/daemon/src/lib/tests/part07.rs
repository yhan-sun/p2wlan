use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::control::TestControlSignal;
use crate::peer::NetworkPath;
use p2pnet_nat::{
    peek_authenticated_punch_identity, HairpinBehavior, MappingBehavior, MappingLifetime,
    NatProfile, PunchPacketKind, StunAttribute, StunMessage, StunObservation,
};
use p2pnet_wireguard::{
    HandshakeInitiator, HandshakeResponder, TransportKeyPair, TransportSession,
};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Notify, Semaphore};

const HARD_HARD_A: &str = "peer-a";
const HARD_HARD_B: &str = "peer-b";

/// Every harness owns kernel-assigned loopback sockets. This counter only
/// namespaces its temporary config directory; it is not a port allocator.
static HARD_HARD_NEXT_HARNESS_ID: AtomicU64 = AtomicU64::new(1);
static HARD_HARD_NEXT_SIGNAL_SEQ: AtomicU64 = AtomicU64::new(1);
pub(crate) static HARD_HARD_E2E_SERIAL: Semaphore = Semaphore::const_new(1);
const HARD_HARD_E2E_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct HarnessStunProfile {
    observer_count: usize,
    timeout: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HarnessNatMode {
    Predictable,
    HighEntropy,
}

impl HarnessStunProfile {
    const FULL_CAPACITY: Self = Self {
        observer_count: 4,
        timeout: Duration::from_millis(350),
    };
    const MINIMUM_CAPACITY: Self = Self {
        observer_count: 3,
        timeout: Duration::from_millis(350),
    };
}

#[derive(Clone, Copy)]
struct HarnessPorts {
    a_public: SocketAddr,
    b_public: SocketAddr,
    a_observers: [SocketAddr; 4],
    b_observers: [SocketAddr; 4],
    a_mapped: [u16; 4],
    b_mapped: [u16; 4],
}

const A_PREDICTABLE_MAPPED_OFFSETS: [i32; 4] = [-16, -12, -8, -4];
const B_PREDICTABLE_MAPPED_OFFSETS: [i32; 4] = [-12, -9, -6, -3];

fn predictable_candidate_guard_offsets(mapped_offsets: &[i32; 4], step: i32) -> Vec<i32> {
    let mut offsets = mapped_offsets.to_vec();
    let last = *mapped_offsets.last().expect("predictable mapped samples");
    for distance in 1..=p2pnet_nat::mapping::MAX_PREDICTED_PORTS {
        let offset = last + step * distance as i32;
        // The public link socket already owns offset zero.
        if offset != 0 && !offsets.contains(&offset) {
            offsets.push(offset);
        }
    }
    offsets
}

#[test]
fn hard_hard_predictable_candidate_guards_cover_complete_successor_windows() {
    for (mapped_offsets, step) in [
        (A_PREDICTABLE_MAPPED_OFFSETS, 4),
        (B_PREDICTABLE_MAPPED_OFFSETS, 3),
    ] {
        let offsets = predictable_candidate_guard_offsets(&mapped_offsets, step);
        assert!(mapped_offsets
            .iter()
            .all(|mapped| offsets.contains(mapped)));
        let last = *mapped_offsets.last().unwrap();
        for distance in 1..=p2pnet_nat::mapping::MAX_PREDICTED_PORTS {
            let predicted = last + step * distance as i32;
            if predicted != 0 {
                assert!(offsets.contains(&predicted));
            }
        }
        assert!(!offsets.contains(&0));
    }
}

async fn reserve_predictable_public_endpoint(
    ip: IpAddr,
    candidate_offsets: &[i32],
) -> (Arc<UdpSocket>, Vec<Arc<UdpSocket>>) {
    const RESERVATION_RETRIES: usize = 64;

    'reserve: for _ in 0..RESERVATION_RETRIES {
        let public = Arc::new(UdpSocket::bind(SocketAddr::new(ip, 0)).await.unwrap());
        let public_port = public.local_addr().unwrap().port();
        let mut guards = Vec::with_capacity(candidate_offsets.len());
        for offset in candidate_offsets {
            let endpoint = SocketAddr::new(ip, offset_port(public_port, *offset));
            match UdpSocket::bind(endpoint).await {
                Ok(socket) => guards.push(Arc::new(socket)),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue 'reserve;
                }
                Err(error) => panic!("bind predictable candidate guard {endpoint}: {error}"),
            }
        }
        return (public, guards);
    }
    panic!("could not reserve a kernel-selected predictable candidate set");
}

impl HarnessPorts {
    async fn allocate_with_mode(
        stun: HarnessStunProfile,
        mode: HarnessNatMode,
    ) -> (
        Self,
        Arc<UdpSocket>,
        Arc<UdpSocket>,
        Vec<TestStunObserver>,
        Vec<Arc<UdpSocket>>,
    ) {
        assert!((3..=4).contains(&stun.observer_count));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let (a_public, b_public, candidate_guards) = match mode {
            HarnessNatMode::Predictable => {
                // Reserve the complete production-bounded successor windows,
                // not only their top candidates. Otherwise Windows can assign
                // a dynamic socket one of the later predicted target ports and
                // let traffic bypass the synthetic NAT link entirely.
                let a_offsets =
                    predictable_candidate_guard_offsets(&A_PREDICTABLE_MAPPED_OFFSETS, 4);
                let b_offsets =
                    predictable_candidate_guard_offsets(&B_PREDICTABLE_MAPPED_OFFSETS, 3);
                let (a_public, mut guards) =
                    reserve_predictable_public_endpoint(ip, &a_offsets).await;
                let (b_public, b_guards) =
                    reserve_predictable_public_endpoint(ip, &b_offsets).await;
                guards.extend(b_guards);
                (a_public, b_public, guards)
            }
            HarnessNatMode::HighEntropy => (
                Arc::new(UdpSocket::bind(SocketAddr::new(ip, 0)).await.unwrap()),
                Arc::new(UdpSocket::bind(SocketAddr::new(ip, 0)).await.unwrap()),
                Vec::new(),
            ),
        };
        let a_public_addr = a_public.local_addr().unwrap();
        let b_public_addr = b_public.local_addr().unwrap();
        let mapped_ports = |public_port: u16, side: u16| match mode {
            HarnessNatMode::Predictable => {
                if side == 0 {
                    A_PREDICTABLE_MAPPED_OFFSETS
                        .map(|offset| offset_port(public_port, offset))
                } else {
                    B_PREDICTABLE_MAPPED_OFFSETS
                        .map(|offset| offset_port(public_port, offset))
                }
            }
            // The first observed port is also the real public endpoint. The
            // remaining samples deliberately jump in both directions so the
            // production allocation model classifies this as HighEntropy,
            // while the birthday candidate set still contains the endpoint
            // that the fake NAT link owns.
            HarnessNatMode::HighEntropy => [
                public_port,
                offset_port(public_port, if side == 0 { 169 } else { 111 }),
                offset_port(public_port, if side == 0 { 31 } else { 28 }),
                offset_port(public_port, if side == 0 { 245 } else { 162 }),
            ],
        };
        let a_mapped = mapped_ports(a_public_addr.port(), 0);
        let b_mapped = mapped_ports(b_public_addr.port(), 1);
        let mut a_observer_list = Vec::with_capacity(4);
        let mut b_observer_list = Vec::with_capacity(4);
        let mut observers = Vec::with_capacity(8);
        for mapped_port in a_mapped {
            let observer = spawn_stun_observer(SocketAddr::new(ip, 0), mapped_port);
            a_observer_list.push(observer.endpoint);
            observers.push(observer);
        }
        for mapped_port in b_mapped {
            let observer = spawn_stun_observer(SocketAddr::new(ip, 0), mapped_port);
            b_observer_list.push(observer.endpoint);
            observers.push(observer);
        }
        let a_observers = a_observer_list.try_into().expect("four A observers");
        let b_observers = b_observer_list.try_into().expect("four B observers");
        (
            Self {
                a_public: a_public_addr,
                b_public: b_public_addr,
                a_observers,
                b_observers,
                a_mapped,
                b_mapped,
            },
            a_public,
            b_public,
            observers,
            candidate_guards,
        )
    }
}

fn offset_port(port: u16, offset: i32) -> u16 {
    let modulus = i32::from(u16::MAX);
    (1 + (i32::from(port).saturating_sub(1) + offset).rem_euclid(modulus)) as u16
}

struct HardHardClockReset;

impl Drop for HardHardClockReset {
    fn drop(&mut self) {
        set_hard_hard_test_now_ms(None);
    }
}

fn hard_hard_now_for_test() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn hard_hard_replacement_candidate(candidate: &str) -> String {
    let endpoint = candidate
        .parse::<SocketAddr>()
        .expect("Hard↔Hard signal candidates must be socket addresses");
    let replacement_port = if endpoint.port() <= u16::MAX - 20_000 {
        endpoint.port() + 20_000
    } else {
        endpoint.port() - 20_000
    };
    SocketAddr::new(endpoint.ip(), replacement_port).to_string()
}

fn hard_hard_profile(public_endpoint: SocketAddr, port_delta: i32) -> NatProfile {
    NatProfile {
        local_addr: "127.0.0.1:0".to_string(),
        observations: Vec::new(),
        udp_blocked: false,
        public_endpoint: Some(public_endpoint.to_string()),
        public_ip_stable: Some(true),
        public_port_stable: Some(false),
        port_preserved: Some(false),
        port_delta: Some(port_delta),
        likely_symmetric: Some(true),
        mapping_behavior: MappingBehavior::AddressOrPortDependent,
        filtering_behavior: p2pnet_nat::FilteringBehavior::AddressOrPortDependent,
        hairpin_behavior: HairpinBehavior::Unknown,
        mapping_lifetime: MappingLifetime::Unknown,
        prediction_candidate: true,
        predicted_endpoints: vec![SocketAddr::new(
            public_endpoint.ip(),
            public_endpoint.port().saturating_add(port_delta as u16),
        )
        .to_string()],
        birthday_candidate: false,
        confidence: 90,
    }
}

fn hard_hard_high_entropy_profile(
    public_endpoint: SocketAddr,
    observers: &[SocketAddr; 4],
    mapped_ports: &[u16; 4],
    observer_count: usize,
) -> NatProfile {
    let observations = observers
        .iter()
        .copied()
        .zip(mapped_ports.iter().copied())
        .take(observer_count)
        .map(|(observer, mapped_port)| StunObservation {
            server: observer.to_string(),
            mapped_address: Some(SocketAddr::new(public_endpoint.ip(), mapped_port).to_string()),
            rtt_ms: Some(1),
            error: None,
        })
        .collect();
    NatProfile {
        local_addr: "127.0.0.1:0".to_string(),
        observations,
        udp_blocked: false,
        public_endpoint: Some(public_endpoint.to_string()),
        public_ip_stable: Some(true),
        public_port_stable: Some(false),
        port_preserved: Some(false),
        port_delta: None,
        likely_symmetric: Some(true),
        mapping_behavior: MappingBehavior::AddressOrPortDependent,
        filtering_behavior: p2pnet_nat::FilteringBehavior::AddressOrPortDependent,
        hairpin_behavior: HairpinBehavior::Unknown,
        mapping_lifetime: MappingLifetime::Unknown,
        prediction_candidate: false,
        predicted_endpoints: Vec::new(),
        birthday_candidate: true,
        confidence: 90,
    }
}

fn harness_config(
    identity: &NodeIdentity,
    node_id: &str,
    virtual_ip: &str,
    config_path: PathBuf,
    stun: HarnessStunProfile,
) -> Config {
    harness_config_with_birthday(identity, node_id, virtual_ip, config_path, stun, false)
}

fn harness_config_with_birthday(
    identity: &NodeIdentity,
    node_id: &str,
    virtual_ip: &str,
    config_path: PathBuf,
    stun: HarnessStunProfile,
    birthday_enabled: bool,
) -> Config {
    let mut config = Config::generate_default("http://hard-hard.test", "phase-2-2").unwrap();
    config.config_path = Some(config_path);
    config.node.node_id = node_id.to_string();
    config.node.public_key = hex::encode(identity.public_key());
    config.node.private_key = hex::encode(identity.private_key());
    config.network.manual = true;
    config.network.virtual_ip = virtual_ip.to_string();
    config.network.udp_bind = "127.0.0.1:0".to_string();
    config.network.stun_timeout_ms = stun.timeout.as_millis() as u64;
    config.network.punch_interval_ms = 1;
    config.network.punch_attempts = 1;
    config.network.upnp_enabled = false;
    config.network.udp_liveness_enabled = false;
    config.network.birthday_probing_enabled = birthday_enabled;
    config.network.socket_pool_enabled = false;
    config.network.fresh_mapping_punch_enabled = true;
    config.network.fresh_mapping_harness_loopback = true;
    config.network.gather_host_candidates = false;
    config.network.predicted_candidates_enabled = true;
    // This is only a planner/path-selector fallback hint. No relay task is
    // started by the manual test daemon.
    config.relay.servers = vec!["relay.invalid:443".to_string()];
    config
}

fn peer_info(
    node_id: &str,
    virtual_ip: &str,
    public_key: String,
    endpoint: SocketAddr,
    nat_type: String,
) -> control::PeerInfo {
    control::PeerInfo {
        node_id: node_id.to_string(),
        device_name: "phase-2-2-test".to_string(),
        app_version: "0.2.0-test".to_string(),
        public_key,
        endpoint: endpoint.to_string(),
        nat_type,
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 1,
        relay_rtt_ms: None,
    }
}

struct TestStunObserver {
    endpoint: SocketAddr,
    requests: Arc<AtomicU16>,
    responses: Arc<AtomicU16>,
    shutdown: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl TestStunObserver {
    fn diagnostics(&self) -> (SocketAddr, u16, u16) {
        (
            self.endpoint,
            self.requests.load(Ordering::Acquire),
            self.responses.load(Ordering::Acquire),
        )
    }
}

impl Drop for TestStunObserver {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Run the synthetic STUN endpoints outside the current-thread Tokio test
/// runtime.  They model independent network observers; scheduling them on the
/// same executor as both daemons made the third sequential sample occasionally
/// miss the production-bounded measurement deadline before the observer task
/// was ever polled. A nonblocking thread keeps the network timing deterministic
/// while preserving the real UDP request/response, 350ms per-sample cap, 1.2s
/// batch cap, and dynamic-socket inbound paths.
fn spawn_stun_observer(bind: SocketAddr, mapped_port: u16) -> TestStunObserver {
    let socket = std::net::UdpSocket::bind(bind).unwrap();
    let endpoint = socket.local_addr().unwrap();
    socket.set_nonblocking(true).unwrap();
    let requests = Arc::new(AtomicU16::new(0));
    let responses = Arc::new(AtomicU16::new(0));
    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_requests = requests.clone();
    let thread_responses = responses.clone();
    let thread_shutdown = shutdown.clone();
    let thread = std::thread::spawn(move || {
        let mut buf = vec![0u8; 2048];
        while !thread_shutdown.load(Ordering::Acquire) {
            let (len, source) = match socket.recv_from(&mut buf) {
                Ok(received) => received,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                Err(_) => return,
            };
            let Ok(request) = StunMessage::decode(&buf[..len]) else {
                continue;
            };
            if request.msg_type != p2pnet_nat::BINDING_REQUEST {
                continue;
            }
            thread_requests.fetch_add(1, Ordering::AcqRel);
            let mut response = StunMessage::with_transaction_id(
                p2pnet_nat::BINDING_RESPONSE,
                request.transaction_id,
            );
            response.add_attribute(StunAttribute::XorMappedAddress(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                mapped_port,
            )));
            if socket.send_to(&response.encode(), source).is_ok() {
                thread_responses.fetch_add(1, Ordering::AcqRel);
            }
        }
    });
    TestStunObserver {
        endpoint,
        requests,
        responses,
        shutdown,
        thread: Some(thread),
    }
}

struct NatPacketLink {
    a_public: Arc<UdpSocket>,
    b_public: Arc<UdpSocket>,
    _a_source: Arc<UdpSocket>,
    _b_source: Arc<UdpSocket>,
    drop_a_to_b: Arc<AtomicBool>,
    drop_b_to_a: Arc<AtomicBool>,
    hold_authenticated_punch: Arc<AtomicBool>,
    hold_ack: Arc<AtomicBool>,
    held_a_to_b: Arc<StdMutex<Vec<Vec<u8>>>>,
    held_b_to_a: Arc<StdMutex<Vec<Vec<u8>>>>,
    held_punch_a_to_b: Arc<StdMutex<Vec<Vec<u8>>>>,
    held_punch_b_to_a: Arc<StdMutex<Vec<Vec<u8>>>>,
    route_dynamic_socket: bool,
    worker: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Clone)]
struct NatRouteTable {
    outbound: Arc<StdMutex<HashMap<SocketAddr, SocketAddr>>>,
    response: Arc<StdMutex<HashMap<(SocketAddr, NatResponseKey), SocketAddr>>>,
}

impl NatRouteTable {
    fn new() -> Self {
        Self {
            outbound: Arc::new(StdMutex::new(HashMap::new())),
            response: Arc::new(StdMutex::new(HashMap::new())),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NatPacketRole {
    Request,
    Response,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum NatResponseKey {
    Generic,
    AuthenticatedPunch {
        generation: u64,
        nonce: [u8; 8],
    },
    DirectValidation {
        generation: u64,
        request_id: u16,
        sequence: u8,
        owner_token: u64,
    },
}

#[derive(Clone, Copy)]
struct NatPacketClassification {
    role: NatPacketRole,
    response_key: NatResponseKey,
}

struct HeldAcks {
    a_to_b: Vec<Vec<u8>>,
    b_to_a: Vec<Vec<u8>>,
}

impl NatPacketLink {
    #[allow(clippy::too_many_arguments)]
    async fn new(
        ports: HarnessPorts,
        a_public: Arc<UdpSocket>,
        b_public: Arc<UdpSocket>,
        udp_a: UdpTransport,
        udp_b: UdpTransport,
        a_keys: TransportKeyPair,
        b_keys: TransportKeyPair,
        actual_public: Option<(SocketAddr, SocketAddr)>,
        primary_a: Option<SocketAddr>,
        route_dynamic_socket: bool,
    ) -> Self {
        let has_separate_sources = actual_public.is_some();
        let (a_source_endpoint, b_source_endpoint) =
            actual_public.unwrap_or((ports.a_public, ports.b_public));
        let a_source = if !has_separate_sources {
            a_public.clone()
        } else {
            Arc::new(UdpSocket::bind(a_source_endpoint).await.unwrap())
        };
        let b_source = if !has_separate_sources {
            b_public.clone()
        } else {
            Arc::new(UdpSocket::bind(b_source_endpoint).await.unwrap())
        };
        let drop_a_to_b = Arc::new(AtomicBool::new(false));
        let drop_b_to_a = Arc::new(AtomicBool::new(false));
        let hold_authenticated_punch = Arc::new(AtomicBool::new(false));
        let hold_ack = Arc::new(AtomicBool::new(false));
        let held_a_to_b = Arc::new(StdMutex::new(Vec::new()));
        let held_b_to_a = Arc::new(StdMutex::new(Vec::new()));
        let held_punch_a_to_b = Arc::new(StdMutex::new(Vec::new()));
        let held_punch_b_to_a = Arc::new(StdMutex::new(Vec::new()));
        let a_to_b_routes = NatRouteTable::new();
        let b_to_a_routes = NatRouteTable::new();
        let worker = Some(tokio::spawn(Self::run(
            a_public.clone(),
            b_public.clone(),
            a_source.clone(),
            b_source.clone(),
            udp_a.clone(),
            udp_b.clone(),
            drop_a_to_b.clone(),
            drop_b_to_a.clone(),
            hold_authenticated_punch.clone(),
            hold_ack.clone(),
            held_a_to_b.clone(),
            held_b_to_a.clone(),
            held_punch_a_to_b.clone(),
            held_punch_b_to_a.clone(),
            b_keys,
            a_keys,
            a_to_b_routes.clone(),
            b_to_a_routes.clone(),
            primary_a,
            route_dynamic_socket,
        )));
        Self {
            a_public,
            b_public,
            _a_source: a_source,
            _b_source: b_source,
            drop_a_to_b,
            drop_b_to_a,
            hold_authenticated_punch,
            hold_ack,
            held_a_to_b,
            held_b_to_a,
            held_punch_a_to_b,
            held_punch_b_to_a,
            route_dynamic_socket,
            worker,
        }
    }

    async fn forward(
        source_socket: &UdpSocket,
        data: &[u8],
        target_udp: &UdpTransport,
        target_peer: &str,
        primary: Option<SocketAddr>,
        _route_dynamic_socket: bool,
        dropped: &AtomicBool,
    ) -> Option<SocketAddr> {
        if dropped.load(Ordering::Acquire) {
            return None;
        }
        // `primary` models the exact NAT mapping which originated the
        // competing ordinary punch. Route the reply only to that owner: a
        // duplicate to the Hard-Hard dynamic socket can consume the one-shot
        // ACK expectation first and make the intended primary winner depend on
        // platform task scheduling.
        if let Some(primary) = primary {
            return source_socket
                .send_to(data, primary)
                .await
                .ok()
                .map(|_| primary);
        }
        // Once a Hard↔Hard winner is selected, use its exact affinity pin.
        // Before that transaction completes, an authenticated probe or the
        // first encrypted validation request can cross the two receive paths
        // while dynamic sockets are already live but no pin exists yet. A
        // real NAT still delivers that response to the live mapping; the
        // harness must therefore fall back to a deterministic usable dynamic
        // socket instead of dropping the packet merely because affinity is
        // not committed yet.
        let has_dynamic_socket = target_udp.has_dynamic_socket_for_peer(target_peer).await;
        if has_dynamic_socket {
            if let Some((_, socket)) = target_udp.socket_for_peer(Some(target_peer)).await {
                if let Ok(target) = socket.local_addr() {
                    return source_socket
                        .send_to(data, target)
                        .await
                        .ok()
                        .map(|_| target);
                }
            }
            return None;
        }
        let sockets = target_udp
            .dynamic_sockets_for_peer_for_test(target_peer)
            .await;
        if let Some((_, socket)) = sockets.into_iter().min_by_key(|(index, _)| *index) {
            if let Ok(target) = socket.local_addr() {
                return source_socket
                    .send_to(data, target)
                    .await
                    .ok()
                    .map(|_| target);
            }
        }
        None
    }

    async fn forward_to_endpoint(
        source_socket: &UdpSocket,
        data: &[u8],
        target: SocketAddr,
        dropped: &AtomicBool,
    ) -> bool {
        if dropped.load(Ordering::Acquire) {
            return false;
        }
        source_socket.send_to(data, target).await.is_ok()
    }

    async fn endpoint_is_live(
        target_udp: &UdpTransport,
        target_peer: &str,
        endpoint: SocketAddr,
        route_dynamic_socket: bool,
    ) -> bool {
        if !route_dynamic_socket && target_udp.local_addr().ok() == Some(endpoint) {
            return true;
        }
        target_udp
            .dynamic_sockets_for_peer_for_test(target_peer)
            .await
            .into_iter()
            .any(|(_, socket)| socket.local_addr().ok() == Some(endpoint))
    }

    fn classify_packet(
        data: &[u8],
        receiver_keys: &TransportKeyPair,
    ) -> NatPacketClassification {
        if let Some(identity) = peek_authenticated_punch_identity(data) {
            let response_key = data
                .get(6..14)
                .and_then(|nonce| <[u8; 8]>::try_from(nonce).ok())
                .map(|nonce| NatResponseKey::AuthenticatedPunch {
                    generation: identity.generation,
                    nonce,
                })
                .unwrap_or(NatResponseKey::Generic);
            return NatPacketClassification {
                role: match identity.kind {
                    PunchPacketKind::Punch => NatPacketRole::Request,
                    PunchPacketKind::Ack => NatPacketRole::Response,
                },
                response_key,
            };
        }
        let mut decoder = TransportSession::new(receiver_keys.clone());
        match decoder
            .decrypt_from_bytes(data)
            .ok()
            .and_then(|packet| crate::transport::parse_direct_validation_token(&packet))
        {
            Some(token) => NatPacketClassification {
                role: match token.kind {
                    crate::transport::DirectValidationKind::Request => NatPacketRole::Request,
                    crate::transport::DirectValidationKind::Ack => NatPacketRole::Response,
                },
                response_key: NatResponseKey::DirectValidation {
                    generation: token.generation,
                    request_id: token.request_id,
                    sequence: token.sequence,
                    owner_token: token.owner_token,
                },
            },
            None => NatPacketClassification {
                role: NatPacketRole::Other,
                response_key: NatResponseKey::Generic,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_with_route(
        source_socket: &UdpSocket,
        data: &[u8],
        source: SocketAddr,
        target_udp: &UdpTransport,
        target_peer: &str,
        primary: Option<SocketAddr>,
        route_dynamic_socket: bool,
        dropped: &AtomicBool,
        routes: &NatRouteTable,
        reverse_routes: &NatRouteTable,
        classification: NatPacketClassification,
    ) {
        // The fake public endpoint has no kernel NAT table. Keep the selected
        // target separately for requests and responses: a dynamic socket can
        // be both the source of a new request and the receiver of an earlier
        // request, so one flat source->target map cannot represent both flows.
        let sticky_target = if primary.is_none() {
            match classification.role {
                NatPacketRole::Response => routes
                    .response
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&(source, classification.response_key))
                    .copied(),
                NatPacketRole::Request | NatPacketRole::Other => routes
                    .outbound
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(&source)
                    .copied(),
            }
        } else {
            None
        };
        let target = match (classification.role, sticky_target) {
            (NatPacketRole::Response, Some(sticky_target)) => {
                if Self::endpoint_is_live(
                    target_udp,
                    target_peer,
                    sticky_target,
                    route_dynamic_socket,
                )
                .await
                    && Self::forward_to_endpoint(source_socket, data, sticky_target, dropped).await
                {
                    Some(sticky_target)
                } else {
                    None
                }
            }
            (_, Some(sticky_target)) => {
                if Self::endpoint_is_live(
                    target_udp,
                    target_peer,
                    sticky_target,
                    route_dynamic_socket,
                )
                .await
                    && Self::forward_to_endpoint(source_socket, data, sticky_target, dropped).await
                {
                    Some(sticky_target)
                } else {
                    Self::forward(
                        source_socket,
                        data,
                        target_udp,
                        target_peer,
                        primary,
                        route_dynamic_socket,
                        dropped,
                    )
                    .await
                }
            }
            (_, None) => {
                Self::forward(
                    source_socket,
                    data,
                    target_udp,
                    target_peer,
                    primary,
                    route_dynamic_socket,
                    dropped,
                )
                .await
            }
        };
        if let Some(target) = target {
            routes
                .outbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(source, target);
            reverse_routes
                .outbound
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(target, source);
            if classification.role == NatPacketRole::Request {
                reverse_routes
                    .response
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .insert((target, classification.response_key), source);
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run(
        a_public: Arc<UdpSocket>,
        b_public: Arc<UdpSocket>,
        a_source: Arc<UdpSocket>,
        b_source: Arc<UdpSocket>,
        udp_a: UdpTransport,
        udp_b: UdpTransport,
        drop_a_to_b: Arc<AtomicBool>,
        drop_b_to_a: Arc<AtomicBool>,
        hold_authenticated_punch: Arc<AtomicBool>,
        hold_ack: Arc<AtomicBool>,
        held_a_to_b: Arc<StdMutex<Vec<Vec<u8>>>>,
        held_b_to_a: Arc<StdMutex<Vec<Vec<u8>>>>,
        held_punch_a_to_b: Arc<StdMutex<Vec<Vec<u8>>>>,
        held_punch_b_to_a: Arc<StdMutex<Vec<Vec<u8>>>>,
        a_to_b_keys: TransportKeyPair,
        b_to_a_keys: TransportKeyPair,
        a_to_b_routes: NatRouteTable,
        b_to_a_routes: NatRouteTable,
        primary_a: Option<SocketAddr>,
        route_dynamic_socket: bool,
    ) {
        let mut a_buf = vec![0u8; 8192];
        let mut b_buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                result = a_public.recv_from(&mut a_buf) => {
                    let Ok((len, source)) = result else { return; };
                    if hold_ack.load(Ordering::Acquire)
                        && Self::is_authenticated_ack(&a_buf[..len])
                    {
                        held_b_to_a
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(a_buf[..len].to_vec());
                        continue;
                    }
                    if hold_authenticated_punch.load(Ordering::Acquire)
                        && Self::is_authenticated_punch(&a_buf[..len])
                    {
                        held_punch_b_to_a
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(a_buf[..len].to_vec());
                        continue;
                    }
                    // B's packet arrived at A's mapped public endpoint. Send
                    // from B_PUBLIC so A observes the real reciprocal NAT
                    // source, and optionally duplicate it to A's primary
                    // socket for the competing-Direct race test.
                    let classification = Self::classify_packet(&a_buf[..len], &b_to_a_keys);
                    Self::forward_with_route(
                        &b_source,
                        &a_buf[..len],
                        source,
                        &udp_a,
                        HARD_HARD_B,
                        primary_a,
                        route_dynamic_socket,
                        &drop_b_to_a,
                        &b_to_a_routes,
                        &a_to_b_routes,
                        classification,
                    ).await;
                }
                result = b_public.recv_from(&mut b_buf) => {
                    let Ok((len, source)) = result else { return; };
                    if hold_ack.load(Ordering::Acquire)
                        && Self::is_authenticated_ack(&b_buf[..len])
                    {
                        held_a_to_b
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(b_buf[..len].to_vec());
                        continue;
                    }
                    if hold_authenticated_punch.load(Ordering::Acquire)
                        && Self::is_authenticated_punch(&b_buf[..len])
                    {
                        held_punch_a_to_b
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(b_buf[..len].to_vec());
                        continue;
                    }
                    // A's packet arrived at B's mapped public endpoint. Send
                    // from A_PUBLIC so B observes A's predicted source.
                    let classification = Self::classify_packet(&b_buf[..len], &a_to_b_keys);
                    Self::forward_with_route(
                        &a_source,
                        &b_buf[..len],
                        source,
                        &udp_b,
                        HARD_HARD_A,
                        None,
                        route_dynamic_socket,
                        &drop_a_to_b,
                        &a_to_b_routes,
                        &b_to_a_routes,
                        classification,
                    ).await;
                }
            }
        }
    }

    fn is_authenticated_ack(data: &[u8]) -> bool {
        peek_authenticated_punch_identity(data)
            .is_some_and(|identity| identity.kind == PunchPacketKind::Ack)
    }

    fn is_authenticated_punch(data: &[u8]) -> bool {
        peek_authenticated_punch_identity(data)
            .is_some_and(|identity| identity.kind == PunchPacketKind::Punch)
    }

    fn set_drop_a_to_b(&self, drop: bool) {
        self.drop_a_to_b.store(drop, Ordering::Release);
    }

    fn set_drop_b_to_a(&self, drop: bool) {
        self.drop_b_to_a.store(drop, Ordering::Release);
    }

    fn set_hold_authenticated_punch(&self, hold: bool) {
        self.hold_authenticated_punch
            .store(hold, Ordering::Release);
    }

    fn held_authenticated_punch_count(&self) -> usize {
        self.held_punch_a_to_b
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
            + self
                .held_punch_b_to_a
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
    }

    async fn release_held_authenticated_punches(
        &self,
        udp_a: &UdpTransport,
        udp_b: &UdpTransport,
    ) {
        let held_a_to_b = std::mem::take(
            &mut *self
                .held_punch_a_to_b
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        let held_b_to_a = std::mem::take(
            &mut *self
                .held_punch_b_to_a
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for packet in held_a_to_b {
            Self::forward(
                &self._a_source,
                &packet,
                udp_b,
                HARD_HARD_A,
                None,
                self.route_dynamic_socket,
                &self.drop_a_to_b,
            )
            .await;
        }
        for packet in held_b_to_a {
            Self::forward(
                &self._b_source,
                &packet,
                udp_a,
                HARD_HARD_B,
                None,
                self.route_dynamic_socket,
                &self.drop_b_to_a,
            )
            .await;
        }
    }

    fn set_hold_ack(&self, hold: bool) {
        self.hold_ack.store(hold, Ordering::Release);
    }

    fn held_ack_count(&self) -> usize {
        self.held_a_to_b
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
            + self
                .held_b_to_a
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len()
    }

    fn take_held_acks(&self) -> HeldAcks {
        HeldAcks {
            a_to_b: std::mem::take(
                &mut *self
                    .held_a_to_b
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            ),
            b_to_a: std::mem::take(
                &mut *self
                    .held_b_to_a
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            ),
        }
    }

    async fn replay_acks(&self, held: HeldAcks, udp_a: &UdpTransport, udp_b: &UdpTransport) {
        for packet in held.a_to_b {
            Self::forward(
                &self._a_source,
                &packet,
                udp_b,
                HARD_HARD_A,
                None,
                self.route_dynamic_socket,
                &self.drop_a_to_b,
            )
            .await;
        }
        for packet in held.b_to_a {
            Self::forward(
                &self._b_source,
                &packet,
                udp_a,
                HARD_HARD_B,
                None,
                self.route_dynamic_socket,
                &self.drop_b_to_a,
            )
            .await;
        }
    }
}

impl Drop for NatPacketLink {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.abort();
        }
    }
}

struct TwoPeerHarness {
    peers_a: Arc<PeerManager>,
    peers_b: Arc<PeerManager>,
    punch_attempts_a: PunchAttemptDeduplicator,
    punch_attempts_b: PunchAttemptDeduplicator,
    udp_a: UdpTransport,
    udp_b: UdpTransport,
    control_a: ControlClient,
    control_b: ControlClient,
    signals_a: Arc<StdMutex<Vec<TestControlSignal>>>,
    signals_b: Arc<StdMutex<Vec<TestControlSignal>>>,
    signal_hook_a_to_b: Arc<StdMutex<Option<TestSignalHook>>>,
    signal_hook_b_to_a: Arc<StdMutex<Option<TestSignalHook>>>,
    shutdown_a: watch::Sender<bool>,
    shutdown_b: watch::Sender<bool>,
    control_tasks: Vec<tokio::task::JoinHandle<()>>,
    udp_tasks: Vec<tokio::task::JoinHandle<()>>,
    validation_tasks: Vec<tokio::task::JoinHandle<()>>,
    peer_reflexive_tasks: Vec<tokio::task::JoinHandle<()>>,
    link: NatPacketLink,
    _candidate_guards: Vec<Arc<UdpSocket>>,
    validation_enabled_a: Arc<AtomicBool>,
    validation_enabled_b: Arc<AtomicBool>,
    stun_observers: Vec<TestStunObserver>,
    temp_dirs: Vec<PathBuf>,
}

type TestSignalHook = Arc<dyn Fn(&TestControlSignal) + Send + Sync>;

impl TwoPeerHarness {
    async fn shutdown(mut self) {
        let _ = self.shutdown_a.send(true);
        let _ = self.shutdown_b.send(true);
        self.peers_a.clear_hard_hard_sessions(None).await;
        self.peers_b.clear_hard_hard_sessions(None).await;
        let _ = timeout(
            Duration::from_secs(2),
            self.udp_a
                .detach_all_dynamic_punch_sockets("phase_2_2_test_teardown"),
        )
        .await;
        let _ = timeout(
            Duration::from_secs(2),
            self.udp_b
                .detach_all_dynamic_punch_sockets("phase_2_2_test_teardown"),
        )
        .await;
        for task in self.control_tasks.drain(..) {
            let _ = timeout(Duration::from_secs(1), task).await;
        }
        let mut background_tasks = self
            .udp_tasks
            .drain(..)
            .chain(self.validation_tasks.drain(..))
            .chain(self.peer_reflexive_tasks.drain(..))
            .collect::<Vec<_>>();
        for task in &background_tasks {
            task.abort();
        }
        for task in background_tasks.drain(..) {
            let _ = timeout(Duration::from_secs(1), task).await;
        }
        self.stun_observers.clear();
        if let Some(task) = self.link.worker.take() {
            task.abort();
            let _ = timeout(Duration::from_secs(1), task).await;
        }
        // Keep the public sockets owned by the link alive until its worker has
        // been stopped; the link then drops at the end of this method.
        for path in self.temp_dirs.drain(..) {
            let _ = fs::remove_dir_all(path);
        }
    }
}

impl Drop for TwoPeerHarness {
    fn drop(&mut self) {
        // Most tests call the async shutdown path explicitly.  Keep a
        // synchronous safety net for assertion failures, otherwise detached
        // control/UDP workers can retain the simulated sockets and starve the
        // next real-UDP test in the same libtest process.
        let _ = self.shutdown_a.send(true);
        let _ = self.shutdown_b.send(true);
        for task in self
            .control_tasks
            .iter()
            .chain(self.udp_tasks.iter())
            .chain(self.validation_tasks.iter())
            .chain(self.peer_reflexive_tasks.iter())
        {
            task.abort();
        }
        if let Some(worker) = self.link.worker.take() {
            worker.abort();
        }
        for path in &self.temp_dirs {
            let _ = fs::remove_dir_all(path);
        }
    }
}

async fn install_test_daemon_udp(
    daemon: &mut Daemon,
    node_id: &str,
    virtual_ip: &str,
    wireguard: &WireGuardTransport,
) -> (
    UdpTransport,
    DirectValidationIngress,
    PeerReflexiveIngress,
    Arc<AtomicBool>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    let peers = daemon.peers.clone();
    let (udp_inbound_tx, udp_inbound_rx) = mpsc::channel(256);
    let validation_ingress = DirectValidationIngress::new();
    let peer_reflexive_ingress = PeerReflexiveIngress::new();
    let validation_enabled = Arc::new(AtomicBool::new(true));
    let udp_base = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_local_node_id(node_id)
        .with_wireguard_transport(wireguard.clone())
        .with_inbound_channel(udp_inbound_tx.clone())
        .with_peer_reflexive_observer(peer_reflexive_ingress.clone());
    let validation_trigger = validation_ingress.clone();
    let validation_enabled_for_trigger = validation_enabled.clone();
    let udp = udp_base.with_validation_trigger(Arc::new(move |observation| {
        if validation_enabled_for_trigger.load(Ordering::Acquire) {
            validation_trigger.submit(observation);
        }
    }));

    *daemon.udp_transport.write().await = Some(udp.clone());
    let udp_for_reader = udp.clone();
    let udp_reader = tokio::spawn(async move {
        let _ = udp_for_reader.run_inbound(udp_inbound_tx).await;
    });
    let (inbound_tx, _inbound_rx) = mpsc::channel(256);
    let wg = wireguard.clone();
    let peers_for_wg = peers.clone();
    let udp_for_wg = udp.clone();
    let wg_reader = tokio::spawn(async move {
        let _ = wg
            .run_inbound_with_peers(
                udp_inbound_rx,
                inbound_tx,
                Some(peers_for_wg),
                Some(udp_for_wg),
            )
            .await;
    });
    let validation_worker = tokio::spawn(run_direct_validation_scheduler_with_worker_limit(
        validation_ingress.clone(),
        udp.clone(),
        peers.clone(),
        wireguard.clone(),
        virtual_ip.to_string(),
        4,
    ));
    let peer_reflexive_worker = tokio::spawn(run_peer_reflexive_signal_loop_with_worker_permits(
        peer_reflexive_ingress.clone(),
        daemon.control.clone(),
        udp.clone(),
        peers,
        PunchAttemptDeduplicator::default(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    ));
    (
        udp,
        validation_ingress,
        peer_reflexive_ingress,
        validation_enabled,
        vec![
            udp_reader,
            wg_reader,
            validation_worker,
            peer_reflexive_worker,
        ],
    )
}

fn install_signal_forwarder(
    from: &mut Daemon,
    to: &Daemon,
    from_node_id: &str,
    from_public_key: String,
    log: Arc<StdMutex<Vec<TestControlSignal>>>,
    signal_hook: Arc<StdMutex<Option<TestSignalHook>>>,
    advance_clock_on_response: bool,
) {
    let event_tx = to.control.event_sender();
    let expected_to_node_id = to.config.node.node_id.clone();
    let from_node_id = from_node_id.to_string();
    from.control.set_test_signal_forwarder(
        from_node_id.clone(),
        from_public_key,
        Arc::new(move |signal| {
            debug_assert_eq!(signal.to_node_id, expected_to_node_id);
            if advance_clock_on_response
                && signal
                    .session_id
                    .as_deref()
                    .is_some_and(|session| session.starts_with("hh1:r:"))
            {
                if let Some(punch_at_ms) = signal.punch_at_ms {
                    set_hard_hard_test_now_ms(Some(punch_at_ms));
                }
            }
            if let Some(hook) = signal_hook
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
            {
                hook(&signal);
            }
            let logged_signal = signal.clone();
            let _ = event_tx.send(ControlEvent::PeerOffer {
                from_node_id: signal.from_node_id,
                candidates: signal.candidates,
                session_id: signal.session_id,
                probe_ephemeral_public_key: None,
                candidate_sources: signal.candidate_sources,
                candidate_generation: signal.candidate_generation,
                candidates_expires_at_ms: signal.candidates_expires_at_ms,
                handshake_init: signal.handshake_init,
                punch_at_ms: signal.punch_at_ms,
                punch_at_server_ms: None,
                sender_public_key: Some(signal.sender_public_key),
            });
            // Publish the observable test copy only after the corresponding
            // control event is in the receiver queue. A waiter that sees this
            // signal can therefore enqueue a replay without overtaking the
            // original response.
            log.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(logged_signal);
        }),
    );
}

async fn build_two_peer_harness(
    advance_clock_on_response: bool,
    race_primary: bool,
    mapping_miss: bool,
) -> TwoPeerHarness {
    build_two_peer_harness_with_stun(
        advance_clock_on_response,
        race_primary,
        mapping_miss,
        HarnessStunProfile::FULL_CAPACITY,
    )
    .await
}

async fn build_two_peer_harness_with_stun(
    advance_clock_on_response: bool,
    race_primary: bool,
    mapping_miss: bool,
    stun: HarnessStunProfile,
) -> TwoPeerHarness {
    build_two_peer_harness_with_stun_mode(
        advance_clock_on_response,
        race_primary,
        mapping_miss,
        stun,
        HarnessNatMode::Predictable,
    )
    .await
}

async fn build_two_peer_harness_with_stun_mode(
    advance_clock_on_response: bool,
    race_primary: bool,
    mapping_miss: bool,
    stun: HarnessStunProfile,
    nat_mode: HarnessNatMode,
) -> TwoPeerHarness {
    let (ports, a_public_socket, b_public_socket, stun_observers, candidate_guards) =
        HarnessPorts::allocate_with_mode(stun, nat_mode).await;
    let birthday_enabled = nat_mode == HarnessNatMode::HighEntropy;
    let a_identity = NodeIdentity::generate();
    let b_identity = NodeIdentity::generate();
    let root = std::env::temp_dir().join(format!(
        "p2wlan-phase-2-2-{}-{}",
        std::process::id(),
        HARD_HARD_NEXT_HARNESS_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    let path_a = root.join("peer-a.json");
    let path_b = root.join("peer-b.json");
    let mut daemon_a = Daemon::new(harness_config_with_birthday(
        &a_identity,
        HARD_HARD_A,
        "10.20.0.1",
        path_a,
        stun,
        birthday_enabled,
    ));
    let mut daemon_b = Daemon::new(harness_config_with_birthday(
        &b_identity,
        HARD_HARD_B,
        "10.20.0.2",
        path_b,
        stun,
        birthday_enabled,
    ));

    let peers_a = daemon_a.peers.clone();
    let peers_b = daemon_b.peers.clone();
    let punch_attempts_a = daemon_a.punch_attempts.clone();
    let punch_attempts_b = daemon_b.punch_attempts.clone();
    let (a_profile, b_profile) = match nat_mode {
        HarnessNatMode::Predictable => (
            hard_hard_profile(ports.a_public, 4),
            hard_hard_profile(ports.b_public, 3),
        ),
        HarnessNatMode::HighEntropy => (
            hard_hard_high_entropy_profile(
                ports.a_public,
                &ports.a_observers,
                &ports.a_mapped,
                stun.observer_count,
            ),
            hard_hard_high_entropy_profile(
                ports.b_public,
                &ports.b_observers,
                &ports.b_mapped,
                stun.observer_count,
            ),
        ),
    };
    peers_a.update_nat_profile(a_profile.clone()).await;
    peers_b.update_nat_profile(b_profile.clone()).await;

    let a_public_key = hex::encode(a_identity.public_key());
    let b_public_key = hex::encode(b_identity.public_key());
    let a_nat_label = a_profile.control_label_with_generation(1);
    let b_nat_label = b_profile.control_label_with_generation(1);
    let info_for_a = peer_info(
        HARD_HARD_B,
        "10.20.0.2",
        b_public_key.clone(),
        ports.b_public,
        b_nat_label,
    );
    let info_for_b = peer_info(
        HARD_HARD_A,
        "10.20.0.1",
        a_public_key.clone(),
        ports.a_public,
        a_nat_label,
    );
    peers_a.add_peer(&info_for_a).await;
    peers_b.add_peer(&info_for_b).await;
    let predicted_sources_a =
        HashMap::from([(ports.b_public.to_string(), "predicted".to_string())]);
    let predicted_sources_b =
        HashMap::from([(ports.a_public.to_string(), "predicted".to_string())]);
    peers_a
        .add_candidates_with_sources(
            HARD_HARD_B,
            &[ports.b_public.to_string()],
            &predicted_sources_a,
        )
        .await;
    peers_b
        .add_candidates_with_sources(
            HARD_HARD_A,
            &[ports.a_public.to_string()],
            &predicted_sources_b,
        )
        .await;
    // Re-admit the same peer metadata after the seed candidate set so the
    // remote profile is explicitly bound to the current candidate epoch.
    peers_a.add_peer(&info_for_a).await;
    peers_b.add_peer(&info_for_b).await;
    assert!(peers_a.hard_hard_plan_for_peer(HARD_HARD_B).await.is_some());
    assert!(peers_b.hard_hard_plan_for_peer(HARD_HARD_A).await.is_some());

    daemon_a
        .publish_candidate_snapshot(
            vec![ports.a_public.to_string()],
            HashMap::from([(ports.a_public.to_string(), "predicted".to_string())]),
            vec!["phase-2-2:a".to_string()],
        )
        .await;
    daemon_b
        .publish_candidate_snapshot(
            vec![ports.b_public.to_string()],
            HashMap::from([(ports.b_public.to_string(), "predicted".to_string())]),
            vec!["phase-2-2:b".to_string()],
        )
        .await;
    *daemon_a.runtime_stun_servers.write().await = ports
        .a_observers
        .iter()
        .take(stun.observer_count)
        .copied()
        .collect();
    *daemon_b.runtime_stun_servers.write().await = ports
        .b_observers
        .iter()
        .take(stun.observer_count)
        .copied()
        .collect();
    *daemon_a.runtime_stun_timeout.write().await = stun.timeout;
    *daemon_b.runtime_stun_timeout.write().await = stun.timeout;

    let mut a_handshake =
        HandshakeInitiator::new(a_identity.clone(), b_identity.public_key(), None);
    let initiation = a_handshake.create_initiation().unwrap();
    let mut b_handshake = HandshakeResponder::new(b_identity.clone(), None);
    let (response, b_keys) = b_handshake
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let a_keys = a_handshake.consume_response(&response).unwrap();
    let a_keys_for_link = a_keys.clone();
    let b_keys_for_link = b_keys.clone();
    let wg_a = daemon_a.transport.clone();
    let wg_b = daemon_b.transport.clone();
    wg_a.add_session(HARD_HARD_B, TransportSession::new(a_keys))
        .await;
    wg_b.add_session(HARD_HARD_A, TransportSession::new(b_keys))
        .await;

    let signals_a = Arc::new(StdMutex::new(Vec::new()));
    let signals_b = Arc::new(StdMutex::new(Vec::new()));
    let signal_hook_a_to_b = Arc::new(StdMutex::new(None));
    let signal_hook_b_to_a = Arc::new(StdMutex::new(None));
    install_signal_forwarder(
        &mut daemon_a,
        &daemon_b,
        HARD_HARD_A,
        a_public_key,
        signals_b.clone(),
        signal_hook_a_to_b.clone(),
        advance_clock_on_response,
    );
    install_signal_forwarder(
        &mut daemon_b,
        &daemon_a,
        HARD_HARD_B,
        b_public_key,
        signals_a.clone(),
        signal_hook_b_to_a.clone(),
        advance_clock_on_response,
    );

    let (udp_a, _validation_a, _prflx_a, validation_enabled_a, mut tasks_a) =
        install_test_daemon_udp(&mut daemon_a, HARD_HARD_A, "10.20.0.1", &wg_a).await;
    let (udp_b, _validation_b, _prflx_b, validation_enabled_b, mut tasks_b) =
        install_test_daemon_udp(&mut daemon_b, HARD_HARD_B, "10.20.0.2", &wg_b).await;
    let primary_a = race_primary.then(|| udp_a.local_addr().unwrap());
    let actual_public = mapping_miss.then(|| {
        (
            SocketAddr::new(ports.a_public.ip(), 0),
            SocketAddr::new(ports.b_public.ip(), 0),
        )
    });
    let link = NatPacketLink::new(
        ports,
        a_public_socket,
        b_public_socket,
        udp_a.clone(),
        udp_b.clone(),
        a_keys_for_link,
        b_keys_for_link,
        actual_public,
        primary_a,
        nat_mode == HarnessNatMode::HighEntropy,
    )
    .await;

    let control_a = daemon_a.control.clone();
    let control_b = daemon_b.control.clone();
    let shutdown_a = daemon_a.shutdown_tx.clone();
    let shutdown_b = daemon_b.shutdown_tx.clone();
    let (network_tx_a, _network_rx_a) = mpsc::channel(32);
    let (network_tx_b, _network_rx_b) = mpsc::channel(32);
    let control_task_a = tokio::spawn(async move {
        let mut relay_started = false;
        daemon_a
            .run_control_event_loop(&mut relay_started, network_tx_a)
            .await;
    });
    let control_task_b = tokio::spawn(async move {
        let mut relay_started = false;
        daemon_b
            .run_control_event_loop(&mut relay_started, network_tx_b)
            .await;
    });
    tasks_a.append(&mut tasks_b);
    TwoPeerHarness {
        peers_a,
        peers_b,
        punch_attempts_a,
        punch_attempts_b,
        udp_a,
        udp_b,
        control_a,
        control_b,
        signals_a,
        signals_b,
        signal_hook_a_to_b,
        signal_hook_b_to_a,
        shutdown_a,
        shutdown_b,
        control_tasks: vec![control_task_a, control_task_b],
        udp_tasks: tasks_a,
        validation_tasks: Vec::new(),
        peer_reflexive_tasks: Vec::new(),
        link,
        _candidate_guards: candidate_guards,
        validation_enabled_a,
        validation_enabled_b,
        stun_observers,
        temp_dirs: vec![root],
    }
}

async fn install_committed_birthday_predecessor(
    peers: &PeerManager,
    udp: &UdpTransport,
    peer_id: &str,
) -> crate::udp::ProvisionalSocketGuard {
    let (socket_index, socket) = udp.bind_fresh_punch_socket().await.unwrap();
    let punch_generation = peers.next_punch_generation(peer_id).await;
    let guard = udp
        .attach_dynamic_punch_socket(
            peer_id,
            socket_index,
            socket,
            peers.current_network_generation_sync(),
            punch_generation,
            None,
        )
        .await
        .unwrap();
    assert!(
        guard
            .commit_and_pin_for_test(
                udp,
                peer_id,
                socket_index,
                peers.current_network_generation_sync(),
                punch_generation,
            )
            .await
    );
    assert!(guard.finalize().await);
    guard
}

async fn trigger_initial_offer(harness: &TwoPeerHarness) {
    let sources = HashMap::from([(
        harness.link.b_public.local_addr().unwrap().to_string(),
        "predicted".to_string(),
    )]);
    // The actual B public endpoint is already installed in A's candidate set;
    // the link socket is bound to that same endpoint. The adapter emits the
    // legacy generation-zero candidate refresh, which is Applied without
    // opening a new remote epoch and therefore leaves the profile fence ready
    // for the planner.
    harness
        .control_b
        .send_peer_offer_with_sources_and_punch_at(
            HARD_HARD_A,
            &[harness.link.b_public.local_addr().unwrap().to_string()],
            &sources,
            &[],
            None,
            None,
        )
        .await
        .unwrap();
}

async fn trigger_retry_offer_with_current_candidates(
    harness: &TwoPeerHarness,
    previous_response: &TestControlSignal,
) {
    let sources = previous_response
        .candidates
        .iter()
        .cloned()
        .map(|candidate| (candidate, "predicted".to_string()))
        .collect::<HashMap<_, _>>();
    harness
        .control_b
        .send_peer_offer_with_sources_and_punch_at(
            HARD_HARD_A,
            &previous_response.candidates,
            &sources,
            &[],
            None,
            Some(Arc::new(crate::PunchSessionCancellation::default())),
        )
        .await
        .unwrap();
}

async fn wait_for_both_direct(harness: &TwoPeerHarness) {
    let result = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if harness.peers_a.is_direct(HARD_HARD_B).await
                && harness.peers_b.is_direct(HARD_HARD_A).await
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if result.is_err() {
        let diagnostics_a = harness.peers_a.diagnostics().await;
        let diagnostics_b = harness.peers_b.diagnostics().await;
        let session_a = harness
            .peers_a
            .hard_hard_session_for_test(HARD_HARD_B)
            .await;
        let session_b = harness
            .peers_b
            .hard_hard_session_for_test(HARD_HARD_A)
            .await;
        let signals_a = harness
            .signals_a
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let signals_b = harness
            .signals_b
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let stun_observers = harness
            .stun_observers
            .iter()
            .map(TestStunObserver::diagnostics)
            .collect::<Vec<_>>();
        panic!(
            "both isolated peers must converge to Direct\nA diagnostics={diagnostics_a:#?}\nB diagnostics={diagnostics_b:#?}\nA session={session_a:#?}\nB session={session_b:#?}\nA sockets={} B sockets={}\nSTUN observers(endpoint, requests, responses)={stun_observers:#?}\nA received signals={signals_a:#?}\nB received signals={signals_b:#?}",
            harness.udp_a.dynamic_socket_count().await,
            harness.udp_b.dynamic_socket_count().await,
        );
    }
}

async fn wait_for_both_direct_compact(harness: &TwoPeerHarness) {
    if timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if harness.peers_a.is_direct(HARD_HARD_B).await
                && harness.peers_b.is_direct(HARD_HARD_A).await
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .is_err()
    {
        let summarize = |diagnostics: Vec<peer::PeerDiagnostics>| {
            diagnostics
                .into_iter()
                .map(|peer| {
                    (
                        peer.node_id,
                        peer.state,
                        peer.active_path,
                        peer.current_direct_pair.map(|pair| {
                            (pair.source, pair.state, pair.remote_endpoint)
                        }),
                        peer.direct_events
                            .into_iter()
                            .map(|event| event.stage)
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let events_a = summarize_hard_hard_diagnostics(&harness.peers_a, HARD_HARD_B).await;
        let events_b = summarize_hard_hard_diagnostics(&harness.peers_b, HARD_HARD_A).await;
        let session_a = harness
            .peers_a
            .hard_hard_session_for_test(HARD_HARD_B)
            .await;
        let session_b = harness
            .peers_b
            .hard_hard_session_for_test(HARD_HARD_A)
            .await;
        let sockets_a = harness
            .udp_a
            .dynamic_sockets_for_peer_for_test(HARD_HARD_B)
            .await
            .into_iter()
            .map(|(index, socket)| (index, socket.local_addr().ok()))
            .collect::<Vec<_>>();
        let sockets_b = harness
            .udp_b
            .dynamic_sockets_for_peer_for_test(HARD_HARD_A)
            .await
            .into_iter()
            .map(|(index, socket)| (index, socket.local_addr().ok()))
            .collect::<Vec<_>>();
        panic!(
            "birthday peers did not both become Direct: A={:?} B={:?}\nA events={events_a:#?}\nB events={events_b:#?}\nA session={session_a:#?}\nB session={session_b:#?}\nA sockets={sockets_a:?}\nB sockets={sockets_b:?}",
            summarize(harness.peers_a.diagnostics().await),
            summarize(harness.peers_b.diagnostics().await),
        );
    }
}

async fn wait_for_current_direct_diagnostics(
    peers: &PeerManager,
    peer_id: &str,
) -> peer::PeerDiagnostics {
    timeout(Duration::from_secs(1), async {
        loop {
            // `diagnostics()` is deliberately nonblocking and may return its
            // previous cached snapshot while a state commit owns the
            // connections writer. Assertions about a just-observed Direct
            // commit must use the current try-read snapshot instead of
            // turning that intentional cache fallback into an Idle-vs-Direct
            // failure under the standard parallel workspace load.
            if let Some((_, diagnostics)) = peers
                .diagnostic_with_path_selection(
                    peer_id,
                    true,
                    false,
                    Duration::ZERO,
                    None,
                )
                .await
            {
                if diagnostics.state == ConnectionState::Direct {
                    return diagnostics;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("current Direct diagnostics must become readable after the commit")
}

struct CurrentFreshDirect {
    diagnostics: peer::PeerDiagnostics,
    socket_index: usize,
    socket_local_endpoint: SocketAddr,
    predicted_ports: Vec<u16>,
}

async fn wait_for_current_fresh_direct(
    peers: &PeerManager,
    udp: &UdpTransport,
    peer_id: &str,
) -> CurrentFreshDirect {
    let current = timeout(Duration::from_secs(1), async {
        loop {
            let diagnostics = peers
                .diagnostic_with_path_selection(
                    peer_id,
                    true,
                    false,
                    Duration::ZERO,
                    None,
                )
                .await
                .map(|(_, diagnostics)| diagnostics);
            let fresh = peers.fresh_mapping_for_peer(peer_id).await;
            let affinity = udp.affinity_pin_for_test(peer_id).await;
            let selected = udp
                .socket_for_peer(Some(peer_id))
                .await
                .and_then(|(index, socket)| {
                    socket
                        .local_addr()
                        .ok()
                        .map(|local_endpoint| (index, local_endpoint))
                });

            if let (Some(diagnostics), Some(fresh), Some(affinity), Some(selected)) =
                (diagnostics, fresh, affinity, selected)
            {
                let pair_local_endpoint = diagnostics
                    .current_direct_pair
                    .as_ref()
                    .and_then(|pair| pair.local_endpoint.as_deref());
                if diagnostics.state == ConnectionState::Direct
                    && diagnostics.active_path == Some(NetworkPath::Direct)
                    && affinity.socket_index == fresh.socket_index
                    && selected.0 == fresh.socket_index
                    && selected.1 == fresh.socket_local_endpoint
                    && pair_local_endpoint
                        == Some(fresh.socket_local_endpoint.to_string()).as_deref()
                {
                    return CurrentFreshDirect {
                        diagnostics,
                        socket_index: fresh.socket_index,
                        socket_local_endpoint: fresh.socket_local_endpoint,
                        predicted_ports: fresh.predicted_ports,
                    };
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    if let Ok(current) = current {
        return current;
    }

    let diagnostics = peers
        .diagnostic_with_path_selection(peer_id, true, false, Duration::ZERO, None)
        .await
        .map(|(_, diagnostics)| {
            (
                diagnostics.state,
                diagnostics.active_path,
                diagnostics.current_direct_pair,
            )
        });
    let fresh = peers.fresh_mapping_for_peer(peer_id).await;
    let affinity = udp.affinity_pin_for_test(peer_id).await;
    let selected = udp
        .socket_for_peer(Some(peer_id))
        .await
        .map(|(index, socket)| (index, socket.local_addr()));
    panic!(
        "fresh Direct socket state did not converge: peer={peer_id} diagnostics={diagnostics:#?} fresh={fresh:#?} affinity={affinity:#?} selected={selected:#?}"
    );
}

async fn wait_for_stage(
    peers: &PeerManager,
    peer_id: &str,
    stage: &str,
) -> peer::DirectTraversalEventDiagnostics {
    let result = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            let found = peers
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == peer_id)
                .and_then(|peer| {
                    peer.direct_events
                        .into_iter()
                        .find(|event| event.stage == stage)
                });
            if let Some(event) = found {
                return event;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if let Ok(event) = result {
        return event;
    }
    let diagnostics = peers.diagnostics().await;
    panic!("peer {peer_id} did not record stage {stage}; diagnostics={diagnostics:#?}")
}

async fn wait_for_both_sweep_failures(harness: &TwoPeerHarness) {
    let (_a, _b) = tokio::join!(
        wait_for_stage(&harness.peers_a, HARD_HARD_B, "hard_hard_sweep_failed"),
        wait_for_stage(&harness.peers_b, HARD_HARD_A, "hard_hard_sweep_failed"),
    );
}

async fn summarize_hard_hard_diagnostics(
    peers: &PeerManager,
    peer_id: &str,
) -> Option<Vec<(String, String)>> {
    peers
        .diagnostics()
        .await
        .into_iter()
        .find(|peer| peer.node_id == peer_id)
        .map(|peer| {
            peer.direct_events
                .into_iter()
                .filter(|event| {
                    event.stage.starts_with("hard_hard_")
                        || event.stage.starts_with("direct_validation_")
                })
                .map(|event| (event.stage, event.detail))
                .collect()
        })
}

async fn wait_for_hard_hard_response_signal(harness: &TwoPeerHarness) -> TestControlSignal {
    wait_for_hard_hard_response_signal_number(harness, 1).await
}

async fn wait_for_hard_hard_response_signal_number(
    harness: &TwoPeerHarness,
    response_number: usize,
) -> TestControlSignal {
    let result = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            let responses = harness
                .signals_a
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .iter()
                .filter(|signal| {
                    signal
                        .session_id
                        .as_deref()
                        .is_some_and(|session| session.starts_with("hh1:r:"))
                })
                .cloned()
                .collect::<Vec<_>>();
            if let Some(response) = responses.into_iter().nth(response_number.saturating_sub(1)) {
                return response;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if let Ok(response) = result {
        return response;
    }
    let diagnostics_a = harness.peers_a.diagnostics().await;
    let diagnostics_b = harness.peers_b.diagnostics().await;
    let session_a = harness
        .peers_a
        .hard_hard_session_for_test(HARD_HARD_B)
        .await;
    let session_b = harness
        .peers_b
        .hard_hard_session_for_test(HARD_HARD_A)
        .await;
    let signals_a = harness
        .signals_a
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let signals_b = harness
        .signals_b
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let stun_observers = harness
        .stun_observers
        .iter()
        .map(TestStunObserver::diagnostics)
        .collect::<Vec<_>>();
    panic!(
        "A must receive Hard↔Hard response number {response_number} before the race\nA diagnostics={diagnostics_a:#?}\nB diagnostics={diagnostics_b:#?}\nA session={session_a:#?}\nB session={session_b:#?}\nA sockets={} B sockets={}\nSTUN observers(endpoint, requests, responses)={stun_observers:#?}\nA received signals={signals_a:#?}\nB received signals={signals_b:#?}",
        harness.udp_a.dynamic_socket_count().await,
        harness.udp_b.dynamic_socket_count().await,
    )
}

async fn inject_candidate_offer(
    harness: &TwoPeerHarness,
    signal: &TestControlSignal,
    candidate_generation: u64,
    session_id: Option<String>,
) -> crate::control::SignalDeliveryReceipt {
    let signal_seq = HARD_HARD_NEXT_SIGNAL_SEQ.fetch_add(1, Ordering::Relaxed);
    let receipt = crate::control::SignalDeliveryReceipt::pending();
    harness
        .control_a
        .event_sender()
        .send(ControlEvent::DeliveredSignal {
            signal_id: format!("hard-hard-test-signal-{signal_seq}"),
            signal_seq: Some(signal_seq),
            event: Box::new(ControlEvent::PeerOffer {
                from_node_id: signal.from_node_id.clone(),
                candidates: signal.candidates.clone(),
                session_id,
                probe_ephemeral_public_key: None,
                candidate_sources: signal.candidate_sources.clone(),
                candidate_generation,
                candidates_expires_at_ms: signal.candidates_expires_at_ms,
                handshake_init: signal.handshake_init.clone(),
                punch_at_ms: None,
                punch_at_server_ms: None,
                sender_public_key: Some(signal.sender_public_key.clone()),
            }),
            receipt: receipt.clone(),
        })
        .expect("test control ingress must accept candidate event");
    receipt
}

async fn wait_for_injected_offer_disposition(
    receipt: crate::control::SignalDeliveryReceipt,
) -> crate::control::SignalApplyOutcome {
    timeout(HARD_HARD_E2E_TIMEOUT, receipt.wait())
        .await
        .expect("candidate offer must reach a state-machine disposition")
}

async fn wait_for_failed_attempt_cleanup(harness: &TwoPeerHarness) {
    // Capture the expected identities before retirement removes the ledger.
    // Timeout diagnostics compare tokens without ever printing them.
    let expected_a = harness
        .peers_a
        .hard_hard_session_for_test(HARD_HARD_B)
        .await
        .map(|record| (record.session_id, record.session_token));
    let expected_b = harness
        .peers_b
        .hard_hard_session_for_test(HARD_HARD_A)
        .await
        .map(|record| (record.session_id, record.session_token));
    let result = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            let clean = !harness
                .peers_a
                .hard_hard_session_is_active(HARD_HARD_B)
                .await
                && !harness
                    .peers_b
                    .hard_hard_session_is_active(HARD_HARD_A)
                    .await
                && harness
                    .peers_a
                    .hard_hard_session_for_test(HARD_HARD_B)
                    .await
                    .is_none()
                && harness
                    .peers_b
                    .hard_hard_session_for_test(HARD_HARD_A)
                    .await
                    .is_none()
                && harness.udp_a.dynamic_socket_count().await == 0
                && harness.udp_b.dynamic_socket_count().await == 0
                && harness
                    .udp_a
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                    .await
                    == 0
                && harness
                    .udp_b
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                    .await
                    == 0;
            if clean {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if result.is_err() {
        let a_active = harness
            .peers_a
            .hard_hard_session_is_active(HARD_HARD_B)
            .await;
        let a_sockets = harness.udp_a.dynamic_socket_count().await;
        let a_pending = harness
            .udp_a
            .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
            .await;
        let b_active = harness
            .peers_b
            .hard_hard_session_is_active(HARD_HARD_A)
            .await;
        let b_sockets = harness.udp_b.dynamic_socket_count().await;
        let b_pending = harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await;
        let a_session = harness
            .peers_a
            .hard_hard_session_for_test(HARD_HARD_B)
            .await
            .map(|record| {
                (
                    record.state,
                    record.cancellation.is_cancelled(),
                    record.expires_at_ms,
                    record.fresh_socket.socket_index,
                    expected_a
                        .as_ref()
                        .is_some_and(|(_, token)| token == &record.session_token),
                )
            });
        let b_session = harness
            .peers_b
            .hard_hard_session_for_test(HARD_HARD_A)
            .await
            .map(|record| {
                (
                    record.state,
                    record.cancellation.is_cancelled(),
                    record.expires_at_ms,
                    record.fresh_socket.socket_index,
                    expected_b
                        .as_ref()
                        .is_some_and(|(_, token)| token == &record.session_token),
                )
            });
        let a_cleanup_owner = if let Some((session_id, token)) = expected_a.as_ref() {
            harness
                .peers_a
                .hard_hard_cleanup_owner_claimed_for_test(HARD_HARD_B, session_id, token)
                .await
        } else {
            false
        };
        let b_cleanup_owner = if let Some((session_id, token)) = expected_b.as_ref() {
            harness
                .peers_b
                .hard_hard_cleanup_owner_claimed_for_test(HARD_HARD_A, session_id, token)
                .await
        } else {
            false
        };
        let a_winner = if let Some((_, token)) = expected_a.as_ref() {
            harness
                .peers_a
                .hard_hard_winner_for_token(HARD_HARD_B, token)
                .await
        } else {
            None
        };
        let b_winner = if let Some((_, token)) = expected_b.as_ref() {
            harness
                .peers_b
                .hard_hard_winner_for_token(HARD_HARD_A, token)
                .await
        } else {
            None
        };
        let a_udp = harness
            .udp_a
            .hard_hard_udp_lifecycle_snapshot_for_test(
                HARD_HARD_B,
                expected_a.as_ref().map(|(_, token)| token.as_str()),
            )
            .await;
        let b_udp = harness
            .udp_b
            .hard_hard_udp_lifecycle_snapshot_for_test(
                HARD_HARD_A,
                expected_b.as_ref().map(|(_, token)| token.as_str()),
            )
            .await;
        panic!(
            "failed Hard↔Hard attempt cleanup:\nA active={a_active} direct={} sockets={a_sockets} pending={a_pending} session(state,cancelled,expires_at_ms,socket,token_match)={a_session:?} cleanup_owner={a_cleanup_owner} winner={a_winner:?} udp={a_udp:#?}\nB active={b_active} direct={} sockets={b_sockets} pending={b_pending} session(state,cancelled,expires_at_ms,socket,token_match)={b_session:?} cleanup_owner={b_cleanup_owner} winner={b_winner:?} udp={b_udp:#?}",
            harness.peers_a.is_direct(HARD_HARD_B).await,
            harness.peers_b.is_direct(HARD_HARD_A).await,
        );
    }
}

async fn assert_relay_remains_available(harness: &TwoPeerHarness) {
    assert_eq!(
        harness
            .peers_a
            .select_path_for_data(HARD_HARD_B, true, true)
            .await
            .path,
        Some(NetworkPath::Relay)
    );
    assert_eq!(
        harness
            .peers_b
            .select_path_for_data(HARD_HARD_A, true, true)
            .await
            .path,
        Some(NetworkPath::Relay)
    );
}

async fn build_hard_hard_ordinary_fallback_fixture(
) -> (Daemon, Arc<PeerManager>, UdpTransport, ControlClient) {
    let mut config =
        Config::generate_default("http://hard-hard-fallback.test", "phase-2-2-fallback").unwrap();
    config.node.node_id = HARD_HARD_A.to_string();
    config.network.manual = true;
    config.network.udp_bind = "127.0.0.1:0".to_string();
    config.network.fresh_mapping_punch_enabled = true;
    config.network.fresh_mapping_harness_loopback = true;
    config.network.birthday_probing_enabled = false;
    config.relay.servers = vec!["relay.invalid:443".to_string()];
    let daemon = Daemon::new(config);
    let peers = daemon.peers.clone();

    let local_public: SocketAddr = "198.51.100.10:41000".parse().unwrap();
    let remote_public: SocketAddr = "198.51.100.20:42000".parse().unwrap();
    let local_profile = hard_hard_profile(local_public, 4);
    let remote_profile = hard_hard_profile(remote_public, 3);
    peers.update_nat_profile(local_profile).await;
    let remote = peer_info(
        HARD_HARD_B,
        "10.20.0.2",
        "hard-hard-fallback-peer-key".to_string(),
        remote_public,
        remote_profile.control_label_with_generation(1),
    );
    peers.add_peer(&remote).await;
    peers
        .add_candidates_with_sources(
            HARD_HARD_B,
            &[remote_public.to_string()],
            &HashMap::from([(remote_public.to_string(), "predicted".to_string())]),
        )
        .await;
    // Bind the parsed remote profile to the candidate epoch installed above.
    peers.add_peer(&remote).await;
    assert!(
        peers.hard_hard_plan_for_peer(HARD_HARD_B).await.is_some(),
        "fixture must select the Hard↔Hard planner branch"
    );

    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let control = daemon.control.clone();
    (daemon, peers, udp, control)
}

fn hard_hard_fallback_signal(
    control: ControlClient,
    boot_epoch_ms: u64,
    stun_servers: Vec<SocketAddr>,
) -> HolePunchSignalContext {
    HolePunchSignalContext {
        control,
        candidate_snapshot: Arc::new(RwLock::new(None)),
        stun_servers,
        stun_timeout: Duration::from_millis(25),
        boot_epoch_ms,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_initiator_is_cancelled_with_its_udp_invocation_only() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );
    let deduplicator = PunchAttemptDeduplicator::default();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    spawn_hole_punch_task_with_lifecycle(
        udp,
        peers.clone(),
        deduplicator.clone(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
        Some(shutdown_rx),
    )
    .await;
    assert_eq!(
        deduplicator.active_session_count(),
        1,
        "the initiator measurement must own its punch permit before detaching"
    );

    shutdown_tx.send(true).unwrap();
    let replacement_generation = peers
        .advance_network_generation("supersede Hard-Hard UDP invocation")
        .await;
    timeout(Duration::from_secs(1), async {
        while deduplicator.active_session_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the old invocation must cancel and release its exact Hard-Hard permit");
    sleep(Duration::from_millis(150)).await;

    let conn = peers.get_connection(HARD_HARD_B).await.unwrap();
    assert!(
        !conn.direct_events.iter().any(|event| {
            event.network_generation == replacement_generation
                && matches!(
                    event.stage.as_str(),
                    "hard_hard_measurement_failed"
                        | "hard_hard_measurement_fenced"
                        | "hard_hard_prediction_signaled"
                        | "hard_hard_advertisement_failed"
                        | "punch_started"
                )
        }),
        "a cancelled old Hard-Hard invocation must not publish or write recovery progress into the replacement generation"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_failed_preledger_measurement_releases_udp_lifecycle_watcher() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );
    let deduplicator = PunchAttemptDeduplicator::default();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    spawn_hole_punch_task_with_lifecycle(
        udp,
        peers.clone(),
        deduplicator.clone(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
        Some(shutdown_rx),
    )
    .await;
    wait_for_stage(&peers, HARD_HARD_B, "hard_hard_measurement_failed").await;

    timeout(Duration::from_secs(1), async {
        while shutdown_tx.receiver_count() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a pre-ledger failure must cancel its handle and let the lease watcher exit");
    assert_eq!(
        deduplicator.active_session_count(),
        0,
        "the failed measurement must also release its short-lived punch owner"
    );
    assert!(
        !*shutdown_tx.borrow(),
        "the watcher must exit because its exact session was cancelled, not because the UDP lease ended"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_lifecycle_watcher_exits_when_session_finishes_first() {
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let cancellation = Arc::new(crate::PunchSessionCancellation::default());
    bind_hard_hard_session_to_punch_invocation(Some(shutdown_rx), cancellation.clone());
    assert!(
        Arc::strong_count(&cancellation) >= 2,
        "the lifecycle watcher must own the exact session cancellation handle"
    );

    cancellation.cancel_for_hard_hard_cleanup();
    timeout(Duration::from_secs(1), async {
        while Arc::strong_count(&cancellation) != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a completed/removed session must not retain a watcher until the UDP lease ends");
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_preflight_failure_falls_through_to_ordinary_punch() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let signal = hard_hard_fallback_signal(control, 0, Vec::new());

    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
    )
    .await;

    let fallback = wait_for_stage(&peers, HARD_HARD_B, "hard_hard_fallback_to_ordinary").await;
    assert!(fallback.detail.contains("reason=boot_epoch_unavailable"));
    wait_for_stage(&peers, HARD_HARD_B, "punch_started").await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_insufficient_stun_falls_through_to_ordinary_punch() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );

    spawn_hole_punch_task(
        udp,
        peers.clone(),
        PunchAttemptDeduplicator::default(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
    )
    .await;

    let fallback = wait_for_stage(&peers, HARD_HARD_B, "hard_hard_fallback_to_ordinary").await;
    assert!(fallback
        .detail
        .contains("reason=insufficient_stun_observers"));
    wait_for_stage(&peers, HARD_HARD_B, "punch_started").await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_responder_without_stun_worker_falls_back_to_admitted_fresh_punch() {
    // The Hard-Hard clock override is process-global so spawned E2E workers can
    // observe it. Serialize this real-clock assertion with those fixtures, and
    // clear any previous override only after owning their shared guard.
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    set_hard_hard_test_now_ms(None);
    let _clock = HardHardClockReset;
    let (daemon, peers, udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let local_endpoint = udp.local_addr().unwrap();
    daemon
        .publish_candidate_snapshot(
            vec![local_endpoint.to_string()],
            HashMap::from([(local_endpoint.to_string(), "host".to_string())]),
            vec!["hard-hard-responder-fallback".to_string()],
        )
        .await;
    *daemon.udp_transport.write().await = Some(udp);
    daemon.runtime_stun_servers.write().await.clear();

    let plan = peers
        .hard_hard_plan_for_peer(HARD_HARD_B)
        .await
        .expect("fixture must retain its Hard↔Hard plan");
    let remote_prediction: SocketAddr = "198.51.100.20:42000".parse().unwrap();
    let coordination = HardHardCoordination {
        role: HardHardRole::Initiator,
        token: "feed-face".to_string(),
        local_network_generation: 0,
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.remote_profile_generation,
        remote_profile_generation: plan.local_profile_generation,
        local_prediction_confidence: 90,
        remote_prediction_confidence: 0,
        local_prediction_model: "fixed_step".to_string(),
        remote_prediction_model: "unknown".to_string(),
        remote_network_generation: 0,
    };
    let punch_at_ms = hard_hard_now_for_test().saturating_add(3_500);
    let offer = PendingPeerOffer {
        from_node_id: HARD_HARD_B.to_string(),
        candidates: vec![remote_prediction.to_string()],
        candidate_sources: HashMap::new(),
        candidate_generation: 1,
        network_generation: peers.current_network_generation_sync(),
        peer_session_generation: peers.peer_session_generation_sync(HARD_HARD_B),
        candidates_expires_at_ms: Some(punch_at_ms.saturating_add(30_000)),
        sender_public_key: None,
        handshake_init: Vec::new(),
        punch_at_ms: Some(punch_at_ms),
        punch_at_server_ms: None,
        session_id: Some(coordination.encode()),
        probe_ephemeral_public_key: None,
        delivery_receipt: None,
    };

    daemon
        .apply_deferred_peer_offer_punch(
            &offer,
            CandidateSetApplyResult::Applied,
            FreshPunchDecision::Fresh(
                crate::FreshPredictionId {
                    boot_epoch: 1,
                    generation: 1,
                },
                vec![remote_prediction],
            ),
        )
        .await;

    wait_for_stage(&peers, HARD_HARD_B, "hard_hard_skipped").await;
    wait_for_stage(&peers, HARD_HARD_B, "punch_scheduled").await;
    assert!(
        !peers.hard_hard_session_is_active(HARD_HARD_B).await,
        "a responder which never claimed a Hard↔Hard worker must not leave a handled session"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_async_failure_uses_next_trigger_for_ordinary_punch() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    // Bound three sockets that intentionally never answer STUN.  This admits
    // Hard↔Hard, then deterministically fails its asynchronous measurement.
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let stun_servers = blackholes
        .iter()
        .map(|socket| socket.local_addr().unwrap())
        .collect::<Vec<_>>();
    let signal = hard_hard_fallback_signal(control, 1, stun_servers);
    let deduplicator = PunchAttemptDeduplicator::default();

    spawn_hole_punch_task(
        udp.clone(),
        peers.clone(),
        deduplicator.clone(),
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal.clone()),
        None,
        None,
    )
    .await;
    wait_for_stage(&peers, HARD_HARD_B, "hard_hard_measurement_failed").await;
    assert!(
        !peers
            .get_connection(HARD_HARD_B)
            .await
            .unwrap()
            .direct_events
            .iter()
            .any(|event| event.stage == "punch_started"),
        "the trigger owned by the asynchronous Hard↔Hard attempt must not also start ordinary punching"
    );

    // A recovery epoch permits exactly one fresh generation.  Once the failed
    // worker releases its punch permit, the next trigger observes that spent
    // quota, returns NotStarted, and must continue through ordinary punching.
    spawn_hole_punch_task(
        udp,
        peers.clone(),
        deduplicator,
        HARD_HARD_B.to_string(),
        Duration::from_millis(1),
        1,
        None,
        Some(signal),
        None,
        None,
    )
    .await;
    let fallback = wait_for_stage(&peers, HARD_HARD_B, "hard_hard_fallback_to_ordinary").await;
    assert!(fallback
        .detail
        .contains("reason=fresh_generation_quota_exhausted"));
    wait_for_stage(&peers, HARD_HARD_B, "punch_started").await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_initiator_deferred_claim_refunds_exact_fresh_quota() {
    let (_daemon, peers, udp, control) = build_hard_hard_ordinary_fallback_fixture().await;
    let blackholes = [
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
        UdpSocket::bind("127.0.0.1:0").await.unwrap(),
    ];
    let signal = hard_hard_fallback_signal(
        control,
        1,
        blackholes
            .iter()
            .map(|socket| socket.local_addr().unwrap())
            .collect(),
    );
    let deduplicator = PunchAttemptDeduplicator::default();
    let epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("fixture recovery must be admitted: {admission:?}"),
    };
    let existing = match deduplicator
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_B,
            peers.current_network_generation_sync(),
            epoch,
            PUNCH_PRIORITY_FRESH_PREDICTION,
            None,
            None,
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => panic!("fixture fresh owner must claim"),
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };

    assert_eq!(
        spawn_hard_hard_initiator(
            udp,
            peers.clone(),
            deduplicator,
            HARD_HARD_B.to_string(),
            signal,
            None,
        )
        .await,
        HardHardInitiatorStart::ExistingPunchOwner,
    );
    assert_eq!(
        peers
            .recovery_epoch_work_budget_report(HARD_HARD_B)
            .await
            .expect("the recovery epoch must remain active")
            .fresh_generations_remaining,
        1,
        "an initiator which never acquired the punch owner must refund its exact reservation"
    );
    assert_eq!(
        peers
            .recovery_epoch_work_budget_report(HARD_HARD_B)
            .await
            .expect("the recovery epoch must remain active")
            .hard_hard_generations_remaining,
        1,
        "the dedicated Hard↔Hard fresh-generation lane must not be consumed by a deferred claim"
    );
    assert!(!existing.is_cancelled());
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_response_network_generation_fence_precedes_punch_preemption() {
    let (_daemon, peers, udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let plan = peers
        .hard_hard_plan_for_peer(HARD_HARD_B)
        .await
        .expect("fixture must retain its Hard↔Hard plan");
    let punch_at_ms = hard_hard_now_for_test().saturating_add(3_500);
    let token = "network-fence-before-claim".to_string();
    let socket_local_endpoint = udp.local_addr().unwrap();
    let remote_prediction: SocketAddr = "198.51.100.20:42000".parse().unwrap();
    assert!(
        peers
            .hard_hard_register_session(peer::HardHardSessionRecord {
                session_id: format!("hh1:i:{token}"),
                probe_session_id: None,
                session_token: token.clone(),
                peer_id: HARD_HARD_B.to_string(),
                initiator: true,
                remote_network_generation: 0,
                local_network_generation: plan.local_network_generation,
                remote_candidate_epoch: plan.remote_candidate_epoch,
                local_profile_generation: plan.local_profile_generation,
                remote_profile_generation: plan.remote_profile_generation,
                local_prediction_confidence: 95,
                remote_prediction_confidence: 0,
                requested_birthday_level: 0,
                generated_candidate_count: 1,
                signaled_candidate_count: 1,
                birthday: false,
                requested_socket_indices: vec![4096],
                requested_socket_count: 1,
                prediction_window: vec![remote_prediction],
                remote_prediction: Vec::new(),
                fresh_socket: peer::HardHardFreshSocketIdentity {
                    peer_id: HARD_HARD_B.to_string(),
                    session_token: token.clone(),
                    network_generation: plan.local_network_generation,
                    remote_candidate_epoch: plan.remote_candidate_epoch,
                    local_profile_generation: plan.local_profile_generation,
                    remote_profile_generation: plan.remote_profile_generation,
                    punch_generation: 1,
                    socket_index: 4096,
                    socket_local_endpoint,
                },
                punch_at_ms,
                expires_at_ms: punch_at_ms.saturating_add(30_000),
                state: peer::HardHardSessionState::AwaitingPeer,
                attempt_count: 0,
                created_at: Instant::now(),
                cancellation: Arc::new(crate::PunchSessionCancellation::default()),
            })
            .await
    );
    let epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("fixture recovery must be admitted: {admission:?}"),
    };
    let deduplicator = PunchAttemptDeduplicator::default();
    let ordinary = match deduplicator
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_B,
            plan.local_network_generation,
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(punch_at_ms),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => panic!("ordinary fixture must claim first"),
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };

    let disposition = spawn_hard_hard_initiator_response(
        udp,
        peers,
        deduplicator,
        HARD_HARD_B.to_string(),
        HardHardCoordination {
            role: HardHardRole::Responder,
            token,
            local_network_generation: 9,
            remote_candidate_epoch: plan.remote_candidate_epoch,
            local_profile_generation: plan.remote_profile_generation,
            remote_profile_generation: plan.local_profile_generation,
            local_prediction_confidence: 90,
            remote_prediction_confidence: 95,
            local_prediction_model: "fixed_step".to_string(),
            remote_prediction_model: "fixed_step".to_string(),
            // Deliberately invalid: this must fence before a priority-2 claim
            // can cancel the ordinary priority-1 owner.
            remote_network_generation: plan.local_network_generation.saturating_add(1),
        },
        vec![remote_prediction],
        punch_at_ms,
    )
    .await;
    assert_eq!(disposition, HardHardRemoteStart::Rejected);
    assert!(
        !ordinary.is_cancelled(),
        "a generation-mismatched response must not preempt the existing ordinary owner"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn stale_fresh_reservation_cannot_refund_recreated_numeric_epoch() {
    let (_daemon, peers, _udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let old_epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("old recovery epoch must be admitted: {admission:?}"),
    };
    let old_reservation = peers
        .try_begin_fresh_generation_for_epoch(HARD_HARD_B, old_epoch)
        .await
        .expect("old epoch must reserve its fresh quota");

    peers
        .recovery_epoch_end(HARD_HARD_B, "test_recreate_numeric_epoch")
        .await;
    let new_epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("replacement recovery epoch must be admitted: {admission:?}"),
    };
    assert_eq!(
        new_epoch, old_epoch,
        "the regression fixture must reproduce numeric recovery-epoch ABA"
    );
    let new_reservation = peers
        .try_begin_fresh_generation_for_epoch(HARD_HARD_B, new_epoch)
        .await
        .expect("replacement epoch must independently reserve its quota");

    old_reservation.refund().await;
    assert_eq!(
        peers
            .recovery_epoch_work_budget_report(HARD_HARD_B)
            .await
            .expect("replacement epoch must remain active")
            .fresh_generations_remaining,
        0,
        "an old allocation token must not replenish the replacement epoch"
    );
    new_reservation.refund().await;
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_fresh_reservation_refunds_after_epoch_lock_contention() {
    let (_daemon, peers, _udp, _control) = build_hard_hard_ordinary_fallback_fixture().await;
    let epoch = match peers.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("recovery epoch must be admitted: {admission:?}"),
    };
    let reservation = peers
        .try_begin_fresh_generation_for_epoch(HARD_HARD_B, epoch)
        .await
        .expect("fixture must reserve the sole fresh quota");
    let reached = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let holder = tokio::spawn({
        let peers = peers.clone();
        let reached = reached.clone();
        let release = release.clone();
        async move {
            peers
                .hold_recovery_epoch_write_for_test(reached, release)
                .await;
        }
    });
    reached.notified().await;

    // Models an outer UDP-lease select dropping the Hard↔Hard future while
    // its explicit refund is blocked behind the epoch writer.
    drop(reservation);
    release.notify_one();
    holder.await.unwrap();
    timeout(Duration::from_secs(1), async {
        loop {
            if peers
                .recovery_epoch_work_budget_report(HARD_HARD_B)
                .await
                .is_some_and(|budget| budget.fresh_generations_remaining == 1)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelling the reservation owner must asynchronously refund the exact epoch");
}

async fn hard_hard_two_peer_success_with_stun(stun: HarnessStunProfile) {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun(true, false, false, stun).await;
    trigger_initial_offer(&harness).await;
    wait_for_both_direct(&harness).await;
    // Reciprocal exact-socket traffic can promote both peers before the
    // non-owner reaches its scheduled sweep.  Require the authoritative path
    // outcome on both sides and proof that at least one real sweep owner
    // completed; do not require a redundant post-Direct sweep from both.
    let sweep_detail = timeout(Duration::from_secs(3), async {
        loop {
            for (peers, peer_id) in [
                (&harness.peers_a, HARD_HARD_B),
                (&harness.peers_b, HARD_HARD_A),
            ] {
                if let Some(detail) = peers.get_connection(peer_id).await.and_then(|connection| {
                    connection
                        .direct_events
                        .iter()
                        .find(|event| event.stage == "hard_hard_sweep_completed")
                        .map(|event| event.detail.clone())
                }) {
                    return detail;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("at least one exact-socket Hard↔Hard owner must complete its sweep");
    assert!(sweep_detail.contains("exact_socket=true"));
    assert!(sweep_detail.contains("direct_confirmed=true"));

    let fresh_direct_a =
        wait_for_current_fresh_direct(&harness.peers_a, &harness.udp_a, HARD_HARD_B).await;
    let fresh_direct_b =
        wait_for_current_fresh_direct(&harness.peers_b, &harness.udp_b, HARD_HARD_A).await;
    let peer_a = fresh_direct_a.diagnostics;
    let peer_b = fresh_direct_b.diagnostics;
    for diagnostics in [&peer_a, &peer_b] {
        assert_eq!(diagnostics.state, ConnectionState::Direct);
        assert_eq!(diagnostics.active_path, Some(NetworkPath::Direct));
    }

    let measured_a = fresh_direct_a.socket_index;
    let measured_b = fresh_direct_b.socket_index;
    assert!(!fresh_direct_a.predicted_ports.is_empty());
    assert!(!fresh_direct_b.predicted_ports.is_empty());
    assert_eq!(
        Some(fresh_direct_a.socket_local_endpoint),
        harness
            .udp_a
            .socket_for_peer(Some(HARD_HARD_B))
            .await
            .and_then(|(_, socket)| socket.local_addr().ok())
    );
    assert_eq!(
        Some(fresh_direct_b.socket_local_endpoint),
        harness
            .udp_b
            .socket_for_peer(Some(HARD_HARD_A))
            .await
            .and_then(|(_, socket)| socket.local_addr().ok())
    );
    assert_eq!(
        harness
            .udp_a
            .affinity_pin_for_test(HARD_HARD_B)
            .await
            .map(|pin| pin.socket_index),
        Some(measured_a),
    );
    assert_eq!(
        harness
            .udp_b
            .affinity_pin_for_test(HARD_HARD_A)
            .await
            .map(|pin| pin.socket_index),
        Some(measured_b),
    );
    let current_pair_a = peer_a
        .current_direct_pair
        .as_ref()
        .expect("A must expose its selected Direct candidate pair");
    let current_pair_b = peer_b
        .current_direct_pair
        .as_ref()
        .expect("B must expose its selected Direct candidate pair");
    let expected_remote_a = harness.link.b_public.local_addr().unwrap();
    let expected_remote_b = harness.link.a_public.local_addr().unwrap();
    assert_eq!(
        current_pair_a.source,
        peer::CandidatePairSource::PeerReflexive
    );
    assert_eq!(
        current_pair_b.source,
        peer::CandidatePairSource::PeerReflexive
    );
    assert_eq!(
        current_pair_a.remote_endpoint,
        expected_remote_a.to_string()
    );
    assert_eq!(
        current_pair_b.remote_endpoint,
        expected_remote_b.to_string()
    );
    assert_eq!(
        current_pair_a.local_endpoint.as_deref(),
        Some(fresh_direct_a.socket_local_endpoint.to_string()).as_deref()
    );
    assert_eq!(
        current_pair_b.local_endpoint.as_deref(),
        Some(fresh_direct_b.socket_local_endpoint.to_string()).as_deref()
    );
    assert!(
        harness
            .udp_a
            .authenticated_evidence_for_socket(measured_a)
            .await
            > 0
    );
    assert!(
        harness
            .udp_b
            .authenticated_evidence_for_socket(measured_b)
            .await
            > 0
    );
    assert!(harness.udp_a.dynamic_socket_count().await >= 1);
    assert!(harness.udp_b.dynamic_socket_count().await >= 1);
    for signals in [&harness.signals_a, &harness.signals_b] {
        assert!(signals.lock().unwrap().iter().any(|signal| {
            signal.session_id.is_some()
                && signal
                    .candidate_sources
                    .values()
                    .any(|source| source.starts_with("predicted_fresh:"))
        }));
    }

    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_success_is_full_e2e_and_exact_socket() {
    hard_hard_two_peer_success_with_stun(HarnessStunProfile::FULL_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_success_with_minimum_stun_capacity() {
    hard_hard_two_peer_success_with_stun(HarnessStunProfile::MINIMUM_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_random_random_birthday_collision_is_full_production_e2e() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;

    for diagnostics in [harness.peers_a.diagnostics().await, harness.peers_b.diagnostics().await]
    {
        assert_eq!(
            diagnostics[0]
                .traversal_plan
                .as_ref()
                .map(|plan| plan.reason.as_str()),
            Some("hard_hard_bounded_birthday")
        );
    }

    trigger_initial_offer(&harness).await;
    wait_for_both_direct_compact(&harness).await;

    for (peers, remote_id, expected_remote) in [
        (&harness.peers_a, HARD_HARD_B, harness.link.b_public.local_addr().unwrap()),
        (&harness.peers_b, HARD_HARD_A, harness.link.a_public.local_addr().unwrap()),
    ] {
        let peer = wait_for_current_direct_diagnostics(peers, remote_id).await;
        assert_eq!(peer.state, ConnectionState::Direct);
        assert_eq!(peer.active_path, Some(NetworkPath::Direct));
        let observed = peer
            .direct_events
            .iter()
            .find(|event| event.stage == "hard_hard_fresh_mapping_observed")
            .or_else(|| {
                peer.direct_events
                    .iter()
                    .find(|event| event.stage == "hard_hard_local_nat_model")
            });
        if let Some(observed) = observed {
            assert!(observed.detail.contains("model=high_entropy"));
            assert!(observed.detail.contains("strategy=bounded_birthday"));
            assert!(observed.detail.contains("socket_count=2"));
        }
        let winner = peer
            .direct_events
            .iter()
            .find(|event| event.stage == "hard_hard_winner_selected")
            .expect("authenticated Probe v2 evidence must select a birthday winner");
        let winner_socket = winner.socket_index.expect("winner must name its socket");
        let winner_phase = if remote_id == HARD_HARD_B {
            harness
                .udp_a
                .dynamic_socket_phase_for_test(winner_socket)
                .await
        } else {
            harness
                .udp_b
                .dynamic_socket_phase_for_test(winner_socket)
                .await
        };
        assert_eq!(
            winner_phase,
            Some(crate::udp::DynamicSocketPhase::Finalized),
            "authenticated birthday winner must reach the Finalized phase: peer={} winner={} dynamic_count={} stages={:?}",
            peer.node_id,
            winner_socket,
            if remote_id == HARD_HARD_B {
                harness.udp_a.dynamic_socket_count().await
            } else {
                harness.udp_b.dynamic_socket_count().await
            },
            peer.direct_events
                .iter()
                .filter(|event| event.stage.starts_with("hard_hard_"))
                .map(|event| (event.stage.as_str(), event.detail.as_str()))
                .collect::<Vec<_>>(),
        );
        let affinity_socket = if remote_id == HARD_HARD_B {
            harness
                .udp_a
                .affinity_pin_for_test(remote_id)
                .await
                .map(|pin| pin.socket_index)
        } else {
            harness
                .udp_b
                .affinity_pin_for_test(remote_id)
                .await
                .map(|pin| pin.socket_index)
        };
        assert_eq!(
            affinity_socket,
            Some(winner_socket)
        );
        let pair = peer
            .current_direct_pair
            .as_ref()
            .expect("Direct must expose the selected birthday pair");
        assert_eq!(pair.source, peer::CandidatePairSource::PeerReflexive);
        assert_eq!(pair.remote_endpoint, expected_remote.to_string());
    }
    let birthday_signals = [
        harness
            .signals_a
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
        harness
            .signals_b
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone(),
    ];
    let birthday_signal_seen = birthday_signals
        .iter()
        .flat_map(|signals| signals.iter())
        .any(|signal| {
            signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.contains("high_entropy"))
        });
    assert!(
        birthday_signal_seen,
        "the session envelope must identify the HighEntropy birthday lane"
    );

    let parse_count = |detail: &str, key: &str| {
        detail
            .split_whitespace()
            .find_map(|field| field.strip_prefix(key)?.parse::<usize>().ok())
    };
    // Read the durable connection ring, not the non-blocking diagnostics
    // cache. A reciprocal Direct promotion can still own the connections
    // writer when this assertion runs; the cache is allowed to return its
    // previous snapshot in that narrow interval.
    let birthday_events = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            for (peers, peer_id) in [
                (&harness.peers_a, HARD_HARD_B),
                (&harness.peers_b, HARD_HARD_A),
            ] {
                if let Some(connection) = peers.get_connection(peer_id).await {
                    let events = connection
                        .direct_events
                        .into_iter()
                        .filter(|event| {
                            event.stage == "hard_hard_birthday_sweep_summary"
                                && event.detail.contains("requested_level=64")
                        })
                        .collect::<Vec<_>>();
                    if !events.is_empty() {
                        return events;
                    }
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("production birthday sweep must report its bounded send count");
    let mut birthday_summaries = 0;
    for event in &birthday_events {
            let sent = parse_count(&event.detail, "packets_sent=")
                .expect("birthday summary must report sent packets");
            let unique = parse_count(&event.detail, "unique_target_endpoints=")
                .expect("birthday summary must report unique target endpoints");
            let effective_target_count = parse_count(&event.detail, "effective_target_count=")
                .expect("birthday summary must report effective target count");
            let generated_candidate_count = parse_count(&event.detail, "generated_candidate_count=")
                .expect("birthday summary must report generated candidates");
            let signaled_candidate_count = parse_count(&event.detail, "signaled_candidate_count=")
                .expect("birthday summary must report signaled candidates");
            let requested_socket_count = parse_count(&event.detail, "requested_socket_count=")
                .expect("birthday summary must report requested sockets");
            let attached_socket_count = parse_count(&event.detail, "attached_socket_count=")
                .expect("birthday summary must report attached sockets");
            let usable_socket_count = parse_count(&event.detail, "usable_socket_count=")
                .expect("birthday summary must report usable sockets");
            let unavailable_socket_count =
                parse_count(&event.detail, "unavailable_socket_count=")
                    .expect("birthday summary must report unavailable sockets");
            let packets_planned = parse_count(&event.detail, "packets_planned=")
                .expect("birthday summary must report planned packets");
            let waves_planned = parse_count(&event.detail, "waves_planned=")
                .expect("birthday summary must report planned waves");
            let waves_started = parse_count(&event.detail, "waves_started=")
                .expect("birthday summary must report started waves");
            let waves_fully_completed = parse_count(&event.detail, "waves_fully_completed=")
                .expect("birthday summary must report fully completed waves");
            let targets_assigned = parse_count(&event.detail, "targets_assigned=")
                .expect("birthday summary must report assigned targets");
            let targets_examined = parse_count(&event.detail, "targets_examined=")
                .expect("birthday summary must report examined targets");
            let targets_attempted = parse_count(&event.detail, "targets_attempted=")
                .expect("birthday summary must report attempted targets");
            let logical_probes_attempted =
                parse_count(&event.detail, "logical_probes_attempted=")
                    .expect("birthday summary must report logical attempts");
            let logical_probes_sent = parse_count(&event.detail, "logical_probes_sent=")
                .expect("birthday summary must report logical probes");
            let physical_datagrams_sent =
                parse_count(&event.detail, "physical_datagrams_sent=")
                    .expect("birthday summary must report physical datagrams");
            let physical_send_errors = parse_count(&event.detail, "physical_send_errors=")
                .expect("birthday summary must report physical send errors");
            let targets_cancelled = parse_count(&event.detail, "targets_cancelled=")
                .expect("birthday summary must report cancelled targets");
            assert_eq!(waves_planned, 2);
            assert_eq!(packets_planned, effective_target_count * 2);
            assert!(sent <= packets_planned);
            assert!(unique <= effective_target_count);
            assert!(generated_candidate_count >= signaled_candidate_count);
            assert_eq!(signaled_candidate_count, effective_target_count);
            assert_eq!(requested_socket_count, 2);
            assert!(attached_socket_count <= requested_socket_count);
            assert!(usable_socket_count <= attached_socket_count);
            assert_eq!(unavailable_socket_count, requested_socket_count - usable_socket_count);
            assert!(waves_fully_completed <= waves_started);
            assert!(waves_started <= waves_planned);
            assert!(targets_examined <= targets_assigned);
            assert!(targets_attempted <= targets_assigned);
            assert!(targets_attempted <= targets_examined);
            assert!(logical_probes_sent <= logical_probes_attempted);
            assert!(logical_probes_sent <= effective_target_count * 2);
            assert!(physical_datagrams_sent >= logical_probes_sent);
            assert!(physical_send_errors <= effective_target_count * 2);
            assert_eq!(targets_cancelled, targets_assigned - targets_attempted);
            assert!(event.detail.contains("first_send_at_ms="));
            assert!(event.detail.contains("last_send_at_ms="));
            assert!(event.detail.contains("stop_reason="));
            birthday_summaries += 1;
    }
    assert!(
        birthday_summaries > 0,
        "production birthday sweep must report its bounded send count"
    );

    timeout(Duration::from_secs(1), async {
        loop {
            if harness.udp_a.dynamic_socket_count().await == 1
                && harness.udp_b.dynamic_socket_count().await == 1
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("birthday losers must detach after the authenticated winner is selected");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_physical_send_error_reaches_one_consistent_terminal_reason() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;

    // This is the production Hard birthday entry point. Fail its first
    // physical UDP send at the shared send abstraction; the socket itself is
    // left open so this cannot be mistaken for socket_unavailable.
    let _send_failures = harness.udp_a.set_probe_send_failures_for_test(1..=512);
    let _peer_send_failures = harness.udp_b.set_probe_send_failures_for_test(1..=512);
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;

    let summary = wait_for_stage(
        &harness.peers_a,
        HARD_HARD_B,
        "hard_hard_birthday_sweep_summary",
    )
    .await;
    assert!(summary.detail.contains("physical_send_errors="));
    assert!(
        summary.detail.contains("stop_reason=send_error"),
        "unexpected birthday summary: {}",
        summary.detail
    );
    assert!(!summary.detail.contains("stop_reason=socket_unavailable"));

    let sweep_failed = wait_for_stage(&harness.peers_a, HARD_HARD_B, "hard_hard_sweep_failed")
        .await;
    let hard_failed = wait_for_stage(&harness.peers_a, HARD_HARD_B, "hard_hard_failed").await;
    assert!(sweep_failed.detail.contains("stop_reason=send_error"));
    assert!(hard_failed.detail.contains("stop_reason=send_error"));

    let summary_count = harness
        .peers_a
        .get_connection(HARD_HARD_B)
        .await
        .unwrap()
        .direct_events
        .iter()
        .filter(|event| event.stage == "hard_hard_birthday_sweep_summary")
        .count();
    assert_eq!(summary_count, 1, "one session must emit one final birthday summary");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_random_random_birthday_no_collision_cleans_up_without_direct() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;

    timeout(Duration::from_secs(5), async {
        loop {
            if !harness.peers_a.is_direct(HARD_HARD_B).await
                && !harness.peers_b.is_direct(HARD_HARD_A).await
                && !harness
                    .peers_a
                    .hard_hard_session_is_active(HARD_HARD_B)
                    .await
                && !harness
                    .peers_b
                    .hard_hard_session_is_active(HARD_HARD_A)
                    .await
                && harness.udp_a.dynamic_socket_count().await == 0
                && harness.udp_b.dynamic_socket_count().await == 0
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded birthday no-collision session must terminate and clean up");

    for peers in [&harness.peers_a, &harness.peers_b] {
        let peer = &peers.diagnostics().await[0];
        assert!(peer.state != ConnectionState::Direct);
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_winner_selected"));
    }
    assert_relay_remains_available(&harness).await;
    assert_eq!(
        harness
            .udp_a
            .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
            .await,
        0
    );
    assert_eq!(
        harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await,
        0
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_birthday_production_cleanup_waits_for_udp_completion() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;

    let record = timeout(Duration::from_secs(8), async {
        loop {
            if let Some(record) = harness.peers_b.hard_hard_session_for_test(HARD_HARD_A).await {
                if record.state != peer::HardHardSessionState::Retiring
                    && harness.udp_b.dynamic_socket_count().await > 0
                    && harness
                        .udp_b
                        .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                        .await
                        > 0
                {
                    return record;
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("production Birthday entry must expose a live socket and pending Probe");
    let (gate, _gate_guard) = harness.peers_b.install_hard_hard_cleanup_gate_for_test(
        &record.peer_id,
        &record.session_id,
        &record.session_token,
    );
    let reached = gate.reached.notified();
    harness
        .peers_b
        .clear_hard_hard_sessions(Some(HARD_HARD_A))
        .await;
    timeout(Duration::from_secs(3), reached)
        .await
        .expect("production cleanup must reach the pre-UDP test gate");

    let retiring = harness
        .peers_b
        .hard_hard_session_snapshot_for_cleanup(
            &record.peer_id,
            &record.session_id,
            &record.session_token,
        )
        .await
        .expect("Retiring ledger entry must remain until UDP cleanup completes");
    assert_eq!(retiring.state, peer::HardHardSessionState::Retiring);
    assert!(!harness
        .peers_b
        .hard_hard_session_is_active(HARD_HARD_A)
        .await);
    assert!(harness.udp_b.dynamic_socket_count().await > 0);
    assert!(harness
        .udp_b
        .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
        .await
        > 0);

    let completed = gate.completed.notified();
    gate.release.notify_waiters();
    timeout(Duration::from_secs(5), completed)
        .await
        .expect("production cleanup must publish completion after UDP cleanup");
    assert!(harness
        .peers_b
        .hard_hard_session_snapshot_for_cleanup(
            &record.peer_id,
            &record.session_id,
            &record.session_token,
        )
        .await
        .is_none());
    assert_eq!(harness.udp_b.dynamic_socket_count().await, 0);
    assert_eq!(
        harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await,
        0
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_random_random_unauthenticated_packet_cannot_win() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    let _ = wait_for_hard_hard_response_signal(&harness).await;
    // The exact dynamic socket is durable production state; the diagnostic
    // ring is intentionally bounded and may evict `hard_hard_sweep_started`
    // after a 128-probe burst before this test's polling task runs.
    let (_, speculative_socket) = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if let Some(socket) = harness.udp_a.socket_for_peer(Some(HARD_HARD_B)).await {
                return socket;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("birthday sweep must expose a speculative socket");
    let injector = UdpSocket::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    injector
        .send_to(b"not-a-probe-v2-packet", speculative_socket.local_addr().unwrap())
        .await
        .unwrap();
    sleep(Duration::from_millis(50)).await;
    for peers in [&harness.peers_a, &harness.peers_b] {
        let peer = &peers.diagnostics().await[0];
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_winner_selected"));
        assert_ne!(peer.state, ConnectionState::Direct);
    }
    drop(injector);
    harness.shutdown().await;

    // A fresh production session must still select an authenticated birthday
    // winner; the raw packet above is the only input in the first session.
    set_hard_hard_test_now_ms(Some(hard_hard_now_for_test()));
    let valid_harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    // Keep validation ingress live in this fresh production session. The
    // first harness above already proves that a malformed datagram cannot
    // select a winner; this session must exercise the normal authenticated
    // birthday path without pausing or dropping its legal validation evidence.
    trigger_initial_offer(&valid_harness).await;
    wait_for_both_direct_compact(&valid_harness).await;
    let valid_a_connection = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if let Some(connection) = valid_harness.peers_a.get_connection(HARD_HARD_B).await {
                if connection.state == ConnectionState::Direct
                    && connection.active_path() == Some(NetworkPath::Direct)
                    && connection.candidate_pairs.iter().any(|pair| {
                        pair.state == peer::CandidatePairState::Selected
                            && pair.source == peer::CandidatePairSource::PeerReflexive
                    })
                {
                    return connection;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("a fresh production session must promote an authenticated peer-reflexive birthday pair");
    assert_eq!(valid_a_connection.state, ConnectionState::Direct);
    let valid_b_connection = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if let Some(connection) = valid_harness.peers_b.get_connection(HARD_HARD_A).await {
                if connection.state == ConnectionState::Direct
                    && connection.active_path() == Some(NetworkPath::Direct)
                    && connection.candidate_pairs.iter().any(|pair| {
                        pair.state == peer::CandidatePairState::Selected
                            && pair.source == peer::CandidatePairSource::PeerReflexive
                    })
                {
                    return connection;
                }
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the reciprocal production session must promote an authenticated peer-reflexive birthday pair");
    assert_eq!(valid_b_connection.state, ConnectionState::Direct);
    valid_harness.shutdown().await;
}

async fn install_direct_scheduler_birthday_session(
    peers: &Arc<PeerManager>,
    peer_id: &str,
    token: &str,
    plan: peer::HardHardPlanSnapshot,
    result: &crate::udp::HardHardBirthdayResult,
) {
    let socket = result
        .sockets
        .first()
        .expect("a Birthday scheduler session needs one exact socket");
    let identity = peer::HardHardFreshSocketIdentity {
        peer_id: peer_id.to_string(),
        session_token: token.to_string(),
        network_generation: plan.local_network_generation,
        remote_candidate_epoch: plan.remote_candidate_epoch,
        local_profile_generation: plan.local_profile_generation,
        remote_profile_generation: plan.remote_profile_generation,
        punch_generation: socket.punch_generation,
        socket_index: socket.socket_index,
        socket_local_endpoint: socket.socket_local_endpoint,
    };
    let now = hard_hard_now_for_test();
    assert!(
        peers
            .hard_hard_register_session(peer::HardHardSessionRecord {
                session_id: format!("birthday-scheduler-{token}"),
                probe_session_id: None,
                session_token: token.to_string(),
                peer_id: peer_id.to_string(),
                initiator: true,
                remote_network_generation: 0,
                local_network_generation: plan.local_network_generation,
                remote_candidate_epoch: plan.remote_candidate_epoch,
                local_profile_generation: plan.local_profile_generation,
                remote_profile_generation: plan.remote_profile_generation,
                local_prediction_confidence: 90,
                remote_prediction_confidence: 0,
                requested_birthday_level: result.requested_level,
                generated_candidate_count: result.requested_level,
                signaled_candidate_count: result
                    .candidate_endpoints
                    .len()
                    .min(crate::MAX_SIGNAL_CANDIDATES),
                birthday: true,
                requested_socket_indices: result
                    .sockets
                    .iter()
                    .map(|socket| socket.socket_index)
                    .collect(),
                requested_socket_count: result.requested_socket_count,
                prediction_window: result.candidate_endpoints.clone(),
                remote_prediction: Vec::new(),
                fresh_socket: identity,
                punch_at_ms: now,
                expires_at_ms: now.saturating_add(30_000),
                state: peer::HardHardSessionState::AwaitingPeer,
                attempt_count: 0,
                created_at: Instant::now(),
                cancellation: Arc::new(crate::PunchSessionCancellation::default()),
            })
            .await
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_birthday_levels_report_requested_and_actual_socket_counts() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    for (requested_level, expected_socket_count) in [(64, 2), (128, 4)] {
        let now = hard_hard_now_for_test();
        set_hard_hard_test_now_ms(Some(now));
        let _clock = HardHardClockReset;
        let harness = build_two_peer_harness_with_stun_mode(
            true,
            false,
            false,
            HarnessStunProfile::FULL_CAPACITY,
            HarnessNatMode::HighEntropy,
        )
        .await;
        let observers = harness
            .stun_observers
            .iter()
            .take(4)
            .map(|observer| observer.endpoint)
            .collect::<Vec<_>>();
        let result = harness
            .udp_a
            .run_hard_hard_birthday_generation(
                HARD_HARD_B,
                &observers,
                Duration::from_millis(300),
                requested_level,
                &format!("level-{requested_level}"),
                None,
            )
            .await
            .expect("birthday generation must succeed below the socket cap");
        assert_eq!(result.requested_level, requested_level);
        assert_eq!(result.level, requested_level);
        assert_eq!(result.requested_socket_count, expected_socket_count);
        assert_eq!(result.sockets.len(), expected_socket_count);
        let plan = harness
            .peers_a
            .hard_hard_plan_for_peer(HARD_HARD_B)
            .await
            .expect("production scheduler test requires the live Hard plan");
        let peer_session_generation = harness
            .peers_a
            .peer_session_generation_sync(HARD_HARD_B)
            .expect("production scheduler test requires the live peer session");
        install_direct_scheduler_birthday_session(
            &harness.peers_a,
            HARD_HARD_B,
            &format!("level-{requested_level}"),
            plan,
            &result,
        )
        .await;
        let scheduler_report = harness
            .udp_a
            .punch_hard_hard_birthday_candidates_with_metadata(
                HARD_HARD_B,
                result
                    .sockets
                    .iter()
                    .map(|socket| socket.socket_index)
                    .collect(),
                result.candidate_endpoints.clone(),
                requested_level,
                requested_level,
                requested_level.min(crate::MAX_SIGNAL_CANDIDATES),
                peer_session_generation,
                (
                    plan.local_profile_generation,
                    plan.remote_profile_generation,
                ),
                &format!("level-{requested_level}"),
                None,
            )
            .await
            .expect("production Birthday scheduler must return a bounded report");
        let scheduler_birthday = scheduler_report
            .birthday
            .as_ref()
            .expect("Birthday scheduler must expose its report");
        assert_eq!(scheduler_birthday.requested_level, requested_level);
        assert_eq!(
            scheduler_birthday.generated_candidate_count,
            requested_level
        );
        assert_eq!(
            scheduler_birthday.signaled_candidate_count,
            requested_level.min(crate::MAX_SIGNAL_CANDIDATES)
        );
        assert_eq!(
            scheduler_birthday.effective_target_count,
            requested_level.min(crate::MAX_SIGNAL_CANDIDATES)
        );
        assert_eq!(
            scheduler_birthday.requested_socket_count,
            expected_socket_count
        );
        for socket in &result.sockets {
            assert!(socket.guard.finalize().await);
        }
        harness
            .udp_a
            .detach_hard_hard_sockets_for_token(
                HARD_HARD_B,
                &format!("level-{requested_level}"),
                None,
                "hard_hard_birthday_level_test_cleanup",
            )
            .await;
        harness.shutdown().await;
    }

    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun_mode(
        true,
        false,
        false,
        HarnessStunProfile::FULL_CAPACITY,
        HarnessNatMode::HighEntropy,
    )
    .await;
    let observers = harness
        .stun_observers
        .iter()
        .take(4)
        .map(|observer| observer.endpoint)
        .collect::<Vec<_>>();
    let predecessor = install_committed_birthday_predecessor(
        &harness.peers_a,
        &harness.udp_a,
        HARD_HARD_B,
    )
    .await;
    let mut filler_guards = Vec::new();
    for index in 0..7 {
        let peer_id = format!("birthday-cap-filler-{index}");
        let (socket_index, socket) = harness.udp_a.bind_fresh_punch_socket().await.unwrap();
        filler_guards.push(
            harness
                .udp_a
                .attach_dynamic_punch_socket(
                    &peer_id,
                    socket_index,
                    socket,
                    harness.peers_a.current_network_generation_sync(),
                    10_000 + index as u64,
                    None,
                )
                .await
                .unwrap(),
        );
    }
    assert_eq!(harness.udp_a.dynamic_socket_count().await, 8);
    let token = "level-256-cap";
    let result = harness
        .udp_a
        .run_hard_hard_birthday_generation(
            HARD_HARD_B,
            &observers,
            Duration::from_millis(300),
            256,
            token,
            None,
        )
        .await
        .expect("capacity downgrade must keep a safe bounded birthday lane");
    assert_eq!(result.requested_level, 256);
    assert_eq!(result.requested_socket_count, 8);
    assert_eq!(result.level, 128);
    assert_eq!(result.sockets.len(), 4);
    let plan = harness
        .peers_a
        .hard_hard_plan_for_peer(HARD_HARD_B)
        .await
        .expect("production scheduler cap test requires the live Hard plan");
    let peer_session_generation = harness
        .peers_a
        .peer_session_generation_sync(HARD_HARD_B)
        .expect("production scheduler cap test requires the live peer session");
    install_direct_scheduler_birthday_session(
        &harness.peers_a,
        HARD_HARD_B,
        token,
        plan,
        &result,
    )
    .await;
    let scheduler_targets = (0..256usize)
        .map(|index| {
            SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                41_000 + u16::try_from(index).expect("test target port fits in u16"),
            )
        })
        .collect::<Vec<_>>();
    let scheduler_report = harness
        .udp_a
        .punch_hard_hard_birthday_candidates_with_metadata(
            HARD_HARD_B,
            result
                .sockets
                .iter()
                .map(|socket| socket.socket_index)
                .collect(),
            scheduler_targets,
            256,
            256,
            crate::MAX_SIGNAL_CANDIDATES,
            peer_session_generation,
            (
                plan.local_profile_generation,
                plan.remote_profile_generation,
            ),
            token,
            None,
        )
        .await
        .expect("production Birthday scheduler must retain the raw 256 request");
    let scheduler_birthday = scheduler_report
        .birthday
        .as_ref()
        .expect("Birthday scheduler cap test must expose its report");
    assert_eq!(scheduler_birthday.requested_level, 256);
    assert_eq!(scheduler_birthday.generated_candidate_count, 256);
    assert_eq!(
        scheduler_birthday.signaled_candidate_count,
        crate::MAX_SIGNAL_CANDIDATES
    );
    assert_eq!(
        scheduler_birthday.effective_target_count,
        crate::MAX_SIGNAL_CANDIDATES
    );
    assert_eq!(scheduler_birthday.requested_socket_count, 8);
    assert_eq!(scheduler_birthday.attached_socket_count, 4);
    assert_eq!(scheduler_birthday.usable_socket_count, 4);
    assert_eq!(scheduler_birthday.unavailable_socket_count, 4);
    assert_eq!(scheduler_birthday.waves_planned, 2);
    let diagnostics = harness.peers_a.diagnostics().await;
    assert!(diagnostics[0].direct_events.iter().any(|event| {
        event.stage == "hard_hard_birthday_degraded"
            && event.detail.contains("requested_level=256")
            && event.detail.contains("actual_level=128")
            && event.detail.contains("requested_socket_count=8")
            && event.detail.contains("actual_socket_count=4")
            && event.detail.contains("reason=socket_cap")
    }));
    assert!(harness.udp_a.dynamic_socket_count().await <= 8);
    for socket in &result.sockets {
        assert!(socket.guard.finalize().await);
    }
    harness
        .udp_a
        .detach_hard_hard_sockets_for_token(HARD_HARD_B, token, None, "hard_hard_birthday_cap_test_cleanup")
        .await;
    drop(filler_guards);
    drop(predecessor);
    timeout(Duration::from_secs(1), async {
        while harness.udp_a.dynamic_socket_count().await != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("capacity validation must clean predecessor and filler readers");
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_responder_measurement_candidate_epoch_change_fences_response() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    let gate = install_hard_hard_responder_measurement_gate_for_test();

    trigger_initial_offer(&harness).await;
    timeout(Duration::from_secs(3), gate.reached.notified())
        .await
        .expect("B responder measurement must pause before its post-measurement plan fence");

    let old_plan = harness
        .peers_b
        .hard_hard_plan_for_peer(HARD_HARD_A)
        .await
        .expect("B must retain the admitted Hard↔Hard plan while measurement is paused");
    let initiator_offer = harness
        .signals_b
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .find(|signal| {
            signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.starts_with("hh1:i:"))
        })
        .cloned()
        .expect("A must have published the initiator prediction before B measures it");
    let replacement = hard_hard_replacement_candidate(
        initiator_offer
            .candidates
            .first()
            .expect("the initiator prediction must contain a candidate"),
    );
    let replacement_sources = HashMap::from([(replacement.clone(), "predicted".to_string())]);
    assert!(matches!(
        harness
            .peers_b
            .add_candidates_with_metadata(
                HARD_HARD_A,
                &[replacement],
                &replacement_sources,
                initiator_offer.candidate_generation.saturating_add(1),
                initiator_offer.candidates_expires_at_ms,
            )
            .await,
        CandidateSetApplyResult::Applied
    ));
    assert!(
        harness
            .peers_b
            .bind_remote_nat_profile_to_candidate_epoch(
                HARD_HARD_A,
                old_plan.remote_profile_generation,
            )
            .await,
        "the changed candidate epoch must still have a current remote profile so the planner remains selected"
    );
    let changed_plan = harness
        .peers_b
        .hard_hard_plan_for_peer(HARD_HARD_A)
        .await
        .expect("the regression must change only the candidate epoch, not remove the planner");
    assert_eq!(
        changed_plan.remote_candidate_epoch,
        old_plan.remote_candidate_epoch.saturating_add(1)
    );
    assert_eq!(
        changed_plan.local_network_generation,
        old_plan.local_network_generation
    );
    assert_eq!(
        changed_plan.local_profile_generation,
        old_plan.local_profile_generation
    );
    assert_eq!(
        changed_plan.remote_profile_generation,
        old_plan.remote_profile_generation
    );

    gate.release.notify_one();
    timeout(Duration::from_secs(3), gate.completed.notified())
        .await
        .expect("the responder worker must finish after rechecking the advanced candidate epoch");
    assert!(
        !harness
            .signals_a
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .any(|signal| {
                signal
                    .session_id
                    .as_deref()
                    .is_some_and(|session| session.starts_with("hh1:r:"))
            }),
        "a responder measured against the old remote candidate epoch must not publish a reciprocal response"
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_first_send_protection_refunds_then_retries_response() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(true, false, false).await;

    let epoch = match harness.peers_b.recovery_epoch_admit(HARD_HARD_A).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("B must admit the protected ordinary fixture: {admission:?}"),
    };
    let ordinary_punch_at =
        unix_time_millis().saturating_add(RELAY_ASSISTED_PUNCH_LEAD.as_millis() as u64);
    let ordinary = match harness
        .punch_attempts_b
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_A,
            harness.peers_b.current_network_generation_sync(),
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(ordinary_punch_at),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => panic!("ordinary fixture must own B's punch window"),
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };
    let ordinary_cancellation = ordinary.cancellation_handle();
    let ordinary_owner = Arc::new(StdMutex::new(Some(ordinary)));
    *harness.signal_hook_a_to_b.lock().unwrap() = Some(Arc::new({
        let ordinary_owner = ordinary_owner.clone();
        move |signal: &TestControlSignal| {
            if signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.starts_with("hh1:i:"))
            {
                ordinary_owner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .expect("ordinary owner must remain live through the protected claim")
                    .mark_first_send_started();
            }
        }
    }));

    trigger_initial_offer(&harness).await;
    let deferred = wait_for_stage(
        &harness.peers_b,
        HARD_HARD_A,
        "hard_hard_responder_claim_deferred",
    )
    .await;
    assert!(
        deferred
            .detail
            .contains("reason=active_first_send_protected"),
        "the responder must encounter the real first-send protection branch: {}",
        deferred.detail
    );
    assert_eq!(
        harness
            .peers_b
            .recovery_epoch_work_budget_report(HARD_HARD_A)
            .await
            .expect("the same recovery epoch must remain active while retrying")
            .fresh_generations_remaining,
        1,
        "a Deferred claim must refund B's sole fresh-generation reservation before waiting"
    );

    wait_for_hard_hard_response_signal(&harness).await;
    assert!(
        ordinary_cancellation.is_cancelled(),
        "after the bounded protection expires, the fresh response must preempt the ordinary owner"
    );
    wait_for_both_direct(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_initiator_response_retries_first_send_protection_once() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    // Use the real clock here: both workers must continue targeting the same
    // absolute punch_at while the initiator waits out the 250ms protection.
    set_hard_hard_test_now_ms(None);
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    let responder_gate = install_hard_hard_responder_measurement_gate_for_test();

    trigger_initial_offer(&harness).await;
    // The gate follows two sequential production-bounded measurements (the
    // initiator, then the responder). Their 1.2s budgets plus debug-runtime
    // scheduling leave too little headroom in a 3s fixture-only wait.
    timeout(Duration::from_secs(5), responder_gate.reached.notified())
        .await
        .expect("B must pause after measurement before publishing its response");
    wait_for_stage(
        &harness.peers_a,
        HARD_HARD_B,
        "hard_hard_prediction_signaled",
    )
    .await;

    let epoch = match harness.peers_a.recovery_epoch_admit(HARD_HARD_B).await {
        RecoveryAdmission::Accepted { epoch } => epoch,
        admission => panic!("A must retain its initiator recovery epoch: {admission:?}"),
    };
    let ordinary_punch_at =
        unix_time_millis().saturating_add(RELAY_ASSISTED_PUNCH_LEAD.as_millis() as u64);
    let ordinary = match harness
        .punch_attempts_a
        .claim_for_epoch_with_rendezvous(
            HARD_HARD_B,
            harness.peers_a.current_network_generation_sync(),
            epoch,
            PUNCH_PRIORITY_SYNCHRONIZED,
            None,
            Some(ordinary_punch_at),
        )
        .await
    {
        RendezvousPunchClaim::Claimed(session) => session,
        RendezvousPunchClaim::Deferred(_) => {
            panic!("ordinary fixture must own A's punch window while awaiting the response")
        }
        RendezvousPunchClaim::RejectedStalePeerSession => {
            panic!("fixture lifecycle must not be retired")
        }
    };
    let ordinary_cancellation = ordinary.cancellation_handle();
    let ordinary_owner = Arc::new(StdMutex::new(Some(ordinary)));
    *harness.signal_hook_b_to_a.lock().unwrap() = Some(Arc::new({
        let ordinary_owner = ordinary_owner.clone();
        move |signal: &TestControlSignal| {
            if signal
                .session_id
                .as_deref()
                .is_some_and(|session| session.starts_with("hh1:r:"))
            {
                ordinary_owner
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .as_ref()
                    .expect("ordinary owner must remain live until A receives the response")
                    .mark_first_send_started();
            }
        }
    }));

    responder_gate.release.notify_one();
    let deferred = wait_for_stage(
        &harness.peers_a,
        HARD_HARD_B,
        "hard_hard_initiator_response_claim_deferred",
    )
    .await;
    assert!(
        deferred
            .detail
            .contains("reason=active_first_send_protected"),
        "the initiator response must hit the real first-send protection branch: {}",
        deferred.detail
    );
    assert!(
        deferred.detail.contains("waiting once"),
        "the protected collision must enter the one bounded retry branch: {}",
        deferred.detail
    );
    assert!(
        !ordinary_cancellation.is_cancelled(),
        "the initial fresh claim must preserve the already-dispatched ordinary send"
    );
    timeout(Duration::from_secs(2), async {
        while !ordinary_cancellation.is_cancelled() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the one bounded retry must preempt the ordinary owner after protection expires");

    wait_for_both_direct(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_prediction_miss_keeps_relay_and_cleans_up() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(true, false, true).await;
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    wait_for_hard_hard_response_signal(&harness).await;

    let actual_a = harness.link._a_source.local_addr().unwrap().port();
    let actual_b = harness.link._b_source.local_addr().unwrap().port();
    let fresh_a = harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .expect("A must have completed its measured mapping before the miss");
    let fresh_b = harness
        .peers_b
        .fresh_mapping_for_peer(HARD_HARD_A)
        .await
        .expect("B must have completed its measured mapping before the miss");
    assert!(!fresh_a.predicted_ports.contains(&actual_a));
    assert!(!fresh_b.predicted_ports.contains(&actual_b));
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);
    assert_relay_remains_available(&harness).await;
    // The per-peer direct-event ring is intentionally best-effort under
    // connection-map contention.  Session/socket/probe teardown is the
    // authoritative completion fence for a missed rendezvous.
    wait_for_failed_attempt_cleanup(&harness).await;

    for peers in [&harness.peers_a, &harness.peers_b] {
        let diagnostics = peers.diagnostics().await;
        let peer = &diagnostics[0];
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "hard_hard_sweep_completed"));
        assert!(!peer
            .direct_events
            .iter()
            .any(|event| event.stage == "direct_validation_promoted"));
    }
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_partial_reachability_never_stays_asymmetric_direct() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(true, false, false).await;
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    wait_for_both_sweep_failures(&harness).await;
    harness.link.set_drop_a_to_b(true);

    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);
    assert_relay_remains_available(&harness).await;
    wait_for_failed_attempt_cleanup(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_local_handover_cancels_waiting_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    assert!(harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .is_some());

    let new_generation = harness
        .peers_a
        .advance_network_generation("phase_2_2_test_local_handover")
        .await;
    assert_eq!(new_generation, 1);
    assert!(
        !harness
            .peers_a
            .hard_hard_session_is_active(HARD_HARD_B)
            .await
    );
    assert!(harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .is_none());
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms"),
    ));
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    assert_eq!(harness.udp_a.dynamic_socket_count().await, 0);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_stale_ack_cannot_resurrect_retired_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    // Advance the shared fixture clock inside the response forwarder, before
    // either endpoint can observe the response.  Advancing it after merely
    // observing the outgoing signal lets the responder capture the old
    // 3.5-second delay while the initiator captures zero, separating the two
    // authenticated-probe windows.
    let harness = build_two_peer_harness(true, false, false).await;
    harness.link.set_hold_ack(true);
    harness.validation_enabled_a.store(false, Ordering::Release);
    harness.validation_enabled_b.store(false, Ordering::Release);

    trigger_initial_offer(&harness).await;
    let response_s1 = wait_for_hard_hard_response_signal(&harness).await;
    assert!(
        response_s1.punch_at_ms.is_some(),
        "S1 response must carry a canonical punch deadline"
    );
    // On a slow CI runner the fake clock can advance through the bounded S1
    // sweep before this polling task observes the transient socket/pending
    // state.  An authenticated ACK held by the link is the durable evidence
    // that S1 emitted a probe; the later S2 assertions verify that replaying
    // those ACKs cannot consume S2's live transactions.
    let s1_probe_wait = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            if harness.link.held_ack_count() > 0 {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if s1_probe_wait.is_err() {
        let stages_a = summarize_hard_hard_diagnostics(&harness.peers_a, HARD_HARD_B).await;
        let stages_b = summarize_hard_hard_diagnostics(&harness.peers_b, HARD_HARD_A).await;
        panic!(
            "S1 must emit authenticated probes whose ACKs can be held: held={} A sockets={} B sockets={} A pending={} B pending={} A events={stages_a:#?} B events={stages_b:#?}",
            harness.link.held_ack_count(),
            harness.udp_a.dynamic_socket_count().await,
            harness.udp_b.dynamic_socket_count().await,
            harness
                .udp_a
                .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                .await,
            harness
                .udp_b
                .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                .await,
        );
    }
    let stale_s1_acks = harness.link.take_held_acks();
    assert!(!stale_s1_acks.a_to_b.is_empty() || !stale_s1_acks.b_to_a.is_empty());

    harness
        .peers_a
        .advance_network_generation("phase_2_2_test_stale_ack_s1_cancel_a")
        .await;
    harness
        .peers_b
        .advance_network_generation("phase_2_2_test_stale_ack_s1_cancel_b")
        .await;
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);

    // Keep ACK holding enabled while S2 is pending. This leaves S2's own
    // pending Probe-v2 transactions alive so replaying only S1's packets is a
    // meaningful stale-ACK assertion rather than a post-success no-op.  Hold
    // only authenticated Punch packets at the harness boundary so one side
    // cannot select a winner before the other side has admitted its own S2
    // pending probes; ACK packets remain held and are still replayed below.
    harness.link.set_hold_authenticated_punch(true);
    sleep(Duration::from_millis(2_100)).await;
    trigger_retry_offer_with_current_candidates(&harness, &response_s1).await;
    let response_s2 = wait_for_hard_hard_response_signal_number(&harness, 2).await;
    timeout(Duration::from_secs(5), async {
        loop {
            if harness.udp_a.dynamic_socket_count().await == 1
                && harness.udp_b.dynamic_socket_count().await == 1
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("S2 must install fresh sockets after S1 cancellation");
    assert!(
        response_s2.punch_at_ms.is_some(),
        "S2 response must carry a canonical punch deadline"
    );
    let s2_probe_wait = timeout(Duration::from_secs(5), async {
        loop {
            if harness.link.held_authenticated_punch_count() > 0
                && harness
                    .udp_a
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                    .await
                    > 0
                && harness
                    .udp_b
                    .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                    .await
                    > 0
            {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    if s2_probe_wait.is_err() {
        let stages_a = summarize_hard_hard_diagnostics(&harness.peers_a, HARD_HARD_B).await;
        let stages_b = summarize_hard_hard_diagnostics(&harness.peers_b, HARD_HARD_A).await;
        let session_a = harness
            .peers_a
            .hard_hard_session_for_test(HARD_HARD_B)
            .await;
        let session_b = harness
            .peers_b
            .hard_hard_session_for_test(HARD_HARD_A)
            .await;
        panic!(
            "S2 must have live pending probes before stale ACK replay: now={} held={} A sockets={} B sockets={} A pending={} B pending={} A session={session_a:#?} B session={session_b:#?} A events={stages_a:#?} B events={stages_b:#?}",
            hard_hard_now_for_test(),
            harness.link.held_ack_count(),
            harness.udp_a.dynamic_socket_count().await,
            harness.udp_b.dynamic_socket_count().await,
            harness
                .udp_a
                .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
                .await,
            harness
                .udp_b
                .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
                .await,
        );
    }
    let s2_token_a = harness
        .peers_a
        .hard_hard_session_for_test(HARD_HARD_B)
        .await
        .expect("S2 must be authoritative on A")
        .session_token;
    let s2_token_b = harness
        .peers_b
        .hard_hard_session_for_test(HARD_HARD_A)
        .await
        .expect("S2 must be authoritative on B")
        .session_token;

    harness
        .link
        .replay_acks(stale_s1_acks, &harness.udp_a, &harness.udp_b)
        .await;
    sleep(Duration::from_millis(100)).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert!(!harness.peers_b.is_direct(HARD_HARD_A).await);
    assert!(
        harness
            .udp_a
            .hard_hard_pending_probe_count_for_test(HARD_HARD_B)
            .await
            > 0,
        "S1 ACKs must not consume S2's A-side pending probes"
    );
    assert!(
        harness
            .udp_b
            .hard_hard_pending_probe_count_for_test(HARD_HARD_A)
            .await
            > 0,
        "S1 ACKs must not consume S2's B-side pending probes"
    );
    assert_eq!(
        harness
            .peers_a
            .hard_hard_session_for_test(HARD_HARD_B)
            .await
            .expect("S2 must remain live after stale ACK replay")
            .session_token,
        s2_token_a
    );
    assert_eq!(
        harness
            .peers_b
            .hard_hard_session_for_test(HARD_HARD_A)
            .await
            .expect("S2 must remain live after stale ACK replay")
            .session_token,
        s2_token_b
    );

    harness.validation_enabled_a.store(true, Ordering::Release);
    harness.validation_enabled_b.store(true, Ordering::Release);
    harness
        .link
        .release_held_authenticated_punches(&harness.udp_a, &harness.udp_b)
        .await;
    timeout(Duration::from_secs(5), async {
        loop {
            if harness.link.held_ack_count() > 0 {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("S2 Punch release must produce held ACKs");
    harness.link.set_hold_authenticated_punch(false);
    harness.link.set_hold_ack(false);
    let s2_acks = harness.link.take_held_acks();
    harness
        .link
        .replay_acks(s2_acks, &harness.udp_a, &harness.udp_b)
        .await;
    wait_for_both_direct(&harness).await;
    harness.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_manager_peer_isolation_keeps_unrelated_session_authoritative() {
    let root_identity = NodeIdentity::generate();
    let manager = Arc::new(PeerManager::new(harness_config(
        &root_identity,
        "peer-root",
        "10.20.0.10",
        std::env::temp_dir().join(format!("p2wlan-phase-2-2-isolation-{}", std::process::id())),
        HarnessStunProfile::FULL_CAPACITY,
    )));
    let identity_b = NodeIdentity::generate();
    let identity_c = NodeIdentity::generate();
    manager
        .add_peer(&peer_info(
            "peer-b",
            "10.20.0.11",
            hex::encode(identity_b.public_key()),
            "127.0.0.1:31001".parse().unwrap(),
            "phase-2-2-test".to_string(),
        ))
        .await;
    manager
        .add_peer(&peer_info(
            "peer-c",
            "10.20.0.12",
            hex::encode(identity_c.public_key()),
            "127.0.0.1:31002".parse().unwrap(),
            "phase-2-2-test".to_string(),
        ))
        .await;

    let make_record = |peer_id: &str, token: &str, socket_index: usize| {
        let socket_local_endpoint = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            31_100 + socket_index as u16,
        );
        let identity = peer::HardHardFreshSocketIdentity {
            peer_id: peer_id.to_string(),
            session_token: token.to_string(),
            network_generation: 0,
            remote_candidate_epoch: 1,
            local_profile_generation: 1,
            remote_profile_generation: 1,
            punch_generation: 1,
            socket_index,
            socket_local_endpoint,
        };
        peer::HardHardSessionRecord {
            session_id: format!("hh1:i:{token}"),
            probe_session_id: None,
            session_token: token.to_string(),
            peer_id: peer_id.to_string(),
            initiator: true,
            remote_network_generation: 0,
            local_network_generation: 0,
            remote_candidate_epoch: 1,
            local_profile_generation: 1,
            remote_profile_generation: 1,
            local_prediction_confidence: 90,
            remote_prediction_confidence: 0,
            requested_birthday_level: 0,
            generated_candidate_count: 1,
            signaled_candidate_count: 1,
            birthday: false,
            requested_socket_indices: vec![socket_index],
            requested_socket_count: 1,
            prediction_window: vec![socket_local_endpoint],
            remote_prediction: Vec::new(),
            fresh_socket: identity,
            punch_at_ms: hard_hard_now_for_test().saturating_add(5_000),
            expires_at_ms: hard_hard_now_for_test().saturating_add(30_000),
            state: peer::HardHardSessionState::AwaitingPeer,
            attempt_count: 0,
            created_at: Instant::now(),
            cancellation: Arc::new(crate::PunchSessionCancellation::default()),
        }
    };
    assert!(
        manager
            .hard_hard_register_session(make_record("peer-b", "token-b", 1000))
            .await
    );
    assert!(
        manager
            .hard_hard_register_session(make_record("peer-c", "token-c", 1001))
            .await
    );
    let c_before = manager
        .hard_hard_session_for_test("peer-c")
        .await
        .expect("peer C session must be present before peer B cleanup");

    manager.clear_hard_hard_sessions(Some("peer-b")).await;
    assert!(!manager.hard_hard_session_is_active("peer-b").await);
    let c_after = manager
        .hard_hard_session_for_test("peer-c")
        .await
        .expect("cleaning peer B must not remove peer C's session");
    assert_eq!(c_after.session_token, c_before.session_token);
    assert_eq!(
        c_after.fresh_socket.socket_index,
        c_before.fresh_socket.socket_index
    );
    assert!(manager.hard_hard_session_is_active("peer-c").await);
    manager.clear_hard_hard_sessions(None).await;
}

#[tokio::test(flavor = "current_thread")]
async fn hard_hard_manager_sticky_winner_rejects_delayed_authenticated_socket() {
    let identity = NodeIdentity::generate();
    let manager = PeerManager::new(harness_config(
        &identity,
        "peer-sticky-root",
        "10.20.0.30",
        std::env::temp_dir().join(format!(
            "p2wlan-phase-2-2-sticky-{}",
            std::process::id()
        )),
        HarnessStunProfile::FULL_CAPACITY,
    ));
    let peer_identity = NodeIdentity::generate();
    manager
        .add_peer(&peer_info(
            "peer-sticky",
            "10.20.0.31",
            hex::encode(peer_identity.public_key()),
            "127.0.0.1:31031".parse().unwrap(),
            "phase-2-2-test".to_string(),
        ))
        .await;
    let endpoint_a: SocketAddr = "127.0.0.1:31100".parse().unwrap();
    let endpoint_b: SocketAddr = "127.0.0.1:31101".parse().unwrap();
    let record = peer::HardHardSessionRecord {
        session_id: "hh1:i:sticky-token".to_string(),
        probe_session_id: None,
        session_token: "sticky-token".to_string(),
        peer_id: "peer-sticky".to_string(),
        initiator: true,
        remote_network_generation: 0,
        local_network_generation: 0,
        remote_candidate_epoch: 1,
        local_profile_generation: 1,
        remote_profile_generation: 1,
        local_prediction_confidence: 90,
        remote_prediction_confidence: 0,
        requested_birthday_level: 0,
        generated_candidate_count: 1,
        signaled_candidate_count: 1,
        birthday: false,
        requested_socket_indices: vec![4100],
        requested_socket_count: 1,
        prediction_window: vec![endpoint_a],
        remote_prediction: Vec::new(),
        fresh_socket: peer::HardHardFreshSocketIdentity {
            peer_id: "peer-sticky".to_string(),
            session_token: "sticky-token".to_string(),
            network_generation: 0,
            remote_candidate_epoch: 1,
            local_profile_generation: 1,
            remote_profile_generation: 1,
            punch_generation: 1,
            socket_index: 4100,
            socket_local_endpoint: endpoint_a,
        },
        punch_at_ms: hard_hard_now_for_test().saturating_add(5_000),
        expires_at_ms: hard_hard_now_for_test().saturating_add(30_000),
        state: peer::HardHardSessionState::AwaitingPeer,
        attempt_count: 0,
        created_at: Instant::now(),
        cancellation: Arc::new(crate::PunchSessionCancellation::default()),
    };
    assert!(manager.hard_hard_register_session(record).await);
    assert!(manager
        .hard_hard_begin_sweep(
            "peer-sticky",
            "sticky-token",
            vec![endpoint_a],
            90,
            0,
        )
        .await
        .is_some());

    let first = manager
        .hard_hard_select_winner("peer-sticky", "sticky-token", 4100, 0, 1, endpoint_a)
        .await
        .expect("the first authenticated socket must become the winner");
    assert_eq!(first.socket_index, 4100);
    assert!(manager
        .hard_hard_select_winner("peer-sticky", "sticky-token", 4101, 0, 2, endpoint_b)
        .await
        .is_none());
    assert_eq!(
        manager
            .hard_hard_winner_for_token("peer-sticky", "sticky-token")
            .await,
        Some(4100)
    );
    assert_eq!(
        manager
            .hard_hard_session_by_token("peer-sticky", "sticky-token")
            .await
            .expect("sticky session must remain authoritative")
            .fresh_socket
            .socket_index,
        4100
    );
    manager.clear_hard_hard_sessions(None).await;
}

async fn hard_hard_remote_candidate_epoch_fence_with_stun(stun: HarnessStunProfile) {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness_with_stun(false, false, false, stun).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    let old_epoch = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .expect("A must have a remote candidate epoch");
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    let candidate = response
        .candidates
        .first()
        .cloned()
        .expect("response must carry a candidate");
    // A newer freshness revision alone no longer advances the remote
    // transport epoch. Use a genuinely different endpoint so this remains a
    // transport-handover fencing test rather than a version-counter test.
    let replacement_candidate = hard_hard_replacement_candidate(&candidate);
    assert!(!response.candidates.contains(&replacement_candidate));
    let candidate_sources =
        HashMap::from([(replacement_candidate.clone(), "predicted".to_string())]);
    let old_epoch_b = harness
        .peers_b
        .current_remote_candidate_epoch(HARD_HARD_A)
        .await
        .expect("B must have a remote candidate epoch");
    let local_candidate_for_b = harness
        .link
        .a_public
        .local_addr()
        .expect("A public test socket must have an endpoint")
        .to_string();
    let replacement_candidate_for_b = hard_hard_replacement_candidate(&local_candidate_for_b);
    let candidate_sources_for_b =
        HashMap::from([(replacement_candidate_for_b.clone(), "predicted".to_string())]);
    let candidates_a = [replacement_candidate];
    let candidates_b = [replacement_candidate_for_b];
    let (apply_result_a, apply_result_b) = tokio::join!(
        harness.peers_a.add_candidates_with_metadata(
            HARD_HARD_B,
            &candidates_a,
            &candidate_sources,
            response.candidate_generation.saturating_add(1),
            response.candidates_expires_at_ms,
        ),
        harness.peers_b.add_candidates_with_metadata(
            HARD_HARD_A,
            &candidates_b,
            &candidate_sources_for_b,
            response.candidate_generation.saturating_add(1),
            None,
        ),
    );
    assert!(matches!(apply_result_a, CandidateSetApplyResult::Applied));
    assert!(matches!(apply_result_b, CandidateSetApplyResult::Applied));
    timeout(Duration::from_secs(3), async {
        loop {
            let epoch_a = harness
                .peers_a
                .current_remote_candidate_epoch(HARD_HARD_B)
                .await;
            let epoch_b = harness
                .peers_b
                .current_remote_candidate_epoch(HARD_HARD_A)
                .await;
            if epoch_a == Some(old_epoch.saturating_add(1))
                && epoch_b == Some(old_epoch_b.saturating_add(1))
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the accepted newer candidate signal must advance exactly one epoch");
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms")
            .saturating_add(30_000),
    ));
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    let diagnostics_a = harness.peers_a.diagnostics().await;
    assert!(diagnostics_a[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "remote_candidates_invalidated"));
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_remote_candidate_epoch_fences_old_session() {
    hard_hard_remote_candidate_epoch_fence_with_stun(HarnessStunProfile::FULL_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_remote_candidate_epoch_fence_with_minimum_stun_capacity() {
    hard_hard_remote_candidate_epoch_fence_with_stun(HarnessStunProfile::MINIMUM_CAPACITY).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_profile_generation_fences_old_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    harness
        .peers_a
        .update_nat_profile(hard_hard_profile("127.0.0.1:49991".parse().unwrap(), 5))
        .await;
    assert_eq!(harness.peers_a.current_local_profile_generation_sync(), 2);
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms"),
    ));
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    assert_eq!(harness.udp_a.dynamic_socket_count().await, 0);
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_duplicate_and_stale_signals_do_not_reopen_session() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, false, false).await;
    // The predictable harness reserves every signaled candidate port, so a
    // Windows ephemeral dynamic socket cannot bypass these NAT drop flags by
    // binding one of the synthetic public targets directly.
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    let original_a = harness.udp_a.dynamic_socket_count().await;
    let original_b = harness.udp_b.dynamic_socket_count().await;

    assert_eq!(harness.udp_a.dynamic_socket_count().await, original_a);
    assert_eq!(harness.udp_b.dynamic_socket_count().await, original_b);

    // A duplicate full offer can wait behind the active responder transaction.
    // Move the shared test clock to its punch boundary, then wait for both
    // durable deliveries to reach a terminal state before installing the next
    // candidate generation. This prevents an old queued offer from racing the
    // direct test mutation below while preserving the real responder ordering.
    set_hard_hard_test_now_ms(Some(
        response
            .punch_at_ms
            .expect("response must carry punch_at_ms"),
    ));
    let duplicate_one = inject_candidate_offer(
        &harness,
        &response,
        response.candidate_generation,
        response.session_id.clone(),
    )
    .await;
    assert_eq!(
        wait_for_injected_offer_disposition(duplicate_one).await,
        crate::control::SignalApplyOutcome::Applied,
        "the first duplicate must drain through the existing responder lane"
    );
    let epoch_after_first_duplicate = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .unwrap();
    let duplicate_two = inject_candidate_offer(
        &harness,
        &response,
        response.candidate_generation,
        response.session_id.clone(),
    )
    .await;
    assert_eq!(
        wait_for_injected_offer_disposition(duplicate_two).await,
        crate::control::SignalApplyOutcome::Applied,
        "the second duplicate must drain through the existing responder lane"
    );
    assert_eq!(
        harness
            .peers_a
            .current_remote_candidate_epoch(HARD_HARD_B)
            .await,
        Some(epoch_after_first_duplicate),
        "an exact duplicate must not advance the remote candidate epoch"
    );
    wait_for_failed_attempt_cleanup(&harness).await;

    let epoch_before_new = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .unwrap();

    let candidate = response
        .candidates
        .first()
        .cloned()
        .expect("response must carry a candidate");
    // Model a real replacement transport before replaying the stale response;
    // an identical set with a higher revision is only a freshness refresh.
    let replacement_candidate = hard_hard_replacement_candidate(&candidate);
    assert!(!response.candidates.contains(&replacement_candidate));
    let sources = HashMap::from([(replacement_candidate.clone(), "predicted".to_string())]);
    assert!(matches!(
        harness
            .peers_a
            .add_candidates_with_metadata(
                HARD_HARD_B,
                &[replacement_candidate],
                &sources,
                response.candidate_generation.saturating_add(1),
                response.candidates_expires_at_ms,
            )
            .await,
        CandidateSetApplyResult::Applied
    ));
    let epoch_after_new = harness
        .peers_a
        .current_remote_candidate_epoch(HARD_HARD_B)
        .await
        .unwrap();
    assert_eq!(epoch_after_new, epoch_before_new.saturating_add(1));
    // Deliver the old response after the newer candidate epoch. The real
    // control ingress must reject it as stale instead of reviving S1.
    let stale_offer = inject_candidate_offer(
        &harness,
        &response,
        response.candidate_generation,
        response.session_id.clone(),
    )
    .await;
    let stale_outcome = wait_for_injected_offer_disposition(stale_offer).await;
    assert!(
        matches!(
            stale_outcome,
            crate::control::SignalApplyOutcome::Applied
                | crate::control::SignalApplyOutcome::TerminalRejected
        ),
        "the stale offer must finish terminally, got {stale_outcome:?}"
    );
    wait_for_failed_attempt_cleanup(&harness).await;
    assert!(!harness.peers_a.is_direct(HARD_HARD_B).await);
    assert_relay_remains_available(&harness).await;
    assert_eq!(
        harness
            .peers_a
            .current_remote_candidate_epoch(HARD_HARD_B)
            .await,
        Some(epoch_after_new),
        "the old response must not advance or replace the newer candidate epoch"
    );
    harness.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hard_hard_two_peer_competing_primary_direct_supersedes_hard_hard() {
    let _serial = HARD_HARD_E2E_SERIAL.acquire().await.unwrap();
    let now = hard_hard_now_for_test();
    set_hard_hard_test_now_ms(Some(now));
    let _clock = HardHardClockReset;
    let harness = build_two_peer_harness(false, true, false).await;
    trigger_initial_offer(&harness).await;
    let response = wait_for_hard_hard_response_signal(&harness).await;
    let punch_at_ms = response
        .punch_at_ms
        .expect("Hard↔Hard response carries a canonical punch deadline");
    let hard_socket_index = harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .expect("A must have its Hard↔Hard measurement before the race")
        .socket_index;

    let primary_local = harness.udp_a.local_addr().unwrap();
    let b_public = harness.link.b_public.local_addr().unwrap();
    harness
        .udp_a
        .punch_candidates_primary_socket(HARD_HARD_B, vec![b_public], Duration::ZERO, 1)
        .await
        .expect("ordinary primary punch must send through the real UDP path");
    timeout(Duration::from_secs(5), async {
        loop {
            if harness.peers_a.is_direct(HARD_HARD_B).await
                && harness
                    .udp_a
                    .affinity_pin_for_test(HARD_HARD_B)
                    .await
                    .is_some_and(|pin| pin.socket_index == 0)
            {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("ordinary primary direct path must win before the Hard↔Hard deadline");

    set_hard_hard_test_now_ms(Some(punch_at_ms));
    // Direct promotion revokes the Hard↔Hard owner immediately. Under a
    // loaded test runtime the cancelled worker can therefore finish without
    // publishing its best-effort diagnostic event (or the ring can evict that
    // event before a long generic wait observes it). The socket/session state
    // below is the authoritative supersession proof; inspect the event when
    // it is available, but do not make cleanup correctness depend on it.
    let superseded_a = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(event) = harness
                .peers_a
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == HARD_HARD_B)
                .and_then(|peer| {
                    peer.direct_events
                        .into_iter()
                        .find(|event| event.stage == "hard_hard_superseded_by_other_direct")
                })
            {
                return event;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if let Ok(superseded_a) = superseded_a {
        assert!(
            superseded_a
                .detail
                .contains(&format!("socket index={hard_socket_index}")),
            "superseded event must identify the detached Hard↔Hard socket: {}",
            superseded_a.detail
        );
    }
    assert_eq!(
        harness.udp_a.dynamic_socket_count().await,
        0,
        "the superseded Hard↔Hard socket must detach while primary remains"
    );
    assert!(
        !harness
            .peers_a
            .hard_hard_session_is_active(HARD_HARD_B)
            .await,
        "the superseded Hard↔Hard session must be retired"
    );
    assert_eq!(
        harness
            .peers_a
            .select_path_for_data(HARD_HARD_B, true, true)
            .await
            .path,
        Some(NetworkPath::Direct)
    );
    assert_eq!(
        harness
            .udp_a
            .affinity_pin_for_test(HARD_HARD_B)
            .await
            .map(|pin| pin.socket_index),
        Some(0)
    );
    assert_eq!(
        harness
            .udp_a
            .socket_for_peer(Some(HARD_HARD_B))
            .await
            .map(|(index, _)| index),
        Some(0)
    );
    let primary_local_text = primary_local.to_string();
    assert_eq!(
        harness.peers_a.diagnostics().await[0]
            .current_direct_pair
            .as_ref()
            .and_then(|pair| pair.local_endpoint.as_deref()),
        Some(primary_local_text.as_str())
    );
    let diagnostics_a = harness.peers_a.diagnostics().await;
    assert!(!diagnostics_a[0]
        .direct_events
        .iter()
        .any(|event| event.stage == "hard_hard_sweep_completed"));
    harness.shutdown().await;
}
