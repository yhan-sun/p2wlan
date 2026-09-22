// Split out of the former flat include!-ed test file so the module is a
// real Rust scope. Everything below is unchanged test code.
use super::*;
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
const PREDICTABLE_RESERVATION_FIRST_PORT: u16 = 20_000;
const PREDICTABLE_RESERVATION_STRIDE: u16 = 128;

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
    let min_offset = A_PREDICTABLE_MAPPED_OFFSETS
        .into_iter()
        .chain(B_PREDICTABLE_MAPPED_OFFSETS)
        .min()
        .unwrap();
    let max_offset = 4 * (p2pnet_nat::mapping::MAX_PREDICTED_PORTS as i32 - 1);
    assert!(i32::from(PREDICTABLE_RESERVATION_STRIDE) > max_offset - min_offset);

    for (mapped_offsets, step) in [
        (A_PREDICTABLE_MAPPED_OFFSETS, 4),
        (B_PREDICTABLE_MAPPED_OFFSETS, 3),
    ] {
        let offsets = predictable_candidate_guard_offsets(&mapped_offsets, step);
        assert!(mapped_offsets.iter().all(|mapped| offsets.contains(mapped)));
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
    const RESERVATION_RETRIES: u16 = 64;

    'reserve: for attempt in 0..RESERVATION_RETRIES {
        // Windows commonly assigns consecutive `bind(0)` ports. Once the A
        // side owns its complete guard window, repeatedly asking the kernel
        // for B's base can therefore keep landing inside that same window.
        // Scan explicit, non-overlapping fixture windows instead. Every port
        // is still bound and ownership-checked before the harness starts.
        let public_port = PREDICTABLE_RESERVATION_FIRST_PORT
            .checked_add(PREDICTABLE_RESERVATION_STRIDE * attempt)
            .expect("predictable reservation port range");
        let public_endpoint = SocketAddr::new(ip, public_port);
        let public = match UdpSocket::bind(public_endpoint).await {
            Ok(socket) => Arc::new(socket),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                continue;
            }
            Err(error) => panic!("bind predictable public endpoint {public_endpoint}: {error}"),
        };
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
    panic!("could not reserve a predictable candidate fixture set");
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
                    A_PREDICTABLE_MAPPED_OFFSETS.map(|offset| offset_port(public_port, offset))
                } else {
                    B_PREDICTABLE_MAPPED_OFFSETS.map(|offset| offset_port(public_port, offset))
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
    mtu: Arc<[NatMtuDirection; 2]>,
    route_dynamic_socket: bool,
    worker: Option<tokio::task::JoinHandle<()>>,
}

// This userspace NAT link models IPv4 path MTUs, not the loopback interface
// MTU. Observe the actual UDP payload after protocol framing/encryption and
// account for the outer IPv4 and UDP headers separately in each direction.
struct NatMtuDirection {
    ip_mtu: AtomicU64,
    max_udp_payload: AtomicU64,
    oversize_drops: AtomicU64,
}

impl NatMtuDirection {
    fn new() -> Self {
        Self {
            ip_mtu: AtomicU64::new(65_535),
            max_udp_payload: AtomicU64::new(0),
            oversize_drops: AtomicU64::new(0),
        }
    }

    fn admit(&self, udp_payload: usize) -> bool {
        let udp_payload = udp_payload as u64;
        self.max_udp_payload
            .fetch_max(udp_payload, Ordering::Relaxed);
        if udp_payload + 20 + 8 > self.ip_mtu.load(Ordering::Acquire) {
            self.oversize_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }
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
        let mtu = Arc::new([NatMtuDirection::new(), NatMtuDirection::new()]);
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
            mtu.clone(),
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
            mtu,
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

    fn classify_packet(data: &[u8], receiver_keys: &TransportKeyPair) -> NatPacketClassification {
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
        mtu: Arc<[NatMtuDirection; 2]>,
        primary_a: Option<SocketAddr>,
        route_dynamic_socket: bool,
    ) {
        let mut a_buf = vec![0u8; 8192];
        let mut b_buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                result = a_public.recv_from(&mut a_buf) => {
                    let Ok((len, source)) = result else { return; };
                    if !mtu[1].admit(len) {
                        continue;
                    }
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
                    if !mtu[0].admit(len) {
                        continue;
                    }
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
        self.hold_authenticated_punch.store(hold, Ordering::Release);
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

    async fn release_held_authenticated_punches(&self, udp_a: &UdpTransport, udp_b: &UdpTransport) {
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
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
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
        vec![udp_reader, wg_reader],
        validation_worker,
        peer_reflexive_worker,
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

    let (
        udp_a,
        _validation_a,
        _prflx_a,
        validation_enabled_a,
        mut tasks_a,
        validation_task_a,
        peer_reflexive_task_a,
    ) = install_test_daemon_udp(&mut daemon_a, HARD_HARD_A, "10.20.0.1", &wg_a).await;
    let (
        udp_b,
        _validation_b,
        _prflx_b,
        validation_enabled_b,
        mut tasks_b,
        validation_task_b,
        peer_reflexive_task_b,
    ) = install_test_daemon_udp(&mut daemon_b, HARD_HARD_B, "10.20.0.2", &wg_b).await;
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
        validation_tasks: vec![validation_task_a, validation_task_b],
        peer_reflexive_tasks: vec![peer_reflexive_task_a, peer_reflexive_task_b],
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
                        peer.current_direct_pair
                            .map(|pair| (pair.source, pair.state, pair.remote_endpoint)),
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
                .diagnostic_with_path_selection(peer_id, true, false, Duration::ZERO, None)
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
                .diagnostic_with_path_selection(peer_id, true, false, Duration::ZERO, None)
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

async fn wait_for_remote_candidates(
    peers: &PeerManager,
    peer_id: &str,
    expected_candidates: &[String],
) {
    let result = timeout(HARD_HARD_E2E_TIMEOUT, async {
        loop {
            let matches = peers
                .diagnostics()
                .await
                .into_iter()
                .find(|peer| peer.node_id == peer_id)
                .is_some_and(|peer| peer.candidates == expected_candidates);
            if matches {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if result.is_err() {
        let diagnostics = peers.diagnostics().await;
        panic!(
            "peer {peer_id} did not apply the expected remote candidates {expected_candidates:?}; diagnostics={diagnostics:#?}"
        );
    }
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
            signal_type: "peer_offer".to_string(),
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
    // A failed speculative session is not the DirectFirst connection
    // deadline. Keep the default policy: Relay can already be confirmed
    // while neither side is yet allowed to send business through it.
    // Require eventual fallback on BOTH sides without ever permitting a
    // stale/unauthenticated Direct path to satisfy this assertion.
    timeout(Duration::from_secs(8), async {
        loop {
            let a = harness
                .peers_a
                .select_path_for_data(HARD_HARD_B, true, true)
                .await;
            let b = harness
                .peers_b
                .select_path_for_data(HARD_HARD_A, true, true)
                .await;
            assert_ne!(a.path, Some(NetworkPath::Direct));
            assert_ne!(b.path, Some(NetworkPath::Direct));
            if a.path == Some(NetworkPath::Relay) && b.path == Some(NetworkPath::Relay) {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both peers must admit confirmed Relay after the bounded DirectFirst window");
}

async fn build_hard_hard_ordinary_fallback_fixture(
) -> (Daemon, Arc<PeerManager>, UdpTransport, ControlClient) {
    build_hard_hard_ordinary_fallback_fixture_with_experiment(false).await
}

async fn build_hard_hard_ordinary_fallback_fixture_with_experiment(
    hard_hard_experiment_only: bool,
) -> (Daemon, Arc<PeerManager>, UdpTransport, ControlClient) {
    let mut config =
        Config::generate_default("http://hard-hard-fallback.test", "phase-2-2-fallback").unwrap();
    config.node.node_id = HARD_HARD_A.to_string();
    config.network.manual = true;
    config.network.udp_bind = "127.0.0.1:0".to_string();
    config.network.fresh_mapping_punch_enabled = true;
    config.network.fresh_mapping_harness_loopback = true;
    config.network.hard_hard_experiment_only = hard_hard_experiment_only;
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

mod scenarios;
