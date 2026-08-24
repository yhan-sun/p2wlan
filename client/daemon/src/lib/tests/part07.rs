use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::Mutex as StdMutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::control::TestControlSignal;
use crate::peer::NetworkPath;
use p2pnet_nat::{
    peek_authenticated_punch_identity, HairpinBehavior, MappingBehavior, MappingLifetime,
    NatProfile, PunchPacketKind, StunAttribute, StunMessage,
};
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Notify, Semaphore};

const HARD_HARD_A: &str = "peer-a";
const HARD_HARD_B: &str = "peer-b";

/// The fixed public ports are the top-1 prediction from each configured STUN
/// sequence. A fresh test allocation gets a disjoint block so the E2E tests
/// remain safe when the workspace runs tests concurrently.
static HARD_HARD_NEXT_PORT: AtomicU16 = AtomicU16::new(30_000);
static HARD_HARD_NEXT_SIGNAL_SEQ: AtomicU64 = AtomicU64::new(1);
static HARD_HARD_E2E_SERIAL: Semaphore = Semaphore::const_new(1);

#[derive(Clone, Copy)]
struct HarnessStunProfile {
    observer_count: usize,
    timeout: Duration,
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

impl HarnessPorts {
    fn allocate(stun: HarnessStunProfile) -> Self {
        assert!((3..=4).contains(&stun.observer_count));
        let base = HARD_HARD_NEXT_PORT.fetch_add(300, Ordering::Relaxed);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let a_public_offset = if stun.observer_count == 4 { 16 } else { 12 };
        let b_public_offset = if stun.observer_count == 4 { 112 } else { 109 };
        Self {
            a_public: SocketAddr::new(ip, base.saturating_add(a_public_offset)),
            b_public: SocketAddr::new(ip, base.saturating_add(b_public_offset)),
            a_observers: [
                SocketAddr::new(ip, base.saturating_add(1)),
                SocketAddr::new(ip, base.saturating_add(2)),
                SocketAddr::new(ip, base.saturating_add(3)),
                SocketAddr::new(ip, base.saturating_add(4)),
            ],
            b_observers: [
                SocketAddr::new(ip, base.saturating_add(5)),
                SocketAddr::new(ip, base.saturating_add(6)),
                SocketAddr::new(ip, base.saturating_add(7)),
                SocketAddr::new(ip, base.saturating_add(8)),
            ],
            a_mapped: [base, base + 4, base + 8, base + 12],
            b_mapped: [base + 100, base + 103, base + 106, base + 109],
        }
    }
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

fn harness_config(
    identity: &NodeIdentity,
    node_id: &str,
    virtual_ip: &str,
    config_path: PathBuf,
    stun: HarnessStunProfile,
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
    config.network.birthday_probing_enabled = false;
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
        endpoint: bind,
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
    hold_ack: Arc<AtomicBool>,
    held_a_to_b: Arc<StdMutex<Vec<Vec<u8>>>>,
    held_b_to_a: Arc<StdMutex<Vec<Vec<u8>>>>,
    worker: Option<tokio::task::JoinHandle<()>>,
}

struct HeldAcks {
    a_to_b: Vec<Vec<u8>>,
    b_to_a: Vec<Vec<u8>>,
}

impl NatPacketLink {
    async fn new(
        ports: HarnessPorts,
        udp_a: UdpTransport,
        udp_b: UdpTransport,
        actual_public: Option<(SocketAddr, SocketAddr)>,
        primary_a: Option<SocketAddr>,
    ) -> Self {
        let a_public = Arc::new(UdpSocket::bind(ports.a_public).await.unwrap());
        let b_public = Arc::new(UdpSocket::bind(ports.b_public).await.unwrap());
        let (a_source_endpoint, b_source_endpoint) =
            actual_public.unwrap_or((ports.a_public, ports.b_public));
        let a_source = if a_source_endpoint == ports.a_public {
            a_public.clone()
        } else {
            Arc::new(UdpSocket::bind(a_source_endpoint).await.unwrap())
        };
        let b_source = if b_source_endpoint == ports.b_public {
            b_public.clone()
        } else {
            Arc::new(UdpSocket::bind(b_source_endpoint).await.unwrap())
        };
        let drop_a_to_b = Arc::new(AtomicBool::new(false));
        let drop_b_to_a = Arc::new(AtomicBool::new(false));
        let hold_ack = Arc::new(AtomicBool::new(false));
        let held_a_to_b = Arc::new(StdMutex::new(Vec::new()));
        let held_b_to_a = Arc::new(StdMutex::new(Vec::new()));
        let worker = Some(tokio::spawn(Self::run(
            a_public.clone(),
            b_public.clone(),
            a_source.clone(),
            b_source.clone(),
            udp_a.clone(),
            udp_b.clone(),
            drop_a_to_b.clone(),
            drop_b_to_a.clone(),
            hold_ack.clone(),
            held_a_to_b.clone(),
            held_b_to_a.clone(),
            primary_a,
        )));
        Self {
            a_public,
            b_public,
            _a_source: a_source,
            _b_source: b_source,
            drop_a_to_b,
            drop_b_to_a,
            hold_ack,
            held_a_to_b,
            held_b_to_a,
            worker,
        }
    }

    async fn forward(
        source_socket: &UdpSocket,
        data: &[u8],
        target_udp: &UdpTransport,
        target_peer: &str,
        primary: Option<SocketAddr>,
        dropped: &AtomicBool,
    ) {
        if dropped.load(Ordering::Acquire) {
            return;
        }
        // `primary` models the exact NAT mapping which originated the
        // competing ordinary punch. Route the reply only to that owner: a
        // duplicate to the Hard-Hard dynamic socket can consume the one-shot
        // ACK expectation first and make the intended primary winner depend on
        // platform task scheduling.
        if let Some(primary) = primary {
            let _ = source_socket.send_to(data, primary).await;
            return;
        }
        if target_udp.has_dynamic_socket_for_peer(target_peer).await {
            if let Some((_, socket)) = target_udp.socket_for_peer(Some(target_peer)).await {
                if let Ok(target) = socket.local_addr() {
                    let _ = source_socket.send_to(data, target).await;
                }
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
        hold_ack: Arc<AtomicBool>,
        held_a_to_b: Arc<StdMutex<Vec<Vec<u8>>>>,
        held_b_to_a: Arc<StdMutex<Vec<Vec<u8>>>>,
        primary_a: Option<SocketAddr>,
    ) {
        let mut a_buf = vec![0u8; 8192];
        let mut b_buf = vec![0u8; 8192];
        loop {
            tokio::select! {
                result = a_public.recv_from(&mut a_buf) => {
                    let Ok((len, _)) = result else { return; };
                    if hold_ack.load(Ordering::Acquire)
                        && Self::is_authenticated_ack(&a_buf[..len])
                    {
                        held_b_to_a
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(a_buf[..len].to_vec());
                        continue;
                    }
                    // B's packet arrived at A's mapped public endpoint. Send
                    // from B_PUBLIC so A observes the real reciprocal NAT
                    // source, and optionally duplicate it to A's primary
                    // socket for the competing-Direct race test.
                    Self::forward(
                        &b_source,
                        &a_buf[..len],
                        &udp_a,
                        HARD_HARD_B,
                        primary_a,
                        &drop_b_to_a,
                    ).await;
                }
                result = b_public.recv_from(&mut b_buf) => {
                    let Ok((len, _)) = result else { return; };
                    if hold_ack.load(Ordering::Acquire)
                        && Self::is_authenticated_ack(&b_buf[..len])
                    {
                        held_a_to_b
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(b_buf[..len].to_vec());
                        continue;
                    }
                    // A's packet arrived at B's mapped public endpoint. Send
                    // from A_PUBLIC so B observes A's predicted source.
                    Self::forward(
                        &a_source,
                        &b_buf[..len],
                        &udp_b,
                        HARD_HARD_A,
                        None,
                        &drop_a_to_b,
                    ).await;
                }
            }
        }
    }

    fn is_authenticated_ack(data: &[u8]) -> bool {
        peek_authenticated_punch_identity(data)
            .is_some_and(|identity| identity.kind == PunchPacketKind::Ack)
    }

    fn set_drop_a_to_b(&self, drop: bool) {
        self.drop_a_to_b.store(drop, Ordering::Release);
    }

    fn set_drop_b_to_a(&self, drop: bool) {
        self.drop_b_to_a.store(drop, Ordering::Release);
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
                &self.drop_b_to_a,
            )
            .await;
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
        for task in self
            .udp_tasks
            .drain(..)
            .chain(self.validation_tasks.drain(..))
            .chain(self.peer_reflexive_tasks.drain(..))
        {
            task.abort();
        }
        self.stun_observers.clear();
        if let Some(task) = self.link.worker.take() {
            task.abort();
        }
        // Keep the public sockets owned by the link alive until its worker has
        // been stopped; then their Drop closes the exact simulated NAT ports.
        drop(self.link);
        for path in self.temp_dirs {
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
    let ports = HarnessPorts::allocate(stun);
    let a_identity = NodeIdentity::generate();
    let b_identity = NodeIdentity::generate();
    let root = std::env::temp_dir().join(format!(
        "p2wlan-phase-2-2-{}-{}",
        std::process::id(),
        HARD_HARD_NEXT_PORT.load(Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    let path_a = root.join("peer-a.json");
    let path_b = root.join("peer-b.json");
    let mut daemon_a = Daemon::new(harness_config(
        &a_identity,
        HARD_HARD_A,
        "10.20.0.1",
        path_a,
        stun,
    ));
    let mut daemon_b = Daemon::new(harness_config(
        &b_identity,
        HARD_HARD_B,
        "10.20.0.2",
        path_b,
        stun,
    ));

    let peers_a = daemon_a.peers.clone();
    let peers_b = daemon_b.peers.clone();
    let punch_attempts_a = daemon_a.punch_attempts.clone();
    let punch_attempts_b = daemon_b.punch_attempts.clone();
    let a_profile = hard_hard_profile(ports.a_public, 4);
    let b_profile = hard_hard_profile(ports.b_public, 3);
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
            SocketAddr::new(ports.a_public.ip(), ports.a_public.port().saturating_add(1)),
            SocketAddr::new(ports.b_public.ip(), ports.b_public.port().saturating_add(1)),
        )
    });
    let link = NatPacketLink::new(
        ports,
        udp_a.clone(),
        udp_b.clone(),
        actual_public,
        primary_a,
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
    let mut stun_observers = ports
        .a_observers
        .iter()
        .take(stun.observer_count)
        .copied()
        .zip(ports.a_mapped.iter().copied())
        .map(|(bind, mapped)| spawn_stun_observer(bind, mapped))
        .collect::<Vec<_>>();
    stun_observers.extend(
        ports
            .b_observers
            .iter()
            .take(stun.observer_count)
            .copied()
            .zip(ports.b_mapped.iter().copied())
            .map(|(bind, mapped)| spawn_stun_observer(bind, mapped)),
    );
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
        validation_enabled_a,
        validation_enabled_b,
        stun_observers,
        temp_dirs: vec![root],
    }
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
            None,
        )
        .await
        .unwrap();
}

async fn wait_for_both_direct(harness: &TwoPeerHarness) {
    let result = timeout(Duration::from_secs(12), async {
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

async fn wait_for_stage(
    peers: &PeerManager,
    peer_id: &str,
    stage: &str,
) -> peer::DirectTraversalEventDiagnostics {
    let result = timeout(Duration::from_secs(12), async {
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
        wait_for_stage(&harness.peers_a, HARD_HARD_B, "hard_hard_sweep_failed",),
        wait_for_stage(&harness.peers_b, HARD_HARD_A, "hard_hard_sweep_failed",),
    );
}

async fn wait_for_hard_hard_response_signal(harness: &TwoPeerHarness) -> TestControlSignal {
    wait_for_hard_hard_response_signal_number(harness, 1).await
}

async fn wait_for_hard_hard_response_signal_number(
    harness: &TwoPeerHarness,
    response_number: usize,
) -> TestControlSignal {
    let result = timeout(Duration::from_secs(12), async {
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
    timeout(Duration::from_secs(12), receipt.wait())
        .await
        .expect("candidate offer must reach a state-machine disposition")
}

async fn wait_for_failed_attempt_cleanup(harness: &TwoPeerHarness) {
    let result = timeout(Duration::from_secs(12), async {
        loop {
            let clean = !harness
                .peers_a
                .hard_hard_session_is_active(HARD_HARD_B)
                .await
                && !harness
                    .peers_b
                    .hard_hard_session_is_active(HARD_HARD_A)
                    .await
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
        panic!(
            "failed Hard↔Hard attempt cleanup: A active={a_active} sockets={a_sockets} pending={a_pending}; B active={b_active} sockets={b_sockets} pending={b_pending}"
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

    let diagnostics_a = harness.peers_a.diagnostics().await;
    let diagnostics_b = harness.peers_b.diagnostics().await;
    let peer_a = &diagnostics_a[0];
    let peer_b = &diagnostics_b[0];
    let fresh_a = harness
        .peers_a
        .fresh_mapping_for_peer(HARD_HARD_B)
        .await
        .expect("A must retain its measured fresh mapping");
    let fresh_b = harness
        .peers_b
        .fresh_mapping_for_peer(HARD_HARD_A)
        .await
        .expect("B must retain its measured fresh mapping");
    for diagnostics in [peer_a, peer_b] {
        assert_eq!(diagnostics.state, ConnectionState::Direct);
        assert_eq!(diagnostics.active_path, Some(NetworkPath::Direct));
    }

    let measured_a = fresh_a.socket_index;
    let measured_b = fresh_b.socket_index;
    assert!(!fresh_a.predicted_ports.is_empty());
    assert!(!fresh_b.predicted_ports.is_empty());
    assert_eq!(
        Some(fresh_a.socket_local_endpoint),
        harness
            .udp_a
            .socket_for_peer(Some(HARD_HARD_B))
            .await
            .and_then(|(_, socket)| socket.local_addr().ok())
    );
    assert_eq!(
        Some(fresh_b.socket_local_endpoint),
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
        Some(fresh_a.socket_local_endpoint.to_string()).as_deref()
    );
    assert_eq!(
        current_pair_b.local_endpoint.as_deref(),
        Some(fresh_b.socket_local_endpoint.to_string()).as_deref()
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
    let s1_probe_wait = timeout(Duration::from_secs(5), async {
        loop {
            if harness.udp_a.dynamic_socket_count().await == 1
                && harness.udp_b.dynamic_socket_count().await == 1
                && harness.link.held_ack_count() > 0
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
    s1_probe_wait.expect("S1 must emit authenticated probes whose ACKs can be held");
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
    // meaningful stale-ACK assertion rather than a post-success no-op.
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
    timeout(Duration::from_secs(5), async {
        loop {
            if harness.link.held_ack_count() > 0
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
    .await
    .expect("S2 must have live pending probes before stale ACK replay");
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
    harness.link.set_drop_a_to_b(true);
    harness.link.set_drop_b_to_a(true);
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
    let superseded_a = wait_for_stage(
        &harness.peers_a,
        HARD_HARD_B,
        "hard_hard_superseded_by_other_direct",
    )
    .await;
    assert!(
        superseded_a
            .detail
            .contains(&format!("socket index={hard_socket_index}")),
        "superseded event must identify the detached Hard↔Hard socket: {}",
        superseded_a.detail
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
    assert_eq!(
        harness.udp_a.dynamic_socket_count().await,
        0,
        "the superseded Hard↔Hard socket must detach while primary remains"
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
    assert!(
        !harness
            .peers_a
            .hard_hard_session_is_active(HARD_HARD_B)
            .await
    );
    harness.shutdown().await;
}
