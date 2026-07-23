//! # p2pnet-daemon
//!
//! The main client daemon that runs the P2P virtual network.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                     Daemon                          │
//! │  ┌─────────┐  ┌──────────┐  ┌──────────────────┐   │
//! │  │  Config  │  │ Control  │  │   PeerManager    │   │
//! │  └─────────┘  │  Client  │  │  (WireGuard/Relay)│   │
//! │               └──────────┘  └──────────────────┘   │
//! │  ┌─────────┐  ┌──────────┐  ┌──────────────────┐   │
//! │  │  DNS    │  │   ACL    │  │  PortMapping     │   │
//! │  └─────────┘  └──────────┘  └──────────────────┘   │
//! │                      ↕                              │
//! │               ┌───────────┐                         │
//! │               │ TUN NIC   │                         │
//! │               └───────────┘                         │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## Phases Implemented
//!
//! - Phase 1: TUN virtual interface
//! - Phase 2: WireGuard encryption & handshake
//! - Phase 3: NAT traversal (STUN / ICE / UDP hole punching)
//! - Phase 4: Relay (DERP-like)
//! - Phase 5: Control plane client, peer management, ACL, DNS, port mapping

pub mod acl;
pub mod config;
pub mod control;
pub mod dataplane;
pub mod diagnostics;
pub mod dns;
pub mod error;
pub mod gateway_mapping;
pub mod peer;
pub mod port_mapping;
pub mod relay;
pub mod route;
pub mod tasks;
pub mod transport;
pub mod traversal_history;
pub mod udp;

// Re-export key types
pub use config::Config;
pub use error::{DaemonError, Result};

// ============================================================
// Daemon
// ============================================================

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use igd_next::{aio::tokio::search_gateway, PortMappingProtocol, SearchOptions};
use p2pnet_crypto::NodeIdentity;
use p2pnet_nat::{CandidateGatherReport, CandidateSource, NatProfile};
use rand::RngCore;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn};

use acl::AclEngine;
use control::{ControlClient, ControlEvent, RelayCatalogEntry};
use dataplane::{DataPlane, InboundPacket, OutboundPacket};
use diagnostics::{run_diagnostics_server, DiagnosticsContext};
use dns::DnsResolver;
use gateway_mapping::{record_method_result, GatewayMappingDiagnostics, GatewayMappingRuntime};
use p2pnet_tun::{InterfaceConfig, Ipv4Packet, TunDevice, VirtualInterface};
use p2pnet_wireguard::{
    HandshakeInitiator, HandshakeResponder, MessageInitiation, MessageResponse, TransportSession,
};
use peer::{
    ConnectionState, NetworkPath, PeerManager, REASON_DIRECT_PROBE_FAILED,
    REASON_DIRECT_SEND_FAILED, REASON_HANDSHAKE_TIMEOUT, REASON_NETWORK_GENERATION_CHANGED,
};
use port_mapping::PortMappingManager;
use relay::{
    select_relay_with_cooldowns, RelayCandidateConfig, RelaySelectionDiagnostics,
    RelaySelectionOutcome, RelayTicketCache, RelayTransport,
};
use transport::{EncryptedPeerPacket, WireGuardTransport};
use udp::{PeerReflexiveObservation, UdpTransport};

/// Shared pending-handshake state (timeout-safe).
#[derive(Default)]
struct PendingHandshakeState {
    pending: HashMap<String, HandshakeInitiator>,
    /// Peers for which a handshake is being prepared.  Candidate gathering and
    /// control-peer lookups await, so a plain `pending` check is not enough to
    /// prevent another trigger from creating and overwriting an initiator in
    /// that window.
    starting: HashSet<String>,
    pending_ids: HashMap<String, u64>,
    next_id: u64,
    /// Number of initiation attempts per peer (bounded retries).
    attempts: HashMap<String, u32>,
}

impl PendingHandshakeState {
    /// Atomically claim the right to prepare a new initiator for `peer_id`.
    ///
    /// A caller must later either commit it with `insert_reserved` or release
    /// it with `cancel_reservation`.
    fn reserve_start(&mut self, peer_id: &str) -> bool {
        if self.pending.contains_key(peer_id) || self.starting.contains(peer_id) {
            return false;
        }
        self.starting.insert(peer_id.to_string());
        true
    }

    fn cancel_reservation(&mut self, peer_id: &str) {
        self.starting.remove(peer_id);
    }

    fn insert_reserved(&mut self, peer_id: String, initiator: HandshakeInitiator) -> Option<u64> {
        if !self.starting.remove(&peer_id) {
            return None;
        }
        Some(self.insert(peer_id, initiator))
    }

    fn insert(&mut self, peer_id: String, initiator: HandshakeInitiator) -> u64 {
        self.next_id = self.next_id.saturating_add(1);
        let pending_id = self.next_id;
        self.pending.insert(peer_id.clone(), initiator);
        self.pending_ids.insert(peer_id, pending_id);
        pending_id
    }

    fn remove(&mut self, peer_id: &str) -> Option<HandshakeInitiator> {
        self.pending_ids.remove(peer_id);
        self.pending.remove(peer_id)
    }

    fn clear_peer(&mut self, peer_id: &str) {
        self.remove(peer_id);
        self.cancel_reservation(peer_id);
        self.attempts.remove(peer_id);
    }

    fn is_current(&self, peer_id: &str, pending_id: u64) -> bool {
        self.pending_ids.get(peer_id).copied() == Some(pending_id)
    }
}

/// Maximum number of handshake re-initiation attempts before giving up.
const MAX_HANDSHAKE_ATTEMPTS: u32 = 5;
/// Handshake timeout before pending entry is cleared.
const HANDSHAKE_TIMEOUT_SECS: u64 = 90;
/// Grace period for UDP/STUN/port-mapping candidate gathering before signaling a WireGuard offer.
///
/// Real home gateways can take a little over 3s when STUN and short UPnP/PCP/NAT-PMP discovery
/// race at startup.  Sending an offer with zero candidates is especially harmful for symmetric-like
/// NATs because the peer starts its synchronized punch window without any usable destination for us.
const CANDIDATE_READY_TIMEOUT_MS: u64 = 8_000;
/// Public STUN fallbacks used when older configs do not specify STUN servers.
const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.miwifi.com:3478",
    "stun.l.google.com:19302",
];
/// Re-gather candidates often enough to notice Wi-Fi/hotspot changes.
const CANDIDATE_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// Server-side signaling currently rejects candidate lists above this size.
const MAX_SIGNAL_CANDIDATES: usize = 20;
/// Keep UPnP discovery short so unsupported gateways never delay startup much.
const UPNP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Short UPnP lease; refreshed by the regular candidate refresh loop.
const PORT_MAPPING_LEASE_SECS: u32 = 120;
/// NAT-PMP / PCP share UDP port 5351 and should fail fast when unsupported.
const NAT_MAPPING_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(1_500);
const NAT_MAPPING_CONTROL_PORT: u16 = 5351;
/// Retry unavailable gateway discovery slowly; repeated 15s multicast probes
/// are noisy and rarely turn a disabled router into an IGD.
const PORT_MAPPING_FAILURE_RETRY: Duration = Duration::from_secs(60);
/// Short cooldown after a selected Relay fails at runtime before trying it again.
const RELAY_RUNTIME_FAILURE_COOLDOWN: Duration = Duration::from_secs(10);
/// Active-path liveness must react much faster than a typical NAT mapping lease.
const DIRECT_LIVENESS_INTERVAL_MAX: Duration = Duration::from_secs(8);
/// Delay advertised in signaling so both peers can align a short UDP punching burst.
const RELAY_ASSISTED_PUNCH_DELAY: Duration = Duration::from_millis(1_500);
/// Start slightly before the advertised punch timestamp to absorb clock skew,
/// HTTP wake-up jitter, and scheduler latency while still keeping the packet
/// budget bounded by the existing probe schedule.
const RELAY_ASSISTED_PUNCH_LEAD: Duration = Duration::from_millis(250);
/// Ignore very stale relay-assisted windows and punch immediately instead.
const RELAY_ASSISTED_PUNCH_STALE_AFTER: Duration = Duration::from_secs(3);
/// Re-advertise peer-reflexive observations a few times during the most useful
/// NAT opening window. The UDP layer already rate-limits duplicate observations,
/// so this stays bounded while giving the remote side several chances to catch
/// the learned source port.
const PEER_REFLEXIVE_SIGNAL_DELAYS: [Duration; 4] = [
    Duration::ZERO,
    Duration::from_millis(80),
    Duration::from_millis(250),
    Duration::from_millis(700),
];
/// Send a few real encrypted packets over a freshly observed UDP path. The
/// packets are valid ICMP echo requests, so the remote TUN can answer and both
/// sides can confirm the WireGuard data path without waiting for user traffic.
const DIRECT_ENCRYPTED_VALIDATION_DELAYS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(80),
    Duration::from_millis(250),
];
const DIRECT_ENCRYPTED_VALIDATION_PAYLOAD: &[u8] = b"p2wlan-direct-validation";
/// Avoid overlapping offer/answer, refresh, and retry bursts for one peer.
/// Competing bursts can create distinct NAT mappings and reduce, rather than
/// improve, the chance that both peers hit the same opening window.
const PUNCH_SESSION_DEDUP_WINDOW: Duration = Duration::from_secs(3);

#[derive(Clone, Default)]
struct PunchAttemptDeduplicator {
    recent_starts: Arc<tokio::sync::Mutex<HashMap<String, Instant>>>,
}

impl PunchAttemptDeduplicator {
    async fn claim(&self, peer_id: &str) -> bool {
        let now = Instant::now();
        let mut starts = self.recent_starts.lock().await;
        starts.retain(|_, started| now.duration_since(*started) < PUNCH_SESSION_DEDUP_WINDOW);
        if starts.contains_key(peer_id) {
            return false;
        }
        starts.insert(peer_id.to_string(), now);
        true
    }
}

/// The main daemon orchestrator.
///
/// Holds all subsystems and coordinates their lifecycle.
pub struct Daemon {
    /// Configuration.
    config: Arc<Config>,
    /// Control plane client.
    control: ControlClient,
    /// Control event receiver.
    control_rx: tokio::sync::mpsc::UnboundedReceiver<ControlEvent>,
    /// Peer connection manager.
    peers: Arc<PeerManager>,
    /// Shared WireGuard transport session adapter.
    transport: WireGuardTransport,
    /// Encrypted outbound packets emitted by the WireGuard adapter.
    encrypted_rx: Option<mpsc::Receiver<EncryptedPeerPacket>>,
    /// In-flight initiator handshakes keyed by responder node ID (shared so timeout tasks can clean up).
    pending_handshakes: Arc<tokio::sync::Mutex<PendingHandshakeState>>,
    /// Local UDP candidate endpoints advertised in signaling messages.
    local_candidates: Arc<RwLock<Vec<String>>>,
    /// Local-only source metadata keyed by candidate endpoint string.
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    /// Latest local NAT behavior profile inferred from STUN observations.
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    /// Cached gateway mapping lifecycle and structured diagnostics.
    gateway_mapping_runtime: Arc<RwLock<GatewayMappingRuntime>>,
    gateway_mapping_diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
    /// Coordinates UDP punch bursts across all trigger paths.
    punch_attempts: PunchAttemptDeduplicator,
    /// Bound UDP transport shared with control-plane-triggered punching.
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    /// Relay transport used when direct UDP is unavailable.
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    /// Latest relay candidate selection diagnostics.
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    /// Port mapping manager.
    port_mappings: Arc<PortMappingManager>,
    /// DNS resolver.
    dns: Arc<DnsResolver>,
    /// ACL engine.
    acl: Arc<RwLock<AclEngine>>,
    /// Route table manager.
    route_manager: Arc<route::RouteManager>,
    /// Shared health state for diagnostics / supervision.
    health: Arc<tasks::HealthState>,
    /// Task manager for spawning and supervising background tasks.
    task_manager: Arc<tasks::TaskManager>,
    /// Shutdown signal sender (true = shut down).
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Shutdown signal receiver cloned into background tasks.
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl Daemon {
    /// Create a new daemon from config.
    pub fn new(config: Config) -> Self {
        let control_enabled = !config.network.manual;
        let config_path = config.config_path.clone();
        let (control, control_rx) = ControlClient::new(&config, control_enabled, config_path);
        let (transport, encrypted_rx) = WireGuardTransport::new();
        let acl_engine = AclEngine::from_config(&config.acl);
        let route_manager = Arc::new(route::RouteManager::new(config.network.interface.clone()));

        let health = tasks::HealthState::new();
        let task_manager = tasks::TaskManager::new(health.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        Self {
            config: Arc::new(config.clone()),
            control,
            control_rx,
            peers: Arc::new(PeerManager::new(config.clone())),
            transport,
            encrypted_rx: Some(encrypted_rx),
            pending_handshakes: Arc::new(tokio::sync::Mutex::new(PendingHandshakeState::default())),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            local_candidate_sources: Arc::new(RwLock::new(HashMap::new())),
            nat_profile: Arc::new(RwLock::new(None)),
            gateway_mapping_runtime: Arc::new(RwLock::new(GatewayMappingRuntime::default())),
            gateway_mapping_diagnostics: Arc::new(RwLock::new(GatewayMappingDiagnostics {
                enabled: config.network.upnp_enabled,
                lease_seconds: PORT_MAPPING_LEASE_SECS,
                ..GatewayMappingDiagnostics::default()
            })),
            punch_attempts: PunchAttemptDeduplicator::default(),
            udp_transport: Arc::new(RwLock::new(None)),
            relay_transport: Arc::new(RwLock::new(None)),
            relay_selection: Arc::new(RwLock::new(RelaySelectionDiagnostics::default())),
            port_mappings: Arc::new(PortMappingManager::new()),
            dns: Arc::new(DnsResolver::new(config.dns.clone())),
            acl: Arc::new(RwLock::new(acl_engine)),
            route_manager,
            health,
            task_manager,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Return a clone of the shutdown sender so main can signal SIGTERM/SIGINT.
    pub fn shutdown_sender(&self) -> tokio::sync::watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Request a graceful shutdown.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.task_manager.request_shutdown();
    }

    /// Run the daemon main loop.
    pub async fn run(&mut self) -> Result<()> {
        info!("P2PNet Daemon v{} starting...", env!("CARGO_PKG_VERSION"));
        info!("Node ID: {}", self.config.node.node_id);
        info!(
            "Network: {} ({})",
            self.config.network.network_id, self.config.network.cidr
        );
        info!("Control server: {}", self.config.control.server_url);

        let mut virtual_ip = self.config.network.virtual_ip.clone();
        let mut netmask = self.config.network.netmask.clone();
        let mut cidr = self.config.network.cidr.clone();
        let mut assigned_node_id = self.config.node.node_id.clone();
        let mut relay_servers = self.config.relay.servers.clone();
        let mut relay_catalog = Vec::new();

        let mut control_event_registered = None;

        if !self.config.network.manual {
            info!("Running in managed mode. Waiting for control plane registration...");
            // Wait for Registered event
            while let Some(event) = self.control_rx.recv().await {
                match event {
                    ControlEvent::Registered {
                        node_id,
                        virtual_ip: vip,
                        cidr: dyn_cidr,
                        relay_servers: rs,
                        relay_catalog: catalog,
                    } => {
                        info!("Control plane registration confirmed. Assigned IP: {}", vip);
                        self.health.mark_control_success().await;

                        // Validate virtual IP
                        if vip.parse::<std::net::Ipv4Addr>().is_err() {
                            return Err(DaemonError::Network(format!(
                                "Server returned invalid virtual IP: {}",
                                vip
                            )));
                        }

                        // Validate CIDR
                        let actual_cidr = dyn_cidr.unwrap_or_else(|| "10.20.0.0/16".to_string());
                        if !is_ip_in_cidr(&vip, &actual_cidr) {
                            return Err(DaemonError::Network(format!(
                                "Server returned virtual IP {} that is outside network CIDR {}",
                                vip, actual_cidr
                            )));
                        }

                        virtual_ip = vip;
                        if let Some(derived_mask) = cidr_to_netmask(&actual_cidr) {
                            netmask = derived_mask;
                        }
                        cidr = actual_cidr;
                        if let Some(nid) = node_id {
                            assigned_node_id = nid;
                        }
                        if !rs.is_empty() {
                            relay_servers = rs;
                        }
                        if !catalog.is_empty() {
                            relay_catalog = catalog;
                        }
                        if relay_servers.is_empty() && relay_catalog.is_empty() {
                            relay_servers =
                                infer_default_relay_servers(&self.config.control.server_url);
                        }

                        control_event_registered = Some(ControlEvent::Registered {
                            node_id: Some(assigned_node_id.clone()),
                            virtual_ip: virtual_ip.clone(),
                            cidr: Some(cidr.clone()),
                            relay_servers: relay_servers.clone(),
                            relay_catalog: relay_catalog.clone(),
                        });
                        break;
                    }
                    ControlEvent::ServerError { code, message } => {
                        return Err(DaemonError::ControlPlane(format!(
                            "Server returned error code {code}: {message}"
                        )));
                    }
                    ControlEvent::ReauthRequired { message } => {
                        return Err(DaemonError::Auth(message));
                    }
                    _ => {
                        warn!("Received event before registration, ignoring: {:?}", event);
                    }
                }
            }
        } else {
            info!("Running in manual/offline mode. Using local configurations.");
        }

        let relay_allow_insecure_plaintext = effective_relay_allow_insecure_plaintext(
            &self.config.control.server_url,
            &relay_catalog,
            &relay_servers,
            self.config.relay.allow_insecure_plaintext,
        );
        if relay_allow_insecure_plaintext && !self.config.relay.allow_insecure_plaintext {
            info!(
                "Allowing plaintext relay because HTTP control plane supplied legacy relay candidates"
            );
        }

        let mut resolved_config = (*self.config).clone();
        resolved_config.network.virtual_ip = virtual_ip.clone();
        resolved_config.network.netmask = netmask.clone();
        resolved_config.network.cidr = cidr.clone();
        resolved_config.node.node_id = assigned_node_id.clone();
        resolved_config.relay.servers = relay_servers.clone();
        resolved_config.relay.allow_insecure_plaintext = relay_allow_insecure_plaintext;
        self.config = Arc::new(resolved_config);

        // Initialize TUN using the resolved IP details
        let tun = self.init_tun_with(&virtual_ip, &netmask, self.config.network.mtu)?;
        if let Some(ref tun) = tun {
            self.route_manager.set_interface(tun.name().to_string());
        }

        // Install overlay route
        self.route_manager.add_cidr_route(&cidr)?;

        let Some(encrypted_rx) = self.encrypted_rx.take() else {
            return Err(DaemonError::Network(
                "encrypted packet receiver already attached".to_string(),
            ));
        };
        let udp_bind = self.config.network.udp_bind.parse().map_err(|e| {
            DaemonError::Config(format!(
                "invalid network.udp_bind '{}': {e}",
                self.config.network.udp_bind
            ))
        })?;
        let udp_advertise = self.config.network.udp_advertise.clone();
        let stun_timeout = Duration::from_millis(self.config.network.stun_timeout_ms);
        let stun_servers =
            parse_stun_servers(&self.config.network.stun_servers, stun_timeout).await?;
        if stun_servers.is_empty() {
            info!("STUN candidate gathering is disabled");
        } else {
            info!("Using STUN endpoints: {stun_servers:?}");
        }
        let configured_keepalive = Duration::from_secs(self.config.network.keepalive_interval_secs);
        let keepalive_interval = if configured_keepalive.is_zero() {
            Duration::ZERO
        } else {
            configured_keepalive.min(DIRECT_LIVENESS_INTERVAL_MAX)
        };
        let upnp_enabled = self.config.network.upnp_enabled;
        let fallback_timeout = Duration::from_millis(self.config.relay.fallback_timeout_ms);
        let prefer_direct = self.config.relay.prefer_direct;
        let punch_interval = Duration::from_millis(self.config.network.punch_interval_ms);
        let punch_attempts = self.config.network.punch_attempts;

        let (network_inbound_tx, network_inbound_rx) = mpsc::channel(1024);
        self.task_manager
            .spawn(
                "network-outbound",
                true,
                run_network_outbound(
                    encrypted_rx,
                    self.peers.clone(),
                    prefer_direct,
                    self.udp_transport.clone(),
                    self.relay_transport.clone(),
                ),
            )
            .await;
        self.task_manager
            .spawn(
                "direct-probe",
                false,
                run_direct_probe_loop(
                    self.peers.clone(),
                    self.udp_transport.clone(),
                    self.punch_attempts.clone(),
                    fallback_timeout,
                    punch_interval,
                    punch_attempts.clamp(1, 3),
                ),
            )
            .await;
        if self.config.diagnostics.enabled {
            let diagnostics_bind = self.config.diagnostics.bind.clone();
            let diagnostics_context = DiagnosticsContext::new(
                self.config.clone(),
                self.peers.clone(),
                self.udp_transport.clone(),
                self.local_candidates.clone(),
                self.nat_profile.clone(),
                self.gateway_mapping_diagnostics.clone(),
                self.relay_transport.clone(),
                self.relay_selection.clone(),
                self.health.clone(),
                self.task_manager.clone(),
                self.shutdown_tx.clone(),
            );
            let shutdown_rx = self.shutdown_rx.clone();
            self.task_manager
                .spawn("diagnostics", false, async move {
                    if let Err(err) =
                        run_diagnostics_server(diagnostics_bind, diagnostics_context, shutdown_rx)
                            .await
                    {
                        warn!("Diagnostics endpoint stopped: {err}");
                    }
                })
                .await;
        }
        if let Some(tun) = tun {
            let peers = self.peers.clone();
            let transport = self.transport.clone();
            let (dataplane, outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers);
            let mut dataplane = dataplane
                .with_acl(self.acl.clone(), self.config.node.node_id.clone())
                .with_overlay_cidr(&self.config.network.cidr);

            let outbound_transport = transport.clone();
            self.task_manager
                .spawn_result("wireguard-outbound", true, async move {
                    outbound_transport.run_outbound(outbound_rx).await
                })
                .await;

            let inbound_transport = transport.clone();
            let inbound_peers = self.peers.clone();
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound_with_peers(network_inbound_rx, inbound_tx, Some(inbound_peers))
                        .await
                })
                .await;

            self.task_manager
                .spawn_result("dataplane", true, async move { dataplane.run().await })
                .await;
        } else {
            let (inbound_tx, inbound_rx) = mpsc::channel(1024);
            let inbound_transport = self.transport.clone();
            let inbound_peers = self.peers.clone();
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound_with_peers(network_inbound_rx, inbound_tx, Some(inbound_peers))
                        .await
                })
                .await;
            self.task_manager
                .spawn(
                    "tun-disabled-inbound-log",
                    false,
                    log_inbound_packets_without_tun(inbound_rx),
                )
                .await;
        }

        let peers = self.peers.clone();
        let control = self.control.clone();
        let local_candidates = self.local_candidates.clone();
        let local_candidate_sources = self.local_candidate_sources.clone();
        let udp_local_candidate_sources = local_candidate_sources.clone();
        let nat_profile = self.nat_profile.clone();
        let gateway_mapping_runtime = self.gateway_mapping_runtime.clone();
        let gateway_mapping_diagnostics = self.gateway_mapping_diagnostics.clone();
        let udp_transport = self.udp_transport.clone();
        let direct_validation_transport = self.transport.clone();
        let direct_validation_local_ip = self.config.network.virtual_ip.clone();
        let udp_inbound_tx = network_inbound_tx.clone();
        let local_node_id = self.config.node.node_id.clone();
        let udp_punch_interval = punch_interval;
        let udp_punch_attempts = punch_attempts;
        let punch_deduplicator = self.punch_attempts.clone();
        self.task_manager
            .spawn_result("udp-direct", false, async move {
                match UdpTransport::bind(udp_bind, peers.clone()).await {
                    Ok(udp) => {
                        let (peer_reflexive_tx, peer_reflexive_rx) = mpsc::channel(128);
                        let udp = udp
                            .with_local_node_id(local_node_id.clone())
                            .with_peer_reflexive_observer(peer_reflexive_tx);
                        tokio::spawn(run_peer_reflexive_signal_loop(
                            peer_reflexive_rx,
                            control.clone(),
                            udp.clone(),
                            peers.clone(),
                            direct_validation_transport,
                            direct_validation_local_ip,
                        ));
                        *udp_transport.write().await = Some(udp.clone());

                        let (mut candidate_endpoints, mut candidate_sources) =
                            match udp.gather_candidate_report(stun_servers.clone(), stun_timeout).await
                            {
                                Ok(report) => {
                                    let (endpoints, sources) = candidate_endpoints_from_report(&report);
                                    info!(
                                        "Local NAT profile: mapping={:?} public={:?} stun_success={}/{} confidence={}",
                                        report.nat_profile.mapping_behavior,
                                        report.nat_profile.public_endpoint,
                                        report
                                            .nat_profile
                                            .observations
                                            .iter()
                                            .filter(|observation| observation.mapped_address.is_some())
                                            .count(),
                                        report.nat_profile.observations.len(),
                                        report.nat_profile.confidence
                                    );
                                    peers.update_nat_profile(report.nat_profile.clone()).await;
                                    *nat_profile.write().await = Some(report.nat_profile);
                                    (endpoints, sources)
                                }
                                Err(err) => {
                                    warn!("Failed to gather UDP candidates: {err}");
                                    (Vec::new(), HashMap::new())
                                }
                            };

                        match udp.local_addr() {
                            Ok(addr) => {
                                if let Some(endpoint) = advertised_udp_endpoint(
                                    addr,
                                    udp_advertise.as_deref(),
                                    &candidate_endpoints,
                                ) {
                                    if !candidate_endpoints.contains(&endpoint) {
                                        candidate_endpoints.insert(0, endpoint.clone());
                                    }
                                    candidate_sources.entry(endpoint.clone()).or_insert_with(|| {
                                        if udp_advertise.as_deref().is_some_and(|configured| {
                                            !configured.trim().is_empty() && configured.trim() == endpoint
                                        }) {
                                            "manual".to_string()
                                        } else {
                                            "host".to_string()
                                        }
                                    });
                                    info!(
                                        "UDP transport listening on {addr}; advertising {endpoint}"
                                    );
                                    if let Err(err) =
                                        control.update_endpoint(&endpoint, "unknown").await
                                    {
                                        warn!("Failed to queue UDP endpoint update: {err}");
                                    }
                                } else {
                                    warn!(
                                        "UDP transport listening on {addr}; no reachable endpoint was discovered or configured."
                                    );
                                }
                            }
                            Err(err) => {
                                warn!("UDP transport bound but local addr unavailable: {err}")
                            }
                        }

                        if upnp_enabled {
                            maybe_add_port_mapping_udp_candidate(
                                udp.local_addr().ok(),
                                &mut candidate_endpoints,
                                &mut candidate_sources,
                                gateway_mapping_runtime.clone(),
                                gateway_mapping_diagnostics.clone(),
                            )
                            .await;
                        }
                        truncate_signal_candidates(
                            &mut candidate_endpoints,
                            &mut candidate_sources,
                        );

                        info!(
                            "Prepared {} UDP candidate endpoints for signaling",
                            candidate_endpoints.len()
                        );
                        *local_candidates.write().await = candidate_endpoints.clone();
                        *udp_local_candidate_sources.write().await = candidate_sources.clone();

                        publish_local_candidates_to_known_peers(
                            &control,
                            peers.clone(),
                            udp.clone(),
                            punch_deduplicator.clone(),
                            &candidate_endpoints,
                            &candidate_sources,
                            udp_punch_interval,
                            udp_punch_attempts,
                            "initial UDP candidates ready",
                        )
                        .await;

                        if keepalive_interval.is_zero() {
                            let refresh_udp = udp.clone();
                            tokio::select! {
                                result = udp.run_inbound(udp_inbound_tx) => result,
                                _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                                    udp: refresh_udp,
                                    stun_servers,
                                    stun_timeout,
                                    udp_advertise,
                                    upnp_enabled,
                                    local_candidates,
                                    local_candidate_sources: udp_local_candidate_sources.clone(),
                                    nat_profile,
                                    gateway_mapping_runtime,
                                    gateway_mapping_diagnostics,
                                    punch_deduplicator,
                                    control,
                                    peers: peers.clone(),
                                    probe_interval: udp_punch_interval,
                                    punch_attempts: udp_punch_attempts,
                                }) => Ok(()),
                            }
                        } else {
                            let keepalive_udp = udp.clone();
                            let refresh_udp = udp.clone();
                            tokio::select! {
                                result = udp.run_inbound(udp_inbound_tx) => result,
                                _ = keepalive_udp.run_keepalives(keepalive_interval) => Ok(()),
                                _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                                    udp: refresh_udp,
                                    stun_servers,
                                    stun_timeout,
                                    udp_advertise,
                                    upnp_enabled,
                                    local_candidates,
                                    local_candidate_sources: udp_local_candidate_sources.clone(),
                                    nat_profile,
                                    gateway_mapping_runtime,
                                    gateway_mapping_diagnostics,
                                    punch_deduplicator,
                                    control,
                                    peers: peers.clone(),
                                    probe_interval: udp_punch_interval,
                                    punch_attempts: udp_punch_attempts,
                                }) => Ok(()),
                            }
                        }
                    }
                    Err(err) => {
                        warn!("UDP transport unavailable ({err}); direct UDP disabled");
                        Ok(())
                    }
                }
            })
            .await;

        // Relay registration must use the node ID assigned by the control plane.
        let mut relay_started = false;

        // If we had a cached control_event_registered, process it first
        if let Some(ControlEvent::Registered {
            ref node_id,
            ref relay_servers,
            ref relay_catalog,
            ..
        }) = control_event_registered
        {
            let relay_node_id = node_id
                .clone()
                .unwrap_or_else(|| self.config.node.node_id.clone());
            let relay_servers = if relay_servers.is_empty() {
                self.config.relay.servers.clone()
            } else {
                relay_servers.clone()
            };
            let relay_candidates = relay_candidates_from_sources(relay_catalog, &relay_servers);
            if relay_candidates.is_empty() {
                debug!(
                    "No relay servers configured; direct UDP only unless peers provide relay later"
                );
            } else {
                relay_started = true;
                let preferred_regions = self.config.relay.preferred_regions.clone();
                let selection_timeout =
                    Duration::from_millis(self.config.relay.selection_timeout_ms.max(1));
                let relay_transport = self.relay_transport.clone();
                let relay_selection = self.relay_selection.clone();
                let relay_peers = self.peers.clone();
                let relay_inbound_tx = network_inbound_tx.clone();

                self.task_manager
                    .spawn(
                        "relay-inbound",
                        false,
                        RelaySupervisor {
                            relay_candidates,
                            preferred_regions,
                            selection_timeout,
                            node_id: relay_node_id,
                            peers: relay_peers,
                            relay_transport,
                            relay_selection,
                            inbound_tx: relay_inbound_tx,
                            ticket_cache: Some(Arc::new(RelayTicketCache::new(
                                self.control.clone(),
                            ))),
                            relay_ticket: None,
                            allow_insecure_plaintext: self.config.relay.allow_insecure_plaintext,
                            ca_cert_path: self.config.relay.ca_cert_path.clone(),
                        }
                        .run(),
                    )
                    .await;
            }
        }

        // Periodic session rekey checker — truly invokes needs_rekey / is_expired.
        {
            let peers = self.peers.clone();
            let transport = self.transport.clone();
            let pending = self.pending_handshakes.clone();
            let control = self.control.clone();
            let local_candidates = self.local_candidates.clone();
            let node_private_key = self.config.node.private_key.clone();
            let node_public_key = self.config.node.public_key.clone();
            self.task_manager
                .spawn("handshake-maintenance", false, async move {
                    let mut tick = tokio::time::interval(Duration::from_secs(10));
                    loop {
                        tick.tick().await;
                        let conns = peers.all_connections().await;
                        for conn in conns {
                            // Establish missing sessions and refresh sessions that need rekey.
                            let has_session = transport.has_session(&conn.node_id).await;
                            let needs = transport.session_needs_rekey(&conn.node_id).await;
                            let expired = transport.session_is_expired(&conn.node_id).await;
                            if has_session && !needs && !expired {
                                continue;
                            }
                            let is_rekey = has_session;
                            if !has_session {
                                debug!(
                                    "No WireGuard session for {}; retrying handshake",
                                    conn.node_id
                                );
                            } else if expired {
                                info!(
                                    "Session for peer {} expired; removing and rekeying",
                                    conn.node_id
                                );
                                transport.remove_session(&conn.node_id).await;
                            } else {
                                info!(
                                    "Session for peer {} needs rekey (message/time threshold)",
                                    conn.node_id
                                );
                            }

                            // Reserve before any further awaits.  The peer-join path can run at
                            // the same time as this maintenance loop; without this reservation,
                            // both paths could create an initiator and the later one would
                            // overwrite the former pending handshake.
                            let reserved = {
                                let mut state = pending.lock().await;
                                if !state.reserve_start(&conn.node_id) {
                                    false
                                } else {
                                    if state.attempts.get(&conn.node_id).copied().unwrap_or(0)
                                        >= MAX_HANDSHAKE_ATTEMPTS
                                    {
                                        warn!(
                                            "Handshake for {} reached max attempts; resetting retry budget",
                                            conn.node_id
                                        );
                                        state.attempts.remove(&conn.node_id);
                                    }
                                    true
                                }
                            };
                            if !reserved {
                                continue;
                            }

                            // PeerConnection doesn't store public key; look up from control.
                            // Best-effort: if control has the peer, use it.
                            // (control.peers is async)
                            // We intentionally skip initiation if we can't get the key —
                            // the peer may also rekey from its side.
                            let control_peers = control.peers().await;
                            let Some(peer_info) = control_peers.get(&conn.node_id) else {
                                pending.lock().await.cancel_reservation(&conn.node_id);
                                debug!("No control peer info for handshake with {}", conn.node_id);
                                continue;
                            };
                            if node_public_key >= peer_info.public_key {
                                // Let the other side initiate.
                                pending.lock().await.cancel_reservation(&conn.node_id);
                                continue;
                            }

                            let Ok(private_key) =
                                decode_x25519_key(&node_private_key, "node private key")
                            else {
                                pending.lock().await.cancel_reservation(&conn.node_id);
                                continue;
                            };
                            let Ok(peer_public) =
                                decode_x25519_key(&peer_info.public_key, "peer public key")
                            else {
                                pending.lock().await.cancel_reservation(&conn.node_id);
                                continue;
                            };
                            let identity = NodeIdentity::from_private_key(private_key);
                            let mut initiator =
                                HandshakeInitiator::new(identity, peer_public, None);
                            let Ok(initiation) = initiator.create_initiation() else {
                                pending.lock().await.cancel_reservation(&conn.node_id);
                                continue;
                            };
                            let initiation_bytes = initiation.to_bytes();
                            let candidates = local_candidates.read().await.clone();
                            let candidate_sources = local_candidate_sources.read().await.clone();

                            // An inbound offer may have established a responder session while
                            // candidates were being read.  Do not send a redundant initiation.
                            if transport.has_session(&conn.node_id).await {
                                pending.lock().await.cancel_reservation(&conn.node_id);
                                continue;
                            }

                            let Some((attempt_no, pending_id)) = ({
                                let mut state = pending.lock().await;
                                state.insert_reserved(conn.node_id.clone(), initiator).map(
                                    |pending_id| {
                                        let attempts =
                                            state.attempts.entry(conn.node_id.clone()).or_insert(0);
                                        *attempts = attempts.saturating_add(1);
                                        (*attempts, pending_id)
                                    },
                                )
                            }) else {
                                continue;
                            };

                            let punch_at_ms = Some(relay_assisted_punch_at_ms());
                            if let Err(err) = control
                                .send_peer_offer_with_sources_and_punch_at(
                                    &conn.node_id,
                                    &candidates,
                                    &candidate_sources,
                                    &initiation_bytes,
                                    punch_at_ms,
                                )
                                .await
                            {
                                warn!("Handshake offer to {} failed: {err}", conn.node_id);
                                let mut state = pending.lock().await;
                                if state.is_current(&conn.node_id, pending_id) {
                                    state.remove(&conn.node_id);
                                }
                            } else {
                                if is_rekey {
                                    info!(
                                        "Rekey: sent handshake initiation to {} ({} bytes, attempt {})",
                                        conn.node_id,
                                        initiation_bytes.len(),
                                        attempt_no
                                    );
                                } else {
                                    info!(
                                        "Retry: sent handshake initiation to {} ({} bytes, attempt {})",
                                        conn.node_id,
                                        initiation_bytes.len(),
                                        attempt_no
                                    );
                                }
                                // Timeout cleanup
                                let pending2 = pending.clone();
                                let timeout_peer = conn.node_id.clone();
                                let transport2 = transport.clone();
                                let peers2 = peers.clone();
                                let generation = peers.current_network_generation().await;
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS))
                                        .await;
                                    if !transport2.has_session(&timeout_peer).await {
                                        warn!("Handshake timeout for peer {timeout_peer}");
                                        peers2
                                            .record_direct_failure_for_generation(
                                                &timeout_peer,
                                                generation,
                                                REASON_HANDSHAKE_TIMEOUT,
                                                "handshake timed out",
                                            )
                                            .await;
                                    }
                                    let mut state = pending2.lock().await;
                                    if state.is_current(&timeout_peer, pending_id) {
                                        state.remove(&timeout_peer);
                                        if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                                            state.attempts.remove(&timeout_peer);
                                        }
                                    }
                                });
                            }
                        }
                    }
                })
                .await;
        }

        // Process control events until shutdown is requested.
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut task_shutdown_rx = self.task_manager.shutdown_rx();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Shutdown signal received in main event loop");
                        break;
                    }
                }
                _ = task_shutdown_rx.changed() => {
                    if *task_shutdown_rx.borrow() {
                        warn!("Task manager requested daemon shutdown");
                        break;
                    }
                }
                event = self.control_rx.recv() => {
                    let Some(event) = event else {
                        warn!("Control event channel closed");
                        break;
                    };
                    match event {
                ControlEvent::Registered {
                    node_id,
                    virtual_ip: _,
                    cidr: _,
                    relay_servers,
                    relay_catalog,
                } => {
                    self.health.mark_control_success().await;
                    if !relay_started {
                        let relay_node_id =
                            node_id.unwrap_or_else(|| self.config.node.node_id.clone());
                        let relay_servers = if relay_servers.is_empty() {
                            self.config.relay.servers.clone()
                        } else {
                            relay_servers
                        };
                        let relay_candidates =
                            relay_candidates_from_sources(&relay_catalog, &relay_servers);
                        if relay_candidates.is_empty() {
                            debug!("No relay servers advertised by control plane");
                            continue;
                        }
                        relay_started = true;
                        let allow_insecure_plaintext = effective_relay_allow_insecure_plaintext(
                            &self.config.control.server_url,
                            &relay_catalog,
                            &relay_servers,
                            self.config.relay.allow_insecure_plaintext,
                        );
                        if allow_insecure_plaintext
                            && !self.config.relay.allow_insecure_plaintext
                        {
                            info!(
                                "Allowing plaintext relay because HTTP control plane supplied legacy relay candidates"
                            );
                        }
                        let preferred_regions = self.config.relay.preferred_regions.clone();
                        let selection_timeout =
                            Duration::from_millis(self.config.relay.selection_timeout_ms.max(1));
                        let relay_transport = self.relay_transport.clone();
                        let relay_selection = self.relay_selection.clone();
                        let relay_peers = self.peers.clone();
                        let relay_inbound_tx = network_inbound_tx.clone();

                        self.task_manager
                            .spawn(
                                "relay-inbound",
                                false,
                                RelaySupervisor {
                                    relay_candidates,
                                    preferred_regions,
                                    selection_timeout,
                                    node_id: relay_node_id,
                                    peers: relay_peers,
                                    relay_transport,
                                    relay_selection,
                                    inbound_tx: relay_inbound_tx,
                                    ticket_cache: Some(Arc::new(RelayTicketCache::new(self.control.clone()))),
                                    relay_ticket: None,
                                    allow_insecure_plaintext,
                                    ca_cert_path: self.config.relay.ca_cert_path.clone(),
                                }
                                .run(),
                            )
                            .await;
                    }
                }

                ControlEvent::PeerJoined(peer_info) => {
                    info!(
                        "Peer joined: {} ({})",
                        peer_info.node_id, peer_info.virtual_ip
                    );
                    self.peers.add_peer(&peer_info).await;

                    match self.maybe_initiate_handshake(&peer_info).await {
                        Ok(punch_at_ms) => {
                            self.start_hole_punch_at(&peer_info.node_id, punch_at_ms).await;
                        }
                        Err(err) => {
                            warn!(
                                "Failed to initiate WireGuard handshake with {}: {err}",
                                peer_info.node_id
                            );
                            self.start_hole_punch(&peer_info.node_id).await;
                        }
                    }

                    if self.dns.is_enabled() {
                        self.dns
                            .register(
                                &peer_info.node_id,
                                &peer_info.virtual_ip,
                                Some(&peer_info.node_id),
                            )
                            .await;
                    }
                }

                ControlEvent::PeerUpdated(peer_info) => {
                    let previous = self.peers.get_connection(&peer_info.node_id).await;
                    let update = self.peers.add_peer(&peer_info).await;
                    if update.public_key_changed {
                        self.transport.remove_session(&peer_info.node_id).await;
                        self.pending_handshakes
                            .lock()
                            .await
                            .clear_peer(&peer_info.node_id);
                        info!(
                            "Peer {} public key changed; discarded the old WireGuard session",
                            peer_info.node_id
                        );
                    }
                    if update.virtual_ip_changed && self.dns.is_enabled() {
                        if let Some(previous) = previous {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                        self.dns
                            .register(
                                &peer_info.node_id,
                                &peer_info.virtual_ip,
                                Some(&peer_info.node_id),
                            )
                            .await;
                    }
                    match self.maybe_initiate_handshake(&peer_info).await {
                        Ok(punch_at_ms) => {
                            self.start_hole_punch_at(&peer_info.node_id, punch_at_ms).await;
                        }
                        Err(err) => {
                            warn!(
                                "Failed to refresh WireGuard handshake with {} after peer update: {err}",
                                peer_info.node_id
                            );
                            self.start_hole_punch(&peer_info.node_id).await;
                        }
                    }
                }

                ControlEvent::PeerLeft(node_id) => {
                    info!("Peer left: {}", node_id);
                    if let Some(previous) = self.peers.get_connection(&node_id).await {
                        if self.dns.is_enabled() {
                            self.dns.unregister(&previous.virtual_ip).await;
                        }
                    }
                    self.transport.remove_session(&node_id).await;
                    self.pending_handshakes.lock().await.clear_peer(&node_id);
                    self.peers.remove_peer(&node_id).await;
                }

                ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_init,
                    punch_at_ms,
                    punch_at_server_ms,
                } => {
                    info!(
                        "Received peer offer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_offer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received offer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_init.len()
                            ),
                        )
                        .await;
                    self.peers
                        .add_candidates_with_metadata(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                        )
                        .await;
                    if !handshake_init.is_empty() {
                        if let Err(err) = self
                            .handle_peer_offer(
                                &from_node_id,
                                &candidates,
                                &handshake_init,
                                punch_at_ms,
                                punch_at_server_ms,
                            )
                            .await
                        {
                            warn!("Failed to handle peer offer from {from_node_id}: {err}");
                        }
                    }
                    self.start_hole_punch_at(&from_node_id, punch_at_ms).await;
                }

                ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    candidate_sources,
                    candidate_generation,
                    candidates_expires_at_ms,
                    handshake_response,
                    punch_at_ms,
                    punch_at_server_ms: _,
                } => {
                    info!(
                        "Received peer answer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_answer_received",
                            None,
                            Some(candidates.len()),
                            None,
                            format!(
                                "received answer handshake_bytes={} punch_at_ms={punch_at_ms:?}",
                                handshake_response.len()
                            ),
                        )
                        .await;
                    self.peers
                        .add_candidates_with_metadata(
                            &from_node_id,
                            &candidates,
                            &candidate_sources,
                            candidate_generation,
                            candidates_expires_at_ms,
                        )
                        .await;
                    if !handshake_response.is_empty() {
                        if let Err(err) = self
                            .handle_peer_answer(&from_node_id, &handshake_response)
                            .await
                        {
                            warn!("Failed to handle peer answer from {from_node_id}: {err}");
                        }
                    }
                    self.start_hole_punch_at(&from_node_id, punch_at_ms).await;
                }

                ControlEvent::PeerReflexive {
                    from_node_id,
                    observed_endpoint,
                    punch_at_ms,
                } => {
                    self.add_local_peer_reflexive_candidate(&observed_endpoint).await;
                    let punch_at_ms =
                        punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms()));
                    let candidates = self.local_candidates.read().await.clone();
                    let candidate_sources = self.local_candidate_sources.read().await.clone();
                    self.peers
                        .record_direct_event(
                            &from_node_id,
                            "peer_reflexive_received",
                            observed_endpoint.parse().ok(),
                            Some(candidates.len()),
                            None,
                            format!(
                                "peer observed our UDP source as {observed_endpoint}; punch_at_ms={punch_at_ms:?}"
                            ),
                        )
                        .await;
                    if !candidates.is_empty() {
                        if let Err(err) = self
                            .control
                            .send_peer_offer_with_sources_and_punch_at(
                                &from_node_id,
                                &candidates,
                                &candidate_sources,
                                &[],
                                punch_at_ms,
                            )
                            .await
                        {
                            warn!(
                                "Failed to re-advertise peer-reflexive local candidate to {from_node_id}: {err}"
                            );
                        } else {
                            self.peers
                                .record_direct_event(
                                    &from_node_id,
                                    "peer_reflexive_offer_sent",
                                    observed_endpoint.parse().ok(),
                                    Some(candidates.len()),
                                    None,
                                    "re-advertised local candidates after peer-reflexive observation",
                                )
                                .await;
                        }
                    }
                    self.start_hole_punch_at(&from_node_id, punch_at_ms).await;
                }

                ControlEvent::PeerRejected {
                    from_node_id,
                    reason,
                } => {
                    warn!("Peer {} rejected connection: {}", from_node_id, reason);
                }

                ControlEvent::TunnelCreated {
                    tunnel_id,
                    public_endpoint,
                } => {
                    info!("Tunnel created: {} → {}", tunnel_id, public_endpoint);
                    self.port_mappings
                        .activate(&tunnel_id, &public_endpoint)
                        .await
                        .ok();
                }

                ControlEvent::ServerError { code, message } => {
                    error!("Control server error: {} - {}", code, message);
                }

                ControlEvent::Disconnected => {
                    // Control loop will re-register; do not shut down the daemon.
                    self.health.set_control_connected(false);
                    warn!("Disconnected from control server; waiting for recovery");
                }

                ControlEvent::ReauthRequired { message } => {
                    error!("Reauthentication required: {message}");
                    self.health.set_reauth_required(true);
                    // Keep running so operator can re-auth; do not exit daemon.
                }

                ControlEvent::ControlRecovered { .. } => {
                    info!("Control plane recovered after disconnection");
                    self.health.mark_control_success().await;
                }
                    }
                }
            }
        }

        info!("Daemon shutting down");
        // Explicit cleanup: notify control loop and clean routes without relying on Drop.
        self.request_shutdown();
        let _ = self.control.shutdown().await;
        self.task_manager.shutdown_all(Duration::from_secs(5)).await;
        self.route_manager.cleanup();
        Ok(())
    }

    fn init_tun_with(&self, vip: &str, netmask: &str, mtu: u32) -> Result<Option<TunDevice>> {
        if std::env::var("P2WLAN_DISABLE_TUN").as_deref() == Ok("1") {
            warn!("TUN creation disabled via P2WLAN_DISABLE_TUN=1");
            return Ok(None);
        }

        let config = InterfaceConfig::new(&self.config.network.interface, vip, netmask, mtu)
            .map_err(|e| DaemonError::Network(format!("invalid TUN config: {e}")))?;

        let tun = TunDevice::create(&config)
            .map_err(|e| DaemonError::Network(format!("failed to create TUN interface: {e}")))?;
        info!(
            "TUN interface {} is up at {} MTU {}",
            tun.name(),
            tun.address(),
            tun.mtu()
        );

        Ok(Some(tun))
    }

    async fn maybe_initiate_handshake(
        &mut self,
        peer_info: &control::PeerInfo,
    ) -> Result<Option<u64>> {
        if self.transport.has_session(&peer_info.node_id).await {
            return Ok(None);
        }

        if self.config.node.public_key >= peer_info.public_key {
            return Ok(None);
        }

        let identity = self.local_identity()?;
        let peer_public = decode_x25519_key(&peer_info.public_key, "peer public key")?;

        // Claim this handshake before candidate gathering.  That work awaits,
        // and the background maintenance loop can otherwise observe an empty
        // `pending` map and overwrite this initiator with another one.
        let reserved = {
            let mut state = self.pending_handshakes.lock().await;
            if !state.reserve_start(&peer_info.node_id) {
                false
            } else {
                if state.attempts.get(&peer_info.node_id).copied().unwrap_or(0)
                    >= MAX_HANDSHAKE_ATTEMPTS
                {
                    state.attempts.remove(&peer_info.node_id);
                }
                true
            }
        };
        if !reserved {
            return Ok(None);
        }

        let mut initiator = HandshakeInitiator::new(identity, peer_public, None);
        let initiation = match initiator.create_initiation() {
            Ok(initiation) => initiation,
            Err(error) => {
                self.pending_handshakes
                    .lock()
                    .await
                    .cancel_reservation(&peer_info.node_id);
                return Err(DaemonError::Peer(format!(
                    "WireGuard initiation failed: {error}"
                )));
            }
        };
        let initiation_bytes = initiation.to_bytes();
        let (candidates, candidate_sources) = self.wait_for_local_candidate_set().await;

        let peer_id_clone = peer_info.node_id.clone();
        if self.transport.has_session(&peer_id_clone).await {
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation(&peer_id_clone);
            return Ok(None);
        }

        let Some((attempt_no, pending_id)) = ({
            let mut state = self.pending_handshakes.lock().await;
            state
                .insert_reserved(peer_id_clone.clone(), initiator)
                .map(|pending_id| {
                    let attempts = state.attempts.entry(peer_id_clone.clone()).or_insert(0);
                    *attempts = attempts.saturating_add(1);
                    (*attempts, pending_id)
                })
        }) else {
            return Ok(None);
        };

        let punch_at_ms = relay_assisted_punch_at_ms();
        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_and_punch_at(
                &peer_id_clone,
                &candidates,
                &candidate_sources,
                &initiation_bytes,
                Some(punch_at_ms),
            )
            .await
        {
            let mut state = self.pending_handshakes.lock().await;
            if state.is_current(&peer_id_clone, pending_id) {
                state.remove(&peer_id_clone);
            }
            return Err(error);
        }

        info!(
            "Sent WireGuard handshake initiation to {} ({} bytes, {} candidates, attempt {})",
            peer_id_clone,
            initiation_bytes.len(),
            candidates.len(),
            {
                let state = self.pending_handshakes.lock().await;
                state.attempts.get(&peer_id_clone).copied().unwrap_or(0)
            },
        );
        self.peers
            .record_direct_event(
                &peer_id_clone,
                "peer_offer_sent",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "sent offer handshake_bytes={} attempt={} punch_at_ms={punch_at_ms}",
                    initiation_bytes.len(),
                    attempt_no
                ),
            )
            .await;

        // Spawn timeout watcher that cleans up pending entry on timeout.
        // Uses the shared Arc<Mutex<>> so the spawned task can remove the entry.
        let pending = self.pending_handshakes.clone();
        let timeout_peer = peer_id_clone;
        let transport = self.transport.clone();
        let peers = self.peers.clone();
        let generation = self.peers.current_network_generation().await;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)).await;
            if !transport.has_session(&timeout_peer).await {
                warn!("Handshake timeout for peer {timeout_peer}");
                peers
                    .record_direct_failure_for_generation(
                        &timeout_peer,
                        generation,
                        REASON_HANDSHAKE_TIMEOUT,
                        "handshake timed out",
                    )
                    .await;
            }
            // Remove from pending so retry is possible.
            let mut state = pending.lock().await;
            if state.is_current(&timeout_peer, pending_id) {
                state.remove(&timeout_peer);
                if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                    state.attempts.remove(&timeout_peer);
                }
            }
        });

        Ok(Some(punch_at_ms))
    }

    async fn wait_for_local_candidate_set(&self) -> (Vec<String>, HashMap<String, String>) {
        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(50);
        let timeout = Duration::from_millis(CANDIDATE_READY_TIMEOUT_MS);

        loop {
            let candidates = self.local_candidates.read().await.clone();
            let candidate_sources = self.local_candidate_sources.read().await.clone();
            if !candidates.is_empty() {
                return (candidates, candidate_sources);
            }
            if waited >= timeout {
                warn!(
                    "Proceeding with WireGuard signaling before UDP candidates are ready after {} ms",
                    timeout.as_millis()
                );
                return (candidates, candidate_sources);
            }
            sleep(step).await;
            waited += step;
        }
    }

    async fn add_local_peer_reflexive_candidate(&self, observed_endpoint: &str) {
        let endpoint = match observed_endpoint.parse::<SocketAddr>() {
            Ok(endpoint) => endpoint.to_string(),
            Err(err) => {
                warn!(
                    "Ignoring invalid relay-assisted peer-reflexive endpoint '{}': {err}",
                    observed_endpoint
                );
                return;
            }
        };

        let mut candidates = self.local_candidates.write().await;
        let mut candidate_sources = self.local_candidate_sources.write().await;
        let already_present = candidates.contains(&endpoint);
        if !already_present {
            candidates.insert(0, endpoint.clone());
        }
        candidate_sources.insert(endpoint.clone(), "peer_reflexive".to_string());
        truncate_signal_candidates(&mut candidates, &mut candidate_sources);

        if !already_present {
            info!(
                "Added relay-assisted peer-reflexive local UDP candidate {}",
                endpoint
            );
        }
    }

    async fn start_hole_punch(&self, node_id: &str) {
        self.start_hole_punch_at(node_id, None).await;
    }

    async fn start_hole_punch_at(&self, node_id: &str, punch_at_ms: Option<u64>) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!("UDP transport is not ready; skipping hole punch for {node_id}");
            return;
        };

        let Some(conn) = self.peers.get_connection(node_id).await else {
            debug!("No peer connection for {node_id}; skipping hole punch");
            return;
        };

        if !matches!(conn.state, ConnectionState::Direct | ConnectionState::Relay) {
            self.peers
                .update_state(node_id, ConnectionState::HolePunching)
                .await;
        }

        let peer_id = node_id.to_string();
        let peers = self.peers.clone();
        let attempts = peers
            .recommended_punch_attempts(self.config.network.punch_attempts)
            .await;
        spawn_hole_punch_task(
            udp,
            peers,
            self.punch_attempts.clone(),
            peer_id,
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
        )
        .await;
    }

    async fn handle_peer_offer(
        &mut self,
        from_node_id: &str,
        _candidates: &[String],
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
    ) -> Result<()> {
        let initiation = MessageInitiation::from_bytes(handshake_init)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard initiation: {e}")))?;
        let identity = self.local_identity()?;
        let mut responder = HandshakeResponder::new(identity, None);
        let (response, keys) = responder
            .consume_initiation_and_respond(&initiation)
            .map_err(|e| DaemonError::Peer(format!("WireGuard response failed: {e}")))?;

        if let Some(known_peer) = self.control.peers().await.get(from_node_id).cloned() {
            let expected_public = decode_x25519_key(&known_peer.public_key, "peer public key")?;
            if responder.initiator_public_key() != Some(&expected_public) {
                return Err(DaemonError::Peer(format!(
                    "WireGuard initiation public key mismatch for peer {from_node_id}"
                )));
            }
        }

        let response_bytes = response.to_bytes();
        let (candidates, candidate_sources) = self.wait_for_local_candidate_set().await;
        let previous_session = self
            .transport
            .replace_session(from_node_id.to_string(), TransportSession::new(keys))
            .await;
        if let Err(error) = self
            .control
            .send_peer_answer_with_sources_and_punch_schedule(
                from_node_id,
                &candidates,
                &candidate_sources,
                &response_bytes,
                // Echo the offer's server deadline so both peers use the
                // same rendezvous window. WebSocket-only peers have no
                // server deadline and retain the previous local fallback.
                punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms())),
                punch_at_server_ms,
            )
            .await
        {
            self.transport
                .restore_session(from_node_id, previous_session)
                .await;
            return Err(error);
        }
        if !self.peers.is_relay(from_node_id).await {
            self.peers
                .update_state(from_node_id, ConnectionState::Connecting)
                .await;
        }
        info!(
            "Installed WireGuard responder session for {from_node_id} and sent response ({} bytes, {} candidates)",
            response_bytes.len(),
            candidates.len()
        );
        self.peers
            .record_direct_event(
                from_node_id,
                "peer_answer_sent",
                None,
                Some(candidates.len()),
                None,
                format!("sent answer handshake_bytes={}", response_bytes.len()),
            )
            .await;
        Ok(())
    }

    async fn handle_peer_answer(
        &mut self,
        from_node_id: &str,
        handshake_response: &[u8],
    ) -> Result<()> {
        let response = MessageResponse::from_bytes(handshake_response)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard response: {e}")))?;
        let keys = {
            let mut state = self.pending_handshakes.lock().await;
            let Some(initiator) = state.pending.get_mut(from_node_id) else {
                warn!("No pending WireGuard handshake for answer from {from_node_id}");
                return Ok(());
            };

            let keys = match initiator.consume_response(&response) {
                Ok(keys) => keys,
                Err(err) => {
                    warn!(
                        "Ignoring WireGuard answer from {from_node_id} that does not match the pending handshake: {err}"
                    );
                    return Ok(());
                }
            };

            state.remove(from_node_id);
            state.attempts.remove(from_node_id);
            keys
        };

        // Replace old session with new one (rekey case).
        let new_session = TransportSession::new(keys);
        self.transport
            .add_session(from_node_id.to_string(), new_session)
            .await;
        if !self.peers.is_relay(from_node_id).await {
            self.peers
                .update_state(from_node_id, ConnectionState::Connecting)
                .await;
        }
        info!("Installed WireGuard initiator session for {from_node_id}");
        self.peers
            .record_direct_event(
                from_node_id,
                "peer_answer_applied",
                None,
                None,
                None,
                format!(
                    "installed initiator session from {} response bytes",
                    handshake_response.len()
                ),
            )
            .await;
        Ok(())
    }

    fn local_identity(&self) -> Result<NodeIdentity> {
        let private_key = decode_x25519_key(&self.config.node.private_key, "node private key")?;
        Ok(NodeIdentity::from_private_key(private_key))
    }

    /// Get a reference to the peer manager.
    pub fn peers(&self) -> &PeerManager {
        &self.peers
    }

    /// Get a reference to the port mapping manager.
    pub fn port_mappings(&self) -> &PortMappingManager {
        &self.port_mappings
    }

    /// Get a reference to the DNS resolver.
    pub fn dns(&self) -> &DnsResolver {
        &self.dns
    }

    /// Get the configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Check whether traffic is allowed by ACL.
    pub async fn check_acl(&self, src: &str, dst: &str, proto: &str, port: u16) -> bool {
        self.acl.read().await.check(src, dst, proto, port)
    }
}

fn advertised_udp_endpoint(
    local_addr: SocketAddr,
    configured: Option<&str>,
    candidates: &[String],
) -> Option<String> {
    if let Some(endpoint) = configured
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
    {
        return Some(endpoint.to_string());
    }

    if !local_addr.ip().is_unspecified() {
        return Some(local_addr.to_string());
    }

    candidates
        .iter()
        .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
        .find(|candidate| is_public_udp_candidate(*candidate))
        .or_else(|| {
            candidates
                .iter()
                .filter_map(|candidate| candidate.parse::<SocketAddr>().ok())
                .find(|candidate| !candidate.ip().is_unspecified() && !candidate.ip().is_loopback())
        })
        .map(|candidate| candidate.to_string())
}

fn candidate_endpoints_from_report(
    report: &CandidateGatherReport,
) -> (Vec<String>, HashMap<String, String>) {
    let mut endpoints = Vec::new();
    let mut sources = HashMap::new();
    for candidate in &report.candidates {
        let endpoint = candidate.endpoint.to_string();
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint.clone());
        }
        sources.insert(
            endpoint,
            candidate_source_label(candidate.source).to_string(),
        );
    }
    truncate_signal_candidates(&mut endpoints, &mut sources);
    (endpoints, sources)
}

fn truncate_signal_candidates(
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) {
    if candidates.len() > MAX_SIGNAL_CANDIDATES {
        warn!(
            "Truncating {} gathered UDP candidates to the signaling limit of {}",
            candidates.len(),
            MAX_SIGNAL_CANDIDATES
        );
        candidates.truncate(MAX_SIGNAL_CANDIDATES);
    }
    let retained = candidates.iter().cloned().collect::<HashSet<_>>();
    candidate_sources.retain(|endpoint, _| retained.contains(endpoint));
}

fn candidate_source_label(source: CandidateSource) -> &'static str {
    match source {
        CandidateSource::Host => "host",
        CandidateSource::StunObserved => "stun_observed",
        CandidateSource::Predicted => "predicted",
        CandidateSource::PeerReflexive => "peer_reflexive",
        CandidateSource::Manual => "manual",
        CandidateSource::Relay => "relay",
    }
}

fn preserve_peer_reflexive_candidates(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
) {
    for endpoint in previous_candidates.iter().rev() {
        if previous_candidate_sources.get(endpoint).map(String::as_str) != Some("peer_reflexive") {
            continue;
        }
        if endpoint.parse::<SocketAddr>().is_err() || candidates.contains(endpoint) {
            continue;
        }
        candidates.insert(0, endpoint.clone());
        candidate_sources.insert(endpoint.clone(), "peer_reflexive".to_string());
    }
}

fn candidate_refresh_requires_network_generation_advance(
    previous_candidates: &[String],
    previous_candidate_sources: &HashMap<String, String>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> bool {
    stable_network_candidate_signature(previous_candidates, previous_candidate_sources)
        != stable_network_candidate_signature(candidates, candidate_sources)
}

fn stable_network_candidate_signature(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> Vec<String> {
    let mut signature = Vec::new();
    for endpoint in candidates {
        let source = candidate_sources
            .get(endpoint)
            .map(String::as_str)
            .unwrap_or("signaled");
        match source {
            "host" | "manual" | "upnp" | "pcp" | "nat_pmp" => {
                signature.push(format!("{source}:{endpoint}"));
            }
            "stun_observed" | "predicted" => match endpoint.parse::<SocketAddr>() {
                Ok(addr) if is_public_udp_candidate(addr) => {
                    signature.push(format!("public-ip:{}", addr.ip()));
                }
                Ok(_) => {}
                Err(_) => signature.push(format!("{source}:{endpoint}")),
            },
            _ => {}
        }
    }
    signature.sort();
    signature.dedup();
    signature
}

fn is_public_udp_candidate(candidate: SocketAddr) -> bool {
    match candidate.ip() {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !is_shared_ipv4(ip)
        }
        IpAddr::V6(ip) => {
            !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && (ip.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PortMappingCandidate {
    endpoint: String,
    source: &'static str,
}

async fn maybe_add_port_mapping_udp_candidate(
    udp_local_addr: Option<SocketAddr>,
    candidates: &mut Vec<String>,
    candidate_sources: &mut HashMap<String, String>,
    runtime: Arc<RwLock<GatewayMappingRuntime>>,
    diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
) {
    let Some(local_addr) = port_mapping_local_addr(udp_local_addr, candidates, candidate_sources)
    else {
        let mut diagnostics = diagnostics.write().await;
        diagnostics.local_endpoint = None;
        diagnostics.upnp.status = "unavailable".to_string();
        diagnostics.upnp.last_error = Some("no LAN IPv4 UDP endpoint available".to_string());
        debug!("Skipping port-mapping UDP candidate because no LAN IPv4 local address was found");
        return;
    };

    let now = Instant::now();
    {
        let runtime = runtime.read().await;
        if runtime.retain_candidate(local_addr, now) {
            if let (Some(endpoint), Some(source)) = (
                runtime.candidate_endpoint.as_ref(),
                runtime.candidate_source,
            ) {
                if !candidates.contains(endpoint) {
                    candidates.insert(0, endpoint.clone());
                    candidate_sources.insert(endpoint.clone(), source.to_string());
                }
                let snapshot = runtime.snapshot(
                    true,
                    PORT_MAPPING_LEASE_SECS,
                    diagnostics.read().await.clone(),
                );
                *diagnostics.write().await = snapshot;
                return;
            }
        }
        if !runtime.needs_discovery(local_addr, now) {
            let snapshot = runtime.snapshot(
                true,
                PORT_MAPPING_LEASE_SECS,
                diagnostics.read().await.clone(),
            );
            *diagnostics.write().await = snapshot;
            return;
        }
    }

    match discover_port_mapping_udp_candidate(local_addr).await {
        GatewayMappingDiscovery {
            candidate: Some(candidate),
            upnp,
            pcp,
            nat_pmp,
        } => {
            let mut diagnostics_guard = diagnostics.write().await;
            record_method_result(&mut diagnostics_guard.upnp, upnp);
            if let Some(result) = pcp {
                record_method_result(&mut diagnostics_guard.pcp, result);
            }
            if let Some(result) = nat_pmp {
                record_method_result(&mut diagnostics_guard.nat_pmp, result);
            }
            if !candidates.contains(&candidate.endpoint) {
                info!(
                    "{} mapped UDP {local_addr} as {}",
                    candidate.source, candidate.endpoint
                );
                // A gateway-created mapping is usually more useful than another
                // host/predicted address and must survive the signaling cap.
                candidates.insert(0, candidate.endpoint.clone());
            }
            candidate_sources.insert(candidate.endpoint.clone(), candidate.source.to_string());
            drop(diagnostics_guard);
            {
                let mut runtime = runtime.write().await;
                runtime.record_success(
                    local_addr,
                    candidate.endpoint.clone(),
                    candidate.source,
                    Duration::from_secs(PORT_MAPPING_LEASE_SECS.into()),
                );
                let snapshot = runtime.snapshot(
                    true,
                    PORT_MAPPING_LEASE_SECS,
                    diagnostics.read().await.clone(),
                );
                *diagnostics.write().await = snapshot;
            }
        }
        GatewayMappingDiscovery {
            candidate: None,
            upnp,
            pcp,
            nat_pmp,
        } => {
            let mut diagnostics_guard = diagnostics.write().await;
            record_method_result(&mut diagnostics_guard.upnp, upnp);
            if let Some(result) = pcp {
                record_method_result(&mut diagnostics_guard.pcp, result);
            }
            if let Some(result) = nat_pmp {
                record_method_result(&mut diagnostics_guard.nat_pmp, result);
            }
            drop(diagnostics_guard);
            let mut runtime = runtime.write().await;
            runtime.record_failure(local_addr, PORT_MAPPING_FAILURE_RETRY);
            let snapshot = runtime.snapshot(
                true,
                PORT_MAPPING_LEASE_SECS,
                diagnostics.read().await.clone(),
            );
            *diagnostics.write().await = snapshot;
            debug!("No UPnP/PCP/NAT-PMP UDP mapping candidate discovered for {local_addr}");
        }
    }
}

struct GatewayMappingDiscovery {
    candidate: Option<PortMappingCandidate>,
    upnp: std::result::Result<(), String>,
    pcp: Option<std::result::Result<(), String>>,
    nat_pmp: Option<std::result::Result<(), String>>,
}

async fn discover_port_mapping_udp_candidate(local_addr: SocketAddr) -> GatewayMappingDiscovery {
    match discover_upnp_udp_candidate(local_addr).await {
        Ok(candidate) => GatewayMappingDiscovery {
            candidate: Some(candidate),
            upnp: Ok(()),
            pcp: None,
            nat_pmp: None,
        },
        Err(upnp) => {
            let (pcp, nat_pmp) = discover_pcp_or_nat_pmp_udp_candidate(local_addr).await;
            let candidate = pcp
                .as_ref()
                .ok()
                .cloned()
                .or_else(|| nat_pmp.as_ref().ok().cloned());
            GatewayMappingDiscovery {
                candidate,
                upnp: Err(upnp),
                pcp: Some(pcp.map(|_| ())),
                nat_pmp: Some(nat_pmp.map(|_| ())),
            }
        }
    }
}

async fn discover_upnp_udp_candidate(
    local_addr: SocketAddr,
) -> std::result::Result<PortMappingCandidate, String> {
    let options = SearchOptions {
        timeout: Some(UPNP_DISCOVERY_TIMEOUT),
        single_search_timeout: Some(UPNP_DISCOVERY_TIMEOUT),
        ..Default::default()
    };
    let gateway = match search_gateway(options).await {
        Ok(gateway) => gateway,
        Err(error) => {
            debug!("UPnP IGD gateway search failed: {error}");
            return Err(format!("gateway discovery failed: {error}"));
        }
    };

    let external_ip = match gateway.get_external_ip().await {
        Ok(ip) if is_public_udp_candidate(SocketAddr::new(ip, 1)) => ip,
        Ok(ip) => {
            debug!("UPnP IGD external IP {ip} is not publicly routable; skipping candidate");
            return Err(format!("gateway reported non-public external IP {ip}"));
        }
        Err(error) => {
            debug!("UPnP IGD external IP lookup failed: {error}");
            return Err(format!("external IP lookup failed: {error}"));
        }
    };

    if gateway
        .add_port(
            PortMappingProtocol::UDP,
            local_addr.port(),
            local_addr,
            PORT_MAPPING_LEASE_SECS,
            "p2wlan direct udp",
        )
        .await
        .is_ok()
    {
        return Ok(PortMappingCandidate {
            endpoint: SocketAddr::new(external_ip, local_addr.port()).to_string(),
            source: "upnp",
        });
    }

    match gateway
        .get_any_address(
            PortMappingProtocol::UDP,
            local_addr,
            PORT_MAPPING_LEASE_SECS,
            "p2wlan direct udp",
        )
        .await
    {
        Ok(endpoint) if is_public_udp_candidate(endpoint) => Ok(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "upnp",
        }),
        Ok(endpoint) => {
            debug!("UPnP IGD mapped to non-public endpoint {endpoint}; skipping candidate");
            Err(format!("gateway assigned non-public endpoint {endpoint}"))
        }
        Err(error) => {
            debug!("UPnP IGD UDP port mapping failed: {error}");
            Err(format!("UDP port mapping failed: {error}"))
        }
    }
}

async fn discover_pcp_or_nat_pmp_udp_candidate(
    local_addr: SocketAddr,
) -> (
    std::result::Result<PortMappingCandidate, String>,
    std::result::Result<PortMappingCandidate, String>,
) {
    let gateway = match default_ipv4_gateway().await {
        Some(gateway) => gateway,
        None => {
            debug!("No default IPv4 gateway found for PCP/NAT-PMP discovery");
            let error = "no default IPv4 gateway found".to_string();
            return (Err(error.clone()), Err(error));
        }
    };
    let Some(local_ip) = local_addr_ipv4(local_addr) else {
        let error = "no usable LAN IPv4 source address".to_string();
        return (Err(error.clone()), Err(error));
    };

    let pcp = discover_pcp_udp_candidate(local_ip, local_addr.port(), gateway);
    let nat_pmp = discover_nat_pmp_udp_candidate(local_ip, local_addr.port(), gateway);
    let (pcp, nat_pmp) = tokio::join!(pcp, nat_pmp);
    (pcp, nat_pmp)
}

async fn discover_nat_pmp_udp_candidate(
    local_ip: Ipv4Addr,
    local_port: u16,
    gateway: Ipv4Addr,
) -> std::result::Result<PortMappingCandidate, String> {
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), NAT_MAPPING_CONTROL_PORT);
    let bind_addr = SocketAddr::new(IpAddr::V4(local_ip), 0);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            debug!("NAT-PMP bind failed on {bind_addr}: {error}");
            return Err(format!("bind {bind_addr} failed: {error}"));
        }
    };

    let public_request = [0u8, 0u8];
    if let Err(error) = socket.send_to(&public_request, gateway_addr).await {
        return Err(format!("public address request send failed: {error}"));
    }
    let mut response = [0u8; 64];
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("NAT-PMP public address receive failed: {error}");
            return Err(format!("public address receive failed: {error}"));
        }
        Err(_) => return Err("public address request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!(
            "public address response came from unexpected {from}"
        ));
    }
    let external_ip = parse_nat_pmp_public_address_response(&response[..len])
        .ok_or_else(|| "invalid NAT-PMP public address response".to_string())?;

    let mut map_request = [0u8; 12];
    map_request[1] = 1; // Map UDP.
    map_request[4..6].copy_from_slice(&local_port.to_be_bytes());
    map_request[6..8].copy_from_slice(&local_port.to_be_bytes());
    map_request[8..12].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    if let Err(error) = socket.send_to(&map_request, gateway_addr).await {
        return Err(format!("UDP mapping request send failed: {error}"));
    }
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("NAT-PMP UDP mapping receive failed: {error}");
            return Err(format!("UDP mapping receive failed: {error}"));
        }
        Err(_) => return Err("UDP mapping request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!("UDP mapping response came from unexpected {from}"));
    }
    let external_port = parse_nat_pmp_mapping_response(&response[..len], local_port)
        .ok_or_else(|| "invalid NAT-PMP UDP mapping response".to_string())?;
    let endpoint = SocketAddr::new(IpAddr::V4(external_ip), external_port);
    is_public_udp_candidate(endpoint)
        .then_some(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "nat_pmp",
        })
        .ok_or_else(|| format!("gateway returned non-public endpoint {endpoint}"))
}

async fn discover_pcp_udp_candidate(
    local_ip: Ipv4Addr,
    local_port: u16,
    gateway: Ipv4Addr,
) -> std::result::Result<PortMappingCandidate, String> {
    let gateway_addr = SocketAddr::new(IpAddr::V4(gateway), NAT_MAPPING_CONTROL_PORT);
    let bind_addr = SocketAddr::new(IpAddr::V4(local_ip), 0);
    let socket = match UdpSocket::bind(bind_addr).await {
        Ok(socket) => socket,
        Err(error) => {
            debug!("PCP bind failed on {bind_addr}: {error}");
            return Err(format!("bind {bind_addr} failed: {error}"));
        }
    };

    let mut request = [0u8; 60];
    request[0] = 2; // PCP version.
    request[1] = 1; // MAP opcode.
    request[4..8].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
    request[8..24].copy_from_slice(&ipv4_mapped_octets(local_ip));
    rand::thread_rng().fill_bytes(&mut request[24..36]);
    request[36] = 17; // UDP.
    request[40..42].copy_from_slice(&local_port.to_be_bytes());
    request[42..44].copy_from_slice(&local_port.to_be_bytes());

    if let Err(error) = socket.send_to(&request, gateway_addr).await {
        return Err(format!("MAP request send failed: {error}"));
    }
    let mut response = [0u8; 128];
    let (len, from) = match timeout(
        NAT_MAPPING_DISCOVERY_TIMEOUT,
        socket.recv_from(&mut response),
    )
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            debug!("PCP UDP mapping receive failed: {error}");
            return Err(format!("MAP response receive failed: {error}"));
        }
        Err(_) => return Err("MAP request timed out".to_string()),
    };
    if from.ip() != IpAddr::V4(gateway) {
        return Err(format!("MAP response came from unexpected {from}"));
    }
    let endpoint = parse_pcp_mapping_response(&response[..len], local_port)
        .ok_or_else(|| "invalid PCP MAP response".to_string())?;
    is_public_udp_candidate(endpoint)
        .then_some(PortMappingCandidate {
            endpoint: endpoint.to_string(),
            source: "pcp",
        })
        .ok_or_else(|| format!("gateway returned non-public endpoint {endpoint}"))
}

fn parse_nat_pmp_public_address_response(response: &[u8]) -> Option<Ipv4Addr> {
    if response.len() < 12 || response[0] != 0 || response[1] != 128 {
        return None;
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        debug!("NAT-PMP public address request failed with result code {result}");
        return None;
    }
    Some(Ipv4Addr::new(
        response[8],
        response[9],
        response[10],
        response[11],
    ))
}

fn parse_nat_pmp_mapping_response(response: &[u8], expected_internal_port: u16) -> Option<u16> {
    if response.len() < 16 || response[0] != 0 || response[1] != 129 {
        return None;
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        debug!("NAT-PMP UDP mapping failed with result code {result}");
        return None;
    }
    let internal_port = u16::from_be_bytes([response[8], response[9]]);
    if internal_port != expected_internal_port {
        return None;
    }
    let external_port = u16::from_be_bytes([response[10], response[11]]);
    (external_port > 0).then_some(external_port)
}

fn parse_pcp_mapping_response(response: &[u8], expected_internal_port: u16) -> Option<SocketAddr> {
    if response.len() < 60 || response[0] != 2 || response[1] != 0x81 {
        return None;
    }
    let result = response[3];
    if result != 0 {
        debug!("PCP UDP mapping failed with result code {result}");
        return None;
    }
    if response[36] != 17 {
        return None;
    }
    let internal_port = u16::from_be_bytes([response[40], response[41]]);
    if internal_port != expected_internal_port {
        return None;
    }
    let external_port = u16::from_be_bytes([response[42], response[43]]);
    if external_port == 0 {
        return None;
    }
    let external_ip = parse_pcp_ip_address(&response[44..60])?;
    Some(SocketAddr::new(external_ip, external_port))
}

fn parse_pcp_ip_address(bytes: &[u8]) -> Option<IpAddr> {
    let bytes: [u8; 16] = bytes.try_into().ok()?;
    if bytes[..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
        return Some(IpAddr::V4(Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        )));
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

fn ipv4_mapped_octets(ip: Ipv4Addr) -> [u8; 16] {
    let mut octets = [0u8; 16];
    octets[10] = 0xff;
    octets[11] = 0xff;
    octets[12..16].copy_from_slice(&ip.octets());
    octets
}

async fn default_ipv4_gateway() -> Option<Ipv4Addr> {
    tokio::task::spawn_blocking(default_ipv4_gateway_blocking)
        .await
        .ok()
        .flatten()
}

fn default_ipv4_gateway_blocking() -> Option<Ipv4Addr> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    {
        let output = Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let output = Command::new("ip")
            .args(["route", "show", "default"])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(target_os = "windows")]
    {
        let output = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric,InterfaceMetric | Select-Object -First 1).NextHop",
            ])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        return parse_first_ipv4(&String::from_utf8_lossy(&output.stdout));
    }

    #[allow(unreachable_code)]
    None
}

fn parse_first_ipv4(text: &str) -> Option<Ipv4Addr> {
    text.split_whitespace().find_map(parse_ipv4_token)
}

fn parse_ipv4_token(token: &str) -> Option<Ipv4Addr> {
    token
        .trim_matches(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .parse()
        .ok()
}

fn port_mapping_local_addr(
    udp_local_addr: Option<SocketAddr>,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> Option<SocketAddr> {
    if udp_local_addr.is_some_and(is_port_mapping_local_addr) {
        return udp_local_addr;
    }

    candidates.iter().find_map(|candidate| {
        if candidate_sources.get(candidate).map(String::as_str) != Some("host") {
            return None;
        }
        let endpoint = candidate.parse::<SocketAddr>().ok()?;
        is_port_mapping_local_addr(endpoint).then_some(endpoint)
    })
}

fn is_port_mapping_local_addr(endpoint: SocketAddr) -> bool {
    endpoint.port() > 0
        && matches!(
            endpoint.ip(),
            IpAddr::V4(ip)
                if !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_link_local()
                    && !ip.is_broadcast()
        )
}

fn local_addr_ipv4(endpoint: SocketAddr) -> Option<Ipv4Addr> {
    match endpoint.ip() {
        IpAddr::V4(ip) if is_port_mapping_local_addr(endpoint) => Some(ip),
        _ => None,
    }
}

fn is_shared_ipv4(ip: std::net::Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

struct UdpCandidateRefreshContext {
    udp: UdpTransport,
    stun_servers: Vec<SocketAddr>,
    stun_timeout: Duration,
    udp_advertise: Option<String>,
    upnp_enabled: bool,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    gateway_mapping_runtime: Arc<RwLock<GatewayMappingRuntime>>,
    gateway_mapping_diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
    punch_deduplicator: PunchAttemptDeduplicator,
    control: ControlClient,
    peers: Arc<PeerManager>,
    probe_interval: Duration,
    punch_attempts: u32,
}

async fn run_udp_candidate_refresh(context: UdpCandidateRefreshContext) {
    let UdpCandidateRefreshContext {
        udp,
        stun_servers,
        stun_timeout,
        udp_advertise,
        upnp_enabled,
        local_candidates,
        local_candidate_sources,
        nat_profile,
        gateway_mapping_runtime,
        gateway_mapping_diagnostics,
        punch_deduplicator,
        control,
        peers,
        probe_interval,
        punch_attempts,
    } = context;
    let mut ticker = interval(CANDIDATE_REFRESH_INTERVAL);
    ticker.tick().await;

    loop {
        ticker.tick().await;

        let report = match udp
            .gather_candidate_report_live(stun_servers.clone(), stun_timeout)
            .await
        {
            Ok(report) => report,
            Err(err) => {
                warn!("Periodic UDP candidate refresh failed: {err}");
                continue;
            }
        };
        let (mut candidates, mut candidate_sources) = candidate_endpoints_from_report(&report);
        peers.update_nat_profile(report.nat_profile.clone()).await;
        let profile_changed = {
            let mut current_profile = nat_profile.write().await;
            if current_profile.as_ref() == Some(&report.nat_profile) {
                false
            } else {
                *current_profile = Some(report.nat_profile.clone());
                true
            }
        };

        let advertised_endpoint = udp.local_addr().ok().and_then(|local_addr| {
            advertised_udp_endpoint(local_addr, udp_advertise.as_deref(), &candidates)
        });
        if let Some(endpoint) = advertised_endpoint.as_ref() {
            if !candidates.contains(endpoint) {
                candidates.insert(0, endpoint.clone());
            }
            candidate_sources
                .entry(endpoint.clone())
                .or_insert_with(|| {
                    if udp_advertise.as_deref().is_some_and(|configured| {
                        !configured.trim().is_empty() && configured.trim() == endpoint
                    }) {
                        "manual".to_string()
                    } else {
                        "host".to_string()
                    }
                });
        }

        if upnp_enabled {
            maybe_add_port_mapping_udp_candidate(
                udp.local_addr().ok(),
                &mut candidates,
                &mut candidate_sources,
                gateway_mapping_runtime.clone(),
                gateway_mapping_diagnostics.clone(),
            )
            .await;
        }
        truncate_signal_candidates(&mut candidates, &mut candidate_sources);

        let previous_candidates = local_candidates.read().await.clone();
        let previous_candidate_sources = local_candidate_sources.read().await.clone();
        preserve_peer_reflexive_candidates(
            &previous_candidates,
            &previous_candidate_sources,
            &mut candidates,
            &mut candidate_sources,
        );
        truncate_signal_candidates(&mut candidates, &mut candidate_sources);
        let should_advance_generation = candidate_refresh_requires_network_generation_advance(
            &previous_candidates,
            &previous_candidate_sources,
            &candidates,
            &candidate_sources,
        );

        let changed = {
            let mut current = local_candidates.write().await;
            if previous_candidates == candidates && previous_candidate_sources == candidate_sources
            {
                false
            } else {
                *current = candidates.clone();
                *local_candidate_sources.write().await = candidate_sources.clone();
                true
            }
        };
        if !changed {
            if profile_changed {
                debug!(
                    "UDP NAT profile changed without advertised candidate endpoint changes: mapping={:?} public={:?}",
                    report.nat_profile.mapping_behavior,
                    report.nat_profile.public_endpoint
                );
            }
            continue;
        }

        info!(
            "UDP candidates changed after network update; refreshed {} candidates (mapping={:?}, public={:?})",
            candidates.len(),
            report.nat_profile.mapping_behavior,
            report.nat_profile.public_endpoint
        );
        if should_advance_generation {
            peers
                .advance_network_generation(format!(
                    "{REASON_NETWORK_GENERATION_CHANGED}: refreshed UDP candidates"
                ))
                .await;
        } else {
            debug!(
                "UDP candidate refresh changed only volatile reflexive ports; keeping network generation stable"
            );
        }
        let endpoint = advertised_endpoint.unwrap_or_default();
        if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
            warn!("Failed to publish refreshed UDP endpoint '{endpoint}': {err}");
        }

        publish_local_candidates_to_known_peers(
            &control,
            peers.clone(),
            udp.clone(),
            punch_deduplicator.clone(),
            &candidates,
            &candidate_sources,
            probe_interval,
            punch_attempts,
            "UDP candidate refresh",
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn publish_local_candidates_to_known_peers(
    control: &ControlClient,
    peers: Arc<PeerManager>,
    udp: UdpTransport,
    punch_deduplicator: PunchAttemptDeduplicator,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    probe_interval: Duration,
    attempts: u32,
    reason: &str,
) {
    if candidates.is_empty() {
        debug!("Skipping {reason} candidate publication because local candidate set is empty");
        return;
    }

    let attempts = peers.recommended_punch_attempts(attempts).await;

    for peer_id in control.peers().await.into_keys() {
        let punch_at_ms = Some(relay_assisted_punch_at_ms());
        if let Err(error) = control
            .send_peer_offer_with_sources_and_punch_at(
                &peer_id,
                candidates,
                candidate_sources,
                &[],
                punch_at_ms,
            )
            .await
        {
            warn!("Failed to publish {reason} UDP candidates to peer {peer_id}: {error}");
            continue;
        }

        debug!(
            "Published {reason} UDP candidates to peer {peer_id} with punch_at_ms={punch_at_ms:?}"
        );
        spawn_hole_punch_task(
            udp.clone(),
            peers.clone(),
            punch_deduplicator.clone(),
            peer_id,
            probe_interval,
            attempts,
            punch_at_ms,
        )
        .await;
    }
}

fn infer_default_relay_servers(control_server_url: &str) -> Vec<String> {
    if std::env::var("P2WLAN_DISABLE_DEFAULT_RELAY").as_deref() == Ok("1") {
        return Vec::new();
    }
    if let Ok(configured) = std::env::var("P2WLAN_DEFAULT_RELAY") {
        return configured
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    let Some(host) = control_server_host(control_server_url) else {
        return Vec::new();
    };
    let normalized = host.trim_matches(['[', ']']);
    if normalized.is_empty()
        || normalized.eq_ignore_ascii_case("localhost")
        || normalized.eq_ignore_ascii_case("ctrl.test")
        || normalized.ends_with(".test")
        || normalized == "127.0.0.1"
        || normalized == "::1"
    {
        return Vec::new();
    }

    let endpoint = if host.starts_with('[') {
        format!("{host}:18081")
    } else if host.contains(':') {
        format!("[{host}]:18081")
    } else {
        format!("{host}:18081")
    };
    vec![format!("default@tcp://{endpoint}")]
}

fn effective_relay_allow_insecure_plaintext(
    control_server_url: &str,
    relay_catalog: &[RelayCatalogEntry],
    relay_servers: &[String],
    configured: bool,
) -> bool {
    configured
        || (relay_catalog.is_empty()
            && control_server_uses_plaintext_http(control_server_url)
            && relay_servers
                .iter()
                .any(|server| relay_spec_is_plaintext(server)))
}

fn control_server_uses_plaintext_http(control_server_url: &str) -> bool {
    control_server_url
        .trim_start()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
}

fn relay_spec_is_plaintext(spec: &str) -> bool {
    let endpoint = spec
        .trim()
        .split_once('@')
        .map(|(_, endpoint)| endpoint)
        .unwrap_or_else(|| spec.trim())
        .trim();
    !endpoint.is_empty()
        && !endpoint
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tls://"))
}

fn control_server_host(control_server_url: &str) -> Option<String> {
    let trimmed = control_server_url.trim();
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next()?.split('@').next_back()?;
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_string());
    }
    authority
        .split(':')
        .next()
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToString::to_string)
}

fn relay_candidates_from_sources(
    relay_catalog: &[RelayCatalogEntry],
    relay_servers: &[String],
) -> Vec<RelayCandidateConfig> {
    if !relay_catalog.is_empty() {
        return relay_catalog
            .iter()
            .map(|entry| {
                RelayCandidateConfig::catalog(
                    entry.region.clone(),
                    entry.audience.clone(),
                    entry.endpoint.clone(),
                )
            })
            .collect();
    }

    relay_servers
        .iter()
        .cloned()
        .map(RelayCandidateConfig::legacy)
        .collect()
}

struct RelaySupervisor {
    relay_candidates: Vec<RelayCandidateConfig>,
    preferred_regions: Vec<String>,
    selection_timeout: Duration,
    node_id: String,
    peers: Arc<PeerManager>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    inbound_tx: mpsc::Sender<transport::ReceivedEncryptedPacket>,
    // A2 fields
    ticket_cache: Option<Arc<RelayTicketCache>>,
    relay_ticket: Option<String>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
}

impl RelaySupervisor {
    async fn run(self) {
        let mut retry_delay = Duration::from_secs(1);
        let max_retry_delay = Duration::from_secs(30);
        let mut cooldowns: HashMap<String, Instant> = HashMap::new();

        loop {
            let now = Instant::now();
            cooldowns.retain(|_, until| *until > now);

            let RelaySelectionOutcome {
                transport,
                relay_rx,
                diagnostics,
            } = select_relay_with_cooldowns(
                &self.relay_candidates,
                &self.preferred_regions,
                self.selection_timeout,
                &self.node_id,
                self.peers.clone(),
                self.ticket_cache.clone(),
                self.relay_ticket.clone(),
                self.allow_insecure_plaintext,
                self.ca_cert_path.clone(),
                &cooldowns,
            )
            .await;
            let permanent_auth = diagnostics
                .candidates
                .iter()
                .any(|candidate| candidate.error_code.as_deref() == Some("permanent_auth"));
            let failure_summary = relay_failure_summary(&diagnostics);
            *self.relay_selection.write().await = diagnostics;

            if let (Some(relay), Some(relay_rx)) = (transport, relay_rx) {
                info!(
                    "Selected relay region {} at {} ({} ms connect latency)",
                    relay.region(),
                    relay.endpoint(),
                    relay.connect_latency_ms()
                );
                *self.relay_transport.write().await = Some(relay.clone());
                retry_delay = Duration::from_secs(1);

                let endpoint = relay.endpoint().to_string();
                let ended = relay
                    .run_inbound(
                        relay_rx,
                        self.inbound_tx.clone(),
                        Some(self.relay_selection.clone()),
                    )
                    .await;
                *self.relay_transport.write().await = None;
                let (peer_failure_code, peer_failure_reason) = match &ended {
                    Ok(()) => (
                        "relay_transport_closed",
                        format!("relay {endpoint} transport closed"),
                    ),
                    Err(error) => (
                        "relay_transport_failed",
                        format!("relay {endpoint} transport failed: {error}"),
                    ),
                };
                self.peers
                    .invalidate_relay_transport(&endpoint, peer_failure_code, peer_failure_reason)
                    .await;

                let should_cooldown = self.relay_candidates.len() > 1;
                let cooldown_ms = duration_millis(RELAY_RUNTIME_FAILURE_COOLDOWN);
                if should_cooldown {
                    cooldowns.insert(
                        endpoint.clone(),
                        Instant::now() + RELAY_RUNTIME_FAILURE_COOLDOWN,
                    );
                }

                let (reason, fallback_code) = match (ended, should_cooldown) {
                    (Ok(()), true) => (
                        format!(
                            "relay {endpoint} disconnected; cooling down for {cooldown_ms} ms before reselection"
                        ),
                        "runtime_disconnected",
                    ),
                    (Ok(()), false) => (
                        format!("relay {endpoint} disconnected; reconnecting"),
                        "runtime_disconnected",
                    ),
                    (Err(error), true) => (
                        format!(
                            "relay {endpoint} failed: {error}; cooling down for {cooldown_ms} ms before reselection"
                        ),
                        "runtime_failed",
                    ),
                    (Err(error), false) => (
                        format!("relay {endpoint} failed: {error}; reconnecting"),
                        "runtime_failed",
                    ),
                };

                let mut diagnostics = self.relay_selection.write().await;
                diagnostics.last_error = Some(reason.clone());
                if diagnostics.last_error_code.is_none() {
                    diagnostics.last_error_code = Some(fallback_code.to_string());
                }
                if let Some(candidate) = diagnostics
                    .candidates
                    .iter_mut()
                    .find(|candidate| candidate.endpoint == endpoint)
                {
                    if should_cooldown {
                        candidate.cooldown_remaining_ms = Some(cooldown_ms);
                        candidate.error = Some(format!(
                            "relay runtime failure; cooling down for {cooldown_ms} ms"
                        ));
                    } else {
                        candidate.error = Some("relay runtime failure; reconnecting".to_string());
                    }
                    candidate.error_code = Some(fallback_code.to_string());
                }
                drop(diagnostics);
                warn!("{reason}");
            } else {
                *self.relay_transport.write().await = None;
                if permanent_auth {
                    retry_delay = max_retry_delay;
                }
                warn!(
                    "No configured relay candidate was reachable ({failure_summary}); retrying in {} seconds",
                    retry_delay.as_secs()
                );
            }

            sleep(retry_delay).await;
            retry_delay = retry_delay.saturating_mul(2).min(max_retry_delay);
        }
    }
}

fn relay_failure_summary(diagnostics: &RelaySelectionDiagnostics) -> String {
    if diagnostics.candidates.is_empty() {
        return diagnostics
            .last_error
            .clone()
            .unwrap_or_else(|| "no relay candidates configured".to_string());
    }

    diagnostics
        .candidates
        .iter()
        .find(|candidate| candidate.error.is_some() || candidate.error_code.is_some())
        .map(|candidate| {
            let code = candidate.error_code.as_deref().unwrap_or("unknown_error");
            let error = candidate.error.as_deref().unwrap_or("no detail");
            format!("{}: {code}: {error}", candidate.endpoint)
        })
        .or_else(|| diagnostics.last_error.clone())
        .unwrap_or_else(|| "no candidate failure detail".to_string())
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

async fn run_network_outbound(
    mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
) {
    while let Some(packet) = encrypted_rx.recv().await {
        let relay = relay_transport.read().await.clone();
        let relay_available = relay.is_some();
        let selection = peers
            .select_path_for_data(&packet.peer_id, prefer_direct, relay_available)
            .await;
        debug!(
            "Path selection for peer {}: path={:?} relay_hedged={} reason_code={} reason={}",
            packet.peer_id,
            selection.path,
            selection.relay_hedged,
            selection.reason_code,
            selection.reason
        );

        let sent_direct = if selection.path == Some(NetworkPath::Direct) {
            match (
                udp_transport.read().await.clone(),
                selection.direct_endpoint,
            ) {
                (Some(udp), Some(endpoint)) => match udp.send_packet_to(&packet, endpoint).await {
                    Ok(_) => true,
                    Err(err) => {
                        warn!(
                            "Direct UDP send failed for peer {}; trying relay fallback: {err}",
                            packet.peer_id
                        );
                        peers
                            .record_direct_failure_with_code(
                                &packet.peer_id,
                                REASON_DIRECT_SEND_FAILED,
                                err.to_string(),
                            )
                            .await;
                        false
                    }
                },
                (None, _) => {
                    peers
                        .record_direct_failure_with_code(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            "UDP transport unavailable for encrypted packet",
                        )
                        .await;
                    false
                }
                (_, None) => {
                    peers
                        .record_direct_failure_with_code(
                            &packet.peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            "path selector chose direct without an endpoint",
                        )
                        .await;
                    false
                }
            }
        } else {
            false
        };

        if sent_direct && selection.direct_confirmed && !selection.relay_hedged {
            continue;
        }

        if let Some(relay) = relay {
            if let Err(err) = relay.send_packet(&packet).await {
                warn!(
                    "Relay fallback send failed for peer {}: {err}",
                    packet.peer_id
                );
            }
        } else if !sent_direct {
            debug!(
                "Encrypted packet for peer {} has no selected path: {} ({})",
                packet.peer_id, selection.reason, selection.reason_code
            );
        }
    }
}

fn direct_probe_ack_grace(probe_interval: Duration) -> Duration {
    probe_interval
        .saturating_mul(2)
        .clamp(Duration::from_secs(1), Duration::from_secs(2))
}

fn unix_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn relay_assisted_punch_at_ms() -> u64 {
    unix_time_millis().saturating_add(RELAY_ASSISTED_PUNCH_DELAY.as_millis() as u64)
}

fn relay_assisted_punch_delay(punch_at_ms: Option<u64>) -> Duration {
    let Some(punch_at_ms) = punch_at_ms else {
        return Duration::ZERO;
    };
    let now = unix_time_millis();
    if punch_at_ms > now {
        return Duration::from_millis(punch_at_ms - now).saturating_sub(RELAY_ASSISTED_PUNCH_LEAD);
    }
    let stale_by = Duration::from_millis(now - punch_at_ms);
    if stale_by > RELAY_ASSISTED_PUNCH_STALE_AFTER {
        debug!(
            "Relay-assisted punch window is stale by {}ms; punching immediately",
            stale_by.as_millis()
        );
    }
    Duration::ZERO
}

async fn spawn_hole_punch_task(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    peer_id: String,
    probe_interval: Duration,
    attempts: u32,
    punch_at_ms: Option<u64>,
) {
    if !punch_deduplicator.claim(&peer_id).await {
        peers
            .record_direct_event(
                &peer_id,
                "punch_suppressed",
                None,
                None,
                None,
                "suppressed overlapping UDP punch session for this peer",
            )
            .await;
        debug!("Suppressing overlapping UDP punch session for {peer_id}");
        return;
    }
    let punch_delay = relay_assisted_punch_delay(punch_at_ms);
    if !punch_delay.is_zero() {
        debug!(
            "Scheduling relay-assisted UDP punch to peer {peer_id} in {}ms",
            punch_delay.as_millis()
        );
    }

    tokio::spawn(async move {
        peers
            .record_direct_event(
                &peer_id,
                "punch_scheduled",
                None,
                None,
                None,
                format!(
                    "scheduled relay-assisted UDP punch delay_ms={} punch_at_ms={punch_at_ms:?}",
                    punch_delay.as_millis()
                ),
            )
            .await;
        if !punch_delay.is_zero() {
            sleep(punch_delay).await;
        }

        let generation = peers.current_network_generation().await;
        let candidates = peers.direct_probe_targets_for(&peer_id).await;
        if candidates.is_empty() {
            debug!("No UDP candidates for {peer_id}; skipping hole punch");
            peers
                .record_direct_failure_for_generation(
                    &peer_id,
                    generation,
                    REASON_DIRECT_PROBE_FAILED,
                    "no UDP candidates for hole punching",
                )
                .await;
            return;
        }
        peers
            .record_direct_event(
                &peer_id,
                "punch_started",
                candidates.first().copied(),
                Some(candidates.len()),
                None,
                format!(
                    "starting synchronized UDP punch across {} candidates",
                    candidates.len()
                ),
            )
            .await;

        let success_count_before = peers
            .direct_probe_success_count_for_generation(&peer_id, generation)
            .await;

        match udp
            .punch_candidates(&peer_id, candidates.clone(), probe_interval, attempts)
            .await
        {
            Ok(sent) => {
                info!("Sent {sent} UDP punch probes to peer {peer_id}");
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_probes_sent",
                        candidates.first().copied(),
                        Some(candidates.len()),
                        Some(sent),
                        format!(
                            "sent {sent} UDP punch probes across {} candidates",
                            candidates.len()
                        ),
                    )
                    .await;
                sleep(direct_probe_ack_grace(probe_interval)).await;
                let success_count_after = peers
                    .direct_probe_success_count_for_generation(&peer_id, generation)
                    .await;
                if sent > 0 && success_count_after == success_count_before {
                    peers
                        .record_direct_event(
                            &peer_id,
                            "punch_ack_timeout",
                            candidates.first().copied(),
                            Some(candidates.len()),
                            Some(sent),
                            format!("no UDP punch ACK after {sent} probes"),
                        )
                        .await;
                    peers
                        .record_direct_failure_for_generation(
                            &peer_id,
                            generation,
                            REASON_DIRECT_PROBE_FAILED,
                            format!("no UDP punch ACK after {sent} probes"),
                        )
                        .await;
                }
            }
            Err(err) => {
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_send_error",
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        format!("hole punch failed: {err}"),
                    )
                    .await;
                peers
                    .record_direct_failure_for_generation(
                        &peer_id,
                        generation,
                        REASON_DIRECT_PROBE_FAILED,
                        format!("hole punch failed: {err}"),
                    )
                    .await;
                warn!("Failed to punch peer {peer_id}: {err}");
            }
        }
    });
}

async fn run_peer_reflexive_signal_loop(
    mut rx: mpsc::Receiver<PeerReflexiveObservation>,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
) {
    while let Some(observation) = rx.recv().await {
        let validation_observation = observation.clone();
        let validation_udp = udp.clone();
        let validation_peers = peers.clone();
        let validation_transport = transport.clone();
        let validation_local_ip = local_virtual_ip.clone();
        tokio::spawn(async move {
            run_direct_encrypted_validation(
                validation_observation,
                validation_udp,
                validation_peers,
                validation_transport,
                &validation_local_ip,
            )
            .await;
        });

        let control = control.clone();
        tokio::spawn(async move {
            let observed_endpoint = observation.observed_endpoint.to_string();
            for delay in PEER_REFLEXIVE_SIGNAL_DELAYS {
                if !delay.is_zero() {
                    sleep(delay).await;
                }
                let punch_at_ms = Some(relay_assisted_punch_at_ms());
                match control
                    .send_peer_reflexive(&observation.peer_id, &observed_endpoint, punch_at_ms)
                    .await
                {
                    Ok(()) => debug!(
                        "Relayed peer-reflexive observation to {}: {} punch_at_ms={punch_at_ms:?}",
                        observation.peer_id, observed_endpoint
                    ),
                    Err(err) => warn!(
                        "Failed to relay peer-reflexive observation to {} at {}: {err}",
                        observation.peer_id, observed_endpoint
                    ),
                }
            }
        });
    }
}

async fn run_direct_encrypted_validation(
    observation: PeerReflexiveObservation,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: &str,
) {
    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; local virtual IP '{}' is not IPv4",
            observation.peer_id, local_virtual_ip
        );
        return;
    };
    let Some(connection) = peers.get_connection(&observation.peer_id).await else {
        return;
    };
    let Ok(peer_ip) = connection.virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; peer virtual IP '{}' is not IPv4",
            observation.peer_id, connection.virtual_ip
        );
        return;
    };

    let generation = peers.current_network_generation().await;
    peers
        .record_direct_event(
            &observation.peer_id,
            "encrypted_trial_started",
            Some(observation.observed_endpoint),
            None,
            None,
            "starting bounded WireGuard validation on authenticated UDP endpoint",
        )
        .await;

    let validation_id = unix_time_millis() as u16;
    let mut sent = 0u32;
    for (sequence, delay) in DIRECT_ENCRYPTED_VALIDATION_DELAYS.into_iter().enumerate() {
        if !delay.is_zero() {
            sleep(delay).await;
        }
        if peers
            .is_direct_for_generation(&observation.peer_id, generation)
            .await
        {
            break;
        }

        let packet = Ipv4Packet::build_icmp_echo_request(
            local_ip,
            peer_ip,
            validation_id,
            sequence as u16,
            DIRECT_ENCRYPTED_VALIDATION_PAYLOAD,
        );
        let encrypted = match transport
            .encrypt_outbound(OutboundPacket {
                peer_id: observation.peer_id.clone(),
                dst_ip: connection.virtual_ip.clone(),
                packet,
            })
            .await
        {
            Ok(Some(encrypted)) => encrypted,
            Ok(None) => {
                debug!(
                    "Skipping encrypted Direct validation for {}; WireGuard session is not ready",
                    observation.peer_id
                );
                return;
            }
            Err(err) => {
                warn!(
                    "Failed to encrypt Direct validation packet for {}: {err}",
                    observation.peer_id
                );
                return;
            }
        };

        match udp
            .send_packet_to(&encrypted, observation.observed_endpoint)
            .await
        {
            Ok(_) => sent = sent.saturating_add(1),
            Err(err) => {
                warn!(
                    "Failed to send encrypted Direct validation to {} at {}: {err}",
                    observation.peer_id, observation.observed_endpoint
                );
                break;
            }
        }
    }

    peers
        .record_direct_event(
            &observation.peer_id,
            "encrypted_trial_sent",
            Some(observation.observed_endpoint),
            None,
            Some(sent),
            format!("sent {sent} bounded WireGuard validation packets"),
        )
        .await;
}

async fn run_direct_probe_loop(
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    punch_deduplicator: PunchAttemptDeduplicator,
    retry_after: Duration,
    probe_interval: Duration,
    attempts: u32,
) {
    if retry_after.is_zero() || attempts == 0 {
        return;
    }

    let mut ticker = interval(retry_after);
    loop {
        ticker.tick().await;

        let Some(udp) = udp_transport.read().await.clone() else {
            continue;
        };

        for (peer_id, candidates) in peers.direct_probe_targets_due(retry_after).await {
            if !punch_deduplicator.claim(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "retry_punch_suppressed",
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        "suppressed overlapping UDP retry session for this peer",
                    )
                    .await;
                continue;
            }
            let udp = udp.clone();
            let peers = peers.clone();
            let attempts = peers.recommended_punch_attempts(attempts).await;
            let generation = peers.current_network_generation().await;
            tokio::spawn(async move {
                let success_count_before = peers
                    .direct_probe_success_count_for_generation(&peer_id, generation)
                    .await;
                peers
                    .record_direct_event(
                        &peer_id,
                        "retry_punch_started",
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        format!(
                            "starting background UDP retry across {} candidates",
                            candidates.len()
                        ),
                    )
                    .await;
                match udp
                    .punch_candidates(&peer_id, candidates.clone(), probe_interval, attempts)
                    .await
                {
                    Ok(0) => {}
                    Ok(sent) => {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "retry_probes_sent",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                format!("sent {sent} background retry probes"),
                            )
                            .await;
                        sleep(direct_probe_ack_grace(probe_interval)).await;
                        let success_count_after = peers
                            .direct_probe_success_count_for_generation(&peer_id, generation)
                            .await;
                        if success_count_after == success_count_before {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "retry_ack_timeout",
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    Some(sent),
                                    format!("no direct probe ACK after {sent} retry probes"),
                                )
                                .await;
                            peers
                                .record_direct_failure_for_generation(
                                    &peer_id,
                                    generation,
                                    REASON_DIRECT_PROBE_FAILED,
                                    format!("no direct probe ACK after {sent} retry probes"),
                                )
                                .await;
                            debug!("Direct UDP retry probes for peer {peer_id} received no ACK");
                        } else {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    "retry_probe_succeeded",
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    Some(sent),
                                    "background UDP retry received an ACK; awaiting encrypted validation",
                                )
                                .await;
                            debug!(
                                "Direct UDP retry probes reached peer {peer_id}; awaiting encrypted validation"
                            );
                        }
                    }
                    Err(err) => {
                        peers
                            .record_direct_event(
                                &peer_id,
                                "retry_send_error",
                                candidates.first().copied(),
                                Some(candidates.len()),
                                None,
                                format!("direct retry failed: {err}"),
                            )
                            .await;
                        peers
                            .record_direct_failure_for_generation(
                                &peer_id,
                                generation,
                                REASON_DIRECT_PROBE_FAILED,
                                format!("direct retry failed: {err}"),
                            )
                            .await;
                        warn!("Failed to retry direct UDP probes for peer {peer_id}: {err}");
                    }
                }
            });
        }
    }
}

async fn log_inbound_packets_without_tun(mut inbound_rx: mpsc::Receiver<InboundPacket>) {
    while let Some(packet) = inbound_rx.recv().await {
        debug!(
            "Dropping {} decrypted inbound bytes from peer {} because TUN is disabled",
            packet.packet.len(),
            packet.peer_id
        );
    }
}

fn decode_x25519_key(hex_value: &str, label: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_value.trim())
        .map_err(|e| DaemonError::Config(format!("invalid {label} hex: {e}")))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        DaemonError::Config(format!(
            "invalid {label} length: expected 32 bytes, got {} bytes",
            bytes.len()
        ))
    })
}

async fn parse_stun_servers(
    values: &[String],
    resolve_timeout: Duration,
) -> Result<Vec<SocketAddr>> {
    let using_defaults = values.is_empty();
    let specs: Vec<String> = if using_defaults {
        DEFAULT_STUN_SERVERS
            .iter()
            .map(|value| (*value).to_string())
            .collect()
    } else {
        values
            .iter()
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect()
    };

    if specs
        .iter()
        .all(|value| is_stun_clear_value(value.as_str()))
    {
        return Ok(Vec::new());
    }

    let mut resolved = Vec::new();
    for spec in specs {
        if is_stun_clear_value(&spec) {
            continue;
        }
        if let Ok(addr) = spec.parse::<SocketAddr>() {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
            continue;
        }

        let addrs = match tokio::time::timeout(resolve_timeout, lookup_host(&spec)).await {
            Ok(Ok(addrs)) => addrs,
            Err(_) if using_defaults => {
                warn!(
                    "Default STUN server {spec} resolution timed out after {} ms",
                    resolve_timeout.as_millis()
                );
                continue;
            }
            Err(_) => {
                return Err(DaemonError::Config(format!(
                    "STUN server '{spec}' resolution timed out after {} ms",
                    resolve_timeout.as_millis()
                )));
            }
            Ok(Err(err)) if using_defaults => {
                warn!("Default STUN server {spec} could not be resolved: {err}");
                continue;
            }
            Ok(Err(err)) => {
                return Err(DaemonError::Config(format!(
                    "invalid or unresolved STUN server '{spec}': {err}"
                )));
            }
        };
        for addr in addrs {
            if !resolved.contains(&addr) {
                resolved.push(addr);
            }
        }
    }

    Ok(resolved)
}

fn is_stun_clear_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "none" | "off" | "false" | "clear" | "unset" | "disable" | "disabled"
    )
}

// ============================================================
// Drop, helpers, and Tests
// ============================================================

impl Drop for Daemon {
    fn drop(&mut self) {
        info!("Daemon cleanup: removing routes...");
        self.route_manager.cleanup();
    }
}

fn cidr_to_netmask(cidr: &str) -> Option<String> {
    let (_, prefix_str) = cidr.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let mask_u32 = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };
    let mask = std::net::Ipv4Addr::from(mask_u32);
    Some(mask.to_string())
}

fn is_ip_in_cidr(ip_str: &str, cidr: &str) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(net_ip) = net_str.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let Ok(prefix) = prefix_str.parse::<u32>() else {
        return false;
    };
    if prefix > 32 {
        return false;
    }

    let ip_u32 = u32::from(ip);
    let net_u32 = u32::from(net_ip);

    let mask = if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    };

    (ip_u32 & mask) == (net_u32 & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2pnet_relay::{Frame, RelayMessage, RelayServer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    #[test]
    fn test_daemon_creation() {
        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let _daemon = Daemon::new(config);
    }

    #[test]
    fn test_daemon_creation_manual_mode() {
        let mut config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
        config.network.manual = true;
        config.control.auth_token = "present-but-ignored".to_string();
        // Must not attempt control-plane registration even with a token.
        let _daemon = Daemon::new(config);
    }

    #[tokio::test]
    async fn punch_attempt_deduplicator_allows_only_one_short_window_per_peer() {
        let deduplicator = PunchAttemptDeduplicator::default();
        assert!(deduplicator.claim("peer-a").await);
        assert!(!deduplicator.claim("peer-a").await);
        assert!(deduplicator.claim("peer-b").await);
    }

    #[test]
    fn relay_assisted_punch_starts_slightly_before_advertised_time() {
        let punch_at_ms = unix_time_millis() + RELAY_ASSISTED_PUNCH_DELAY.as_millis() as u64;

        let delay = relay_assisted_punch_delay(Some(punch_at_ms));

        assert!(delay <= RELAY_ASSISTED_PUNCH_DELAY - RELAY_ASSISTED_PUNCH_LEAD);
        assert!(
            delay
                >= RELAY_ASSISTED_PUNCH_DELAY
                    - RELAY_ASSISTED_PUNCH_LEAD
                    - Duration::from_millis(50)
        );
    }

    #[tokio::test]
    async fn encrypted_direct_validation_uses_observed_endpoint_and_wireguard_session() {
        let local_identity = NodeIdentity::generate();
        let remote_identity = NodeIdentity::generate();
        let mut initiator =
            HandshakeInitiator::new(local_identity, remote_identity.public_key(), None);
        let initiation = initiator.create_initiation().unwrap();
        let mut responder = HandshakeResponder::new(remote_identity, None);
        let (response, remote_keys) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();
        let local_keys = initiator.consume_response(&response).unwrap();

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let remote_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let observed_endpoint = remote_socket.local_addr().unwrap();
        peers
            .add_peer(&control::PeerInfo {
                node_id: "node-b".to_string(),
                device_name: String::new(),
                public_key: hex::encode(responder.initiator_public_key().unwrap()),
                endpoint: observed_endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport
            .add_session("node-b", TransportSession::new(local_keys))
            .await;

        run_direct_encrypted_validation(
            PeerReflexiveObservation {
                peer_id: "node-b".to_string(),
                observed_endpoint,
            },
            udp,
            peers.clone(),
            transport,
            "10.20.0.1",
        )
        .await;

        let mut datagram = vec![0u8; 2048];
        let (len, _) = tokio::time::timeout(
            Duration::from_secs(1),
            remote_socket.recv_from(&mut datagram),
        )
        .await
        .unwrap()
        .unwrap();
        let mut remote_session = TransportSession::new(remote_keys);
        let decrypted = remote_session.decrypt_from_bytes(&datagram[..len]).unwrap();
        let packet = Ipv4Packet::new(&decrypted).unwrap();
        assert_eq!(packet.src_addr(), Ipv4Addr::new(10, 20, 0, 1));
        assert_eq!(packet.dst_addr(), Ipv4Addr::new(10, 20, 0, 2));
        assert!(packet
            .payload()
            .ends_with(DIRECT_ENCRYPTED_VALIDATION_PAYLOAD));

        let diagnostics = peers.diagnostics().await;
        assert!(diagnostics[0]
            .direct_events
            .iter()
            .any(|event| event.stage == "encrypted_trial_sent" && event.sent_probes == Some(3)));
    }

    #[test]
    fn test_advertised_udp_endpoint_uses_configured_value() {
        let local = "0.0.0.0:51820".parse().unwrap();
        assert_eq!(
            advertised_udp_endpoint(local, Some("203.0.113.10:51820"), &[]),
            Some("203.0.113.10:51820".to_string())
        );
    }

    #[test]
    fn test_advertised_udp_endpoint_uses_public_candidate_for_unspecified_bind() {
        let local = "0.0.0.0:51820".parse().unwrap();
        assert_eq!(
            advertised_udp_endpoint(
                local,
                None,
                &[
                    "192.168.1.10:51820".to_string(),
                    "74.125.250.129:43000".to_string()
                ]
            ),
            Some("74.125.250.129:43000".to_string())
        );
    }

    #[test]
    fn test_advertised_udp_endpoint_uses_specific_bind_address() {
        let local = "127.0.0.1:51820".parse().unwrap();
        assert_eq!(
            advertised_udp_endpoint(local, None, &[]),
            Some("127.0.0.1:51820".to_string())
        );
    }

    #[test]
    fn signal_candidate_cap_keeps_priority_prefix_and_source_map_aligned() {
        let mut candidates = (1..=MAX_SIGNAL_CANDIDATES + 3)
            .map(|index| format!("192.0.2.{index}:51820"))
            .collect::<Vec<_>>();
        let mapped = "198.51.100.10:42000".to_string();
        candidates.insert(0, mapped.clone());
        let mut sources = candidates
            .iter()
            .cloned()
            .map(|endpoint| (endpoint, "host".to_string()))
            .collect::<HashMap<_, _>>();
        sources.insert(mapped.clone(), "upnp".to_string());

        truncate_signal_candidates(&mut candidates, &mut sources);

        assert_eq!(candidates.len(), MAX_SIGNAL_CANDIDATES);
        assert_eq!(candidates[0], mapped);
        assert_eq!(sources.len(), MAX_SIGNAL_CANDIDATES);
        assert!(sources.keys().all(|endpoint| candidates.contains(endpoint)));
        assert_eq!(sources.get(&mapped).map(String::as_str), Some("upnp"));
    }

    #[test]
    fn candidate_refresh_generation_ignores_stun_port_churn_on_same_public_ip() {
        let previous = vec![
            "192.168.1.10:59288".to_string(),
            "93.184.216.34:27106".to_string(),
        ];
        let previous_sources = HashMap::from([
            ("192.168.1.10:59288".to_string(), "host".to_string()),
            (
                "93.184.216.34:27106".to_string(),
                "stun_observed".to_string(),
            ),
        ]);
        let next = vec![
            "192.168.1.10:59288".to_string(),
            "93.184.216.34:31999".to_string(),
        ];
        let next_sources = HashMap::from([
            ("192.168.1.10:59288".to_string(), "host".to_string()),
            (
                "93.184.216.34:31999".to_string(),
                "stun_observed".to_string(),
            ),
        ]);

        assert!(!candidate_refresh_requires_network_generation_advance(
            &previous,
            &previous_sources,
            &next,
            &next_sources,
        ));
    }

    #[test]
    fn candidate_refresh_generation_advances_on_host_or_public_ip_change() {
        let previous = vec![
            "192.168.1.10:59288".to_string(),
            "93.184.216.34:27106".to_string(),
        ];
        let previous_sources = HashMap::from([
            ("192.168.1.10:59288".to_string(), "host".to_string()),
            (
                "93.184.216.34:27106".to_string(),
                "stun_observed".to_string(),
            ),
        ]);
        let host_changed = vec![
            "192.168.2.10:59288".to_string(),
            "93.184.216.34:27106".to_string(),
        ];
        let host_changed_sources = HashMap::from([
            ("192.168.2.10:59288".to_string(), "host".to_string()),
            (
                "93.184.216.34:27106".to_string(),
                "stun_observed".to_string(),
            ),
        ]);
        let public_ip_changed = vec![
            "192.168.1.10:59288".to_string(),
            "93.184.216.35:27106".to_string(),
        ];
        let public_ip_changed_sources = HashMap::from([
            ("192.168.1.10:59288".to_string(), "host".to_string()),
            (
                "93.184.216.35:27106".to_string(),
                "stun_observed".to_string(),
            ),
        ]);

        assert!(candidate_refresh_requires_network_generation_advance(
            &previous,
            &previous_sources,
            &host_changed,
            &host_changed_sources,
        ));
        assert!(candidate_refresh_requires_network_generation_advance(
            &previous,
            &previous_sources,
            &public_ip_changed,
            &public_ip_changed_sources,
        ));
    }

    #[test]
    fn preserve_peer_reflexive_candidates_keeps_observed_endpoint_across_refresh() {
        let previous = vec![
            "93.184.216.34:27106".to_string(),
            "93.184.216.34:45000".to_string(),
        ];
        let previous_sources = HashMap::from([
            (
                "93.184.216.34:27106".to_string(),
                "stun_observed".to_string(),
            ),
            (
                "93.184.216.34:45000".to_string(),
                "peer_reflexive".to_string(),
            ),
        ]);
        let mut next = vec!["93.184.216.34:31999".to_string()];
        let mut next_sources = HashMap::from([(
            "93.184.216.34:31999".to_string(),
            "stun_observed".to_string(),
        )]);

        preserve_peer_reflexive_candidates(
            &previous,
            &previous_sources,
            &mut next,
            &mut next_sources,
        );

        assert_eq!(next[0], "93.184.216.34:45000");
        assert_eq!(
            next_sources.get("93.184.216.34:45000").map(String::as_str),
            Some("peer_reflexive")
        );
    }

    #[test]
    fn nat_pmp_response_parsers_accept_valid_udp_mapping() {
        let public = [0, 128, 0, 0, 0, 0, 0, 1, 93, 184, 216, 34];
        assert_eq!(
            parse_nat_pmp_public_address_response(&public),
            Some(Ipv4Addr::new(93, 184, 216, 34))
        );

        let mut mapping = [0u8; 16];
        mapping[0] = 0;
        mapping[1] = 129;
        mapping[8..10].copy_from_slice(&51820u16.to_be_bytes());
        mapping[10..12].copy_from_slice(&42000u16.to_be_bytes());
        mapping[12..16].copy_from_slice(&PORT_MAPPING_LEASE_SECS.to_be_bytes());
        assert_eq!(parse_nat_pmp_mapping_response(&mapping, 51820), Some(42000));
        assert_eq!(parse_nat_pmp_mapping_response(&mapping, 51821), None);
    }

    #[test]
    fn pcp_response_parser_accepts_ipv4_mapped_udp_mapping() {
        let mut response = [0u8; 60];
        response[0] = 2;
        response[1] = 0x81;
        response[36] = 17;
        response[40..42].copy_from_slice(&51820u16.to_be_bytes());
        response[42..44].copy_from_slice(&42000u16.to_be_bytes());
        response[44..60].copy_from_slice(&ipv4_mapped_octets(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(
            parse_pcp_mapping_response(&response, 51820),
            Some("93.184.216.34:42000".parse().unwrap())
        );
        assert_eq!(parse_pcp_mapping_response(&response, 51821), None);
    }

    #[test]
    fn default_gateway_parsers_extract_ipv4_addresses() {
        assert_eq!(
            parse_first_ipv4("default via 192.168.1.1 dev en0"),
            Some(Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(
            parse_first_ipv4("gateway: 10.0.0.1\ninterface: en0"),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_infer_default_relay_servers_from_public_control_host() {
        assert_eq!(
            infer_default_relay_servers("http://47.109.40.237:18080"),
            vec!["default@tcp://47.109.40.237:18081".to_string()]
        );
        assert_eq!(
            infer_default_relay_servers("https://relay.example.com/api"),
            vec!["default@tcp://relay.example.com:18081".to_string()]
        );
        assert_eq!(
            infer_default_relay_servers("http://[2001:db8::1]:18080"),
            vec!["default@tcp://[2001:db8::1]:18081".to_string()]
        );
    }

    #[test]
    fn test_effective_relay_plaintext_policy_for_legacy_http_control() {
        let legacy_servers = vec!["default@tcp://47.109.40.237:18081".to_string()];
        assert!(effective_relay_allow_insecure_plaintext(
            "http://47.109.40.237:18080",
            &[],
            &legacy_servers,
            false,
        ));
        assert!(effective_relay_allow_insecure_plaintext(
            "https://ctrl.example.com",
            &[],
            &legacy_servers,
            true,
        ));
        assert!(!effective_relay_allow_insecure_plaintext(
            "https://ctrl.example.com",
            &[],
            &legacy_servers,
            false,
        ));

        let catalog = vec![RelayCatalogEntry {
            region: "cn".to_string(),
            audience: "relay-cn-1".to_string(),
            endpoint: "tls://relay.example.com:18081".to_string(),
        }];
        assert!(!effective_relay_allow_insecure_plaintext(
            "http://47.109.40.237:18080",
            &catalog,
            &legacy_servers,
            false,
        ));
    }

    #[test]
    fn test_relay_spec_plaintext_detection() {
        assert!(relay_spec_is_plaintext("default@47.109.40.237:18081"));
        assert!(relay_spec_is_plaintext("default@tcp://47.109.40.237:18081"));
        assert!(!relay_spec_is_plaintext("cn@tls://relay.example.com:18081"));
    }

    #[test]
    fn relay_catalog_takes_precedence_over_legacy_servers() {
        let catalog = vec![RelayCatalogEntry {
            region: "sg".to_string(),
            audience: "relay-sg-1".to_string(),
            endpoint: "tls://relay.example.com:18081".to_string(),
        }];
        let legacy = vec!["default@127.0.0.1:18081".to_string()];

        let candidates = relay_candidates_from_sources(&catalog, &legacy);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].region, "sg");
        assert_eq!(candidates[0].audience.as_deref(), Some("relay-sg-1"));
        assert_eq!(candidates[0].endpoint, "tls://relay.example.com:18081");
    }

    #[test]
    fn legacy_relay_servers_are_used_without_catalog() {
        let legacy = vec!["west@127.0.0.1:18081".to_string()];

        let candidates = relay_candidates_from_sources(&[], &legacy);

        assert_eq!(candidates.len(), 1);
        assert!(candidates[0].audience.is_none());
        assert_eq!(candidates[0].endpoint, "west@127.0.0.1:18081");
    }

    async fn wait_for_relay_endpoint(
        relay_transport: Arc<RwLock<Option<RelayTransport>>>,
        expected_endpoint: &str,
    ) {
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                let matches = relay_transport
                    .read()
                    .await
                    .as_ref()
                    .is_some_and(|relay| relay.endpoint() == expected_endpoint);
                if matches {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("expected relay endpoint was not published");
    }

    async fn accept_relay_registration(listener: &TcpListener, node_id: &str) -> TcpStream {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).await.unwrap();
        let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;
        let mut payload = vec![0u8; payload_len];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&header[..4], b"DERP");
        assert_eq!(header[5], p2pnet_relay::protocol::MSG_REGISTER);
        assert_eq!(payload, node_id.as_bytes());
        stream
            .write_all(&Frame::registered(node_id).encode())
            .await
            .unwrap();
        stream
    }

    #[tokio::test]
    async fn relay_supervisor_reconnects_after_stream_closes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let (reconnected_tx, mut reconnected_rx) = mpsc::channel(1);
        let server = tokio::spawn(async move {
            let first = accept_relay_registration(&listener, "node-a").await;
            drop(first);

            let _second = accept_relay_registration(&listener, "node-a").await;
            reconnected_tx.send(()).await.unwrap();
            std::future::pending::<()>().await;
        });

        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let peers = Arc::new(PeerManager::new(config));
        let relay_transport = Arc::new(RwLock::new(None));
        let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
        let (inbound_tx, _inbound_rx) = mpsc::channel(4);
        let supervisor = tokio::spawn(
            RelaySupervisor {
                relay_candidates: vec![RelayCandidateConfig::legacy(endpoint)],
                preferred_regions: Vec::new(),
                selection_timeout: Duration::from_millis(500),
                node_id: "node-a".to_string(),
                peers,
                relay_transport: relay_transport.clone(),
                relay_selection: relay_selection.clone(),
                inbound_tx,
                ticket_cache: None,
                relay_ticket: None,
                allow_insecure_plaintext: true, // test
                ca_cert_path: None,
            }
            .run(),
        );

        tokio::time::timeout(Duration::from_secs(4), reconnected_rx.recv())
            .await
            .expect("relay supervisor did not reconnect")
            .expect("relay test server stopped");
        tokio::time::timeout(Duration::from_secs(1), async {
            while relay_transport.read().await.is_none() {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("reconnected relay was not published");
        assert!(relay_selection.read().await.last_error.is_none());

        supervisor.abort();
        server.abort();
    }

    #[tokio::test]
    async fn relay_supervisor_fails_over_to_standby_after_runtime_disconnect() {
        let primary = RelayServer::start_random().await.unwrap();
        let standby = RelayServer::start_random().await.unwrap();
        let primary_endpoint = primary.addr.to_string();
        let standby_endpoint = standby.addr.to_string();

        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let peers = Arc::new(PeerManager::new(config));
        let relay_transport = Arc::new(RwLock::new(None));
        let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
        let (inbound_tx, _inbound_rx) = mpsc::channel(4);
        let supervisor = tokio::spawn(
            RelaySupervisor {
                relay_candidates: vec![
                    RelayCandidateConfig::legacy(format!("primary@{primary_endpoint}")),
                    RelayCandidateConfig::legacy(format!("standby@{standby_endpoint}")),
                ],
                preferred_regions: vec!["primary".to_string()],
                selection_timeout: Duration::from_millis(500),
                node_id: "node-a".to_string(),
                peers,
                relay_transport: relay_transport.clone(),
                relay_selection: relay_selection.clone(),
                inbound_tx,
                ticket_cache: None,
                relay_ticket: None,
                allow_insecure_plaintext: true,
                ca_cert_path: None,
            }
            .run(),
        );

        wait_for_relay_endpoint(relay_transport.clone(), &primary_endpoint).await;
        primary.shutdown().await;
        wait_for_relay_endpoint(relay_transport, &standby_endpoint).await;

        let diagnostics = relay_selection.read().await.clone();
        assert_eq!(
            diagnostics.selected_endpoint.as_deref(),
            Some(standby_endpoint.as_str())
        );
        let primary_candidate = diagnostics
            .candidates
            .iter()
            .find(|candidate| candidate.endpoint == primary_endpoint)
            .expect("primary relay candidate should remain in diagnostics");
        assert_eq!(
            primary_candidate.error_code.as_deref(),
            Some("cooling_down")
        );
        assert!(primary_candidate.cooldown_remaining_ms.is_some());

        supervisor.abort();
        standby.shutdown().await;
    }

    #[test]
    fn test_infer_default_relay_servers_skips_local_and_test_hosts() {
        assert!(infer_default_relay_servers("http://127.0.0.1:18080").is_empty());
        assert!(infer_default_relay_servers("http://localhost:18080").is_empty());
        assert!(infer_default_relay_servers("https://ctrl.test").is_empty());
    }

    #[tokio::test]
    async fn test_parse_stun_servers() {
        let servers = parse_stun_servers(
            &["127.0.0.1:3478".to_string(), " 10.0.0.1:3478 ".to_string()],
            Duration::from_millis(100),
        )
        .await
        .unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], "127.0.0.1:3478".parse().unwrap());
        assert_eq!(servers[1], "10.0.0.1:3478".parse().unwrap());
    }

    #[tokio::test]
    async fn test_parse_stun_servers_resolves_hostname() {
        let servers = parse_stun_servers(&["localhost:3478".to_string()], Duration::from_secs(1))
            .await
            .unwrap();
        assert!(servers
            .iter()
            .any(|server| server.ip().is_loopback() && server.port() == 3478));
    }

    #[tokio::test]
    async fn test_parse_stun_servers_can_be_disabled() {
        assert!(
            parse_stun_servers(&["off".to_string()], Duration::from_millis(100))
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_parse_stun_servers_rejects_invalid_endpoint() {
        let err = parse_stun_servers(&["not-a-socket".to_string()], Duration::from_millis(100))
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid or unresolved STUN server"));
    }

    #[tokio::test]
    async fn stale_wireguard_answer_does_not_clear_pending_handshake() {
        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let mut daemon = Daemon::new(config);
        let peer_id = "peer-stale-answer";

        let peer_identity = NodeIdentity::generate();
        let mut initiator = HandshakeInitiator::new(
            daemon.local_identity().unwrap(),
            peer_identity.public_key(),
            None,
        );
        let initiation = initiator.create_initiation().unwrap();

        {
            let mut state = daemon.pending_handshakes.lock().await;
            state.insert(peer_id.to_string(), initiator);
            state.attempts.insert(peer_id.to_string(), 1);
        }

        let mut responder = HandshakeResponder::new(peer_identity, None);
        let (mut stale_response, _) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();
        stale_response.receiver_index ^= 0x1111_0001;

        daemon
            .handle_peer_answer(peer_id, &stale_response.to_bytes())
            .await
            .unwrap();

        let state = daemon.pending_handshakes.lock().await;
        assert!(state.pending.contains_key(peer_id));
        assert_eq!(state.attempts.get(peer_id), Some(&1));
    }

    #[test]
    fn handshake_start_reservation_prevents_concurrent_initiators() {
        let mut state = PendingHandshakeState::default();
        let peer_id = "peer-race";

        assert!(state.reserve_start(peer_id));
        assert!(state.starting.contains(peer_id));
        assert!(
            !state.reserve_start(peer_id),
            "a second trigger must not start an initiator while the first gathers candidates"
        );

        state.cancel_reservation(peer_id);
        assert!(state.reserve_start(peer_id));
    }

    #[tokio::test]
    async fn test_network_outbound_uses_relay_when_udp_unavailable() {
        let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
        let relay_endpoint = server.addr.to_string();

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&control::PeerInfo {
                node_id: "node-b".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: String::new(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;

        let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
            .await
            .unwrap();
        let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
            .await
            .unwrap();

        let udp_transport = Arc::new(RwLock::new(None));
        let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
        let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
        let worker = tokio::spawn(run_network_outbound(
            encrypted_rx,
            peers,
            true,
            udp_transport,
            relay_transport,
        ));

        let payload = vec![4, 9, 8, 7, 6];
        encrypted_tx
            .send(EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .unwrap()
            .unwrap();
        if let RelayMessage::Data { from_node, data } = received {
            assert_eq!(from_node, "node-a");
            assert_eq!(data, payload);
        } else {
            panic!("Expected Data message, got {:?}", received);
        }

        worker.abort();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_network_outbound_uses_relay_until_direct_is_verified() {
        let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
        let relay_endpoint = server.addr.to_string();
        let direct_sink = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let direct_endpoint = direct_sink.local_addr().unwrap();

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&control::PeerInfo {
                node_id: "node-b".to_string(),
                device_name: String::new(),
                public_key: "pk".to_string(),
                endpoint: direct_endpoint.to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;

        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers.clone())
            .await
            .unwrap();
        let (_relay_b, mut rx_b) = p2pnet_relay::RelayClient::connect(&relay_endpoint, "node-b")
            .await
            .unwrap();

        let udp_transport = Arc::new(RwLock::new(Some(udp)));
        let relay_transport = Arc::new(RwLock::new(Some(relay_a)));
        let (encrypted_tx, encrypted_rx) = mpsc::channel(4);
        let worker = tokio::spawn(run_network_outbound(
            encrypted_rx,
            peers.clone(),
            true,
            udp_transport,
            relay_transport,
        ));

        let payload = vec![9, 8, 7, 6, 5];
        encrypted_tx
            .send(EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await
            .unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .unwrap()
            .unwrap();
        if let RelayMessage::Data { from_node, data } = received {
            assert_eq!(from_node, "node-a");
            assert_eq!(data, payload);
        } else {
            panic!("Expected Data message, got {:?}", received);
        }

        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), direct_sink.recv_from(&mut buf))
                .await
                .is_err()
        );

        let conn = peers.get_connection("node-b").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.active_path(), None);
        assert_eq!(conn.relay_server, Some(relay_endpoint));
        let selection = peers.select_path_for_data("node-b", true, true).await;
        assert_eq!(selection.path, Some(peer::NetworkPath::Relay));

        worker.abort();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_daemon_acl_check() {
        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let daemon = Daemon::new(config);

        // Default ACL allows everything
        assert!(daemon.check_acl("node1", "node2", "tcp", 80).await);
    }

    #[tokio::test]
    async fn test_daemon_dns() {
        let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.dns.enabled = true;
        let daemon = Daemon::new(config);

        daemon
            .dns()
            .register("test", "10.20.0.5", Some("node1"))
            .await;
        let ip = daemon.dns().resolve("test").await;
        assert_eq!(ip, Some("10.20.0.5".to_string()));
    }

    #[tokio::test]
    async fn test_daemon_port_mapping() {
        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let daemon = Daemon::new(config);

        let mapping =
            port_mapping::PortMapping::new(port_mapping::Protocol::Tcp, "127.0.0.1", 8080, 30000);
        daemon.port_mappings().create(mapping).await.unwrap();
        let list = daemon.port_mappings().list().await;
        assert_eq!(list.len(), 1);
    }
}
