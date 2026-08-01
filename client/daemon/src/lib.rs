//! # p2wlan-daemon
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
mod candidate_refresh;
pub mod config;
pub mod control;
pub mod dataplane;
pub mod diagnostics;
pub mod dns;
pub mod error;
pub mod gateway_mapping;
mod network_outbound;
pub mod peer;
pub mod port_mapping;
pub mod relay;
mod relay_runtime;
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
use p2pnet_crypto::{DhKeyPair, NodeIdentity};
use p2pnet_nat::{CandidateGatherReport, CandidateSource, MappingBehavior, NatProfile};
use rand::RngCore;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn};

use acl::AclEngine;
use candidate_refresh::{
    add_peer_reflexive_candidate_to_set, advertised_udp_endpoint, candidate_endpoints_from_report,
    control_udp_endpoint_from_candidates, maybe_add_port_mapping_udp_candidate,
    publish_local_candidates_to_known_peers, run_udp_candidate_refresh, truncate_signal_candidates,
    UdpCandidateRefreshContext,
};
#[cfg(test)]
use candidate_refresh::{
    candidate_refresh_requires_network_generation_advance,
    compact_volatile_public_signal_candidates, ipv4_mapped_octets, parse_first_ipv4,
    parse_nat_pmp_mapping_response, parse_nat_pmp_public_address_response,
    parse_pcp_mapping_response, preserve_peer_reflexive_candidates,
    should_update_stable_control_endpoint,
};
#[cfg(test)]
use control::RelayCatalogEntry;
use control::{ControlClient, ControlEvent};
use dataplane::{DataPlane, InboundPacket, OutboundPacket};
use diagnostics::{run_diagnostics_server_with_retry, DiagnosticsContext};
use dns::DnsResolver;
use gateway_mapping::{record_method_result, GatewayMappingDiagnostics, GatewayMappingRuntime};
use network_outbound::run_network_outbound;
use p2pnet_tun::{InterfaceConfig, Ipv4Packet, TunDevice, VirtualInterface};
use p2pnet_wireguard::{
    HandshakeInitiator, HandshakeResponder, MessageInitiation, MessageResponse, TransportSession,
};
use peer::{
    ConnectionState, PeerManager, DIRECT_RETRY_BASE_INTERVAL, REASON_DIRECT_PROBE_FAILED,
    REASON_HANDSHAKE_TIMEOUT,
};
use port_mapping::PortMappingManager;
#[cfg(test)]
use relay::RelayCandidateConfig;
use relay::{RelaySelectionDiagnostics, RelayTicketCache, RelayTransport};
use relay_runtime::{
    effective_relay_allow_insecure_plaintext, infer_default_relay_servers,
    relay_candidates_from_sources, run_relay_peer_validation_loop, udp_observers_from_sources,
    RelaySupervisor,
};
#[cfg(test)]
use relay_runtime::{relay_spec_is_plaintext, send_relay_validation_packet, RelayValidationPacket};
use transport::{EncryptedPeerPacket, WireGuardTransport};
use udp::{PeerReflexiveObservation, UdpTransport};

/// Shared pending-handshake state (timeout-safe).
#[derive(Default)]
struct PendingHandshakeState {
    pending: HashMap<String, HandshakeInitiator>,
    pending_session_ids: HashMap<String, String>,
    pending_probe_ephemeral: HashMap<String, DhKeyPair>,
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

    fn insert_reserved(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
    ) -> Option<u64> {
        if !self.starting.remove(&peer_id) {
            return None;
        }
        Some(self.insert(peer_id, initiator, session_id, probe_ephemeral))
    }

    fn insert(
        &mut self,
        peer_id: String,
        initiator: HandshakeInitiator,
        session_id: Option<String>,
        probe_ephemeral: Option<DhKeyPair>,
    ) -> u64 {
        self.next_id = self.next_id.saturating_add(1);
        let pending_id = self.next_id;
        self.pending.insert(peer_id.clone(), initiator);
        if let Some(session_id) = session_id {
            self.pending_session_ids.insert(peer_id.clone(), session_id);
        } else {
            self.pending_session_ids.remove(&peer_id);
        }
        if let Some(probe_ephemeral) = probe_ephemeral {
            self.pending_probe_ephemeral
                .insert(peer_id.clone(), probe_ephemeral);
        } else {
            self.pending_probe_ephemeral.remove(&peer_id);
        }
        self.pending_ids.insert(peer_id, pending_id);
        pending_id
    }

    fn remove(&mut self, peer_id: &str) -> Option<HandshakeInitiator> {
        self.pending_ids.remove(peer_id);
        self.pending_session_ids.remove(peer_id);
        self.pending_probe_ephemeral.remove(peer_id);
        self.pending.remove(peer_id)
    }

    fn session_id(&self, peer_id: &str) -> Option<&str> {
        self.pending_session_ids.get(peer_id).map(String::as_str)
    }

    fn probe_ephemeral(&self, peer_id: &str) -> Option<DhKeyPair> {
        self.pending_probe_ephemeral.get(peer_id).cloned()
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
///
/// Keep this large enough for a linear symmetric NAT to publish its observed
/// STUN group plus the full predicted successor run. Air-like NATs can need
/// the high-teens successor ports before a peer-reflexive path appears.
const MAX_SIGNAL_CANDIDATES: usize = 32;
/// A bounded public candidate group preserves ICE-style linear NAT coverage.
///
/// Air-like linear symmetric NATs need the STUN group plus a predicted run
/// that reaches the high-teens port jumps seen in relay-first/direct-chase ICE.
/// The overall signaling cap still prevents broad scanning.
const MAX_SIGNAL_VOLATILE_PUBLIC_PER_PUBLIC_IP: usize = MAX_SIGNAL_CANDIDATES;
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
const DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW: Duration = Duration::from_secs(1);

#[derive(Clone, Default)]
struct PunchAttemptDeduplicator {
    recent_starts: Arc<tokio::sync::Mutex<HashMap<String, PunchAttemptRecord>>>,
}

#[derive(Clone, Copy)]
struct PunchAttemptRecord {
    started_at: Instant,
    priority: u8,
}

impl PunchAttemptDeduplicator {
    async fn claim(&self, peer_id: &str) -> bool {
        self.claim_with_window_and_priority(peer_id, PUNCH_SESSION_DEDUP_WINDOW, 1)
            .await
    }

    async fn claim_with_window(&self, peer_id: &str, window: Duration) -> bool {
        self.claim_with_window_and_priority(peer_id, window, 0)
            .await
    }

    async fn claim_with_window_and_priority(
        &self,
        peer_id: &str,
        window: Duration,
        priority: u8,
    ) -> bool {
        let now = Instant::now();
        let mut starts = self.recent_starts.lock().await;
        starts.retain(|_, record| now.duration_since(record.started_at) < window);
        if let Some(record) = starts.get(peer_id) {
            if record.priority >= priority {
                return false;
            }
        }
        starts.insert(
            peer_id.to_string(),
            PunchAttemptRecord {
                started_at: now,
                priority,
            },
        );
        true
    }
}

fn should_cancel_maintenance_offer(
    is_rekey: bool,
    has_session: bool,
    needs_rekey: bool,
    expired: bool,
) -> bool {
    if is_rekey {
        has_session && !needs_rekey && !expired
    } else {
        has_session
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
        let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
        let (control, control_rx) = ControlClient::new(
            &config,
            control_enabled,
            config_path,
            Some(relay_selection.clone()),
        );
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
            relay_selection,
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
        info!("P2WLAN daemon v{} starting...", env!("CARGO_PKG_VERSION"));
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
        resolved_config.network.udp_observers =
            udp_observers_from_sources(&relay_catalog, &resolved_config.network.udp_observers);
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
        let mut stun_servers =
            parse_stun_servers(&self.config.network.stun_servers, stun_timeout).await?;
        let udp_observers = if self.config.network.udp_observers.is_empty() {
            Vec::new()
        } else {
            parse_stun_servers(&self.config.network.udp_observers, stun_timeout).await?
        };
        for observer in &udp_observers {
            if !stun_servers.contains(observer) {
                stun_servers.push(*observer);
            }
        }
        if stun_servers.is_empty() {
            info!("STUN/UDP-observer candidate gathering is disabled");
        } else if udp_observers.is_empty() {
            info!("Using STUN endpoints: {stun_servers:?}");
        } else {
            info!("Using STUN/UDP observer endpoints: stun_and_observers={stun_servers:?} observers={udp_observers:?}");
        }
        let configured_keepalive = Duration::from_secs(self.config.network.keepalive_interval_secs);
        let keepalive_interval = if configured_keepalive.is_zero() {
            Duration::ZERO
        } else {
            configured_keepalive.min(DIRECT_LIVENESS_INTERVAL_MAX)
        };
        let upnp_enabled = self.config.network.upnp_enabled;
        let socket_pool_enabled = self.config.network.socket_pool_enabled;
        let socket_pool_size = self.config.network.socket_pool_size;
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
                    self.local_candidates.clone(),
                    self.punch_attempts.clone(),
                    DIRECT_RETRY_BASE_INTERVAL,
                    punch_interval,
                    punch_attempts.clamp(1, 3),
                ),
            )
            .await;
        self.task_manager
            .spawn(
                "relay-peer-validation",
                false,
                run_relay_peer_validation_loop(
                    self.peers.clone(),
                    self.transport.clone(),
                    self.relay_transport.clone(),
                    virtual_ip.clone(),
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
                    if let Err(err) = run_diagnostics_server_with_retry(
                        diagnostics_bind,
                        diagnostics_context,
                        shutdown_rx,
                    )
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
                        let udp = if socket_pool_enabled {
                            match udp.clone().with_socket_pool(socket_pool_size).await {
                                Ok(udp) => udp,
                                Err(error) => {
                                    warn!(
                                        "Failed to create experimental UDP socket pool; using the primary socket only: {error}"
                                    );
                                    udp
                                }
                            }
                        } else {
                            udp
                        };
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
                                    let pool_eligible = socket_pool_enabled
                                        && report.nat_profile.mapping_behavior
                                            == MappingBehavior::AddressOrPortDependent
                                        && !report.nat_profile.udp_blocked;
                                    udp.set_socket_pool_active(pool_eligible);
                                    if udp.socket_count() > 1 {
                                        info!(
                                            "Experimental UDP socket pool: sockets={} active={} reason={}",
                                            udp.socket_count(),
                                            udp.socket_pool_active(),
                                            if pool_eligible {
                                                "address/port-dependent mapping"
                                            } else {
                                                "NAT profile did not qualify"
                                            }
                                        );
                                    }
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
                        let mut published_endpoint = None;
                        if let Some(endpoint) = control_udp_endpoint_from_candidates(
                            &candidate_endpoints,
                            &candidate_sources,
                        ) {
                            if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
                                warn!("Failed to queue UDP endpoint update '{endpoint}': {err}");
                            } else {
                                published_endpoint = Some(endpoint);
                            }
                        }

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
                                    published_endpoint,
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
                                    published_endpoint,
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
                            if !conn.online {
                                continue;
                            }
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
                                    "Session for peer {} expired; rekeying before dropping old session",
                                    conn.node_id
                                );
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
                            // candidates were being read. For normal retries, any session is
                            // enough to cancel. For rekeys, keep the old session alive and only
                            // cancel once it has been replaced by a session that no longer needs
                            // rekey. This avoids a brief no-session window that pushes traffic
                            // through relay during otherwise healthy Direct paths.
                            let current_has_session = transport.has_session(&conn.node_id).await;
                            let current_needs = if is_rekey && current_has_session {
                                transport.session_needs_rekey(&conn.node_id).await
                            } else {
                                false
                            };
                            let current_expired = if is_rekey && current_has_session {
                                transport.session_is_expired(&conn.node_id).await
                            } else {
                                false
                            };
                            if should_cancel_maintenance_offer(
                                is_rekey,
                                current_has_session,
                                current_needs,
                                current_expired,
                            ) {
                                pending.lock().await.cancel_reservation(&conn.node_id);
                                continue;
                            }

                            let session_id = new_probe_session_id();
                            let (probe_ephemeral, probe_ephemeral_public_key) =
                                new_probe_ephemeral_keypair();
                            let Some((attempt_no, pending_id)) = ({
                                let mut state = pending.lock().await;
                                state
                                    .insert_reserved(
                                        conn.node_id.clone(),
                                        initiator,
                                        Some(session_id.clone()),
                                        Some(probe_ephemeral),
                                    )
                                    .map(|pending_id| {
                                        let attempts =
                                            state.attempts.entry(conn.node_id.clone()).or_insert(0);
                                        *attempts = attempts.saturating_add(1);
                                        (*attempts, pending_id)
                                    })
                            }) else {
                                continue;
                            };
                            peers
                                .set_probe_session_id(&conn.node_id, Some(session_id.clone()))
                                .await;

                            let punch_at_ms = Some(relay_assisted_punch_at_ms());
                            if let Err(err) = control
                                .send_peer_offer_with_sources_punch_and_session(
                                    &conn.node_id,
                                    &candidates,
                                    &candidate_sources,
                                    &initiation_bytes,
                                    punch_at_ms,
                                    Some(session_id.clone()),
                                    Some(probe_ephemeral_public_key.clone()),
                                )
                                .await
                            {
                                warn!("Handshake offer to {} failed: {err}", conn.node_id);
                                let mut state = pending.lock().await;
                                if state.is_current(&conn.node_id, pending_id) {
                                    state.remove(&conn.node_id);
                                    peers.set_probe_session_id(&conn.node_id, None).await;
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

                    if peer_info.online {
                        let mut sent_handshake_offer = false;
                        match self.maybe_initiate_handshake(&peer_info).await {
                            Ok(punch_at_ms) => {
                                sent_handshake_offer = punch_at_ms.is_some();
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
                        if !sent_handshake_offer {
                            self.publish_current_candidates_to_peer(
                                &peer_info.node_id,
                                "peer joined",
                            )
                            .await;
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
                    } else {
                        debug!(
                            "Peer {} is currently offline; keeping it in diagnostics without starting traversal",
                            peer_info.node_id
                        );
                    }
                }

                ControlEvent::PeerUpdated(peer_info) => {
                    let previous = self.peers.get_connection(&peer_info.node_id).await;
                    let update = self.peers.add_peer(&peer_info).await;
                    if !peer_info.online {
                        self.transport.remove_session(&peer_info.node_id).await;
                        self.pending_handshakes
                            .lock()
                            .await
                            .clear_peer(&peer_info.node_id);
                        if self.dns.is_enabled() {
                            if let Some(previous) = previous.as_ref() {
                                self.dns.unregister(&previous.virtual_ip).await;
                            } else {
                                self.dns.unregister(&peer_info.virtual_ip).await;
                            }
                        }
                        debug!(
                            "Peer {} is offline according to control plane; cleared active sessions and skipped traversal",
                            peer_info.node_id
                        );
                        continue;
                    }
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
                    let was_offline = previous.as_ref().is_some_and(|peer| !peer.online);
                    if (update.virtual_ip_changed || was_offline) && self.dns.is_enabled() {
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
                    let mut sent_handshake_offer = false;
                    match self.maybe_initiate_handshake(&peer_info).await {
                        Ok(punch_at_ms) => {
                            sent_handshake_offer = punch_at_ms.is_some();
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
                    if !sent_handshake_offer {
                        self.publish_current_candidates_to_peer(
                            &peer_info.node_id,
                            "peer updated",
                        )
                        .await;
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
                    session_id,
                    probe_ephemeral_public_key,
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
                        .set_probe_session_id(&from_node_id, session_id.clone())
                        .await;
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
                                session_id.clone(),
                                probe_ephemeral_public_key.clone(),
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
                    session_id,
                    probe_ephemeral_public_key,
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
                            .handle_peer_answer(
                                &from_node_id,
                                &handshake_response,
                                session_id.clone(),
                                probe_ephemeral_public_key.clone(),
                            )
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
                    let local_candidate_changed = self
                        .add_local_peer_reflexive_candidate(&observed_endpoint)
                        .await;
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
                    if local_candidate_changed && !candidates.is_empty() {
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
                    } else if !local_candidate_changed {
                        self.peers
                            .record_direct_event(
                                &from_node_id,
                                "peer_reflexive_offer_skipped",
                                observed_endpoint.parse().ok(),
                                Some(candidates.len()),
                                None,
                                "peer-reflexive candidate already advertised; skipped full offer re-advertisement",
                            )
                            .await;
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
                ControlEvent::ControlHealthy => {
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

        let session_id = new_probe_session_id();
        let (probe_ephemeral, probe_ephemeral_public_key) = new_probe_ephemeral_keypair();
        let Some((attempt_no, pending_id)) = ({
            let mut state = self.pending_handshakes.lock().await;
            state
                .insert_reserved(
                    peer_id_clone.clone(),
                    initiator,
                    Some(session_id.clone()),
                    Some(probe_ephemeral),
                )
                .map(|pending_id| {
                    let attempts = state.attempts.entry(peer_id_clone.clone()).or_insert(0);
                    *attempts = attempts.saturating_add(1);
                    (*attempts, pending_id)
                })
        }) else {
            return Ok(None);
        };
        self.peers
            .set_probe_session_id(&peer_id_clone, Some(session_id.clone()))
            .await;

        let punch_at_ms = relay_assisted_punch_at_ms();
        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_punch_and_session(
                &peer_id_clone,
                &candidates,
                &candidate_sources,
                &initiation_bytes,
                Some(punch_at_ms),
                Some(session_id.clone()),
                Some(probe_ephemeral_public_key.clone()),
            )
            .await
        {
            let mut state = self.pending_handshakes.lock().await;
            if state.is_current(&peer_id_clone, pending_id) {
                state.remove(&peer_id_clone);
                self.peers.set_probe_session_id(&peer_id_clone, None).await;
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

    async fn add_local_peer_reflexive_candidate(&self, observed_endpoint: &str) -> bool {
        let mut candidates = self.local_candidates.write().await;
        let mut candidate_sources = self.local_candidate_sources.write().await;
        match add_peer_reflexive_candidate_to_set(
            observed_endpoint,
            &mut candidates,
            &mut candidate_sources,
        ) {
            Ok(true) => {
                info!(
                    "Updated relay-assisted peer-reflexive local UDP candidate {}",
                    observed_endpoint
                );
                true
            }
            Ok(false) => false,
            Err(err) => {
                warn!(
                    "Ignoring invalid relay-assisted peer-reflexive endpoint '{}': {err}",
                    observed_endpoint
                );
                false
            }
        }
    }

    async fn publish_current_candidates_to_peer(&self, node_id: &str, reason: &str) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!(
                "UDP transport is not ready; skipping {reason} candidate publication to {node_id}"
            );
            return;
        };
        let candidates = self.local_candidates.read().await.clone();
        if candidates.is_empty() {
            debug!("Local UDP candidates are not ready; skipping {reason} candidate publication to {node_id}");
            return;
        }
        let candidate_sources = self.local_candidate_sources.read().await.clone();
        let punch_at_ms = Some(relay_assisted_punch_at_ms());

        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_and_punch_at(
                node_id,
                &candidates,
                &candidate_sources,
                &[],
                punch_at_ms,
            )
            .await
        {
            warn!("Failed to publish {reason} UDP candidates to peer {node_id}: {error}");
            return;
        }

        info!(
            "Published {reason} UDP candidates to peer {node_id} ({} candidates) punch_at_ms={punch_at_ms:?}",
            candidates.len()
        );
        let attempts = self
            .peers
            .recommended_punch_attempts(self.config.network.punch_attempts)
            .await;
        spawn_hole_punch_task(
            udp,
            self.peers.clone(),
            self.punch_attempts.clone(),
            node_id.to_string(),
            Duration::from_millis(self.config.network.punch_interval_ms),
            attempts,
            punch_at_ms,
        )
        .await;
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

        if self.local_candidates.read().await.is_empty() {
            self.peers
                .record_direct_event(
                    node_id,
                    "punch_delayed_local_candidates_not_ready",
                    None,
                    Some(0),
                    None,
                    "delayed UDP punch until local candidates are ready",
                )
                .await;
            debug!("Local UDP candidates are not ready; delaying hole punch for {node_id}");
            return;
        }

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

    #[allow(clippy::too_many_arguments)]
    async fn handle_peer_offer(
        &mut self,
        from_node_id: &str,
        _candidates: &[String],
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
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

        let (response_probe_ephemeral_public_key, probe_ephemeral_shared) = match (
            session_id.as_ref(),
            probe_ephemeral_public_key.as_deref(),
        ) {
            (Some(_), Some(peer_probe_public_key)) => {
                let (local_probe_ephemeral, local_probe_public_key) = new_probe_ephemeral_keypair();
                match derive_probe_ephemeral_shared(&local_probe_ephemeral, peer_probe_public_key) {
                    Ok(shared) => (Some(local_probe_public_key), Some(shared)),
                    Err(err) => {
                        warn!(
                            "Ignoring malformed probe ephemeral public key from {from_node_id}: {err}"
                        );
                        (None, None)
                    }
                }
            }
            _ => (None, None),
        };

        if session_id.is_some() || probe_ephemeral_shared.is_some() {
            self.peers
                .set_probe_session_binding(from_node_id, session_id.clone(), probe_ephemeral_shared)
                .await;
        }

        let response_bytes = response.to_bytes();
        let (candidates, candidate_sources) = self.wait_for_local_candidate_set().await;
        let previous_session = self
            .transport
            .replace_session(from_node_id.to_string(), TransportSession::new(keys))
            .await;
        if let Err(error) = self
            .control
            .send_peer_answer_with_sources_schedule_and_session(
                from_node_id,
                &candidates,
                &candidate_sources,
                &response_bytes,
                // Echo the offer's server deadline so both peers use the
                // same rendezvous window. WebSocket-only peers have no
                // server deadline and retain the previous local fallback.
                punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms())),
                punch_at_server_ms,
                session_id.clone(),
                response_probe_ephemeral_public_key,
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
                format!(
                    "sent answer handshake_bytes={} session_id={}",
                    response_bytes.len(),
                    session_id.as_deref().unwrap_or("legacy")
                ),
            )
            .await;
        Ok(())
    }

    async fn handle_peer_answer(
        &mut self,
        from_node_id: &str,
        handshake_response: &[u8],
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        let response = MessageResponse::from_bytes(handshake_response)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard response: {e}")))?;
        let (keys, clear_session_binding, probe_ephemeral_shared) = {
            let mut state = self.pending_handshakes.lock().await;
            let expected_session_id = state.session_id(from_node_id).map(str::to_string);
            if let (Some(expected), Some(received)) =
                (expected_session_id.as_deref(), session_id.as_deref())
            {
                if expected != received {
                    warn!(
                        "Ignoring WireGuard answer from {from_node_id} with mismatched session_id"
                    );
                    return Ok(());
                }
            }

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

            let probe_ephemeral_shared = match (
                expected_session_id.as_ref(),
                state.probe_ephemeral(from_node_id),
                probe_ephemeral_public_key.as_deref(),
            ) {
                (Some(_), Some(local_probe_ephemeral), Some(peer_probe_public_key)) => {
                    match derive_probe_ephemeral_shared(
                        &local_probe_ephemeral,
                        peer_probe_public_key,
                    ) {
                        Ok(shared) => Some(shared),
                        Err(err) => {
                            warn!(
                                "Ignoring malformed probe ephemeral public key from {from_node_id}: {err}"
                            );
                            None
                        }
                    }
                }
                _ => None,
            };

            state.remove(from_node_id);
            state.attempts.remove(from_node_id);
            (
                keys,
                expected_session_id.is_some() && session_id.is_none(),
                probe_ephemeral_shared,
            )
        };

        if let Some(session_id) = session_id {
            self.peers
                .set_probe_session_binding(from_node_id, Some(session_id), probe_ephemeral_shared)
                .await;
        } else if clear_session_binding {
            self.peers.set_probe_session_id(from_node_id, None).await;
        }

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

fn new_probe_session_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn new_probe_ephemeral_keypair() -> (DhKeyPair, String) {
    let keypair = DhKeyPair::generate();
    let public_key_hex = hex::encode(keypair.public_key());
    (keypair, public_key_hex)
}

fn derive_probe_ephemeral_shared(
    local_keypair: &DhKeyPair,
    peer_public_key_hex: &str,
) -> Result<[u8; 32]> {
    let peer_public = decode_x25519_key(peer_public_key_hex, "probe ephemeral public key")?;
    local_keypair
        .diffie_hellman(&peer_public)
        .map_err(|e| DaemonError::Peer(format!("probe ephemeral X25519 failed: {e}")))
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
            if peers.is_direct(&peer_id).await {
                peers
                    .record_direct_event(
                        &peer_id,
                        "punch_skipped_already_direct",
                        None,
                        None,
                        None,
                        "skipped UDP punch because Direct path is already confirmed",
                    )
                    .await;
                debug!("Skipping UDP punch for {peer_id}; Direct path is already confirmed");
                return;
            }
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

    if peers
        .is_direct_for_generation(&observation.peer_id, generation)
        .await
    {
        peers
            .record_direct_event(
                &observation.peer_id,
                "encrypted_trial_skipped",
                Some(observation.observed_endpoint),
                None,
                Some(0),
                "skipped bounded WireGuard validation because Direct is already confirmed for this network generation",
            )
            .await;
        return;
    }

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
                peers
                    .record_direct_event(
                        &observation.peer_id,
                        "encrypted_trial_skipped",
                        Some(observation.observed_endpoint),
                        None,
                        Some(sent),
                        "skipped bounded WireGuard validation because WireGuard session is not ready",
                    )
                    .await;
                return;
            }
            Err(err) => {
                warn!(
                    "Failed to encrypt Direct validation packet for {}: {err}",
                    observation.peer_id
                );
                peers
                    .record_direct_event(
                        &observation.peer_id,
                        "encrypted_trial_failed",
                        Some(observation.observed_endpoint),
                        None,
                        Some(sent),
                        format!("failed to encrypt bounded WireGuard validation packet: {err}"),
                    )
                    .await;
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
    local_candidates: Arc<RwLock<Vec<String>>>,
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

        if local_candidates.read().await.is_empty() {
            debug!("Local UDP candidates are not ready; delaying background Direct probe cycle");
            continue;
        }

        for (peer_id, candidates) in peers.direct_probe_targets_due(retry_after).await {
            let reclaim_active = peers.direct_reclaim_active(&peer_id).await;
            let dedup_window = if reclaim_active {
                DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW
            } else {
                PUNCH_SESSION_DEDUP_WINDOW
            };
            if !punch_deduplicator
                .claim_with_window(&peer_id, dedup_window)
                .await
            {
                peers
                    .record_direct_event(
                        &peer_id,
                        if reclaim_active {
                            "direct_reclaim_punch_suppressed"
                        } else {
                            "retry_punch_suppressed"
                        },
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        if reclaim_active {
                            "suppressed overlapping UDP Direct reclaim session for this peer"
                        } else {
                            "suppressed overlapping UDP retry session for this peer"
                        },
                    )
                    .await;
                continue;
            }
            let udp = udp.clone();
            let peers = peers.clone();
            let attempts = peers.recommended_punch_attempts(attempts).await;
            let generation = peers.current_network_generation().await;
            tokio::spawn(async move {
                let punch_started_stage = if reclaim_active {
                    "direct_reclaim_punch_started"
                } else {
                    "retry_punch_started"
                };
                let probes_sent_stage = if reclaim_active {
                    "direct_reclaim_probes_sent"
                } else {
                    "retry_probes_sent"
                };
                let ack_timeout_stage = if reclaim_active {
                    "direct_reclaim_ack_timeout"
                } else {
                    "retry_ack_timeout"
                };
                let probe_succeeded_stage = if reclaim_active {
                    "direct_reclaim_probe_succeeded"
                } else {
                    "retry_probe_succeeded"
                };
                let send_error_stage = if reclaim_active {
                    "direct_reclaim_send_error"
                } else {
                    "retry_send_error"
                };
                let retry_label = if reclaim_active {
                    "generation-change Direct reclaim"
                } else {
                    "background UDP retry"
                };
                let success_count_before = peers
                    .direct_probe_success_count_for_generation(&peer_id, generation)
                    .await;
                peers
                    .record_direct_event(
                        &peer_id,
                        punch_started_stage,
                        candidates.first().copied(),
                        Some(candidates.len()),
                        None,
                        format!(
                            "starting {retry_label} across {} candidates",
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
                                probes_sent_stage,
                                candidates.first().copied(),
                                Some(candidates.len()),
                                Some(sent),
                                format!("sent {sent} {retry_label} probes"),
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
                                    ack_timeout_stage,
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    Some(sent),
                                    format!(
                                        "no direct probe ACK after {sent} {retry_label} probes"
                                    ),
                                )
                                .await;
                            peers
                                .record_direct_failure_for_generation(
                                    &peer_id,
                                    generation,
                                    REASON_DIRECT_PROBE_FAILED,
                                    format!(
                                        "no direct probe ACK after {sent} {retry_label} probes"
                                    ),
                                )
                                .await;
                            debug!("Direct UDP retry probes for peer {peer_id} received no ACK");
                        } else {
                            peers
                                .record_direct_event(
                                    &peer_id,
                                    probe_succeeded_stage,
                                    candidates.first().copied(),
                                    Some(candidates.len()),
                                    Some(sent),
                                    format!(
                                        "{retry_label} received an ACK; awaiting encrypted validation"
                                    ),
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
                                send_error_stage,
                                candidates.first().copied(),
                                Some(candidates.len()),
                                None,
                                format!("{retry_label} failed: {err}"),
                            )
                            .await;
                        peers
                            .record_direct_failure_for_generation(
                                &peer_id,
                                generation,
                                REASON_DIRECT_PROBE_FAILED,
                                format!("{retry_label} failed: {err}"),
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
#[path = "lib/tests.rs"]
mod tests;
