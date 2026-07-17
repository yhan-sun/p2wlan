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
pub mod peer;
pub mod port_mapping;
pub mod relay;
pub mod route;
pub mod tasks;
pub mod transport;
pub mod udp;

// Re-export key types
pub use config::Config;
pub use error::{DaemonError, Result};

// ============================================================
// Daemon
// ============================================================

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use p2pnet_crypto::NodeIdentity;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};

use acl::AclEngine;
use control::{ControlClient, ControlEvent};
use dataplane::{DataPlane, InboundPacket};
use diagnostics::{run_diagnostics_server, DiagnosticsContext};
use dns::DnsResolver;
use p2pnet_tun::{InterfaceConfig, TunDevice, VirtualInterface};
use p2pnet_wireguard::{
    HandshakeInitiator, HandshakeResponder, MessageInitiation, MessageResponse, TransportSession,
};
use peer::{ConnectionState, PeerManager};
use port_mapping::PortMappingManager;
use relay::{select_relay, RelaySelectionDiagnostics, RelaySelectionOutcome, RelayTransport};
use transport::{EncryptedPeerPacket, WireGuardTransport};
use udp::UdpTransport;

/// Shared pending-handshake state (timeout-safe).
#[derive(Default)]
struct PendingHandshakeState {
    pending: HashMap<String, HandshakeInitiator>,
    /// Number of initiation attempts per peer (bounded retries).
    attempts: HashMap<String, u32>,
}

/// Maximum number of handshake re-initiation attempts before giving up.
const MAX_HANDSHAKE_ATTEMPTS: u32 = 5;
/// Handshake timeout before pending entry is cleared.
const HANDSHAKE_TIMEOUT_SECS: u64 = 30;

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

                        control_event_registered = Some(ControlEvent::Registered {
                            node_id: Some(assigned_node_id.clone()),
                            virtual_ip: virtual_ip.clone(),
                            cidr: Some(cidr.clone()),
                            relay_servers: relay_servers.clone(),
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

        // Initialize TUN using the resolved IP details
        let tun = self.init_tun_with(&virtual_ip, &netmask, self.config.network.mtu)?;

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
        let stun_servers = parse_stun_servers(&self.config.network.stun_servers)?;
        let stun_timeout = Duration::from_millis(self.config.network.stun_timeout_ms);
        let keepalive_interval = Duration::from_secs(self.config.network.keepalive_interval_secs);
        let fallback_timeout = Duration::from_millis(self.config.relay.fallback_timeout_ms);
        let prefer_direct = self.config.relay.prefer_direct;

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
                    fallback_timeout,
                    Duration::from_millis(self.config.network.punch_interval_ms),
                    self.config.network.punch_attempts.clamp(1, 3),
                ),
            )
            .await;
        if self.config.diagnostics.enabled {
            let diagnostics_bind = self.config.diagnostics.bind.clone();
            let diagnostics_context = DiagnosticsContext::new(
                self.config.clone(),
                self.peers.clone(),
                self.udp_transport.clone(),
                self.relay_transport.clone(),
                self.relay_selection.clone(),
                self.health.clone(),
                self.task_manager.clone(),
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
            let (mut dataplane, outbound_rx, inbound_tx) = DataPlane::new_bidirectional(tun, peers);

            let outbound_transport = transport.clone();
            self.task_manager
                .spawn_result("wireguard-outbound", true, async move {
                    outbound_transport.run_outbound(outbound_rx).await
                })
                .await;

            let inbound_transport = transport.clone();
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound(network_inbound_rx, inbound_tx)
                        .await
                })
                .await;

            self.task_manager
                .spawn_result("dataplane", true, async move { dataplane.run().await })
                .await;
        } else {
            let (inbound_tx, inbound_rx) = mpsc::channel(1024);
            let inbound_transport = self.transport.clone();
            self.task_manager
                .spawn_result("wireguard-inbound", true, async move {
                    inbound_transport
                        .run_inbound(network_inbound_rx, inbound_tx)
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
        let udp_transport = self.udp_transport.clone();
        let udp_inbound_tx = network_inbound_tx.clone();
        self.task_manager
            .spawn_result("udp-direct", false, async move {
            match UdpTransport::bind(udp_bind, peers).await {
                Ok(udp) => {
                    *udp_transport.write().await = Some(udp.clone());

                    let mut candidate_endpoints =
                        match udp.gather_candidates(stun_servers, stun_timeout).await {
                            Ok(candidates) => candidates,
                            Err(err) => {
                                warn!("Failed to gather UDP candidates: {err}");
                                Vec::new()
                            }
                        };

                    match udp.local_addr() {
                        Ok(addr) => {
                            if let Some(endpoint) =
                                advertised_udp_endpoint(addr, udp_advertise.as_deref())
                            {
                                if !candidate_endpoints.contains(&endpoint) {
                                    candidate_endpoints.insert(0, endpoint.clone());
                                }
                                info!("UDP transport listening on {addr}; advertising {endpoint}");
                                if let Err(err) =
                                    control.update_endpoint(&endpoint, "unknown").await
                                {
                                    warn!("Failed to queue UDP endpoint update: {err}");
                                }
                            } else {
                                warn!(
                                    "UDP transport listening on {addr}; endpoint not advertised because bind address is unspecified. Set --udp-advertise to publish a reachable endpoint."
                                );
                            }
                        }
                        Err(err) => warn!("UDP transport bound but local addr unavailable: {err}"),
                    }

                    info!(
                        "Prepared {} UDP candidate endpoints for signaling",
                        candidate_endpoints.len()
                    );
                    *local_candidates.write().await = candidate_endpoints;

                    if keepalive_interval.is_zero() {
                        udp.run_inbound(udp_inbound_tx).await
                    } else {
                        let keepalive_udp = udp.clone();
                        tokio::select! {
                            result = udp.run_inbound(udp_inbound_tx) => result,
                            _ = keepalive_udp.run_keepalives(keepalive_interval) => Ok(()),
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
            if relay_servers.is_empty() {
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
                    .spawn_result("relay-inbound", false, async move {
                        let RelaySelectionOutcome {
                            transport,
                            relay_rx,
                            diagnostics,
                        } = select_relay(
                            &relay_servers,
                            &preferred_regions,
                            selection_timeout,
                            &relay_node_id,
                            relay_peers,
                        )
                        .await;
                        *relay_selection.write().await = diagnostics;

                        if let (Some(relay), Some(relay_rx)) = (transport, relay_rx) {
                            info!(
                                "Selected relay region {} at {} ({} ms connect latency)",
                                relay.region(),
                                relay.endpoint(),
                                relay.connect_latency_ms()
                            );
                            *relay_transport.write().await = Some(relay.clone());
                            relay.run_inbound(relay_rx, relay_inbound_tx).await
                        } else {
                            warn!("No configured relay candidate was reachable");
                            Ok(())
                        }
                    })
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
                .spawn("rekey", false, async move {
                    let mut tick = tokio::time::interval(Duration::from_secs(30));
                    loop {
                        tick.tick().await;
                        let conns = peers.all_connections().await;
                        for conn in conns {
                            // Remove expired sessions and trigger rekey handshake.
                            let needs = transport.session_needs_rekey(&conn.node_id).await;
                            let expired = transport.session_is_expired(&conn.node_id).await;
                            if !needs && !expired {
                                continue;
                            }
                            if expired {
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

                            // Only the lexicographically smaller public key initiates rekey.
                            // We don't have peer public key here easily; use peer connection.
                            // Skip if already pending.
                            {
                                let state = pending.lock().await;
                                if state.pending.contains_key(&conn.node_id) {
                                    continue;
                                }
                                if state.attempts.get(&conn.node_id).copied().unwrap_or(0)
                                    >= MAX_HANDSHAKE_ATTEMPTS
                                {
                                    warn!(
                                        "Rekey for {} skipped: max attempts reached",
                                        conn.node_id
                                    );
                                    continue;
                                }
                            }

                            // Build a new handshake initiation if we have the peer's public key.
                            let Some(_peer_conn) = peers.get_connection(&conn.node_id).await else {
                                continue;
                            };
                            // PeerConnection doesn't store public key; look up from control.
                            // Best-effort: if control has the peer, use it.
                            // (control.peers is async)
                            // We intentionally skip rekey initiation if we can't get the key —
                            // the peer may also rekey from its side.
                            let control_peers = control.peers().await;
                            let Some(peer_info) = control_peers.get(&conn.node_id) else {
                                debug!("No control peer info for rekey of {}", conn.node_id);
                                continue;
                            };
                            if node_public_key >= peer_info.public_key {
                                // Let the other side initiate.
                                continue;
                            }

                            let Ok(private_key) =
                                decode_x25519_key(&node_private_key, "node private key")
                            else {
                                continue;
                            };
                            let Ok(peer_public) =
                                decode_x25519_key(&peer_info.public_key, "peer public key")
                            else {
                                continue;
                            };
                            let identity = NodeIdentity::from_private_key(private_key);
                            let mut initiator =
                                HandshakeInitiator::new(identity, peer_public, None);
                            let Ok(initiation) = initiator.create_initiation() else {
                                continue;
                            };
                            let initiation_bytes = initiation.to_bytes();
                            let candidates = local_candidates.read().await.clone();

                            {
                                let mut state = pending.lock().await;
                                *state.attempts.entry(conn.node_id.clone()).or_insert(0) += 1;
                                state.pending.insert(conn.node_id.clone(), initiator);
                            }

                            if let Err(err) = control
                                .send_peer_offer(&conn.node_id, &candidates, &initiation_bytes)
                                .await
                            {
                                warn!("Rekey offer to {} failed: {err}", conn.node_id);
                                let mut state = pending.lock().await;
                                state.pending.remove(&conn.node_id);
                            } else {
                                info!(
                                    "Rekey: sent handshake initiation to {} ({} bytes)",
                                    conn.node_id,
                                    initiation_bytes.len()
                                );
                                // Timeout cleanup
                                let pending2 = pending.clone();
                                let timeout_peer = conn.node_id.clone();
                                let transport2 = transport.clone();
                                let peers2 = peers.clone();
                                tokio::spawn(async move {
                                    tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS))
                                        .await;
                                    if !transport2.has_session(&timeout_peer).await {
                                        warn!("Rekey handshake timeout for peer {timeout_peer}");
                                        peers2
                                            .record_direct_failure(
                                                &timeout_peer,
                                                "rekey handshake timed out",
                                            )
                                            .await;
                                    }
                                    let mut state = pending2.lock().await;
                                    state.pending.remove(&timeout_peer);
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
                        if relay_servers.is_empty() {
                            debug!("No relay servers advertised by control plane");
                            continue;
                        }
                        relay_started = true;
                        let preferred_regions = self.config.relay.preferred_regions.clone();
                        let selection_timeout =
                            Duration::from_millis(self.config.relay.selection_timeout_ms.max(1));
                        let relay_transport = self.relay_transport.clone();
                        let relay_selection = self.relay_selection.clone();
                        let relay_peers = self.peers.clone();
                        let relay_inbound_tx = network_inbound_tx.clone();

                        self.task_manager
                            .spawn_result("relay-inbound", false, async move {
                                let RelaySelectionOutcome {
                                    transport,
                                    relay_rx,
                                    diagnostics,
                                } = select_relay(
                                    &relay_servers,
                                    &preferred_regions,
                                    selection_timeout,
                                    &relay_node_id,
                                    relay_peers,
                                )
                                .await;
                                *relay_selection.write().await = diagnostics;

                                if let (Some(relay), Some(relay_rx)) = (transport, relay_rx) {
                                    info!(
                                        "Selected relay region {} at {} ({} ms connect latency)",
                                        relay.region(),
                                        relay.endpoint(),
                                        relay.connect_latency_ms()
                                    );
                                    *relay_transport.write().await = Some(relay.clone());
                                    relay.run_inbound(relay_rx, relay_inbound_tx).await
                                } else {
                                    warn!("No configured relay candidate was reachable");
                                    Ok(())
                                }
                            })
                            .await;
                    }
                }

                ControlEvent::PeerJoined(peer_info) => {
                    info!(
                        "Peer joined: {} ({})",
                        peer_info.node_id, peer_info.virtual_ip
                    );
                    self.peers.add_peer(&peer_info).await;

                    if let Err(err) = self.maybe_initiate_handshake(&peer_info).await {
                        warn!(
                            "Failed to initiate WireGuard handshake with {}: {err}",
                            peer_info.node_id
                        );
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

                ControlEvent::PeerLeft(node_id) => {
                    info!("Peer left: {}", node_id);
                    self.peers.remove_peer(&node_id).await;
                }

                ControlEvent::PeerOffer {
                    from_node_id,
                    candidates,
                    handshake_init,
                } => {
                    info!(
                        "Received peer offer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers.add_candidates(&from_node_id, &candidates).await;
                    if !handshake_init.is_empty() {
                        if let Err(err) = self
                            .handle_peer_offer(&from_node_id, &candidates, &handshake_init)
                            .await
                        {
                            warn!("Failed to handle peer offer from {from_node_id}: {err}");
                        }
                    }
                    self.start_hole_punch(&from_node_id).await;
                }

                ControlEvent::PeerAnswer {
                    from_node_id,
                    candidates,
                    handshake_response,
                } => {
                    info!(
                        "Received peer answer from {} ({} candidates)",
                        from_node_id,
                        candidates.len()
                    );
                    self.peers.add_candidates(&from_node_id, &candidates).await;
                    if !handshake_response.is_empty() {
                        if let Err(err) = self
                            .handle_peer_answer(&from_node_id, &handshake_response)
                            .await
                        {
                            warn!("Failed to handle peer answer from {from_node_id}: {err}");
                        }
                    }
                    self.start_hole_punch(&from_node_id).await;
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

    async fn maybe_initiate_handshake(&mut self, peer_info: &control::PeerInfo) -> Result<()> {
        if self.transport.has_session(&peer_info.node_id).await {
            return Ok(());
        }

        {
            let state = self.pending_handshakes.lock().await;
            if state.pending.contains_key(&peer_info.node_id) {
                if state.attempts.get(&peer_info.node_id).copied().unwrap_or(0)
                    >= MAX_HANDSHAKE_ATTEMPTS
                {
                    warn!(
                        "Handshake to {} reached max attempts ({})",
                        peer_info.node_id, MAX_HANDSHAKE_ATTEMPTS
                    );
                    return Ok(());
                }
                // Still pending — don't duplicate.
                return Ok(());
            }
        }

        if self.config.node.public_key >= peer_info.public_key {
            return Ok(());
        }

        let identity = self.local_identity()?;
        let peer_public = decode_x25519_key(&peer_info.public_key, "peer public key")?;
        let mut initiator = HandshakeInitiator::new(identity, peer_public, None);
        let initiation = initiator
            .create_initiation()
            .map_err(|e| DaemonError::Peer(format!("WireGuard initiation failed: {e}")))?;
        let initiation_bytes = initiation.to_bytes();
        let candidates = self.local_candidates.read().await.clone();

        let peer_id_clone = peer_info.node_id.clone();
        {
            let mut state = self.pending_handshakes.lock().await;
            let attempts = state.attempts.entry(peer_id_clone.clone()).or_insert(0);
            *attempts = attempts.saturating_add(1);
            state.pending.insert(peer_id_clone.clone(), initiator);
        }

        self.control
            .send_peer_offer(&peer_id_clone, &candidates, &initiation_bytes)
            .await?;

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

        // Spawn timeout watcher that cleans up pending entry on timeout.
        // Uses the shared Arc<Mutex<>> so the spawned task can remove the entry.
        let pending = self.pending_handshakes.clone();
        let timeout_peer = peer_id_clone;
        let transport = self.transport.clone();
        let peers = self.peers.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)).await;
            if !transport.has_session(&timeout_peer).await {
                warn!("Handshake timeout for peer {timeout_peer}");
                peers
                    .record_direct_failure(&timeout_peer, "handshake timed out")
                    .await;
            }
            // Remove from pending so retry is possible.
            let mut state = pending.lock().await;
            state.pending.remove(&timeout_peer);
        });

        Ok(())
    }

    async fn start_hole_punch(&self, node_id: &str) {
        let Some(udp) = self.udp_transport.read().await.clone() else {
            debug!("UDP transport is not ready; skipping hole punch for {node_id}");
            return;
        };

        let Some(conn) = self.peers.get_connection(node_id).await else {
            debug!("No peer connection for {node_id}; skipping hole punch");
            return;
        };

        let mut candidates = Vec::new();
        for candidate in &conn.candidates {
            if let Ok(addr) = candidate.parse::<SocketAddr>() {
                if !candidates.contains(&addr) {
                    candidates.push(addr);
                }
            }
        }
        if let Some(endpoint) = conn.endpoint {
            if !candidates.contains(&endpoint) {
                candidates.push(endpoint);
            }
        }

        if candidates.is_empty() {
            debug!("No UDP candidates for {node_id}; skipping hole punch");
            self.peers
                .record_direct_failure(node_id, "no UDP candidates for hole punching")
                .await;
            return;
        }

        if conn.state != ConnectionState::Direct {
            self.peers
                .update_state(node_id, ConnectionState::HolePunching)
                .await;
        }

        let peer_id = node_id.to_string();
        let peers = self.peers.clone();
        let probe_interval = Duration::from_millis(self.config.network.punch_interval_ms);
        let attempts = self.config.network.punch_attempts;
        tokio::spawn(async move {
            match udp
                .punch_candidates(&peer_id, candidates, probe_interval, attempts)
                .await
            {
                Ok(sent) => {
                    info!("Sent {sent} UDP punch probes to peer {peer_id}");
                    sleep(probe_interval).await;
                    if sent > 0 && !peers.is_direct(&peer_id).await {
                        peers
                            .record_direct_failure(
                                &peer_id,
                                format!("no UDP punch ACK after {sent} probes"),
                            )
                            .await;
                    }
                }
                Err(err) => {
                    peers
                        .record_direct_failure(&peer_id, format!("hole punch failed: {err}"))
                        .await;
                    warn!("Failed to punch peer {peer_id}: {err}");
                }
            }
        });
    }

    async fn handle_peer_offer(
        &mut self,
        from_node_id: &str,
        _candidates: &[String],
        handshake_init: &[u8],
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

        self.transport
            .add_session(from_node_id.to_string(), TransportSession::new(keys))
            .await;
        self.peers
            .update_state(from_node_id, ConnectionState::Connecting)
            .await;

        let response_bytes = response.to_bytes();
        let candidates = self.local_candidates.read().await.clone();
        self.control
            .send_peer_answer(from_node_id, &candidates, &response_bytes)
            .await?;
        info!(
            "Installed WireGuard responder session for {from_node_id} and sent response ({} bytes, {} candidates)",
            response_bytes.len(),
            candidates.len()
        );
        Ok(())
    }

    async fn handle_peer_answer(
        &mut self,
        from_node_id: &str,
        handshake_response: &[u8],
    ) -> Result<()> {
        let response = MessageResponse::from_bytes(handshake_response)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard response: {e}")))?;
        let initiator = {
            let mut state = self.pending_handshakes.lock().await;
            state.pending.remove(from_node_id)
        };
        let Some(mut initiator) = initiator else {
            warn!("No pending WireGuard handshake for answer from {from_node_id}");
            return Ok(());
        };

        let keys = initiator
            .consume_response(&response)
            .map_err(|e| DaemonError::Peer(format!("WireGuard response consume failed: {e}")))?;

        // Reset attempt count on success so future rekey attempts can proceed.
        {
            let mut state = self.pending_handshakes.lock().await;
            state.attempts.remove(from_node_id);
        }

        // Replace old session with new one (rekey case).
        let new_session = TransportSession::new(keys);
        self.transport
            .add_session(from_node_id.to_string(), new_session)
            .await;
        self.peers
            .update_state(from_node_id, ConnectionState::Connecting)
            .await;
        info!("Installed WireGuard initiator session for {from_node_id}");
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

fn advertised_udp_endpoint(local_addr: SocketAddr, configured: Option<&str>) -> Option<String> {
    if let Some(endpoint) = configured
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
    {
        return Some(endpoint.to_string());
    }

    if local_addr.ip().is_unspecified() {
        return None;
    }

    Some(local_addr.to_string())
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
        let use_direct = peers
            .should_use_direct_for_data(&packet.peer_id, prefer_direct, relay_available)
            .await;

        let sent_direct = if use_direct {
            if let Some(udp) = udp_transport.read().await.clone() {
                match udp.send_packet(&packet).await {
                    Ok(Some(_)) => true,
                    Ok(None) => {
                        peers
                            .record_direct_failure(
                                &packet.peer_id,
                                "no direct UDP endpoint for encrypted packet",
                            )
                            .await;
                        false
                    }
                    Err(err) => {
                        warn!(
                            "Direct UDP send failed for peer {}; trying relay fallback: {err}",
                            packet.peer_id
                        );
                        peers
                            .record_direct_failure(&packet.peer_id, err.to_string())
                            .await;
                        false
                    }
                }
            } else {
                peers
                    .record_direct_failure(
                        &packet.peer_id,
                        "UDP transport unavailable for encrypted packet",
                    )
                    .await;
                false
            }
        } else {
            false
        };

        if sent_direct {
            continue;
        }

        if let Some(relay) = relay {
            if let Err(err) = relay.send_packet(&packet).await {
                warn!(
                    "Relay fallback send failed for peer {}: {err}",
                    packet.peer_id
                );
            }
        } else if !use_direct {
            if let Some(udp) = udp_transport.read().await.clone() {
                match udp.send_packet(&packet).await {
                    Ok(Some(_)) => {}
                    Ok(None) => debug!(
                        "Encrypted packet for peer {} has no direct UDP endpoint and no relay fallback",
                        packet.peer_id
                    ),
                    Err(err) => warn!("Best-effort direct UDP send failed: {err}"),
                }
            } else {
                debug!(
                    "Encrypted packet for peer {} has no direct UDP path and no relay fallback",
                    packet.peer_id
                );
            }
        } else {
            debug!(
                "Encrypted packet for peer {} has no direct UDP path and no relay fallback",
                packet.peer_id
            );
        }
    }
}

async fn run_direct_probe_loop(
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
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

        for (peer_id, candidates) in peers.direct_probe_targets().await {
            if !peers.direct_retry_due(&peer_id, retry_after).await {
                continue;
            }

            let udp = udp.clone();
            let peers = peers.clone();
            tokio::spawn(async move {
                match udp
                    .punch_candidates(&peer_id, candidates, probe_interval, attempts)
                    .await
                {
                    Ok(0) => {}
                    Ok(sent) => {
                        sleep(probe_interval).await;
                        if !peers.is_direct(&peer_id).await {
                            peers
                                .record_direct_failure(
                                    &peer_id,
                                    format!("no direct probe ACK after {sent} retry probes"),
                                )
                                .await;
                            debug!("Direct UDP retry probes for peer {peer_id} did not confirm");
                        } else {
                            debug!("Direct UDP retry probes restored peer {peer_id}");
                        }
                    }
                    Err(err) => {
                        peers
                            .record_direct_failure(&peer_id, format!("direct retry failed: {err}"))
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

fn parse_stun_servers(values: &[String]) -> Result<Vec<SocketAddr>> {
    values
        .iter()
        .map(|value| {
            value.trim().parse::<SocketAddr>().map_err(|e| {
                DaemonError::Config(format!("invalid STUN server '{}': {e}", value.trim()))
            })
        })
        .collect()
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

    #[test]
    fn test_advertised_udp_endpoint_uses_configured_value() {
        let local = "0.0.0.0:51820".parse().unwrap();
        assert_eq!(
            advertised_udp_endpoint(local, Some("203.0.113.10:51820")),
            Some("203.0.113.10:51820".to_string())
        );
    }

    #[test]
    fn test_advertised_udp_endpoint_skips_unspecified_address() {
        let local = "0.0.0.0:51820".parse().unwrap();
        assert_eq!(advertised_udp_endpoint(local, None), None);
    }

    #[test]
    fn test_advertised_udp_endpoint_uses_specific_bind_address() {
        let local = "127.0.0.1:51820".parse().unwrap();
        assert_eq!(
            advertised_udp_endpoint(local, None),
            Some("127.0.0.1:51820".to_string())
        );
    }

    #[test]
    fn test_parse_stun_servers() {
        let servers =
            parse_stun_servers(&["127.0.0.1:3478".to_string(), " 10.0.0.1:3478 ".to_string()])
                .unwrap();
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0], "127.0.0.1:3478".parse().unwrap());
        assert_eq!(servers[1], "10.0.0.1:3478".parse().unwrap());
    }

    #[test]
    fn test_parse_stun_servers_rejects_invalid_endpoint() {
        let err = parse_stun_servers(&["not-a-socket".to_string()]).unwrap_err();
        assert!(err.to_string().contains("invalid STUN server"));
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
        assert_eq!(received.from_node, "node-a");
        assert_eq!(received.data, payload);

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
        assert_eq!(received.from_node, "node-a");
        assert_eq!(received.data, payload);

        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), direct_sink.recv_from(&mut buf))
                .await
                .is_err()
        );

        let conn = peers.get_connection("node-b").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Relay);
        assert_eq!(conn.active_path(), Some(peer::NetworkPath::Relay));

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
