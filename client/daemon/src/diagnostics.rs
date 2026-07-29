//! Local diagnostics endpoint.
//!
//! This is intentionally tiny: a loopback HTTP listener that exposes runtime
//! status JSON without pulling in a web framework.

use std::sync::Arc;

use p2pnet_nat::NatProfile;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::{DaemonError, Result};
use crate::gateway_mapping::GatewayMappingDiagnostics;
use crate::peer::{PeerDiagnostics, PeerManager, PeerManagerStats, DIRECT_RETRY_BASE_INTERVAL};
use crate::relay::{RelaySelectionDiagnostics, RelayTransport};
use crate::tasks::{HealthState, TaskManager};
use crate::traversal_history::TraversalHistoryDiagnostics;
use crate::udp::{UdpSocketPoolMemberDiagnostics, UdpTransport};

const IPV6_SAFE_MIN_MTU: u32 = 1280;
const RELAY_SAFE_MTU: u32 = 1380;
const WIREGUARD_STYLE_MTU: u32 = 1420;
const COMMON_ETHERNET_MTU: u32 = 1500;

/// Static protocol boundary advertised by diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolDiagnostics {
    pub data_plane: String,
    pub handshake: String,
    pub key_exchange: String,
    pub aead: String,
    pub hash_kdf: String,
    pub device_identity: String,
    pub relay_transport: String,
    pub wireguard_interop: bool,
    pub turn_compatible: bool,
    pub security_audit: String,
}

impl ProtocolDiagnostics {
    fn current() -> Self {
        Self {
            data_plane: "wireguard_like_noise".to_string(),
            handshake: "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s".to_string(),
            key_exchange: "X25519".to_string(),
            aead: "ChaCha20-Poly1305".to_string(),
            hash_kdf: "BLAKE2s/HKDF-BLAKE2s".to_string(),
            device_identity: "Ed25519 challenge-response".to_string(),
            relay_transport: "DERP-like TCP/TLS ciphertext forwarding".to_string(),
            wireguard_interop: false,
            turn_compatible: false,
            security_audit: "not_completed".to_string(),
        }
    }
}

/// MTU boundary and current TUN configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtuDiagnostics {
    pub configured_mtu: u32,
    pub profile: String,
    pub ipv6_safe_min_mtu: u32,
    pub relay_safe_mtu: u32,
    pub wireguard_style_mtu: u32,
    pub common_ethernet_mtu: u32,
    pub automatic_pmtu: bool,
    pub relay_path_observed: bool,
    pub suggested_safe_mtu: Option<u32>,
    pub risks: Vec<MtuRiskDiagnostics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtuRiskDiagnostics {
    pub code: String,
    pub severity: String,
    pub message: String,
    pub suggested_mtu: Option<u32>,
}

impl MtuDiagnostics {
    fn from_runtime(configured_mtu: u32, relay_path_observed: bool) -> Self {
        let risks = mtu_risks(configured_mtu, relay_path_observed);
        let suggested_safe_mtu = suggested_safe_mtu(configured_mtu, relay_path_observed);
        Self {
            configured_mtu,
            profile: mtu_profile(configured_mtu).to_string(),
            ipv6_safe_min_mtu: IPV6_SAFE_MIN_MTU,
            relay_safe_mtu: RELAY_SAFE_MTU,
            wireguard_style_mtu: WIREGUARD_STYLE_MTU,
            common_ethernet_mtu: COMMON_ETHERNET_MTU,
            automatic_pmtu: false,
            relay_path_observed,
            suggested_safe_mtu,
            risks,
        }
    }
}

/// Runtime diagnostics snapshot returned by the local endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    pub version: String,
    pub process_id: u32,
    pub node_id: String,
    pub virtual_ip: String,
    pub network_id: String,
    pub network_generation: u64,
    pub protocol: ProtocolDiagnostics,
    pub mtu: MtuDiagnostics,
    pub udp_local_addr: Option<String>,
    /// Number of live direct UDP sockets (one unless the bounded experiment is enabled).
    pub udp_socket_count: usize,
    /// Whether the experimental socket pool is actively used for punch probes.
    pub udp_socket_pool_active: bool,
    /// Per-socket counters for the bounded UDP traversal experiment.
    pub udp_socket_pool: Vec<UdpSocketPoolMemberDiagnostics>,
    pub local_candidates: Vec<String>,
    pub nat_profile: Option<NatProfile>,
    pub gateway_mapping: GatewayMappingDiagnostics,
    pub relay_servers: Vec<String>,
    pub relay_connected: bool,
    pub relay_selection: RelaySelectionDiagnostics,
    pub traversal_history: TraversalHistoryDiagnostics,
    pub peers: Vec<PeerDiagnostics>,
    pub stats: PeerManagerStats,
    pub health: crate::tasks::HealthSnapshot,
}

/// Shared state needed to build diagnostics responses.
#[derive(Clone)]
pub struct DiagnosticsContext {
    config: Arc<Config>,
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    local_candidates: Arc<RwLock<Vec<String>>>,
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    gateway_mapping: Arc<RwLock<GatewayMappingDiagnostics>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    health: Arc<HealthState>,
    task_manager: Arc<TaskManager>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl DiagnosticsContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<Config>,
        peers: Arc<PeerManager>,
        udp_transport: Arc<RwLock<Option<UdpTransport>>>,
        local_candidates: Arc<RwLock<Vec<String>>>,
        nat_profile: Arc<RwLock<Option<NatProfile>>>,
        gateway_mapping: Arc<RwLock<GatewayMappingDiagnostics>>,
        relay_transport: Arc<RwLock<Option<RelayTransport>>>,
        relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
        health: Arc<HealthState>,
        task_manager: Arc<TaskManager>,
        shutdown_tx: tokio::sync::watch::Sender<bool>,
    ) -> Self {
        Self {
            config,
            peers,
            udp_transport,
            local_candidates,
            nat_profile,
            gateway_mapping,
            relay_transport,
            relay_selection,
            health,
            task_manager,
            shutdown_tx,
        }
    }
}

fn mtu_profile(mtu: u32) -> &'static str {
    match mtu {
        0..=1279 => "low",
        1280..=RELAY_SAFE_MTU => "relay_safe",
        1381..=WIREGUARD_STYLE_MTU => "default",
        1421..=COMMON_ETHERNET_MTU => "high",
        _ => "jumbo_high_risk",
    }
}

fn suggested_safe_mtu(mtu: u32, relay_path_observed: bool) -> Option<u32> {
    if mtu < IPV6_SAFE_MIN_MTU {
        Some(IPV6_SAFE_MIN_MTU)
    } else if relay_path_observed && mtu > RELAY_SAFE_MTU {
        Some(RELAY_SAFE_MTU)
    } else if mtu > WIREGUARD_STYLE_MTU {
        Some(WIREGUARD_STYLE_MTU)
    } else {
        None
    }
}

fn mtu_risks(mtu: u32, relay_path_observed: bool) -> Vec<MtuRiskDiagnostics> {
    let mut risks = Vec::new();
    if mtu < IPV6_SAFE_MIN_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "below_ipv6_safe_min".to_string(),
            severity: "warning".to_string(),
            message: format!(
                "Configured MTU {mtu} is below the IPv6 minimum {IPV6_SAFE_MIN_MTU}; use it only as a temporary PMTU blackhole workaround."
            ),
            suggested_mtu: Some(IPV6_SAFE_MIN_MTU),
        });
    }
    if relay_path_observed && mtu > RELAY_SAFE_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "relay_path_high_mtu".to_string(),
            severity: "warning".to_string(),
            message: format!(
                "Relay path observed with MTU {mtu}; if large flows stall, try lowering MTU to {RELAY_SAFE_MTU} before changing the default globally."
            ),
            suggested_mtu: Some(RELAY_SAFE_MTU),
        });
    }
    if mtu > COMMON_ETHERNET_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "jumbo_mtu_high_risk".to_string(),
            severity: "warning".to_string(),
            message: format!(
                "Configured MTU {mtu} exceeds common Ethernet MTU {COMMON_ETHERNET_MTU}; require end-to-end jumbo-frame validation or lower to {WIREGUARD_STYLE_MTU}."
            ),
            suggested_mtu: Some(WIREGUARD_STYLE_MTU),
        });
    } else if mtu > WIREGUARD_STYLE_MTU {
        risks.push(MtuRiskDiagnostics {
            code: "above_wireguard_style_default".to_string(),
            severity: "notice".to_string(),
            message: format!(
                "Configured MTU {mtu} is above the WireGuard-style default {WIREGUARD_STYLE_MTU}; mobile, CGNAT, or enterprise paths may blackhole large packets."
            ),
            suggested_mtu: Some(WIREGUARD_STYLE_MTU),
        });
    }
    risks
}

/// Run the local diagnostics HTTP endpoint until the listener fails.
pub async fn run_diagnostics_server(
    bind: String,
    context: DiagnosticsContext,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(&bind).await.map_err(|e| {
        DaemonError::Network(format!(
            "failed to bind diagnostics endpoint at {bind}: {e}"
        ))
    })?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| DaemonError::Network(format!("failed to read diagnostics local addr: {e}")))?;
    info!("Diagnostics endpoint listening at http://{local_addr}/status");

    serve_diagnostics(listener, context, shutdown_rx).await
}

async fn serve_diagnostics(
    listener: TcpListener,
    context: DiagnosticsContext,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    let mut shutdown_rx = shutdown_rx;
    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    info!("Diagnostics server received shutdown signal");
                    break;
                }
            }
            result = listener.accept() => {
                let (stream, _remote_addr) = result
                    .map_err(|e| DaemonError::Network(format!("diagnostics accept failed: {e}")))?;

                let context = context.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, context).await {
                        debug!("diagnostics request failed: {err}");
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_connection(mut stream: TcpStream, context: DiagnosticsContext) -> Result<()> {
    let mut buffer = [0u8; 1024];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buffer))
        .await
        .map_err(|_| DaemonError::Network("diagnostics request timed out".to_string()))?
        .map_err(|e| DaemonError::Network(format!("diagnostics read failed: {e}")))?;

    let request = String::from_utf8_lossy(&buffer[..n]);
    let cors_origin = allowed_cors_origin(&request);
    let (method, path) = request
        .lines()
        .next()
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(method), Some(path)) => Some((method, path)),
                _ => None,
            }
        })
        .unwrap_or(("GET", "/"));

    match (method, path) {
        ("GET", "/health") => {
            write_response(&mut stream, 200, "text/plain", "ok\n", cors_origin).await?
        }
        ("GET", "/status") => {
            let snapshot = build_snapshot(context).await;
            let body = serde_json::to_string_pretty(&snapshot)?;
            write_response(&mut stream, 200, "application/json", &body, cors_origin).await?;
        }
        ("POST", "/shutdown") => {
            write_response(
                &mut stream,
                200,
                "text/plain",
                "shutting down\n",
                cors_origin,
            )
            .await?;
            let _ = context.shutdown_tx.send(true);
        }
        _ => {
            warn!("Unknown diagnostics path requested: {path}");
            write_response(&mut stream, 404, "text/plain", "not found\n", cors_origin).await?;
        }
    }

    Ok(())
}

fn allowed_cors_origin(request: &str) -> Option<&str> {
    request.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.eq_ignore_ascii_case("origin") {
            return None;
        }
        let origin = value.trim();
        matches!(
            origin,
            "http://localhost:14327"
                | "http://127.0.0.1:14327"
                | "http://localhost:1420"
                | "http://127.0.0.1:1420"
        )
        .then_some(origin)
    })
}

async fn build_snapshot(context: DiagnosticsContext) -> DiagnosticsSnapshot {
    let udp = context.udp_transport.read().await.clone();
    let udp_local_endpoint = udp.as_ref().and_then(|udp| udp.local_addr().ok());
    let udp_local_addr = udp_local_endpoint.map(|addr| addr.to_string());
    let udp_socket_count = udp.as_ref().map(UdpTransport::socket_count).unwrap_or(0);
    let udp_socket_pool_active = udp.as_ref().is_some_and(UdpTransport::socket_pool_active);
    let udp_socket_pool = match udp.as_ref() {
        Some(udp) => udp.socket_pool_diagnostics().await,
        None => Vec::new(),
    };
    let relay_connected = context.relay_transport.read().await.is_some();
    let direct_retry_after = DIRECT_RETRY_BASE_INTERVAL;

    let tasks = context.task_manager.task_statuses().await;
    let health_snap = context.health.snapshot(&tasks).await;
    let mut relay_selection = context.relay_selection.read().await.clone();
    relay_selection.refresh_runtime_ages();

    let peers = context
        .peers
        .diagnostics_with_path_selection(
            context.config.relay.prefer_direct,
            relay_connected,
            direct_retry_after,
            udp_local_endpoint,
        )
        .await;
    let stats = PeerManagerStats::from_diagnostics(&peers);

    DiagnosticsSnapshot {
        version: env!("CARGO_PKG_VERSION").to_string(),
        process_id: std::process::id(),
        node_id: context.config.node.node_id.clone(),
        virtual_ip: context.config.network.virtual_ip.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation: context.peers.current_network_generation().await,
        protocol: ProtocolDiagnostics::current(),
        mtu: MtuDiagnostics::from_runtime(
            context.config.network.mtu,
            relay_connected || stats.relay_connections > 0,
        ),
        udp_local_addr,
        udp_socket_count,
        udp_socket_pool_active,
        udp_socket_pool,
        local_candidates: context.local_candidates.read().await.clone(),
        nat_profile: context.nat_profile.read().await.clone(),
        gateway_mapping: context.gateway_mapping.read().await.clone(),
        relay_servers: context.config.relay.servers.clone(),
        relay_connected,
        relay_selection,
        traversal_history: context.peers.traversal_history_diagnostics().await,
        peers,
        stats,
        health: health_snap,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
    cors_origin: Option<&str>,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let cors_header = cors_origin
        .map(|origin| format!("Access-Control-Allow-Origin: {origin}\r\nVary: Origin\r\n"))
        .unwrap_or_default();
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n{cors_header}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .map_err(|e| DaemonError::Network(format!("diagnostics write failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpStream;

    use super::*;
    use crate::control::PeerInfo;
    use crate::peer::{REASON_DIRECT_PROBE_FAILED, REASON_PATH_RELAY_UNAVAILABLE};

    #[test]
    fn cors_origin_is_restricted_to_local_dev_server() {
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\nOrigin: http://localhost:14327\r\n\r\n"),
            Some("http://localhost:14327")
        );
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\nOrigin: http://localhost:1420\r\n\r\n"),
            Some("http://localhost:1420")
        );
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\norigin: http://127.0.0.1:1420\r\n\r\n"),
            Some("http://127.0.0.1:1420")
        );
        assert_eq!(
            allowed_cors_origin("GET /status HTTP/1.1\r\nOrigin: https://example.com\r\n\r\n"),
            None
        );
    }

    #[test]
    fn mtu_diagnostics_explain_relay_high_mtu_risk() {
        let default_direct = MtuDiagnostics::from_runtime(1420, false);
        assert_eq!(default_direct.profile, "default");
        assert!(!default_direct.relay_path_observed);
        assert_eq!(default_direct.suggested_safe_mtu, None);
        assert!(default_direct.risks.is_empty());

        let relay_default = MtuDiagnostics::from_runtime(1420, true);
        assert!(relay_default.relay_path_observed);
        assert_eq!(relay_default.suggested_safe_mtu, Some(RELAY_SAFE_MTU));
        assert!(relay_default
            .risks
            .iter()
            .any(|risk| risk.code == "relay_path_high_mtu"
                && risk.suggested_mtu == Some(RELAY_SAFE_MTU)));

        let jumbo = MtuDiagnostics::from_runtime(9000, false);
        assert_eq!(jumbo.profile, "jumbo_high_risk");
        assert!(jumbo
            .risks
            .iter()
            .any(|risk| risk.code == "jumbo_mtu_high_risk"
                && risk.suggested_mtu == Some(WIREGUARD_STYLE_MTU)));
    }

    #[tokio::test]
    async fn diagnostics_server_returns_status_json() {
        let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.node.node_id = "node-a".to_string();
        config.network.virtual_ip = "10.20.0.1".to_string();
        let config = Arc::new(config);
        let peers = Arc::new(PeerManager::new((*config).clone()));
        peers
            .add_peer(&PeerInfo {
                node_id: "node-b".to_string(),
                device_name: "Office Mac".to_string(),
                public_key: "pk".to_string(),
                endpoint: "127.0.0.1:51820".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
            })
            .await;
        peers.record_direct_failure("node-b", "probe timeout").await;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let health = HealthState::new();
        let task_manager = TaskManager::new(health.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let context = DiagnosticsContext::new(
            config,
            peers,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(GatewayMappingDiagnostics::default())),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(RelaySelectionDiagnostics::default())),
            health,
            task_manager,
            shutdown_tx,
        );
        let worker = tokio::spawn(serve_diagnostics(listener, context, shutdown_rx));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(
                b"GET /status HTTP/1.1\r\nHost: localhost\r\nOrigin: http://127.0.0.1:1420\r\n\r\n",
            )
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"gateway_mapping\""));
        assert!(response.contains("Access-Control-Allow-Origin: http://127.0.0.1:1420\r\n"));
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let snapshot: DiagnosticsSnapshot = serde_json::from_str(body).unwrap();
        assert_eq!(snapshot.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(snapshot.process_id, std::process::id());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.network_generation, 0);
        assert_eq!(
            snapshot.protocol.handshake,
            "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
        );
        assert_eq!(snapshot.protocol.aead, "ChaCha20-Poly1305");
        assert!(!snapshot.protocol.wireguard_interop);
        assert!(!snapshot.protocol.turn_compatible);
        assert_eq!(snapshot.protocol.security_audit, "not_completed");
        assert_eq!(snapshot.mtu.configured_mtu, 1420);
        assert_eq!(snapshot.mtu.profile, "default");
        assert_eq!(snapshot.mtu.relay_safe_mtu, 1380);
        assert!(!snapshot.mtu.automatic_pmtu);
        assert!(!snapshot.mtu.relay_path_observed);
        assert_eq!(snapshot.mtu.suggested_safe_mtu, None);
        assert!(snapshot.mtu.risks.is_empty());
        assert!(snapshot.local_candidates.is_empty());
        assert_eq!(snapshot.nat_profile, None);
        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(snapshot.peers[0].node_id, "node-b");
        assert_eq!(snapshot.peers[0].device_name, "Office Mac");
        assert_eq!(
            snapshot.relay_selection,
            RelaySelectionDiagnostics::default()
        );
        assert_eq!(
            snapshot.peers[0].direct.last_error.as_deref(),
            Some("probe timeout")
        );
        assert_eq!(
            snapshot.peers[0].direct.last_error_code.as_deref(),
            Some(REASON_DIRECT_PROBE_FAILED)
        );
        assert_eq!(snapshot.peers[0].last_path_selection, None);
        assert!(snapshot.peers[0].path_events.is_empty());
        let current_path = snapshot.peers[0]
            .current_path_selection
            .as_ref()
            .expect("current path selection should be included in /status");
        assert_eq!(current_path.reason_code, REASON_PATH_RELAY_UNAVAILABLE);

        let mut shutdown_stream = TcpStream::connect(addr).await.unwrap();
        shutdown_stream
            .write_all(b"POST /shutdown HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut shutdown_response = String::new();
        shutdown_stream
            .read_to_string(&mut shutdown_response)
            .await
            .unwrap();

        assert!(shutdown_response.starts_with("HTTP/1.1 200 OK"));
        assert!(shutdown_response.contains("shutting down"));

        worker.await.unwrap().unwrap();
    }
}
