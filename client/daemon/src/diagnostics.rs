//! Local diagnostics endpoint.
//!
//! This is intentionally tiny: a loopback HTTP listener that exposes runtime
//! status JSON without pulling in a web framework.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::error::{DaemonError, Result};
use crate::peer::{PeerDiagnostics, PeerManager, PeerManagerStats};
use crate::relay::{RelaySelectionDiagnostics, RelayTransport};
use crate::tasks::{HealthState, TaskManager};
use crate::udp::UdpTransport;

/// Runtime diagnostics snapshot returned by the local endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    pub process_id: u32,
    pub node_id: String,
    pub virtual_ip: String,
    pub network_id: String,
    pub network_generation: u64,
    pub udp_local_addr: Option<String>,
    pub relay_servers: Vec<String>,
    pub relay_connected: bool,
    pub relay_selection: RelaySelectionDiagnostics,
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
            relay_transport,
            relay_selection,
            health,
            task_manager,
            shutdown_tx,
        }
    }
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
    let udp_local_addr = context
        .udp_transport
        .read()
        .await
        .as_ref()
        .and_then(|udp| udp.local_addr().ok())
        .map(|addr| addr.to_string());
    let relay_connected = context.relay_transport.read().await.is_some();

    let tasks = context.task_manager.task_statuses().await;
    let health_snap = context.health.snapshot(&tasks).await;

    DiagnosticsSnapshot {
        process_id: std::process::id(),
        node_id: context.config.node.node_id.clone(),
        virtual_ip: context.config.network.virtual_ip.clone(),
        network_id: context.config.network.network_id.clone(),
        network_generation: context.peers.current_network_generation().await,
        udp_local_addr,
        relay_servers: context.config.relay.servers.clone(),
        relay_connected,
        relay_selection: context.relay_selection.read().await.clone(),
        peers: context
            .peers
            .diagnostics_with_path_selection(context.config.relay.prefer_direct, relay_connected)
            .await,
        stats: context.peers.stats().await,
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
        assert!(response.contains("Access-Control-Allow-Origin: http://127.0.0.1:1420\r\n"));
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let snapshot: DiagnosticsSnapshot = serde_json::from_str(body).unwrap();
        assert_eq!(snapshot.process_id, std::process::id());
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.network_generation, 0);
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
