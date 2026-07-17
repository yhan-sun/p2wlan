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
use crate::udp::UdpTransport;

/// Runtime diagnostics snapshot returned by the local endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsSnapshot {
    pub node_id: String,
    pub virtual_ip: String,
    pub network_id: String,
    pub udp_local_addr: Option<String>,
    pub relay_servers: Vec<String>,
    pub relay_connected: bool,
    pub relay_selection: RelaySelectionDiagnostics,
    pub peers: Vec<PeerDiagnostics>,
    pub stats: PeerManagerStats,
}

/// Run the local diagnostics HTTP endpoint until the listener fails.
pub async fn run_diagnostics_server(
    bind: String,
    config: Arc<Config>,
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
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

    serve_diagnostics(
        listener,
        config,
        peers,
        udp_transport,
        relay_transport,
        relay_selection,
    )
    .await
}

async fn serve_diagnostics(
    listener: TcpListener,
    config: Arc<Config>,
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
) -> Result<()> {
    loop {
        let (stream, _remote_addr) = listener
            .accept()
            .await
            .map_err(|e| DaemonError::Network(format!("diagnostics accept failed: {e}")))?;

        let config = config.clone();
        let peers = peers.clone();
        let udp_transport = udp_transport.clone();
        let relay_transport = relay_transport.clone();
        let relay_selection = relay_selection.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                stream,
                config,
                peers,
                udp_transport,
                relay_transport,
                relay_selection,
            )
            .await
            {
                debug!("diagnostics request failed: {err}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    config: Arc<Config>,
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
) -> Result<()> {
    let mut buffer = [0u8; 1024];
    let n = timeout(Duration::from_secs(3), stream.read(&mut buffer))
        .await
        .map_err(|_| DaemonError::Network("diagnostics request timed out".to_string()))?
        .map_err(|e| DaemonError::Network(format!("diagnostics read failed: {e}")))?;

    let request = String::from_utf8_lossy(&buffer[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("GET"), Some(path)) => Some(path),
                _ => None,
            }
        })
        .unwrap_or("/");

    match path {
        "/health" => write_response(&mut stream, 200, "text/plain", "ok\n").await?,
        "/status" => {
            let snapshot = build_snapshot(
                config,
                peers,
                udp_transport,
                relay_transport,
                relay_selection,
            )
            .await;
            let body = serde_json::to_string_pretty(&snapshot)?;
            write_response(&mut stream, 200, "application/json", &body).await?;
        }
        _ => {
            warn!("Unknown diagnostics path requested: {path}");
            write_response(&mut stream, 404, "text/plain", "not found\n").await?;
        }
    }

    Ok(())
}

async fn build_snapshot(
    config: Arc<Config>,
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
) -> DiagnosticsSnapshot {
    let udp_local_addr = udp_transport
        .read()
        .await
        .as_ref()
        .and_then(|udp| udp.local_addr().ok())
        .map(|addr| addr.to_string());
    let relay_connected = relay_transport.read().await.is_some();

    DiagnosticsSnapshot {
        node_id: config.node.node_id.clone(),
        virtual_ip: config.network.virtual_ip.clone(),
        network_id: config.network.network_id.clone(),
        udp_local_addr,
        relay_servers: config.relay.servers.clone(),
        relay_connected,
        relay_selection: relay_selection.read().await.clone(),
        peers: peers.diagnostics().await,
        stats: peers.stats().await,
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
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
        let worker = tokio::spawn(serve_diagnostics(
            listener,
            config,
            peers,
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(None)),
            Arc::new(RwLock::new(RelaySelectionDiagnostics::default())),
        ));

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();

        assert!(response.starts_with("HTTP/1.1 200 OK"));
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        let snapshot: DiagnosticsSnapshot = serde_json::from_str(body).unwrap();
        assert_eq!(snapshot.node_id, "node-a");
        assert_eq!(snapshot.peers.len(), 1);
        assert_eq!(snapshot.peers[0].node_id, "node-b");
        assert_eq!(
            snapshot.relay_selection,
            RelaySelectionDiagnostics::default()
        );
        assert_eq!(
            snapshot.peers[0].direct.last_error.as_deref(),
            Some("probe timeout")
        );

        worker.abort();
    }
}
