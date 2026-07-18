//! Relay transport adapter for encrypted peer packets.
//!
//! This layer bridges the daemon's WireGuard packet model to the DERP-like
//! relay client. Relay payloads remain encrypted WireGuard datagrams; the relay
//! server only sees source/destination node IDs and opaque bytes.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pnet_relay::{RelayClient, RelayMessage};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

/// Diagnostics for one configured relay candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCandidateDiagnostics {
    pub region: String,
    pub endpoint: String,
    pub connect_latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Result of the most recent relay selection pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySelectionDiagnostics {
    pub selected_region: Option<String>,
    pub selected_endpoint: Option<String>,
    pub selected_connect_latency_ms: Option<u64>,
    pub candidates: Vec<RelayCandidateDiagnostics>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
struct RelayCandidate {
    index: usize,
    region: String,
    endpoint: String,
    preference_rank: usize,
}

struct ConnectedCandidate {
    candidate: RelayCandidate,
    transport: RelayTransport,
    relay_rx: mpsc::UnboundedReceiver<RelayMessage>,
}

/// Relay selector output. A failed pass still returns diagnostics.
pub struct RelaySelectionOutcome {
    pub transport: Option<RelayTransport>,
    pub relay_rx: Option<mpsc::UnboundedReceiver<RelayMessage>>,
    pub diagnostics: RelaySelectionDiagnostics,
}

fn parse_candidate(
    index: usize,
    spec: &str,
    preferred_regions: &[String],
) -> std::result::Result<RelayCandidate, String> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Err("empty relay candidate".to_string());
    }

    let (region, endpoint) = match spec.split_once('@') {
        Some((region, endpoint)) if !region.trim().is_empty() => {
            (region.trim().to_string(), endpoint.trim())
        }
        Some(_) => return Err(format!("relay candidate '{spec}' has an empty region")),
        None => ("default".to_string(), spec),
    };

    endpoint
        .parse::<SocketAddr>()
        .map_err(|err| format!("invalid relay endpoint '{endpoint}': {err}"))?;

    let preference_rank = preferred_regions
        .iter()
        .position(|preferred| preferred.eq_ignore_ascii_case(&region))
        .unwrap_or(preferred_regions.len());

    Ok(RelayCandidate {
        index,
        region,
        endpoint: endpoint.to_string(),
        preference_rank,
    })
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// Connect to all valid relay candidates concurrently and select the best one.
/// Preferred regions win first; connection latency and config order break ties.
pub async fn select_relay(
    specs: &[String],
    preferred_regions: &[String],
    selection_timeout: Duration,
    node_id: &str,
    peers: Arc<PeerManager>,
) -> RelaySelectionOutcome {
    let mut diagnostics = RelaySelectionDiagnostics::default();
    let mut candidates = Vec::new();
    let mut seen_endpoints = HashSet::new();

    for (index, spec) in specs.iter().enumerate() {
        match parse_candidate(index, spec, preferred_regions) {
            Ok(candidate) if seen_endpoints.insert(candidate.endpoint.clone()) => {
                diagnostics.candidates.push(RelayCandidateDiagnostics {
                    region: candidate.region.clone(),
                    endpoint: candidate.endpoint.clone(),
                    connect_latency_ms: None,
                    error: None,
                });
                candidates.push(candidate);
            }
            Ok(candidate) => diagnostics.candidates.push(RelayCandidateDiagnostics {
                region: candidate.region,
                endpoint: candidate.endpoint,
                connect_latency_ms: None,
                error: Some("duplicate relay endpoint".to_string()),
            }),
            Err(error) => diagnostics.candidates.push(RelayCandidateDiagnostics {
                region: "unknown".to_string(),
                endpoint: spec.trim().to_string(),
                connect_latency_ms: None,
                error: Some(error),
            }),
        }
    }

    let mut tasks = JoinSet::new();
    for candidate in candidates {
        let node_id = node_id.to_string();
        let peers = peers.clone();
        tasks.spawn(async move {
            let started = Instant::now();
            let result = timeout(
                selection_timeout,
                RelayTransport::connect_in_region(
                    &candidate.endpoint,
                    &candidate.region,
                    &node_id,
                    peers,
                ),
            )
            .await;
            let latency_ms = duration_millis(started.elapsed());
            (candidate, latency_ms, result)
        });
    }

    let mut connected = Vec::new();
    while let Some(task_result) = tasks.join_next().await {
        let Ok((candidate, latency_ms, result)) = task_result else {
            continue;
        };
        let candidate_diagnostics = &mut diagnostics.candidates[candidate.index];
        candidate_diagnostics.connect_latency_ms = Some(latency_ms);

        match result {
            Ok(Ok((transport, relay_rx))) => connected.push(ConnectedCandidate {
                candidate,
                transport,
                relay_rx,
            }),
            Ok(Err(error)) => candidate_diagnostics.error = Some(error.to_string()),
            Err(_) => {
                candidate_diagnostics.error = Some(format!(
                    "relay selection timed out after {} ms",
                    duration_millis(selection_timeout)
                ));
            }
        }
    }

    connected.sort_by_key(|connected| {
        (
            connected.candidate.preference_rank,
            connected.transport.connect_latency_ms,
            connected.candidate.index,
        )
    });

    if let Some(selected) = connected.into_iter().next() {
        diagnostics.selected_region = Some(selected.candidate.region.clone());
        diagnostics.selected_endpoint = Some(selected.candidate.endpoint.clone());
        diagnostics.selected_connect_latency_ms = Some(selected.transport.connect_latency_ms);
        RelaySelectionOutcome {
            transport: Some(selected.transport),
            relay_rx: Some(selected.relay_rx),
            diagnostics,
        }
    } else {
        diagnostics.last_error = Some(if specs.is_empty() {
            "no relay candidates configured".to_string()
        } else {
            "all relay candidates failed".to_string()
        });
        RelaySelectionOutcome {
            transport: None,
            relay_rx: None,
            diagnostics,
        }
    }
}

/// Sends and receives encrypted WireGuard datagrams through a relay server.
#[derive(Clone)]
pub struct RelayTransport {
    relay_region: String,
    relay_endpoint: String,
    connect_latency_ms: u64,
    client: Arc<Mutex<RelayClient>>,
    peers: Arc<PeerManager>,
}

impl RelayTransport {
    /// Connect to a relay server and register this node ID.
    pub async fn connect(
        relay_endpoint: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayMessage>)> {
        Self::connect_in_region(relay_endpoint, "default", node_id, peers).await
    }

    async fn connect_in_region(
        relay_endpoint: &str,
        relay_region: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayMessage>)> {
        let started = Instant::now();
        let (client, relay_rx) = RelayClient::connect(relay_endpoint, node_id)
            .await
            .map_err(|e| {
                DaemonError::Relay(format!("failed to connect to relay {relay_endpoint}: {e}"))
            })?;

        Ok((
            Self {
                relay_region: relay_region.to_string(),
                relay_endpoint: relay_endpoint.to_string(),
                connect_latency_ms: duration_millis(started.elapsed()),
                client: Arc::new(Mutex::new(client)),
                peers,
            },
            relay_rx,
        ))
    }

    /// Selected relay region label.
    pub fn region(&self) -> &str {
        &self.relay_region
    }

    /// Selected relay endpoint.
    pub fn endpoint(&self) -> &str {
        &self.relay_endpoint
    }

    /// TCP connect plus relay registration latency.
    pub fn connect_latency_ms(&self) -> u64 {
        self.connect_latency_ms
    }

    /// Send a single encrypted packet through the relay.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<()> {
        self.client
            .lock()
            .await
            .send_data(&packet.peer_id, &packet.wire_bytes)
            .await
            .map_err(|e| {
                DaemonError::Relay(format!(
                    "relay send to peer {} via {} failed: {e}",
                    packet.peer_id, self.relay_endpoint
                ))
            })?;

        self.peers
            .set_relay(&packet.peer_id, &self.relay_endpoint)
            .await;
        self.peers
            .record_sent(&packet.peer_id, packet.wire_bytes.len() as u64)
            .await;
        debug!(
            "Sent {} encrypted bytes to peer {} through relay {}",
            packet.wire_bytes.len(),
            packet.peer_id,
            self.relay_endpoint
        );
        Ok(())
    }

    /// Convert relay messages into inbound encrypted datagrams for WireGuard.
    pub async fn run_inbound(
        self,
        mut relay_rx: mpsc::UnboundedReceiver<RelayMessage>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        while let Some(message) = relay_rx.recv().await {
            if message.from_node.is_empty() {
                debug!(
                    "Ignoring relay control message from {}: {} bytes",
                    self.relay_endpoint,
                    message.data.len()
                );
                continue;
            }

            self.peers
                .record_relay_success(&message.from_node, &self.relay_endpoint, false)
                .await;
            inbound_tx
                .send(ReceivedEncryptedPacket {
                    source: None,
                    wire_bytes: message.data,
                })
                .await
                .map_err(|_| {
                    DaemonError::Network("relay inbound packet channel closed".to_string())
                })?;
        }

        warn!("Relay inbound stream from {} ended", self.relay_endpoint);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use p2pnet_relay::RelayServer;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::{ConnectionState, PeerManager};

    fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: virtual_ip.to_string(),
            online: true,
            last_seen: 0,
        }
    }

    fn peer_manager() -> Arc<PeerManager> {
        Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ))
    }

    #[tokio::test]
    async fn relay_transport_sends_encrypted_datagrams() {
        let server = RelayServer::start_random().await.unwrap();
        let relay_endpoint = server.addr.to_string();

        let peers_a = peer_manager();
        let peers_b = peer_manager();
        peers_a.add_peer(&peer("node-b", "10.20.0.2")).await;
        peers_b.add_peer(&peer("node-a", "10.20.0.1")).await;

        let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers_a.clone())
            .await
            .unwrap();
        let (relay_b, rx_b) = RelayTransport::connect(&relay_endpoint, "node-b", peers_b.clone())
            .await
            .unwrap();

        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let inbound_worker = tokio::spawn(relay_b.run_inbound(rx_b, inbound_tx));

        let payload = vec![4, 1, 2, 3, 4, 5];
        relay_a
            .send_packet(&EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await
            .unwrap();

        let received = timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.source, None);
        assert_eq!(received.wire_bytes, payload);

        let conn_a = peers_a.get_connection("node-b").await.unwrap();
        assert_eq!(conn_a.state, ConnectionState::Relay);
        assert_eq!(conn_a.relay_server, Some(relay_endpoint.clone()));

        let conn_b = peers_b.get_connection("node-a").await.unwrap();
        assert_eq!(conn_b.state, ConnectionState::Relay);
        assert_eq!(conn_b.relay_server, Some(relay_endpoint));

        inbound_worker.abort();
        server.shutdown().await;
    }

    #[test]
    fn relay_candidate_parses_region_and_legacy_endpoint() {
        let preferred = vec!["cn-east".to_string()];
        let regional = parse_candidate(0, "cn-east@127.0.0.1:8080", &preferred).unwrap();
        assert_eq!(regional.region, "cn-east");
        assert_eq!(regional.endpoint, "127.0.0.1:8080");
        assert_eq!(regional.preference_rank, 0);

        let legacy = parse_candidate(1, "127.0.0.1:8081", &preferred).unwrap();
        assert_eq!(legacy.region, "default");
        assert_eq!(legacy.endpoint, "127.0.0.1:8081");
        assert_eq!(legacy.preference_rank, 1);
    }

    #[tokio::test]
    async fn relay_selector_prefers_configured_region() {
        let east = RelayServer::start_random().await.unwrap();
        let west = RelayServer::start_random().await.unwrap();
        let specs = vec![format!("east@{}", east.addr), format!("west@{}", west.addr)];

        let outcome = select_relay(
            &specs,
            &["west".to_string()],
            Duration::from_secs(1),
            "node-a",
            peer_manager(),
        )
        .await;

        let transport = outcome.transport.as_ref().unwrap();
        assert_eq!(transport.region(), "west");
        assert_eq!(transport.endpoint(), west.addr.to_string());
        assert_eq!(outcome.diagnostics.selected_region.as_deref(), Some("west"));
        assert_eq!(outcome.diagnostics.candidates.len(), 2);
        assert!(outcome
            .diagnostics
            .candidates
            .iter()
            .all(|c| c.error.is_none()));

        drop(outcome);
        east.shutdown().await;
        west.shutdown().await;
    }

    #[tokio::test]
    async fn relay_selector_falls_back_when_preferred_region_is_unreachable() {
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let fallback = RelayServer::start_random().await.unwrap();
        let specs = vec![
            format!("preferred@{dead_addr}"),
            format!("fallback@{}", fallback.addr),
        ];

        let outcome = select_relay(
            &specs,
            &["preferred".to_string()],
            Duration::from_secs(1),
            "node-a",
            peer_manager(),
        )
        .await;

        let transport = outcome.transport.as_ref().unwrap();
        assert_eq!(transport.region(), "fallback");
        assert_eq!(transport.endpoint(), fallback.addr.to_string());
        assert!(outcome.diagnostics.candidates[0].error.is_some());
        assert!(outcome.diagnostics.candidates[1].error.is_none());
        assert_eq!(outcome.diagnostics.last_error, None);

        drop(outcome);
        fallback.shutdown().await;
    }
}
