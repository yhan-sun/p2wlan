//! Peer connection manager.
//!
//! Manages connections to other nodes in the virtual network:
//! - Tracks active peer tunnels (WireGuard sessions)
//! - Handles ICE candidate exchange for NAT traversal
//! - Falls back to relay when direct connection fails
//! - Routes packets between TUN device and peer tunnels

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

use crate::config::Config;
use crate::control::PeerInfo;

// ============================================================
// Connection State
// ============================================================

/// The state of a peer connection attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectionState {
    /// No connection attempted yet.
    Idle,
    /// Currently performing NAT detection / ICE candidate gathering.
    Connecting,
    /// Attempting UDP hole punching.
    HolePunching,
    /// Direct P2P connection established.
    Direct,
    /// Direct connection failed, falling back to relay.
    FallbackToRelay,
    /// Connected via relay server.
    Relay,
    /// Connection failed.
    Failed,
    /// Connection closed.
    Closed,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Connecting => write!(f, "connecting"),
            Self::HolePunching => write!(f, "hole_punching"),
            Self::Direct => write!(f, "direct"),
            Self::FallbackToRelay => write!(f, "fallback_to_relay"),
            Self::Relay => write!(f, "relay"),
            Self::Failed => write!(f, "failed"),
            Self::Closed => write!(f, "closed"),
        }
    }
}

// ============================================================
// Peer Connection
// ============================================================

/// Information about a connection to a specific peer.
#[derive(Debug, Clone)]
pub struct PeerConnection {
    /// Peer node ID.
    pub node_id: String,
    /// Peer's virtual IP.
    pub virtual_ip: String,
    /// Peer's public endpoint (ip:port) if known.
    pub endpoint: Option<SocketAddr>,
    /// Peer's NAT type.
    pub nat_type: String,
    /// Current connection state.
    pub state: ConnectionState,
    /// When the connection was established.
    pub connected_at: Option<Instant>,
    /// Bytes sent to this peer.
    pub bytes_sent: u64,
    /// Bytes received from this peer.
    pub bytes_received: u64,
    /// Which relay server is being used (if connected via relay).
    pub relay_server: Option<String>,
    /// ICE candidates for this peer.
    pub candidates: Vec<String>,
}

impl PeerConnection {
    /// Create a new peer connection in Idle state.
    pub fn new(node_id: &str, virtual_ip: &str) -> Self {
        Self {
            node_id: node_id.to_string(),
            virtual_ip: virtual_ip.to_string(),
            endpoint: None,
            nat_type: String::new(),
            state: ConnectionState::Idle,
            connected_at: None,
            bytes_sent: 0,
            bytes_received: 0,
            relay_server: None,
            candidates: Vec::new(),
        }
    }

    /// Whether the connection is active (direct or relay).
    pub fn is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Direct | ConnectionState::Relay)
    }

    /// Whether the connection is via relay.
    pub fn is_relay(&self) -> bool {
        self.state == ConnectionState::Relay
    }

    /// Transition to a new state.
    pub fn transition(&mut self, new_state: ConnectionState) {
        info!(
            "Peer {} state: {} → {}",
            self.node_id, self.state, new_state
        );
        if new_state == ConnectionState::Direct || new_state == ConnectionState::Relay {
            self.connected_at = Some(Instant::now());
        }
        self.state = new_state;
    }

    /// Record bytes sent.
    pub fn record_sent(&mut self, n: u64) {
        self.bytes_sent += n;
    }

    /// Record bytes received.
    pub fn record_received(&mut self, n: u64) {
        self.bytes_received += n;
    }
}

// ============================================================
// Peer Manager
// ============================================================

/// Manages all peer connections.
pub struct PeerManager {
    /// Active peer connections, indexed by node ID.
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    /// Virtual IP → node ID mapping for routing.
    ip_to_node: Arc<RwLock<HashMap<String, String>>>,
    /// Configuration.
    _config: Config,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new(config: Config) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            ip_to_node: Arc::new(RwLock::new(HashMap::new())),
            _config: config,
        }
    }

    /// Add or update a peer from control plane info.
    pub async fn add_peer(&self, info: &PeerInfo) {
        let mut conns = self.connections.write().await;
        let mut ip_map = self.ip_to_node.write().await;

        let conn = conns
            .entry(info.node_id.clone())
            .or_insert_with(|| PeerConnection::new(&info.node_id, &info.virtual_ip));

        conn.virtual_ip = info.virtual_ip.clone();
        conn.nat_type = info.nat_type.clone();
        if let Ok(addr) = info.endpoint.parse::<SocketAddr>() {
            conn.endpoint = Some(addr);
        }

        ip_map.insert(info.virtual_ip.clone(), info.node_id.clone());
    }

    /// Remove a peer.
    pub async fn remove_peer(&self, node_id: &str) {
        let mut conns = self.connections.write().await;
        if let Some(conn) = conns.remove(node_id) {
            let mut ip_map = self.ip_to_node.write().await;
            ip_map.remove(&conn.virtual_ip);
        }
    }

    /// Get a peer connection by node ID.
    pub async fn get_connection(&self, node_id: &str) -> Option<PeerConnection> {
        self.connections.read().await.get(node_id).cloned()
    }

    /// Look up the node ID for a virtual IP.
    pub async fn resolve_virtual_ip(&self, virtual_ip: &str) -> Option<String> {
        self.ip_to_node.read().await.get(virtual_ip).cloned()
    }

    /// Update a peer's connection state.
    pub async fn update_state(&self, node_id: &str, state: ConnectionState) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.transition(state);
        }
    }

    /// Add ICE candidates for a peer.
    pub async fn add_candidates(&self, node_id: &str, candidates: &[String]) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            for c in candidates {
                if !conn.candidates.contains(c) {
                    conn.candidates.push(c.clone());
                }
            }

            if conn.endpoint.is_none() {
                conn.endpoint = conn
                    .candidates
                    .iter()
                    .find_map(|candidate| candidate.parse::<SocketAddr>().ok());
            }
        }
    }

    /// Set the relay server for a peer.
    pub async fn set_relay(&self, node_id: &str, relay_server: &str) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.relay_server = Some(relay_server.to_string());
            conn.transition(ConnectionState::Relay);
        }
    }

    /// Record bytes sent to a peer.
    pub async fn record_sent(&self, node_id: &str, n: u64) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_sent(n);
        }
    }

    /// Record bytes received from a peer.
    pub async fn record_received(&self, node_id: &str, n: u64) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.record_received(n);
        }
    }

    /// Get all active connections.
    pub async fn active_connections(&self) -> Vec<PeerConnection> {
        self.connections
            .read()
            .await
            .values()
            .filter(|c| c.is_active())
            .cloned()
            .collect()
    }

    /// Get all connections (including inactive).
    pub async fn all_connections(&self) -> Vec<PeerConnection> {
        self.connections.read().await.values().cloned().collect()
    }

    /// Get connection statistics.
    pub async fn stats(&self) -> PeerManagerStats {
        let conns = self.connections.read().await;
        let total = conns.len();
        let direct = conns
            .values()
            .filter(|c| c.state == ConnectionState::Direct)
            .count();
        let relay = conns
            .values()
            .filter(|c| c.state == ConnectionState::Relay)
            .count();
        let total_bytes_sent = conns.values().map(|c| c.bytes_sent).sum();
        let total_bytes_received = conns.values().map(|c| c.bytes_received).sum();

        PeerManagerStats {
            total_peers: total,
            direct_connections: direct,
            relay_connections: relay,
            total_bytes_sent,
            total_bytes_received,
        }
    }
}

/// Aggregate statistics for the peer manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerManagerStats {
    pub total_peers: usize,
    pub direct_connections: usize,
    pub relay_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::generate_default("https://ctrl.test", "net1").unwrap()
    }

    #[test]
    fn test_connection_state_display() {
        assert_eq!(ConnectionState::Idle.to_string(), "idle");
        assert_eq!(ConnectionState::Direct.to_string(), "direct");
        assert_eq!(ConnectionState::Relay.to_string(), "relay");
    }

    #[test]
    fn test_peer_connection_new() {
        let conn = PeerConnection::new("peer1", "10.20.0.2");
        assert_eq!(conn.node_id, "peer1");
        assert_eq!(conn.virtual_ip, "10.20.0.2");
        assert!(!conn.is_active());
        assert!(!conn.is_relay());
    }

    #[test]
    fn test_peer_connection_transition() {
        let mut conn = PeerConnection::new("peer1", "10.20.0.2");
        assert_eq!(conn.state, ConnectionState::Idle);

        conn.transition(ConnectionState::Connecting);
        assert_eq!(conn.state, ConnectionState::Connecting);
        assert!(conn.connected_at.is_none());

        conn.transition(ConnectionState::Direct);
        assert!(conn.is_active());
        assert!(!conn.is_relay());
        assert!(conn.connected_at.is_some());
    }

    #[test]
    fn test_peer_connection_relay() {
        let mut conn = PeerConnection::new("peer1", "10.20.0.2");
        conn.transition(ConnectionState::Relay);
        assert!(conn.is_active());
        assert!(conn.is_relay());
    }

    #[test]
    fn test_peer_connection_bytes() {
        let mut conn = PeerConnection::new("peer1", "10.20.0.2");
        conn.record_sent(100);
        conn.record_sent(50);
        conn.record_received(200);
        assert_eq!(conn.bytes_sent, 150);
        assert_eq!(conn.bytes_received, 200);
    }

    #[tokio::test]
    async fn test_peer_manager_add_remove() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };

        manager.add_peer(&peer_info).await;
        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.virtual_ip, "10.20.0.2");

        // Resolve virtual IP
        let node_id = manager.resolve_virtual_ip("10.20.0.2").await.unwrap();
        assert_eq!(node_id, "peer1");

        manager.remove_peer("peer1").await;
        assert!(manager.get_connection("peer1").await.is_none());
    }

    #[tokio::test]
    async fn test_peer_manager_candidates() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };

        manager.add_peer(&peer_info).await;
        manager
            .add_candidates(
                "peer1",
                &["10.0.0.1:5000".to_string(), "192.168.1.1:5000".to_string()],
            )
            .await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.candidates.len(), 2);
    }

    #[tokio::test]
    async fn test_peer_manager_selects_endpoint_from_candidates() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };

        manager.add_peer(&peer_info).await;
        manager
            .add_candidates(
                "peer1",
                &[
                    "not-a-socket".to_string(),
                    "127.0.0.1:51820".to_string(),
                    "10.0.0.1:51820".to_string(),
                ],
            )
            .await;

        let conn = manager.get_connection("peer1").await.unwrap();
        assert_eq!(conn.endpoint, Some("127.0.0.1:51820".parse().unwrap()));
    }

    #[tokio::test]
    async fn test_peer_manager_stats() {
        let config = test_config();
        let manager = PeerManager::new(config);

        // Add two peers
        for (id, ip) in [("p1", "10.20.0.2"), ("p2", "10.20.0.3")] {
            let peer_info = PeerInfo {
                node_id: id.to_string(),
                public_key: "pk".to_string(),
                endpoint: "1.2.3.4:5000".to_string(),
                nat_type: "FullCone".to_string(),
                virtual_ip: ip.to_string(),
                online: true,
                last_seen: 0,
            };
            manager.add_peer(&peer_info).await;
        }

        manager.update_state("p1", ConnectionState::Direct).await;
        manager.update_state("p2", ConnectionState::Relay).await;

        manager.record_sent("p1", 1000).await;
        manager.record_received("p2", 500).await;

        let stats = manager.stats().await;
        assert_eq!(stats.total_peers, 2);
        assert_eq!(stats.direct_connections, 1);
        assert_eq!(stats.relay_connections, 1);
        assert_eq!(stats.total_bytes_sent, 1000);
        assert_eq!(stats.total_bytes_received, 500);
    }

    #[tokio::test]
    async fn test_peer_manager_active_connections() {
        let config = test_config();
        let manager = PeerManager::new(config);

        let peer_info = PeerInfo {
            node_id: "peer1".to_string(),
            public_key: "pk".to_string(),
            endpoint: "1.2.3.4:5000".to_string(),
            nat_type: "FullCone".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
        };
        manager.add_peer(&peer_info).await;

        // Initially no active connections
        assert!(manager.active_connections().await.is_empty());

        manager.update_state("peer1", ConnectionState::Direct).await;
        assert_eq!(manager.active_connections().await.len(), 1);
    }
}
