//! Port mapping (FRP-like tunnel management).
//!
//! Allows exposing local services through the P2P network:
//! - Forward TCP connections from a public port to a local port
//! - Forward UDP traffic similarly
//! - Manage tunnel lifecycle (create, list, delete)
//!
//! ## Example
//!
//! ```text
//! localhost:8080  ←→  public:30000
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::info;

use crate::error::{DaemonError, Result};

// ============================================================
// Port Mapping Types
// ============================================================

/// Protocol for port mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "udp")]
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
        }
    }
}

impl std::str::FromStr for Protocol {
    type Err = DaemonError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(DaemonError::PortMapping(format!("unknown protocol: {s}"))),
        }
    }
}

/// A port mapping (tunnel) entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Unique tunnel ID.
    pub id: String,
    /// Protocol (TCP or UDP).
    pub protocol: Protocol,
    /// Local address to forward to.
    pub local_address: String,
    /// Local port.
    pub local_port: u16,
    /// Public port on the relay.
    pub remote_port: u16,
    /// Public endpoint (assigned by server).
    pub public_endpoint: Option<String>,
    /// Whether the tunnel is active.
    pub active: bool,
    /// When the tunnel was created.
    pub created_at: u64,
    /// Bytes forwarded.
    pub bytes_forwarded: u64,
}

impl PortMapping {
    /// Create a new port mapping.
    pub fn new(protocol: Protocol, local_address: &str, local_port: u16, remote_port: u16) -> Self {
        Self {
            id: format!("tunnel-{}-{}-{}", protocol, local_port, remote_port),
            protocol,
            local_address: local_address.to_string(),
            local_port,
            remote_port,
            public_endpoint: None,
            active: false,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            bytes_forwarded: 0,
        }
    }

    /// Get the local socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        format!("{}:{}", self.local_address, self.local_port)
            .parse()
            .map_err(|e| DaemonError::PortMapping(format!("invalid local address: {e}")))
    }
}

// ============================================================
// Port Mapping Manager
// ============================================================

/// Manages all port mappings.
#[derive(Default)]
pub struct PortMappingManager {
    /// Active mappings by tunnel ID.
    mappings: Arc<RwLock<HashMap<String, PortMapping>>>,
}

impl PortMappingManager {
    /// Create a new port mapping manager.
    pub fn new() -> Self {
        Self {
            mappings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a new port mapping.
    pub async fn create(&self, mapping: PortMapping) -> Result<()> {
        let mut mappings = self.mappings.write().await;
        if mappings.contains_key(&mapping.id) {
            return Err(DaemonError::PortMapping(format!(
                "tunnel {} already exists",
                mapping.id
            )));
        }
        info!(
            "Creating port mapping: {} ({}:{} → :{})",
            mapping.id, mapping.local_address, mapping.local_port, mapping.remote_port
        );
        mappings.insert(mapping.id.clone(), mapping);
        Ok(())
    }

    /// Activate a mapping after server confirmation.
    pub async fn activate(&self, tunnel_id: &str, public_endpoint: &str) -> Result<()> {
        let mut mappings = self.mappings.write().await;
        if let Some(m) = mappings.get_mut(tunnel_id) {
            m.active = true;
            m.public_endpoint = Some(public_endpoint.to_string());
            info!("Activated tunnel {} → {}", tunnel_id, public_endpoint);
            Ok(())
        } else {
            Err(DaemonError::PortMapping(format!(
                "tunnel {tunnel_id} not found"
            )))
        }
    }

    /// Remove a port mapping.
    pub async fn delete(&self, tunnel_id: &str) -> Result<()> {
        let mut mappings = self.mappings.write().await;
        if mappings.remove(tunnel_id).is_some() {
            info!("Deleted tunnel {}", tunnel_id);
            Ok(())
        } else {
            Err(DaemonError::PortMapping(format!(
                "tunnel {tunnel_id} not found"
            )))
        }
    }

    /// List all mappings.
    pub async fn list(&self) -> Vec<PortMapping> {
        self.mappings.read().await.values().cloned().collect()
    }

    /// List only active mappings.
    pub async fn active_mappings(&self) -> Vec<PortMapping> {
        self.mappings
            .read()
            .await
            .values()
            .filter(|m| m.active)
            .cloned()
            .collect()
    }

    /// Get a mapping by ID.
    pub async fn get(&self, tunnel_id: &str) -> Option<PortMapping> {
        self.mappings.read().await.get(tunnel_id).cloned()
    }

    /// Record bytes forwarded through a tunnel.
    pub async fn record_forwarded(&self, tunnel_id: &str, bytes: u64) {
        if let Some(m) = self.mappings.write().await.get_mut(tunnel_id) {
            m.bytes_forwarded += bytes;
        }
    }

    /// Get aggregate stats.
    pub async fn stats(&self) -> PortMappingStats {
        let mappings = self.mappings.read().await;
        let total = mappings.len();
        let active = mappings.values().filter(|m| m.active).count();
        let total_bytes = mappings.values().map(|m| m.bytes_forwarded).sum();
        PortMappingStats {
            total,
            active,
            total_bytes_forwarded: total_bytes,
        }
    }
}

/// Port mapping statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMappingStats {
    pub total: usize,
    pub active: usize,
    pub total_bytes_forwarded: u64,
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_from_str() {
        assert_eq!("tcp".parse::<Protocol>().unwrap(), Protocol::Tcp);
        assert_eq!("UDP".parse::<Protocol>().unwrap(), Protocol::Udp);
        assert!("icmp".parse::<Protocol>().is_err());
    }

    #[test]
    fn test_port_mapping_new() {
        let m = PortMapping::new(Protocol::Tcp, "127.0.0.1", 8080, 30000);
        assert_eq!(m.protocol, Protocol::Tcp);
        assert_eq!(m.local_port, 8080);
        assert_eq!(m.remote_port, 30000);
        assert!(!m.active);
        assert!(m.public_endpoint.is_none());
    }

    #[test]
    fn test_port_mapping_local_addr() {
        let m = PortMapping::new(Protocol::Tcp, "127.0.0.1", 8080, 30000);
        let addr = m.local_addr().unwrap();
        assert_eq!(addr.port(), 8080);
    }

    #[tokio::test]
    async fn test_port_mapping_manager_create_delete() {
        let manager = PortMappingManager::new();
        let m = PortMapping::new(Protocol::Tcp, "127.0.0.1", 8080, 30000);
        let id = m.id.clone();

        manager.create(m).await.unwrap();
        assert!(manager.get(&id).await.is_some());

        manager.delete(&id).await.unwrap();
        assert!(manager.get(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_port_mapping_manager_activate() {
        let manager = PortMappingManager::new();
        let m = PortMapping::new(Protocol::Tcp, "127.0.0.1", 8080, 30000);
        let id = m.id.clone();

        manager.create(m).await.unwrap();
        manager
            .activate(&id, "public.example.com:30000")
            .await
            .unwrap();

        let m = manager.get(&id).await.unwrap();
        assert!(m.active);
        assert_eq!(
            m.public_endpoint,
            Some("public.example.com:30000".to_string())
        );
    }

    #[tokio::test]
    async fn test_port_mapping_manager_duplicate() {
        let manager = PortMappingManager::new();
        let m = PortMapping::new(Protocol::Tcp, "127.0.0.1", 8080, 30000);

        manager.create(m.clone()).await.unwrap();
        assert!(manager.create(m).await.is_err());
    }

    #[tokio::test]
    async fn test_port_mapping_manager_list() {
        let manager = PortMappingManager::new();
        manager
            .create(PortMapping::new(Protocol::Tcp, "127.0.0.1", 8080, 30000))
            .await
            .unwrap();
        manager
            .create(PortMapping::new(Protocol::Udp, "127.0.0.1", 9090, 30001))
            .await
            .unwrap();

        let list = manager.list().await;
        assert_eq!(list.len(), 2);

        let active = manager.active_mappings().await;
        assert!(active.is_empty());
    }

    #[tokio::test]
    async fn test_port_mapping_manager_stats() {
        let manager = PortMappingManager::new();
        let m = PortMapping::new(Protocol::Tcp, "127.0.0.1", 8080, 30000);
        let id = m.id.clone();

        manager.create(m).await.unwrap();
        manager.activate(&id, "public:30000").await.unwrap();
        manager.record_forwarded(&id, 1024).await;

        let stats = manager.stats().await;
        assert_eq!(stats.total, 1);
        assert_eq!(stats.active, 1);
        assert_eq!(stats.total_bytes_forwarded, 1024);
    }
}
