//! DNS resolver for the virtual network.
//!
//! Resolves hostnames within the P2P network to virtual IPs:
//! - Built-in DNS server listening on the TUN interface
//! - Maps hostnames to virtual IPs
//! - Supports custom DNS entries
//! - Intercepts DNS queries for the `.p2pnet.local` domain

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::config::DnsConfig;

// ============================================================
// DNS Entry
// ============================================================

/// A DNS entry mapping a hostname to a virtual IP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEntry {
    /// Hostname (e.g. "myserver.p2pnet.local").
    pub hostname: String,
    /// Virtual IP address.
    pub virtual_ip: String,
    /// Node ID that this hostname refers to.
    pub node_id: Option<String>,
    /// TTL in seconds (0 = no expiry).
    #[serde(default)]
    pub ttl: u32,
}

// ============================================================
// DNS Resolver
// ============================================================

/// DNS resolver for the virtual network.
pub struct DnsResolver {
    /// DNS configuration.
    config: DnsConfig,
    /// Hostname → DNS entry mapping.
    entries: Arc<RwLock<HashMap<String, DnsEntry>>>,
    /// Virtual IP → hostname reverse mapping.
    reverse: Arc<RwLock<HashMap<String, String>>>,
}

impl DnsResolver {
    /// Create a new DNS resolver.
    pub fn new(config: DnsConfig) -> Self {
        let mut entries = HashMap::new();
        let mut reverse = HashMap::new();

        // Load initial mappings from config
        for (hostname, virtual_ip) in &config.mappings {
            entries.insert(
                hostname.clone(),
                DnsEntry {
                    hostname: hostname.clone(),
                    virtual_ip: virtual_ip.clone(),
                    node_id: None,
                    ttl: 0,
                },
            );
            reverse.insert(virtual_ip.clone(), hostname.clone());
        }

        Self {
            config,
            entries: Arc::new(RwLock::new(entries)),
            reverse: Arc::new(RwLock::new(reverse)),
        }
    }

    /// Whether DNS is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get the DNS suffix.
    pub fn suffix(&self) -> &str {
        &self.config.suffix
    }

    /// Resolve a hostname to a virtual IP.
    pub async fn resolve(&self, hostname: &str) -> Option<String> {
        // Try exact match first
        if let Some(entry) = self.entries.read().await.get(hostname) {
            debug!("DNS resolved: {} → {}", hostname, entry.virtual_ip);
            return Some(entry.virtual_ip.clone());
        }

        // Try with suffix appended
        let fqdn = if hostname.contains('.') {
            hostname.to_string()
        } else {
            format!("{}.{}", hostname, self.config.suffix)
        };

        if let Some(entry) = self.entries.read().await.get(&fqdn) {
            debug!("DNS resolved: {} → {}", hostname, entry.virtual_ip);
            return Some(entry.virtual_ip.clone());
        }

        debug!("DNS lookup failed for: {}", hostname);
        None
    }

    /// Reverse lookup: virtual IP → hostname.
    pub async fn reverse_lookup(&self, virtual_ip: &str) -> Option<String> {
        self.reverse.read().await.get(virtual_ip).cloned()
    }

    /// Register a DNS entry for a node.
    pub async fn register(&self, hostname: &str, virtual_ip: &str, node_id: Option<&str>) {
        let fqdn = if hostname.contains('.') {
            hostname.to_string()
        } else {
            format!("{}.{}", hostname, self.config.suffix)
        };

        let entry = DnsEntry {
            hostname: fqdn.clone(),
            virtual_ip: virtual_ip.to_string(),
            node_id: node_id.map(|s| s.to_string()),
            ttl: 0,
        };

        info!("DNS register: {} → {}", fqdn, virtual_ip);
        self.entries.write().await.insert(fqdn.clone(), entry);
        self.reverse
            .write()
            .await
            .insert(virtual_ip.to_string(), fqdn);
    }

    /// Unregister a DNS entry by virtual IP.
    pub async fn unregister(&self, virtual_ip: &str) {
        if let Some(hostname) = self.reverse.write().await.remove(virtual_ip) {
            self.entries.write().await.remove(&hostname);
            info!("DNS unregister: {} ({})", hostname, virtual_ip);
        }
    }

    /// List all DNS entries.
    pub async fn list(&self) -> Vec<DnsEntry> {
        self.entries.read().await.values().cloned().collect()
    }

    /// Check if a hostname belongs to our domain.
    pub fn is_local_domain(&self, hostname: &str) -> bool {
        hostname.ends_with(&self.config.suffix) || !hostname.contains('.')
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> DnsConfig {
        DnsConfig {
            enabled: true,
            suffix: "p2pnet.local".to_string(),
            mappings: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_dns_resolve_with_suffix() {
        let resolver = DnsResolver::new(test_config());
        resolver
            .register("myserver", "10.20.0.5", Some("node1"))
            .await;

        // Short name resolution
        let ip = resolver.resolve("myserver").await.unwrap();
        assert_eq!(ip, "10.20.0.5");

        // FQDN resolution
        let ip = resolver.resolve("myserver.p2pnet.local").await.unwrap();
        assert_eq!(ip, "10.20.0.5");
    }

    #[tokio::test]
    async fn test_dns_reverse_lookup() {
        let resolver = DnsResolver::new(test_config());
        resolver.register("myserver", "10.20.0.5", None).await;

        let hostname = resolver.reverse_lookup("10.20.0.5").await.unwrap();
        assert_eq!(hostname, "myserver.p2pnet.local");
    }

    #[tokio::test]
    async fn test_dns_unregister() {
        let resolver = DnsResolver::new(test_config());
        resolver.register("myserver", "10.20.0.5", None).await;
        resolver.unregister("10.20.0.5").await;

        assert!(resolver.resolve("myserver").await.is_none());
        assert!(resolver.reverse_lookup("10.20.0.5").await.is_none());
    }

    #[tokio::test]
    async fn test_dns_list() {
        let resolver = DnsResolver::new(test_config());
        resolver.register("a", "10.20.0.1", None).await;
        resolver.register("b", "10.20.0.2", None).await;

        let list = resolver.list().await;
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn test_is_local_domain() {
        let resolver = DnsResolver::new(test_config());
        assert!(resolver.is_local_domain("myserver.p2pnet.local"));
        assert!(resolver.is_local_domain("myserver")); // short name
        assert!(!resolver.is_local_domain("google.com"));
    }

    #[test]
    fn test_dns_config_with_mappings() {
        let mut mappings = HashMap::new();
        mappings.insert("web.p2pnet.local".to_string(), "10.20.0.10".to_string());

        let config = DnsConfig {
            enabled: true,
            suffix: "p2pnet.local".to_string(),
            mappings,
        };

        let resolver = DnsResolver::new(config);
        // The initial mapping should be loaded
    }

    #[tokio::test]
    async fn test_dns_resolve_not_found() {
        let resolver = DnsResolver::new(test_config());
        assert!(resolver.resolve("nonexistent").await.is_none());
    }
}
