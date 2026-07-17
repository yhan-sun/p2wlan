//! Node configuration management.
//!
//! Handles loading/saving node configuration including:
//! - Node identity (key pair, node ID)
//! - Network settings (virtual IP, MTU, CIDR)
//! - Control server endpoint
//! - Relay servers
//! - Port mappings

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

use crate::error::{DaemonError, Result};

// ============================================================
// Configuration
// ============================================================

/// Full daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// File path this config was loaded from (not serialized).
    #[serde(skip)]
    pub config_path: Option<std::path::PathBuf>,
    /// Node identity.
    pub node: NodeConfig,
    /// Network settings.
    pub network: NetworkConfig,
    /// Control plane connection.
    pub control: ControlConfig,
    /// Relay configuration.
    pub relay: RelayConfig,
    /// Local diagnostics endpoint configuration.
    #[serde(default)]
    pub diagnostics: DiagnosticsConfig,
    /// Port mappings.
    #[serde(default)]
    pub port_mappings: Vec<PortMappingConfig>,
    /// DNS configuration.
    #[serde(default)]
    pub dns: DnsConfig,
    /// ACL rules.
    #[serde(default)]
    pub acl: AclConfig,
}

/// Node identity configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// This node's ID (hex, derived from public key).
    pub node_id: String,
    /// X25519 public key (hex).
    pub public_key: String,
    /// X25519 private key (hex, stored encrypted in production).
    pub private_key: String,
    /// Human-readable device name.
    #[serde(default = "default_device_name")]
    pub device_name: String,
    /// Platform string.
    #[serde(default = "default_platform")]
    pub platform: String,
    /// Ed25519 public key (hex) for device identity signing.
    #[serde(default)]
    pub ed25519_public_key: String,
    /// Ed25519 private key (hex) — do NOT log this value.
    #[serde(default)]
    pub ed25519_private_key: String,
}

fn default_device_name() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn default_platform() -> String {
    std::env::consts::OS.to_string()
}

/// Virtual network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network ID to join.
    pub network_id: String,
    /// Whether to run in manual/offline mode.
    #[serde(default)]
    pub manual: bool,
    /// Assigned virtual IPv4 address.
    pub virtual_ip: String,
    /// Network CIDR (e.g. "10.20.0.0/16").
    #[serde(default = "default_cidr")]
    pub cidr: String,
    /// Optional IPv6 CIDR.
    pub ipv6_cidr: Option<String>,
    /// MTU for the TUN interface.
    #[serde(default = "default_mtu")]
    pub mtu: u32,
    /// Subnet mask.
    #[serde(default = "default_netmask")]
    pub netmask: String,
    /// TUN interface name.
    #[serde(default = "default_interface")]
    pub interface: String,
    /// Local UDP bind address for direct peer transport.
    #[serde(default = "default_udp_bind")]
    pub udp_bind: String,
    /// Optional endpoint advertised to peers when it differs from the local bind address.
    #[serde(default)]
    pub udp_advertise: Option<String>,
    /// STUN servers used to discover server-reflexive UDP candidates.
    #[serde(default)]
    pub stun_servers: Vec<String>,
    /// Timeout for each STUN query in milliseconds.
    #[serde(default = "default_stun_timeout_ms")]
    pub stun_timeout_ms: u64,
    /// Interval between active UDP hole-punch probes in milliseconds.
    #[serde(default = "default_punch_interval_ms")]
    pub punch_interval_ms: u64,
    /// Number of active probe rounds sent to each peer candidate.
    #[serde(default = "default_punch_attempts")]
    pub punch_attempts: u32,
    /// Periodic direct-path NAT keepalive interval in seconds.
    #[serde(default = "default_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,
}

fn default_cidr() -> String {
    "10.20.0.0/16".to_string()
}
fn default_mtu() -> u32 {
    1420
}
fn default_netmask() -> String {
    "255.255.0.0".to_string()
}
fn default_interface() -> String {
    "p2pnet0".to_string()
}
fn default_udp_bind() -> String {
    "0.0.0.0:0".to_string()
}
fn default_stun_timeout_ms() -> u64 {
    1500
}
fn default_punch_interval_ms() -> u64 {
    200
}
fn default_punch_attempts() -> u32 {
    10
}
fn default_keepalive_interval_secs() -> u64 {
    25
}

/// Control plane server configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Control server URL (e.g. "https://control.p2pnet.io:443").
    pub server_url: String,
    /// User authentication token (JWT) obtained after login/register.
    pub auth_token: String,
    /// Device credential token for API authentication (replaces user JWT
    /// for device-level operations after Ed25519 challenge is completed).
    #[serde(default)]
    pub device_credential: String,
    /// Whether the device credential has been issued.
    #[serde(default)]
    pub credential_issued: bool,
    /// Reconnect interval in seconds.
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_secs: u64,
    /// Heartbeat interval in seconds.
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
}

fn default_reconnect_interval() -> u64 {
    5
}
fn default_heartbeat_interval() -> u64 {
    30
}

/// Relay configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Relay candidates as `region@endpoint` or backward-compatible `endpoint` values.
    pub servers: Vec<String>,
    /// Region labels to prefer, in priority order. Empty means latency-only selection.
    #[serde(default)]
    pub preferred_regions: Vec<String>,
    /// Maximum time allowed for each concurrent relay connection attempt (ms).
    #[serde(default = "default_relay_selection_timeout")]
    pub selection_timeout_ms: u64,
    /// Whether to prefer direct P2P over relay.
    #[serde(default = "default_true")]
    pub prefer_direct: bool,
    /// Timeout for direct connection attempt before falling back to relay (ms).
    #[serde(default = "default_relay_timeout")]
    pub fallback_timeout_ms: u64,
}

fn default_true() -> bool {
    true
}
fn default_relay_timeout() -> u64 {
    5000
}
fn default_relay_selection_timeout() -> u64 {
    3000
}

/// Local diagnostics HTTP endpoint configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticsConfig {
    /// Whether to expose the local diagnostics HTTP endpoint.
    #[serde(default)]
    pub enabled: bool,
    /// Local bind address for diagnostics. Keep this on loopback.
    #[serde(default = "default_diagnostics_bind")]
    pub bind: String,
}

fn default_diagnostics_bind() -> String {
    "127.0.0.1:39277".to_string()
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_diagnostics_bind(),
        }
    }
}

/// Port mapping configuration (FRP-like).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMappingConfig {
    /// Unique mapping ID.
    pub id: String,
    /// Protocol: "tcp" or "udp".
    pub protocol: String,
    /// Local address to forward to.
    #[serde(default = "default_local_addr")]
    pub local_address: String,
    /// Local port.
    pub local_port: u16,
    /// Remote (public) port on the relay.
    pub remote_port: u16,
    /// Whether the mapping is active.
    #[serde(default)]
    pub active: bool,
}

fn default_local_addr() -> String {
    "127.0.0.1".to_string()
}

/// DNS configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether to enable the built-in DNS resolver.
    #[serde(default)]
    pub enabled: bool,
    /// DNS domain suffix (e.g. "p2pnet.local").
    #[serde(default = "default_dns_suffix")]
    pub suffix: String,
    /// Custom DNS mappings (hostname → virtual IP).
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, String>,
}

fn default_dns_suffix() -> String {
    "p2pnet.local".to_string()
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            suffix: default_dns_suffix(),
            mappings: std::collections::HashMap::new(),
        }
    }
}

/// ACL (Access Control List) configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    /// Whether ACL is enabled.
    #[serde(default)]
    pub enabled: bool,
    /// ACL rules.
    #[serde(default)]
    pub rules: Vec<AclRule>,
}

/// A single ACL rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    /// Rule action: "allow" or "deny".
    pub action: String,
    /// Source node ID or "*" for any.
    pub src: String,
    /// Destination node ID or "*" for any.
    pub dst: String,
    /// Protocol: "tcp", "udp", "icmp", or "*" for any.
    #[serde(default = "default_wildcard")]
    pub proto: String,
    /// Destination port range (e.g. "22", "80-443", "*").
    #[serde(default = "default_wildcard")]
    pub port: String,
}

fn default_wildcard() -> String {
    "*".to_string()
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            rules: vec![AclRule {
                action: "allow".to_string(),
                src: "*".to_string(),
                dst: "*".to_string(),
                proto: "*".to_string(),
                port: "*".to_string(),
            }],
        }
    }
}

// ============================================================
// Config loading / saving
// ============================================================

impl Config {
    /// Load configuration from a JSON file.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| DaemonError::Config(format!("failed to read config: {e}")))?;
        let config: Config = serde_json::from_str(&content)
            .map_err(|e| DaemonError::Config(format!("failed to parse config: {e}")))?;
        Ok(config)
    }

    /// Save configuration to a JSON file using atomic write (temp + rename)
    /// and sets 0600 permissions on Unix.
    pub fn save_to_file(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| DaemonError::Config(format!("failed to serialize config: {e}")))?;

        // Write to temp file first for atomicity
        let tmp_path = path.with_extension("tmp");
        let mut file = std::fs::File::create(&tmp_path)
            .map_err(|e| DaemonError::Config(format!("failed to create temp config: {e}")))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file
                .metadata()
                .map_err(|e| {
                    DaemonError::Config(format!("failed to get temp config metadata: {e}"))
                })?
                .permissions();
            perms.set_mode(0o600);
            file.set_permissions(perms).map_err(|e| {
                DaemonError::Config(format!("failed to set config permissions: {e}"))
            })?;
        }

        file.write_all(content.as_bytes())
            .map_err(|e| DaemonError::Config(format!("failed to write temp config: {e}")))?;

        file.sync_all()
            .map_err(|e| DaemonError::Config(format!("failed to sync temp config: {e}")))?;
        drop(file);

        std::fs::rename(&tmp_path, path)
            .map_err(|e| DaemonError::Config(format!("failed to rename config: {e}")))?;

        Ok(())
    }

    /// Generate a default config with a new identity (X25519 + Ed25519).
    pub fn generate_default(control_url: &str, network_id: &str) -> Result<Self> {
        let identity = p2pnet_crypto::NodeIdentity::generate();
        let ed25519 = p2pnet_crypto::Ed25519KeyPair::generate();

        Ok(Self {
            config_path: None,
            node: NodeConfig {
                node_id: identity.node_id().to_string(),
                public_key: hex::encode(identity.public_key()),
                private_key: hex::encode(identity.private_key()),
                device_name: default_device_name(),
                platform: default_platform(),
                ed25519_public_key: hex::encode(ed25519.public_key()),
                ed25519_private_key: hex::encode(ed25519.private_key()),
            },
            network: NetworkConfig {
                network_id: network_id.to_string(),
                manual: false,
                virtual_ip: "10.20.0.1".to_string(),
                cidr: default_cidr(),
                ipv6_cidr: None,
                mtu: default_mtu(),
                netmask: default_netmask(),
                interface: default_interface(),
                udp_bind: default_udp_bind(),
                udp_advertise: None,
                stun_servers: Vec::new(),
                stun_timeout_ms: default_stun_timeout_ms(),
                punch_interval_ms: default_punch_interval_ms(),
                punch_attempts: default_punch_attempts(),
                keepalive_interval_secs: default_keepalive_interval_secs(),
            },
            control: ControlConfig {
                server_url: control_url.to_string(),
                auth_token: String::new(),
                device_credential: String::new(),
                credential_issued: false,
                reconnect_interval_secs: default_reconnect_interval(),
                heartbeat_interval_secs: default_heartbeat_interval(),
            },
            relay: RelayConfig {
                servers: vec![format!("{control_url}:8080")],
                preferred_regions: Vec::new(),
                selection_timeout_ms: default_relay_selection_timeout(),
                prefer_direct: true,
                fallback_timeout_ms: default_relay_timeout(),
            },
            diagnostics: DiagnosticsConfig::default(),
            port_mappings: Vec::new(),
            dns: DnsConfig::default(),
            acl: AclConfig::default(),
        })
    }
}

// ============================================================
// hostname helper (simple, no external dep)
// ============================================================

mod hostname {
    use std::ffi::OsString;

    pub fn get() -> Result<OsString, std::io::Error> {
        #[cfg(target_os = "windows")]
        {
            // Use COMPUTERNAME env var on Windows
            std::env::var_os("COMPUTERNAME").ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "COMPUTERNAME not set")
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            // Use gethostname crate or nix
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "hostname not implemented",
            ))
        }
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_generation() {
        let config = Config::generate_default("https://control.example.com", "net123").unwrap();
        assert!(!config.node.node_id.is_empty());
        assert!(!config.node.public_key.is_empty());
        assert_eq!(config.network.network_id, "net123");
        assert_eq!(config.network.mtu, 1420);
        assert!(config.relay.prefer_direct);
        assert!(config.relay.preferred_regions.is_empty());
        assert_eq!(config.relay.selection_timeout_ms, 3000);
        assert!(!config.diagnostics.enabled);
        assert_eq!(config.diagnostics.bind, "127.0.0.1:39277");
        assert!(config.port_mappings.is_empty());
    }

    #[test]
    fn test_config_serialization_roundtrip() {
        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let json = serde_json::to_string_pretty(&config).unwrap();
        let decoded: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.node.node_id, config.node.node_id);
        assert_eq!(decoded.network.virtual_ip, config.network.virtual_ip);
        assert_eq!(decoded.network.udp_bind, config.network.udp_bind);
        assert_eq!(decoded.network.udp_advertise, config.network.udp_advertise);
        assert_eq!(decoded.network.stun_servers, config.network.stun_servers);
        assert_eq!(
            decoded.network.stun_timeout_ms,
            config.network.stun_timeout_ms
        );
        assert_eq!(
            decoded.network.punch_interval_ms,
            config.network.punch_interval_ms
        );
        assert_eq!(
            decoded.network.punch_attempts,
            config.network.punch_attempts
        );
        assert_eq!(
            decoded.network.keepalive_interval_secs,
            config.network.keepalive_interval_secs
        );
        assert_eq!(decoded.diagnostics.enabled, config.diagnostics.enabled);
        assert_eq!(decoded.diagnostics.bind, config.diagnostics.bind);
        assert_eq!(
            decoded.relay.preferred_regions,
            config.relay.preferred_regions
        );
        assert_eq!(
            decoded.relay.selection_timeout_ms,
            config.relay.selection_timeout_ms
        );
    }

    #[test]
    fn test_config_backward_compatible_udp_endpoint_defaults() {
        // Old config without ed25519 keys should still deserialize
        let json = r#"{
            "node": {
                "node_id": "node1",
                "public_key": "pub",
                "private_key": "priv",
                "device_name": "dev",
                "platform": "linux"
            },
            "network": {
                "network_id": "net1",
                "virtual_ip": "10.20.0.1",
                "cidr": "10.20.0.0/16",
                "ipv6_cidr": null,
                "mtu": 1420,
                "netmask": "255.255.0.0",
                "interface": "p2pnet0"
            },
            "control": {
                "server_url": "http://ctrl",
                "auth_token": "",
                "reconnect_interval_secs": 5,
                "heartbeat_interval_secs": 30
            },
            "relay": {
                "servers": [],
                "prefer_direct": true,
                "fallback_timeout_ms": 5000
            }
        }"#;

        let decoded: Config = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.network.udp_bind, "0.0.0.0:0");
        assert_eq!(decoded.network.udp_advertise, None);
        assert!(decoded.network.stun_servers.is_empty());
        assert_eq!(decoded.network.stun_timeout_ms, 1500);
        assert_eq!(decoded.network.punch_interval_ms, 200);
        assert_eq!(decoded.network.punch_attempts, 10);
        assert_eq!(decoded.network.keepalive_interval_secs, 25);
        assert!(decoded.relay.preferred_regions.is_empty());
        assert_eq!(decoded.relay.selection_timeout_ms, 3000);
        assert!(!decoded.diagnostics.enabled);
        assert_eq!(decoded.diagnostics.bind, "127.0.0.1:39277");
    }

    #[test]
    fn test_config_save_load_roundtrip() {
        let dir = std::env::temp_dir().join("p2pnet_config_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_config.json");

        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.save_to_file(&path).unwrap();
        let loaded = Config::load_from_file(&path).unwrap();

        assert_eq!(loaded.node.node_id, config.node.node_id);
        assert_eq!(loaded.network.network_id, config.network.network_id);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_port_mapping_config() {
        let mapping = PortMappingConfig {
            id: "map1".to_string(),
            protocol: "tcp".to_string(),
            local_address: "127.0.0.1".to_string(),
            local_port: 8080,
            remote_port: 30000,
            active: true,
        };
        assert_eq!(mapping.protocol, "tcp");
        assert!(mapping.active);
    }

    #[test]
    fn test_acl_default_allows_all() {
        let acl = AclConfig::default();
        assert!(!acl.enabled);
        assert_eq!(acl.rules.len(), 1);
        assert_eq!(acl.rules[0].action, "allow");
        assert_eq!(acl.rules[0].src, "*");
    }

    #[test]
    fn test_dns_default() {
        let dns = DnsConfig::default();
        assert!(!dns.enabled);
        assert_eq!(dns.suffix, "p2pnet.local");
        assert!(dns.mappings.is_empty());
    }

    #[test]
    fn test_network_config_defaults() {
        let config = Config::generate_default("https://ctrl", "net1").unwrap();
        assert_eq!(config.network.cidr, "10.20.0.0/16");
        assert_eq!(config.network.mtu, 1420);
        assert_eq!(config.network.netmask, "255.255.0.0");
        assert_eq!(config.network.interface, "p2pnet0");
        assert_eq!(config.network.udp_bind, "0.0.0.0:0");
        assert_eq!(config.network.udp_advertise, None);
        assert!(config.network.stun_servers.is_empty());
        assert_eq!(config.network.stun_timeout_ms, 1500);
        assert_eq!(config.network.punch_interval_ms, 200);
        assert_eq!(config.network.punch_attempts, 10);
        assert_eq!(config.network.keepalive_interval_secs, 25);
    }
}
