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
#[derive(Clone, Serialize, Deserialize)]
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

fn redacted_presence(value: &str) -> &'static str {
    if value.trim().is_empty() {
        "[empty]"
    } else {
        "[redacted]"
    }
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("node_id", &self.node_id)
            .field("public_key", &self.public_key)
            .field("private_key", &redacted_presence(&self.private_key))
            .field("device_name", &self.device_name)
            .field("platform", &self.platform)
            .field("ed25519_public_key", &self.ed25519_public_key)
            .field(
                "ed25519_private_key",
                &redacted_presence(&self.ed25519_private_key),
            )
            .finish()
    }
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
    /// UDP observer endpoints. These speak STUN Binding and are queried alongside
    /// public STUN servers so relay/VM-side observers can expose destination-side
    /// mappings for linear symmetric NAT prediction.
    #[serde(default)]
    pub udp_observers: Vec<String>,
    /// Timeout for each STUN query in milliseconds.
    #[serde(default = "default_stun_timeout_ms")]
    pub stun_timeout_ms: u64,
    /// Enable outbound-UDP liveness diagnostics (legal DNS A query probe) when a
    /// ScatterExtended wide scan exhausts with zero matched ACKs.
    #[serde(default = "default_true")]
    pub udp_liveness_enabled: bool,
    /// Public DNS resolvers probed for outbound UDP reachability (ip:port).
    #[serde(default = "default_udp_liveness_targets")]
    pub udp_liveness_targets: Vec<String>,
    /// Per-target round timeout in milliseconds.
    #[serde(default = "default_udp_liveness_timeout_ms")]
    pub udp_liveness_timeout_ms: u32,
    /// How long a (peer, generation) verdict is cached before re-probing, ms.
    #[serde(default = "default_udp_liveness_ttl_ms")]
    pub udp_liveness_ttl_ms: u32,
    /// Number of parallel probe rounds (each fans out to all targets).
    #[serde(default = "default_udp_liveness_retries")]
    pub udp_liveness_retries: u32,
    /// When true, run a pre-flight liveness check before a punch starts and skip
    /// the punch if Blocked.  Default OFF: relay already carries the data plane,
    /// and a pre-punch "skip" is harder to self-heal than post-scan attribution.
    #[serde(default)]
    pub udp_liveness_pre_flight: bool,
    /// Interval between active UDP hole-punch probes in milliseconds.
    #[serde(default = "default_punch_interval_ms")]
    pub punch_interval_ms: u64,
    /// Number of active probe rounds sent to each peer candidate.
    #[serde(default = "default_punch_attempts")]
    pub punch_attempts: u32,
    /// Periodic direct-path NAT keepalive interval in seconds.
    #[serde(default = "default_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,
    /// Whether to try short-lived UPnP IGD / PCP / NAT-PMP UDP port mappings for direct candidates.
    #[serde(default = "default_true")]
    pub upnp_enabled: bool,
    /// Whether to synthesize bounded birthday probing endpoints when NAT profile suggests it.
    #[serde(default = "default_true")]
    pub birthday_probing_enabled: bool,
    /// Enable the experimental bounded UDP socket pool for hard NATs.
    /// Disabled by default until a network has passed the NAT-06 A/B baseline.
    #[serde(default)]
    pub socket_pool_enabled: bool,
    /// Total UDP sockets (primary plus experimental members) when the pool is enabled.
    #[serde(default = "default_socket_pool_size")]
    pub socket_pool_size: usize,
    /// Enable fresh-socket measure-then-punch generations for hard NATs.
    ///
    /// Each hard-NAT Direct attempt binds a dedicated fresh UDP socket,
    /// measures the NAT's port sequence through distinct STUN observers in
    /// send order, models the allocation step, and punches the peer from the
    /// same socket so the peer-facing mapping is the model's prediction.
    #[serde(default = "default_true")]
    pub fresh_mapping_punch_enabled: bool,
    /// Whether to include extrapolated server-reflexive candidates inferred
    /// from the observed STUN mapping sequence.
    ///
    /// This remains enabled in production. The explicit off switch exists for
    /// reproducible experiments that compare the traversal stack with a
    /// static STUN-observed candidate baseline.
    #[serde(default = "default_true")]
    pub predicted_candidates_enabled: bool,
    /// Whether the local socket address is gathered as a Host candidate.
    ///
    /// NAT-simulation harnesses disable host candidates so every punch must
    /// traverse the simulated NATs (a loopback host candidate would otherwise
    /// connect the two daemons directly).
    #[serde(default = "default_true")]
    pub gather_host_candidates: bool,
    /// Allow loopback endpoints in the fresh-mapping measurement/punch flow
    /// (NAT-simulation harnesses only).
    ///
    /// Production fresh-mapping generations only target public probe
    /// endpoints; the deterministic dual-NAT harness (`scripts/nat-sim`)
    /// simulates the NATs on loopback addresses and needs the fresh path to
    /// accept them.  Like `P2WLAN_DISABLE_TUN`, this is a documented test
    /// escape hatch and defaults to off.
    #[serde(default)]
    pub fresh_mapping_harness_loopback: bool,
    /// Drive a real encrypted overlay payload through the production
    /// dataplane (DataPlane -> WireGuard encrypt -> outbound path selector ->
    /// WireGuard decrypt -> DataPlane) using an in-memory mock TUN instead of
    /// a system interface (independent validation harnesses only).
    ///
    /// This is NOT a test-only plaintext bypass: every payload byte goes
    /// through the exact production outbound/inbound pipeline, and the flag
    /// is off by default so production daemons never create the mock
    /// interface or the validation loop.  The loopback virtual interface
    /// requires no privileges and is the documented alternative used when
    /// macOS TUN creation is unavailable to the validation harness.
    #[serde(default)]
    pub validate_overlay: bool,
    /// When `validate_overlay` is enabled, target every online peer with an
    /// established WireGuard session instead of only Direct peers.  The
    /// outbound path selector then rides Relay until Direct is confirmed, so
    /// an availability harness can prove "first usable business packet" over
    /// Relay without any Direct path.  This is independent-harness only and
    /// defaults to off: with the flag off, the overlay loop preserves the
    /// strict-direct semantics of sending only over confirmed Direct paths.
    #[serde(default)]
    pub overlay_any_path: bool,
    /// When `validate_overlay` is enabled, fire one BURST of this many
    /// business payloads per peer right after the first usable evidence, and
    /// verify that every echo comes back (zero loss/duplicate/reorder in the
    /// real dataplane + WireGuard pipeline).  `0` disables the burst
    /// (independent validation harnesses only).
    #[serde(default)]
    pub overlay_burst: usize,
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
    #[cfg(target_os = "windows")]
    {
        "p2wlan".to_string()
    }
    #[cfg(not(target_os = "windows"))]
    {
        "p2wlan0".to_string()
    }
}
fn default_udp_bind() -> String {
    "0.0.0.0:0".to_string()
}
fn default_stun_timeout_ms() -> u64 {
    1500
}
fn default_udp_liveness_targets() -> Vec<String> {
    vec![
        "223.5.5.5:53".into(),      // AliDNS (CN)
        "119.29.29.29:53".into(),    // China Unicom (CN)
        "114.114.114.114:53".into(), // 114DNS (CN)
        "8.8.8.8:53".into(),         // Google (overseas / fallback)
    ]
}
fn default_udp_liveness_timeout_ms() -> u32 {
    1500
}
fn default_udp_liveness_ttl_ms() -> u32 {
    30_000
}
fn default_udp_liveness_retries() -> u32 {
    2
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

fn default_socket_pool_size() -> usize {
    1
}

/// Control-plane proxy policy.
///
/// The daemon's own control-plane HTTP traffic must be explicit about whether
/// the process environment's `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`
/// variables are honored.  UDP endpoints are always derived from STUN
/// candidates and signalled as JSON; a proxy's egress IP is never used as a
/// UDP endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlProxyMode {
    /// Do NOT read environment proxies for control-plane HTTP.  This is the
    /// default: control traffic connects directly and is never routed through
    /// an ambient proxy.
    #[default]
    Direct,
    /// Explicitly allow reading `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` for
    /// control-plane HTTP.  WebSocket signaling remains direct-only (the
    /// pinned tokio-tungstenite client has no proxy support).
    Environment,
}

impl ControlProxyMode {
    /// Short stable label used by diagnostics and structured events.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Environment => "environment",
        }
    }
}

/// Control plane server configuration.
#[derive(Clone, Serialize, Deserialize)]
pub struct ControlConfig {
    /// Control server URL (e.g. "https://control.p2wlan.io:443").
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
    /// Explicit control-plane HTTP proxy policy.  `direct` by default; the
    /// daemon never consults environment proxies unless this is `environment`.
    #[serde(default)]
    pub proxy_mode: ControlProxyMode,
}

impl std::fmt::Debug for ControlConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlConfig")
            .field("server_url", &self.server_url)
            .field("auth_token", &redacted_presence(&self.auth_token))
            .field(
                "device_credential",
                &redacted_presence(&self.device_credential),
            )
            .field("credential_issued", &self.credential_issued)
            .field("reconnect_interval_secs", &self.reconnect_interval_secs)
            .field("heartbeat_interval_secs", &self.heartbeat_interval_secs)
            .field("proxy_mode", &self.proxy_mode)
            .finish()
    }
}

fn default_reconnect_interval() -> u64 {
    5
}
fn default_heartbeat_interval() -> u64 {
    5
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
    /// Bounded time the first business packet waits for a relay transport to
    /// become available before it is dropped with a stable diagnostic reason.
    ///
    /// This replaces the old, never-enforced `fallback_timeout_ms` ("timeout
    /// for direct connection attempt before falling back to relay").  Relay is
    /// never deliberately delayed by this value: once a relay transport is
    /// connected, outbound packets use it immediately.  Old configs that still
    /// carry `fallback_timeout_ms` are read as this field (backward-compatible
    /// parse), and the field is serialized under the new name.
    #[serde(default = "default_relay_timeout", alias = "fallback_timeout_ms")]
    pub relay_startup_timeout_ms: u64,
    /// Whether to allow insecure plaintext TCP to relay (default: false, development only).
    #[serde(default)]
    pub allow_insecure_plaintext: bool,
    /// Path to additional CA certificate bundle for self-hosted relays.
    #[serde(default)]
    pub ca_cert_path: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_relay_timeout() -> u64 {
    3000
}
fn default_relay_selection_timeout() -> u64 {
    2000
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
    /// Path to the daemon's own log file (set from `--log-file`). Populated
    /// only in-process; not part of the persisted config. Backs `GET
    /// /logs/tail`. Ignored when the operator did not configure a log file.
    #[serde(default, skip_serializing)]
    pub log_path: Option<std::path::PathBuf>,
    /// Per-process random token authorizing diagnostics **mutation** endpoints.
    /// Generated at startup and never persisted to the config file or command
    /// line; surfaced to local callers (Flutter / tray) through a 0600 file
    /// whose path is `auth_token_path`. `None` means mutations fail closed.
    #[serde(default, skip_serializing)]
    pub auth_token: Option<String>,
    /// Where the per-process diagnostics auth token is written at startup and
    /// deleted on graceful shutdown. In-process only; never persisted.
    #[serde(default, skip_serializing)]
    pub auth_token_path: Option<std::path::PathBuf>,
}

fn default_diagnostics_bind() -> String {
    "127.0.0.1:39277".to_string()
}

impl Default for DiagnosticsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_diagnostics_bind(),
            log_path: None,
            auth_token: None,
            auth_token_path: None,
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
    /// DNS domain suffix (e.g. "p2wlan.local").
    #[serde(default = "default_dns_suffix")]
    pub suffix: String,
    /// Custom DNS mappings (hostname → virtual IP).
    #[serde(default)]
    pub mappings: std::collections::HashMap<String, String>,
}

fn default_dns_suffix() -> String {
    "p2wlan.local".to_string()
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
