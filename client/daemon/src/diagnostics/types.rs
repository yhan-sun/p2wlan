const IPV6_SAFE_MIN_MTU: u32 = 1280;
const RELAY_SAFE_MTU: u32 = 1380;
const WIREGUARD_STYLE_MTU: u32 = 1420;
const COMMON_ETHERNET_MTU: u32 = 1500;
const DIAGNOSTICS_BIND_RETRY_INTERVAL: Duration = Duration::from_secs(1);

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
