const IPV6_SAFE_MIN_MTU: u32 = 1280;
const RELAY_SAFE_MTU: u32 = 1380;
const WIREGUARD_STYLE_MTU: u32 = 1420;
const COMMON_ETHERNET_MTU: u32 = 1500;
const DIAGNOSTICS_BIND_RETRY_INTERVAL: Duration = Duration::from_secs(1);
// A status request must fail closed when a contended runtime lock prevents a
// complete snapshot. It must not leave the UI and acceptance harness hanging
// indefinitely while the dataplane continues running.
const DIAGNOSTICS_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// Best-effort transport hint. NAT measurement remains authoritative;
    /// this is `unknown` when the host/Android integration does not expose a
    /// Wi-Fi/cellular classification.
    #[serde(default, skip_serializing_if = "NetworkHint::is_unknown")]
    pub network_hint: NetworkHint,
    /// Monotonic milliseconds since this daemon process started (matches the
    /// timeline events' `at_ms` clock).
    pub uptime_ms: u64,
    /// Monotonic status revision. Bumped by every recorded status event; a
    /// client compares this to its last-seen revision to decide whether a full
    /// snapshot refetch is needed (see `GET /events?since=N`).
    #[serde(default)]
    pub revision: u64,
    /// Event revision captured atomically with the peer array. A successful
    /// response always has `captured_revision == revision`; clients can reject
    /// a mixed or legacy response without interpreting nested peer fields.
    #[serde(default)]
    pub captured_revision: u64,
    /// Daemon-monotonic capture time in milliseconds. This shares the
    /// `/status.uptime_ms` and timeline-event `at_ms` clock; it is not Unix time.
    #[serde(default)]
    pub captured_at_ms: u64,
    /// Whether `peers` came from an older validated capture. The current
    /// endpoint fails closed with 503 under sustained lock contention, so a
    /// successful response always sets this to false.
    #[serde(default)]
    pub peer_snapshot_stale: bool,
    /// Age of the validated peer capture when this response was assembled.
    #[serde(default)]
    pub peer_snapshot_age_ms: u64,
    /// Versioned stable hash of the serialized peer array. It contains no
    /// credentials and lets clients distinguish capture shapes cheaply.
    #[serde(default)]
    pub peer_snapshot_shape: String,
    /// Authoritative daemon readiness phase (see `derive_ready_phase`). Clients
    /// must render this instead of inferring readiness from `virtual_ip` alone.
    #[serde(default)]
    pub ready_phase: String,
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
    /// Version and canonical hash of the atomic candidate snapshot backing
    /// `local_candidates`. `None` means initial UDP gathering has not yet
    /// committed a snapshot.
    pub candidate_snapshot_version: Option<u64>,
    pub candidate_snapshot_hash: Option<u64>,
    pub nat_profile: Option<NatProfile>,
    /// Normalized NAT truth used by the traversal planner. This is additive
    /// to the historical profile so older clients can continue to ignore it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nat_capabilities: Option<NatCapabilities>,
    pub gateway_mapping: GatewayMappingDiagnostics,
    pub relay_servers: Vec<String>,
    pub relay_connected: bool,
    pub relay_selection: RelaySelectionDiagnostics,
    /// Control-plane HTTP proxy policy label (`direct` | `environment`).
    pub control_proxy_mode: String,
    /// Whether the configured proxy mode consults environment proxy variables.
    /// Never includes the proxy URL, tokens, or authentication material.
    pub control_proxy_consults_env: bool,
    /// Bounded connection timeline (correlation id + event ring).
    pub connection_timeline: ConnectionTimelineDiagnostics,
    pub traversal_history: TraversalHistoryDiagnostics,
    pub peers: Vec<PeerDiagnostics>,
    pub stats: PeerManagerStats,
    pub health: crate::tasks::HealthSnapshot,
}

/// Lightweight, peer-scoped diagnostics response used by the dual-end
/// harness. It intentionally omits the large local/network-wide sections of
/// `/status` while retaining all fields needed to validate one Direct chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerScopedDiagnosticsSnapshot {
    pub node_id: String,
    pub network_id: String,
    pub network_generation: u64,
    pub network_peer_count: usize,
    pub captured_at_ms: u64,
    pub peer: Option<PeerDiagnostics>,
}

/// Process-scoped diagnostics used by supervisors and acceptance harnesses.
///
/// This endpoint deliberately avoids the network-wide peer snapshot. A busy
/// or stale peer must not make a daemon appear dead merely because the full
/// `/status` materialization timed out. It contains identity and readiness
/// fields only; it must never grow to include tickets, tokens, keys, or
/// endpoint credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeDiagnosticsSnapshot {
    pub version: String,
    pub process_id: u32,
    pub node_id: String,
    pub virtual_ip: String,
    pub network_id: String,
    pub network_generation: u64,
    pub uptime_ms: u64,
    pub relay_connected: bool,
}

pub const DIAGNOSTICS_CONTRACT_VERSION: u32 = 1;

/// Production serializer boundary for the status endpoint. Keeping the
/// contract marker in a typed wrapper makes a field mutation visible to both
/// Rust fixture tests and Flutter's production parser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    #[serde(flatten)]
    pub snapshot: DiagnosticsSnapshot,
}

impl StatusResponse {
    pub fn from_snapshot(snapshot: DiagnosticsSnapshot) -> Self {
        Self {
            contract_version: DIAGNOSTICS_CONTRACT_VERSION,
            snapshot,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    /// Daemon process incarnation. Event sequence numbers restart at zero, so
    /// clients must pair this with `revision` when advancing their cursor.
    #[serde(default)]
    pub process_id: u32,
    pub revision: u64,
    /// Oldest sequence still retained in the bounded event ring; zero when the
    /// ring is empty.
    #[serde(default)]
    pub oldest_seq: u64,
    /// True when `since` belongs to an older process or fell behind an evicted
    /// ring segment. The client must fetch a full `/status` snapshot before
    /// consuming further deltas.
    #[serde(default)]
    pub reset_required: bool,
    pub events: Vec<StatusEvent>,
}

impl EventsResponse {
    pub fn from_poll(poll: StatusEventPoll) -> Self {
        Self {
            contract_version: DIAGNOSTICS_CONTRACT_VERSION,
            process_id: poll.process_id,
            revision: poll.revision,
            oldest_seq: poll.oldest_seq,
            reset_required: poll.reset_required,
            events: poll.events,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntryResponse {
    pub cidr: String,
    pub expected_interface: String,
    pub actual_interface: Option<String>,
    pub state: crate::route::RouteState,
    pub owned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutesResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    pub interface: String,
    pub mtu: u32,
    pub healthy: bool,
    #[serde(rename = "conflictCount")]
    pub conflict_count: usize,
    pub entries: Vec<RouteEntryResponse>,
}

impl RoutesResponse {
    pub fn new(
        interface: String,
        mtu: u32,
        healthy: bool,
        conflict_count: usize,
        entries: Vec<RouteEntryResponse>,
    ) -> Self {
        Self {
            contract_version: DIAGNOSTICS_CONTRACT_VERSION,
            interface,
            mtu,
            healthy,
            conflict_count,
            entries,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteRepairResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    pub cidr: String,
    pub changed: bool,
    pub attempted: bool,
    pub before: String,
    pub after: String,
    pub reason: String,
    #[serde(rename = "restartedDaemon")]
    pub restarted_daemon: bool,
}

impl RouteRepairResponse {
    pub fn new(
        cidr: String,
        changed: bool,
        attempted: bool,
        before: String,
        after: String,
        reason: String,
    ) -> Self {
        Self {
            contract_version: DIAGNOSTICS_CONTRACT_VERSION,
            cidr,
            changed,
            attempted,
            before,
            after,
            reason,
            restarted_daemon: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersPageResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    pub peers: Vec<PeerDiagnostics>,
    pub total: usize,
    pub cursor: Option<String>,
    pub next_cursor: Option<String>,
}

impl PeersPageResponse {
    pub fn new(
        peers: Vec<PeerDiagnostics>,
        total: usize,
        cursor: Option<String>,
        next_cursor: Option<String>,
    ) -> Self {
        Self {
            contract_version: DIAGNOSTICS_CONTRACT_VERSION,
            peers,
            total,
            cursor,
            next_cursor,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionPreflightResponse {
    #[serde(rename = "contractVersion")]
    pub contract_version: u32,
    pub state: String,
    #[serde(rename = "canCreateTun")]
    pub can_create_tun: Option<bool>,
    #[serde(rename = "canModifyRoutes")]
    pub can_modify_routes: Option<bool>,
    #[serde(rename = "elevationSupported")]
    pub elevation_supported: bool,
    #[serde(rename = "reasonCode")]
    pub reason_code: String,
    pub message: String,
}

/// Shared state needed to build diagnostics responses.
#[derive(Clone)]
pub struct DiagnosticsContext {
    config: Arc<Config>,
    peers: Arc<PeerManager>,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    candidate_snapshot: Arc<RwLock<Option<crate::CandidateSnapshotLease>>>,
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    gateway_mapping: Arc<RwLock<GatewayMappingDiagnostics>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    health: Arc<HealthState>,
    task_manager: Arc<TaskManager>,
    /// Shared route manager: source of the authoritative overlay-route state
    /// for `GET /routes` and `POST /routes/verify` / `/routes/repair`.
    route_manager: Arc<crate::route::RouteManager>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Per-process connection timeline (correlation id + bounded events).
    timeline: Arc<ConnectionTimeline>,
    /// Bounded monotonic status event log backing `/events` and the
    /// `/status.revision` counter.
    status_events: Arc<StatusEventBus>,
    /// Last fully validated peer capture. It is retained with its own revision,
    /// age and shape for diagnostics, but is never mixed into a newer snapshot
    /// when the live peer locks are contended.
    peer_snapshot_cache: Arc<std::sync::Mutex<Option<CachedPeerSnapshot>>>,
    /// Path to the daemon's own log file (when the operator set `--log-file`),
    /// used by the bounded `GET /logs/tail` endpoint. `None` when logging to
    /// stdout.
    log_path: Option<std::path::PathBuf>,
    /// Per-process random token required to authorize diagnostics **mutation**
    /// endpoints (`POST /speedtest`, `POST /routes/repair`, `POST /shutdown`).
    /// `None` when the diagnostics endpoint is disabled; mutations then fail
    /// closed with 403.
    auth_token: Option<String>,
}

impl DiagnosticsContext {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: Arc<Config>,
        peers: Arc<PeerManager>,
        udp_transport: Arc<RwLock<Option<UdpTransport>>>,
        candidate_snapshot: Arc<RwLock<Option<crate::CandidateSnapshotLease>>>,
        nat_profile: Arc<RwLock<Option<NatProfile>>>,
        gateway_mapping: Arc<RwLock<GatewayMappingDiagnostics>>,
        relay_transport: Arc<RwLock<Option<RelayTransport>>>,
        relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
        health: Arc<HealthState>,
        task_manager: Arc<TaskManager>,
        route_manager: Arc<crate::route::RouteManager>,
        shutdown_tx: tokio::sync::watch::Sender<bool>,
        timeline: Arc<ConnectionTimeline>,
        status_events: Arc<StatusEventBus>,
        log_path: Option<std::path::PathBuf>,
        auth_token: Option<String>,
    ) -> Self {
        Self {
            config,
            peers,
            udp_transport,
            candidate_snapshot,
            nat_profile,
            gateway_mapping,
            relay_transport,
            relay_selection,
            health,
            task_manager,
            route_manager,
            shutdown_tx,
            timeline,
            status_events,
            peer_snapshot_cache: Arc::new(std::sync::Mutex::new(None)),
            log_path,
            auth_token,
        }
    }
}

#[derive(Debug, Clone)]
struct CachedPeerSnapshot {
    peers: Vec<PeerDiagnostics>,
    capture_revision: u64,
    captured_at: std::time::Instant,
    captured_at_ms: u64,
    shape: String,
}

/// Compare a bearer token against the daemon's per-process diagnostics auth
/// token in constant time. `None` token (diagnostics disabled) never matches.
fn auth_matches(expect: Option<&str>, provided: Option<&str>) -> bool {
    use subtle::ConstantTimeEq;

    match (expect, provided) {
        (Some(expected), Some(given)) => expected.as_bytes().ct_eq(given.as_bytes()).into(),
        _ => false,
    }
}

#[cfg(test)]
mod auth_matches_tests {
    use super::*;

    #[test]
    fn bearer_matches_only_the_exact_token() {
        assert!(auth_matches(Some("abc123"), Some("abc123")));
        assert!(!auth_matches(Some("abc123"), Some("abc124")));
        assert!(!auth_matches(Some("abc123"), Some("abc12")));
        assert!(!auth_matches(Some("abc123"), None));
        assert!(!auth_matches(None, Some("abc123")));
        assert!(!auth_matches(None, None));
    }
}

/// Derive the authoritative readiness phase from daemon-side signals only.
///
/// The phase is a coarse, UI-safe ladder. Clients render this instead of
/// inferring "connected" from `virtual_ip` presence alone. Priority (top wins):
/// shutdown > reauth required > unhealthy > control not connected > VIP still
/// being allocated > connected (relayed or direct) > still discovering peers.
pub fn derive_ready_phase(
    health: &crate::tasks::HealthSnapshot,
    _relay_transport_connected: bool,
    peers: &[PeerDiagnostics],
    virtual_ip: &str,
    manual_mode: bool,
) -> &'static str {
    use crate::tasks::HealthStatus;
    if health.status == HealthStatus::ShuttingDown {
        return "stopping";
    }
    if health.reauth_required {
        return "credential_reauth_required";
    }
    if health.status == HealthStatus::Unhealthy {
        return "error";
    }
    if !health.control_connected {
        if manual_mode && !virtual_ip.trim().is_empty() {
            // `connected_manual` is reserved for an explicitly configured
            // local-only network. A managed daemon retaining an old VIP while
            // its control/device lease is down is not manual connectivity.
            return "connected_manual";
        }
        return "connecting_control";
    }
    if virtual_ip.trim().is_empty() {
        // Connected to control but the VIP has not been assigned yet. This is
        // a distinct state from "no peers found": the daemon is still waiting
        // on the control plane to allocate 10.20.x.x.
        return "allocating_virtual_ip";
    }
    let has_direct = peers
        .iter()
        .any(|peer| peer.online && peer.active_path.as_ref() == Some(&NetworkPath::Direct));
    // A shared relay TCP/TLS transport only proves local writer readiness. It
    // is not peer delivery evidence. Relay readiness requires the peer's
    // same-generation encrypted forced-relay ACK reflected in active_path and
    // relay_confirmed_*.
    let has_relay = peers.iter().any(|peer| {
        peer.online
            && peer.active_path.as_ref() == Some(&NetworkPath::Relay)
            && peer.relay_confirmed_generation.is_some()
            && peer
                .relay_confirmed_endpoint
                .as_deref()
                .is_some_and(|endpoint| !endpoint.is_empty())
    });
    if has_direct {
        "connected_direct"
    } else if has_relay {
        "connected_relay"
    } else {
        // Connected to control, VIP allocated, but no peer path yet.
        "discovering_peers"
    }
}

#[cfg(test)]
mod ready_phase_tests {
    use super::*;
    use crate::tasks::{HealthSnapshot, HealthStatus};

    fn health(control_connected: bool) -> HealthSnapshot {
        HealthSnapshot {
            status: HealthStatus::Healthy,
            reason: None,
            critical_tasks: Vec::new(),
            control_connected,
            last_control_success_secs_ago: None,
            control_api_reachable: control_connected,
            device_lease_healthy: control_connected,
            last_device_lease_success_secs_ago: None,
            reauth_required: false,
        }
    }

    #[test]
    fn managed_disconnect_with_retained_vip_is_not_manual() {
        assert_eq!(
            derive_ready_phase(&health(false), false, &[], "10.20.0.1", false),
            "connecting_control"
        );
        assert_eq!(
            derive_ready_phase(&health(false), false, &[], "10.20.0.1", true),
            "connected_manual"
        );
    }

    #[test]
    fn relay_transport_without_peer_confirmation_is_still_discovering() {
        assert_eq!(
            derive_ready_phase(&health(true), true, &[], "10.20.0.1", false),
            "discovering_peers"
        );
    }

    #[test]
    fn offline_peer_cannot_make_the_daemon_ready() {
        let connection = crate::peer::PeerConnection::new("offline-peer", "10.20.0.2");
        let mut peer = PeerDiagnostics::from(&connection);
        peer.online = false;
        peer.active_path = Some(NetworkPath::Relay);
        peer.relay_confirmed_generation = Some(0);
        peer.relay_confirmed_endpoint = Some("relay.example:443".to_string());

        assert_eq!(
            derive_ready_phase(&health(true), true, &[peer], "10.20.0.1", false),
            "discovering_peers"
        );
    }
}
