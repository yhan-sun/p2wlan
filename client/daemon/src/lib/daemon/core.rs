/// The main daemon orchestrator.
///
/// Holds all subsystems and coordinates their lifecycle.
pub struct Daemon {
    /// Configuration.
    config: Arc<Config>,
    /// Control plane client.
    control: ControlClient,
    /// Control event receiver.
    control_rx: tokio::sync::mpsc::UnboundedReceiver<ControlEvent>,
    /// Peer connection manager.
    peers: Arc<PeerManager>,
    /// Shared WireGuard transport session adapter.
    transport: WireGuardTransport,
    /// RAW routed outbound packets emitted by the WireGuard adapter to the
    /// network outbound worker (which is the only place that encrypts
    /// business packets).
    outbound_rx: Option<mpsc::Receiver<OutboundPacket>>,
    /// In-flight initiator handshakes keyed by responder node ID (shared so timeout tasks can clean up).
    pending_handshakes: Arc<tokio::sync::Mutex<PendingHandshakeState>>,
    /// Serializes offer, answer, and maintenance mutations for one peer.
    handshake_arbiter: HandshakeArbiter,
    /// Local UDP candidate endpoints advertised in signaling messages.
    local_candidates: Arc<RwLock<Vec<String>>>,
    /// Local-only source metadata keyed by candidate endpoint string.
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    /// Stable physical/public identity used for network-generation changes.
    local_network_identity: Arc<RwLock<Vec<String>>>,
    /// Serializes candidate gathering/commit so endpoints, sources, identity,
    /// and generation advance as one coherent snapshot.
    candidate_refresh_lock: Arc<Mutex<()>>,
    /// Shared candidate snapshot lease: within its TTL no signaling path may
    /// re-run a live STUN gather (single-flight); expired snapshots are still
    /// used as a bounded old snapshot so a slow refresh never blocks an
    /// answer/offer.
    candidate_snapshot: Arc<RwLock<Option<CandidateSnapshotLease>>>,
    /// Per-peer offer-ingress dedup / rate-limit records.  Decided BEFORE any
    /// candidate-plane state is touched, so repeated/old offers from a
    /// churning peer cannot trigger candidate applies or fresh transactions.
    offer_ingress: Arc<std::sync::Mutex<HashMap<String, OfferIngressRecord>>>,
    /// Latest local NAT behavior profile inferred from STUN observations.
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    /// Cached gateway mapping lifecycle and structured diagnostics.
    gateway_mapping_runtime: Arc<RwLock<GatewayMappingRuntime>>,
    gateway_mapping_diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
    /// Coordinates UDP punch bursts across all trigger paths.
    punch_attempts: PunchAttemptDeduplicator,
    /// Bound UDP transport shared with control-plane-triggered punching.
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    /// Authoritative UDP transport publication stream.  The legacy RwLock is
    /// retained for existing best-effort consumers; WireGuard inbound uses
    /// this watch-backed slot so it follows delayed publication and replacement.
    udp_transport_publication: UdpTransportPublication,
    /// Resolved STUN / observer endpoints used by live candidate refreshes.
    runtime_stun_servers: Arc<RwLock<Vec<SocketAddr>>>,
    /// Timeout for runtime STUN refreshes.
    runtime_stun_timeout: Arc<RwLock<Duration>>,
    /// Relay transport used when direct UDP is unavailable.
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    /// Latest relay candidate selection diagnostics.
    relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    /// Port mapping manager.
    port_mappings: Arc<PortMappingManager>,
    /// DNS resolver.
    dns: Arc<DnsResolver>,
    /// ACL engine.
    acl: Arc<RwLock<AclEngine>>,
    /// Route table manager.
    route_manager: Arc<route::RouteManager>,
    /// Shared health state for diagnostics / supervision.
    health: Arc<tasks::HealthState>,
    /// Task manager for spawning and supervising background tasks.
    task_manager: Arc<tasks::TaskManager>,
    /// Shutdown signal sender (true = shut down).
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    /// Shutdown signal receiver cloned into background tasks.
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    /// Persistent monotonic daemon incarnation.  Fresh-mapping prediction
    /// labels embed this as the incarnation epoch (`predicted_fresh:<boot>:<gen>`)
    /// and candidate generations embed it in their high bits: a restarted
    /// daemon always supersedes every generation an older incarnation sent,
    /// regardless of wall-clock rollback or a restart within the same
    /// millisecond, and old incarnations' late signals can never win again.
    boot_epoch_ms: u64,
    /// Per-process connection timeline (correlation id + bounded event ring).
    timeline: Arc<ConnectionTimeline>,
    /// Watch for relay transport availability.  The relay supervisor flips this
    /// whenever the shared `relay_transport` slot is set or cleared, so the
    /// outbound path can wait event-driven for a relay to come up instead of
    /// polling at a fixed interval.
    relay_available_tx: watch::Sender<bool>,
}

impl Daemon {
    /// Create a new daemon from config.
    pub fn new(config: Config) -> Self {
        let control_enabled = !config.network.manual;
        let config_path = config.config_path.clone();
        let relay_selection = Arc::new(RwLock::new(RelaySelectionDiagnostics::default()));
        // The fresh-mapping prediction incarnation epoch: a persistent
        // strictly-monotonic counter (seeded from the wall clock only on the
        // very first boot).  A restarted daemon's label supersedes every label
        // an older incarnation sent even when the wall clock rolled back or
        // the restart landed within the same millisecond, and the receiver's
        // high-water keeps older incarnations' late signals out.
        //
        // Zero means no trustworthy incarnation exists for this boot (missing
        // config path, corrupt or unreadable state file, version mismatch,
        // unwritable state directory, or the counter exhausted): fresh-mapping
        // prediction is disabled rather than silently re-seeded from the wall
        // clock, which could regress below the high-water receivers recorded.
        let boot_epoch_ms = crate::incarnation::next_boot_incarnation(&config).unwrap_or(0);
        // An incarnation that outgrew the 41-bit candidate-generation
        // encoding field also disables fresh prediction (the label must never
        // wrap): ordinary signaling continues with the legacy generation 0.
        let boot_epoch_ms = if crate::control::incarnation_fits_candidate_generation_encoding(
            boot_epoch_ms,
        ) {
            boot_epoch_ms
        } else {
            0
        };
        if boot_epoch_ms == 0 {
            warn!(
                "Fresh-mapping prediction is disabled for this boot (no trustworthy persistent incarnation or the incarnation outgrew its encoding field); ordinary punching continues"
            );
        }
        let timeline = ConnectionTimeline::new(&config.node.node_id, boot_epoch_ms);
        let (control, control_rx) = ControlClient::new(
            &config,
            control_enabled,
            config_path,
            Some(relay_selection.clone()),
            timeline.clone(),
        );
        let (transport, outbound_rx) = WireGuardTransport::new();
        let acl_engine = AclEngine::from_config(&config.acl);
        let route_manager = Arc::new(route::RouteManager::new(config.network.interface.clone()));

        let health = tasks::HealthState::new();
        let task_manager = tasks::TaskManager::new(health.clone());
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let udp_transport = Arc::new(RwLock::new(None));
        let (relay_available_tx, _relay_available_rx) = tokio::sync::watch::channel(false);

        // Register the punch-session canceller on the peer manager so a
        // stale/404 quarantined peer's in-flight recovery session is
        // cancelled authoritatively (the daemon's own `punch_attempts` is
        // the same deduplicator the daemon hands to the punch tasks).
        let punch_attempts = PunchAttemptDeduplicator::default();
        let peers = Arc::new(PeerManager::new(config.clone()));
        peers.set_timeline(timeline.clone());
        transport.set_outbound_loss_context(&peers, timeline.clone());
        // Share ONE outbound-loss counter map between the peer manager (worker
        // drops) and the transport (session-not-ready queue drops) so
        // `/status.stats.outbound_drops` / `outbound_send_failures` report
        // every loss source in one place.
        let outbound_loss = Arc::new(tokio::sync::Mutex::new(
            crate::peer::OutboundLossCounters::default(),
        ));
        peers.set_outbound_loss_sink(outbound_loss.clone());
        transport.set_outbound_loss_sink(Some(outbound_loss));
        {
            let punch_attempts = punch_attempts.clone();
            peers.set_punch_cancel_hook(Arc::new(move |peer_id| {
                punch_attempts.cancel(peer_id);
            }));
        }

        Self {
            config: Arc::new(config.clone()),
            control,
            control_rx,
            peers,
            transport,
            outbound_rx: Some(outbound_rx),
            pending_handshakes: Arc::new(tokio::sync::Mutex::new(PendingHandshakeState::default())),
            handshake_arbiter: HandshakeArbiter::default(),
            local_candidates: Arc::new(RwLock::new(Vec::new())),
            local_candidate_sources: Arc::new(RwLock::new(HashMap::new())),
            local_network_identity: Arc::new(RwLock::new(Vec::new())),
            candidate_refresh_lock: Arc::new(Mutex::new(())),
            candidate_snapshot: Arc::new(RwLock::new(None)),
            offer_ingress: Arc::new(std::sync::Mutex::new(HashMap::new())),
            nat_profile: Arc::new(RwLock::new(None)),
            gateway_mapping_runtime: Arc::new(RwLock::new(GatewayMappingRuntime::default())),
            gateway_mapping_diagnostics: Arc::new(RwLock::new(GatewayMappingDiagnostics {
                enabled: config.network.upnp_enabled,
                lease_seconds: PORT_MAPPING_LEASE_SECS,
                ..GatewayMappingDiagnostics::default()
            })),
            punch_attempts,
            udp_transport: udp_transport.clone(),
            udp_transport_publication: UdpTransportPublication::new(udp_transport),
            runtime_stun_servers: Arc::new(RwLock::new(Vec::new())),
            runtime_stun_timeout: Arc::new(RwLock::new(Duration::from_millis(
                config.network.stun_timeout_ms,
            ))),
            relay_transport: Arc::new(RwLock::new(None)),
            relay_selection,
            port_mappings: Arc::new(PortMappingManager::new()),
            dns: Arc::new(DnsResolver::new(config.dns.clone())),
            acl: Arc::new(RwLock::new(acl_engine)),
            route_manager,
            health,
            task_manager,
            shutdown_tx,
            shutdown_rx,
            boot_epoch_ms,
            timeline,
            relay_available_tx,
        }
    }

    /// Return a clone of the shutdown sender so main can signal SIGTERM/SIGINT.
    pub fn shutdown_sender(&self) -> tokio::sync::watch::Sender<bool> {
        self.shutdown_tx.clone()
    }

    /// Request a graceful shutdown.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.task_manager.request_shutdown();
    }
}
