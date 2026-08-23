#[derive(Clone)]
struct UdpDirectTaskContext {
    udp_bind: SocketAddr,
    peers: Arc<PeerManager>,
    control: ControlClient,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    local_network_identity: Arc<RwLock<Vec<String>>>,
    candidate_snapshot: Arc<RwLock<Option<CandidateSnapshotLease>>>,
    candidate_refresh_lock: Arc<Mutex<()>>,
    nat_profile: Arc<RwLock<Option<NatProfile>>>,
    gateway_mapping_runtime: Arc<RwLock<GatewayMappingRuntime>>,
    gateway_mapping_diagnostics: Arc<RwLock<GatewayMappingDiagnostics>>,
    udp_transport_publication: UdpTransportPublication,
    direct_validation_transport: WireGuardTransport,
    direct_validation_local_ip: String,
    udp_inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    local_node_id: String,
    stun_servers: Vec<SocketAddr>,
    stun_server_specs: Vec<String>,
    udp_observer_specs: Vec<String>,
    runtime_stun_servers: Arc<RwLock<Vec<SocketAddr>>>,
    stun_timeout: Duration,
    udp_advertise: Option<String>,
    upnp_enabled: bool,
    socket_pool_enabled: bool,
    socket_pool_size: usize,
    keepalive_interval: Duration,
    punch_deduplicator: PunchAttemptDeduplicator,
    udp_punch_interval: Duration,
    udp_punch_attempts: u32,
    /// Daemon incarnation epoch embedded in fresh-prediction labels.
    boot_epoch_ms: u64,
    /// Ambient proxy / TUN-capture environment detected at daemon startup.
    /// Included in the NAT profile log so a proxied egress cannot masquerade
    /// as a healthy `UdpBlocked`/`EndpointIndependent` local mapping.
    proxy_env: crate::netenv::ProxyEnvironment,
    /// P2WLAN-owned TUN names excluded from foreign-capture detection.
    excluded_interfaces: Vec<String>,
    /// Daemon-wide shutdown signal.  UDP bind retry and every per-instance
    /// reader/worker observe this instead of making a failed bind permanent.
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

/// Minimum spacing between automatic recovery attempts for one peer.
///
/// The first failed punch must be repaired immediately, but a symmetric NAT
/// can produce several timeout signals while the relay and control lanes are
/// still converging. A small per-peer cooldown single-flights those signals;
/// content-aware publication throttling below separately limits duplicate
/// candidate offers without suppressing the local punch retry.
const DIRECT_RECOVERY_KICK_MIN_INTERVAL: Duration = Duration::from_secs(2);

/// Minimum spacing between successful publications of the same candidate
/// snapshot for one peer.
///
/// A failed Direct batch can be reported by several overlapping workers. The
/// two-second admission interval above bounds task creation, but it used to
/// re-publish the exact same candidate set on every admitted failure. Besides
/// wasting the peer's recovery budget, every publication carries a new signal
/// revision and creates avoidable candidate-ingress contention. A content
/// change is still admitted immediately (subject to the short task interval),
/// while an unchanged snapshot is refreshed well before its 45-second signal
/// expiry.
const DIRECT_RECOVERY_UNCHANGED_REPUBLISH_INTERVAL: Duration = Duration::from_secs(30);

/// Hard bound for per-peer recovery admission state owned by one UDP
/// incarnation.  Control rosters can churn for the lifetime of a socket; a
/// peer that left must not leave an immortal hash/timestamp entry behind.
const DIRECT_RECOVERY_KICK_GATE_MAX_PEERS: usize = 1024;

#[derive(Debug, Default)]
struct DirectRecoveryKickGate {
    peers: HashMap<String, DirectRecoveryKickState>,
}

#[derive(Debug, Default)]
struct DirectRecoveryKickState {
    in_flight: bool,
    last_attempt_at: Option<Instant>,
    last_published: Option<(u64, Instant)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectRecoveryKickPlan {
    /// Publish a new offer and start the local half only after that exact offer
    /// (including its `punch_at_ms`) has been accepted by the control plane.
    PublishCoordinatedPunch,
    /// Neither side starts a new synchronized window.  Reusing a freshly
    /// generated local timestamp without publishing it would create a
    /// permanently one-sided rendezvous.
    SkipUnchanged,
}

/// Hash the candidate payload in the same order in which it is signalled.
///
/// `CandidateSnapshotLease::hash` intentionally canonicalizes a set because it
/// is used to decide whether transport content changed.  Recovery signalling
/// has a stronger requirement: candidate order is probe priority, so swapping
/// two otherwise identical endpoints must publish a fresh coordinated offer.
fn direct_recovery_ordered_snapshot_hash(
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut mix = |bytes: &[u8]| {
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    };
    for candidate in candidates {
        // Field tags and terminators keep `(candidate, source)` boundaries
        // unambiguous without sorting away the priority order.
        mix(&[0xc1]);
        mix(candidate.as_bytes());
        mix(&[0]);
        mix(&[0x5a]);
        if let Some(source) = candidate_sources.get(candidate) {
            mix(source.as_bytes());
        }
        mix(&[0xff]);
    }
    hash
}

impl DirectRecoveryKickGate {
    /// Reserve the single in-flight recovery owner for one peer.
    fn try_begin(&mut self, peer_id: &str, now: Instant) -> bool {
        if !self.peers.contains_key(peer_id)
            && self.peers.len() >= DIRECT_RECOVERY_KICK_GATE_MAX_PEERS
        {
            // Never evict an active owner: doing so would allow a second task
            // for that peer and would let the first task's eventual finish
            // recreate an unbounded entry.  Idle entries are LRU-evicted.
            let oldest_idle = self
                .peers
                .iter()
                .filter(|(_, state)| !state.in_flight)
                .min_by_key(|(_, state)| state.last_attempt_at)
                .map(|(peer_id, _)| peer_id.clone());
            let Some(oldest_idle) = oldest_idle else {
                return false;
            };
            self.peers.remove(&oldest_idle);
        }
        let state = self.peers.entry(peer_id.to_string()).or_default();
        if state.in_flight
            || state.last_attempt_at.is_some_and(|previous| {
                now.saturating_duration_since(previous) < DIRECT_RECOVERY_KICK_MIN_INTERVAL
            })
        {
            return false;
        }
        state.in_flight = true;
        state.last_attempt_at = Some(now);
        true
    }

    /// Decide whether both sides may enter a newly coordinated punch window.
    fn plan(&self, peer_id: &str, snapshot_hash: u64, now: Instant) -> DirectRecoveryKickPlan {
        if self
            .peers
            .get(peer_id)
            .and_then(|state| state.last_published)
            .is_none_or(|(previous_hash, previous_at)| {
                previous_hash != snapshot_hash
                    || now.saturating_duration_since(previous_at)
                        >= DIRECT_RECOVERY_UNCHANGED_REPUBLISH_INTERVAL
            })
        {
            DirectRecoveryKickPlan::PublishCoordinatedPunch
        } else {
            DirectRecoveryKickPlan::SkipUnchanged
        }
    }

    /// Release the in-flight owner and remember only successful publication.
    fn finish(&mut self, peer_id: &str, published_snapshot: Option<(u64, Instant)>) {
        let state = self.peers.entry(peer_id.to_string()).or_default();
        state.in_flight = false;
        if let Some(published_snapshot) = published_snapshot {
            state.last_published = Some(published_snapshot);
        }
    }
}

/// Cancellation-safe owner of one gate reservation.
///
/// A UDP incarnation can be superseded while its HTTP send or punch admission
/// is awaiting.  Dropping the task must release `in_flight`; otherwise one
/// cancelled task permanently disables recovery for that peer until another
/// transport rebuild replaces the whole hook.
struct DirectRecoveryKickOwner {
    gate: Arc<std::sync::Mutex<DirectRecoveryKickGate>>,
    peer_id: String,
    finished: bool,
}

impl DirectRecoveryKickOwner {
    fn new(gate: Arc<std::sync::Mutex<DirectRecoveryKickGate>>, peer_id: String) -> Self {
        Self {
            gate,
            peer_id,
            finished: false,
        }
    }

    fn finish(mut self, published_snapshot: Option<(u64, Instant)>) {
        self.gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .finish(&self.peer_id, published_snapshot);
        self.finished = true;
    }
}

impl Drop for DirectRecoveryKickOwner {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .finish(&self.peer_id, None);
    }
}

/// Install the automatic recovery edge for the current UDP socket instance.
///
/// A candidate-only `peer_offer` is already understood by the control plane
/// and by older peers: it refreshes the peer's candidate set without creating
/// a second WireGuard handshake.  The matching synchronized punch is started
/// locally as well, so either side can create a new destination-specific NAT
/// mapping.  The peer-reflexive signal path then feeds the observed mapping
/// back into the normal direct validation flow.
#[allow(clippy::too_many_arguments)]
fn install_direct_recovery_kick_hook(
    peers: &Arc<PeerManager>,
    control: &ControlClient,
    udp: &UdpTransport,
    candidate_snapshot: &Arc<RwLock<Option<CandidateSnapshotLease>>>,
    runtime_stun_servers: &Arc<RwLock<Vec<SocketAddr>>>,
    stun_timeout: Duration,
    punch_deduplicator: &PunchAttemptDeduplicator,
    probe_interval: Duration,
    attempts: u32,
    boot_epoch_ms: u64,
    instance_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let kick_gate = Arc::new(std::sync::Mutex::new(DirectRecoveryKickGate::default()));
    let peers_for_hook = peers.clone();
    let control_for_hook = control.clone();
    let udp_for_hook = udp.clone();
    let candidate_snapshot_for_hook = candidate_snapshot.clone();
    let runtime_stun_servers_for_hook = runtime_stun_servers.clone();
    let punch_deduplicator_for_hook = punch_deduplicator.clone();
    let instance_shutdown_for_hook = instance_shutdown_rx;

    peers.set_direct_recovery_kick_hook(Arc::new(move |peer_id| {
        // The PeerManager hook slot is replaced synchronously, but a caller
        // may already hold a clone of the old hook.  Refuse new work as soon
        // as this UDP publication lease is revoked.
        if *instance_shutdown_for_hook.borrow() {
            return;
        }
        let should_kick = {
            let mut gate = kick_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            gate.try_begin(peer_id, Instant::now())
        };
        if !should_kick {
            return;
        }

        let peer_id = peer_id.to_string();
        let peers = peers_for_hook.clone();
        let control = control_for_hook.clone();
        let udp = udp_for_hook.clone();
        let candidate_snapshot = candidate_snapshot_for_hook.clone();
        let runtime_stun_servers = runtime_stun_servers_for_hook.clone();
        let punch_deduplicator = punch_deduplicator_for_hook.clone();
        let kick_gate = kick_gate.clone();
        let instance_shutdown_rx = instance_shutdown_for_hook.clone();
        let owner = DirectRecoveryKickOwner::new(kick_gate.clone(), peer_id.clone());

        tokio::spawn(async move {
            let punch_shutdown_rx = instance_shutdown_rx.clone();
            let published_snapshot = tokio::select! {
                biased;
                _ = wait_for_udp_direct_shutdown(instance_shutdown_rx) => None,
                published_snapshot = async {
                if !peers.peer_online(&peer_id).await || peers.is_direct(&peer_id).await {
                    return None;
            }

            let snapshot = candidate_snapshot.read().await.clone();
                let (candidates, candidate_sources, canonical_snapshot_hash) = match snapshot {
                    Some(snapshot) if !snapshot.candidates.is_empty() => (
                        snapshot.candidates,
                        snapshot.candidate_sources,
                        snapshot.hash,
                ),
                    _ => {
                        debug!(
                            event = "direct_recovery_kick_skipped",
                            peer_id = %peer_id,
                            reason = "current_udp_candidate_snapshot_not_ready",
                            "Skipping automatic direct recovery kick until the current UDP incarnation publishes its candidate snapshot"
                        );
                        return None;
                    }
            };

                let now = Instant::now();
                let snapshot_hash = direct_recovery_ordered_snapshot_hash(
                    &candidates,
                    &candidate_sources,
                );
                let plan = kick_gate
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .plan(&peer_id, snapshot_hash, now);
                if plan == DirectRecoveryKickPlan::SkipUnchanged {
                debug!(
                    event = "direct_recovery_kick_skipped",
                    peer_id = %peer_id,
                        snapshot_hash = format_args!("{snapshot_hash:016x}"),
                        canonical_snapshot_hash = format_args!("{canonical_snapshot_hash:016x}"),
                        reason = "unchanged_candidate_snapshot_cooldown",
                        "Skipping duplicate automatic Direct recovery publication and its local synchronized punch"
                );
                    return None;
            }

            let punch_at_ms = Some(relay_assisted_punch_at_ms());
                if let Err(error) = control
                .send_peer_offer_with_sources_and_punch_at(
                    &peer_id,
                    &candidates,
                    &candidate_sources,
                    &[],
                    punch_at_ms,
                    None,
                )
                .await
            {
                    warn!(
                    event = "direct_recovery_candidate_kick_failed",
                    peer_id = %peer_id,
                        snapshot_hash = format_args!("{snapshot_hash:016x}"),
                    error = %error,
                        reason = "offer_not_accepted_no_local_synchronized_punch",
                    "Failed to publish the automatic direct recovery candidate kick"
                    );
                    return None;
            }

                info!(
                    event = "direct_recovery_candidate_kick_sent",
                    peer_id = %peer_id,
                    candidate_count = candidates.len(),
                    snapshot_hash = format_args!("{snapshot_hash:016x}"),
                    canonical_snapshot_hash = format_args!("{canonical_snapshot_hash:016x}"),
                    punch_at_ms = ?punch_at_ms,
                    "Published current UDP candidates to trigger automatic direct recovery"
                );

            let signal = Some(HolePunchSignalContext {
                control: control.clone(),
                candidate_snapshot,
                stun_servers: runtime_stun_servers.read().await.clone(),
                stun_timeout,
                boot_epoch_ms,
            });
                spawn_hole_punch_task_with_lifecycle(
                udp,
                peers,
                punch_deduplicator,
                    peer_id.clone(),
                probe_interval,
                attempts.clamp(1, 3),
                punch_at_ms,
                signal,
                None,
                None,
                    Some(punch_shutdown_rx),
            )
            .await;
                Some((snapshot_hash, now))
                } => published_snapshot,
            };

            owner.finish(published_snapshot);
        });
    }));
}

async fn run_udp_direct_task(ctx: UdpDirectTaskContext) -> Result<()> {
    let excluded_interfaces = ctx.excluded_interfaces.clone();
    run_udp_direct_task_with_binder(ctx, move |udp_bind, peers| {
        let excluded_interfaces = excluded_interfaces.clone();
        async move {
            let environment = tokio::task::spawn_blocking(move || {
                crate::netenv::direct_route_snapshot(&excluded_interfaces)
            })
            .await
            .map_err(|error| {
                DaemonError::Network(format!("direct-route inspection task failed: {error}"))
            })?;
            // Pin every direct UDP socket whenever a physical route is known,
            // not only when a *foreign* TUN was detected.  The daemon's own
            // TUN is intentionally excluded from the diagnostic capture flag,
            // but it must still never become the egress for its public control,
            // STUN, or peer traffic.
            let outbound_interface = environment
                .direct_socket_interface()
                .map_err(DaemonError::Network)?;
            if let Some(interface) = outbound_interface.as_deref() {
                info!(
                    interface,
                    capture_interface = ?environment.capture_iface,
                    "Binding direct UDP sockets to the physical route interface"
                );
            }
            UdpTransport::bind_to_interface(udp_bind, peers, outbound_interface).await
        }
    })
    .await
}

/// Supervise UDP binding for the daemon lifetime.  A socket bind or reader
/// failure must unpublish its instance and retry; returning `Ok(())` would
/// otherwise leave WireGuard inbound permanently disconnected from UDP.
async fn run_udp_direct_task_with_binder<F, Fut>(
    ctx: UdpDirectTaskContext,
    mut bind: F,
) -> Result<()>
where
    F: FnMut(SocketAddr, Arc<PeerManager>) -> Fut,
    Fut: std::future::Future<Output = Result<UdpTransport>>,
{
    // Each worker permit pool outlives individual UDP socket instances. A
    // rebind may begin while retired validation or peer-reflexive workers are
    // still unwinding, so every replacement scheduler consumes the same
    // daemon-lifetime capacity.
    let direct_validation_worker_permits = new_direct_validation_worker_permits();
    let peer_reflexive_signal_worker_permits = new_peer_reflexive_signal_worker_permits();
    let mut retry_delay = udp_direct_retry_initial_delay();
    // A successful UDP instance owns the Direct evidence for the current
    // socket incarnation.  If that instance exits and a later bind succeeds,
    // the old PeerConnection Direct state must not survive the rebind: its
    // endpoint/affinity may belong to a closed NAT mapping and its validation
    // ACKs may still be in flight.  The generation advance below fences both
    // before the replacement starts probing.
    let mut had_live_udp_instance = false;
    loop {
        if udp_direct_shutdown_requested(&ctx.shutdown_rx) {
            return Ok(());
        }

        let mut instance_ctx = ctx.clone();
        if had_live_udp_instance {
            let (resolved_stun, resolved_observers) = tokio::join!(
                parse_stun_servers(&ctx.stun_server_specs, ctx.stun_timeout),
                async {
                    if ctx.udp_observer_specs.is_empty() {
                        Ok(Vec::new())
                    } else {
                        parse_stun_servers(&ctx.udp_observer_specs, ctx.stun_timeout).await
                    }
                },
            );
            match (resolved_stun, resolved_observers) {
                (Ok(mut stun), Ok(observers)) => {
                    for observer in observers {
                        if !stun.contains(&observer) {
                            stun.push(observer);
                        }
                    }
                    instance_ctx.stun_servers = stun.clone();
                    *ctx.runtime_stun_servers.write().await = stun;
                    info!(
                        count = instance_ctx.stun_servers.len(),
                        "Re-resolved STUN/observer endpoints after UDP transport change"
                    );
                }
                (Err(error), _) | (_, Err(error)) => warn!(
                    "Failed to re-resolve STUN/observer endpoints after network change; retaining the last resolved set: {error}"
                ),
            }
        }

        let (result, instance_runtime) = match bind(ctx.udp_bind, ctx.peers.clone()).await {
            Ok(udp) => {
                if had_live_udp_instance {
                    let generation = ctx
                        .peers
                        .advance_network_generation("udp_transport_rebind")
                        .await;
                    info!(
                        generation,
                        "UDP transport rebound; invalidated the previous Direct socket generation before publishing replacement"
                    );
                }
                had_live_udp_instance = true;
                let instance_started_at = Instant::now();
                (
                    run_udp_direct_instance(
                        instance_ctx,
                        udp,
                        direct_validation_worker_permits.clone(),
                        peer_reflexive_signal_worker_permits.clone(),
                    )
                    .await,
                    Some(instance_started_at.elapsed()),
                )
            }
            Err(err) => (Err(err), None),
        };

        if udp_direct_shutdown_requested(&ctx.shutdown_rx) {
            return Ok(());
        }

        if let Some(instance_runtime) = instance_runtime {
            let reset_retry_delay =
                udp_direct_retry_delay_after_instance(retry_delay, instance_runtime);
            if reset_retry_delay != retry_delay {
                info!(
                    runtime_ms = instance_runtime.as_millis(),
                    "UDP direct instance was stable; resetting bind retry backoff"
                );
                retry_delay = reset_retry_delay;
            }
        }

        match result {
            Ok(()) => warn!(
                "UDP direct instance stopped unexpectedly; retrying bind in {}ms",
                retry_delay.as_millis()
            ),
            Err(err) => warn!(
                "UDP direct instance failed ({err}); retrying bind in {}ms",
                retry_delay.as_millis()
            ),
        }

        if wait_for_udp_direct_retry_or_shutdown(ctx.shutdown_rx.clone(), retry_delay).await {
            return Ok(());
        }
        retry_delay = retry_delay
            .checked_mul(2)
            .unwrap_or_else(udp_direct_retry_max_delay)
            .min(udp_direct_retry_max_delay());
    }
}

async fn run_udp_direct_instance(
    ctx: UdpDirectTaskContext,
    udp: UdpTransport,
    direct_validation_worker_permits: Arc<tokio::sync::Semaphore>,
    peer_reflexive_signal_worker_permits: Arc<tokio::sync::Semaphore>,
) -> Result<()> {
    let UdpDirectTaskContext {
        udp_bind: _,
        peers,
        control,
        local_candidates,
        local_candidate_sources: udp_local_candidate_sources,
        local_network_identity,
        candidate_snapshot,
        candidate_refresh_lock,
        nat_profile,
        gateway_mapping_runtime,
        gateway_mapping_diagnostics,
        udp_transport_publication,
        direct_validation_transport,
        direct_validation_local_ip,
        udp_inbound_tx,
        local_node_id,
        stun_servers,
        stun_server_specs: _,
        udp_observer_specs: _,
        runtime_stun_servers,
        stun_timeout,
        udp_advertise,
        upnp_enabled,
        socket_pool_enabled,
        socket_pool_size,
        keepalive_interval,
        punch_deduplicator,
        udp_punch_interval,
        udp_punch_attempts,
        boot_epoch_ms,
        proxy_env,
        excluded_interfaces,
        shutdown_rx,
    } = ctx;

    let udp = if socket_pool_enabled {
        match udp.clone().with_socket_pool(socket_pool_size).await {
            Ok(udp) => udp,
            Err(error) => {
                warn!(
                            "Failed to create experimental UDP socket pool; using the primary socket only: {error}"
                        );
                udp
            }
        }
    } else {
        udp
    };
    let peer_reflexive_ingress = PeerReflexiveIngress::new();
    // Every source of direct-validation evidence feeds this bounded
    // per-peer newest-wins ingress. The scheduler is the only place
    // that may spawn a validation worker; it grants at most one lease
    // per peer/generation and has its own hard global worker cap.
    let validation_ingress = DirectValidationIngress::new();
    let udp = udp
        .with_local_node_id(local_node_id.clone())
        .with_wireguard_transport(direct_validation_transport.clone())
        .with_inbound_channel(udp_inbound_tx.clone())
        .with_peer_reflexive_observer(peer_reflexive_ingress.clone());
    // Matched ACKs enter the same scheduler as peer-reflexive
    // observations. The ingress is synchronous/nonblocking for the
    // UDP reader and retains each queued peer's newest endpoint.
    let trigger_ingress = validation_ingress.clone();
    let trigger = std::sync::Arc::new(move |observation: PeerReflexiveObservation| {
        trigger_ingress.submit(observation);
    });
    let udp = udp.with_validation_trigger(trigger);
    // Peer lifecycle transitions revoke heartbeat leases synchronously. The
    // transport owns the lease registry, so the callback only sends the
    // cancellation signal and never performs async work under peer locks.
    let heartbeat_cancel_udp = udp.clone();
    peers.set_relay_backoff_heartbeat_cancel_hook(std::sync::Arc::new(move |peer_id| {
        heartbeat_cancel_udp.cancel_relay_backoff_heartbeat(peer_id);
    }));
    // Publication is intentionally before the initial STUN/candidate lock.
    // A refresh can hold that lock while a failed socket is rebound; inbound
    // WireGuard must nevertheless see the replacement immediately.
    let lease = udp_transport_publication.publish(udp.clone()).await;
    let validation_scheduler_worker =
        tokio::spawn(run_direct_validation_scheduler_until_cancelled(
            validation_ingress,
            udp.clone(),
            peers.clone(),
            direct_validation_transport.clone(),
            direct_validation_local_ip.clone(),
            direct_validation_worker_permits,
            lease.shutdown_receiver(),
        ));
    let peer_reflexive_worker = tokio::spawn(run_peer_reflexive_signal_loop_until_cancelled(
        peer_reflexive_ingress,
        control.clone(),
        udp.clone(),
        peers.clone(),
        punch_deduplicator.clone(),
        peer_reflexive_signal_worker_permits,
        lease.shutdown_receiver(),
    ));

    // Start the reader before the initial STUN gather. The live gather uses
    // the reader-owned STUN waiter registry; starting it only after a serial
    // gather made public candidates wait behind observer timeouts and left
    // the first Direct offer with only a private host candidate.
    let mut inbound_worker = tokio::spawn({
        let udp = udp.clone();
        let inbound_tx = udp_inbound_tx.clone();
        async move { udp.run_inbound(inbound_tx).await }
    });

    let local_interface_networks = p2pnet_nat::gather_local_networks();
    info!(
        count = local_interface_networks.len(),
        "Updated local directly-connected networks for on-link Host probing"
    );
    peers
        .set_local_interface_networks(local_interface_networks)
        .await;

    // Publish host candidates as soon as the socket has a port.  The full
    // report below may spend seconds probing an unreachable STUN observer;
    // that delay is useful for NAT classification but must not delay the
    // first encrypted relay session or the first LAN/public host punch.
    if peers.gather_host_candidates().await {
        if let Ok(local_addr) = udp.local_addr() {
            let mut host_candidates = p2pnet_nat::gather_local_addresses()
                .into_iter()
                .filter(|ip| ip.is_ipv4() == local_addr.ip().is_ipv4())
                .map(|ip| SocketAddr::new(ip, local_addr.port()).to_string())
                .collect::<Vec<_>>();
            if !local_addr.ip().is_unspecified() && !local_addr.ip().is_loopback() {
                host_candidates.push(local_addr.to_string());
            }
            host_candidates.sort();
            host_candidates.dedup();
            if !host_candidates.is_empty() {
                let mut host_sources = host_candidates
                    .iter()
                    .cloned()
                    .map(|endpoint| (endpoint, "host".to_string()))
                    .collect::<HashMap<_, _>>();
                let host_network_identity = prepare_signal_candidates_and_network_identity(
                    &[],
                    &HashMap::new(),
                    &mut host_candidates,
                    &mut host_sources,
                );
                // This fast path must never wait behind an older refresh: a
                // rebound UDP instance must still observe shutdown promptly.
                if let Ok(_host_commit_guard) = candidate_refresh_lock.try_lock() {
                    publish_candidate_snapshot_to_store(
                        &candidate_snapshot,
                        host_candidates.clone(),
                        host_sources.clone(),
                        host_network_identity.clone(),
                    )
                    .await;
                    *local_candidates.write().await = host_candidates.clone();
                    *udp_local_candidate_sources.write().await = host_sources;
                    *local_network_identity.write().await = host_network_identity;
                    info!(
                        "Published {} host UDP candidates before STUN refresh",
                        host_candidates.len()
                    );
                }
            }
        }
    }

    // Do not let a slow initial STUN refresh hide a successfully rebound UDP
    // transport. If this lease is superseded while waiting, skip candidate
    // work entirely and let the common cleanup below withdraw only our owner.
    let initial_refresh_guard = tokio::select! {
        guard = candidate_refresh_lock.lock() => Some(guard),
        _ = wait_for_udp_direct_stop(shutdown_rx.clone(), lease.shutdown_receiver()) => None,
    };
    let outcome = if let Some(initial_refresh_guard) = initial_refresh_guard {
        let mut advertised_nat_type = "unknown".to_string();

        let (mut candidate_endpoints, mut candidate_sources) = match udp
            .gather_candidate_report_live_parallel(stun_servers.clone(), stun_timeout)
            .await
        {
            Ok(report) => {
                let (endpoints, sources) = candidate_endpoints_from_report(&report);
                info!(
                            "Local NAT profile: mapping={:?} public={:?} stun_success={}/{} confidence={} egress={}",
                            report.nat_profile.mapping_behavior,
                            report.nat_profile.public_endpoint,
                            report
                                .nat_profile
                                .observations
                                .iter()
                                .filter(|observation| observation.mapped_address.is_some())
                                .count(),
                            report.nat_profile.observations.len(),
                            report.nat_profile.confidence,
                            proxy_env.label(),
                );
                peers.update_nat_profile(report.nat_profile.clone()).await;
                advertised_nat_type = report
                    .nat_profile
                    .control_label_with_generation(peers.current_local_profile_generation_sync());
                let pool_eligible = socket_pool_enabled
                    && report.nat_profile.mapping_behavior
                        == MappingBehavior::AddressOrPortDependent
                    && !report.nat_profile.udp_blocked;
                udp.set_socket_pool_active(pool_eligible);
                if udp.socket_count() > 1 {
                    info!(
                        "Experimental UDP socket pool: sockets={} active={} reason={}",
                        udp.socket_count(),
                        udp.socket_pool_active(),
                        if pool_eligible {
                            "address/port-dependent mapping"
                        } else {
                            "NAT profile did not qualify"
                        }
                    );
                }
                *nat_profile.write().await = Some(report.nat_profile);
                (endpoints, sources)
            }
            Err(err) => {
                warn!("Failed to gather UDP candidates: {err}");
                (Vec::new(), HashMap::new())
            }
        };

        match udp.local_addr() {
            Ok(addr) => {
                if let Some(endpoint) = advertised_udp_endpoint(
                    addr,
                    udp_advertise.as_deref(),
                    &candidate_endpoints,
                    peers.gather_host_candidates().await,
                ) {
                    // The advertised endpoint is the peer's PRIMARY punch
                    // target and must be FIRST in the signaled order (the
                    // receiver preserves signal order as its probe
                    // priority).  The public mapping is already present
                    // from gathering, so move it to the front instead of
                    // only inserting when absent (field evidence:
                    // v0.1.116 acceptance rounds where the private host
                    // endpoint stayed first timed out at ~102 s because
                    // the peer punched the unreachable private address).
                    if let Some(index) = candidate_endpoints.iter().position(|c| c == &endpoint) {
                        candidate_endpoints.remove(index);
                    }
                    candidate_endpoints.insert(0, endpoint.clone());
                    candidate_sources
                        .entry(endpoint.clone())
                        .or_insert_with(|| {
                            if udp_advertise.as_deref().is_some_and(|configured| {
                                !configured.trim().is_empty() && configured.trim() == endpoint
                            }) {
                                "manual".to_string()
                            } else {
                                "host".to_string()
                            }
                        });
                    info!("UDP transport listening on {addr}; advertising {endpoint}");
                } else {
                    warn!(
                            "UDP transport listening on {addr}; no reachable endpoint was discovered or configured."
                        );
                }
            }
            Err(err) => {
                warn!("UDP transport bound but local addr unavailable: {err}")
            }
        }

        let initial_network_identity = prepare_signal_candidates_and_network_identity(
            &[],
            &HashMap::new(),
            &mut candidate_endpoints,
            &mut candidate_sources,
        );
        // Commit the candidate snapshot BEFORE the endpoint publish and
        // any gateway-mapping discovery.  A congested control lane or a
        // silent SSDP gateway must never delay the local candidate commit
        // (which every responder answer reads).
        info!(
            "Prepared {} UDP candidate endpoints for signaling",
            candidate_endpoints.len()
        );
        publish_candidate_snapshot_to_store(
            &candidate_snapshot,
            candidate_endpoints.clone(),
            candidate_sources.clone(),
            initial_network_identity.clone(),
        )
        .await;
        *local_candidates.write().await = candidate_endpoints.clone();
        *udp_local_candidate_sources.write().await = candidate_sources.clone();
        *local_network_identity.write().await = initial_network_identity.clone();
        // `initial_refresh_guard` is the incarnation fence for candidate
        // publishers. An old detached gateway-mapping task that passed its
        // owner check must still hold this lock, so it completes before this
        // guard is acquired. A task that acquires it later observes the new
        // transport owner and discards its result. Installing the recovery
        // hook only after this incarnation commits its first snapshot makes
        // that snapshot authoritative without relying on wall/monotonic time.
        install_direct_recovery_kick_hook(
            &peers,
            &control,
            &udp,
            &candidate_snapshot,
            &runtime_stun_servers,
            stun_timeout,
            &punch_deduplicator,
            udp_punch_interval,
            udp_punch_attempts,
            boot_epoch_ms,
            lease.shutdown_receiver(),
        );
        if upnp_enabled {
            // Gateway mapping discovery (SSDP/IGD/PCP/NAT-PMP) can take
            // seconds on gateways without a mapping service.  It must
            // never block the commit or hold the refresh lock; run it as
            // bounded best-effort background work and fold any discovered
            // candidate back into the committed set.
            let local_addr = udp.local_addr().ok();
            let local_candidates = local_candidates.clone();
            let local_sources = udp_local_candidate_sources.clone();
            let candidate_snapshot = candidate_snapshot.clone();
            let candidate_refresh_lock = candidate_refresh_lock.clone();
            let runtime = gateway_mapping_runtime.clone();
            let diagnostics = gateway_mapping_diagnostics.clone();
            let mapping_publication = udp_transport_publication.clone();
            let mapping_owner = lease.owner();
            tokio::spawn(async move {
                let mut discovered = Vec::new();
                let mut discovered_sources = HashMap::new();
                maybe_add_port_mapping_udp_candidate(
                    local_addr,
                    &mut discovered,
                    &mut discovered_sources,
                    runtime,
                    diagnostics,
                )
                .await;
                if discovered.is_empty() {
                    return;
                }
                let _refresh_guard = candidate_refresh_lock.lock().await;
                if !mapping_publication.is_current_owner(mapping_owner).await {
                    debug!("Discarding gateway mapping discovered by a superseded UDP transport");
                    return;
                }
                let Some(current) = candidate_snapshot.read().await.clone() else {
                    return;
                };
                let mut candidates = current.candidates;
                let mut sources = current.candidate_sources;
                for endpoint in discovered {
                    if !candidates.contains(&endpoint) {
                        candidates.push(endpoint.clone());
                    }
                    if let Some(source) = discovered_sources.get(&endpoint) {
                        sources.insert(endpoint, source.clone());
                    }
                }
                publish_candidate_snapshot_to_store(
                    &candidate_snapshot,
                    candidates.clone(),
                    sources.clone(),
                    current.network_identity,
                )
                .await;
                *local_candidates.write().await = candidates;
                *local_sources.write().await = sources;
            });
        }
        let mut published_endpoint = None;
        if let Some(endpoint) =
            control_udp_endpoint_from_candidates(&candidate_endpoints, &candidate_sources)
        {
            // The handshake control lane has its own bounded deadline; a
            // short caller budget keeps a pathological lane from stalling
            // transport startup.
            match tokio::time::timeout(
                Duration::from_millis(STARTUP_ENDPOINT_PUBLISH_BUDGET_MS),
                control.update_endpoint_for_handshake(&endpoint, &advertised_nat_type),
            )
            .await
            {
                Ok(Ok(())) => published_endpoint = Some(endpoint),
                Ok(Err(err)) => {
                    warn!("Failed to publish initial UDP endpoint '{endpoint}': {err}")
                }
                Err(_) => {
                    warn!("Initial UDP endpoint publish '{endpoint}' exceeded its budget")
                }
            }
        }
        drop(initial_refresh_guard);

        // Candidate-only fan-out is background work.  Starting the UDP
        // reader and validation workers must not wait behind a serial
        // control lane servicing a large peer roster; a foreground
        // handshake can then use the critical offer lane immediately.
        let initial_publication_worker = tokio::spawn({
            let control = control.clone();
            let peers = peers.clone();
            let udp = udp.clone();
            let punch_deduplicator = punch_deduplicator.clone();
            let candidates = candidate_endpoints.clone();
            let candidate_sources = candidate_sources.clone();
            let candidate_snapshot = candidate_snapshot.clone();
            let stun_servers = stun_servers.clone();
            let signal_control = control.clone();
            async move {
                publish_local_candidates_to_known_peers(
                    &control,
                    peers,
                    udp,
                    punch_deduplicator,
                    &candidates,
                    &candidate_sources,
                    udp_punch_interval,
                    udp_punch_attempts,
                    "initial UDP candidates ready",
                    Some(HolePunchSignalContext {
                        control: signal_control,
                        candidate_snapshot: candidate_snapshot.clone(),
                        stun_servers,
                        stun_timeout,
                        boot_epoch_ms,
                    }),
                )
                .await;
            }
        });

        // Route inspection invokes platform commands (`route`/`ip`) and must
        // not block the async runtime while the UDP instance is starting.
        let route_excluded_interfaces = excluded_interfaces.clone();
        let initial_route_signature = tokio::task::spawn_blocking(move || {
            crate::netenv::network_route_signature(&route_excluded_interfaces)
        })
        .await
        .unwrap_or_default();
        let outcome = if keepalive_interval.is_zero() {
            let refresh_udp = udp.clone();
            tokio::select! {
                result = &mut inbound_worker => match result {
                    Ok(result) => result,
                    Err(error) => Err(DaemonError::Network(format!(
                        "UDP inbound worker failed: {error}"
                    ))),
                },
                _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                    udp: refresh_udp,
                    stun_servers,
                    stun_timeout,
                    udp_advertise,
                    upnp_enabled,
                    published_endpoint,
                     local_candidates: local_candidates.clone(),
                     local_candidate_sources: udp_local_candidate_sources.clone(),
                     local_network_identity: local_network_identity.clone(),
                     candidate_snapshot: candidate_snapshot.clone(),
                    candidate_refresh_lock: candidate_refresh_lock.clone(),
                    nat_profile,
                    gateway_mapping_runtime,
                    gateway_mapping_diagnostics,
                    punch_deduplicator,
                    control,
                    peers: peers.clone(),
                    probe_interval: udp_punch_interval,
                    punch_attempts: udp_punch_attempts,
                    boot_epoch_ms,
                }) => Ok(()),
                changed = wait_for_network_route_change(initial_route_signature, excluded_interfaces.clone()) => {
                    Err(DaemonError::Network(format!("network route changed; rebuilding direct UDP transport: {changed:?}")))
                },
                _ = wait_for_udp_direct_stop(shutdown_rx.clone(), lease.shutdown_receiver()) => Ok(()),
            }
        } else {
            let keepalive_udp = udp.clone();
            let refresh_udp = udp.clone();
            tokio::select! {
                result = &mut inbound_worker => match result {
                    Ok(result) => result,
                    Err(error) => Err(DaemonError::Network(format!(
                        "UDP inbound worker failed: {error}"
                    ))),
                },
                _ = keepalive_udp.run_keepalives(keepalive_interval) => Ok(()),
                _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                    udp: refresh_udp,
                    stun_servers,
                    stun_timeout,
                    udp_advertise,
                    upnp_enabled,
                    published_endpoint,
                     local_candidates: local_candidates.clone(),
                     local_candidate_sources: udp_local_candidate_sources.clone(),
                     local_network_identity: local_network_identity.clone(),
                     candidate_snapshot: candidate_snapshot.clone(),
                    candidate_refresh_lock: candidate_refresh_lock.clone(),
                    nat_profile,
                    gateway_mapping_runtime,
                    gateway_mapping_diagnostics,
                    punch_deduplicator,
                    control,
                    peers: peers.clone(),
                    probe_interval: udp_punch_interval,
                    punch_attempts: udp_punch_attempts,
                    boot_epoch_ms,
                }) => Ok(()),
                changed = wait_for_network_route_change(initial_route_signature, excluded_interfaces.clone()) => {
                    Err(DaemonError::Network(format!("network route changed; rebuilding direct UDP transport: {changed:?}")))
                },
                _ = wait_for_udp_direct_stop(shutdown_rx.clone(), lease.shutdown_receiver()) => Ok(()),
            }
        };
        initial_publication_worker.abort();
        let _ = initial_publication_worker.await;
        outcome
    } else {
        Ok(())
    };

    inbound_worker.abort();
    let _ = inbound_worker.await;

    // This sends the ownership-scoped stop signal before withdrawing the
    // watch value and cancels every validation owner tied to this socket.  A
    // superseded worker gets `false` here and therefore cannot erase the
    // replacement published by a newer owner.
    udp.cancel_all_direct_validation_sessions().await;
    udp.cancel_all_relay_backoff_heartbeats();
    let withdrew_current = udp_transport_publication
        .clear_if_owner(lease.owner())
        .await;
    if withdrew_current && udp_transport_publication.current_owner().await.is_none() {
        if let Ok(_refresh_guard) = candidate_refresh_lock.try_lock() {
            // Never signal endpoints from a socket that has already closed.
            *candidate_snapshot.write().await = None;
            local_candidates.write().await.clear();
            udp_local_candidate_sources.write().await.clear();
            local_network_identity.write().await.clear();
        } else {
            // Shutdown and replacement must not wait behind a stuck STUN
            // gather. Clear asynchronously after that gather releases the
            // lock, but only if no replacement transport has appeared.
            let publication = udp_transport_publication.clone();
            let candidate_snapshot = candidate_snapshot.clone();
            let local_candidates = local_candidates.clone();
            let local_candidate_sources = udp_local_candidate_sources.clone();
            let local_network_identity = local_network_identity.clone();
            let deferred_refresh_lock = candidate_refresh_lock.clone();
            tokio::spawn(async move {
                let _refresh_guard = deferred_refresh_lock.lock().await;
                if publication.current_owner().await.is_some() {
                    return;
                }
                *candidate_snapshot.write().await = None;
                local_candidates.write().await.clear();
                local_candidate_sources.write().await.clear();
                local_network_identity.write().await.clear();
            });
        }
    }
    stop_direct_validation_scheduler_worker(validation_scheduler_worker).await;
    stop_peer_reflexive_signal_worker(peer_reflexive_worker).await;
    outcome
}

/// Poll the kernel route view and require the same changed signature twice.
/// Route commands can transiently return an empty/partial view during DHCP;
/// the two-sample confirmation avoids tearing down a healthy transport for a
/// single incomplete read while still rebuilding within a few seconds.
async fn wait_for_network_route_change(
    baseline: Vec<String>,
    excluded_interfaces: Vec<String>,
) -> Vec<String> {
    let mut ticker = interval(Duration::from_secs(1));
    ticker.tick().await;
    let mut confirmation = RouteChangeConfirmation::new(baseline);
    loop {
        ticker.tick().await;
        let excluded = excluded_interfaces.clone();
        let current =
            tokio::task::spawn_blocking(move || crate::netenv::network_route_signature(&excluded))
                .await
                .unwrap_or_default();
        if let Some(changed) = confirmation.observe(current) {
            return changed;
        }
    }
}

#[derive(Debug)]
struct RouteChangeConfirmation {
    baseline: Vec<String>,
    pending_change: Option<Vec<String>>,
}

impl RouteChangeConfirmation {
    fn new(baseline: Vec<String>) -> Self {
        Self {
            baseline,
            pending_change: None,
        }
    }

    fn observe(&mut self, current: Vec<String>) -> Option<Vec<String>> {
        if current.is_empty() {
            self.pending_change = None;
            return None;
        }
        if self.baseline.is_empty() {
            self.baseline = current;
            return None;
        }
        if current == self.baseline {
            self.pending_change = None;
            return None;
        }
        if self.pending_change.as_ref() == Some(&current) {
            return Some(current);
        }
        self.pending_change = Some(current);
        None
    }
}

fn udp_direct_retry_initial_delay() -> Duration {
    #[cfg(test)]
    {
        Duration::from_millis(10)
    }
    #[cfg(not(test))]
    {
        Duration::from_millis(500)
    }
}

fn udp_direct_retry_max_delay() -> Duration {
    #[cfg(test)]
    {
        Duration::from_millis(100)
    }
    #[cfg(not(test))]
    {
        Duration::from_secs(10)
    }
}

/// A live socket earns a retry reset only after it has survived long enough
/// that the preceding failure is no longer likely to be an immediate bind or
/// reader crash loop.  A short-lived successful bind intentionally retains
/// its exponential backoff.
fn udp_direct_retry_reset_after() -> Duration {
    #[cfg(test)]
    {
        Duration::from_millis(25)
    }
    #[cfg(not(test))]
    {
        Duration::from_secs(30)
    }
}

fn udp_direct_retry_delay_after_instance(
    retry_delay: Duration,
    instance_runtime: Duration,
) -> Duration {
    if instance_runtime >= udp_direct_retry_reset_after() {
        udp_direct_retry_initial_delay()
    } else {
        retry_delay
    }
}

fn udp_direct_shutdown_requested(shutdown_rx: &tokio::sync::watch::Receiver<bool>) -> bool {
    *shutdown_rx.borrow()
}

async fn wait_for_udp_direct_shutdown(mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *shutdown_rx.borrow_and_update() {
            return;
        }
        if shutdown_rx.changed().await.is_err() {
            return;
        }
    }
}

async fn wait_for_udp_direct_retry_or_shutdown(
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
    retry_delay: Duration,
) -> bool {
    if *shutdown_rx.borrow_and_update() {
        return true;
    }
    tokio::select! {
        _ = sleep(retry_delay) => false,
        changed = shutdown_rx.changed() => {
            changed.is_err() || *shutdown_rx.borrow_and_update()
        }
    }
}

async fn wait_for_udp_direct_stop(
    daemon_shutdown_rx: tokio::sync::watch::Receiver<bool>,
    instance_shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::select! {
        _ = wait_for_udp_direct_shutdown(daemon_shutdown_rx) => {},
        _ = wait_for_udp_direct_shutdown(instance_shutdown_rx) => {},
    }
}

/// Tie the authoritative validation scheduler to this UDP transport instance.
/// A failed/replaced transport first cancels every registry owner, then this
/// wrapper drops the queue receiver; no scheduler can outlive its socket.
async fn run_direct_validation_scheduler_until_cancelled(
    observations: DirectValidationIngress,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
    worker_permits: Arc<tokio::sync::Semaphore>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::select! {
        _ = run_direct_validation_scheduler(observations, udp, peers, transport, local_virtual_ip, worker_permits) => {},
        _ = wait_for_udp_direct_shutdown(shutdown_rx) => {},
    }
}

/// Tie the peer-reflexive loop to the transport instance that owns it.  The
/// historical detached task held a sender and receiver for its own channel,
/// so it could outlive a failed socket forever; this wrapper exits whenever
/// that instance is superseded or withdrawn.
async fn run_peer_reflexive_signal_loop_until_cancelled(
    ingress: PeerReflexiveIngress,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    worker_permits: Arc<tokio::sync::Semaphore>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::select! {
        _ = run_peer_reflexive_signal_loop(ingress, control, udp, peers, punch_deduplicator, worker_permits) => {},
        _ = wait_for_udp_direct_shutdown(shutdown_rx) => {},
    }
}

async fn stop_peer_reflexive_signal_worker(mut worker: tokio::task::JoinHandle<()>) {
    if timeout(Duration::from_secs(1), &mut worker).await.is_err() {
        worker.abort();
        let _ = worker.await;
    }
}

// `udp_direct.rs` is included at the crate root; avoid colliding with the
// crate-wide `mod tests` declaration in `lib.rs`.
#[cfg(test)]
mod udp_direct_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::{mpsc, watch};
    use tokio::time::timeout;

    use super::*;

    #[test]
    fn direct_recovery_kick_gate_single_flights_and_deduplicates_content() {
        let mut gate = DirectRecoveryKickGate::default();
        let started_at = Instant::now();

        assert!(gate.try_begin("peer-a", started_at));
        assert!(
            !gate.try_begin("peer-a", started_at + Duration::from_secs(3)),
            "an in-flight owner must suppress every overlapping recovery task"
        );
        assert_eq!(
            gate.plan("peer-a", 0x11, started_at),
            DirectRecoveryKickPlan::PublishCoordinatedPunch
        );
        gate.finish("peer-a", Some((0x11, started_at)));

        let duplicate_at = started_at + DIRECT_RECOVERY_KICK_MIN_INTERVAL;
        assert!(gate.try_begin("peer-a", duplicate_at));
        assert_eq!(
            gate.plan("peer-a", 0x11, duplicate_at),
            DirectRecoveryKickPlan::SkipUnchanged,
            "an unchanged snapshot must neither be re-published nor start a one-sided punch every two seconds"
        );
        gate.finish("peer-a", None);

        let changed_at = duplicate_at + DIRECT_RECOVERY_KICK_MIN_INTERVAL;
        assert!(gate.try_begin("peer-a", changed_at));
        assert_eq!(
            gate.plan("peer-a", 0x22, changed_at),
            DirectRecoveryKickPlan::PublishCoordinatedPunch,
            "new candidate content must bypass the unchanged-snapshot cooldown"
        );
        gate.finish("peer-a", Some((0x22, changed_at)));

        let refresh_at = changed_at + DIRECT_RECOVERY_UNCHANGED_REPUBLISH_INTERVAL;
        assert!(gate.try_begin("peer-a", refresh_at));
        assert_eq!(
            gate.plan("peer-a", 0x22, refresh_at),
            DirectRecoveryKickPlan::PublishCoordinatedPunch,
            "unchanged content must be refreshed before its signaling lease expires"
        );
    }

    #[test]
    fn direct_recovery_snapshot_hash_preserves_probe_priority_order() {
        let first = "198.51.100.10:41000".to_string();
        let second = "198.51.100.10:41001".to_string();
        let sources = HashMap::from([
            (first.clone(), "stun_observed".to_string()),
            (second.clone(), "predicted".to_string()),
        ]);
        let ordered = vec![first.clone(), second.clone()];
        let reversed = vec![second, first];

        let ordered_hash = direct_recovery_ordered_snapshot_hash(&ordered, &sources);
        let reversed_hash = direct_recovery_ordered_snapshot_hash(&reversed, &sources);
        assert_ne!(
            ordered_hash, reversed_hash,
            "candidate order is probe priority and must be part of recovery deduplication"
        );

        let mut gate = DirectRecoveryKickGate::default();
        let started_at = Instant::now();
        assert!(gate.try_begin("peer-order", started_at));
        gate.finish("peer-order", Some((ordered_hash, started_at)));
        let reordered_at = started_at + DIRECT_RECOVERY_KICK_MIN_INTERVAL;
        assert!(gate.try_begin("peer-order", reordered_at));
        assert_eq!(
            gate.plan("peer-order", reversed_hash, reordered_at),
            DirectRecoveryKickPlan::PublishCoordinatedPunch,
            "a priority reorder must publish a new coordinated offer"
        );
    }

    #[test]
    fn failed_recovery_publication_keeps_fast_retry_available() {
        let mut gate = DirectRecoveryKickGate::default();
        let started_at = Instant::now();
        assert!(gate.try_begin("peer-a", started_at));
        gate.finish("peer-a", None);

        let retry_at = started_at + DIRECT_RECOVERY_KICK_MIN_INTERVAL;
        assert!(gate.try_begin("peer-a", retry_at));
        assert_eq!(
            gate.plan("peer-a", 0x11, retry_at),
            DirectRecoveryKickPlan::PublishCoordinatedPunch,
            "a failed publication must not enter the long content cooldown"
        );
    }

    #[test]
    fn dropped_recovery_owner_releases_single_flight_reservation() {
        let gate = Arc::new(std::sync::Mutex::new(DirectRecoveryKickGate::default()));
        let started_at = Instant::now();
        assert!(gate.lock().unwrap().try_begin("peer-cancelled", started_at));

        {
            let _owner = DirectRecoveryKickOwner::new(gate.clone(), "peer-cancelled".to_string());
            assert!(gate.lock().unwrap().peers["peer-cancelled"].in_flight);
        }

        assert!(!gate.lock().unwrap().peers["peer-cancelled"].in_flight);
        assert!(gate.lock().unwrap().try_begin(
            "peer-cancelled",
            started_at + DIRECT_RECOVERY_KICK_MIN_INTERVAL,
        ));
    }

    #[test]
    fn direct_recovery_kick_gate_evicts_idle_entries_and_stays_bounded() {
        let mut gate = DirectRecoveryKickGate::default();
        let started_at = Instant::now();
        for index in 0..DIRECT_RECOVERY_KICK_GATE_MAX_PEERS {
            let peer_id = format!("peer-{index}");
            let attempted_at = started_at + Duration::from_millis(index as u64);
            assert!(gate.try_begin(&peer_id, attempted_at));
            gate.finish(&peer_id, None);
        }
        assert_eq!(gate.peers.len(), DIRECT_RECOVERY_KICK_GATE_MAX_PEERS);

        let overflow_at = started_at + Duration::from_secs(10);
        assert!(gate.try_begin("peer-overflow", overflow_at));
        assert_eq!(gate.peers.len(), DIRECT_RECOVERY_KICK_GATE_MAX_PEERS);
        assert!(!gate.peers.contains_key("peer-0"));
        assert!(gate.peers.contains_key("peer-overflow"));
    }

    #[test]
    fn route_change_requires_two_matching_nonempty_observations() {
        let baseline = vec!["default:en0:192.168.1.1".to_string()];
        let changed = vec!["default:en5:192.168.0.1".to_string()];
        let mut confirmation = RouteChangeConfirmation::new(baseline.clone());

        assert_eq!(confirmation.observe(Vec::new()), None);
        assert_eq!(confirmation.observe(changed.clone()), None);
        assert_eq!(confirmation.observe(baseline), None);
        assert_eq!(confirmation.observe(changed.clone()), None);
        assert_eq!(confirmation.observe(changed.clone()), Some(changed));
    }

    fn test_context(daemon: &Daemon, shutdown_rx: watch::Receiver<bool>) -> UdpDirectTaskContext {
        let (udp_inbound_tx, _udp_inbound_rx) = mpsc::channel(8);
        UdpDirectTaskContext {
            udp_bind: "127.0.0.1:0".parse().unwrap(),
            peers: daemon.peers.clone(),
            control: ControlClient::disabled_for_test(),
            local_candidates: daemon.local_candidates.clone(),
            local_candidate_sources: daemon.local_candidate_sources.clone(),
            local_network_identity: daemon.local_network_identity.clone(),
            candidate_snapshot: daemon.candidate_snapshot.clone(),
            candidate_refresh_lock: daemon.candidate_refresh_lock.clone(),
            nat_profile: daemon.nat_profile.clone(),
            gateway_mapping_runtime: daemon.gateway_mapping_runtime.clone(),
            gateway_mapping_diagnostics: daemon.gateway_mapping_diagnostics.clone(),
            udp_transport_publication: daemon.udp_transport_publication.clone(),
            direct_validation_transport: daemon.transport.clone(),
            direct_validation_local_ip: daemon.config.network.virtual_ip.clone(),
            udp_inbound_tx,
            local_node_id: daemon.config.node.node_id.clone(),
            stun_servers: Vec::new(),
            stun_server_specs: vec!["off".to_string()],
            udp_observer_specs: Vec::new(),
            runtime_stun_servers: daemon.runtime_stun_servers.clone(),
            stun_timeout: Duration::from_millis(10),
            udp_advertise: None,
            upnp_enabled: false,
            socket_pool_enabled: false,
            socket_pool_size: 1,
            keepalive_interval: Duration::ZERO,
            punch_deduplicator: daemon.punch_attempts.clone(),
            udp_punch_interval: Duration::from_millis(10),
            udp_punch_attempts: 1,
            boot_epoch_ms: 0,
            proxy_env: crate::netenv::ProxyEnvironment::default(),
            excluded_interfaces: Vec::new(),
            shutdown_rx,
        }
    }

    #[tokio::test]
    async fn udp_direct_retries_bind_failure_and_republishes_transport() {
        let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let context = test_context(&daemon, shutdown_rx);
        let mut updates = daemon.udp_transport_publication.subscribe();
        let attempts = Arc::new(AtomicUsize::new(0));
        let bind_attempts = attempts.clone();

        let worker = tokio::spawn(async move {
            run_udp_direct_task_with_binder(context, move |udp_bind, peers| {
                let attempts = bind_attempts.clone();
                async move {
                    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Err(DaemonError::Network(
                            "injected UDP bind failure".to_string(),
                        ));
                    }
                    UdpTransport::bind(udp_bind, peers).await
                }
            })
            .await
        });

        timeout(Duration::from_secs(3), updates.changed())
            .await
            .expect("a retry after bind failure must eventually publish UDP")
            .expect("the UDP publication sender must remain alive");
        assert!(updates.borrow().is_some());
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "the injected bind failure must be followed by a retry"
        );

        let _ = shutdown_tx.send(true);
        timeout(Duration::from_secs(3), worker)
            .await
            .expect("UDP supervisor must stop promptly on shutdown")
            .expect("UDP supervisor task must not panic")
            .expect("UDP supervisor must exit cleanly");
    }

    #[tokio::test]
    async fn udp_direct_publishes_before_initial_candidate_refresh_lock() {
        let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        // Simulate an already-running candidate refresh. A successful UDP
        // rebind must publish for WireGuard inbound before this slow path can
        // acquire the lock, and shutdown must not wait for the lock holder.
        let candidate_guard = daemon.candidate_refresh_lock.lock().await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let context = test_context(&daemon, shutdown_rx);
        let mut updates = daemon.udp_transport_publication.subscribe();

        let worker = tokio::spawn(run_udp_direct_task_with_binder(
            context,
            |udp_bind, peers| async move { UdpTransport::bind(udp_bind, peers).await },
        ));

        timeout(Duration::from_secs(1), updates.changed())
            .await
            .expect("bound UDP must publish before the initial candidate lock is released")
            .expect("the UDP publication sender must remain alive");
        assert!(updates.borrow().is_some());

        let _ = shutdown_tx.send(true);
        timeout(Duration::from_secs(1), worker)
            .await
            .expect("UDP supervisor must stop while initial candidate work is blocked")
            .expect("UDP supervisor task must not panic")
            .expect("UDP supervisor must exit cleanly");
        drop(candidate_guard);
    }

    #[tokio::test]
    async fn udp_direct_rebind_fences_snapshot_before_replacing_recovery_hook() {
        let daemon = Daemon::new(Config::generate_default("https://ctrl.test", "net1").unwrap());
        let stale_candidates = vec!["198.51.100.7:41000".to_string()];
        daemon
            .publish_candidate_snapshot_with_age(
                stale_candidates.clone(),
                HashMap::from([(stale_candidates[0].clone(), "stale".to_string())]),
                Duration::ZERO,
            )
            .await;

        // Model a detached publisher that passed its old-owner check while
        // holding the serialization lock. The replacement transport may be
        // published immediately, but its recovery hook must not become
        // visible until this writer drains and a current snapshot commits.
        let candidate_guard = daemon.candidate_refresh_lock.lock().await;
        let retired_hook_calls = Arc::new(AtomicUsize::new(0));
        let calls = retired_hook_calls.clone();
        daemon
            .peers
            .set_direct_recovery_kick_hook(Arc::new(move |_| {
                calls.fetch_add(1, Ordering::SeqCst);
            }));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let context = test_context(&daemon, shutdown_rx);
        let mut updates = daemon.udp_transport_publication.subscribe();
        let worker = tokio::spawn(run_udp_direct_task_with_binder(
            context,
            |udp_bind, peers| async move { UdpTransport::bind(udp_bind, peers).await },
        ));

        timeout(Duration::from_secs(1), updates.changed())
            .await
            .expect("replacement UDP must publish before the candidate barrier drains")
            .expect("the UDP publication sender must remain alive");
        daemon.peers.request_direct_recovery_kick("peer-under-test");
        assert_eq!(retired_hook_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            daemon
                .candidate_snapshot
                .read()
                .await
                .as_ref()
                .expect("the seeded snapshot must remain present")
                .candidates,
            stale_candidates,
            "the current incarnation cannot commit while the old writer holds the barrier"
        );

        drop(candidate_guard);
        timeout(Duration::from_secs(2), async {
            loop {
                let before = retired_hook_calls.load(Ordering::SeqCst);
                daemon.peers.request_direct_recovery_kick("peer-under-test");
                tokio::task::yield_now().await;
                if retired_hook_calls.load(Ordering::SeqCst) == before {
                    break;
                }
            }
        })
        .await
        .expect("the current recovery hook must install after its snapshot commit");
        assert_ne!(
            daemon
                .candidate_snapshot
                .read()
                .await
                .as_ref()
                .expect("the current incarnation must publish a snapshot")
                .candidates,
            stale_candidates,
            "the hook replacement must be preceded by a current-incarnation snapshot"
        );

        let _ = shutdown_tx.send(true);
        timeout(Duration::from_secs(3), worker)
            .await
            .expect("UDP supervisor must stop promptly on shutdown")
            .expect("UDP supervisor task must not panic")
            .expect("UDP supervisor must exit cleanly");
    }

    #[test]
    fn udp_direct_retry_backoff_resets_only_after_a_stable_instance() {
        let current_delay = udp_direct_retry_max_delay();
        let stability_window = udp_direct_retry_reset_after();

        assert_eq!(
            udp_direct_retry_delay_after_instance(current_delay, stability_window),
            udp_direct_retry_initial_delay(),
            "a stable UDP instance must reset the next bind retry"
        );
        assert_eq!(
            udp_direct_retry_delay_after_instance(
                current_delay,
                stability_window.saturating_sub(Duration::from_millis(1)),
            ),
            current_delay,
            "a short-lived UDP instance must retain exponential backoff"
        );
    }
}

async fn stop_direct_validation_scheduler_worker(mut worker: tokio::task::JoinHandle<()>) {
    if timeout(Duration::from_secs(1), &mut worker).await.is_err() {
        worker.abort();
        let _ = worker.await;
    }
}
