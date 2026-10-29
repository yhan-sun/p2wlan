#[derive(Clone)]
struct UdpDirectTaskContext {
    udp_bind: SocketAddr,
    /// Explicit loopback-only escape hatch for the deterministic NAT simulator.
    /// Production configurations keep physical-interface pinning enabled.
    fresh_mapping_harness_loopback: bool,
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
    udp_inbound_tx: crate::dataplane_resources::EncryptedRxSink,
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
    /// Android JNI hints are consumed by this existing transport supervisor.
    android_network_change_rx: Option<AndroidNetworkChangeReceiver>,
    /// Lets the binder skip its normal failure backoff after a physical
    /// network hint has deliberately withdrawn the current socket.
    android_network_change_observed: Arc<std::sync::atomic::AtomicU64>,
    #[cfg(test)]
    original_owners_for_test: Option<Arc<C01UdpOwnersForTest>>,
}

enum UdpDirectLifecycleSignal {
    Stop,
    NetworkChanged(AndroidNetworkChangeHint),
    RouteChanged,
}

enum UdpDirectInstanceExit {
    Stopped,
    RouteChanged,
}

/// The route used to select this socket's interface is its handover baseline.
/// Sampling again after startup discovery could silently adopt a new route
/// while the socket remains pinned to the previous interface.
struct UdpDirectBinding {
    udp: UdpTransport,
    route_signature: Vec<String>,
}

include!("udp_direct_gateway_commit.rs");
#[cfg(test)]
include!("udp_direct_original_owner_test.rs");

fn direct_socket_interface_for_bind(
    environment: &crate::netenv::DirectRouteSnapshot,
    udp_bind: SocketAddr,
    fresh_mapping_harness_loopback: bool,
) -> std::result::Result<Option<String>, String> {
    // The deterministic simulator exposes its STUN observers on loopback and
    // launches the daemon with an explicit test-only loopback flag. Pinning
    // that socket to the physical interface makes loopback unreachable and
    // turns the simulator into a false UdpBlocked result. Never relax the
    // production default: both the test flag and a loopback bind are required.
    if fresh_mapping_harness_loopback && udp_bind.ip().is_loopback() {
        return Ok(None);
    }
    environment.direct_socket_interface()
}

async fn run_udp_direct_task(ctx: UdpDirectTaskContext) -> Result<()> {
    let excluded_interfaces = ctx.excluded_interfaces.clone();
    let sampled_interfaces = excluded_interfaces.clone();
    let fresh_mapping_harness_loopback = ctx.fresh_mapping_harness_loopback;
    run_udp_direct_task_with_binder_and_route_sampler(
        ctx,
        move |udp_bind, peers| {
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
                let outbound_interface = direct_socket_interface_for_bind(
                    &environment,
                    udp_bind,
                    fresh_mapping_harness_loopback,
                )
                .map_err(DaemonError::Network)?;
                if fresh_mapping_harness_loopback && udp_bind.ip().is_loopback() {
                    info!(
                        bind = %udp_bind,
                        "Using loopback routing for the explicit NAT simulator harness"
                    );
                } else if let Some(interface) = outbound_interface.as_deref() {
                    info!(
                        interface,
                        capture_interface = ?environment.capture_iface,
                        "Binding direct UDP sockets to the physical route interface"
                    );
                }
                let udp =
                    UdpTransport::bind_to_interface(udp_bind, peers, outbound_interface).await?;
                Ok(UdpDirectBinding {
                    udp,
                    route_signature: environment.signature,
                })
            }
        },
        move || sample_udp_network_route(sampled_interfaces.clone()),
    )
    .await
}

#[cfg(test)]
async fn run_udp_direct_task_with_binder<F, Fut>(ctx: UdpDirectTaskContext, bind: F) -> Result<()>
where
    F: FnMut(SocketAddr, Arc<PeerManager>) -> Fut,
    Fut: std::future::Future<Output = Result<UdpDirectBinding>>,
{
    // Existing socket/owner fixtures inject an empty route alongside their
    // loopback binder. Route regressions inject their own controlled sampler.
    run_udp_direct_task_with_binder_and_route_sampler(ctx, bind, || std::future::ready(Vec::new()))
        .await
}

/// Supervise UDP binding for the daemon lifetime.  A socket bind or reader
/// failure must unpublish its instance and retry; returning `Ok(())` would
/// otherwise leave WireGuard inbound permanently disconnected from UDP.
async fn run_udp_direct_task_with_binder_and_route_sampler<F, Fut, S, Sample>(
    ctx: UdpDirectTaskContext,
    mut bind: F,
    mut sample_route: S,
) -> Result<()>
where
    F: FnMut(SocketAddr, Arc<PeerManager>) -> Fut,
    Fut: std::future::Future<Output = Result<UdpDirectBinding>>,
    S: FnMut() -> Sample,
    Sample: std::future::Future<Output = Vec<String>>,
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

        // Hints queued during discovery/cleanup describe one latest network,
        // not a backlog of sockets that each need to be constructed.
        if let Some(receiver) = &ctx.android_network_change_rx {
            if let Some(hint) = crate::android_network_change::take_latest(receiver).await {
                record_android_network_change(
                    &ctx.peers,
                    &ctx.android_network_change_observed,
                    &hint,
                );
            }
        }

        // A failed bind still needs its pre-attempt route baseline. Capturing
        // it after failure could absorb the network that should wake retry.
        let Some(retry_route_baseline) =
            udp_direct_attempt_or_shutdown(ctx.shutdown_rx.clone(), sample_route()).await
        else {
            return Ok(());
        };
        let mut instance_ctx = ctx.clone();
        let network_hint_before_instance = ctx
            .android_network_change_observed
            .load(std::sync::atomic::Ordering::Acquire);
        // Discovery and bind belong to this same supervisor attempt. A stop
        // must also retire an attempt still waiting on DNS, a mirror writer,
        // or the platform binder before it publishes a socket.
        let Some(binding) = udp_direct_attempt_or_shutdown(ctx.shutdown_rx.clone(), async {
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
            bind(ctx.udp_bind, ctx.peers.clone()).await
        })
        .await
        else {
            return Ok(());
        };

        let (result, instance_runtime, route_changed) = match binding {
            Ok(mut binding) => {
                if let Some(capture) = ctx.direct_validation_transport.resource_capture() {
                    if binding
                        .udp
                        .attach_resource_capture(capture.clone())
                        .is_err()
                    {
                        // Observation failure cannot change socket availability.
                        // Keep the original transport and mark the missing scope.
                        capture.unobserved_residency_exit();
                    }
                }
                if let Some(receiver) = &ctx.android_network_change_rx {
                    if let Some(hint) = crate::android_network_change::take_latest(receiver).await {
                        record_android_network_change(
                            &ctx.peers,
                            &ctx.android_network_change_observed,
                            &hint,
                        );
                        // A callback crossed DNS/interface selection or bind.
                        // This unpublished socket has no readers to retire.
                        continue;
                    }
                }
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
                let result = run_udp_direct_instance(
                    instance_ctx,
                    binding.udp,
                    binding.route_signature,
                    direct_validation_worker_permits.clone(),
                    peer_reflexive_signal_worker_permits.clone(),
                    &mut sample_route,
                )
                .await;
                let route_changed = matches!(result, Ok(UdpDirectInstanceExit::RouteChanged));
                (
                    result.map(|_| ()),
                    Some(instance_started_at.elapsed()),
                    route_changed,
                )
            }
            Err(err) => (Err(err), None, false),
        };

        if udp_direct_shutdown_requested(&ctx.shutdown_rx) {
            return Ok(());
        }

        let network_hint_observed = route_changed
            || ctx
                .android_network_change_observed
                .load(std::sync::atomic::Ordering::Acquire)
                != network_hint_before_instance;
        if network_hint_observed {
            // A callback-authorized physical handoff already withdrew the
            // old publication. Rebind immediately; the normal exponential
            // bind backoff is for faults, not an explicit network edge.
            retry_delay = udp_direct_retry_initial_delay();
        } else if let Some(instance_runtime) = instance_runtime {
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

        let retry_wait = if network_hint_observed {
            Duration::ZERO
        } else {
            retry_delay
        };
        match result {
            Ok(()) => warn!(
                "UDP direct instance stopped unexpectedly; retrying bind in {}ms",
                retry_wait.as_millis()
            ),
            Err(err) => warn!(
                "UDP direct instance failed ({err}); retrying bind in {}ms",
                retry_wait.as_millis()
            ),
        }

        match wait_for_udp_direct_retry_or_change(
            ctx.shutdown_rx.clone(),
            ctx.android_network_change_rx.clone(),
            retry_wait,
            wait_for_network_route_change_with_sampler(retry_route_baseline, &mut sample_route),
        )
        .await
        {
            Some(UdpDirectLifecycleSignal::Stop) => return Ok(()),
            Some(UdpDirectLifecycleSignal::NetworkChanged(hint)) => {
                record_android_network_change(
                    &ctx.peers,
                    &ctx.android_network_change_observed,
                    &hint,
                );
                retry_delay = udp_direct_retry_initial_delay();
                continue;
            }
            Some(UdpDirectLifecycleSignal::RouteChanged) => {
                retry_delay = udp_direct_retry_initial_delay();
                continue;
            }
            None => {}
        }
        // An explicit handover bypasses only this wait. Never store zero in
        // the exponential backoff: 0 * 2 would busy-loop on every later fault.
        if !network_hint_observed {
            retry_delay = retry_delay
                .checked_mul(2)
                .unwrap_or_else(udp_direct_retry_max_delay)
                .min(udp_direct_retry_max_delay());
        }
    }
}

async fn run_udp_direct_instance<S, Sample>(
    ctx: UdpDirectTaskContext,
    udp: UdpTransport,
    initial_route_signature: Vec<String>,
    direct_validation_worker_permits: Arc<tokio::sync::Semaphore>,
    peer_reflexive_signal_worker_permits: Arc<tokio::sync::Semaphore>,
    sample_route: &mut S,
) -> Result<UdpDirectInstanceExit>
where
    S: FnMut() -> Sample,
    Sample: std::future::Future<Output = Vec<String>>,
{
    #[cfg(test)]
    let original_instance_for_test = ctx
        .original_owners_for_test
        .as_ref()
        .map(|owner| owner.begin());
    let UdpDirectTaskContext {
        udp_bind: _,
        fresh_mapping_harness_loopback,
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
        stun_server_specs,
        udp_observer_specs,
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
        excluded_interfaces: _,
        shutdown_rx,
        android_network_change_rx,
        android_network_change_observed,
        #[cfg(test)]
            original_owners_for_test: _,
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
    let dplpmtud_local_virtual_ip = direct_validation_local_ip
        .parse::<Ipv4Addr>()
        .map_err(|error| {
            DaemonError::Network(format!(
                "invalid local virtual IPv4 address for DPLPMTUD: {direct_validation_local_ip}: {error}"
            ))
        })?;
    let peer_reflexive_ingress = PeerReflexiveIngress::new();
    // Every source of direct-validation evidence feeds this bounded
    // per-peer reachability-ranked ingress. The scheduler is the only place
    // that may spawn a validation worker; it grants at most one lease
    // per peer/generation and has its own hard global worker cap.
    let validation_ingress = DirectValidationIngress::with_peer_manager(peers.clone());
    let udp = udp
        .with_local_node_id(local_node_id.clone())
        .with_wireguard_transport(direct_validation_transport.clone())
        .with_inbound_sink(udp_inbound_tx.clone())
        .with_peer_reflexive_observer(peer_reflexive_ingress.clone())
        .with_dplpmtud_local_virtual_ip(dplpmtud_local_virtual_ip);
    // Matched ACKs enter the same scheduler as peer-reflexive
    // observations. The ingress is synchronous/nonblocking for the
    // UDP reader and retains the highest-ranked queued endpoint, with newest
    // observations winning within the same reachability class.
    let trigger_ingress = validation_ingress.clone();
    let trigger = std::sync::Arc::new(move |observation: PeerReflexiveObservation| {
        trigger_ingress.submit(observation)
    });
    let udp = udp.with_validation_admission_trigger(trigger);
    // Peer lifecycle transitions revoke heartbeat leases synchronously. The
    // transport owns the lease registry, so the callback only sends the
    // cancellation signal and never performs async work under peer locks.
    peers.set_relay_backoff_heartbeat_cancel_hook(udp.relay_backoff_heartbeat_cancel_hook());
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
            #[cfg(test)]
            original_instance_for_test.clone(),
        ));
    let dplpmtud_scheduler_worker = tokio::spawn(run_dplpmtud_scheduler_until_cancelled(
        udp.clone(),
        peers.clone(),
        direct_validation_transport.clone(),
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
        #[cfg(test)]
        original_instance_for_test.clone(),
    ));

    // Start the reader before the initial STUN gather. The live gather uses
    // the reader-owned STUN waiter registry; starting it only after a serial
    // gather made public candidates wait behind observer timeouts and left
    // the first Direct offer with only a private host candidate.
    let mut inbound_worker = tokio::spawn({
        let udp = udp.clone();
        let inbound_tx = udp_inbound_tx.clone();
        async move { udp.run_inbound_with_sink(inbound_tx).await }
    });

    #[cfg(test)]
    if let Some(owner) = &original_instance_for_test {
        owner.spawned(0, validation_scheduler_worker.id());
        owner.spawned(1, dplpmtud_scheduler_worker.id());
        owner.spawned(2, peer_reflexive_worker.id());
        owner.spawned(3, inbound_worker.id());
    }
    let mut initial_publication_worker = None;
    // One lifecycle future covers startup discovery as well as steady-state
    // work. Cancellation drops the gather, then runs the same owner-scoped
    // cleanup; a queued edge cannot wait behind an entire STUN refresh.
    let outcome = {
        let work = async {
            // The local cfg fixture exercises lifecycle/socket ownership only.
            // Do not reach route/STUN/HTTP setup or hold the candidate lock.
            #[cfg(test)]
            if original_instance_for_test.is_some() {
                std::future::pending::<()>().await;
            }
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
                            publish_candidate_snapshot_to_store_with_readiness(
                                &candidate_snapshot,
                                host_candidates.clone(),
                                host_sources.clone(),
                                host_network_identity.clone(),
                                false,
                            )
                            .await;
                            *local_candidates.write().await = host_candidates.clone();
                            *udp_local_candidate_sources.write().await = host_sources;
                            *local_network_identity.write().await = host_network_identity;
                            info!(
                        "Published {} provisional host UDP candidates before STUN refresh (initial_gather_complete=false)",
                        host_candidates.len()
                    );
                        }
                    }
                }
            }

            let initial_refresh_guard = candidate_refresh_lock.lock().await;
            let initial_endpoint_fence = EndpointPublicationFence::new(&udp, &peers);
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
                    let nat_publication =
                        peers.update_nat_profile(report.nat_profile.clone()).await;
                    advertised_nat_type = report
                        .nat_profile
                        .control_label_with_generation_and_observation(
                            nat_publication.generation,
                            nat_publication.observation,
                        );
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
                        &candidate_sources,
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
                        if let Some(index) = candidate_endpoints.iter().position(|c| c == &endpoint)
                        {
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
                "Prepared {} UDP candidate endpoints for signaling (initial_gather_complete=true)",
                candidate_endpoints.len()
            );
            let initial_publication_version = publish_candidate_snapshot_to_store(
                &candidate_snapshot,
                candidate_endpoints.clone(),
                candidate_sources.clone(),
                initial_network_identity.clone(),
            )
            .await;
            *local_candidates.write().await = candidate_endpoints.clone();
            *udp_local_candidate_sources.write().await = candidate_sources.clone();
            *local_network_identity.write().await = initial_network_identity.clone();
            if upnp_enabled {
                // Gateway mapping discovery (SSDP/IGD/PCP/NAT-PMP) can take
                // seconds on gateways without a mapping service.  It must
                // never block the commit or hold the refresh lock; run it as
                // bounded best-effort background work and fold any discovered
                // candidate back into the committed set.
                let mapping_udp = udp.clone();
                let mapping_peers = peers.clone();
                let mapping_generation = peers.current_network_generation_sync();
                let local_candidates = local_candidates.clone();
                let local_sources = udp_local_candidate_sources.clone();
                let candidate_snapshot = candidate_snapshot.clone();
                let candidate_refresh_lock = candidate_refresh_lock.clone();
                let runtime = gateway_mapping_runtime.clone();
                let diagnostics = gateway_mapping_diagnostics.clone();
                let mapping_owner = lease.owner();
                let mapping_publication = udp_transport_publication.clone();
                let mapping_candidate_endpoints = candidate_endpoints.clone();
                let mapping_candidate_sources = candidate_sources.clone();
                tokio::spawn(async move {
                    let mut discovered = Vec::new();
                    let mut discovered_sources = HashMap::new();
                    maybe_add_port_mapping_udp_candidate(
                        (&mapping_udp, &mapping_peers),
                        &mapping_candidate_endpoints,
                        &mapping_candidate_sources,
                        &mut discovered,
                        &mut discovered_sources,
                        runtime,
                        diagnostics,
                    )
                    .await;
                    if discovered.is_empty() {
                        return;
                    }
                    if let Err(reason) = commit_gateway_mapping_candidates(
                        &mapping_publication,
                        mapping_owner,
                        &mapping_peers,
                        mapping_generation,
                        &candidate_refresh_lock,
                        &candidate_snapshot,
                        &local_candidates,
                        &local_sources,
                        discovered,
                        discovered_sources,
                    )
                    .await
                    {
                        debug!(
                            event = "gateway_mapping_candidate_discarded",
                            reason_code = reason,
                            "Gateway mapping no longer owns the candidate publication"
                        );
                    }
                });
            }
            let initial_control_endpoint = control_udp_endpoint_from_candidates_with_loopback(
                &candidate_endpoints,
                &candidate_sources,
                fresh_mapping_harness_loopback,
            );
            let mut published_endpoint = None;
            if let Some(endpoint) = initial_control_endpoint.as_ref() {
                // The handshake control lane has its own bounded deadline; a
                // short caller budget keeps a pathological lane from stalling
                // transport startup.
                match tokio::time::timeout(
                    Duration::from_millis(STARTUP_ENDPOINT_PUBLISH_BUDGET_MS),
                    control.update_endpoint_for_handshake_fenced(
                        endpoint,
                        &advertised_nat_type,
                        initial_endpoint_fence.clone(),
                    ),
                )
                .await
                {
                    Ok(Ok(())) => published_endpoint = Some(endpoint.clone()),
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
            let initial_publication_task = {
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
                        initial_publication_version,
                        initial_endpoint_fence,
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
            };
            initial_publication_worker = Some(tokio::spawn(initial_publication_task));

            if keepalive_interval.is_zero() {
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
                        stun_server_specs,
                        udp_observer_specs,
                        runtime_stun_servers,
                        udp_transport_publication: udp_transport_publication.clone(),
                        stun_timeout,
                        udp_advertise,
                        upnp_enabled,
                        allow_loopback_stun_endpoint: fresh_mapping_harness_loopback,
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
                        control: control.clone(),
                        peers: peers.clone(),
                        probe_interval: udp_punch_interval,
                        punch_attempts: udp_punch_attempts,
                        boot_epoch_ms,
                    }) => Ok(()),
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
                        stun_server_specs,
                        udp_observer_specs,
                        runtime_stun_servers,
                        udp_transport_publication: udp_transport_publication.clone(),
                        stun_timeout,
                        udp_advertise,
                        upnp_enabled,
                        allow_loopback_stun_endpoint: fresh_mapping_harness_loopback,
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
                        control: control.clone(),
                        peers: peers.clone(),
                        probe_interval: udp_punch_interval,
                        punch_attempts: udp_punch_attempts,
                        boot_epoch_ms,
                    }) => Ok(()),
                }
            }
        };
        tokio::select! {
            biased;
            lifecycle = wait_for_udp_direct_lifecycle(
                shutdown_rx.clone(), lease.shutdown_receiver(), android_network_change_rx.clone(),
            ) => match lifecycle {
                UdpDirectLifecycleSignal::Stop => Ok(UdpDirectInstanceExit::Stopped),
                UdpDirectLifecycleSignal::NetworkChanged(hint) => {
                    record_android_network_change(&peers, &android_network_change_observed, &hint);
                    Err(DaemonError::Network("Android physical network changed; rebuilding direct UDP transport".into()))
                },
                UdpDirectLifecycleSignal::RouteChanged => Ok(UdpDirectInstanceExit::RouteChanged),
            },
            // Start observing the bind-time route before STUN and candidate
            // preparation. The same owner-scoped cleanup handles either input.
            _ = wait_for_network_route_change_with_sampler(initial_route_signature, sample_route) => {
                info!(event = "udp_network_route_changed", "Stable network route changed; rebuilding direct UDP transport");
                Ok(UdpDirectInstanceExit::RouteChanged)
            },
            result = work => result.map(|()| UdpDirectInstanceExit::Stopped),
        }
    };
    if let Some(worker) = initial_publication_worker {
        worker.abort();
        let _ = worker.await;
    }

    #[cfg(test)]
    let original_inbound_id = inbound_worker.id();
    inbound_worker.abort();
    let _original_inbound_join = inbound_worker.await;
    #[cfg(test)]
    if let Some(owner) = &original_instance_for_test {
        let error = match &_original_inbound_join {
            Ok(Ok(())) => None,
            Err(error) if error.is_cancelled() => None,
            other => Some(format!("original inbound join: {other:?}")),
        };
        owner.joined(3, original_inbound_id, error);
    }

    // This sends the ownership-scoped stop signal before withdrawing the
    // watch value and cancels every validation owner tied to this socket.  A
    // superseded worker gets `false` here and therefore cannot erase the
    // replacement published by a newer owner.
    udp.cancel_all_direct_validation_sessions().await;
    udp.dplpmtud_runtime()
        .close("udp_transport_withdrawn", tokio::time::Instant::now());
    udp.cancel_all_relay_backoff_heartbeats();
    let withdrew_current = udp_transport_publication
        .clear_if_owner(lease.owner())
        .await;
    #[cfg(test)]
    if let Some(owner) = &original_instance_for_test {
        owner.withdrawn(withdrew_current);
    }
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
    stop_direct_validation_scheduler_worker(
        validation_scheduler_worker,
        #[cfg(test)]
        original_instance_for_test.as_ref(),
    )
    .await;
    stop_dplpmtud_scheduler_worker(
        dplpmtud_scheduler_worker,
        #[cfg(test)]
        original_instance_for_test.as_ref(),
    )
    .await;
    stop_peer_reflexive_signal_worker(
        peer_reflexive_worker,
        #[cfg(test)]
        original_instance_for_test.as_ref(),
    )
    .await;
    outcome
}

/// Poll the kernel route view and require the same changed signature twice.
/// Route commands can transiently return an empty/partial view during DHCP;
/// the two-sample confirmation avoids tearing down a healthy transport for a
/// single incomplete read while still rebuilding within a few seconds.
async fn sample_udp_network_route(excluded_interfaces: Vec<String>) -> Vec<String> {
    tokio::task::spawn_blocking(move || {
        crate::netenv::network_route_signature(&excluded_interfaces)
    })
    .await
    .unwrap_or_default()
}

fn udp_route_poll_interval() -> Duration {
    if cfg!(test) {
        Duration::from_millis(10)
    } else {
        Duration::from_secs(1)
    }
}

async fn wait_for_network_route_change_with_sampler<F, Fut>(
    baseline: Vec<String>,
    mut sample: F,
) -> Vec<String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    let mut ticker = interval(udp_route_poll_interval());
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await;
    let mut confirmation = RouteChangeConfirmation::new(baseline);
    loop {
        ticker.tick().await;
        let current = sample().await;
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

async fn udp_direct_attempt_or_shutdown<T>(
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    attempt: impl std::future::Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        biased;
        _ = wait_for_udp_direct_shutdown(shutdown_rx) => None,
        result = attempt => Some(result),
    }
}

async fn wait_for_udp_direct_retry_or_change(
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    network_change_rx: Option<AndroidNetworkChangeReceiver>,
    retry_delay: Duration,
    route_change: impl std::future::Future<Output = Vec<String>>,
) -> Option<UdpDirectLifecycleSignal> {
    // A newly available Android network must wake a failed bind immediately,
    // even when the previous unavailable network exhausted the retry backoff.
    // Reuse the same receiver and bounded coalescing as the live UDP instance.
    tokio::select! {
        biased;
        _ = wait_for_udp_direct_shutdown(shutdown_rx) => Some(UdpDirectLifecycleSignal::Stop),
        hint = async {
            match network_change_rx {
                Some(receiver) => crate::android_network_change::recv_latest(&receiver).await,
                None => std::future::pending().await,
            }
        } => Some(match hint {
            Some(hint) => UdpDirectLifecycleSignal::NetworkChanged(hint),
            None => UdpDirectLifecycleSignal::Stop,
        }),
        _ = route_change => Some(UdpDirectLifecycleSignal::RouteChanged),
        _ = sleep(retry_delay) => None,
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

async fn wait_for_udp_direct_lifecycle(
    daemon_shutdown_rx: tokio::sync::watch::Receiver<bool>,
    instance_shutdown_rx: tokio::sync::watch::Receiver<bool>,
    network_change_rx: Option<AndroidNetworkChangeReceiver>,
) -> UdpDirectLifecycleSignal {
    let Some(network_change_rx) = network_change_rx else {
        wait_for_udp_direct_stop(daemon_shutdown_rx, instance_shutdown_rx).await;
        return UdpDirectLifecycleSignal::Stop;
    };
    tokio::select! {
        _ = wait_for_udp_direct_stop(daemon_shutdown_rx, instance_shutdown_rx) => {
            UdpDirectLifecycleSignal::Stop
        }
        hint = crate::android_network_change::recv_latest(&network_change_rx) => {
            match hint {
                Some(hint) => UdpDirectLifecycleSignal::NetworkChanged(hint),
                None => UdpDirectLifecycleSignal::Stop,
            }
        }
    }
}

fn record_android_network_change(
    peers: &PeerManager,
    observed: &std::sync::atomic::AtomicU64,
    hint: &AndroidNetworkChangeHint,
) {
    observed.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    peers.emit_timeline(
        "physical_network_changed",
        Some("direct"),
        Some("physical_network_changed"),
        Some(format!(
            "kotlin_network_generation={} network_identity_hash={}",
            hint.kotlin_network_generation, hint.network_identity_hash
        )),
    );
}

fn emit_dplpmtud_timeline(
    peers: &PeerManager,
    event: &'static str,
    identity: &crate::dplpmtud::DplpmtudPathIdentity,
    detail: impl Into<String>,
) {
    peers.emit_timeline(
        event,
        Some("direct"),
        None,
        Some(format!(
            "peer={} network_generation={} peer_session_generation={} remote_candidate_epoch={} local_endpoint={} remote_endpoint={} transport_instance_id={} socket_index={} {}",
            identity.peer_id,
            identity.epoch.network_generation,
            identity.epoch.peer_session_generation.value(),
            identity.epoch.remote_candidate_epoch,
            identity.local_endpoint,
            identity.authenticated_remote_endpoint,
            identity.socket.transport_instance_id,
            identity.socket.socket_index,
            detail.into(),
        )),
    );
}

async fn run_dplpmtud_worker(
    start: crate::dplpmtud::DplpmtudWorkerStart,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
) {
    let runtime = udp.dplpmtud_runtime();
    let crate::dplpmtud::DplpmtudWorkerStart {
        lease,
        socket,
        local_virtual_ip,
        peer_virtual_ip,
    } = start;
    let identity = lease.identity.clone();
    let peer_id = lease.peer_id.clone();
    let worker_owner_token = lease.worker_owner_token;
    let notify = lease.notify.clone();
    let mut cancel_rx = lease.cancel_rx;
    let publication_owner = udp.inbound_publication_owner();
    let hard_deadline = tokio::time::Instant::now() + crate::dplpmtud::DPLPMTUD_WORKER_MAX_LIFETIME;

    emit_dplpmtud_timeline(
        &peers,
        "dplpmtud_started",
        &identity,
        format!(
            "outer_ip_family={:?} base_udp_datagram_size={}",
            identity.outer_ip_family,
            crate::dplpmtud::DPLPMTUD_BASE_UDP_DATAGRAM_SIZE,
        ),
    );

    loop {
        let now = tokio::time::Instant::now();
        if *cancel_rx.borrow()
            || now >= hard_deadline
            || publication_owner == 0
            || udp.inbound_publication_owner() != publication_owner
            || udp.transport_instance_id() != identity.socket.transport_instance_id
            || socket.local_addr().ok() != Some(identity.local_endpoint)
            || !peers.dplpmtud_path_is_current_sync(&identity)
        {
            break;
        }

        if let Some(plan) = runtime.schedule_probe(&peer_id, &identity, worker_owner_token, now) {
            if !runtime.outstanding_is_current(&plan) {
                continue;
            }
            emit_dplpmtud_timeline(
                &peers,
                "dplpmtud_probe_scheduled",
                &identity,
                format!(
                    "sequence={} candidate_udp_datagram_size={} deadline_ms={}",
                    plan.probe_identity.sequence,
                    plan.probe_identity.candidate_udp_datagram_size.0,
                    crate::dplpmtud::DPLPMTUD_PROBE_TIMEOUT.as_millis(),
                ),
            );

            let plaintext = crate::dplpmtud::build_encrypted_probe_plaintext(
                local_virtual_ip,
                peer_virtual_ip,
                &identity,
                &plan,
            );
            let send_result: std::result::Result<
                crate::transport::BoundedEmitOutcome,
                crate::dplpmtud::DplpmtudProbeSendFailure,
            > = match plaintext {
                Ok(plaintext) => {
                    let target_size = plan.probe_identity.candidate_udp_datagram_size.0 as usize;
                    let send_udp = udp.clone();
                    let send_socket = socket.clone();
                    let send_runtime = runtime.clone();
                    let send_plan = plan.clone();
                    let send_peers = peers.clone();
                    let send_identity = identity.clone();
                    let remote_endpoint = identity.authenticated_remote_endpoint;
                    transport
                        .encrypt_and_emit_outbound_with_lock_timeout_typed(
                            OutboundPacket {
                                room_authorization: None,
                                peer_id: peer_id.clone(),
                                dst_ip: peer_virtual_ip.to_string(),
                                packet: plaintext,
                                trace: None,
                            },
                            crate::transport::DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT,
                            move |encrypted| async move {
                                if encrypted.wire_bytes.len() != target_size {
                                    return Err(crate::dplpmtud::DplpmtudProbeSendFailure::from(
                                        DaemonError::Network(format!(
                                        "DPLPMTUD encrypted datagram size mismatch: built={} expected={target_size}",
                                        encrypted.wire_bytes.len(),
                                        )),
                                    ));
                                }
                                if send_udp.inbound_publication_owner() != publication_owner
                                    || !send_peers
                                        .dplpmtud_path_is_current_sync(&send_identity)
                                    || send_socket.local_addr().ok()
                                        != Some(send_identity.local_endpoint)
                                    || !send_runtime.begin_probe_send(
                                        &send_plan,
                                        tokio::time::Instant::now(),
                                    )
                                {
                                    return Err(crate::dplpmtud::DplpmtudProbeSendFailure::from(
                                        DaemonError::Network(
                                            "DPLPMTUD exact path was cancelled before UDP send"
                                                .to_string(),
                                        ),
                                    ));
                                }
                                send_udp
                                    .send_encrypted_packet_on_socket_for_dplpmtud(
                                        &send_socket,
                                        send_identity.socket.socket_index,
                                        &encrypted,
                                        remote_endpoint,
                                    )
                                    .await
                            },
                        )
                        .await
                }
                Err(error) => Err(crate::dplpmtud::DplpmtudProbeSendFailure::from(
                    DaemonError::Network(error),
                )),
            };

            match send_result {
                Ok(crate::transport::BoundedEmitOutcome::Sent) => {
                    runtime.finish_probe_send(&plan, Ok(()), tokio::time::Instant::now());
                    emit_dplpmtud_timeline(
                        &peers,
                        "dplpmtud_probe_sent",
                        &identity,
                        format!(
                            "sequence={} candidate_udp_datagram_size={}",
                            plan.probe_identity.sequence,
                            plan.probe_identity.candidate_udp_datagram_size.0,
                        ),
                    );
                }
                Ok(crate::transport::BoundedEmitOutcome::LockTimeout) => {
                    runtime.finish_probe_send(
                        &plan,
                        Err(crate::dplpmtud::DplpmtudProbeSendFailure::EmitLockUnavailable),
                        tokio::time::Instant::now(),
                    );
                    emit_dplpmtud_timeline(
                        &peers,
                        "dplpmtud_probe_send_failed",
                        &identity,
                        format!(
                            "sequence={} candidate_udp_datagram_size={} failure=emit_lock_unavailable",
                            plan.probe_identity.sequence,
                            plan.probe_identity.candidate_udp_datagram_size.0,
                        ),
                    );
                }
                Ok(crate::transport::BoundedEmitOutcome::SessionUnavailable) => {
                    runtime.finish_probe_send(
                        &plan,
                        Err(crate::dplpmtud::DplpmtudProbeSendFailure::SessionUnavailable),
                        tokio::time::Instant::now(),
                    );
                    emit_dplpmtud_timeline(
                        &peers,
                        "dplpmtud_probe_send_failed",
                        &identity,
                        format!(
                            "sequence={} candidate_udp_datagram_size={} failure=session_unavailable",
                            plan.probe_identity.sequence,
                            plan.probe_identity.candidate_udp_datagram_size.0,
                        ),
                    );
                }
                Err(failure) => {
                    runtime.finish_probe_send(&plan, Err(failure), tokio::time::Instant::now());
                    emit_dplpmtud_timeline(
                        &peers,
                        "dplpmtud_probe_send_failed",
                        &identity,
                        format!(
                            "sequence={} candidate_udp_datagram_size={} failure={failure:?}",
                            plan.probe_identity.sequence,
                            plan.probe_identity.candidate_udp_datagram_size.0,
                        ),
                    );
                }
            }
            continue;
        }

        let Some((state, wakeup, outstanding)) =
            runtime.worker_state(&peer_id, &identity, worker_owner_token)
        else {
            break;
        };
        if matches!(
            state,
            crate::dplpmtud::DplpmtudState::Disabled | crate::dplpmtud::DplpmtudState::Unsupported
        ) {
            break;
        }

        let wait_until = wakeup.unwrap_or(hard_deadline).min(hard_deadline);
        if state == crate::dplpmtud::DplpmtudState::SearchComplete {
            emit_dplpmtud_timeline(
                &peers,
                "dplpmtud_raise_timer_started",
                &identity,
                format!(
                    "raise_in_ms={}",
                    wait_until
                        .saturating_duration_since(tokio::time::Instant::now())
                        .as_millis()
                ),
            );
        }
        tokio::select! {
            changed = cancel_rx.changed() => {
                if changed.is_err() || *cancel_rx.borrow_and_update() {
                    break;
                }
            }
            _ = notify.notified() => {}
            _ = tokio::time::sleep_until(wait_until) => {
                if let Some(outstanding) = outstanding {
                    let plan = crate::dplpmtud::DplpmtudProbePlan {
                        peer_id: peer_id.clone(),
                        worker_owner_token,
                        path_identity: identity.clone(),
                        probe_identity: outstanding,
                        wire_token: crate::dplpmtud::DplpmtudWireToken {
                            sequence: outstanding.sequence,
                            nonce: outstanding.nonce,
                            path_cookie: outstanding.path_cookie,
                            network_generation: identity.epoch.network_generation,
                            peer_session_generation: identity.epoch.peer_session_generation.value(),
                            remote_candidate_epoch: identity.epoch.remote_candidate_epoch,
                            direct_validation_owner_token: identity.direct_validation_owner_token,
                            direct_validation_request_id: identity.direct_validation_request_id,
                            candidate_udp_datagram_size: outstanding.candidate_udp_datagram_size,
                            outer_ip_family: identity.outer_ip_family,
                        },
                        deadline: wait_until,
                    };
                    if runtime.timeout_probe(&plan, tokio::time::Instant::now())
                        == crate::dplpmtud::DplpmtudTransitionDecision::Applied
                    {
                        let snapshot = runtime.snapshot_for_path(&identity);
                        emit_dplpmtud_timeline(
                            &peers,
                            "dplpmtud_probe_timeout",
                            &identity,
                            format!(
                                "sequence={} candidate_udp_datagram_size={} confirmed_udp_datagram_size={} search_upper_udp_datagram_size={}",
                                outstanding.sequence,
                                outstanding.candidate_udp_datagram_size.0,
                                snapshot
                                    .as_ref()
                                    .and_then(|value| value.confirmed_udp_datagram_size)
                                    .unwrap_or(0),
                                snapshot.as_ref().map_or(0, |value| value.search_upper_udp_datagram_size),
                            ),
                        );
                        emit_dplpmtud_timeline(
                            &peers,
                            "dplpmtud_search_bounds_updated",
                            &identity,
                            format!(
                                "confirmed_udp_datagram_size={} search_upper_udp_datagram_size={}",
                                snapshot
                                    .as_ref()
                                    .and_then(|value| value.confirmed_udp_datagram_size)
                                    .unwrap_or(0),
                                snapshot.as_ref().map_or(0, |value| value.search_upper_udp_datagram_size),
                            ),
                        );
                    }
                }
            }
        }
    }

    runtime.finish_worker(&peer_id, &identity, worker_owner_token);
    emit_dplpmtud_timeline(
        &peers,
        "dplpmtud_cancelled",
        &identity,
        "worker exited after cancellation, lifecycle change, publication replacement, or intrinsic deadline",
    );
}

async fn run_dplpmtud_scheduler_until_cancelled(
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let ingress = udp.dplpmtud_worker_ingress();
    let mut path_changes = peers.subscribe_committed_business_path_changes();
    let mut workers = tokio::task::JoinSet::new();
    udp.reconcile_dplpmtud_paths().await;

    loop {
        if *shutdown_rx.borrow_and_update() {
            break;
        }
        tokio::select! {
            start = ingress.next() => {
                let worker_udp = udp.clone();
                let worker_peers = peers.clone();
                let worker_transport = transport.clone();
                workers.spawn(async move {
                    run_dplpmtud_worker(start, worker_udp, worker_peers, worker_transport).await;
                });
            }
            changed = path_changes.changed() => {
                if changed.is_err() {
                    break;
                }
                udp.reconcile_dplpmtud_paths().await;
            }
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(?error, "DPLPMTUD worker stopped unexpectedly");
                }
                udp.reconcile_dplpmtud_paths().await;
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow_and_update() {
                    break;
                }
            }
        }
    }

    udp.dplpmtud_runtime().close(
        "udp_transport_scheduler_stopped",
        tokio::time::Instant::now(),
    );
    workers.abort_all();
    while workers.join_next().await.is_some() {}
}

async fn stop_dplpmtud_scheduler_worker(
    mut worker: tokio::task::JoinHandle<()>,
    #[cfg(test)] original_owner_for_test: Option<&C01UdpInstanceForTest>,
) {
    #[cfg(test)]
    if let Some(owner) = original_owner_for_test {
        c01_stop_original_worker_for_test(worker, owner, 1).await;
        return;
    }
    if timeout(Duration::from_secs(1), &mut worker).await.is_err() {
        worker.abort();
        let _ = worker.await;
    }
}

/// Tie the authoritative validation scheduler to this UDP transport instance.
/// A failed/replaced transport first cancels every registry owner, then this
/// wrapper drops the queue receiver; no scheduler can outlive its socket.
#[cfg_attr(test, allow(clippy::too_many_arguments))]
async fn run_direct_validation_scheduler_until_cancelled(
    observations: DirectValidationIngress,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
    worker_permits: Arc<tokio::sync::Semaphore>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    #[cfg(test)] original_owner_for_test: Option<C01UdpInstanceForTest>,
) {
    #[cfg(test)]
    if let Some(owner) = original_owner_for_test {
        c01_validation_until_joined_for_test(
            observations,
            udp,
            peers,
            transport,
            local_virtual_ip,
            worker_permits,
            shutdown_rx,
            owner,
        )
        .await;
        return;
    }
    tokio::select! {
        _ = run_direct_validation_scheduler(observations, udp, peers, transport, local_virtual_ip, worker_permits) => {},
        _ = wait_for_udp_direct_shutdown(shutdown_rx) => {},
    }
}

/// Tie the peer-reflexive loop to the transport instance that owns it.  The
/// historical detached task held a sender and receiver for its own channel,
/// so it could outlive a failed socket forever; this wrapper exits whenever
/// that instance is superseded or withdrawn.
#[cfg_attr(test, allow(clippy::too_many_arguments))]
async fn run_peer_reflexive_signal_loop_until_cancelled(
    ingress: PeerReflexiveIngress,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    punch_deduplicator: PunchAttemptDeduplicator,
    worker_permits: Arc<tokio::sync::Semaphore>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    #[cfg(test)] original_owner_for_test: Option<C01UdpInstanceForTest>,
) {
    #[cfg(test)]
    if let Some(owner) = original_owner_for_test {
        c01_peer_reflexive_until_joined_for_test(
            ingress,
            control,
            udp,
            peers,
            punch_deduplicator,
            worker_permits,
            shutdown_rx,
            owner,
        )
        .await;
        return;
    }
    tokio::select! {
        _ = run_peer_reflexive_signal_loop(ingress, control, udp, peers, punch_deduplicator, worker_permits) => {},
        _ = wait_for_udp_direct_shutdown(shutdown_rx) => {},
    }
}

async fn stop_peer_reflexive_signal_worker(
    mut worker: tokio::task::JoinHandle<()>,
    #[cfg(test)] original_owner_for_test: Option<&C01UdpInstanceForTest>,
) {
    #[cfg(test)]
    if let Some(owner) = original_owner_for_test {
        c01_stop_original_worker_for_test(worker, owner, 2).await;
        return;
    }
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

    use tokio::sync::{broadcast, mpsc, watch};
    use tokio::time::timeout;

    use super::*;

    include!("udp_direct_handover_tests.rs");
    include!("udp_direct_route_tests.rs");

    #[test]
    fn nat_harness_loopback_does_not_pin_to_physical_interface() {
        let environment = crate::netenv::DirectRouteSnapshot {
            physical_route_interface: Some("eth0".to_string()),
            ..Default::default()
        };
        assert_eq!(
            direct_socket_interface_for_bind(&environment, "127.0.0.1:0".parse().unwrap(), true,)
                .unwrap(),
            None
        );
    }

    #[test]
    fn loopback_without_explicit_harness_flag_keeps_production_pinning() {
        let environment = crate::netenv::DirectRouteSnapshot {
            physical_route_interface: Some("eth0".to_string()),
            ..Default::default()
        };
        assert_eq!(
            direct_socket_interface_for_bind(&environment, "127.0.0.1:0".parse().unwrap(), false,)
                .unwrap(),
            Some("eth0".to_string())
        );
    }

    #[test]
    fn harness_flag_cannot_disable_pinning_for_non_loopback_bind() {
        let environment = crate::netenv::DirectRouteSnapshot {
            physical_route_interface: Some("eth0".to_string()),
            ..Default::default()
        };
        assert_eq!(
            direct_socket_interface_for_bind(&environment, "0.0.0.0:0".parse().unwrap(), true,)
                .unwrap(),
            Some("eth0".to_string())
        );
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
            fresh_mapping_harness_loopback: false,
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
            udp_inbound_tx: udp_inbound_tx.into(),
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
            android_network_change_rx: None,
            android_network_change_observed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            original_owners_for_test: None,
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
                    bind_test_udp_direct(udp_bind, peers).await
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
            bind_test_udp_direct,
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
    async fn android_network_hint_rebinds_udp_once_and_supersedes_old_publication() {
        check_resource_capture_across_original_udp_rebind(false).await;
    }

    #[tokio::test]
    async fn runtime_resource_capture_follows_both_original_udp_instances() {
        check_resource_capture_across_original_udp_rebind(true).await;
    }

    async fn check_resource_capture_across_original_udp_rebind(observe: bool) {
        let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        config.diagnostics.enabled = observe;
        config.diagnostics.resource_capture = observe;
        let daemon = Daemon::new(config);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (network_tx, network_rx) = broadcast::channel(8);
        let mut context = test_context(&daemon, shutdown_rx);
        context.android_network_change_rx = Some(Arc::new(tokio::sync::Mutex::new(network_rx)));
        let mut updates = daemon.udp_transport_publication.subscribe();

        let worker = tokio::spawn(run_udp_direct_task_with_binder(
            context,
            bind_test_udp_direct,
        ));
        timeout(Duration::from_secs(1), updates.changed())
            .await
            .expect("initial UDP publication did not arrive")
            .expect("UDP publication sender closed");
        let old_transport = updates
            .borrow()
            .clone()
            .expect("initial UDP transport must be published");
        let old_instance = old_transport.transport_instance_id();
        let generation_before = daemon.peers.current_network_generation().await;

        network_tx
            .send(AndroidNetworkChangeHint {
                kotlin_network_generation: 2,
                network_identity_hash: "cellular-hash".to_string(),
            })
            .expect("the direct lifecycle receiver must remain subscribed");

        // The old publication is withdrawn before the replacement is exposed.
        timeout(Duration::from_secs(1), updates.changed())
            .await
            .expect("old UDP publication was not withdrawn")
            .expect("UDP publication sender closed");
        assert!(updates.borrow().is_none());
        timeout(Duration::from_secs(1), updates.changed())
            .await
            .expect("replacement UDP publication did not arrive")
            .expect("UDP publication sender closed");
        let new_transport = updates
            .borrow()
            .clone()
            .expect("replacement UDP transport must be published");
        assert_ne!(old_instance, new_transport.transport_instance_id());
        for udp in [&old_transport, &new_transport] {
            assert_eq!(udp.resource_capture().is_some(), observe);
            if observe {
                assert!(Arc::ptr_eq(
                    udp.resource_capture().unwrap(),
                    daemon.transport.resource_capture().unwrap(),
                ));
            }
        }
        assert_eq!(
            daemon.peers.current_network_generation().await,
            generation_before + 1,
            "one callback-authorized handoff must advance PeerManager once",
        );

        let _ = shutdown_tx.send(true);
        timeout(Duration::from_secs(1), worker)
            .await
            .expect("UDP lifecycle did not stop")
            .expect("UDP lifecycle task panicked")
            .expect("UDP lifecycle did not exit cleanly");
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

async fn stop_direct_validation_scheduler_worker(
    mut worker: tokio::task::JoinHandle<()>,
    #[cfg(test)] original_owner_for_test: Option<&C01UdpInstanceForTest>,
) {
    #[cfg(test)]
    if let Some(owner) = original_owner_for_test {
        c01_stop_original_worker_for_test(worker, owner, 0).await;
        return;
    }
    if timeout(Duration::from_secs(1), &mut worker).await.is_err() {
        worker.abort();
        let _ = worker.await;
    }
}
