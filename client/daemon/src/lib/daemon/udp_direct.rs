#[derive(Clone)]
struct UdpDirectTaskContext {
    udp_bind: SocketAddr,
    peers: Arc<PeerManager>,
    control: ControlClient,
    local_candidates: Arc<RwLock<Vec<String>>>,
    local_candidate_sources: Arc<RwLock<HashMap<String, String>>>,
    local_network_identity: Arc<RwLock<Vec<String>>>,
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
    /// Daemon-wide shutdown signal.  UDP bind retry and every per-instance
    /// reader/worker observe this instead of making a failed bind permanent.
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

async fn run_udp_direct_task(ctx: UdpDirectTaskContext) -> Result<()> {
    run_udp_direct_task_with_binder(ctx, |udp_bind, peers| async move {
        UdpTransport::bind(udp_bind, peers).await
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
    // One permit pool outlives every individual UDP socket instance. A rebind
    // may begin while an old validation worker is still unwinding, so each
    // replacement scheduler must consume the same daemon-lifetime capacity.
    let direct_validation_worker_permits = new_direct_validation_worker_permits();
    let mut retry_delay = udp_direct_retry_initial_delay();
    loop {
        if udp_direct_shutdown_requested(&ctx.shutdown_rx) {
            return Ok(());
        }

        let result = match bind(ctx.udp_bind, ctx.peers.clone()).await {
            Ok(udp) => {
                run_udp_direct_instance(
                    ctx.clone(),
                    udp,
                    direct_validation_worker_permits.clone(),
                )
                .await
            }
            Err(err) => Err(err),
        };

        if udp_direct_shutdown_requested(&ctx.shutdown_rx) {
            return Ok(());
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
) -> Result<()> {
    let UdpDirectTaskContext {
        udp_bind: _,
        peers,
        control,
        local_candidates,
        local_candidate_sources: udp_local_candidate_sources,
        local_network_identity,
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
    // Publication is intentionally before the initial STUN/candidate lock.
    // A refresh can hold that lock while a failed socket is rebound; inbound
    // WireGuard must nevertheless see the replacement immediately.
    let lease = udp_transport_publication.publish(udp.clone()).await;
    let validation_scheduler_worker = tokio::spawn(
        run_direct_validation_scheduler_until_cancelled(
            validation_ingress,
            udp.clone(),
            peers.clone(),
            direct_validation_transport.clone(),
            direct_validation_local_ip.clone(),
            direct_validation_worker_permits,
            lease.shutdown_receiver(),
        ),
    );
    let peer_reflexive_worker = tokio::spawn(run_peer_reflexive_signal_loop_until_cancelled(
        peer_reflexive_ingress,
        control.clone(),
        udp.clone(),
        peers.clone(),
        direct_validation_transport,
        direct_validation_local_ip,
        lease.shutdown_receiver(),
    ));

    // Do not let a slow initial STUN refresh hide a successfully rebound UDP
    // transport. If this lease is superseded while waiting, skip candidate
    // work entirely and let the common cleanup below withdraw only our owner.
    let initial_refresh_guard = tokio::select! {
        guard = candidate_refresh_lock.lock() => Some(guard),
        _ = wait_for_udp_direct_stop(shutdown_rx.clone(), lease.shutdown_receiver()) => None,
    };
    let outcome = if let Some(initial_refresh_guard) = initial_refresh_guard {

            let (mut candidate_endpoints, mut candidate_sources) =
                match udp.gather_candidate_report(stun_servers.clone(), stun_timeout).await
                {
                    Ok(report) => {
                        let (endpoints, sources) = candidate_endpoints_from_report(&report);
                        info!(
                            "Local NAT profile: mapping={:?} public={:?} stun_success={}/{} confidence={}",
                            report.nat_profile.mapping_behavior,
                            report.nat_profile.public_endpoint,
                            report
                                .nat_profile
                                .observations
                                .iter()
                                .filter(|observation| observation.mapped_address.is_some())
                                .count(),
                            report.nat_profile.observations.len(),
                            report.nat_profile.confidence
                        );
                        peers.update_nat_profile(report.nat_profile.clone()).await;
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
                        if !candidate_endpoints.contains(&endpoint) {
                            candidate_endpoints.insert(0, endpoint.clone());
                        }
                        candidate_sources.entry(endpoint.clone()).or_insert_with(|| {
                            if udp_advertise.as_deref().is_some_and(|configured| {
                                !configured.trim().is_empty() && configured.trim() == endpoint
                            }) {
                                "manual".to_string()
                            } else {
                                "host".to_string()
                            }
                        });
                        info!(
                            "UDP transport listening on {addr}; advertising {endpoint}"
                        );
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

            if upnp_enabled {
                maybe_add_port_mapping_udp_candidate(
                    udp.local_addr().ok(),
                    &mut candidate_endpoints,
                    &mut candidate_sources,
                    gateway_mapping_runtime.clone(),
                    gateway_mapping_diagnostics.clone(),
                )
                .await;
            }
            let initial_network_identity = prepare_signal_candidates_and_network_identity(
                &[],
                &HashMap::new(),
                &mut candidate_endpoints,
                &mut candidate_sources,
            );
            *local_network_identity.write().await = initial_network_identity;
            let mut published_endpoint = None;
            if let Some(endpoint) = control_udp_endpoint_from_candidates(
                &candidate_endpoints,
                &candidate_sources,
            ) {
                if let Err(err) = control.update_endpoint(&endpoint, "unknown").await {
                    warn!("Failed to queue UDP endpoint update '{endpoint}': {err}");
                } else {
                    published_endpoint = Some(endpoint);
                }
            }

            info!(
                "Prepared {} UDP candidate endpoints for signaling",
                candidate_endpoints.len()
            );
            *local_candidates.write().await = candidate_endpoints.clone();
            *udp_local_candidate_sources.write().await = candidate_sources.clone();
            drop(initial_refresh_guard);

            publish_local_candidates_to_known_peers(
                &control,
                peers.clone(),
                udp.clone(),
                punch_deduplicator.clone(),
                &candidate_endpoints,
                &candidate_sources,
                udp_punch_interval,
                udp_punch_attempts,
                "initial UDP candidates ready",
                Some(HolePunchSignalContext {
                    control: control.clone(),
                    local_candidates: local_candidates.clone(),
                    local_candidate_sources: udp_local_candidate_sources.clone(),
                    stun_servers: stun_servers.clone(),
                    stun_timeout,
                    boot_epoch_ms,
                }),
            )
            .await;

            if keepalive_interval.is_zero() {
                let refresh_udp = udp.clone();
                tokio::select! {
                    result = udp.clone().run_inbound(udp_inbound_tx) => result,
                    _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                        udp: refresh_udp,
                        stun_servers,
                        stun_timeout,
                        udp_advertise,
                        upnp_enabled,
                        published_endpoint,
                        local_candidates,
                        local_candidate_sources: udp_local_candidate_sources.clone(),
                        local_network_identity: local_network_identity.clone(),
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
                    _ = wait_for_udp_direct_stop(shutdown_rx.clone(), lease.shutdown_receiver()) => Ok(()),
                }
            } else {
                let keepalive_udp = udp.clone();
                let refresh_udp = udp.clone();
                tokio::select! {
                    result = udp.clone().run_inbound(udp_inbound_tx) => result,
                    _ = keepalive_udp.run_keepalives(keepalive_interval) => Ok(()),
                    _ = run_udp_candidate_refresh(UdpCandidateRefreshContext {
                        udp: refresh_udp,
                        stun_servers,
                        stun_timeout,
                        udp_advertise,
                        upnp_enabled,
                        published_endpoint,
                        local_candidates,
                        local_candidate_sources: udp_local_candidate_sources.clone(),
                        local_network_identity: local_network_identity.clone(),
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
                    _ = wait_for_udp_direct_stop(shutdown_rx.clone(), lease.shutdown_receiver()) => Ok(()),
                }
            }
    } else {
        Ok(())
    };

    // This sends the ownership-scoped stop signal before withdrawing the
    // watch value and cancels every validation owner tied to this socket.  A
    // superseded worker gets `false` here and therefore cannot erase the
    // replacement published by a newer owner.
    udp.cancel_all_direct_validation_sessions().await;
    let _ = udp_transport_publication.clear_if_owner(lease.owner()).await;
    stop_direct_validation_scheduler_worker(validation_scheduler_worker).await;
    stop_peer_reflexive_signal_worker(peer_reflexive_worker).await;
    outcome
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
    transport: WireGuardTransport,
    local_virtual_ip: String,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::select! {
        _ = run_peer_reflexive_signal_loop(ingress, control, udp, peers, transport, local_virtual_ip) => {},
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

    fn test_context(
        daemon: &Daemon,
        shutdown_rx: watch::Receiver<bool>,
    ) -> UdpDirectTaskContext {
        let (udp_inbound_tx, _udp_inbound_rx) = mpsc::channel(8);
        UdpDirectTaskContext {
            udp_bind: "127.0.0.1:0".parse().unwrap(),
            peers: daemon.peers.clone(),
            control: ControlClient::disabled_for_test(),
            local_candidates: daemon.local_candidates.clone(),
            local_candidate_sources: daemon.local_candidate_sources.clone(),
            local_network_identity: daemon.local_network_identity.clone(),
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
            shutdown_rx,
        }
    }

    #[tokio::test]
    async fn udp_direct_retries_bind_failure_and_republishes_transport() {
        let daemon = Daemon::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        );
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
                        return Err(DaemonError::Network("injected UDP bind failure".to_string()));
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
        let daemon = Daemon::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        );
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
}

async fn stop_direct_validation_scheduler_worker(mut worker: tokio::task::JoinHandle<()>) {
    if timeout(Duration::from_secs(1), &mut worker).await.is_err() {
        worker.abort();
        let _ = worker.await;
    }
}
