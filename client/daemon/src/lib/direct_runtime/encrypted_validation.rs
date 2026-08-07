/// Hard cap for unstarted, distinct-peer validation observations. Existing
/// peers always replace their pending endpoint, so churn consumes no extra
/// queue slots.
const MAX_PENDING_DIRECT_VALIDATION_PEERS: usize = 128;
/// Hard cap for active validation tasks for the whole daemon. The registry
/// limits each peer/generation to one worker; the daemon-owned permit pool
/// also spans UDP transport replacement, so an old socket's workers cannot
/// overlap a fresh socket's full worker budget during a rebind.
const MAX_ACTIVE_DIRECT_VALIDATION_WORKERS: usize = 16;

/// Create the validation worker capacity shared by every UDP transport
/// instance supervised for one daemon lifetime.
///
/// This intentionally lives outside a scheduler: a bind failure or transport
/// replacement starts a new scheduler, while an old worker can still be
/// winding down. Both schedulers must account against the same hard cap.
fn new_direct_validation_worker_permits() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(
        MAX_ACTIVE_DIRECT_VALIDATION_WORKERS,
    ))
}

/// Synchronous, per-peer newest-wins ingress for direct validation.
///
/// UDP receive paths cannot await. Instead of a bounded `mpsc::try_send` that
/// can discard the newest endpoint when full, this slot map retains the latest
/// observation for every already-queued peer and wakes one authoritative
/// scheduler. Distinct peers are bounded explicitly by
/// [`MAX_PENDING_DIRECT_VALIDATION_PEERS`].
#[derive(Clone)]
struct DirectValidationIngress {
    latest: Arc<std::sync::Mutex<HashMap<String, PeerReflexiveObservation>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl DirectValidationIngress {
    fn new() -> Self {
        Self {
            latest: Arc::new(std::sync::Mutex::new(HashMap::new())),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Store the latest endpoint without blocking the UDP reader. A new peer
    /// is refused only when the bounded pending-peer set is full; an existing
    /// peer always wins with its newest observation.
    fn submit(&self, observation: PeerReflexiveObservation) {
        let peer_id = observation.peer_id.clone();
        let inserted = {
            let mut latest = self
                .latest
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if latest.contains_key(&peer_id) || latest.len() < MAX_PENDING_DIRECT_VALIDATION_PEERS {
                latest.insert(peer_id.clone(), observation);
                true
            } else {
                false
            }
        };
        if inserted {
            self.notify.notify_one();
        } else {
            debug!(
                peer_id = %peer_id,
                max_pending_peers = MAX_PENDING_DIRECT_VALIDATION_PEERS,
                "dropping direct-validation observation for a new peer because the coalesced ingress is full"
            );
        }
    }

    async fn next(&self) -> PeerReflexiveObservation {
        loop {
            // Register before checking the map so a submit between the check
            // and await leaves a stored notification for this waiter.
            let notified = self.notify.notified();
            let observation = {
                let mut latest = self
                    .latest
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                latest
                    .keys()
                    .next()
                    .cloned()
                    .and_then(|peer_id| latest.remove(&peer_id))
            };
            if let Some(observation) = observation {
                return observation;
            }
            notified.await;
        }
    }

    /// Take an observation that replaced the scheduler's just-selected value
    /// before it could create or merge the registry lease.  This closes the
    /// ingress handoff with newest-wins semantics; observations that arrive
    /// after the registry session exists take the `Merged` path and update
    /// that session's watch target immediately, even while worker capacity is
    /// saturated.
    fn take_latest_for_peer(&self, peer_id: &str) -> Option<PeerReflexiveObservation> {
        self.latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(peer_id)
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

/// The one authoritative task spawner for daemon-internal validation.
///
/// Both authenticated-punch ACKs and peer-reflexive observations feed the
/// coalescing ingress. The registry grants a worker lease at most once for a
/// `(peer, generation)` and turns all later observations into newest-wins
/// target updates, so ingress bursts cannot create a task storm.
async fn run_direct_validation_scheduler(
    observations: DirectValidationIngress,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
    worker_permits: Arc<tokio::sync::Semaphore>,
) {
    run_direct_validation_scheduler_with_worker_permits(
        observations,
        udp,
        peers,
        transport,
        local_virtual_ip,
        worker_permits,
    )
    .await;
}

/// Scheduler implementation with a daemon-shared worker permit pool.
///
/// A permit lives for the full worker lifetime, so no path can exceed the
/// bound even if thousands of peers simultaneously receive observations or a
/// transport replacement overlaps worker shutdown. Registry leases may wait
/// in a separately bounded queue; this lets a same-peer `Merged` observation
/// update its target while all workers are occupied without spawning an extra
/// task. `JoinSet` owns every child task, so dropping a cancelled scheduler
/// aborts its workers instead of leaving detached tasks behind.
async fn run_direct_validation_scheduler_with_worker_permits(
    observations: DirectValidationIngress,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
    worker_permits: Arc<tokio::sync::Semaphore>,
) {
    let mut pending_leases = std::collections::VecDeque::new();
    let mut workers = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(Err(error)) = joined {
                    debug!(?error, "direct-validation worker stopped unexpectedly");
                }
            }
            observation = observations.next() => {
                // A same-peer observation that arrives while a lease is
                // waiting for a permit must still update its watch target
                // immediately.  Only the actual worker start is capacity
                // limited; merge operations never consume a permit.
                let observation = observations
                    .take_latest_for_peer(&observation.peer_id)
                    .unwrap_or(observation);
                let generation = peers.current_network_generation().await;
                match udp
                    .begin_or_merge_direct_validation(
                        &observation.peer_id,
                        observation.observed_endpoint,
                        generation,
                    )
                    .await
                {
                    crate::udp::DirectValidationSessionStart::Spawn(lease) => {
                        if pending_leases.len() >= MAX_PENDING_DIRECT_VALIDATION_PEERS {
                            let removed = udp
                                .finish_direct_validation_session(
                                    &lease.peer_id,
                                    lease.owner_token,
                                )
                                .await;
                            debug!(
                                peer_id = %lease.peer_id,
                                owner_token = lease.owner_token,
                                max_pending_peers = MAX_PENDING_DIRECT_VALIDATION_PEERS,
                                removed,
                                "direct-validation pending lease cap reached; dropping newest distinct peer"
                            );
                        } else {
                            // Retain the owner/session while capacity is
                            // saturated.  Later observations for this peer
                            // merge into the same watch target, and the owner
                            // token keeps stale cleanup from touching a
                            // replacement session.
                            pending_leases.push_back(lease);
                        }
                    }
                    crate::udp::DirectValidationSessionStart::Merged => {
                        debug!(
                            peer_id = %observation.peer_id,
                            remote_endpoint = %observation.observed_endpoint,
                            generation,
                            "merged peer-reflexive observation into active direct-validation session"
                        );
                    }
                    crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
                        debug!(
                            peer_id = %observation.peer_id,
                            remote_endpoint = %observation.observed_endpoint,
                            generation,
                            "ignored stale direct-validation observation after network generation advance"
                        );
                    }
                    crate::udp::DirectValidationSessionStart::IgnoredInactive => {
                        debug!(
                            peer_id = %observation.peer_id,
                            remote_endpoint = %observation.observed_endpoint,
                            generation,
                            "ignored direct-validation observation for a Direct peer or retired UDP transport"
                        );
                    }
                }
            }
            permit = worker_permits.clone().acquire_owned(), if !pending_leases.is_empty() => {
                let Ok(permit) = permit else {
                    return;
                };
                let Some(lease) = pending_leases.pop_front() else {
                    drop(permit);
                    continue;
                };
                let worker_udp = udp.clone();
                let worker_peers = peers.clone();
                let worker_transport = transport.clone();
                let worker_local_ip = local_virtual_ip.clone();
                workers.spawn(async move {
                    let _permit = permit;
                    run_direct_encrypted_validation_session(
                        lease,
                        worker_udp,
                        worker_peers,
                        worker_transport,
                        &worker_local_ip,
                    )
                    .await;
                });
            }
        }
    }
}

/// Focused-test wrapper that builds one explicit shared pool. Production
/// callers receive their pool from the UDP supervisor so every rebind shares
/// it; tests can pass a small deterministic limit without changing the global
/// daemon bound.
#[cfg(test)]
async fn run_direct_validation_scheduler_with_worker_limit(
    observations: DirectValidationIngress,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: String,
    worker_limit: usize,
) {
    run_direct_validation_scheduler_with_worker_permits(
        observations,
        udp,
        peers,
        transport,
        local_virtual_ip,
        Arc::new(tokio::sync::Semaphore::new(worker_limit)),
    )
    .await;
}

/// Compatibility entry point for focused tests and explicit callers.  Normal
/// runtime traffic goes through `run_direct_validation_scheduler`; this helper
/// still obtains the same single-flight lease, so it cannot bypass ownership.
#[cfg(test)]
async fn run_direct_encrypted_validation(
    observation: PeerReflexiveObservation,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: &str,
) {
    let generation = peers.current_network_generation().await;
    let start = udp
        .begin_or_merge_direct_validation(
            &observation.peer_id,
            observation.observed_endpoint,
            generation,
        )
        .await;
    let lease = match start {
        crate::udp::DirectValidationSessionStart::Spawn(lease) => lease,
        crate::udp::DirectValidationSessionStart::IgnoredInactive => {
            if peers.is_direct(&observation.peer_id).await {
                // The production scheduler suppresses queued observations once
                // Direct is confirmed. Preserve the focused helper's
                // historical diagnostic assertion without allocating a
                // worker/session.
                peers
                    .record_direct_event(
                        &observation.peer_id,
                        "encrypted_trial_skipped",
                        Some(observation.observed_endpoint),
                        None,
                        Some(0),
                        "skipped bounded WireGuard validation because Direct is already confirmed before session allocation",
                    )
                    .await;
            }
            return;
        }
        _ => return,
    };
    run_direct_encrypted_validation_session(lease, udp, peers, transport, local_virtual_ip).await;
}

fn active_direct_validation_target(
    target_rx: &watch::Receiver<crate::udp::DirectValidationTarget>,
    owner_token: u64,
) -> Option<crate::udp::DirectValidationTarget> {
    let target = *target_rx.borrow();
    (!target.cancelled && target.owner_token == owner_token).then_some(target)
}

/// Wait for either a bounded delay or a target/cancellation update.  A
/// changed target is deliberately not a new task: the current worker reads it
/// before the next request and sends only to the newest endpoint.
async fn wait_for_validation_update(
    target_rx: &mut watch::Receiver<crate::udp::DirectValidationTarget>,
    delay: Duration,
) -> bool {
    if delay.is_zero() {
        return false;
    }
    tokio::select! {
        changed = target_rx.changed() => changed.is_ok(),
        _ = sleep(delay) => false,
    }
}

async fn current_validation_target(
    peers: &PeerManager,
    target_rx: &watch::Receiver<crate::udp::DirectValidationTarget>,
    owner_token: u64,
) -> Option<crate::udp::DirectValidationTarget> {
    let target = active_direct_validation_target(target_rx, owner_token)?;
    (peers.current_network_generation().await == target.generation).then_some(target)
}

async fn run_direct_encrypted_validation_session(
    lease: crate::udp::DirectValidationSessionLease,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    local_virtual_ip: &str,
) {
    let peer_id = lease.peer_id.clone();
    let owner_token = lease.owner_token;
    let mut target_rx = lease.target_rx;

    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; local virtual IP '{}' is not IPv4",
            peer_id, local_virtual_ip
        );
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };
    let Some(connection) = peers.get_connection(&peer_id).await else {
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };
    let Ok(peer_ip) = connection.virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; peer virtual IP '{}' is not IPv4",
            peer_id, connection.virtual_ip
        );
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };

    let Some(initial_target) = current_validation_target(&peers, &target_rx, owner_token).await
    else {
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };
    let generation = initial_target.generation;
    tracing::info!(
        event = "encrypted_trial_started",
        peer_id = %peer_id,
        remote_endpoint = %initial_target.endpoint,
        generation,
        owner_token,
        "encrypted direct-validation session started"
    );
    peers
        .record_direct_event(
            &peer_id,
            "encrypted_trial_started",
            Some(initial_target.endpoint),
            None,
            None,
            format!(
                "starting bounded direct-validation request/ACK exchange owner={owner_token} generation={generation}"
            ),
        )
        .await;

    if peers.is_direct_for_generation(&peer_id, generation).await {
        peers
            .record_direct_event(
                &peer_id,
                "encrypted_trial_skipped",
                Some(initial_target.endpoint),
                None,
                Some(0),
                "skipped bounded WireGuard validation because Direct is already confirmed for this network generation",
            )
            .await;
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    }

    // An observation can arrive before offer/answer installs the WireGuard
    // session.  Keep one owned worker alive, but always read the latest target
    // before it sends a packet and leave immediately if the owner is revoked.
    let session_wait_started = Instant::now();
    let mut waiting_for_session = false;
    loop {
        let Some(target) = current_validation_target(&peers, &target_rx, owner_token).await
        else {
            udp.finish_direct_validation_session(&peer_id, owner_token).await;
            return;
        };
        if target.generation != generation {
            udp.finish_direct_validation_session(&peer_id, owner_token).await;
            return;
        }
        if peers.is_direct_for_generation(&peer_id, generation).await {
            peers
                .record_direct_event(
                    &peer_id,
                    "encrypted_trial_skipped",
                    Some(target.endpoint),
                    None,
                    Some(0),
                    "skipped bounded WireGuard validation because Direct became confirmed while waiting for the WireGuard session",
                )
                .await;
            udp.finish_direct_validation_session(&peer_id, owner_token).await;
            return;
        }

        let status = transport.session_status(&peer_id).await;
        if status.has_active && !status.expired {
            if waiting_for_session {
                peers
                    .record_direct_event(
                        &peer_id,
                        "encrypted_trial_session_ready",
                        Some(target.endpoint),
                        None,
                        Some(0),
                        format!(
                            "WireGuard session became ready after {}ms",
                            session_wait_started.elapsed().as_millis()
                        ),
                    )
                    .await;
            }
            break;
        }

        if !waiting_for_session {
            waiting_for_session = true;
            peers
                .record_direct_event(
                    &peer_id,
                    "encrypted_trial_waiting_for_session",
                    Some(target.endpoint),
                    None,
                    Some(0),
                    "peer-reflexive endpoint arrived before the WireGuard session; waiting for the handshake",
                )
                .await;
        }
        let elapsed = session_wait_started.elapsed();
        if elapsed >= DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT {
            debug!(
                "Skipping encrypted Direct validation for {}; WireGuard session was not ready within {}ms",
                peer_id,
                DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.as_millis()
            );
            peers
                .record_direct_event(
                    &peer_id,
                    "encrypted_trial_skipped",
                    Some(target.endpoint),
                    None,
                    Some(0),
                    format!(
                        "timed out after {}ms waiting for the WireGuard session",
                        DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.as_millis()
                    ),
                )
                .await;
            udp.finish_direct_validation_session(&peer_id, owner_token).await;
            return;
        }
        let _ = wait_for_validation_update(
            &mut target_rx,
            DIRECT_ENCRYPTED_VALIDATION_SESSION_POLL.min(
                DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.saturating_sub(elapsed),
            ),
        )
        .await;
    }

    // The worker has a fixed request budget.  Endpoint churn only changes the
    // destination read at each attempt; it cannot create another task or an
    // unbounded retry loop.
    let validation_id = unix_time_millis() as u16;
    let mut sent = 0u32;
    for (sequence, delay) in DIRECT_VALIDATION_REQUEST_DELAYS.into_iter().enumerate() {
        let _ = wait_for_validation_update(&mut target_rx, delay).await;
        let Some(target) = current_validation_target(&peers, &target_rx, owner_token).await
        else {
            break;
        };
        if target.generation != generation
            || peers.is_direct_for_generation(&peer_id, generation).await
        {
            break;
        }

        let request_id = validation_id.wrapping_add(sequence as u16);
        if !udp
            .expect_direct_validation_ack_owned(
                &peer_id,
                request_id,
                generation,
                owner_token,
                target.endpoint,
            )
            .await
        {
            break;
        }
        let payload = build_direct_validation_payload(
            DirectValidationKind::Request,
            generation,
            request_id,
            sequence as u8,
            owner_token,
        );
        let packet = Ipv4Packet::build_icmp_echo_request(
            local_ip,
            peer_ip,
            request_id,
            sequence as u16,
            &payload,
        );
        let send_udp = udp.clone();
        let endpoint = target.endpoint;
        match transport
            .encrypt_and_emit_outbound(
                OutboundPacket {
                    peer_id: peer_id.clone(),
                    dst_ip: connection.virtual_ip.clone(),
                    packet,
                },
                move |encrypted| async move {
                    send_udp.send_packet_to(&encrypted, endpoint).await.map(|_| ())
                },
            )
            .await
        {
            Ok(true) => {
                sent = sent.saturating_add(1);
                tracing::info!(
                    event = "direct_validation_request_sent",
                    peer_id = %peer_id,
                    remote_endpoint = %endpoint,
                    generation,
                    owner_token,
                    request_id,
                    sequence,
                    sent,
                    "direct-validation request sent"
                );
                peers
                    .record_direct_event(
                        &peer_id,
                        "direct_validation_request_sent",
                        Some(endpoint),
                        None,
                        Some(sent),
                        format!(
                            "sent direct-validation request owner={owner_token} generation={generation} request_id={request_id} seq={sequence}"
                        ),
                    )
                    .await;

                let ack_wait_started = Instant::now();
                while ack_wait_started.elapsed() < DIRECT_VALIDATION_ACK_WAIT {
                    let Some(current) = current_validation_target(&peers, &target_rx, owner_token)
                        .await
                    else {
                        break;
                    };
                    if current.generation != generation
                        || peers.is_direct_for_generation(&peer_id, generation).await
                    {
                        break;
                    }
                    // A newer endpoint cleared this request's expectation in
                    // the registry.  Stop waiting for the stale ACK and move
                    // to the next bounded attempt.
                    if current.endpoint != endpoint {
                        break;
                    }
                    let remaining = DIRECT_VALIDATION_ACK_WAIT
                        .saturating_sub(ack_wait_started.elapsed());
                    let _ = wait_for_validation_update(
                        &mut target_rx,
                        DIRECT_ENCRYPTED_VALIDATION_SESSION_POLL.min(remaining),
                    )
                    .await;
                }
            }
            Ok(false) => {
                debug!(
                    "Stopping encrypted Direct validation for {}; WireGuard session is no longer ready",
                    peer_id
                );
                peers
                    .record_direct_event(
                        &peer_id,
                        "encrypted_trial_skipped",
                        Some(endpoint),
                        None,
                        Some(sent),
                        "stopped bounded WireGuard validation because the WireGuard session became unavailable",
                    )
                    .await;
                break;
            }
            Err(err) => {
                warn!(
                    "Failed to send encrypted Direct validation to {} at {}: {err}",
                    peer_id, endpoint
                );
                peers
                    .record_direct_event(
                        &peer_id,
                        "encrypted_trial_failed",
                        Some(endpoint),
                        None,
                        Some(sent),
                        format!("failed to emit bounded WireGuard validation packet: {err}"),
                    )
                    .await;
                break;
            }
        }
    }

    let final_endpoint = active_direct_validation_target(&target_rx, owner_token)
        .map(|target| target.endpoint)
        .or(Some(initial_target.endpoint));
    peers
        .record_direct_event(
            &peer_id,
            "encrypted_trial_sent",
            final_endpoint,
            None,
            Some(sent),
            format!("sent {sent} bounded WireGuard validation requests owner={owner_token}"),
        )
        .await;
    udp.finish_direct_validation_session(&peer_id, owner_token).await;
}
