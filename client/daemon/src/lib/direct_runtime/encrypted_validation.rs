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
    state: Arc<std::sync::Mutex<DirectValidationIngressState>>,
    notify: Arc<tokio::sync::Notify>,
}

#[derive(Default)]
struct DirectValidationIngressState {
    latest: HashMap<String, PeerReflexiveObservation>,
    order: std::collections::VecDeque<String>,
}

impl DirectValidationIngress {
    fn new() -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(DirectValidationIngressState::default())),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Store the latest endpoint without blocking the UDP reader. A new peer
    /// is refused only when the bounded pending-peer set is full; an existing
    /// peer always wins with its newest observation.
    fn submit(&self, observation: PeerReflexiveObservation) {
        let peer_id = observation.peer_id.clone();
        let inserted = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.latest.contains_key(&peer_id)
                || state.latest.len() < MAX_PENDING_DIRECT_VALIDATION_PEERS
            {
                let is_new_peer = state.latest.insert(peer_id.clone(), observation).is_none();
                if is_new_peer {
                    state.order.push_back(peer_id.clone());
                }
                true
            } else {
                false
            }
        };
        if inserted {
            // There is one authoritative scheduler consumer.  `notify_one`
            // preserves the permit if the consumer is between its map check
            // and await; it then drains the remaining FIFO entries without
            // sleeping again.
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
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                // `take_latest_for_peer` removes the map entry after the
                // peer has already been placed in `order`.  Drain those
                // stale order entries here instead of sleeping with a live
                // peer still queued behind one stale key.
                let mut selected = None;
                while let Some(peer_id) = state.order.pop_front() {
                    if let Some(observation) = state.latest.remove(&peer_id) {
                        selected = Some(observation);
                        break;
                    }
                }
                selected
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
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .latest
            .remove(peer_id)
    }

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .latest
            .len()
    }
}

/// Write an encrypted-validation lifecycle event with the exact generation
/// and owner captured by the session lease.  A peer timeline already scopes
/// the event to `peer_id`; the explicit owner makes a queued worker, its ACK
/// expectation, and its terminal result traceable without treating probe ACK
/// counters from another peer as evidence for this worker.
#[allow(clippy::too_many_arguments)]
async fn record_validation_event(
    peers: &PeerManager,
    peer_id: &str,
    generation: u64,
    owner_token: u64,
    stage: impl Into<String>,
    endpoint: Option<SocketAddr>,
    sent_probes: Option<u32>,
    detail: impl Into<String>,
) {
    peers
        .record_direct_validation_event(
            peer_id,
            generation,
            owner_token,
            stage,
            endpoint,
            None,
            sent_probes,
            detail,
        )
        .await;
}

/// Render the WireGuard session snapshot used by Direct-validation logs.
/// Session instances are process-local diagnostic identities, not receiver
/// indexes or credentials; exposing them lets a real dual-end run distinguish
/// an old worker/previous-key overlap from a peer that simply did not answer.
fn format_validation_session_status(status: TransportSessionStatus) -> String {
    format!(
        "session_active={} session_expired={} session_needs_rekey={} active_session_instance={} previous_session_instance={} pending_responder_count={} expires_in_ms={}",
        status.has_active,
        status.expired,
        status.needs_rekey,
        status
            .active_session_instance
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        status
            .previous_session_instance
            .map_or_else(|| "none".to_string(), |value| value.to_string()),
        status.pending_responder_count,
        status
            .expires_in
            .map_or_else(|| "none".to_string(), |value| value.as_millis().to_string()),
    )
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
                let slow_relay_suppressed = udp
                    .direct_validation_suppressed_by_slow_relay(
                        &observation.peer_id,
                        generation,
                    )
                    .await;
                match udp
                    .begin_or_merge_direct_validation(
                        &observation.peer_id,
                        observation.observed_endpoint,
                        generation,
                    )
                    .await
                {
                    crate::udp::DirectValidationSessionStart::Spawn(lease) => {
                        let queued_target = *lease.target_rx.borrow();
                        if pending_leases.len() >= MAX_PENDING_DIRECT_VALIDATION_PEERS {
                            record_validation_event(
                                &peers,
                                &lease.peer_id,
                                queued_target.generation,
                                lease.owner_token,
                                "direct_validation_dropped",
                                Some(queued_target.endpoint),
                                Some(0),
                                format!(
                                    "dropped validation session before worker start: pending peer cap {} reached",
                                    MAX_PENDING_DIRECT_VALIDATION_PEERS
                                ),
                            )
                            .await;
                            let removed = udp
                                .finish_direct_validation_session(
                                    &lease.peer_id,
                                    lease.owner_token,
                                )
                                .await;
                            debug!(
                                peer_id = %lease.peer_id,
                                max_pending_peers = MAX_PENDING_DIRECT_VALIDATION_PEERS,
                                removed,
                                "direct-validation pending lease cap reached; dropping newest distinct peer"
                            );
                        } else {
                            record_validation_event(
                                &peers,
                                &lease.peer_id,
                                queued_target.generation,
                                lease.owner_token,
                                "direct_validation_queued",
                                Some(queued_target.endpoint),
                                Some(0),
                                format!(
                                    "queued encrypted validation session generation={} pending_leases={}",
                                    queued_target.generation,
                                    pending_leases.len().saturating_add(1)
                                ),
                            )
                            .await;
                            // Retain the owner/session while capacity is
                            // saturated.  Later observations for this peer
                            // merge into the same watch target, and the owner
                            // token keeps stale cleanup from touching a
                            // replacement session.
                            pending_leases.push_back(lease);
                        }
                    }
                    crate::udp::DirectValidationSessionStart::Merged => {
                        peers
                            .record_direct_event(
                                &observation.peer_id,
                                "direct_validation_observation_merged",
                                Some(observation.observed_endpoint),
                                None,
                                Some(0),
                                format!(
                                    "merged newest endpoint into the peer's existing validation worker generation={generation}"
                                ),
                            )
                            .await;
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
                        if slow_relay_suppressed {
                            peers
                                .record_direct_event(
                                    &observation.peer_id,
                                    "direct_validation_suppressed",
                                    Some(observation.observed_endpoint),
                                    None,
                                    Some(0),
                                    format!(
                                        "reason_code=direct_validation_slow_relay_cooldown generation={generation}"
                                    ),
                                )
                                .await;
                        }
                        debug!(
                            peer_id = %observation.peer_id,
                            remote_endpoint = %observation.observed_endpoint,
                            generation,
                            slow_relay_suppressed,
                            "ignored direct-validation observation for a Direct peer, retired UDP transport, or slow-relay cooldown"
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
    // The lease is the source of truth for this worker's generation.  Every
    // terminal event below uses this captured value, even when cancellation
    // races a later network-generation advance.
    let lease_target = *target_rx.borrow();
    let generation = lease_target.generation;
    let lease_endpoint = lease_target.endpoint;

    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; local virtual IP '{}' is not IPv4",
            peer_id, local_virtual_ip
        );
        record_validation_event(
            &peers,
            &peer_id,
            generation,
            owner_token,
            "direct_validation_cancelled",
            Some(lease_endpoint),
            Some(0),
            format!(
                "cancelled before start: local virtual IP '{local_virtual_ip}' is not IPv4"
            ),
        )
        .await;
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };
    let Some(connection) = peers.get_connection(&peer_id).await else {
        record_validation_event(
            &peers,
            &peer_id,
            generation,
            owner_token,
            "direct_validation_cancelled",
            Some(lease_endpoint),
            Some(0),
            "cancelled before start: peer connection disappeared",
        )
        .await;
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };
    let Ok(peer_ip) = connection.virtual_ip.parse::<Ipv4Addr>() else {
        debug!(
            "Skipping encrypted Direct validation for {}; peer virtual IP '{}' is not IPv4",
            peer_id, connection.virtual_ip
        );
        record_validation_event(
            &peers,
            &peer_id,
            generation,
            owner_token,
            "direct_validation_cancelled",
            Some(lease_endpoint),
            Some(0),
            format!(
                "cancelled before start: peer virtual IP '{}' is not IPv4",
                connection.virtual_ip
            ),
        )
        .await;
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };

    let Some(initial_target) = current_validation_target(&peers, &target_rx, owner_token).await
    else {
        let observed_target = *target_rx.borrow();
        let direct = peers.is_direct_for_generation(&peer_id, generation).await;
        record_validation_event(
            &peers,
            &peer_id,
            generation,
            owner_token,
            if direct {
                "direct_validation_completed"
            } else {
                "direct_validation_cancelled"
            },
            Some(observed_target.endpoint),
            Some(0),
            if direct {
                "completed before request: encrypted Direct validation was confirmed by another owned path"
                    .to_string()
            } else if observed_target.cancelled {
                "cancelled before request: validation owner was revoked".to_string()
            } else if observed_target.owner_token != owner_token {
                "cancelled before request: validation owner was replaced".to_string()
            } else if peers.current_network_generation().await != generation {
                "cancelled before request: network generation advanced".to_string()
            } else {
                "cancelled before request: validation target was unavailable".to_string()
            },
        )
        .await;
        udp.finish_direct_validation_session(&peer_id, owner_token).await;
        return;
    };
    let initial_session_status = transport.session_status(&peer_id).await;
    let initial_session_detail = format_validation_session_status(initial_session_status);
    tracing::debug!(target: "p2pnet_daemon::direct_validation",
        event = "direct_validation_session_snapshot",
        peer_id = %peer_id,
        remote_endpoint = %initial_target.endpoint,
        generation,
        session_active = initial_session_status.has_active,
        session_expired = initial_session_status.expired,
        session_needs_rekey = initial_session_status.needs_rekey,
        active_session_instance = ?initial_session_status.active_session_instance,
        previous_session_instance = ?initial_session_status.previous_session_instance,
        pending_responder_count = initial_session_status.pending_responder_count,
        "captured WireGuard session snapshot before Direct validation"
    );
    tracing::info!(
        event = "encrypted_trial_started",
        peer_id = %peer_id,
        remote_endpoint = %initial_target.endpoint,
        generation,
        "encrypted direct-validation session started"
    );
    record_validation_event(
        &peers,
        &peer_id,
        generation,
        owner_token,
        "direct_validation_started",
        Some(initial_target.endpoint),
        Some(0),
        format!("started encrypted direct-validation request/ACK exchange generation={generation} {initial_session_detail}"),
    )
    .await;
    peers
        .record_direct_event(
            &peer_id,
            "encrypted_trial_started",
            Some(initial_target.endpoint),
            None,
            None,
            format!(
                "starting bounded direct-validation request/ACK exchange generation={generation}"
            ),
        )
        .await;

    // An observation can arrive before offer/answer installs the WireGuard
    // session.  Keep one owned worker alive, but always read the latest target
    // before it sends a packet and leave immediately if the owner is revoked.
    let session_wait_started = Instant::now();
    let mut waiting_for_session = false;
    loop {
        let Some(target) = current_validation_target(&peers, &target_rx, owner_token).await
        else {
            let observed_target = *target_rx.borrow();
            let direct = peers.is_direct_for_generation(&peer_id, generation).await;
            record_validation_event(
                &peers,
                &peer_id,
                generation,
                owner_token,
                if direct {
                    "direct_validation_completed"
                } else {
                    "direct_validation_cancelled"
                },
                Some(observed_target.endpoint),
                Some(0),
                if direct {
                    "completed while waiting for WireGuard session: encrypted ACK promoted Direct"
                        .to_string()
                } else if observed_target.cancelled {
                    "cancelled while waiting for WireGuard session: validation owner was revoked"
                        .to_string()
                } else if observed_target.owner_token != owner_token {
                    "cancelled while waiting for WireGuard session: validation owner was replaced"
                        .to_string()
                } else {
                    "cancelled while waiting for WireGuard session: network generation advanced"
                        .to_string()
                },
            )
            .await;
            udp.finish_direct_validation_session(&peer_id, owner_token).await;
            return;
        };
        if target.generation != generation {
            record_validation_event(
                &peers,
                &peer_id,
                generation,
                owner_token,
                "direct_validation_cancelled",
                Some(target.endpoint),
                Some(0),
                format!(
                    "cancelled while waiting for WireGuard session: target generation {} replaced lease generation {}",
                    target.generation, generation
                ),
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
                            "WireGuard session became ready after {}ms {}",
                            session_wait_started.elapsed().as_millis(),
                            format_validation_session_status(status)
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
                    format!(
                        "peer-reflexive endpoint arrived before the WireGuard session; waiting for the handshake {}",
                        format_validation_session_status(status)
                    ),
                )
                .await;
        }
        let elapsed = session_wait_started.elapsed();
        if elapsed >= DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_session_wait_timeout",
                peer_id = %peer_id,
                remote_endpoint = %target.endpoint,
                generation,
                wait_ms = DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.as_millis(),
                session_active = status.has_active,
                session_expired = status.expired,
                session_needs_rekey = status.needs_rekey,
                active_session_instance = ?status.active_session_instance,
                previous_session_instance = ?status.previous_session_instance,
                pending_responder_count = status.pending_responder_count,
                "Direct validation stopped while waiting for a ready WireGuard session"
            );
            record_validation_event(
                &peers,
                &peer_id,
                generation,
                owner_token,
                "direct_validation_timed_out",
                Some(target.endpoint),
                Some(0),
                format!(
                    "timed out waiting for a ready WireGuard session after {}ms {}",
                    DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT.as_millis(),
                    format_validation_session_status(status)
                ),
            )
            .await;
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
    let mut terminal_stage = "direct_validation_timed_out";
    let mut terminal_reason = String::from(
        "no encrypted validation ACK received within the bounded request/ACK exchange",
    );
    let mut stop_worker = false;
    let mut emit_lock_timeouts = 0u32;
    for (sequence, delay) in DIRECT_VALIDATION_REQUEST_DELAYS.into_iter().enumerate() {
        let _ = wait_for_validation_update(&mut target_rx, delay).await;
        let Some(target) = current_validation_target(&peers, &target_rx, owner_token).await
        else {
            let observed_target = *target_rx.borrow();
            if peers.is_direct_for_generation(&peer_id, generation).await {
                terminal_stage = "direct_validation_completed";
                terminal_reason =
                    "completed after encrypted validation ACK promoted Direct".to_string();
            } else {
                terminal_stage = "direct_validation_cancelled";
                terminal_reason = if observed_target.cancelled {
                    "cancelled during request exchange: validation owner was revoked".to_string()
                } else if observed_target.owner_token != owner_token {
                    "cancelled during request exchange: validation owner was replaced".to_string()
                } else {
                    "cancelled during request exchange: network generation advanced".to_string()
                };
            }
            break;
        };
        if target.generation != generation {
            terminal_stage = "direct_validation_cancelled";
            terminal_reason = format!(
                "cancelled before next request: target generation {} no longer matches lease generation {}",
                target.generation, generation
            );
            break;
        }

        let request_id = validation_id.wrapping_add(sequence as u16);
        // Resolve the ACTUAL sending socket, take its send lease and register
        // the ACK expectation for that exact socket in one logic path.  The
        // send below uses the resolved socket directly, so a dynamic socket
        // detach or an affinity switch can never make the ACK expectation
        // disagree with the socket that really carried the request.  The
        // lease lives inside the expectation until the ACK, a cancellation, a
        // timeout or a generation invalidation releases it, keeping the
        // socket's reader alive for the whole ACK window.
        let prepared = match udp
            .prepare_direct_validation_send(
                &peer_id,
                request_id,
                generation,
                owner_token,
                target.endpoint,
            )
            .await
        {
            Ok(prepared) => prepared,
            Err(crate::udp::DirectValidationSendError::OwnerRevoked) => {
                tracing::debug!(target: "p2pnet_daemon::direct_validation",
                    event = "direct_validation_request_prepare_rejected",
                    peer_id = %peer_id,
                    remote_endpoint = %target.endpoint,
                    generation,
                    request_id,
                    sequence,
                    reason_code = "direct_validation_owner_revoked",
                    "Direct validation request was not prepared because its ownership lease was revoked"
                );
                terminal_stage = "direct_validation_cancelled";
                terminal_reason = format!(
                    "cancelled before request {request_id}: validation owner no longer owns endpoint {}",
                    target.endpoint
                );
                break;
            }
            Err(crate::udp::DirectValidationSendError::NoSocket) => {
                tracing::debug!(target: "p2pnet_daemon::direct_validation",
                    event = "direct_validation_request_prepare_rejected",
                    peer_id = %peer_id,
                    remote_endpoint = %target.endpoint,
                    generation,
                    request_id,
                    sequence,
                    reason_code = "direct_validation_no_udp_socket",
                    "Direct validation request was not prepared because no UDP socket was available"
                );
                terminal_stage = "direct_validation_failed";
                terminal_reason =
                    "failed to prepare validation send: no UDP socket resolved for the peer"
                        .to_string();
                peers
                    .record_direct_event(
                        &peer_id,
                        "encrypted_trial_failed",
                        Some(target.endpoint),
                        None,
                        Some(sent),
                        "no UDP socket resolved for the owned validation request",
                    )
                    .await;
                break;
            }
        };
        let socket_index = Some(prepared.socket_index);
        let request_session_status = transport.session_status(&peer_id).await;
        tracing::debug!(target: "p2pnet_daemon::direct_validation",
            event = "direct_validation_request_prepared",
            peer_id = %peer_id,
            remote_endpoint = %target.endpoint,
            generation,
            request_id,
            sequence,
            socket_index = prepared.socket_index,
            session_active = request_session_status.has_active,
            session_expired = request_session_status.expired,
            session_needs_rekey = request_session_status.needs_rekey,
            active_session_instance = ?request_session_status.active_session_instance,
            previous_session_instance = ?request_session_status.previous_session_instance,
            pending_responder_count = request_session_status.pending_responder_count,
            "prepared exact UDP socket and captured WireGuard session before encryption"
        );
        peers
            .record_direct_validation_event_with_metadata(
                &peer_id,
                generation,
                crate::peer::DirectValidationEventMetadata {
                    local_validation_session_id: Some(owner_token),
                    request_id: Some(request_id),
                    expected_endpoint: Some(target.endpoint),
                    ..crate::peer::DirectValidationEventMetadata::default()
                },
                "direct_validation_request_prepared",
                Some(target.endpoint),
                socket_index,
                None,
                Some(sent),
                format!(
                    "prepared exact UDP socket before encryption {}",
                    format_validation_session_status(request_session_status)
                ),
            )
            .await;
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
        let validation_peer_id = peer_id.clone();
        let send_socket = prepared.socket.clone();
        let send_socket_index = prepared.socket_index;
        let endpoint = target.endpoint;
        match transport
            .encrypt_and_emit_outbound_with_lock_timeout(
                OutboundPacket {
                    peer_id: peer_id.clone(),
                    dst_ip: connection.virtual_ip.clone(),
                    packet,
                },
                crate::transport::DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT,
                move |encrypted| async move {
                    if !send_udp
                        .mark_direct_validation_send_started(
                            &validation_peer_id,
                            request_id,
                            generation,
                            owner_token,
                        )
                        .await
                    {
                        return Err(crate::error::DaemonError::Network(
                            "direct-validation owner was revoked before UDP send".to_string(),
                        ));
                    }
                    send_udp
                        .send_encrypted_packet_on_socket(
                            &send_socket,
                            send_socket_index,
                            &encrypted,
                            endpoint,
                        )
                        .await
                        .map(|_| ())
                },
            )
            .await
        {
            Ok(crate::transport::BoundedEmitOutcome::Sent) => {
                sent = sent.saturating_add(1);
                tracing::info!(
                    event = "direct_validation_request_sent",
                    peer_id = %peer_id,
                    remote_endpoint = %endpoint,
                    generation,
                    request_id,
                    sequence,
                    sent,
                    "direct-validation request sent"
                );
                peers
                    .record_direct_validation_event_with_metadata(
                        &peer_id,
                        generation,
                        crate::peer::DirectValidationEventMetadata {
                            local_validation_session_id: Some(owner_token),
                            request_id: Some(request_id),
                            expected_endpoint: Some(endpoint),
                            ..crate::peer::DirectValidationEventMetadata::default()
                        },
                        "direct_validation_request_sent",
                        Some(endpoint),
                        socket_index,
                        None,
                        Some(sent),
                        format!(
                            "sent direct-validation request generation={generation} request_id={request_id} seq={sequence}"
                        ),
                    )
                    .await;

                let ack_wait_started = Instant::now();
                while ack_wait_started.elapsed() < DIRECT_VALIDATION_ACK_WAIT {
                    let Some(current) = current_validation_target(&peers, &target_rx, owner_token)
                        .await
                    else {
                        if peers.is_direct_for_generation(&peer_id, generation).await {
                            terminal_stage = "direct_validation_completed";
                            terminal_reason =
                                "completed while awaiting ACK: encrypted validation ACK promoted Direct"
                                    .to_string();
                        } else {
                            terminal_stage = "direct_validation_cancelled";
                            terminal_reason =
                                "cancelled while awaiting ACK: validation owner was revoked or generation advanced"
                                    .to_string();
                        }
                        stop_worker = true;
                        break;
                    };
                    if current.generation != generation
                        || peers.is_direct_for_generation(&peer_id, generation).await
                    {
                        if peers.is_direct_for_generation(&peer_id, generation).await {
                            terminal_stage = "direct_validation_completed";
                            terminal_reason =
                                "completed while awaiting ACK: encrypted validation ACK promoted Direct"
                                    .to_string();
                        } else {
                            terminal_stage = "direct_validation_cancelled";
                            terminal_reason =
                                "cancelled while awaiting ACK: network generation advanced"
                                    .to_string();
                        }
                        stop_worker = true;
                        break;
                    }
                    // A newer observation only changes the target for the
                    // next bounded attempt. This request was already sent to
                    // `endpoint`, so its ACK remains valid evidence when it
                    // arrives within the same owner/generation/request lease.
                    // Do not abort the wait merely because candidate
                    // discovery learned a fresher endpoint: doing so turns
                    // normal peer-reflexive churn into validation starvation
                    // and can make a healthy ACK arrive after its expectation
                    // was incorrectly withdrawn.
                    let remaining = DIRECT_VALIDATION_ACK_WAIT
                        .saturating_sub(ack_wait_started.elapsed());
                    let _ = wait_for_validation_update(
                        &mut target_rx,
                        DIRECT_ENCRYPTED_VALIDATION_SESSION_POLL.min(remaining),
                    )
                    .await;
                }
                if stop_worker {
                    break;
                }
                // Keep each bounded request's terminal wait visible.  The
                // worker-level timeout alone cannot distinguish a dead
                // endpoint from a request that was sent successfully but
                // never received an authenticated ACK.
                if ack_wait_started.elapsed() >= DIRECT_VALIDATION_ACK_WAIT {
                    peers
                        .record_direct_validation_event_with_metadata(
                            &peer_id,
                            generation,
                            crate::peer::DirectValidationEventMetadata {
                                local_validation_session_id: Some(owner_token),
                                request_id: Some(request_id),
                                expected_endpoint: Some(endpoint),
                                ..crate::peer::DirectValidationEventMetadata::default()
                            },
                            "direct_validation_ack_wait_timeout",
                            Some(endpoint),
                            socket_index,
                            None,
                            Some(sent),
                            format!(
                                "reason_code=direct_validation_ack_timeout request_id={} sequence={} ack_wait_ms={} sent_requests={}",
                                request_id,
                                sequence,
                                DIRECT_VALIDATION_ACK_WAIT.as_millis(),
                                sent,
                            ),
                        )
                        .await;
                }
            }
            Ok(crate::transport::BoundedEmitOutcome::LockTimeout) => {
                emit_lock_timeouts = emit_lock_timeouts.saturating_add(1);
                tracing::debug!(target: "p2pnet_daemon::direct_validation",
                    event = "direct_validation_emit_lock_timeout",
                    peer_id = %peer_id,
                    remote_endpoint = %endpoint,
                    generation,
                    request_id,
                    sequence,
                    socket_index = ?socket_index,
                    lock_timeout_ms = crate::transport::DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT.as_millis(),
                    "Direct validation did not allocate a WireGuard counter because the per-peer emit lock was busy"
                );
                udp.clear_direct_validation_expectation_if_owned(&peer_id, owner_token)
                    .await;
                record_validation_event(
                    &peers,
                    &peer_id,
                    generation,
                    owner_token,
                    "direct_validation_emit_lock_timeout",
                    Some(endpoint),
                    Some(sent),
                    format!(
                        "reason_code=direct_validation_emit_lock_timeout lock_timeout_ms={} request_id={} sequence={} attempt={}",
                        crate::transport::DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT.as_millis(),
                        request_id,
                        sequence,
                        emit_lock_timeouts
                    ),
                )
                .await;
                // The request did not acquire the counter-ordering lock and
                // therefore never received a counter or touched the wire.
                // It is safe to continue to the next bounded request delay;
                // treating this as a dead WireGuard session would terminate
                // the only validation worker precisely during a live-TUN
                // burst and force Direct to wait for a fresh observation.
                continue;
            }
            Ok(crate::transport::BoundedEmitOutcome::SessionUnavailable) => {
                let terminal_session_status = transport.session_status(&peer_id).await;
                debug!(target: "p2pnet_daemon::direct_validation",
                    event = "direct_validation_session_unavailable",
                    peer_id = %peer_id,
                    remote_endpoint = %endpoint,
                    generation,
                    request_id,
                    sequence,
                    socket_index = ?socket_index,
                    session_active = terminal_session_status.has_active,
                    session_expired = terminal_session_status.expired,
                    session_needs_rekey = terminal_session_status.needs_rekey,
                    active_session_instance = ?terminal_session_status.active_session_instance,
                    previous_session_instance = ?terminal_session_status.previous_session_instance,
                    pending_responder_count = terminal_session_status.pending_responder_count,
                    "stopping encrypted Direct validation because the WireGuard session was unavailable"
                );
                terminal_stage = "direct_validation_cancelled";
                terminal_reason =
                    "cancelled: WireGuard session became unavailable while emitting request"
                        .to_string();
                // Withdraw the expectation: the request never left this
                // daemon, so a late ACK must not match it.  This releases the
                // socket send lease held by the expectation.
                udp.clear_direct_validation_expectation_if_owned(&peer_id, owner_token)
                    .await;
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
                tracing::warn!(target: "p2pnet_daemon::direct_validation",
                    event = "direct_validation_emit_failed",
                    peer_id = %peer_id,
                    remote_endpoint = %endpoint,
                    generation,
                    request_id,
                    sequence,
                    socket_index = ?socket_index,
                    error = %err,
                    "encrypted Direct validation emit failed"
                );
                warn!(
                    "Failed to send encrypted Direct validation to {} at {}: {err}",
                    peer_id, endpoint
                );
                terminal_stage = "direct_validation_failed";
                terminal_reason = format!("failed to emit encrypted validation packet: {err}");
                // Withdraw the expectation and its socket lease: the request
                // was never sent, so no ACK may confirm it.
                udp.clear_direct_validation_expectation_if_owned(&peer_id, owner_token)
                    .await;
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

    // The ACK handler revokes the worker as part of the same epoch transaction
    // that promotes Direct.  Observe the state once more before publishing a
    // timeout so a promotion racing the final ACK wait is reported as success.
    if peers.is_direct_for_generation(&peer_id, generation).await {
        terminal_stage = "direct_validation_completed";
        terminal_reason = "completed: encrypted validation ACK confirmed Direct".to_string();
    } else if emit_lock_timeouts > 0 {
        terminal_reason = format!(
            "no encrypted validation ACK; {} request(s) skipped by bounded emit-lock timeout ({}ms), with no counter allocated",
            emit_lock_timeouts,
            crate::transport::DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT.as_millis()
        );
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
            format!("sent {sent} bounded WireGuard validation requests"),
        )
        .await;
    record_validation_event(
        &peers,
        &peer_id,
        generation,
        owner_token,
        terminal_stage,
        final_endpoint,
        Some(sent),
        terminal_reason,
    )
    .await;
    udp.finish_direct_validation_session(&peer_id, owner_token).await;
}
