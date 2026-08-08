/// Hard cap for peer-reflexive HTTP/fast-punch workers.  A worker owns a
/// permit for its whole lifetime, including the UDP grace period and any
/// control-plane backoff, so endpoint churn cannot create unbounded tasks
/// across distinct peers.
const MAX_ACTIVE_PEER_REFLEXIVE_SIGNAL_WORKERS: usize = 16;
/// Bound the coalesced peer table as well as task concurrency.  Existing
/// peers always replace their newest endpoint; only a genuinely new peer is
/// refused once this bounded table is full.
const MAX_PENDING_PEER_REFLEXIVE_SIGNAL_PEERS: usize = 128;

/// Create the peer-reflexive worker capacity shared by every UDP transport
/// instance supervised for one daemon lifetime.
///
/// A replacement transport can be published while a retired instance is still
/// unwinding a control-plane request. Keeping this semaphore above an
/// individual signal loop makes the 16-worker bound daemon-wide instead of
/// allowing one full pool per overlapping UDP instance.
fn new_peer_reflexive_signal_worker_permits() -> Arc<tokio::sync::Semaphore> {
    Arc::new(tokio::sync::Semaphore::new(
        MAX_ACTIVE_PEER_REFLEXIVE_SIGNAL_WORKERS,
    ))
}

#[derive(Default)]
struct PeerReflexiveSignalSlot {
    latest: Option<PeerReflexiveObservation>,
    active: bool,
    next_signal_at: Option<Instant>,
    rate_limit_backoff: Duration,
}

type PeerReflexiveSignalSlots = Arc<Mutex<HashMap<String, PeerReflexiveSignalSlot>>>;

/// Store one newest-wins observation in the peer-reflexive signal table.
///
/// Idle slots are retained until their pacing window expires so a fresh
/// observation for the same peer cannot bypass a previous 429/backoff.  Once
/// that window has elapsed, stale idle slots are pruned before admitting a
/// new peer, keeping the table bounded without losing rate-limit state.
async fn enqueue_peer_reflexive_signal_observation(
    slots: &PeerReflexiveSignalSlots,
    observation: PeerReflexiveObservation,
) -> bool {
    let peer_id = observation.peer_id.clone();
    let now = Instant::now();
    let mut slots_guard = slots.lock().await;
    slots_guard.retain(|_, slot| {
        slot.active
            || slot.latest.is_some()
            || slot.next_signal_at.is_some_and(|next| next > now)
    });

    if let Some(slot) = slots_guard.get_mut(&peer_id) {
        slot.latest = Some(observation);
        return true;
    }
    if slots_guard.len() >= MAX_PENDING_PEER_REFLEXIVE_SIGNAL_PEERS {
        return false;
    }
    slots_guard.insert(
        peer_id,
        PeerReflexiveSignalSlot {
            latest: Some(observation),
            ..PeerReflexiveSignalSlot::default()
        },
    );
    true
}

/// Claim one pending peer slot only when a global worker permit is available.
/// The `active` bit is set while holding the slot lock, before the task is
/// spawned, so the receive loop cannot race itself into duplicate workers for
/// one peer.
#[cfg(test)]
async fn claim_pending_peer_reflexive_signal_worker(
    slots: &PeerReflexiveSignalSlots,
    worker_permits: &Arc<tokio::sync::Semaphore>,
) -> Option<(String, tokio::sync::OwnedSemaphorePermit)> {
    let permit = worker_permits.clone().try_acquire_owned().ok()?;
    let peer_id = {
        let mut slots_guard = slots.lock().await;
        let Some((peer_id, slot)) = slots_guard
            .iter_mut()
            .find(|(_, slot)| !slot.active && slot.latest.is_some())
        else {
            drop(permit);
            return None;
        };
        slot.active = true;
        peer_id.clone()
    };
    Some((peer_id, permit))
}

/// Wait until this loop has a pending peer and the shared daemon worker budget
/// has capacity.  A plain `try_acquire` is insufficient once UDP transports
/// can overlap during replacement: the new instance would not be notified
/// when an old instance releases its final permit.
async fn wait_for_pending_peer_reflexive_signal_worker(
    slots: &PeerReflexiveSignalSlots,
    work_available: &Arc<tokio::sync::Notify>,
    worker_permits: &Arc<tokio::sync::Semaphore>,
) -> Option<(String, tokio::sync::OwnedSemaphorePermit)> {
    loop {
        // Register before inspecting slots so an observation inserted between
        // the check and await leaves a stored notification for this waiter.
        let notified = work_available.notified();
        let has_pending = slots
            .lock()
            .await
            .values()
            .any(|slot| !slot.active && slot.latest.is_some());
        if !has_pending {
            notified.await;
            continue;
        }
        drop(notified);

        // This awaits one daemon-wide permit.  If another overlapping UDP
        // instance owns the last permit, releasing it wakes this waiter
        // directly rather than depending on another local observation.
        let Ok(permit) = worker_permits.clone().acquire_owned().await else {
            return None;
        };
        let peer_id = {
            let mut slots_guard = slots.lock().await;
            slots_guard
                .iter_mut()
                .find(|(_, slot)| !slot.active && slot.latest.is_some())
                .map(|(peer_id, slot)| {
                    slot.active = true;
                    peer_id.clone()
                })
        };
        if let Some(peer_id) = peer_id {
            return Some((peer_id, permit));
        }

        // Another scheduler consumed the last pending slot while this future
        // waited for capacity. Return the permit and resume waiting for work.
        drop(permit);
    }
}

/// Compute the next pacing window after a rate-limited signal.  Keeping this
/// arithmetic in one helper makes the 429 policy explicit and testable: the
/// current request waits for the current backoff, then the next retry doubles
/// it up to the hard maximum.
fn peer_reflexive_rate_limit_window(
    current_backoff: Duration,
    now: Instant,
) -> (Instant, Duration) {
    let current_backoff = if current_backoff.is_zero() {
        PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL
    } else {
        current_backoff
    };
    let next_backoff = current_backoff
        .checked_mul(2)
        .unwrap_or(PEER_REFLEXIVE_SIGNAL_BACKOFF_MAX)
        .min(PEER_REFLEXIVE_SIGNAL_BACKOFF_MAX);
    (now + current_backoff, next_backoff)
}

/// Consume peer-reflexive observations without turning endpoint churn into
/// validation, punch or HTTP task fan-out.  There is at most one owned signal
/// worker per peer; each worker reads the newest stored endpoint before work.
async fn run_peer_reflexive_signal_loop(
    ingress: PeerReflexiveIngress,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    worker_permits: Arc<tokio::sync::Semaphore>,
) {
    run_peer_reflexive_signal_loop_with_worker_permits(
        ingress,
        control,
        udp,
        peers,
        worker_permits,
    )
    .await;
}

/// Run the peer-reflexive loop against an explicit permit pool. Production
/// receives its pool from the UDP supervisor; focused tests can pass a small
/// shared pool to exercise replacement overlap deterministically.
async fn run_peer_reflexive_signal_loop_with_worker_permits(
    ingress: PeerReflexiveIngress,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    worker_permits: Arc<tokio::sync::Semaphore>,
) {
    let slots: PeerReflexiveSignalSlots = Arc::new(Mutex::new(HashMap::new()));
    let work_available = Arc::new(tokio::sync::Notify::new());
    let mut workers = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            observation = ingress.next() => {
                // This is the second validation ingress.  It uses the exact
                // same bounded scheduler registered by matched ACK handling;
                // it is never allowed to spawn a validation task itself.
                udp.enqueue_direct_validation_observation(observation.clone());

                let peer_id = observation.peer_id.clone();
                // A converged Direct peer must not schedule HTTP signal or
                // fast-punch work at all; the worker re-checks again so a
                // promotion racing this enqueue cannot slip through.
                if peers.is_direct_sync(&peer_id) {
                    debug!(
                        peer_id = %peer_id,
                        "dropping peer-reflexive signal for a Direct peer"
                    );
                    continue;
                }
                if !enqueue_peer_reflexive_signal_observation(&slots, observation).await {
                    debug!(
                        peer_id = %peer_id,
                        max_pending_peers = MAX_PENDING_PEER_REFLEXIVE_SIGNAL_PEERS,
                        "dropping peer-reflexive signal for a new peer because the coalesced table is full"
                    );
                }
                work_available.notify_one();
            }
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(%error, "peer-reflexive signal worker terminated unexpectedly");
                }
            }
            claimed = wait_for_pending_peer_reflexive_signal_worker(
                &slots,
                &work_available,
                &worker_permits,
            ) => {
                let Some((peer_id, permit)) = claimed else {
                    return;
                };
                let worker_slots = slots.clone();
                let worker_control = control.clone();
                let worker_udp = udp.clone();
                let worker_peers = peers.clone();
                workers.spawn(async move {
                    let _permit = permit;
                    run_peer_reflexive_signal_worker(
                        peer_id,
                        worker_slots,
                        worker_control,
                        worker_udp,
                        worker_peers,
                    )
                    .await;
                });
            }
        }
    }
}

async fn run_peer_reflexive_signal_worker(
    peer_id: String,
    slots: PeerReflexiveSignalSlots,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
) {
    loop {
        let Some((mut observation, delay)) = take_peer_reflexive_observation(&slots, &peer_id).await
        else {
            return;
        };
        if !delay.is_zero() {
            sleep(delay).await;
            // Coalesce every port change that arrived during the pacing or
            // 429 backoff window into this one request.
            if let Some(newest) = take_newest_peer_reflexive_observation(&slots, &peer_id).await {
                observation = newest;
            }
        }

        // Direct may have been confirmed while this worker was paced: the
        // fast punch and the relayed HTTP signal must not fire into a
        // confirmed path.
        if peers.is_direct(&peer_id).await {
            peers
                .record_direct_event(
                    &peer_id,
                    "peer_reflexive_signal_skipped_direct",
                    Some(observation.observed_endpoint),
                    None,
                    None,
                    "peer is already Direct; skipping peer-reflexive HTTP signal and fast punch",
                )
                .await;
            continue;
        }

        run_peer_reflexive_fast_punch(&udp, &peers, &observation).await;
        let endpoint = observation.observed_endpoint.to_string();
        let result = control
            .send_peer_reflexive(
                &observation.peer_id,
                &endpoint,
                Some(relay_assisted_punch_at_ms()),
            )
            .await;

        let now = Instant::now();
        let (next_signal_at, next_backoff, retry_after_rate_limit) = match result {
            Ok(()) => {
                debug!(
                    peer_id = %observation.peer_id,
                    remote_endpoint = %endpoint,
                    "relayed coalesced peer-reflexive observation"
                );
                (
                    now + PEER_REFLEXIVE_SIGNAL_MIN_INTERVAL,
                    PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL,
                    false,
                )
            }
            Err(error) if error.to_string().contains("HTTP 429") => {
                let current_backoff = {
                    let slots = slots.lock().await;
                    slots
                        .get(&peer_id)
                        .map(|slot| slot.rate_limit_backoff)
                        .filter(|backoff| !backoff.is_zero())
                        .unwrap_or(PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL)
                };
                let (next_signal_at, next_backoff) =
                    peer_reflexive_rate_limit_window(current_backoff, now);
                warn!(
                    peer_id = %observation.peer_id,
                    remote_endpoint = %endpoint,
                    backoff_ms = current_backoff.as_millis(),
                    "peer-reflexive signal received HTTP 429; retaining only the newest endpoint until backoff expires"
                );
                (next_signal_at, next_backoff, true)
            }
            Err(error) => {
                warn!(
                    peer_id = %observation.peer_id,
                    remote_endpoint = %endpoint,
                    "failed to relay peer-reflexive observation: {error}"
                );
                (
                    now + PEER_REFLEXIVE_SIGNAL_MIN_INTERVAL,
                    PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL,
                    false,
                )
            }
        };

        let mut slots_guard = slots.lock().await;
        let Some(slot) = slots_guard.get_mut(&peer_id) else {
            return;
        };
        slot.next_signal_at = Some(next_signal_at);
        slot.rate_limit_backoff = next_backoff;
        // A 429 retries exactly the one newest endpoint after exponential
        // backoff.  If another observation arrived while the HTTP request was
        // in flight it already occupies `latest` and wins over this retry.
        if retry_after_rate_limit && slot.latest.is_none() {
            slot.latest = Some(observation);
        }
        if slot.latest.is_none() {
            slot.active = false;
            return;
        }
    }
}

async fn take_peer_reflexive_observation(
    slots: &PeerReflexiveSignalSlots,
    peer_id: &str,
) -> Option<(PeerReflexiveObservation, Duration)> {
    let mut slots = slots.lock().await;
    let slot = slots.get_mut(peer_id)?;
    let observation = match slot.latest.take() {
        Some(observation) => observation,
        None => {
            slot.active = false;
            return None;
        }
    };
    let delay = slot
        .next_signal_at
        .map(|next| next.saturating_duration_since(Instant::now()))
        .unwrap_or(Duration::ZERO);
    Some((observation, delay))
}

async fn take_newest_peer_reflexive_observation(
    slots: &PeerReflexiveSignalSlots,
    peer_id: &str,
) -> Option<PeerReflexiveObservation> {
    slots
        .lock()
        .await
        .get_mut(peer_id)
        .and_then(|slot| slot.latest.take())
}

async fn run_peer_reflexive_fast_punch(
    udp: &UdpTransport,
    peers: &Arc<PeerManager>,
    observation: &PeerReflexiveObservation,
) {
    let generation = peers.current_network_generation().await;
    let success_count_before = peers
        .direct_probe_success_count_for_generation(&observation.peer_id, generation)
        .await;
    peers
        .record_direct_event(
            &observation.peer_id,
            "peer_reflexive_fast_punch_started",
            Some(observation.observed_endpoint),
            Some(1),
            None,
            "probing newest coalesced peer-reflexive endpoint immediately",
        )
        .await;
    match udp
        .punch_candidates_until_not_direct(
            &observation.peer_id,
            vec![observation.observed_endpoint],
            PEER_REFLEXIVE_FAST_PUNCH_INTERVAL,
            PEER_REFLEXIVE_FAST_PUNCH_ATTEMPTS,
        )
        .await
    {
        Ok(sent) => {
            peers
                .record_direct_event(
                    &observation.peer_id,
                    "peer_reflexive_fast_punch_sent",
                    Some(observation.observed_endpoint),
                    Some(1),
                    Some(sent),
                    format!("sent {sent} probes to newest peer-reflexive endpoint"),
                )
                .await;
            sleep(direct_probe_ack_grace(PEER_REFLEXIVE_FAST_PUNCH_INTERVAL)).await;
            let success_count_after = peers
                .direct_probe_success_count_for_generation(&observation.peer_id, generation)
                .await;
            if sent > 0 && success_count_after == success_count_before {
                peers
                    .record_direct_event(
                        &observation.peer_id,
                        "peer_reflexive_fast_punch_ack_timeout",
                        Some(observation.observed_endpoint),
                        Some(1),
                        Some(sent),
                        "newest peer-reflexive endpoint did not ACK before encrypted validation",
                    )
                    .await;
            }
        }
        Err(error) => {
            peers
                .record_direct_event(
                    &observation.peer_id,
                    "peer_reflexive_fast_punch_error",
                    Some(observation.observed_endpoint),
                    Some(1),
                    None,
                    format!("failed to probe newest peer-reflexive endpoint: {error}"),
                )
                .await;
            debug!(
                peer_id = %observation.peer_id,
                remote_endpoint = %observation.observed_endpoint,
                "peer-reflexive fast punch failed: {error}"
            );
        }
    }
}
