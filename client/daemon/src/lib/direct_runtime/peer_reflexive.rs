/// Hard cap for peer-reflexive HTTP/fast-punch workers.  A worker owns a
/// permit for its whole lifetime, including the UDP grace period and any
/// control-plane backoff, so endpoint churn cannot create unbounded tasks
/// across distinct peers.
const MAX_ACTIVE_PEER_REFLEXIVE_SIGNAL_WORKERS: usize = 16;
/// Bound the coalesced peer table as well as task concurrency.  Existing
/// peers always replace their newest endpoint; only a genuinely new peer is
/// refused once this bounded table is full.
const MAX_PENDING_PEER_REFLEXIVE_SIGNAL_PEERS: usize = 128;

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

/// Fill all currently available worker permits from coalesced peer slots.
async fn spawn_pending_peer_reflexive_signal_workers(
    slots: &PeerReflexiveSignalSlots,
    workers: &mut tokio::task::JoinSet<()>,
    worker_permits: &Arc<tokio::sync::Semaphore>,
    control: &ControlClient,
    udp: &UdpTransport,
    peers: &Arc<PeerManager>,
) {
    loop {
        let Some((peer_id, permit)) =
            claim_pending_peer_reflexive_signal_worker(slots, worker_permits).await
        else {
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
    _transport: WireGuardTransport,
    _local_virtual_ip: String,
) {
    run_peer_reflexive_signal_loop_with_worker_limit(
        ingress,
        control,
        udp,
        peers,
        MAX_ACTIVE_PEER_REFLEXIVE_SIGNAL_WORKERS,
    )
    .await;
}

/// Implementation with a test-configurable worker cap.  Production callers
/// use [`run_peer_reflexive_signal_loop`] so the cap remains a single audited
/// constant at the daemon boundary.
async fn run_peer_reflexive_signal_loop_with_worker_limit(
    ingress: PeerReflexiveIngress,
    control: ControlClient,
    udp: UdpTransport,
    peers: Arc<PeerManager>,
    worker_limit: usize,
) {
    let slots: PeerReflexiveSignalSlots = Arc::new(Mutex::new(HashMap::new()));
    let mut workers = tokio::task::JoinSet::new();
    let worker_permits = Arc::new(tokio::sync::Semaphore::new(worker_limit));

    loop {
        tokio::select! {
            observation = ingress.next() => {
                // This is the second validation ingress.  It uses the exact
                // same bounded scheduler registered by matched ACK handling;
                // it is never allowed to spawn a validation task itself.
                udp.enqueue_direct_validation_observation(observation.clone());

                let peer_id = observation.peer_id.clone();
                if !enqueue_peer_reflexive_signal_observation(&slots, observation).await {
                    debug!(
                        peer_id = %peer_id,
                        max_pending_peers = MAX_PENDING_PEER_REFLEXIVE_SIGNAL_PEERS,
                        "dropping peer-reflexive signal for a new peer because the coalesced table is full"
                    );
                }
                spawn_pending_peer_reflexive_signal_workers(
                    &slots,
                    &mut workers,
                    &worker_permits,
                    &control,
                    &udp,
                    &peers,
                )
                .await;
            }
            joined = workers.join_next(), if !workers.is_empty() => {
                if let Some(Err(error)) = joined {
                    warn!(%error, "peer-reflexive signal worker terminated unexpectedly");
                }
                // A permit is returned when the joined task is dropped.  Fill
                // newly available capacity immediately so a peer that was
                // coalesced while the cap was full is never stranded.
                spawn_pending_peer_reflexive_signal_workers(
                    &slots,
                    &mut workers,
                    &worker_permits,
                    &control,
                    &udp,
                    &peers,
                )
                .await;
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
        .punch_candidates(
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
