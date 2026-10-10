use super::*;

#[cfg(test)]
#[path = "tests/dynamic_mapping.rs"]
mod measurement_tests;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FreshMappingGateStage {
    AfterModelBeforeProbe,
    BeforeZeroCleanup,
}

#[cfg(test)]
#[derive(Debug)]
pub(super) struct FreshMappingGateContext {
    pub(super) peer_id: String,
    pub(super) socket_index: usize,
    pub(super) network_generation: u64,
    pub(super) punch_generation: u64,
}

#[cfg(test)]
pub(super) struct FreshMappingGenerationGate {
    pub(super) stage: FreshMappingGateStage,
    pub(super) peer_id: String,
    pub(super) arrived_tx: StdMutex<Option<oneshot::Sender<FreshMappingGateContext>>>,
    pub(super) release_rx: StdMutex<Option<oneshot::Receiver<()>>>,
}

#[cfg(test)]
pub(super) struct FreshMappingGateGuard {
    pub(super) slot: Arc<StdMutex<Option<Arc<FreshMappingGenerationGate>>>>,
    pub(super) gate: Arc<FreshMappingGenerationGate>,
    pub(super) release_tx: Option<oneshot::Sender<()>>,
}

#[cfg(test)]
impl FreshMappingGateGuard {
    pub(super) fn release(&mut self) {
        if let Some(release) = self.release_tx.take() {
            let _ = release.send(());
        }
    }
}

#[cfg(test)]
impl Drop for FreshMappingGateGuard {
    fn drop(&mut self) {
        self.release();
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &self.gate))
        {
            *slot = None;
        }
    }
}

#[cfg(test)]
impl UdpTransport {
    async fn wait_for_fresh_mapping_gate_for_test(
        &self,
        stage: FreshMappingGateStage,
        peer_id: &str,
        socket_index: usize,
        network_generation: u64,
        punch_generation: u64,
    ) {
        let gate = {
            let mut slot = self
                .fresh_mapping_generation_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if slot
                .as_ref()
                .is_some_and(|gate| gate.stage == stage && gate.peer_id == peer_id)
            {
                slot.take()
            } else {
                None
            }
        };
        let Some(gate) = gate else {
            return;
        };
        let arrived = gate
            .arrived_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("the selected lifecycle gate is consumed once");
        let release = gate
            .release_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
            .expect("the selected lifecycle gate has one release receiver");
        let _ = arrived.send(FreshMappingGateContext {
            peer_id: peer_id.to_owned(),
            socket_index,
            network_generation,
            punch_generation,
        });
        // No mutex guard or runtime authority is retained across this await.
        // This non-paused test watchdog does not rebase any model timestamp.
        timeout(Duration::from_secs(2), release)
            .await
            .expect("the test must release its lifecycle gate within 2s")
            .expect("gate guard Drop must release a parked generation");
    }
}

pub(super) const MEASUREMENT_SOFTWARE_TAG: &str = "P2WLAN/0.2";

pub(crate) fn monotonic_millis() -> u64 {
    static ORIGIN: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    // Zero is reserved for a missing response in MappingObservation. Never
    // publish this process-local value as an absolute signaling timestamp.
    ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min((u64::MAX - 1) as u128) as u64
        + 1
}

#[derive(Debug, Default)]
pub(super) struct FreshMappingMeasurementBatch {
    pub(super) observations: Vec<MappingObservation>,
    pub(super) attempts: Vec<p2pnet_nat::AllocationAttempt>,
    pub(super) stats: HardHardMeasurementStats,
}

pub(super) fn last_mapping_send_is_unobserved(attempts: &[p2pnet_nat::AllocationAttempt]) -> bool {
    attempts
        .iter()
        .rev()
        .find(|attempt| attempt.outcome != p2pnet_nat::AllocationAttemptOutcome::SendFailed)
        .is_some_and(|attempt| {
            attempt.outcome == p2pnet_nat::AllocationAttemptOutcome::SentUnobserved
        })
}

fn primary_mapping_tail_after_gap(
    attempts: &[p2pnet_nat::AllocationAttempt],
    primary: SocketAddr,
    observers: &[SocketAddr],
    request_limit: usize,
) -> Option<Vec<SocketAddr>> {
    if attempts.last()?.outcome == p2pnet_nat::AllocationAttemptOutcome::Observed {
        return None;
    }
    // A timed-out or failed pair is never retried as a fresh allocation. The
    // successful suffix must use three still-uncontacted primary destinations.
    let mut used = attempts
        .iter()
        .filter(|attempt| attempt.local_endpoint == primary)
        .map(|attempt| attempt.destination)
        .collect::<HashSet<_>>();
    let tail = observers
        .iter()
        .copied()
        .filter(|observer| used.insert(*observer))
        .take(3)
        .collect::<Vec<_>>();
    (tail.len() == 3 && attempts.len().saturating_add(tail.len()) <= request_limit).then_some(tail)
}

fn ordered_mapping_request_timeout(
    stun_timeout: Duration,
    started_ms: u64,
    now_ms: u64,
    remaining_requests: usize,
) -> Option<Duration> {
    let remaining_ms = FRESH_MAPPING_MEASURE_BUDGET
        .as_millis()
        .saturating_sub(u128::from(now_ms.saturating_sub(started_ms)));
    let timeout = stun_timeout
        .min(FRESH_MAPPING_STUN_TIMEOUT)
        .min(Duration::from_millis(
            remaining_ms
                .checked_div(remaining_requests as u128)?
                .min(u128::from(u64::MAX)) as u64,
        ));
    (!timeout.is_zero()).then_some(timeout)
}

#[derive(Debug)]
pub(super) enum MappingIoError {
    Inactive,
    Deadline,
    Io(std::io::Error),
}

/// Preserve one absolute request deadline through readiness, epoch admission
/// and response waits. The existing predicate also observes Direct promotion;
/// a short poll is needed because that predicate has no cancellation receiver.
pub(super) async fn wait_for_mapping_io<T>(
    future: impl std::future::Future<Output = T>,
    deadline: tokio::time::Instant,
    keep_measuring: &impl Fn() -> bool,
) -> std::result::Result<T, MappingIoError> {
    tokio::pin!(future);
    loop {
        if !keep_measuring() {
            return Err(MappingIoError::Inactive);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(MappingIoError::Deadline);
        }
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(deadline) => return Err(MappingIoError::Deadline),
            _ = tokio::time::sleep(Duration::from_millis(25)) => {},
            value = &mut future => {
                // Readiness can race cancellation or an elapsed deadline.
                if !keep_measuring() { return Err(MappingIoError::Inactive); }
                if tokio::time::Instant::now() >= deadline { return Err(MappingIoError::Deadline); }
                return Ok(value);
            }
        }
    }
}

impl UdpTransport {
    pub(super) async fn send_mapping_request_until(
        &self,
        socket: &UdpSocket,
        encoded: &[u8],
        observer: SocketAddr,
        deadline: tokio::time::Instant,
        keep_measuring: &impl Fn() -> bool,
    ) -> std::result::Result<u64, MappingIoError> {
        loop {
            wait_for_mapping_io(socket.writable(), deadline, keep_measuring)
                .await?
                .map_err(MappingIoError::Io)?;
            // Generation change and actual handoff share the existing epoch
            // gate. Readiness never retains it, and the syscall cannot await.
            let _epoch =
                wait_for_mapping_io(self.network_epoch_gate.lock(), deadline, keep_measuring)
                    .await?;
            let sent_at_ms = monotonic_millis();
            match socket.try_send_to(encoded, observer) {
                Ok(_) => return Ok(sent_at_ms),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(MappingIoError::Io(error)),
            }
        }
    }

    /// Bind a brand-new dedicated punch socket for one fresh-mapping generation.
    ///
    /// The socket is intentionally fresh: it has never contacted any observer
    /// or peer, so its next mappings follow the NAT's allocation sequence from
    /// a clean slate.
    pub(crate) async fn bind_fresh_punch_socket(&self) -> Result<(usize, Arc<UdpSocket>)> {
        let bind_addr = match self.socket.local_addr() {
            Ok(addr) if !addr.ip().is_unspecified() => SocketAddr::new(addr.ip(), 0),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        let socket = p2pnet_netbind::bind_udp(bind_addr, self.outbound_interface.as_deref())
            .await
            .map_err(|error| {
                DaemonError::Network(format!(
                    "failed to bind fresh-mapping punch socket at {bind_addr}: {error}"
                ))
            })?;
        let socket_index = self.next_dynamic_index();
        Ok((socket_index, Arc::new(socket)))
    }

    /// Measure the NAT's public port sequence with a dedicated socket.
    ///
    /// Requests are sent strictly sequentially: the next STUN request only
    /// goes out after the previous response arrived (or its budget ran out).
    /// This makes the observed send-order sequence the actual allocation order
    /// of the CGNAT for this socket; with back-to-back sends a shared CGNAT
    /// can allocate ports for the different destinations in an order that has
    /// nothing to do with our request order, producing deltas like
    /// [-1,+3,-1] that look like a negative step.
    /// Between the last request and the caller's first peer-directed punch
    /// this socket is exclusively owned by the generation: no refresh,
    /// maintainer or relay traffic may consume the next mapping.
    ///
    /// `keep_measuring` is re-evaluated before EVERY sample send and before
    /// every waiter wait: a Direct promotion, a session cancellation or a
    /// network-generation advance must stop the measurement immediately
    /// instead of completing the remaining STUN samples (which would only
    /// allocate more NAT mappings for a path that no longer needs them).
    pub(super) async fn measure_fresh_mapping_batch(
        &self,
        socket: &Arc<UdpSocket>,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        keep_measuring: impl Fn() -> bool,
    ) -> FreshMappingMeasurementBatch {
        let mut seen = HashSet::new();
        let observers = observers
            .iter()
            .copied()
            .filter(|observer| seen.insert(*observer))
            .take(usize::from(u16::MAX))
            .collect::<Vec<_>>();
        let requests = observers
            .into_iter()
            .map(|observer| (socket.clone(), observer))
            .collect::<Vec<_>>();
        self.measure_ordered_mapping_requests(&requests, stun_timeout, keep_measuring)
            .await
    }

    /// A single bounded measurement budget across a controlled socket/observer
    /// grid. Every request waits for its response before the next pair sends.
    /// The caller supplies fresh pairs; this collector records gaps rather
    /// than interpreting a timeout as evidence about an allocation.
    pub(super) async fn measure_ordered_mapping_requests(
        &self,
        requests: &[(Arc<UdpSocket>, SocketAddr)],
        stun_timeout: Duration,
        keep_measuring: impl Fn() -> bool,
    ) -> FreshMappingMeasurementBatch {
        self.measure_ordered_mapping_requests_with_primary_fallback(
            requests,
            None,
            stun_timeout,
            keep_measuring,
        )
        .await
    }

    /// A failed early grid observation may spend the remaining SAME budget on
    /// a primary-socket tail. It never retries an attempted pair, adds requests,
    /// discards unknown sends, or grants shared-allocator evidence on a gap.
    pub(super) async fn measure_ordered_mapping_requests_with_primary_fallback(
        &self,
        requests: &[(Arc<UdpSocket>, SocketAddr)],
        primary_fallback: Option<&Arc<UdpSocket>>,
        stun_timeout: Duration,
        keep_measuring: impl Fn() -> bool,
    ) -> FreshMappingMeasurementBatch {
        let deadline = tokio::time::Instant::now() + FRESH_MAPPING_MEASURE_BUDGET;
        let started_ms = monotonic_millis();
        let mut requests =
            requests[..requests.len().min(p2pnet_nat::MAX_ALLOCATION_SAMPLES)].to_vec();
        let request_limit = requests.len();
        let mut primary_fallback = primary_fallback.and_then(|socket| {
            Some((
                socket.clone(),
                socket.local_addr().ok()?,
                requests
                    .iter()
                    .filter(|(candidate, _)| Arc::ptr_eq(candidate, socket))
                    .map(|(_, observer)| *observer)
                    .collect::<Vec<_>>(),
            ))
        });
        let mut observations = Vec::with_capacity(requests.len());
        let mut attempts = Vec::with_capacity(requests.len());
        let mut stun_datagrams_sent = 0u32;
        let mut stun_bytes_sent = 0u64;
        let mut stun_send_errors = 0u32;
        let mut stun_send_error_bytes = 0u64;
        let mut last_send_at_ms = None;
        loop {
            let sequence = attempts.len();
            if attempts
                .last()
                .is_some_and(|attempt: &p2pnet_nat::AllocationAttempt| {
                    attempt.outcome != p2pnet_nat::AllocationAttemptOutcome::Observed
                })
            {
                if let Some((primary, endpoint, observers)) = primary_fallback.take() {
                    if let Some(tail) = primary_mapping_tail_after_gap(
                        &attempts,
                        endpoint,
                        &observers,
                        request_limit,
                    ) {
                        requests.truncate(sequence);
                        requests
                            .extend(tail.into_iter().map(|observer| (primary.clone(), observer)));
                        debug!(
                            reason = "hard_hard_grid_primary_tail_fallback",
                            attempts_completed = sequence,
                            requests_remaining = requests.len().saturating_sub(sequence),
                            "Incomplete grid will finish with unused primary-socket destinations"
                        );
                    }
                }
            }
            let Some((socket, observer)) = requests.get(sequence) else {
                break;
            };
            if !keep_measuring() {
                debug!(
                    "Fresh-mapping STUN measurement aborted before sample {sequence}: Direct was confirmed, the session was cancelled or the network generation changed"
                );
                break;
            }
            let Some(per_sample_timeout) = ordered_mapping_request_timeout(
                stun_timeout,
                started_ms,
                monotonic_millis(),
                requests.len().saturating_sub(sequence),
            ) else {
                break;
            };
            let request_deadline = deadline.min(tokio::time::Instant::now() + per_sample_timeout);

            let mut request = StunMessage::binding_request();
            request.add_attribute(StunAttribute::Software(
                MEASUREMENT_SOFTWARE_TAG.to_string(),
            ));
            let transaction_id = request.transaction_id;
            let encoded = request.encode();
            let (response_tx, response_rx) = oneshot::channel();
            let registration = match self.stun_waiters.register(transaction_id, response_tx) {
                Ok(registration) => registration,
                Err(error) => {
                    debug!(
                        reason = error.reason(),
                        "Fresh-mapping STUN waiter admission failed"
                    );
                    break;
                }
            };
            if !keep_measuring() || tokio::time::Instant::now() >= request_deadline {
                break;
            }
            let local_endpoint = socket
                .local_addr()
                .ok()
                .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            attempts.push(p2pnet_nat::AllocationAttempt {
                sequence: sequence as u16,
                local_endpoint,
                destination: *observer,
                sent_at_ms: monotonic_millis(),
                datagram_bytes: encoded.len() as u32,
                outcome: p2pnet_nat::AllocationAttemptOutcome::SendFailed,
            });
            let sent_at_ms = match self
                .send_mapping_request_until(
                    socket,
                    &encoded,
                    *observer,
                    request_deadline,
                    &keep_measuring,
                )
                .await
            {
                Ok(sent_at_ms) => sent_at_ms,
                Err(MappingIoError::Inactive) => break,
                Err(error) => {
                    stun_send_errors = stun_send_errors.saturating_add(1);
                    stun_send_error_bytes =
                        stun_send_error_bytes.saturating_add(encoded.len() as u64);
                    match error {
                        MappingIoError::Io(error) => {
                            debug!(reason = "mapping_send_failed", %error, sequence, "Fresh-mapping STUN handoff failed")
                        }
                        _ => debug!(
                            reason = "mapping_send_deadline",
                            sequence,
                            "Fresh-mapping STUN handoff exceeded original request deadline"
                        ),
                    }
                    continue;
                }
            };
            if let Some(attempt) = attempts.last_mut() {
                attempt.outcome = p2pnet_nat::AllocationAttemptOutcome::SentUnobserved;
                attempt.sent_at_ms = sent_at_ms;
            }
            stun_datagrams_sent = stun_datagrams_sent.saturating_add(1);
            stun_bytes_sent = stun_bytes_sent.saturating_add(encoded.len() as u64);
            last_send_at_ms = Some(sent_at_ms);
            if !keep_measuring() {
                debug!(
                    "Fresh-mapping STUN measurement aborted while waiting for sample {sequence}: Direct was confirmed, the session was cancelled or the network generation changed"
                );
                break;
            }
            let result = wait_for_mapping_io(response_rx, request_deadline, &keep_measuring).await;
            drop(registration);
            if matches!(result, Err(MappingIoError::Inactive)) {
                break;
            }
            let responded_at_ms = monotonic_millis();
            let parsed = match result {
                Ok(Ok(StunResponse { data, source })) if source == *observer => {
                    match StunMessage::decode(&data) {
                        Ok(response)
                            if response.transaction_id == transaction_id
                                && response.msg_type == p2pnet_nat::BINDING_RESPONSE =>
                        {
                            response.get_reflexive_address()
                        }
                        Ok(_) => None,
                        Err(_) => None,
                    }
                }
                _ => None,
            };
            if let Some(observed) = parsed {
                if let Some(attempt) = attempts.last_mut() {
                    attempt.outcome = p2pnet_nat::AllocationAttemptOutcome::Observed;
                }
                observations.push(MappingObservation {
                    sequence: sequence as u16,
                    observer: *observer,
                    observed,
                    sent_at_ms,
                    responded_at_ms,
                    local_endpoint,
                });
            } else {
                debug!(
                    "Fresh-mapping STUN {sequence} to {observer} got no usable response within {:?}",
                    per_sample_timeout
                );
            }
        }
        let finished_at_ms = monotonic_millis();
        FreshMappingMeasurementBatch {
            stats: HardHardMeasurementStats {
                stun_datagrams_sent,
                stun_bytes_sent,
                stun_send_errors,
                stun_send_error_bytes,
                stun_responses: u32::try_from(observations.len()).unwrap_or(u32::MAX),
                measurement_started_at_ms: Some(started_ms),
                last_measurement_send_at_ms: last_send_at_ms,
                measurement_completed_at_ms: Some(finished_at_ms),
            },
            observations,
            attempts,
        }
    }

    /// Run one atomic fresh-mapping punch generation for a peer.
    ///
    /// 1. Bind a fresh dedicated socket (never used before).
    /// 2. Measure 3-4 distinct STUN observers in send order.
    /// 3. Model the port sequence and build the rank-ordered prediction.
    /// 4. Punch the peer's stable public endpoint from the same socket,
    ///    creating the peer-facing mapping predicted by the model.
    ///
    /// The dedicated socket stays attached for the peer, so a successful
    /// Direct path continues to use it (and only it) as the data socket.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_fresh_mapping_generation(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        stable_targets: &[SocketAddr],
        probe_interval: Duration,
        attempts: u32,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
    ) -> FreshMappingOutcome {
        self.run_fresh_mapping_generation_internal(
            peer_id,
            observers,
            stun_timeout,
            stable_targets,
            probe_interval,
            attempts,
            cancellation,
            false,
            None,
        )
        .await
    }

    /// Measure and commit a fresh mapping without sending a peer-directed
    /// probe before the synchronized rendezvous.  The returned dynamic socket
    /// is the exact socket that produced the STUN sequence; the Hard↔Hard
    /// coordinator later sweeps that same index and fails closed if it is gone.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_hard_hard_fresh_mapping_generation(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
        scheduled_delay: Duration,
        max_scheduled_delay: Duration,
    ) -> FreshMappingOutcome {
        if scheduled_delay > max_scheduled_delay {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
        }
        self.run_fresh_mapping_generation_internal(
            peer_id,
            observers,
            stun_timeout,
            &[],
            Duration::ZERO,
            0,
            cancellation,
            true,
            Some((
                monotonic_millis().saturating_add(scheduled_delay.as_millis() as u64),
                max_scheduled_delay.as_millis() as u64,
            )),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run_fresh_mapping_generation_internal(
        &self,
        peer_id: &str,
        observers: &[SocketAddr],
        stun_timeout: Duration,
        stable_targets: &[SocketAddr],
        probe_interval: Duration,
        attempts: u32,
        cancellation: Option<&Arc<crate::PunchSessionCancellation>>,
        measure_only: bool,
        scheduled_send: Option<(u64, u64)>,
    ) -> FreshMappingOutcome {
        if !self.peers.local_nat_requires_fresh_mapping_punch().await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::StableLocalNat);
        }
        if cancellation.is_some_and(|c| c.is_cancelled()) {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        let allow_loopback = self.peers.fresh_mapping_harness_loopback_enabled().await;
        let stable_targets = stable_targets
            .iter()
            .copied()
            .filter(|endpoint| fresh_mapping_target_eligible(*endpoint, allow_loopback))
            .collect::<Vec<_>>();
        if !measure_only && stable_targets.is_empty() {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::NoStablePeerEndpoint);
        }
        if self.local_node_id.is_none() || self.peers.probe_key_for_peer(peer_id).await.is_none() {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::MissingProbeKey);
        }
        if self.peers.is_direct(peer_id).await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }

        // The previous generation's dedicated socket stays attached until the
        // new one is measured, modeled and punched: if this generation fails
        // (insufficient STUN samples, rejected model, superseded by an older
        // session), the old peer-facing mapping must keep working instead of
        // being destroyed preemptively.

        let network_generation = self.peers.current_network_generation().await;
        let punch_generation = self.peers.next_punch_generation(peer_id).await;
        let (socket_index, socket) = match self.bind_fresh_punch_socket().await {
            Ok(bound) => bound,
            Err(error) => {
                warn!("Fresh-mapping punch socket bind failed for peer {peer_id}: {error}");
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BindFailed);
            }
        };
        // The attach returns the ownership guard directly: the map insert and
        // the guard's creation happen without any await in between, so there
        // is never a provisional socket without a watcher, even if this future
        // is dropped at the very next await point.
        let provisional_guard = match self
            .attach_dynamic_punch_socket(
                peer_id,
                socket_index,
                socket.clone(),
                network_generation,
                punch_generation,
                cancellation,
            )
            .await
        {
            Ok(guard) => guard,
            Err(error) => {
                warn!("Failed to attach fresh-mapping punch socket for peer {peer_id}: {error:?}");
                return FreshMappingOutcome::Rejected(match error {
                    DynamicSocketAttachError::Superseded => FreshMappingRejection::Superseded,
                    DynamicSocketAttachError::CapacityRejected => {
                        FreshMappingRejection::CapacityRejected
                    }
                    DynamicSocketAttachError::NoInboundChannel
                    | DynamicSocketAttachError::ReaderStartupFailed => {
                        FreshMappingRejection::BindFailed
                    }
                });
            }
        };
        // From here on the socket is provisional: if the owning session is
        // preempted while this future is dropped at an await point, the
        // watcher detaches it unless the generation commits.  The commit is
        // an atomic phase transition under the socket-state lock, so the
        // watcher and the generation can never disagree about ownership.
        // Without a session cancellation handle the watcher still covers a
        // dropped future via the guard's own stop signal.

        let observers = observers
            .iter()
            .copied()
            .filter(|observer| observer.is_ipv4())
            .take(FRESH_MAPPING_OBSERVERS_PER_BATCH)
            .collect::<Vec<_>>();
        if observers.len() < 3 {
            self.detach_dynamic_socket_by_index(socket_index, "insufficient_observers")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
        }

        let local_endpoint = socket
            .local_addr()
            .ok()
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
        self.peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_generation_started",
                None,
                Some(observers.len()),
                None,
                format!(
                    "punch_generation={punch_generation} network_generation={network_generation} socket_local={local_endpoint} socket_index={socket_index} observers={} targets={}",
                    observers.len(),
                    stable_targets.len()
                ),
            )
            .await;

        let started_ms = monotonic_millis();
        let measurement_peer_id = peer_id.to_string();
        let measurement = self
            .measure_fresh_mapping_batch(&socket, &observers, stun_timeout, || {
                !cancellation.is_some_and(|c| c.is_cancelled())
                    && !self.peers.is_direct_sync(&measurement_peer_id)
                    && self.peers.current_network_generation_sync() == network_generation
            })
            .await;
        let finished_ms = monotonic_millis();
        if self
            .abort_generation_if_cancelled(cancellation, peer_id, socket_index)
            .await
        {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        let batch = MappingBatch {
            generation: punch_generation,
            network_generation,
            socket_identity: local_endpoint,
            observations: measurement.observations,
            started_at_ms: started_ms,
            finished_at_ms: finished_ms,
        };
        let sample_count = batch.successful_samples();

        for observation in &batch.observations {
            debug!(
                event = "fresh_mapping_observer",
                peer_id = %peer_id,
                network_generation = network_generation,
                punch_generation = punch_generation,
                socket_local = %observation.local_endpoint,
                sequence = observation.sequence,
                observer = %observation.observer,
                srflx = %observation.observed,
                rtt_ms = observation.rtt_ms().unwrap_or(0),
                "fresh_mapping_observer peer_id={} punch_generation={} seq={} observer={} srflx={} rtt_ms={}",
                peer_id,
                punch_generation,
                observation.sequence,
                observation.observer,
                observation.observed,
                observation.rtt_ms().unwrap_or(0)
            );
        }

        if sample_count < 3 {
            // Direct confirmation, session cancellation and generation
            // advances take precedence over the sample-count rejection: an
            // aborted measurement (the peer went Direct mid-batch) must
            // report the real reason instead of masking it as an insufficient
            // sample count.
            if self.peers.is_direct(peer_id).await {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "fresh_mapping_skipped",
                        None,
                        None,
                        None,
                        "peer became Direct while the fresh-mapping generation measured; keeping the working data path",
                    )
                    .await;
                self.detach_dynamic_socket_by_index(socket_index, "peer_became_direct")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
            }
            if self.peers.current_network_generation().await != network_generation {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "fresh_mapping_skipped",
                        None,
                        None,
                        None,
                        format!(
                            "network generation changed during the fresh-mapping measurement (expected {network_generation}); discarding the batch"
                        ),
                    )
                    .await;
                self.detach_dynamic_socket_by_index(socket_index, "network_generation_changed")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
            }
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    "insufficient STUN samples for a mapping model",
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "insufficient_samples")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
        }

        if last_mapping_send_is_unobserved(&measurement.attempts) {
            self.peers.record_direct_event(
                peer_id, "fresh_mapping_rejected", None, Some(sample_count), None,
                "allocation_unobserved_send: the last accepted STUN request has no mapping observation",
            ).await;
            self.detach_dynamic_socket_by_index(socket_index, "allocation_unobserved_send")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::UnobservedAllocation);
        }

        if batch.public_ip().is_none() {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    "observed public IP changed across the measurement batch",
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "public_ip_changed")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::PublicIpChanged);
        }

        let now_ms = monotonic_millis();
        let model = match build_model_for_batch(&batch, FRESH_MAPPING_MODEL_MAX_AGE, now_ms) {
            Ok(model) => model,
            Err(ModelRejection::BatchStale) => {
                self.detach_dynamic_socket_by_index(socket_index, "batch_stale")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
            }
            Err(ModelRejection::InconsistentBatch) => {
                self.detach_dynamic_socket_by_index(socket_index, "inconsistent_batch")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InconsistentBatch);
            }
            Err(ModelRejection::InsufficientSamples) => {
                self.detach_dynamic_socket_by_index(socket_index, "insufficient_samples")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::InsufficientSamples);
            }
            Err(ModelRejection::PublicIpChanged) => {
                self.detach_dynamic_socket_by_index(socket_index, "public_ip_changed")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::PublicIpChanged);
            }
            Err(ModelRejection::NarrowRandom | ModelRejection::NoConsistentStep) => {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "fresh_mapping_rejected",
                        None,
                        Some(sample_count),
                        None,
                        format!(
                            "port sequence is not consistently linear: sequence={:?} deltas={:?}",
                            batch.ordered_ports(),
                            model_deltas(&batch)
                        ),
                    )
                    .await;
                self.detach_dynamic_socket_by_index(socket_index, "unpredictable_sequence")
                    .await;
                return FreshMappingOutcome::Rejected(FreshMappingRejection::UnpredictableSequence);
            }
        };

        let step = match &model.kind {
            PortModelKind::FixedStep { step }
            | PortModelKind::Linear { step }
            | PortModelKind::NoisyLinear { step } => Some(*step),
            PortModelKind::MonotonicWindow { direction } => Some(i16::from(*direction)),
            _ => None,
        };
        if step
            .is_some_and(|step| u32::from(step.unsigned_abs()) > FRESH_MAPPING_MAX_ABS_STEP as u32)
        {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_rejected",
                    None,
                    Some(sample_count),
                    None,
                    format!(
                        "model step {} exceeds the {FRESH_MAPPING_MAX_ABS_STEP} bound; treating as unpredictable",
                        step.unwrap_or(0)
                    ),
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "unpredictable_sequence")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::UnpredictableSequence);
        }

        let ports = batch.ordered_ports();
        let last = *ports.last().expect("three or more samples");
        // The peer-facing mapping is fixed when the first peer-directed punch
        // goes out.  The window must cover the ports a shared CGNAT consumed
        // between the last STUN allocation (request send, not response) and
        // that punch; signal propagation time does not move our own mapping.
        let first_sent_at_ms = batch
            .observations
            .first()
            .map(|observation| observation.sent_at_ms)
            .unwrap_or(batch.started_at_ms);
        let last_sent_at_ms = batch
            .observations
            .last()
            .map(|observation| observation.sent_at_ms)
            .unwrap_or(batch.finished_at_ms);
        let measurement_span_ms = last_sent_at_ms.saturating_sub(first_sent_at_ms);
        let probe_gap_ms = now_ms.saturating_sub(last_sent_at_ms);
        let public_ip = batch.public_ip();
        // Fold this batch into the adaptive learner (scoped by destination:
        // STUN prior + per-peer direction) and read back its stride estimate +
        // allocation direction.  The detector is fed the raw observed ports; the
        // step learner is fed the model's deltas.  A network-generation change
        // resets both first, so a reading from a superseded allocator is never
        // applied here.
        let _learner_ip =
            public_ip.expect("a valid batch was checked for a single public IP above");
        let learning = self
            .observe_learning(&ports, &model, network_generation)
            .await;
        let learner_used = learning.step_estimate.is_some_and(|estimate| {
            u32::from(estimate.unsigned_abs()) <= FRESH_MAPPING_MAX_ABS_STEP as u32
        });
        let effective_step = if learner_used {
            learning.step_estimate
        } else {
            None
        };
        // Prefer the peer-scope allocation direction over the STUN prior: once
        // this peer's real mapping direction was observed on the wire, a
        // complex CGNAT that allocates toward STUN differently than toward the
        // peer must not drag this peer's window back toward the STUN direction
        // (audit P1-B).  With no peer-scope evidence the STUN direction is the
        // prior.
        let peer_direction = self
            .peer_learning_snapshot(peer_id, network_generation)
            .await
            .map(|snapshot| snapshot.direction);
        let direction = peer_direction.unwrap_or(learning.direction);
        let predicted = if let Some((send_at_ms, max_send_delay_ms)) = scheduled_send {
            // The measure-only lane has not pinned a peer-facing mapping yet.
            // Shared allocators keep moving until the scheduled first send.
            let timing = p2pnet_nat::mapping::rendezvous::RendezvousPredictionTiming {
                measurement_span_ms,
                last_measurement_send_at_ms: last_sent_at_ms,
                now_ms,
                send_delay_ms: send_at_ms.saturating_sub(now_ms),
                max_send_delay_ms,
                max_model_age: FRESH_MAPPING_MODEL_MAX_AGE,
            };
            match p2pnet_nat::mapping::rendezvous::predict_for_rendezvous(
                &model,
                last,
                timing,
                effective_step,
                direction == DirectionPattern::Reverse,
            ) {
                Ok(predicted) => predicted,
                Err(_) => {
                    self.detach_dynamic_socket_by_index(socket_index, "forecast_stale")
                        .await;
                    return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
                }
            }
        } else {
            predict_ports_with_learning(
                &model,
                last,
                measurement_span_ms,
                probe_gap_ms,
                effective_step,
                direction == DirectionPattern::Reverse,
            )
        };
        let predicted_ports = predicted
            .iter()
            .map(|candidate| candidate.port)
            .collect::<Vec<_>>();

        let sequence_label = format!("{:?}", ports);
        let deltas_label = format!("{:?}", model.deltas);
        info!(
            event = "fresh_mapping_model",
            peer_id = %peer_id,
            network_generation = network_generation,
            punch_generation = punch_generation,
            socket_local = %local_endpoint,
            model = ?model.kind,
            confidence = model.confidence,
            sequence = %sequence_label,
            deltas = %deltas_label,
            sample_age_ms = now_ms.saturating_sub(batch.started_at_ms),
            forecast_delay_ms = scheduled_send.map_or(0, |(at_ms, _)| at_ms.saturating_sub(now_ms)),
            step_estimate = ?learning.step_estimate,
            learner_revision_count = learning.revision_count,
            direction_pattern = learning.direction.as_str(),
            learner_used = learner_used,
            predicted = ?predicted_ports,
            "fresh_mapping_model peer_id={} punch_generation={} model={:?} confidence={} sequence={} deltas={} step_estimate={:?} learner_revision_count={} direction_pattern={} learner_used={} predicted={:?}",
            peer_id,
            punch_generation,
            model.kind,
            model.confidence,
            sequence_label,
            deltas_label,
            learning.step_estimate,
            learning.revision_count,
            learning.direction.as_str(),
            learner_used,
            predicted_ports
        );
        // The fresh-mapping model is only recorded after ownership, network
        // and direct-path validations below pass and the generation commits:
        // a stale generation must never overwrite the fresh state a newer
        // generation already recorded.

        // Re-validate ownership before touching any shared state: the ~1s
        // measurement may have seen the peer go Direct through the previous
        // socket, the network generation change, or this session be
        // superseded.  Never tear down a working path or commit a stale
        // mapping on top of it.
        if self
            .abort_generation_if_cancelled(cancellation, peer_id, socket_index)
            .await
        {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        if self.peers.is_direct(peer_id).await {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    None,
                    None,
                    None,
                    "peer became Direct while the fresh-mapping generation measured; keeping the working data path",
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "peer_became_direct")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        if self.peers.current_network_generation().await != network_generation {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    None,
                    None,
                    None,
                    format!(
                        "network generation changed during the fresh-mapping measurement (expected {network_generation}); discarding the batch"
                    ),
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "network_generation_changed")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::BatchStale);
        }

        #[cfg(test)]
        if !measure_only {
            self.wait_for_fresh_mapping_gate_for_test(
                FreshMappingGateStage::AfterModelBeforeProbe,
                peer_id,
                socket_index,
                network_generation,
                punch_generation,
            )
            .await;
        }

        // The peer-facing punch loop: only sends from the dedicated socket
        // may claim success.  The mapping is fixed when the first peer-facing
        // probe enters the kernel send queue.
        // In measure-only mode there is deliberately no peer-directed send at
        // this point.  Keep the result timestamps meaningful by anchoring the
        // handoff to the final STUN request rather than inventing a punch.
        let first_punch_sent_at_ms = if measure_only {
            first_sent_at_ms
        } else {
            monotonic_millis()
        };
        let mut sent = 0u32;
        let mut probe_summary = FreshMappingProbeSummary::default();
        if !measure_only {
            for round in 0..attempts {
                if cancellation.is_some_and(|c| c.is_cancelled()) {
                    probe_summary.record_outer_stop(FreshMappingProbeStopCause::Cancelled);
                    debug!(
                    "Fresh-mapping punch generation {punch_generation} aborted mid-punch; session superseded"
                );
                    break;
                }
                if self.peers.is_direct(peer_id).await {
                    probe_summary.record_outer_stop(FreshMappingProbeStopCause::DirectConfirmed);
                    // Direct was confirmed while this generation was measuring or
                    // punching: stop emitting peer-facing probes from the
                    // generation's socket immediately.
                    debug!(
                    "Fresh-mapping punch generation {punch_generation} aborted mid-punch; Direct was confirmed"
                );
                    break;
                }
                if self.peers.current_network_generation_sync() != network_generation {
                    probe_summary
                        .record_outer_stop(FreshMappingProbeStopCause::NetworkGenerationChanged);
                    debug!(
                    "Fresh-mapping punch generation {punch_generation} aborted mid-punch; the network generation changed"
                );
                    break;
                }
                for target in &stable_targets {
                    probe_summary.record_call();
                    match self
                        .send_probe_on_socket_result_with_hard_hard_token_classified(
                            socket_index,
                            socket.clone(),
                            Some(peer_id),
                            *target,
                            true,
                            PendingProbePurpose::ConnectivityCheck,
                            None,
                            false,
                            None,
                        )
                        .await
                    {
                        Ok(result) => {
                            sent = sent.saturating_add(1);
                            probe_summary.record_success(&result);
                            if !OUTBOUND_CONNECTIVITY_PROBE_SPACING.is_zero() {
                                sleep(OUTBOUND_CONNECTIVITY_PROBE_SPACING).await;
                            }
                        }
                        Err(failure) => {
                            probe_summary.record_failure(&failure);
                            debug!(
                                "Fresh-mapping punch from socket {socket_index} to {} failed: {}",
                                target, failure.error
                            );
                        }
                    }
                    if round + 1 < attempts && !probe_interval.is_zero() {
                        sleep(probe_interval.min(Duration::from_millis(50))).await;
                    }
                }
            }
        }
        let last_punch_sent_at_ms = monotonic_millis();

        // No peer-facing probe ever entered the kernel queue: the generation
        // must not claim success.  The provisional socket is detached while
        // the previous generation's socket (the peer's working path) stays.
        if !measure_only && sent == 0 {
            let cancelled = cancellation.is_some_and(|c| c.is_cancelled());
            if cancelled {
                probe_summary.record_outer_stop(FreshMappingProbeStopCause::Cancelled);
            }
            #[cfg(test)]
            self.wait_for_fresh_mapping_gate_for_test(
                FreshMappingGateStage::BeforeZeroCleanup,
                peer_id,
                socket_index,
                network_generation,
                punch_generation,
            )
            .await;
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    stable_targets.first().copied(),
                    Some(stable_targets.len()),
                    Some(sent),
                    format!(
                        "fresh-mapping generation sent no peer-facing probe (attempts={attempts}); keeping the previous generation's socket {}",
                        probe_summary.diagnostic_fields(),
                    ),
                )
                .await;
            self.detach_dynamic_socket_by_index(socket_index, "no_peer_facing_probe")
                .await;
            // Cleanup includes real lock/drain awaits. Cancellation arriving
            // inside any of them must supersede the completed generation.
            let cancelled_after_cleanup = cancellation.is_some_and(|c| c.is_cancelled());
            return FreshMappingOutcome::Rejected(if cancelled_after_cleanup {
                FreshMappingRejection::Superseded
            } else {
                FreshMappingRejection::NoProbesSent(Box::new(probe_summary))
            });
        }

        // The new generation is now established (measurement, model and at
        // least one peer-facing punch all completed).  Commit the socket and
        // pin the affinity as one atomic phase transition under the
        // socket-state lock: the provisional watcher can never detach a
        // committed socket, and a cancelled generation can never commit.
        // The commit re-validates ownership (peer, socket index, network
        // generation, per-peer committed-generation high-water) and returns
        // the predecessor pin so a cancellation that lands right after the
        // commit can roll the peer back to its old path — conditionally, by
        // the watcher, only while the affinity still equals this commit's pin.
        if measure_only && !self.reserve_hard_hard_socket(peer_id, socket_index).await {
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        let commit_outcome = provisional_guard
            .commit_and_pin(
                self,
                peer_id,
                socket_index,
                network_generation,
                punch_generation,
            )
            .await;
        if !commit_outcome.committed() {
            // The watcher already detached the provisional socket (session
            // cancelled while this future was dropped at an await point, or
            // the commit raced cancellation): abort without touching the
            // previous generation's socket.
            self.detach_dynamic_socket_by_index(socket_index, "generation_abandoned")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }
        // Cancellation may still have arrived between the final pre-commit
        // check and the commit.  The durable handoff is skipped: when this
        // future ends, the guard drops and its watcher performs the
        // conditional rollback (restores the predecessor pin and detaches
        // this socket — only while the affinity still equals the pin this
        // commit installed, so a newer commit can never be downgraded).
        if cancellation.is_some_and(|c| c.is_cancelled()) {
            self.peers
                .record_direct_event(
                    peer_id,
                    "fresh_mapping_skipped",
                    stable_targets.first().copied(),
                    Some(stable_targets.len()),
                    None,
                    "fresh-mapping generation committed after its punch session was superseded; the watcher restores the previous generation's pin and detaches the socket",
                )
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }

        // Final ownership verification before claiming success: the committed
        // socket must still be attached in a usable phase and still pinned
        // for this peer.  A network-generation change or a superseding
        // generation can detach it during the punch; an Accepted outcome must
        // never correspond to a detached socket.  The generation's guard is
        // returned with the outcome: the durable handoff (`finalize`) runs in
        // the caller AFTER the fresh prediction was advertised to the peer,
        // so an advertise failure or a session cancellation between the
        // commit and the advertise can still roll the socket back.
        let still_owned = {
            let state = self.socket_state.lock().await;
            state
                .dynamic
                .get(&socket_index)
                .is_some_and(|entry| entry.phase.is_usable() && entry.peer_id == peer_id)
                && state
                    .affinity
                    .get(peer_id)
                    .is_some_and(|pin| pin.socket_index == socket_index)
        };
        if !still_owned {
            self.detach_dynamic_socket_by_index(socket_index, "ownership_lost_before_accept")
                .await;
            return FreshMappingOutcome::Rejected(FreshMappingRejection::Superseded);
        }

        // Record the fresh mapping only now that ownership, network and
        // direct-path validations passed and the socket is committed.
        self.peers
            .record_direct_event(
                peer_id,
                "fresh_mapping_model",
                stable_targets.first().copied(),
                Some(predicted_ports.len()),
                None,
                format!(
                    "punch_generation={punch_generation} model={:?} confidence={} sequence={} deltas={} step_estimate={:?} learner_revision_count={} direction_pattern={} learner_used={} predicted={:?}",
                    model.kind,
                    model.confidence,
                    sequence_label,
                    deltas_label,
                    learning.step_estimate,
                    learning.revision_count,
                    learning.direction.as_str(),
                    learner_used,
                    predicted_ports
                ),
            )
            .await;
        self.peers
            .record_fresh_mapping_with_socket(
                peer_id,
                p2pnet_nat::mapping::PortModel::clone(&model),
                predicted_ports.clone(),
                local_endpoint,
                socket_index,
                public_ip,
                punch_generation,
                network_generation,
            )
            .await;

        self.peers
            .record_direct_event(
                peer_id,
                if measure_only {
                    "fresh_mapping_measurement_ready"
                } else {
                    "fresh_mapping_punch_sent"
                },
                stable_targets.first().copied(),
                Some(stable_targets.len()),
                Some(sent),
                format!(
                    "punch_generation={punch_generation} socket_local={local_endpoint} socket_index={socket_index} first_sent_ms={first_punch_sent_at_ms} last_sent_ms={last_punch_sent_at_ms} targets={} sent={sent} measure_only={measure_only}",
                    stable_targets.len()
                ),
            )
            .await;
        debug!(
            "Fresh-mapping punch generation {punch_generation} sent {sent} probes to peer {peer_id} from {local_endpoint}"
        );

        // The durable handoff is NOT performed here: the caller advertises
        // the fresh prediction window and only then calls `finalize`, which
        // waits for the watcher's explicit acknowledgement and detaches the
        // superseded predecessor.  Until then the peer can still be rolled
        // back to its previous path on cancellation.
        FreshMappingOutcome::Accepted(
            Box::new(FreshMappingResult {
                punch_generation,
                network_generation,
                socket_local_endpoint: local_endpoint,
                socket_index,
                model,
                predicted_ports,
                public_ip,
                first_punch_sent_at_ms,
                last_punch_sent_at_ms,
                measurement: measurement.stats,
            }),
            Box::new(provisional_guard),
        )
    }
}
