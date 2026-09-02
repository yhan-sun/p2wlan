/// Run the independent, bounded handshake lanes used by WireGuard offers,
/// answers and their endpoint publishes.
///
/// The ordinary control loop intentionally remains serial for stateful
/// device/peer work.  It can therefore be waiting on a slow candidate-only
/// POST when a real offer or answer arrives.  This worker owns a different
/// HTTP client and three separate bounded channels, so head-of-line blocking
/// cannot consume a handshake's short rendezvous window.
///
/// Delivery rules:
/// - answers are dispatched from their own channel ahead of offers and have a
///   dedicated in-flight budget: a slow offer or its retries can never delay
///   a later answer;
/// - every lane is bounded (queue capacity + in-flight semaphore);
/// - dropping the command's response receiver (the handshake owner was
///   cancelled or replaced) aborts queued and in-flight work: a stale owner
///   never sends and never holds a lane slot;
/// - retries reuse the exact prepared payload and are cut off by one overall
///   deadline, so a successful round can never become a 3 x 5 s sequence.
#[allow(clippy::too_many_arguments)]
async fn run_critical_control_loop(
    http: RouteAwareControlHttpClient,
    candidate_http: RouteAwareControlHttpClient,
    mut answer_rx: mpsc::Receiver<CriticalAnswerCommand>,
    mut offer_rx: mpsc::Receiver<CriticalOfferCommand>,
    mut ctrl_rx: mpsc::Receiver<CriticalControlCommand>,
    mut candidate_rx: mpsc::Receiver<CandidateOfferCommand>,
    mut auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
    health: Option<Arc<crate::tasks::HealthState>>,
) {
    let answer_permits = Arc::new(Semaphore::new(CRITICAL_ANSWER_MAX_INFLIGHT));
    let offer_permits = Arc::new(Semaphore::new(CRITICAL_OFFER_MAX_INFLIGHT));
    let ctrl_permits = Arc::new(Semaphore::new(CRITICAL_CTRL_MAX_INFLIGHT));
    let mut answers = JoinSet::new();
    let mut offers = JoinSet::new();
    let mut ctrls = JoinSet::new();
    let mut candidate_tasks = JoinSet::new();
    let mut candidate_workers: HashMap<String, mpsc::Sender<CandidateOfferCommand>> =
        HashMap::new();
    let mut candidate_auth: Option<CriticalControlAuth> = None;

    loop {
        tokio::select! {
            biased;
            Some(command) = answer_rx.recv() => {
                answers.spawn(run_critical_answer_command(
                    http.clone(),
                    command,
                    auth_rx.clone(),
                    event_tx.clone(),
                    answer_permits.clone(),
                ));
            }
            Some(command) = offer_rx.recv() => {
                offers.spawn(run_critical_offer_command(
                    http.clone(),
                    command,
                    auth_rx.clone(),
                    event_tx.clone(),
                    offer_permits.clone(),
                ));
            }
            Some(command) = ctrl_rx.recv() => {
                match command {
                    CriticalControlCommand::UpdateEndpoint { endpoint, nat_type, response_tx } => {
                        ctrls.spawn(run_critical_endpoint_command(
                            http.clone(),
                            auth_rx.clone(),
                            endpoint,
                            nat_type,
                            response_tx,
                            event_tx.clone(),
                            ctrl_permits.clone(),
                            relay_selection.clone(),
                            health.clone(),
                        ));
                    }
                    CriticalControlCommand::Shutdown => {
                        answers.abort_all();
                        offers.abort_all();
                        ctrls.abort_all();
                        candidate_tasks.abort_all();
                        return;
                    }
                }
            }
            changed = auth_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                let current = auth_rx.borrow().clone();
                let identity_changed = candidate_auth.as_ref().is_some_and(|previous| {
                    current
                        .as_ref()
                        .is_none_or(|current| !previous.same_identity_as(current))
                });
                if identity_changed {
                    // No queued candidate from a previous registration may be
                    // published using a new identity.  Aborting a request
                    // makes the caller observe a terminal channel failure;
                    // the candidate payload itself remains generation/expiry
                    // checked if the HTTP request was already ambiguous.
                    candidate_tasks.abort_all();
                    while candidate_tasks.join_next().await.is_some() {}
                    candidate_workers.clear();
                }
                candidate_auth = current;
            }
            Some(command) = candidate_rx.recv() => {
                if command
                    .fresh_ownership
                    .as_ref()
                    .is_some_and(|ownership| ownership.is_cancelled())
                {
                    let _ = command.response_tx.send(PeerOfferSendOutcome::Cancelled);
                    continue;
                }

                let peer_id = command.to_node_id.clone();
                let worker_tx = if let Some(sender) = candidate_workers.get(&peer_id) {
                    sender.clone()
                } else {
                    let sender = spawn_candidate_offer_worker(
                        &mut candidate_tasks,
                        candidate_http.clone(),
                        auth_rx.clone(),
                        event_tx.clone(),
                    );
                    candidate_workers.insert(peer_id.clone(), sender.clone());
                    sender
                };
                match worker_tx.try_send(command) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(command)) => {
                        warn!(
                            "Candidate offer queue full for {peer_id}; reason_code=candidate_offer_queue_full"
                        );
                        let _ = command.response_tx.send(PeerOfferSendOutcome::Failed);
                    }
                    Err(mpsc::error::TrySendError::Closed(command)) => {
                        candidate_workers.remove(&peer_id);
                        warn!(
                            "Candidate offer worker closed for {peer_id}; recreating lane reason_code=candidate_offer_worker_closed"
                        );
                        // A completed/panicked worker can leave its sender in
                        // the routing map until this command observes the
                        // closed receiver. Recreate the per-peer lane and
                        // retry the SAME immutable command once; dropping the
                        // first post-rebind candidate offer would otherwise
                        // leave the remote peer on the retired UDP endpoint.
                        let replacement = spawn_candidate_offer_worker(
                            &mut candidate_tasks,
                            candidate_http.clone(),
                            auth_rx.clone(),
                            event_tx.clone(),
                        );
                        candidate_workers.insert(peer_id.clone(), replacement.clone());
                        if let Err(error) = replacement.try_send(command) {
                            let command = match error {
                                mpsc::error::TrySendError::Full(command) => command,
                                mpsc::error::TrySendError::Closed(command) => {
                                    candidate_workers.remove(&peer_id);
                                    command
                                }
                            };
                            warn!(
                                "Replacement candidate offer worker unavailable for {peer_id}; reason_code=candidate_offer_worker_recreate_failed"
                            );
                            let _ = command.response_tx.send(PeerOfferSendOutcome::Failed);
                        }
                    }
                }
            }
            else => break,
        }
    }

    candidate_tasks.abort_all();
}

fn spawn_candidate_offer_worker(
    candidate_tasks: &mut JoinSet<()>,
    candidate_http: RouteAwareControlHttpClient,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
) -> mpsc::Sender<CandidateOfferCommand> {
    let (sender, receiver) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
    candidate_tasks.spawn(run_candidate_offer_worker(
        receiver,
        candidate_http,
        auth_rx,
        event_tx,
    ));
    sender
}

/// One per-peer candidate worker.  Requests for different peers run in
/// parallel, while this receiver preserves the strict order for one peer.
async fn run_candidate_offer_worker(
    mut rx: mpsc::Receiver<CandidateOfferCommand>,
    http: RouteAwareControlHttpClient,
    mut auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
) {
    enum CandidateOfferAttempt {
        Completed(Result<()>),
        OwnershipCancelled,
        ResponseClosed,
    }

    while let Some(command) = rx.recv().await {
        let CandidateOfferCommand {
            to_node_id,
            candidates,
            session_id,
            probe_ephemeral_public_key,
            candidate_sources,
            handshake_init,
            punch_at_ms,
            fresh_ownership,
            response_tx,
        } = command;
        let mut response_tx = response_tx;
        let deadline = Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE;
        let Some(auth) =
            wait_for_critical_control_auth(auth_rx.clone(), &mut response_tx, deadline).await
        else {
            continue;
        };
        if fresh_ownership
            .as_ref()
            .is_some_and(|ownership| ownership.is_cancelled())
        {
            let _ = response_tx.send(PeerOfferSendOutcome::Cancelled);
            continue;
        }
        // `wait_for_critical_control_auth` uses a clone of this receiver. Mark
        // the worker's receiver as having observed the same registration so a
        // duplicate publication of an unchanged token cannot cancel the
        // request before it reaches the control server.
        let current_auth = auth_rx.borrow_and_update().clone();
        if current_auth
            .as_ref()
            .is_some_and(|current| !auth.same_identity_as(current))
        {
            let _ = response_tx.send(PeerOfferSendOutcome::Failed);
            continue;
        }

        let signal_type = if fresh_ownership.is_some() {
            "peer_offer_fresh"
        } else {
            "peer_offer"
        };
        let payload = match prepare_signal_payload(
            &auth.self_node_id,
            &to_node_id,
            signal_type,
            &candidates,
            &candidate_sources,
            &handshake_init,
            punch_at_ms,
            None,
            session_id.as_deref(),
            probe_ephemeral_public_key.as_deref(),
            auth.signal_signing_identity.as_ref(),
        ) {
            Ok(payload) => payload,
            Err(error) => {
                let _ = event_tx.send(ControlEvent::ServerError {
                    code: 4000,
                    message: error.to_string(),
                });
                let _ = response_tx.send(PeerOfferSendOutcome::Failed);
                continue;
            }
        };

        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = match http.current() {
            Err(error) => CandidateOfferAttempt::Completed(Err(error)),
            Ok(_) if remaining.is_zero() => {
                CandidateOfferAttempt::Completed(Err(DaemonError::ControlPlane(
                    "candidate offer deadline exceeded; delivery status is unknown".into(),
                )))
            }
            Ok(current_http) => {
                // Keep one request future alive across duplicate auth-watch
                // notifications.  Dropping an in-flight reqwest future does
                // not prove that the server did not accept its POST; starting
                // a new future here can therefore duplicate a candidate
                // publication that already reached the control plane.
                let request = send_prepared_signal(
                    &current_http,
                    &auth.base_url,
                    &auth.token,
                    &payload,
                );
                tokio::pin!(request);
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break CandidateOfferAttempt::Completed(Err(DaemonError::ControlPlane(
                            "candidate offer deadline exceeded; delivery status is unknown".into(),
                        )));
                    }
                    tokio::select! {
                        biased;
                        // Fresh ownership can be revoked while the HTTP request is
                        // already in flight. Drop the local request future and
                        // report ambiguous delivery so the caller rolls back the
                        // retired socket; the server may already have accepted it.
                        // This cancels only the current immutable command, leaving
                        // the per-peer FIFO worker available for its replacement.
                        _ = async {
                            if let Some(ownership) = fresh_ownership.as_ref() {
                                ownership.cancelled().await;
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => break CandidateOfferAttempt::OwnershipCancelled,
                        // Cancelling one owner must abort only this immutable
                        // request. Returning from the whole per-peer worker leaves
                        // a closed sender cached in `candidate_workers`, so the
                        // next (often post-rebind) candidate publication is lost.
                        _ = response_tx.closed() => break CandidateOfferAttempt::ResponseClosed,
                        result = timeout(remaining, &mut request) => break CandidateOfferAttempt::Completed(match result {
                            Ok(result) => result,
                            Err(_) => Err(DaemonError::ControlPlane(
                                "candidate offer deadline exceeded during request; delivery status is unknown".into(),
                            )),
                        }),
                        changed = auth_rx.changed() => {
                            if changed.is_err() {
                                break CandidateOfferAttempt::Completed(Err(DaemonError::ControlPlane(
                                    "candidate offer control identity watch closed".into(),
                                )));
                            }
                            if auth_rx.borrow().as_ref().is_some_and(|current| {
                                !auth.same_identity_as(current)
                            }) {
                                break CandidateOfferAttempt::Completed(Err(DaemonError::ControlPlane(
                                    "candidate offer control identity changed during request".into(),
                                )));
                            }
                            // A duplicate publication of the same identity is
                            // harmless, but the request may already have reached
                            // the server. Keep polling this exact future instead
                            // of dropping it and issuing a duplicate POST.
                            continue;
                        }
                    }
                }
            },
        };
        let result = match result {
            CandidateOfferAttempt::Completed(_)
                if fresh_ownership
                    .as_ref()
                    .is_some_and(|ownership| ownership.is_cancelled()) =>
            {
                // Close the completion race in which HTTP readiness and
                // ownership revocation become observable in the same poll.
                let _ = response_tx.send(PeerOfferSendOutcome::Cancelled);
                continue;
            }
            CandidateOfferAttempt::Completed(result) => result,
            CandidateOfferAttempt::OwnershipCancelled => {
                let _ = response_tx.send(PeerOfferSendOutcome::Cancelled);
                continue;
            }
            CandidateOfferAttempt::ResponseClosed => {
                // The response receiver is the request owner's cancellation
                // token. The in-flight HTTP future was dropped by the select,
                // so no detached I/O or retry survives; keep the lane for the
                // next command from this peer.
                continue;
            }
        };
        let outcome = match result {
            Ok(()) => {
                debug!("Sent candidate peer_offer to {to_node_id} punch_at_ms={punch_at_ms:?}");
                let _ = event_tx.send(ControlEvent::ControlHealthy);
                PeerOfferSendOutcome::Sent
            }
            Err(error) => {
                let _ = event_tx.send(ControlEvent::ServerError {
                    code: 4000,
                    message: error.to_string(),
                });
                PeerOfferSendOutcome::Failed
            }
        };
        let _ = response_tx.send(outcome);
    }
}

/// Admit a command to its lane's in-flight budget, skipping it entirely when
/// the owner already dropped the response receiver (cancelled while queued).
async fn acquire_critical_permit_or_skip<T>(
    permits: &Arc<Semaphore>,
    response_tx: &oneshot::Sender<T>,
) -> Option<OwnedSemaphorePermit> {
    if response_tx.is_closed() {
        return None;
    }
    let permit = permits.clone().acquire_owned().await.ok()?;
    if response_tx.is_closed() {
        return None;
    }
    Some(permit)
}

async fn run_critical_answer_command(
    http: RouteAwareControlHttpClient,
    command: CriticalAnswerCommand,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    permits: Arc<Semaphore>,
) {
    let mut response_tx = command.response_tx;
    let Some(_permit) = acquire_critical_permit_or_skip(&permits, &response_tx).await else {
        return;
    };
    let deadline = Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE;
    let result = send_critical_signal(
        &http,
        auth_rx,
        &mut response_tx,
        deadline,
        &command.to_node_id,
        "peer_answer",
        &command.candidates,
        &command.candidate_sources,
        &command.handshake_response,
        command.punch_at_ms,
        command.punch_at_server_ms,
        command.session_id.as_deref(),
        command.probe_ephemeral_public_key.as_deref(),
    )
    .await;
    let Some(result) = result else {
        return;
    };
    match &result {
        Ok(()) => {
            debug!(
                "Sent peer answer to {} through critical lane punch_at_ms={:?}",
                command.to_node_id, command.punch_at_ms
            );
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        Err(error) => {
            let _ = event_tx.send(ControlEvent::ServerError {
                code: 4001,
                message: error.to_string(),
            });
        }
    }
    let _ = response_tx.send(result);
}

async fn run_critical_offer_command(
    http: RouteAwareControlHttpClient,
    command: CriticalOfferCommand,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    permits: Arc<Semaphore>,
) {
    let mut response_tx = command.response_tx;
    let Some(_permit) = acquire_critical_permit_or_skip(&permits, &response_tx).await else {
        return;
    };
    let deadline = Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE;
    let result = send_critical_signal(
        &http,
        auth_rx,
        &mut response_tx,
        deadline,
        &command.to_node_id,
        "peer_offer",
        &command.candidates,
        &command.candidate_sources,
        &command.handshake_init,
        command.punch_at_ms,
        None,
        command.session_id.as_deref(),
        command.probe_ephemeral_public_key.as_deref(),
    )
    .await;
    let Some(result) = result else {
        return;
    };
    let outcome = match &result {
        Ok(()) => {
            debug!(
                "Sent handshake peer_offer to {} through critical lane punch_at_ms={:?}",
                command.to_node_id, command.punch_at_ms
            );
            let _ = event_tx.send(ControlEvent::ControlHealthy);
            PeerOfferSendOutcome::Sent
        }
        Err(error) => {
            let _ = event_tx.send(ControlEvent::ServerError {
                code: 4000,
                message: error.to_string(),
            });
            PeerOfferSendOutcome::Failed
        }
    };
    let _ = response_tx.send(outcome);
}

#[allow(clippy::too_many_arguments)]
async fn run_critical_endpoint_command(
    http: RouteAwareControlHttpClient,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    endpoint: String,
    nat_type: String,
    mut response_tx: oneshot::Sender<Result<()>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    permits: Arc<Semaphore>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
    health: Option<Arc<crate::tasks::HealthState>>,
) {
    let Some(_permit) = acquire_critical_permit_or_skip(&permits, &response_tx).await else {
        return;
    };
    let deadline = Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE;
    let Some(auth) =
        wait_for_critical_control_auth(auth_rx.clone(), &mut response_tx, deadline).await
    else {
        return;
    };
    let relay_rtt_ms = current_relay_rtt_ms(relay_selection.as_ref()).await;
    let remaining = deadline.saturating_duration_since(Instant::now());
    let result = if remaining.is_zero() {
        Err(DaemonError::ControlPlane(
            "critical lane deadline exceeded before endpoint publish".into(),
        ))
    } else {
        match http.current() {
            Err(error) => Err(error),
            Ok(current_http) => {
                tokio::select! {
                    result = timeout(remaining, update_endpoint(
                        &current_http,
                        &auth.base_url,
                        &auth.token,
                        &auth.self_node_id,
                        &endpoint,
                        &nat_type,
                        relay_rtt_ms,
                    )) => {
                        match result {
                            Ok(result) => result,
                            Err(_) => Err(DaemonError::ControlPlane(
                                "critical lane deadline exceeded during endpoint publish".into(),
                            )),
                        }
                    }
                    _ = response_tx.closed() => return,
                }
            }
        }
    };
    match &result {
        Ok(()) => {
            if let Some(health) = health.as_ref() {
                health.mark_device_lease_success().await;
            }
            debug!(
                "Updated endpoint for {} through handshake control lane: {} ({})",
                auth.self_node_id, endpoint, nat_type
            );
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        Err(error) => {
            if let Some(health) = health.as_ref() {
                // Endpoint PATCH is the online lease operation. Preserve API
                // reachability independently: a later successful GET may
                // still prove the control API reachable, but it cannot repair
                // this failed device lease.
                health.set_device_lease_healthy(false);
            }
            let _ = event_tx.send(ControlEvent::ServerError {
                code: 2000,
                message: error.to_string(),
            });
        }
    }
    let _ = response_tx.send(result);
}

/// Wait for registration to publish an authoritative signal identity.  A
/// caller which lost its response receiver was cancelled by the handshake
/// owner, so do not retain its bounded-lane slot while the control plane is
/// offline or retry a stale response after re-registration.  The wait is
/// bounded by the overall lane deadline.
async fn wait_for_critical_control_auth<T>(
    mut auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    response_tx: &mut oneshot::Sender<T>,
    deadline: Instant,
) -> Option<CriticalControlAuth> {
    loop {
        if response_tx.is_closed() {
            return None;
        }
        if let Some(auth) = auth_rx.borrow().clone() {
            return Some(auth);
        }
        if Instant::now() >= deadline {
            return None;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::select! {
            _ = response_tx.closed() => return None,
            changed = auth_rx.changed() => {
                if changed.is_err() {
                    return None;
                }
            }
            _ = time::sleep(remaining) => return None,
        }
    }
}

/// Deliver one critical handshake signal with a single overall deadline.
///
/// The payload is prepared once and every retry re-sends that exact body
/// (candidate generation, expiry, Probe signature, session id and WireGuard
/// bytes never change between delivery-ambiguous attempts).  The identity is
/// re-validated against the registration watch before every attempt: after a
/// re-registration a stale owner must not send a new session's signal with
/// the old node id/token.
#[allow(clippy::too_many_arguments)]
async fn send_critical_signal<T>(
    http: &RouteAwareControlHttpClient,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    response_tx: &mut oneshot::Sender<T>,
    deadline: Instant,
    to_node_id: &str,
    signal_type: &str,
    candidates: &[String],
    candidate_sources: &HashMap<String, String>,
    handshake: &[u8],
    punch_at_ms: Option<u64>,
    punch_at_server_ms: Option<u64>,
    session_id: Option<&str>,
    probe_ephemeral_public_key: Option<&str>,
) -> Option<Result<()>> {
    let auth = wait_for_critical_control_auth(auth_rx.clone(), response_tx, deadline).await?;

    let payload = match prepare_signal_payload(
        &auth.self_node_id,
        to_node_id,
        signal_type,
        candidates,
        candidate_sources,
        handshake,
        punch_at_ms,
        punch_at_server_ms,
        session_id,
        probe_ephemeral_public_key,
        auth.signal_signing_identity.as_ref(),
    ) {
        Ok(payload) => payload,
        Err(error) => return Some(Err(error)),
    };

    // The retry delay is applied before each attempt after the first; the
    // overall deadline remains the binding constraint.
    let retry_delays = std::iter::once(std::time::Duration::ZERO)
        .chain(CRITICAL_SIGNAL_RETRY_DELAYS.iter().copied())
        .take(CRITICAL_SIGNAL_MAX_ATTEMPTS);
    for (attempt, retry_delay) in retry_delays.enumerate() {
        if attempt > 0 {
            tokio::select! {
                _ = time::sleep(retry_delay) => {}
                _ = response_tx.closed() => return None,
            }
        }
        if response_tx.is_closed() {
            return None;
        }
        if Instant::now() >= deadline {
            return Some(Err(DaemonError::ControlPlane(format!(
                "critical {signal_type} to {to_node_id} exceeded the lane deadline before delivery"
            ))));
        }
        // The registration loop may have replaced the identity while this
        // owner waited in the queue.  Never send a new session's answer (or
        // any handshake signal) with an old node id/token.
        if auth_rx
            .borrow()
            .as_ref()
            .is_some_and(|current| !auth.same_identity_as(current))
        {
            return Some(Err(DaemonError::ControlPlane(format!(
                "critical {signal_type} to {to_node_id} aborted: control identity was replaced by re-registration"
            ))));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = match http.current() {
            Err(error) => Err(error),
            Ok(current_http) => {
                tokio::select! {
                    result = timeout(remaining, send_prepared_signal(
                        &current_http,
                        &auth.base_url,
                        &auth.token,
                        &payload,
                    )) => {
                        match result {
                            Ok(result) => result,
                            Err(_) => Err(DaemonError::ControlPlane(format!(
                                "critical {signal_type} to {to_node_id} exceeded the lane deadline during the request"
                            ))),
                        }
                    }
                    _ = response_tx.closed() => return None,
                }
            }
        };
        match result {
            Ok(()) => return Some(Ok(())),
            Err(error)
                if attempt + 1 < CRITICAL_SIGNAL_MAX_ATTEMPTS
                    && !is_permanent_auth_error(&error.to_string()) =>
            {
                warn!(
                    "Critical {signal_type} to {to_node_id} failed on attempt {}; retrying: {error}",
                    attempt + 1
                );
            }
            Err(error) => return Some(Err(error)),
        }
    }

    unreachable!("critical signal retry loop must return on its final attempt")
}
