include!("candidate_dispatch.rs");

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
/// - every lane bounds both queued commands and spawned tasks;
/// - dropping the command's response receiver (the handshake owner was
///   cancelled or replaced) skips the command at admission or aborts its
///   in-flight work, releasing the active lane slot;
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
    mut shutdown_rx: watch::Receiver<bool>,
    advertised_snapshot: Arc<std::sync::Mutex<AdvertisedEndpointSnapshot>>,
    lifecycle_tx: mpsc::UnboundedSender<ControlCommand>,
) {
    let answer_permits = Arc::new(Semaphore::new(CRITICAL_ANSWER_MAX_INFLIGHT));
    let offer_permits = Arc::new(Semaphore::new(CRITICAL_OFFER_MAX_INFLIGHT));
    let ctrl_permits = Arc::new(Semaphore::new(CRITICAL_CTRL_MAX_INFLIGHT));
    let mut answers = JoinSet::new();
    let mut offers = JoinSet::new();
    let mut ctrls = JoinSet::new();
    let mut candidate_tasks = JoinSet::new();
    let mut candidate_workers: HashMap<String, CandidateOfferLane> = HashMap::new();
    let mut candidate_auth = auth_rx.borrow().clone();
    let mut pending_candidate_dispatch: Option<PendingCandidateDispatch> = None;

    loop {
        if *shutdown_rx.borrow() || shutdown_rx.has_changed().is_err() {
            break;
        }
        if let Some(command) = pending_candidate_dispatch
            .as_mut()
            .and_then(|pending| pending.take_ready_lane_command(&candidate_workers, &auth_rx))
        {
            pending_candidate_dispatch = route_candidate_offer(
                command,
                &mut candidate_workers,
                &mut candidate_tasks,
                &candidate_http,
                &auth_rx,
                &event_tx,
            );
        }
        let pending_auth = auth_rx.clone();
        tokio::select! {
            biased;
            _ = control_shutdown_requested(&mut shutdown_rx) => break,
            Some(_) = answers.join_next(), if !answers.is_empty() => {}
            Some(_) = offers.join_next(), if !offers.is_empty() => {}
            Some(_) = ctrls.join_next(), if !ctrls.is_empty() => {}
            Some(completed) = candidate_tasks.join_next_with_id(), if !candidate_tasks.is_empty() => {
                reap_candidate_offer_lane(&mut candidate_workers, completed);
            }
            // Keep waiting commands in their bounded channels. A semaphore
            // inside each spawned task limits HTTP, but cannot bound the
            // number of tasks waiting for it. Each lane remains independent.
            Some(command) = answer_rx.recv(), if answers.len() < CRITICAL_ANSWER_MAX_INFLIGHT => {
                answers.spawn(run_critical_answer_command(
                    http.clone(),
                    command,
                    auth_rx.clone(),
                    event_tx.clone(),
                    answer_permits.clone(),
                ));
            }
            Some(command) = offer_rx.recv(), if offers.len() < CRITICAL_OFFER_MAX_INFLIGHT => {
                offers.spawn(run_critical_offer_command(
                    http.clone(),
                    command,
                    auth_rx.clone(),
                    event_tx.clone(),
                    offer_permits.clone(),
                ));
            }
            Some(command) = ctrl_rx.recv(), if ctrls.len() < CRITICAL_CTRL_MAX_INFLIGHT => {
                match command {
                    CriticalControlCommand::UpdateEndpoint { endpoint, nat_type, publication_fence, response_tx } => {
                        ctrls.spawn(run_critical_endpoint_command(
                            http.clone(),
                            auth_rx.clone(),
                            endpoint,
                            nat_type,
                            publication_fence,
                            response_tx,
                            event_tx.clone(),
                            ctrl_permits.clone(),
                            relay_selection.clone(),
                            health.clone(),
                            advertised_snapshot.clone(),
                            lifecycle_tx.clone(),
                        ));
                    }
                    CriticalControlCommand::Shutdown => {
                        break;
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
                    pending_candidate_dispatch = None;
                    candidate_tasks.abort_all();
                    while candidate_tasks.join_next().await.is_some() {}
                    candidate_workers.clear();
                }
                candidate_auth = current;
            }
            closed_command = async {
                match pending_candidate_dispatch.as_mut() {
                    Some(dispatch) => dispatch.poll(pending_auth).await,
                    None => std::future::pending().await,
                }
            }, if pending_candidate_dispatch.is_some() => {
                pending_candidate_dispatch = closed_command.and_then(|command| {
                    // A closed reservation still belongs to its retiring lane.
                    // Wait for exact task completion before any same-peer restart.
                    PendingCandidateDispatch::wait_for_closed_lane(command, &auth_rx)
                });
            }
            Some(command) = candidate_rx.recv(), if pending_candidate_dispatch.is_none() => {
                pending_candidate_dispatch = route_candidate_offer(
                    CandidateDispatchCommand::new(command), &mut candidate_workers, &mut candidate_tasks,
                    &candidate_http, &auth_rx, &event_tx,
                );
            }
            else => break,
        }
    }

    drop(pending_candidate_dispatch);
    answers.abort_all();
    offers.abort_all();
    ctrls.abort_all();
    candidate_tasks.abort_all();
    while answers.join_next().await.is_some() {}
    while offers.join_next().await.is_some() {}
    while ctrls.join_next().await.is_some() {}
    while candidate_tasks.join_next().await.is_some() {}
}

fn spawn_candidate_offer_worker(
    candidate_tasks: &mut JoinSet<()>,
    candidate_http: RouteAwareControlHttpClient,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
) -> CandidateOfferLane {
    let (sender, receiver) = mpsc::channel(CANDIDATE_OFFER_QUEUE_CAPACITY);
    let task = candidate_tasks.spawn(run_candidate_offer_worker(
        receiver,
        candidate_http,
        auth_rx,
        event_tx,
    ));
    CandidateOfferLane {
        sender,
        task_id: task.id(),
    }
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

    let mut retiring = false;
    while let Some(command) = receive_candidate_offer(&mut rx, &mut retiring).await {
        let CandidateOfferCommand {
            expected_registration_seq,
            not_after,
            attempt_timeout,
            prepaid_attempts,
            to_node_id,
            candidates,
            session_id,
            probe_ephemeral_public_key,
            candidate_sources,
            handshake_init,
            punch_at_ms,
            punch_at_server_ms,
            fresh_ownership,
            publication_fence,
            response_tx,
        } = command;
        let mut response_tx = response_tx;
        if !(1..=HARD_HARD_START_ACK_MAX_ATTEMPTS).contains(&prepaid_attempts) {
            let _ = response_tx.send(PeerOfferSendOutcome::Failed);
            continue;
        }
        let deadline = not_after
            .map_or(Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE, |limit| {
                limit.min(Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE)
            });
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
        if let Some(fence) = publication_fence.as_ref() {
            if !fence.is_current().await {
                let _ = response_tx.send(PeerOfferSendOutcome::Cancelled);
                continue;
            }
        }
        // `wait_for_critical_control_auth` uses a clone of this receiver. Mark
        // the worker's receiver as having observed the same registration so a
        // duplicate publication of an unchanged token cannot cancel the
        // request before it reaches the control server.
        let current_auth = auth_rx.borrow_and_update().clone();
        if current_auth
            .as_ref()
            .is_none_or(|current| !auth.same_identity_as(current))
            || expected_registration_seq
                .is_some_and(|expected| auth.registration_seq != Some(expected))
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
            punch_at_server_ms,
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

        let mut attempt = 0;
        let result = loop {
            attempt += 1;
            let remaining = deadline.saturating_duration_since(Instant::now());
            // A stalled first request leaves time for prepaid retries only
            // when the original window can also fit their backoff. Very short
            // windows keep one full attempt instead of manufacturing retries
            // whose only remaining time would be spent waiting to send.
            let retries_left = u32::from(prepaid_attempts.saturating_sub(attempt));
            let attempt_budget = remaining
                .checked_sub(Duration::from_millis(25) * retries_left)
                .filter(|usable| !usable.is_zero())
                .map_or(remaining, |usable| usable / (retries_left + 1));
            // A barrier's HTTP slice starts here, after both queue waits and
            // identity admission. Queue pressure never triggers another paid
            // attempt, and this slice cannot extend the original phase.
            let attempt_budget =
                attempt_timeout.map_or(attempt_budget, |limit| attempt_budget.min(limit));
            let attempt_deadline = (Instant::now() + attempt_budget).min(deadline);
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
                    let request_auth = auth_rx.clone();
                    let request = async {
                        if attempt > 1 {
                            time::sleep(Duration::from_millis(25)).await;
                        }
                        // A candidate refresh may have waited behind the
                        // per-peer command lane and auth. Recheck its exact
                        // network, peer session and snapshot at the final
                        // HTTP boundary, including after retry backoff.
                        if let Some(fence) = publication_fence.as_ref() {
                            if !fence.is_current().await {
                                return Err(DaemonError::ControlPlane(
                                    "candidate publication identity expired before delivery".into(),
                                ));
                            }
                        }
                        if Instant::now() >= deadline
                            || request_auth.has_changed().is_err()
                            || request_auth
                                .borrow()
                                .as_ref()
                                .is_none_or(|current| !auth.same_identity_as(current))
                        {
                            return Err(DaemonError::ControlPlane(
                            "candidate offer deadline or control identity expired before delivery".into()));
                        }
                        crate::control::hard_hard_a0_control_stage(
                            session_id.as_deref(),
                            "offer_http_attempt",
                            "request_started",
                        );
                        send_prepared_signal(
                            &current_http,
                            &auth.base_url,
                            &auth.token,
                            auth.registration_seq,
                            &payload,
                        )
                        .await
                    };
                    tokio::pin!(request);
                    loop {
                        let remaining = attempt_deadline.saturating_duration_since(Instant::now());
                        if remaining.is_zero() {
                            break CandidateOfferAttempt::Completed(Err(
                                DaemonError::ControlPlane(
                                    "candidate offer deadline exceeded; delivery status is unknown"
                                        .into(),
                                ),
                            ));
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
                                if auth_rx.borrow().as_ref().is_none_or(|current| {
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
                }
            };
            let retry = matches!(&result, CandidateOfferAttempt::Completed(Err(error))
            if attempt < prepaid_attempts
                && !is_permanent_auth_error(&error.to_string())
                && !is_registration_conflict_error(&error.to_string())
                && Instant::now() < deadline
                && !response_tx.is_closed()
                && fresh_ownership.as_ref().is_none_or(|owner| !owner.is_cancelled())
                && auth_rx.has_changed().is_ok()
                && auth_rx.borrow().as_ref().is_some_and(|current| auth.same_identity_as(current)));
            if !retry {
                break result;
            }
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
            CandidateOfferAttempt::Completed(_)
                if auth_rx.has_changed().is_err()
                    || auth_rx
                        .borrow()
                        .as_ref()
                        .is_none_or(|current| !auth.same_identity_as(current)) =>
            {
                let _ = response_tx.send(PeerOfferSendOutcome::Failed);
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
        if let Some(fence) = publication_fence.as_ref() {
            if !fence.is_current().await {
                // A network handover or peer replacement may have raced the
                // request completion. Its delivery is then ambiguous, but it
                // must not start a new local punch against that old snapshot.
                let _ = response_tx.send(PeerOfferSendOutcome::Cancelled);
                continue;
            }
        }
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
    response_tx: &mut oneshot::Sender<T>,
) -> Option<OwnedSemaphorePermit> {
    if response_tx.is_closed() {
        return None;
    }
    let permit = tokio::select! {
        biased;
        _ = response_tx.closed() => return None,
        permit = permits.clone().acquire_owned() => permit.ok()?,
    };
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
    let Some(_permit) = acquire_critical_permit_or_skip(&permits, &mut response_tx).await else {
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
    let Some(_permit) = acquire_critical_permit_or_skip(&permits, &mut response_tx).await else {
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
    publication_fence: Option<crate::EndpointPublicationFence>,
    mut response_tx: oneshot::Sender<Result<()>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    permits: Arc<Semaphore>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
    health: Option<Arc<crate::tasks::HealthState>>,
    advertised_snapshot: Arc<std::sync::Mutex<AdvertisedEndpointSnapshot>>,
    lifecycle_tx: mpsc::UnboundedSender<ControlCommand>,
) {
    if !endpoint_publication_is_current(publication_fence.as_ref()) {
        let _ = response_tx.send(Err(endpoint_publication_superseded()));
        return;
    }
    let Some(_permit) = acquire_critical_permit_or_skip(&permits, &mut response_tx).await else {
        return;
    };
    let deadline = Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE;
    let Some(auth) =
        wait_for_critical_control_auth(auth_rx.clone(), &mut response_tx, deadline).await
    else {
        return;
    };
    // The critical lane may have waited behind another endpoint publication.
    // Do not issue a request if ordinary registration has already replaced
    // this identity; the server header fence remains the final authority for
    // the race after this local check.
    if auth_rx
        .borrow()
        .as_ref()
        .is_none_or(|current| !auth.same_identity_as(current))
    {
        let _ = response_tx.send(Err(DaemonError::ControlPlane(
            "critical endpoint publish aborted: control identity was replaced by re-registration"
                .into(),
        )));
        return;
    }
    let relay_rtt_ms = current_relay_rtt_ms(relay_selection.as_ref()).await;
    let published_nat_type = control_label_with_registration_seq(&nat_type, auth.registration_seq);
    if !endpoint_publication_is_current(publication_fence.as_ref()) {
        let _ = response_tx.send(Err(endpoint_publication_superseded()));
        return;
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    let mut result = if remaining.is_zero() {
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
                        &published_nat_type,
                        relay_rtt_ms,
                        auth.registration_seq,
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
    // An in-flight HTTP request can already have a remote effect; a retired
    // owner must nevertheless never replace the current local advertisement.
    if !endpoint_publication_is_current(publication_fence.as_ref()) {
        let _ = response_tx.send(Err(endpoint_publication_superseded()));
        return;
    }
    // A successful response must still belong to the registration that issued
    // it.  This prevents an old critical task from updating its local
    // snapshot or reporting a healthy lease after a concurrent re-register.
    if result.is_ok()
        && auth_rx
            .borrow()
            .as_ref()
            .is_none_or(|current| !auth.same_identity_as(current))
    {
        result = Err(DaemonError::ControlPlane(
            "critical endpoint publish completed after control identity was replaced".into(),
        ));
    }
    match &result {
        Ok(()) => {
            {
                let mut advertised = advertised_snapshot.lock().unwrap();
                if !endpoint_publication_is_current(publication_fence.as_ref()) {
                    let _ = response_tx.send(Err(endpoint_publication_superseded()));
                    return;
                }
                advertised.update(endpoint.clone(), published_nat_type.clone());
            }
            if let Some(health) = health.as_ref() {
                health.mark_device_lease_success().await;
            }
            debug!(
                "Updated endpoint for {} through handshake control lane: {} ({})",
                auth.self_node_id, endpoint, published_nat_type
            );
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        Err(error) => {
            if is_registration_conflict_error(&error.to_string()) {
                let _ = lifecycle_tx.send(ControlCommand::LifecycleConflict {
                    message: error.to_string(),
                });
            }
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
                        auth.registration_seq,
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
                    && !is_permanent_auth_error(&error.to_string())
                    // A 409 session fence is conclusive. Retrying the exact
                    // same stale proof only burns the handshake window while
                    // the ordinary lifecycle is already shutting this daemon
                    // down on its next control poll.
                    && !is_registration_conflict_error(&error.to_string()) =>
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
