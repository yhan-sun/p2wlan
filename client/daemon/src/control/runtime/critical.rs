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
async fn run_critical_control_loop(
    mut answer_rx: mpsc::Receiver<CriticalAnswerCommand>,
    mut offer_rx: mpsc::Receiver<CriticalOfferCommand>,
    mut ctrl_rx: mpsc::Receiver<CriticalControlCommand>,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
) {
    let http = Arc::new(reqwest::Client::new());
    let answer_permits = Arc::new(Semaphore::new(CRITICAL_ANSWER_MAX_INFLIGHT));
    let offer_permits = Arc::new(Semaphore::new(CRITICAL_OFFER_MAX_INFLIGHT));
    let ctrl_permits = Arc::new(Semaphore::new(CRITICAL_CTRL_MAX_INFLIGHT));
    let mut answers = JoinSet::new();
    let mut offers = JoinSet::new();
    let mut ctrls = JoinSet::new();

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
                        ));
                    }
                    CriticalControlCommand::Shutdown => {
                        answers.abort_all();
                        offers.abort_all();
                        ctrls.abort_all();
                        return;
                    }
                }
            }
            else => break,
        }
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
    http: Arc<reqwest::Client>,
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
    http: Arc<reqwest::Client>,
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
    http: Arc<reqwest::Client>,
    auth_rx: watch::Receiver<Option<CriticalControlAuth>>,
    endpoint: String,
    nat_type: String,
    mut response_tx: oneshot::Sender<Result<()>>,
    event_tx: mpsc::UnboundedSender<ControlEvent>,
    permits: Arc<Semaphore>,
    relay_selection: Option<Arc<RwLock<RelaySelectionDiagnostics>>>,
) {
    let Some(_permit) = acquire_critical_permit_or_skip(&permits, &response_tx).await else {
        return;
    };
    let deadline = Instant::now() + CRITICAL_SIGNAL_OVERALL_DEADLINE;
    let Some(auth) = wait_for_critical_control_auth(
        auth_rx.clone(),
        &mut response_tx,
        deadline,
    )
    .await
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
        tokio::select! {
            result = timeout(remaining, update_endpoint(
                &http,
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
    };
    match &result {
        Ok(()) => {
            debug!(
                "Updated endpoint for {} through handshake control lane: {} ({})",
                auth.self_node_id, endpoint, nat_type
            );
            let _ = event_tx.send(ControlEvent::ControlHealthy);
        }
        Err(error) => {
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
    http: &reqwest::Client,
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
        if auth_rx.borrow().as_ref().is_some_and(|current| {
            !auth.same_identity_as(current)
        }) {
            return Some(Err(DaemonError::ControlPlane(format!(
                "critical {signal_type} to {to_node_id} aborted: control identity was replaced by re-registration"
            ))));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let result = tokio::select! {
            result = timeout(remaining, send_prepared_signal(
                http,
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
