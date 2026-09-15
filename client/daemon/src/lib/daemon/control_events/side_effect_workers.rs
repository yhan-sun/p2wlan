/// Responder offers have their own cooperative lane.  Candidate refresh,
/// peer-reflexive HTTP and event-triggered initiator preparation may occupy
/// the bounded general slow-work set, but a WireGuard answer must still be
/// admitted and processed immediately.  One owner per peer keeps this lane
/// bounded by the number of registered peers and coalesces retransmissions.
const RESPONDER_WORK_RETRY_LIMIT: u8 = 3;
const RESPONDER_WORK_RETRY_BACKOFF: [Duration; 3] = [
    Duration::from_millis(50),
    Duration::from_millis(100),
    Duration::from_millis(250),
];

fn responder_offer_error_is_retryable(error: &DaemonError) -> bool {
    // Control-plane command completion can be lost after the signal was
    // dequeued.  The responder transaction is idempotent through its exact
    // handshake cache, so a bounded retry is safe.  Parsing, identity and
    // role errors are terminal and are never retried.
    matches!(error, DaemonError::ControlPlane(_))
        || matches!(
            error,
            DaemonError::Network(reason)
                if reason == REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT
                    || reason == REASON_RESPONDER_SESSION_STAGE_TIMEOUT
                    || reason == REASON_RESPONDER_PROBE_BINDING_CONTENDED
                    || reason == REASON_RESPONDER_COMMIT_CONTENDED
        )
}

fn responder_offer_error_reason_code(error: &DaemonError) -> &'static str {
    match error {
        DaemonError::ControlPlane(_) => "control_plane_error",
        DaemonError::Network(reason) if reason == REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT => {
            REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT
        }
        DaemonError::Network(reason) if reason == REASON_RESPONDER_SESSION_STAGE_TIMEOUT => {
            REASON_RESPONDER_SESSION_STAGE_TIMEOUT
        }
        DaemonError::Network(reason) if reason == REASON_RESPONDER_PROBE_BINDING_CONTENDED => {
            REASON_RESPONDER_PROBE_BINDING_CONTENDED
        }
        DaemonError::Network(reason) if reason == REASON_RESPONDER_COMMIT_CONTENDED => {
            REASON_RESPONDER_COMMIT_CONTENDED
        }
        _ => "responder_offer_error",
    }
}

fn responder_offer_retry_delay(attempt: u8) -> Duration {
    RESPONDER_WORK_RETRY_BACKOFF
        .get(attempt.saturating_sub(1) as usize)
        .copied()
        .unwrap_or_else(|| RESPONDER_WORK_RETRY_BACKOFF[RESPONDER_WORK_RETRY_BACKOFF.len() - 1])
}

/// A control signal can arrive a few seconds before the corresponding
/// PeerJoined event (REST polling and signal delivery are independent).  Keep
/// one bounded responder worker alive for this interval so the authenticated
/// offer is replayed after the peer identity is installed instead of being
/// rejected as unknown.  The worker is cancelled by the normal peer-lifecycle
/// cleanup path, and repeated offers replace its single queued value.
const UNKNOWN_PEER_OFFER_WAIT: Duration = Duration::from_secs(8);
const UNKNOWN_PEER_OFFER_POLL: Duration = Duration::from_millis(25);

impl Daemon {
    /// Consume the newest queued peer-reflexive observation under one owner.
    /// The global control slow-work set caps the number of these workers;
    /// this per-peer owner prevents endpoint churn from consuming that cap.
    async fn run_peer_reflexive_worker(
        &self,
        mut work: PendingPeerReflexive,
        mut reservation: PeerReflexiveWorkReservation,
    ) {
        loop {
            let peer_id = work.from_node_id.clone();
            if let Some(receipt) = work.delivery_receipt.as_ref() {
                receipt.record_phase("worker_started", "peer_reflexive");
            }
            if *reservation.cancellation.borrow() {
                work.complete_delivery(control::SignalApplyOutcome::Retry);
                return;
            }
            let Some(peer_session_generation) = work.peer_session_generation else {
                work.complete_delivery(control::SignalApplyOutcome::Retry);
                return;
            };
            if !self
                .peers
                .peer_session_is_current_sync(&peer_id, peer_session_generation)
            {
                work.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
                return;
            }
            self.handle_peer_reflexive_work(&work, &mut reservation.cancellation)
                .await;
            work.complete_delivery(if *reservation.cancellation.borrow() {
                control::SignalApplyOutcome::Retry
            } else if self
                .peers
                .peer_session_is_current_sync(&peer_id, peer_session_generation)
            {
                control::SignalApplyOutcome::Applied
            } else {
                control::SignalApplyOutcome::TerminalRejected
            });
            let Some(next) = self
                .pending_handshakes
                .lock()
                .finish_peer_reflexive_work(&peer_id, reservation.owner)
            else {
                return;
            };
            work = next;
        }
    }

    /// Handle one admitted responder offer with a bounded, idempotent retry.
    ///
    /// The exact durable receipt remains attached to this worker until the
    /// responder transaction commits or returns a typed retry/terminal result.
    /// `handle_event_peer_offer` uses the exact responder cache keyed by the
    /// WireGuard token, therefore retrying the same plaintext offer cannot
    /// create a second response or a second session. No encrypted data packet
    /// is retained here; this is control-plane handshake material only.
    async fn handle_admitted_responder_offer(
        &self,
        offer: &PendingPeerOffer,
        owner: u64,
        cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        let peer_id = offer.from_node_id.clone();
        if let Some(receipt) = offer.delivery_receipt.as_ref() {
            receipt.record_phase("worker_started", "responder_offer");
        }
        let lifecycle_is_current = || {
            offer
                .peer_session_generation
                .is_some_and(|expected| self.peers.peer_session_is_current_sync(&peer_id, expected))
                && self.peers.current_network_generation_sync() == offer.network_generation
        };
        if !lifecycle_is_current() {
            offer.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
            return;
        }
        for retry_attempt in 0..=RESPONDER_WORK_RETRY_LIMIT {
            if *cancellation.borrow() {
                offer.complete_delivery(control::SignalApplyOutcome::Retry);
                debug!(
                    "Peer offer responder worker cancelled before handling: peer={} owner={}",
                    peer_id, owner
                );
                self.peers
                    .record_direct_event(
                        &peer_id,
                        "peer_offer_responder_worker_cancelled",
                        None,
                        None,
                        None,
                        format!("owner={} cancelled before handler", owner),
                    )
                    .await;
                self.timeline.emit(
                    "peer_offer_responder_worker_cancelled",
                    None,
                    Some("generation_cancelled"),
                    Some(format!(
                        "peer={} owner={} before_handler=true",
                        peer_id, owner
                    )),
                );
                return;
            }
            self.peers
                .record_direct_event(
                    &peer_id,
                    "peer_offer_responder_handler_entered",
                    None,
                    None,
                    None,
                    format!(
                        "owner={} retry_attempt={} generation={} session_fp={}",
                        owner,
                        retry_attempt,
                        offer.network_generation,
                        handshake_token_fingerprint(offer.session_id.as_deref())
                    ),
                )
                .await;
            debug!(
                "Peer offer responder handler entered: peer={} owner={} retry_attempt={}",
                peer_id, owner, retry_attempt
            );
            self.timeline.emit(
                "peer_offer_responder_handler_entered",
                None,
                None,
                Some(format!(
                    "peer={} owner={} retry_attempt={} generation={} session_fp={}",
                    peer_id,
                    owner,
                    retry_attempt,
                    offer.network_generation,
                    handshake_token_fingerprint(offer.session_id.as_deref())
                )),
            );
            match self
                .handle_event_peer_offer(offer.clone(), owner, cancellation)
                .await
            {
                Ok(()) if *cancellation.borrow() => {
                    offer.complete_delivery(control::SignalApplyOutcome::Retry);
                    self.timeline.emit(
                        "peer_offer_responder_worker_cancelled",
                        None,
                        Some("generation_cancelled"),
                        Some(format!(
                            "peer={} owner={} after_handler=true",
                            peer_id, owner
                        )),
                    );
                    return;
                }
                Ok(()) => {
                    offer.complete_delivery(if lifecycle_is_current() {
                        control::SignalApplyOutcome::Applied
                    } else {
                        control::SignalApplyOutcome::TerminalRejected
                    });
                    debug!(
                        "Peer offer responder handler completed: peer={} owner={}",
                        peer_id, owner
                    );
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "peer_offer_responder_handler_completed",
                            None,
                            None,
                            None,
                            format!(
                                "owner={} retry_attempt={} generation={} session_fp={}",
                                owner,
                                retry_attempt,
                                offer.network_generation,
                                handshake_token_fingerprint(offer.session_id.as_deref())
                            ),
                        )
                        .await;
                    self.timeline.emit(
                        "peer_offer_responder_handler_completed",
                        None,
                        None,
                        Some(format!(
                            "peer={} owner={} retry_attempt={} generation={} session_fp={}",
                            peer_id,
                            owner,
                            retry_attempt,
                            offer.network_generation,
                            handshake_token_fingerprint(offer.session_id.as_deref())
                        )),
                    );
                    return;
                }
                Err(err)
                    if responder_offer_error_is_retryable(&err)
                        && retry_attempt < RESPONDER_WORK_RETRY_LIMIT =>
                {
                    let next_attempt = retry_attempt.saturating_add(1);
                    let delay = responder_offer_retry_delay(next_attempt);
                    let reason_code = responder_offer_error_reason_code(&err);
                    warn!(
                        "Peer offer responder failed transiently: peer={} owner={} retry_attempt={} delay_ms={} reason_code={} error={}",
                        peer_id,
                        owner,
                        next_attempt,
                        delay.as_millis(),
                        reason_code,
                        err
                    );
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "peer_offer_responder_retry",
                            None,
                            None,
                            None,
                            format!(
                                "owner={} retry_attempt={} delay_ms={} reason_code={reason_code}",
                                owner,
                                next_attempt,
                                delay.as_millis()
                            ),
                        )
                        .await;
                    self.timeline.emit(
                        "peer_offer_responder_retry",
                        None,
                        Some(reason_code),
                        Some(format!(
                            "peer={} owner={} retry_attempt={} delay_ms={}",
                            peer_id,
                            owner,
                            next_attempt,
                            delay.as_millis()
                        )),
                    );
                    tokio::select! {
                        _ = sleep(delay) => {}
                        changed = cancellation.changed() => {
                            if changed.is_err() || *cancellation.borrow() {
                                offer.complete_delivery(control::SignalApplyOutcome::Retry);
                                return;
                            }
                        }
                    }
                }
                Err(err) => {
                    offer.complete_delivery(if responder_offer_error_is_retryable(&err) {
                        control::SignalApplyOutcome::Retry
                    } else {
                        control::SignalApplyOutcome::TerminalRejected
                    });
                    warn!(
                        "Failed to handle peer offer from {} owner={} reason_code=responder_terminal_error retry_attempt={} error={}",
                        peer_id, owner, retry_attempt, err
                    );
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "peer_offer_responder_failed",
                            None,
                            None,
                            None,
                            format!(
                                "owner={} reason_code=responder_terminal_error retry_attempt={}",
                                owner, retry_attempt
                            ),
                        )
                        .await;
                    self.timeline.emit(
                        "peer_offer_responder_failed",
                        None,
                        Some("responder_terminal_error"),
                        Some(format!(
                            "peer={} owner={} retry_attempt={retry_attempt}",
                            peer_id, owner
                        )),
                    );
                    return;
                }
            }
        }
        offer.complete_delivery(control::SignalApplyOutcome::Retry);
    }

    /// Consume only the latency-critical responder half of an offer.  Remote
    /// incarnation admission is non-queuing; bounded contention completes the
    /// durable receipt as Retry so ordered server delivery can replay it.
    async fn run_responder_offer_worker(
        &self,
        mut offer: PendingPeerOffer,
        mut reservation: ResponderWorkReservation,
    ) {
        loop {
            let peer_id = offer.from_node_id.clone();
            if *reservation.cancellation.borrow() {
                offer.complete_delivery(control::SignalApplyOutcome::Retry);
                return;
            }
            if !self
                .wait_for_peer_offer_identity(
                    &offer.from_node_id,
                    offer.sender_public_key.as_deref(),
                    &mut reservation.cancellation,
                )
                .await
            {
                let peers_snapshot = self.control.peers().await;
                let peer_entry = peers_snapshot.get(&peer_id);
                let terminal = match peer_entry {
                    None => true,
                    Some(peer)
                        if offer.sender_public_key.as_deref().is_some_and(|k| {
                            !k.trim().is_empty() && k.trim() != peer.public_key.trim()
                        }) =>
                    {
                        true
                    }
                    _ => false,
                };
                let outcome = if terminal {
                    control::SignalApplyOutcome::TerminalRejected
                } else {
                    control::SignalApplyOutcome::Retry
                };
                // A newer offer may have replaced the timed-out value while
                // the peer was still unknown.  Consume it under the same
                // owner; otherwise release the owner so a later signal can
                // create a fresh bounded waiter.
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .finish_responder_work(&peer_id, reservation.owner)
                else {
                    offer.complete_delivery(outcome);
                    return;
                };
                offer.complete_delivery(outcome);
                offer = next;
                continue;
            }
            // Several offers may have arrived while this worker waited for
            // PeerJoined. Consume the newest one before any candidate or
            // WireGuard state is touched; the same owner remains active so a
            // later arrival races only with the post-work handoff below.
            if let Some(newest) = self
                .pending_handshakes
                .lock()
                .take_queued_responder_work(&peer_id, reservation.owner)
            {
                offer.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
                offer = newest;
                continue;
            }
            let mut reset_outcome = RemoteIncarnationResetOutcome::Unchanged;
            for reset_attempt in 0..=RESPONDER_WORK_RETRY_LIMIT {
                reset_outcome = self
                    .reset_peer_for_remote_incarnation_if_needed_for_identity(
                        &offer.from_node_id,
                        offer.candidate_generation,
                        offer.sender_public_key.as_deref(),
                        RemoteIncarnationResetWork::PreserveResponder,
                    )
                    .await;
                if !reset_outcome.retryable() {
                    break;
                }
                if reset_attempt == RESPONDER_WORK_RETRY_LIMIT {
                    break;
                }
                let delay = responder_offer_retry_delay(reset_attempt.saturating_add(1));
                self.timeline.emit(
                    "peer_offer_incarnation_retry",
                    None,
                    Some(reset_outcome.reason_code()),
                    Some(format!(
                        "peer={} owner={} retry_attempt={} delay_ms={}",
                        peer_id,
                        reservation.owner,
                        reset_attempt.saturating_add(1),
                        delay.as_millis()
                    )),
                );
                tokio::select! {
                    _ = sleep(delay) => {}
                    changed = reservation.cancellation.changed() => {
                        let _ = changed;
                        offer.complete_delivery(control::SignalApplyOutcome::Retry);
                        return;
                    }
                }
            }
            if reset_outcome == RemoteIncarnationResetOutcome::RejectedIdentity {
                offer.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .finish_responder_work(&peer_id, reservation.owner)
                else {
                    return;
                };
                offer = next;
                continue;
            }
            if reset_outcome == RemoteIncarnationResetOutcome::RejectedLifecycle {
                // The incarnation high-water mark has already advanced, but
                // the claimed lifecycle was removed or superseded before its
                // cleanup commit. This exact offer is stale; redelivery must
                // not reinterpret a subsequent NoReset as a successful reset.
                offer.complete_delivery(control::SignalApplyOutcome::TerminalRejected);
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .finish_responder_work(&peer_id, reservation.owner)
                else {
                    return;
                };
                offer = next;
                continue;
            }
            if reset_outcome.retryable() {
                offer.complete_delivery(control::SignalApplyOutcome::Retry);
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .finish_responder_work(&peer_id, reservation.owner)
                else {
                    return;
                };
                offer = next;
                continue;
            }
            let Some(peer_session_generation) =
                self.peers.peer_session_generation_sync(&offer.from_node_id)
            else {
                offer.complete_delivery(control::SignalApplyOutcome::Retry);
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .finish_responder_work(&peer_id, reservation.owner)
                else {
                    return;
                };
                offer = next;
                continue;
            };
            offer.peer_session_generation = Some(peer_session_generation);
            self.handle_admitted_responder_offer(
                &offer,
                reservation.owner,
                &mut reservation.cancellation,
            )
            .await;
            if *reservation.cancellation.borrow() {
                return;
            }

            let Some(next) = self
                .pending_handshakes
                .lock()
                .finish_responder_work(&peer_id, reservation.owner)
            else {
                return;
            };
            offer = next;
        }
    }

    /// Apply candidate/fresh-prediction work in its own bounded per-peer
    /// owner.  Durable delivery was committed at enqueue, so contention is
    /// repaired here without retaining a server receipt or blocking later
    /// signals from the same sender.
    async fn run_candidate_offer_worker(
        &self,
        mut offer: PendingPeerOffer,
        mut reservation: CandidateOfferWorkReservation,
    ) {
        'work: loop {
            let peer_id = offer.from_node_id.clone();
            if *reservation.cancellation.borrow()
                || !self
                    .pending_handshakes
                    .lock()
                    .candidate_offer_work_is_current(&peer_id, reservation.owner)
            {
                return;
            }
            if !self
                .wait_for_peer_offer_identity(
                    &peer_id,
                    offer.sender_public_key.as_deref(),
                    &mut reservation.cancellation,
                )
                .await
            {
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .finish_candidate_offer_work(&peer_id, reservation.owner)
                else {
                    return;
                };
                offer = next;
                continue;
            }
            if let Some(newest) = self
                .pending_handshakes
                .lock()
                .take_queued_candidate_offer_work(&peer_id, reservation.owner)
            {
                offer = newest;
                continue;
            }
            if self.peers.current_network_generation_sync() != offer.network_generation {
                let Some(next) = self
                    .pending_handshakes
                    .lock()
                    .finish_candidate_offer_work(&peer_id, reservation.owner)
                else {
                    return;
                };
                offer = next;
                continue;
            }

            let mut retry_attempt = 0u8;
            let remote_incarnation_reset = loop {
                let outcome = self
                    .reset_peer_for_remote_incarnation_if_needed_for_identity(
                        &peer_id,
                        offer.candidate_generation,
                        offer.sender_public_key.as_deref(),
                        RemoteIncarnationResetWork::PreserveResponder,
                    )
                    .await;
                match outcome {
                    RemoteIncarnationResetOutcome::Changed => break true,
                    RemoteIncarnationResetOutcome::Unchanged => break false,
                    RemoteIncarnationResetOutcome::RejectedIdentity
                    | RemoteIncarnationResetOutcome::RejectedLifecycle => {
                        let Some(next) = self
                            .pending_handshakes
                            .lock()
                            .finish_candidate_offer_work(&peer_id, reservation.owner)
                        else {
                            return;
                        };
                        offer = next;
                        continue 'work;
                    }
                    RemoteIncarnationResetOutcome::PendingCleanup
                    | RemoteIncarnationResetOutcome::ContendedEpoch
                    | RemoteIncarnationResetOutcome::ContendedConnections => {
                        if let Some(newest) = self
                            .pending_handshakes
                            .lock()
                            .take_queued_candidate_offer_work(&peer_id, reservation.owner)
                        {
                            offer = newest;
                            continue 'work;
                        }
                        retry_attempt = retry_attempt.saturating_add(1);
                        let delay = responder_offer_retry_delay(retry_attempt);
                        self.timeline.emit(
                            "peer_offer_candidate_retry",
                            None,
                            Some(outcome.reason_code()),
                            Some(format!(
                                "peer={} owner={} retry_attempt={} delay_ms={}",
                                peer_id,
                                reservation.owner,
                                retry_attempt,
                                delay.as_millis()
                            )),
                        );
                        tokio::select! {
                            _ = sleep(delay) => {}
                            changed = reservation.cancellation.changed() => {
                                let _ = changed;
                                return;
                            }
                        }
                    }
                }
            };

            offer.peer_session_generation = self.peers.peer_session_generation_sync(&peer_id);
            let ingress = self
                .offer_ingress_verdict(
                    &peer_id,
                    &offer.candidates,
                    &offer.candidate_sources,
                    offer.candidates_expires_at_ms,
                    offer.sender_public_key.as_deref(),
                )
                .await;
            let (_fresh_verdict, candidate_apply_result, fresh_punch) = if ingress
                == OfferIngressVerdict::Apply
            {
                if matches!(
                    fresh_prediction_from_sources(&offer.candidate_sources),
                    Ok(None)
                ) {
                    // Ordinary candidate revisions are the common cold-start
                    // path. Never hold the epoch while queueing a connection
                    // writer: the bounded candidate owner already retains the
                    // exact payload and can retry without blocking RelayReady,
                    // confirmation, status, or the responder receipt.
                    let mut apply_retry_attempt = 0u8;
                    let apply_result = loop {
                        match self
                                .peers
                                .try_add_candidates_with_metadata_for_identity(
                                    &peer_id,
                                    &offer.candidates,
                                    &offer.candidate_sources,
                                    offer.candidate_generation,
                                    offer.candidates_expires_at_ms,
                                    offer.sender_public_key.as_deref(),
                                )
                                .await
                            {
                                crate::peer::CandidateSetTryApplyOutcome::Completed(result) => {
                                    break result;
                                }
                                outcome @ (crate::peer::CandidateSetTryApplyOutcome::ContendedEpoch
                                | crate::peer::CandidateSetTryApplyOutcome::ContendedConnections) => {
                                    // `offer_ingress_verdict` has already committed
                                    // this payload's Apply admission. Do not replace the
                                    // active value here: a same-fingerprint successor
                                    // would be classified as Duplicate even though this
                                    // candidate mutation never committed. Retain the exact
                                    // payload across bounded contention; the one
                                    // newest-wins successor remains queued and is consumed
                                    // by `finish_candidate_offer_work` after this mutation.
                                    apply_retry_attempt = apply_retry_attempt.saturating_add(1);
                                    let delay =
                                        responder_offer_retry_delay(apply_retry_attempt);
                                    let reason_code = match outcome {
                                        crate::peer::CandidateSetTryApplyOutcome::ContendedEpoch => {
                                            "candidate_epoch_busy"
                                        }
                                        crate::peer::CandidateSetTryApplyOutcome::ContendedConnections => {
                                            "candidate_connections_busy"
                                        }
                                        crate::peer::CandidateSetTryApplyOutcome::Completed(_) => {
                                            unreachable!()
                                        }
                                    };
                                    self.timeline.emit(
                                        "peer_offer_candidate_retry",
                                        None,
                                        Some(reason_code),
                                        Some(format!(
                                            "peer={} owner={} retry_attempt={} delay_ms={}",
                                            peer_id,
                                            reservation.owner,
                                            apply_retry_attempt,
                                            delay.as_millis()
                                        )),
                                    );
                                    tokio::select! {
                                        _ = sleep(delay) => {}
                                        changed = reservation.cancellation.changed() => {
                                            let _ = changed;
                                            return;
                                        }
                                    }
                                }
                            }
                    };
                    (
                        FreshSignalVerdict::None,
                        apply_result,
                        FreshPunchDecision::None,
                    )
                } else {
                    let mut fresh_retry_attempt = 0u8;
                    loop {
                        let result = self
                            .fresh_prediction_transaction(
                                &peer_id,
                                &offer.candidates,
                                &offer.candidate_sources,
                                offer.candidate_generation,
                                offer.candidates_expires_at_ms,
                                offer.sender_public_key.as_deref(),
                                true,
                            )
                            .await;
                        if result.0 != FreshSignalVerdict::Contended {
                            break result;
                        }
                        if let Some(newest) = self
                            .pending_handshakes
                            .lock()
                            .take_queued_candidate_offer_work(&peer_id, reservation.owner)
                        {
                            offer = newest;
                            continue 'work;
                        }
                        fresh_retry_attempt = fresh_retry_attempt.saturating_add(1);
                        let delay = responder_offer_retry_delay(fresh_retry_attempt);
                        self.timeline.emit(
                            "peer_offer_fresh_candidate_retry",
                            None,
                            Some("fresh_transaction_contended"),
                            Some(format!(
                                "peer={} owner={} retry_attempt={} delay_ms={}",
                                peer_id,
                                reservation.owner,
                                fresh_retry_attempt,
                                delay.as_millis()
                            )),
                        );
                        tokio::select! {
                            _ = sleep(delay) => {}
                            changed = reservation.cancellation.changed() => {
                                let _ = changed;
                                return;
                            }
                        }
                    }
                }
            } else {
                self.peers
                        .record_direct_event(
                            &peer_id,
                            "peer_offer_ingress_suppressed",
                            None,
                            Some(offer.candidates.len()),
                            None,
                            format!(
                                "offer suppressed by ingress verdict={ingress:?}; candidate apply, fresh prediction and punch skipped"
                            ),
                        )
                        .await;
                (
                    FreshSignalVerdict::None,
                    CandidateSetApplyResult::IgnoredStale,
                    FreshPunchDecision::None,
                )
            };
            if !offer.handshake_init.is_empty() {
                self.peers
                    .recovery_reopen_on_evidence(&peer_id, "authenticated_peer_offer")
                    .await;
            }
            #[cfg(test)]
            let postprocess_test_gate = self.pause_candidate_postprocess_for_test(&peer_id).await;
            self.apply_deferred_peer_offer_punch_for_candidate_work(
                &offer,
                candidate_apply_result,
                fresh_punch,
                &mut reservation,
            )
            .await;
            #[cfg(test)]
            if let Some(gate) = postprocess_test_gate {
                gate.completed.notify_one();
            }
            if remote_incarnation_reset && !*reservation.cancellation.borrow() {
                self.publish_current_candidates_to_peer(
                    &peer_id,
                    "remote incarnation candidate replay",
                )
                .await;
                if let Some(peer_info) = self.control.peers().await.get(&peer_id).cloned() {
                    if peer_info.online && self.should_start_initiator_handshake(&peer_info) {
                        if let Some(reservation) = self
                            .reserve_event_initiator_handshake(&peer_id)
                            .into_reservation()
                        {
                            self.run_event_initiator_handshake(peer_info, reservation)
                                .await;
                        }
                    }
                }
            }

            let Some(next) = self
                .pending_handshakes
                .lock()
                .finish_candidate_offer_work(&peer_id, reservation.owner)
            else {
                return;
            };
            offer = next;
        }
    }
}
