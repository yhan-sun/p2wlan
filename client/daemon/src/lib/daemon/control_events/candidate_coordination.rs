fn candidate_signal_starts_synchronized_punch(
    handshake_payload: &[u8],
    apply_result: CandidateSetApplyResult,
) -> bool {
    !handshake_payload.is_empty() || apply_result == CandidateSetApplyResult::Applied
}

/// Verdict for a signal's fresh-mapping prediction payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreshSignalVerdict {
    /// No fresh prediction label: an ordinary signal.
    None,
    /// The label is newer than the peer's high-water: candidates may be
    /// applied and, once the apply really succeeds, the identity is committed
    /// and a priority-2 punch session may claim.
    Accepted(crate::FreshPredictionId),
    /// The label equals the high-water AND the payload matches the snapshot
    /// the identity was committed with: an idempotent retry.  Candidates are
    /// not re-applied; the fresh punch starts from the COMMITTED snapshot.
    AlreadyRecorded(crate::FreshPredictionId),
    /// The label equals the high-water but the payload differs from the
    /// committed snapshot (or no snapshot exists): a retry must never apply
    /// different candidates under the same identity.
    PayloadMismatch(crate::FreshPredictionId),
    /// The label is older than the high-water: a superseded prediction sent
    /// late.  Its candidates must not be applied and no punch may start from
    /// them.
    Stale,
    /// The payload carried conflicting fresh labels: rejected
    /// deterministically like a stale signal.
    Inconsistent,
    /// The bounded candidate owner must retain this exact signal and retry
    /// after a resource-contended non-queuing transaction attempt.
    Contended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HardHardOfferHandling {
    NotHardHard,
    /// The authenticated fresh window remains usable, but the local
    /// Hard↔Hard optimization did not acquire a worker.  Continue through the
    /// ordinary fresh-punch path instead of swallowing the offer.
    Fallback,
    Rejected,
    Started,
}

impl Daemon {
    /// Repair the local peer-manager roster when a signal races a lifecycle
    /// event.  The control client keeps an authoritative snapshot separately
    /// from the event consumer; a PeerLeft/PeerJoined boundary can therefore
    /// leave the consumer temporarily without a connection even though the
    /// current roster still says the peer is online.  A deferred offer is
    /// already authenticated by the control channel, so re-installing that
    /// current online record is safe and lets the newest candidate set make
    /// progress without waiting for another roster event.
    async fn restore_peer_offer_identity_from_control_roster(&self, peer_id: &str) -> bool {
        let Some(peer_info) = self
            .control
            .peers()
            .await
            .get(peer_id)
            .filter(|peer| peer.online)
            .cloned()
        else {
            return false;
        };

        self.peers.add_peer(&peer_info).await;
        let restored = self.peers.peer_exists_sync(peer_id);
        if restored {
            self.timeline.emit(
                "peer_offer_identity_restored",
                None,
                Some("control_roster_repair"),
                Some(format!(
                    "peer={peer_id} restored from current online control roster"
                )),
            );
        }
        restored
    }

    async fn wait_for_peer_offer_identity(
        &self,
        peer_id: &str,
        expected_sender_public_key: Option<&str>,
        cancellation: &mut watch::Receiver<bool>,
    ) -> bool {
        let deadline = Instant::now() + UNKNOWN_PEER_OFFER_WAIT;
        loop {
            if self
                .peers
                .signal_sender_identity_matches_peer_sync(peer_id, expected_sender_public_key)
                && self.peers.peer_session_generation_sync(peer_id).is_some()
            {
                return true;
            }
            if self
                .restore_peer_offer_identity_from_control_roster(peer_id)
                .await
                && self
                    .peers
                    .signal_sender_identity_matches_peer_sync(peer_id, expected_sender_public_key)
                && self.peers.peer_session_generation_sync(peer_id).is_some()
            {
                return true;
            }
            if *cancellation.borrow() {
                return false;
            }
            let recorded_key = self.peers.peer_identity_recorded_public_key_sync(peer_id);
            if let (Some(recorded), Some(expected)) =
                (recorded_key.as_deref(), expected_sender_public_key)
            {
                if !expected.trim().is_empty()
                    && !recorded.trim().is_empty()
                    && expected.trim() != recorded.trim()
                {
                    debug!(
                        "Rejecting peer offer from {peer_id}: sender key {expected} does not match recorded key {recorded}"
                    );
                    self.timeline.emit(
                        "peer_offer_rejected",
                        None,
                        Some("sender_key_mismatch"),
                        Some(format!("peer={peer_id}")),
                    );
                    return false;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let peers_snapshot = self.control.peers().await;
                let peer_entry = peers_snapshot.get(peer_id);
                let reason = match peer_entry {
                    None => "membership_revoked",
                    Some(peer) if !peer.online => "peer_lifecycle_pending",
                    Some(peer)
                        if expected_sender_public_key.is_some_and(|k| {
                            !k.trim().is_empty() && k.trim() != peer.public_key.trim()
                        }) =>
                    {
                        "sender_key_mismatch"
                    }
                    _ => "peer_lifecycle_pending",
                };
                debug!(
                    "Dropping deferred peer offer from {peer_id}: peer identity was not registered within {:?}, reason={reason}",
                    UNKNOWN_PEER_OFFER_WAIT
                );
                self.timeline.emit(
                    "peer_offer_rejected",
                    None,
                    Some(reason),
                    Some(format!("peer={peer_id}")),
                );
                return false;
            }
            tokio::select! {
                changed = cancellation.changed() => {
                    if changed.is_err() || *cancellation.borrow() {
                        return false;
                    }
                }
                _ = sleep(UNKNOWN_PEER_OFFER_POLL.min(remaining)) => {}
            }
        }
    }

    #[cfg(test)]
    async fn pause_candidate_postprocess_for_test(
        &self,
        peer_id: &str,
    ) -> Option<Arc<CandidatePostprocessTestGate>> {
        let gate = {
            let mut installed = self
                .candidate_postprocess_test_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if installed
                .as_ref()
                .is_some_and(|(installed_peer, _)| installed_peer == peer_id)
            {
                installed.take().map(|(_, gate)| gate)
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.wait().await;
            Some(gate)
        } else {
            None
        }
    }

    async fn start_candidate_offer_punch(
        &self,
        offer: &PendingPeerOffer,
        reservation: &mut CandidateOfferWorkReservation,
        punch_at_ms: Option<u64>,
        fresh_prediction: Option<FreshPredictionId>,
        frozen_targets: Option<Vec<SocketAddr>>,
    ) -> bool {
        let peer_fingerprint = format!(
            "{:016x}",
            crate::transport::wire_fingerprint(offer.from_node_id.as_bytes())
        );
        let mut retry_attempt = 0u8;
        let mut wait_started: Option<std::time::Instant> = None;
        let mut wait_resource: Option<&'static str> = None;
        loop {
            let cancellation_requested = *reservation.cancellation.borrow();
            let reservation_current = self
                .pending_handshakes
                .lock()
                .candidate_offer_work_is_current(&offer.from_node_id, reservation.owner);
            if cancellation_requested || !reservation_current {
                if let (Some(started), Some(resource)) = (wait_started, wait_resource) {
                    self.timeline.emit(
                        "peer_offer_candidate_postprocess_wait_cancelled",
                        None,
                        Some(if cancellation_requested {
                            "reservation_cancelled"
                        } else {
                            "owner_retired"
                        }),
                        Some(format!(
                            "peer_fp={peer_fingerprint} worker=candidate_offer owner={} resource={resource} network_generation={} candidate_generation={} peer_session_generation={:?} wait_ms={}",
                            reservation.owner,
                            offer.network_generation,
                            offer.candidate_generation,
                            offer.peer_session_generation,
                            started.elapsed().as_millis()
                        )),
                    );
                }
                return false;
            }
            if self.peers.current_network_generation_sync() != offer.network_generation
                || self.peers.peer_session_generation_sync(&offer.from_node_id)
                    != offer.peer_session_generation
            {
                if let (Some(started), Some(resource)) = (wait_started, wait_resource) {
                    self.timeline.emit(
                        "peer_offer_candidate_postprocess_wait_cancelled",
                        None,
                        Some("lifecycle_or_network_generation_changed"),
                        Some(format!(
                            "peer_fp={peer_fingerprint} worker=candidate_offer owner={} resource={resource} network_generation={} candidate_generation={} peer_session_generation={:?} wait_ms={}",
                            reservation.owner,
                            offer.network_generation,
                            offer.candidate_generation,
                            offer.peer_session_generation,
                            started.elapsed().as_millis()
                        )),
                    );
                }
                return false;
            }

            let outcome = self
                .start_hole_punch_at_for_candidate_work(
                    &offer.from_node_id,
                    punch_at_ms,
                    fresh_prediction,
                    frozen_targets.clone(),
                )
                .await;
            let resource = match outcome {
                HolePunchStartOutcome::ContendedEpoch => Some("network_epoch_gate"),
                HolePunchStartOutcome::ContendedConnections => Some("connections_write"),
                _ => None,
            };
            if let Some(resource) = resource {
                if wait_started.is_none() {
                    wait_started = Some(std::time::Instant::now());
                    wait_resource = Some(resource);
                    self.timeline.emit(
                        "peer_offer_candidate_postprocess_wait_started",
                        None,
                        Some(resource),
                        Some(format!(
                            "peer_fp={peer_fingerprint} worker=candidate_offer owner={} network_generation={} candidate_generation={} peer_session_generation={:?}",
                            reservation.owner,
                            offer.network_generation,
                            offer.candidate_generation,
                            offer.peer_session_generation
                        )),
                    );
                }
                retry_attempt = retry_attempt.saturating_add(1);
                let delay = responder_offer_retry_delay(retry_attempt);
                tokio::select! {
                    _ = sleep(delay) => {}
                    changed = reservation.cancellation.changed() => {
                        if changed.is_err() || *reservation.cancellation.borrow() {
                            if let (Some(started), Some(resource)) = (wait_started, wait_resource) {
                                self.timeline.emit(
                                    "peer_offer_candidate_postprocess_wait_cancelled",
                                    None,
                                    Some("reservation_cancelled"),
                                    Some(format!(
                                        "peer_fp={peer_fingerprint} worker=candidate_offer owner={} resource={resource} network_generation={} candidate_generation={} peer_session_generation={:?} wait_ms={}",
                                        reservation.owner,
                                        offer.network_generation,
                                        offer.candidate_generation,
                                        offer.peer_session_generation,
                                        started.elapsed().as_millis()
                                    )),
                                );
                            }
                            return false;
                        }
                    }
                }
                continue;
            }

            if let (Some(started), Some(resource)) = (wait_started, wait_resource) {
                let result = match outcome {
                    HolePunchStartOutcome::Started => "started",
                    HolePunchStartOutcome::HealthyDirect => "healthy_direct",
                    HolePunchStartOutcome::PeerMissing => "peer_missing",
                    HolePunchStartOutcome::Stale => "stale",
                    HolePunchStartOutcome::NotReady => "not_ready",
                    HolePunchStartOutcome::ContendedEpoch
                    | HolePunchStartOutcome::ContendedConnections => unreachable!(),
                };
                self.timeline.emit(
                    "peer_offer_candidate_postprocess_wait_resolved",
                    None,
                    Some(result),
                    Some(format!(
                        "peer_fp={peer_fingerprint} worker=candidate_offer owner={} resource={resource} network_generation={} candidate_generation={} peer_session_generation={:?} wait_ms={}",
                        reservation.owner,
                        offer.network_generation,
                        offer.candidate_generation,
                        offer.peer_session_generation,
                        started.elapsed().as_millis()
                    )),
                );
            }
            return !matches!(
                outcome,
                HolePunchStartOutcome::Stale | HolePunchStartOutcome::PeerMissing
            );
        }
    }

    async fn apply_deferred_peer_offer_punch_for_candidate_work(
        &self,
        offer: &PendingPeerOffer,
        candidate_apply_result: CandidateSetApplyResult,
        fresh_punch: FreshPunchDecision,
        reservation: &mut CandidateOfferWorkReservation,
    ) {
        let hard_hard_handling = self
            .handle_hard_hard_fresh_offer(
                &offer.from_node_id,
                offer.session_id.as_deref(),
                offer.punch_at_ms,
                fresh_punch.clone(),
            )
            .await;
        if candidate_apply_result == CandidateSetApplyResult::Applied
            && hard_hard_handling != HardHardOfferHandling::Started
        {
            self.peers
                .clear_hard_hard_sessions(Some(&offer.from_node_id))
                .await;
        }
        if matches!(
            hard_hard_handling,
            HardHardOfferHandling::Rejected | HardHardOfferHandling::Started
        ) {
            return;
        }
        match fresh_punch {
            FreshPunchDecision::Fresh(id, frozen_targets) => {
                if !self
                    .start_candidate_offer_punch(
                        offer,
                        reservation,
                        offer.punch_at_ms,
                        Some(id),
                        Some(frozen_targets.clone()),
                    )
                    .await
                {
                    return;
                }
                // C=0 (mutual-APD): when we also hold a fresh local mapping,
                // knock back from OUR fresh source at the SAME canonical
                // deadline toward the peer's fresh predicted ports.  This is
                // the fresh-fresh synchronized pair that breaks the
                // no-mutually-admitted-endpoint deadlock; bounded by the
                // per-(peer, generation) budget.
                self.coordinate_c0_fresh_fresh_pair(offer, &frozen_targets, id)
                    .await;
            }
            FreshPunchDecision::Degraded => {
                if !offer.handshake_init.is_empty() {
                    let _ = self
                        .start_candidate_offer_punch(
                            offer,
                            reservation,
                            offer.punch_at_ms,
                            None,
                            None,
                        )
                        .await;
                }
            }
            FreshPunchDecision::None => {
                if candidate_signal_starts_synchronized_punch(
                    &offer.handshake_init,
                    candidate_apply_result,
                ) {
                    let _ = self
                        .start_candidate_offer_punch(
                            offer,
                            reservation,
                            offer.punch_at_ms,
                            None,
                            None,
                        )
                        .await;
                }
            }
        }
    }

    #[cfg(test)]
    async fn apply_deferred_peer_offer_punch(
        &self,
        offer: &PendingPeerOffer,
        candidate_apply_result: CandidateSetApplyResult,
        fresh_punch: FreshPunchDecision,
    ) {
        let hard_hard_handling = self
            .handle_hard_hard_fresh_offer(
                &offer.from_node_id,
                offer.session_id.as_deref(),
                offer.punch_at_ms,
                fresh_punch.clone(),
            )
            .await;
        if candidate_apply_result == CandidateSetApplyResult::Applied
            && hard_hard_handling != HardHardOfferHandling::Started
        {
            self.peers
                .clear_hard_hard_sessions(Some(&offer.from_node_id))
                .await;
        }
        if matches!(
            hard_hard_handling,
            HardHardOfferHandling::Rejected | HardHardOfferHandling::Started
        ) {
            return;
        }
        match fresh_punch {
            FreshPunchDecision::Fresh(id, frozen_targets) => {
                self.start_hole_punch_at(
                    &offer.from_node_id,
                    offer.punch_at_ms,
                    Some(id),
                    Some(frozen_targets.clone()),
                )
                .await;
                self.coordinate_c0_fresh_fresh_pair(offer, &frozen_targets, id)
                    .await;
            }
            FreshPunchDecision::Degraded => {
                if !offer.handshake_init.is_empty() {
                    self.start_hole_punch_at(&offer.from_node_id, offer.punch_at_ms, None, None)
                        .await;
                }
            }
            FreshPunchDecision::None => {
                if candidate_signal_starts_synchronized_punch(
                    &offer.handshake_init,
                    candidate_apply_result,
                ) {
                    self.start_hole_punch_at(&offer.from_node_id, offer.punch_at_ms, None, None)
                        .await;
                }
            }
        }
    }

    /// Route a well-formed, control-context-admitted `hh1` fresh signal into
    /// the two-sided synchronized rendezvous.  The envelope is an epoch fence,
    /// not a cryptographic authenticator: malformed or mismatched metadata is
    /// consumed and rejected rather than silently degrading into an ordinary
    /// one-sided Hard↔Hard punch.
    async fn handle_hard_hard_fresh_offer(
        &self,
        peer_id: &str,
        session_id: Option<&str>,
        punch_at_ms: Option<u64>,
        fresh_punch: FreshPunchDecision,
    ) -> HardHardOfferHandling {
        let Some(session_id) = session_id else {
            return HardHardOfferHandling::NotHardHard;
        };
        if !HardHardCoordination::looks_like(session_id) {
            return HardHardOfferHandling::NotHardHard;
        }
        let Some(coordination) = HardHardCoordination::parse(session_id) else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    None,
                    None,
                    None,
                    "malformed Hard↔Hard session envelope; no fallback punch started",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        };
        let FreshPunchDecision::Fresh(_id, frozen_targets) = fresh_punch else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    None,
                    None,
                    None,
                    "Hard↔Hard session did not carry an admitted, unexpired fresh prediction window",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        };
        if !self
            .peers
            .bind_remote_nat_profile_to_candidate_epoch(
                peer_id,
                coordination.local_profile_generation,
            )
            .await
        {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    frozen_targets.first().copied(),
                    Some(frozen_targets.len()),
                    None,
                    "Hard↔Hard profile generation was not current for the admitted candidate context",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        }
        let Some(punch_at_ms) = punch_at_ms else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "hard_hard_session_rejected",
                    frozen_targets.first().copied(),
                    Some(frozen_targets.len()),
                    None,
                    "Hard↔Hard session had no canonical punch_at_ms; Relay remains usable",
                )
                .await;
            return HardHardOfferHandling::Rejected;
        };
        let Some(udp) = self.udp_transport.read().await.clone() else {
            return HardHardOfferHandling::Fallback;
        };
        let Some(signal) = self.hole_punch_signal_context().await else {
            return HardHardOfferHandling::Fallback;
        };
        match coordination.role {
            HardHardRole::Initiator => {
                // A new remote initiator supersedes any older rendezvous on
                // this peer. Clear it before the new responder measurement is
                // launched; the new record is registered only after that
                // bounded measurement completes.
                self.peers.clear_hard_hard_sessions(Some(peer_id)).await;
                match spawn_hard_hard_responder(
                    udp,
                    self.peers.clone(),
                    self.punch_attempts.clone(),
                    signal,
                    peer_id.to_string(),
                    coordination,
                    punch_at_ms,
                    frozen_targets,
                )
                .await
                {
                    HardHardRemoteStart::Started => HardHardOfferHandling::Started,
                    HardHardRemoteStart::NotStarted => HardHardOfferHandling::Fallback,
                    HardHardRemoteStart::Rejected => HardHardOfferHandling::Rejected,
                }
            }
            HardHardRole::Responder => {
                let current_remote_candidate_epoch = self
                    .peers
                    .current_remote_candidate_epoch(peer_id)
                    .await
                    .unwrap_or_default();
                match self
                    .peers
                    .hard_hard_prepare_response(
                        peer_id,
                        &coordination.token,
                        current_remote_candidate_epoch,
                    )
                    .await
                {
                    crate::peer::HardHardResponseAdmission::Rejected => {
                        self.peers
                            .record_direct_event(
                                peer_id,
                                "hard_hard_response_fenced",
                                frozen_targets.first().copied(),
                                Some(frozen_targets.len()),
                                None,
                                "Hard↔Hard response did not match the one live initiator session or its expected candidate epoch",
                            )
                            .await;
                        return HardHardOfferHandling::Rejected;
                    }
                    crate::peer::HardHardResponseAdmission::AlreadySweeping => {
                        return HardHardOfferHandling::Started;
                    }
                    crate::peer::HardHardResponseAdmission::Ready => {}
                }
                match spawn_hard_hard_initiator_response(
                    udp,
                    self.peers.clone(),
                    self.punch_attempts.clone(),
                    peer_id.to_string(),
                    coordination,
                    frozen_targets,
                    punch_at_ms,
                )
                .await
                {
                    HardHardRemoteStart::Started => HardHardOfferHandling::Started,
                    HardHardRemoteStart::NotStarted => HardHardOfferHandling::Fallback,
                    HardHardRemoteStart::Rejected => HardHardOfferHandling::Rejected,
                }
            }
        }
    }

    /// Coordinate the C=0 fresh-fresh synchronized pair on the receiver side
    /// of a fresh offer.
    ///
    /// The peer advertised its FRESH predicted ports (`frozen_targets`) with a
    /// canonical `punch_at_ms`.  We already punch at that deadline through the
    /// ordinary path (`start_hole_punch_at`); when we ALSO hold a fresh local
    /// mapping for this peer, we additionally knock from OUR fresh source at
    /// the SAME canonical instant toward the peer's fresh ports — the
    /// mutual-APD deadlock breaker.
    ///
    /// Fully bounded: the per-(peer, generation) C=0 ledger caps the number of
    /// distinct fresh-fresh pairs ever attempted, and the C=0 rendezvous
    /// window itself reuses the micro-window target cap and attempt count.
    /// When the budget is exhausted, no further fresh-fresh pairs are
    /// scheduled and the relay keeps carrying the data plane.
    ///
    /// A miss is attributed to the ledger immediately (the pair was
    /// attempted); a hit is decided by the existing encrypted-validation path
    /// and stops further attempts via the ledger.
    async fn coordinate_c0_fresh_fresh_pair(
        &self,
        offer: &PendingPeerOffer,
        frozen_targets: &[SocketAddr],
        id: crate::FreshPredictionId,
    ) {
        let peer_id = &offer.from_node_id;
        let generation = self.peers.current_network_generation().await;
        // Budget gate first: exhausted means we stop scheduling C=0 pairs.
        if !self.peers.c0_pair_admission(peer_id, generation).await {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_budget_exhausted",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: per-(peer, generation) budget exhausted",
                )
                .await;
            return;
        }
        // We must hold a fresh local mapping (the SOURCE the peer must learn)
        // for this pair to be meaningful.
        let Some(local_fresh) = self.peers.fresh_mapping_for_peer(peer_id).await else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_no_local_fresh",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: no fresh local mapping available",
                )
                .await;
            return;
        };
        // Remote targets = the peer's OWN fresh predicted ports (frozen by
        // the offer's committed snapshot), NOT historical stable_targets.
        let Some(plan) = C0FreshPairPlan::new(
            local_fresh.socket_local_endpoint,
            frozen_targets,
            offer.punch_at_ms,
        ) else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_no_remote_fresh",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: no remote fresh predicted ports in the offer",
                )
                .await;
            return;
        };
        let Some(udp) = self.udp_transport.read().await.clone() else {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_skipped_no_udp",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair not scheduled: UDP transport not ready",
                )
                .await;
            return;
        };
        let scheduled = spawn_c0_synchronized_fresh_pair(
            udp,
            self.peers.clone(),
            self.punch_attempts.clone(),
            peer_id.clone(),
            plan.local_fresh_endpoint,
            local_fresh.socket_index,
            plan.bounded_targets.clone(),
            Some(plan.canonical_punch_at_ms),
            Some(id),
        )
        .await;
        // Attribution: the pair was (or was not) attempted; the ledger
        // counts the attempt regardless of the wire outcome, and a hit is
        // decided by encrypted validation independently.
        self.peers
            .c0_pair_attempt(
                peer_id,
                generation,
                self.peers.recovery_epoch_for(peer_id).await,
                &plan.local_fresh_endpoint.to_string(),
                &plan
                    .bounded_targets
                    .first()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                Some(plan.canonical_punch_at_ms),
                crate::peer::C0PairOutcome::Miss,
            )
            .await;
        if !scheduled {
            self.peers
                .record_direct_event(
                    peer_id,
                    "c0_rendezvous_not_scheduled",
                    None,
                    None,
                    None,
                    "C=0 fresh-fresh pair could not be scheduled (budget/admission/udp/deferred); attributed as attempted miss",
                )
                .await;
        }
    }

    /// Run the slow half of one peer-reflexive control event.
    ///
    /// Updating the candidate set can wait behind a live STUN refresh and the
    /// optional re-advertisement performs HTTP I/O. This must never execute
    /// in the serial control receiver: offers and answers need to keep making
    /// their short candidate/handshake transactions while this work waits.
    /// The caller owns a per-peer newest-wins reservation, so endpoint churn
    /// cannot create more than one active worker for a peer.
    async fn handle_peer_reflexive_work(
        &self,
        work: &PendingPeerReflexive,
        cancellation: &mut watch::Receiver<bool>,
    ) {
        if *cancellation.borrow() {
            return;
        }
        let peer_id = &work.from_node_id;
        let already_direct_at_arrival = self.peers.should_defer_relay_assisted_punch(peer_id).await;
        let local_candidate_changed = tokio::select! {
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    return;
                }
                return;
            }
            changed = self.add_local_peer_reflexive_candidate(&work.observed_endpoint) => changed,
        };
        if let Ok(observed_addr) = work.observed_endpoint.parse::<SocketAddr>() {
            self.peers
                .record_fresh_mapping_prediction_result(peer_id, observed_addr)
                .await;
        }
        let punch_at_ms = work
            .punch_at_ms
            .or_else(|| Some(relay_assisted_punch_at_ms()));
        let (candidates, candidate_sources) = tokio::select! {
            changed = cancellation.changed() => {
                if changed.is_err() || *cancellation.borrow() {
                    return;
                }
                return;
            }
            candidates = self.current_local_candidate_set() => candidates,
        };
        let selected_remote_endpoint = self
            .peers
            .selected_direct_endpoint_for_consent(peer_id)
            .await;
        // Re-check after the potentially long candidate-refresh wait. A
        // concurrent inbound ACK/answer may have promoted Direct meanwhile;
        // that must suppress the stale HTTP offer and punch, even when the
        // peer was not Direct at the time this observation arrived.
        let already_direct = self.peers.should_defer_relay_assisted_punch(peer_id).await;
        let schedule_punch = !already_direct;
        let skip_reason = already_direct.then_some("direct_confirmed_healthy");
        self.peers
            .record_direct_event(
                peer_id,
                "peer_reflexive_received",
                work.observed_endpoint.parse().ok(),
                Some(candidates.len()),
                None,
                format!(
                    "peer observed our UDP source as {}; already_advertised={} already_direct_at_arrival={already_direct_at_arrival} already_direct={already_direct} selected_remote_endpoint={selected_remote_endpoint:?} schedule_punch={schedule_punch} skip_reason={skip_reason:?}",
                    work.observed_endpoint,
                    !local_candidate_changed,
                ),
            )
            .await;
        if already_direct || *cancellation.borrow() {
            return;
        }
        // The peer-reflexive signal carries the observer's relay-normalized
        // rendezvous deadline.  Join it with a tiny trusted remote-target
        // slice before the optional candidate re-offer: this is the receiver
        // half of the shared micro-window, not a replacement for the normal
        // full recovery punch below. Old signals without a deadline retain
        // the legacy full-punch behavior but never invent a one-sided
        // "synchronized" micro-window.
        if let Some(shared_punch_at_ms) = work.punch_at_ms {
            let udp = self.udp_transport.read().await.clone();
            let targets = self.peers.direct_probe_target_set_for(peer_id).await;
            if let (Some(udp), Some(targets)) = (udp, targets) {
                spawn_peer_reflexive_micro_window(
                    udp,
                    self.peers.clone(),
                    self.punch_attempts.clone(),
                    peer_id.to_string(),
                    targets.candidates,
                    Some(shared_punch_at_ms),
                    "peer_reflexive_receiver",
                )
                .await;
            } else {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "peer_reflexive_micro_window_skipped",
                        None,
                        None,
                        None,
                        "receiver could not join shared peer-reflexive micro-window because UDP transport or trusted remote targets were unavailable",
                    )
                    .await;
            }
        }
        if local_candidate_changed && !candidates.is_empty() {
            let send_result = tokio::select! {
                changed = cancellation.changed() => {
                    if changed.is_err() || *cancellation.borrow() {
                        return;
                    }
                    return;
                }
                result = self.control.send_peer_offer_with_sources_and_punch_at(
                    peer_id,
                    &candidates,
                    &candidate_sources,
                    &[],
                    punch_at_ms,
                    None,
                ) => result,
            };
            if let Err(err) = send_result {
                warn!("Failed to re-advertise peer-reflexive local candidate to {peer_id}: {err}");
            } else {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "peer_reflexive_offer_sent",
                        work.observed_endpoint.parse().ok(),
                        Some(candidates.len()),
                        None,
                        "re-advertised local candidates after peer-reflexive observation",
                    )
                    .await;
            }
        } else if !local_candidate_changed {
            self.peers
                .record_direct_event(
                    peer_id,
                    "peer_reflexive_offer_skipped",
                    work.observed_endpoint.parse().ok(),
                    Some(candidates.len()),
                    None,
                    "peer-reflexive candidate already advertised; skipped full offer re-advertisement",
                )
                .await;
        }
        if !*cancellation.borrow() && !self.peers.should_defer_relay_assisted_punch(peer_id).await {
            self.start_hole_punch_at(peer_id, punch_at_ms, None, None)
                .await;
        }
    }
}
