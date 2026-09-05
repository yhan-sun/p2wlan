/// Await an initiator offer only while its reserved pending transaction is
/// still live.  The control runtime owns the actual HTTP request, but dropping
/// this receiver wait on cancellation releases the bounded control-event work
/// slot immediately instead of leaving it occupied until that request times
/// out.
async fn await_initiator_offer_or_cancellation<F>(
    offer: F,
    cancellation: &mut tokio::sync::watch::Receiver<bool>,
) -> Option<Result<()>>
where
    F: std::future::Future<Output = Result<()>>,
{
    // A closed sender is fail-closed too: without the reservation owner we
    // must not report an old offer as current.
    if *cancellation.borrow() || cancellation.has_changed().is_err() {
        return None;
    }

    tokio::select! {
        biased;
        changed = cancellation.changed() => {
            let _ = changed;
            None
        }
        result = offer => {
            // If both branches become ready together, prefer cancellation;
            // this final check also covers a sender being dropped immediately
            // after the request completed.
            if *cancellation.borrow() || cancellation.has_changed().is_err() {
                None
            } else {
                Some(result)
            }
        }
    }
}

enum EventInitiatorReservationOutcome {
    Reserved(HandshakeStartReservation),
    Busy,
    Contended,
    RejectedLifecycle,
}

impl EventInitiatorReservationOutcome {
    fn into_reservation(self) -> Option<HandshakeStartReservation> {
        match self {
            Self::Reserved(reservation) => Some(reservation),
            Self::Busy | Self::Contended | Self::RejectedLifecycle => None,
        }
    }

    #[cfg(test)]
    fn expect(self, message: &str) -> HandshakeStartReservation {
        match self {
            Self::Reserved(reservation) => reservation,
            Self::Busy => panic!("{message}: reservation busy"),
            Self::Contended => panic!("{message}: arbiter contended"),
            Self::RejectedLifecycle => panic!("{message}: lifecycle rejected"),
        }
    }
}

impl Daemon {
    /// Fast admission used by the serial control event loop before it puts
    /// potentially slow initiator work into its bounded work set.
    fn reserve_event_initiator_handshake(&self, peer_id: &str) -> EventInitiatorReservationOutcome {
        let network_generation = self.peers.current_network_generation_sync();
        let Some(peer_session_generation) = self.peers.peer_session_generation_sync(peer_id) else {
            return EventInitiatorReservationOutcome::RejectedLifecycle;
        };
        let identity = HandshakeLeaseIdentity::new(
            peer_id,
            HandshakeOwnerKind::EventInitiatorReserve,
            None,
            network_generation,
            Some(peer_session_generation),
            "reserve",
        );
        let handshake_guard = match self.handshake_arbiter.try_acquire(identity) {
            Ok(handshake_guard) => handshake_guard,
            Err(contention) => {
                let holder = contention
                    .holder
                    .as_ref()
                    .map(HandshakeHolderSnapshot::detail)
                    .unwrap_or_else(|| "holder_kind=unknown holder_phase=unknown".to_string());
                self.timeline.emit(
                    "initiator_reservation_contended",
                    None,
                    Some("arbiter_contended"),
                    Some(format!(
                        "peer={peer_id} generation={network_generation} peer_session_generation={} {holder}",
                        peer_session_generation.value()
                    )),
                );
                return EventInitiatorReservationOutcome::Contended;
            }
        };
        let transaction = self.pending_handshakes.try_with(|state| {
            let stale_session_id = state.remove_stale_pending_for_generation(
                peer_id,
                network_generation,
                peer_session_generation,
            );
            let reservation = state.reserve_start_with_owner_at_generation_and_kind(
                peer_id,
                network_generation,
                peer_session_generation,
                HandshakeOwnerKind::EventInitiatorReserve,
            );
            if reservation.is_some()
                && state.attempts.get(peer_id).copied().unwrap_or(0) >= MAX_HANDSHAKE_ATTEMPTS
            {
                state.attempts.remove(peer_id);
            }
            (stale_session_id, reservation)
        });
        let Some((stale_session_id, reservation)) = transaction else {
            drop(handshake_guard);
            return EventInitiatorReservationOutcome::Contended;
        };
        drop(handshake_guard);
        let Some(mut reservation) = reservation else {
            return EventInitiatorReservationOutcome::Busy;
        };
        reservation.stale_session_id = stale_session_id;
        self.timeline.emit(
            "initiator_handshake_reserved",
            None,
            None,
            Some(format!(
                "peer={peer_id} owner={} owner_kind={} generation={network_generation}",
                reservation.owner,
                reservation.owner_kind.as_str(),
            )),
        );
        EventInitiatorReservationOutcome::Reserved(reservation)
    }

    /// Commit one exact retry identity before publishing its wake edge.  The
    /// per-peer map coalesces duplicate contention, the reservation remains
    /// the cross-await owner, and the supervised control loop plus maintenance
    /// scan jointly provide progress without detached tasks.
    fn schedule_initiator_retry(
        &self,
        peer_id: &str,
        reservation: &mut HandshakeStartReservation,
        phase: InitiatorRetryPhase,
        reason_code: &'static str,
    ) -> bool {
        let scheduled = self.pending_handshakes.lock().schedule_initiator_retry(
            peer_id,
            reservation,
            phase,
            Instant::now(),
        );
        let Some((identity, revision)) = scheduled else {
            // Capacity, TTL, or an ownership mismatch cannot leave a prepared
            // reservation with no progress edge.  Cancel only the exact owner;
            // a replacement lifecycle remains untouched.
            let cancelled = self
                .pending_handshakes
                .lock()
                .cancel_reservation_if_current(peer_id, reservation.owner);
            self.timeline.emit(
                "initiator_handshake_retry_rejected",
                None,
                Some("retry_not_admitted"),
                Some(format!(
                    "peer={peer_id} owner={} generation={} peer_session_generation={} phase={} cancellation_generation={} cancelled_exact_owner={cancelled}",
                    reservation.owner,
                    reservation.network_generation,
                    reservation.peer_session_generation.value(),
                    phase.as_str(),
                    reservation.cancellation_generation,
                )),
            );
            return false;
        };
        reservation.disposition = HandshakeStartDisposition::RetryScheduled;
        self.timeline.emit(
            "initiator_handshake_retry_scheduled",
            None,
            Some(reason_code),
            Some(format!(
                "peer={} owner={} generation={} peer_session_generation={} phase={} attempt={} cancellation_generation={} retry_revision={revision}",
                identity.peer_id,
                identity.reservation_owner,
                identity.network_generation,
                identity.peer_session_generation.value(),
                identity.phase.as_str(),
                identity.attempt,
                identity.cancellation_generation,
            )),
        );
        self.handshake_retry_kick_tx.send_replace(revision);
        true
    }

    /// Put an exact prepared initiation back under its reservation before
    /// publishing the retry edge. Every publish-side contention path uses
    /// this helper so taking the prepared value out of the short state turn
    /// can never create a lost wake or regenerate Noise/Probe key material.
    fn retain_prepared_initiator_publish_retry(
        &self,
        peer_id: &str,
        reservation: &mut HandshakeStartReservation,
        prepared: PreparedInitiatorHandshake,
        reason_code: &'static str,
    ) {
        if self
            .pending_handshakes
            .lock()
            .store_prepared_if_current(peer_id, reservation, prepared)
        {
            self.schedule_initiator_retry(
                peer_id,
                reservation,
                InitiatorRetryPhase::Publish,
                reason_code,
            );
        }
    }

    /// Complete an initiator handshake after the control event loop has
    /// atomically admitted a reservation for this peer.
    ///
    /// The reservation is the single-flight boundary.  The arbiter only
    /// protects short state transitions; it is deliberately released before
    /// STUN candidate gathering and the control-plane offer POST so an inbound
    /// offer/answer can still make progress for the same peer.
    async fn run_reserved_initiator_handshake(
        &self,
        peer_info: &control::PeerInfo,
        reservation: &mut HandshakeStartReservation,
    ) -> Result<Option<u64>> {
        if let Some(stale_session_id) = reservation.stale_session_id.take() {
            self.peers
                .discard_pending_probe_session_binding(&peer_info.node_id, &stale_session_id)
                .await;
        }
        if *reservation.cancellation.borrow() {
            return Ok(None);
        }

        // Bind the entire initiator transaction to the generation captured by
        // its reservation.  The answer may arrive much later; it must not be
        // allowed to turn an old initiation into a session for a newer network
        // incarnation, nor may an old task silently retag itself as new.
        let handshake_generation = reservation.network_generation;
        if self.peers.current_network_generation_sync() != handshake_generation
            || !self.peers.peer_session_is_current_sync(
                &peer_info.node_id,
                reservation.peer_session_generation,
            )
        {
            self.pending_handshakes
                .lock()
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }
        let peer_id = peer_info.node_id.clone();
        let prepared_already = self
            .pending_handshakes
            .lock()
            .has_prepared_for_reservation(&peer_id, reservation);
        if !prepared_already {
            let identity = HandshakeLeaseIdentity::new(
                &peer_id,
                HandshakeOwnerKind::EventInitiatorPrepare,
                Some(reservation.owner),
                handshake_generation,
                Some(reservation.peer_session_generation),
                "preparation",
            );
            let Ok(handshake_guard) = self.handshake_arbiter.try_acquire(identity) else {
                self.schedule_initiator_retry(
                    &peer_id,
                    reservation,
                    InitiatorRetryPhase::Preparation,
                    "arbiter_contended",
                );
                return Ok(None);
            };
            let current = self
                .pending_handshakes
                .try_with(|state| state.starting_reservation_is_current(&peer_id, reservation));
            drop(handshake_guard);
            match current {
                Some(true) => {}
                Some(false) => return Ok(None),
                None => {
                    self.schedule_initiator_retry(
                        &peer_id,
                        reservation,
                        InitiatorRetryPhase::Preparation,
                        "pending_state_contended",
                    );
                    return Ok(None);
                }
            }

            // Every actor/control/candidate await below is owned by the exact
            // reservation, never by the mutation-turn lease.
            let status = self.transport.session_status(&peer_info.node_id).await;
            if status.has_active || status.has_pending_responder {
                self.pending_handshakes
                    .lock()
                    .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                return Ok(None);
            }

            let identity = match self.local_identity() {
                Ok(identity) => identity,
                Err(error) => {
                    self.pending_handshakes
                        .lock()
                        .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                    return Err(error);
                }
            };
            let peer_public = match decode_x25519_key(&peer_info.public_key, "peer public key") {
                Ok(peer_public) => peer_public,
                Err(error) => {
                    self.pending_handshakes
                        .lock()
                        .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                    return Err(error);
                }
            };
            if !local_is_designated_handshake_initiator(&identity.public_key(), &peer_public) {
                self.pending_handshakes
                    .lock()
                    .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                return Ok(None);
            }

            let mut initiator = HandshakeInitiator::new(identity, peer_public, None);
            let initiation = match initiator.create_initiation() {
                Ok(initiation) => initiation,
                Err(error) => {
                    self.pending_handshakes
                        .lock()
                        .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                    return Err(DaemonError::Peer(format!(
                        "WireGuard initiation failed: {error}"
                    )));
                }
            };
            let initiation_bytes = initiation.to_bytes();

            // Candidate gathering may wait on a live STUN fan-out. Keep the owner
            // reservation; the arbiter was already released before actor I/O.
            // Host candidates are published before that gather completes, so a
            // provisional non-empty snapshot must not immediately win the first
            // offer. Give the full startup snapshot a bounded opportunity while
            // preserving the relay-first fast path.
            let (candidates, candidate_sources) = {
                let initial_snapshot = self.initial_candidate_set_if_ready().await;
                let mut relay_available = self.relay_available_tx.subscribe();
                let relay_is_available = *relay_available.borrow();
                if let Some(initial_snapshot) = initial_snapshot {
                    if let Some(snapshot) = relay_first_candidate_shortcut(
                        initial_snapshot.0,
                        initial_snapshot.1,
                        relay_is_available,
                    ) {
                        if snapshot.0.is_empty() {
                            self.peers
                                .record_direct_event(
                                    &peer_info.node_id,
                                    "relay_first_empty_candidate_offer",
                                    None,
                                    Some(0),
                                    None,
                                    "relay transport is available; encrypted handshake is not gated on STUN candidates",
                                )
                                .await;
                        }
                        snapshot
                    } else {
                        self.wait_for_local_candidate_set().await
                    }
                } else if relay_is_available {
                    // The relay is already usable, so do not hold the encrypted
                    // session behind a slow first STUN gather. The full candidate
                    // snapshot is still published independently by UDP startup.
                    self.peers
                        .record_direct_event(
                            &peer_info.node_id,
                            "relay_first_empty_candidate_offer",
                            None,
                            Some(0),
                            None,
                            "relay transport is available before the initial UDP candidate snapshot; encrypted handshake is not gated on STUN candidates",
                        )
                        .await;
                    (Vec::new(), HashMap::new())
                } else {
                    // Once the relay transport is up, an empty candidate list is
                    // intentional: the control-plane handshake still establishes
                    // the encrypted session, and the forced relay probe can then
                    // prove the relay path.  Waiting for STUN here recreated the
                    // old "relay TCP is ready but the first business packet waits
                    // for candidate gathering" failure.  Direct candidates are
                    // refreshed and signaled independently after this point.
                    // Relay selection and candidate gathering run in parallel.
                    // Whichever becomes usable first wins; a cancellation is
                    // fail-closed and releases the reservation immediately.
                    tokio::select! {
                        biased;
                        changed = relay_available.changed() => {
                            if changed.is_ok() && *relay_available.borrow() {
                                self.peers
                                    .record_direct_event(
                                        &peer_info.node_id,
                                        "relay_first_empty_candidate_offer",
                                        None,
                                        Some(0),
                                        None,
                                        "relay became available before STUN candidates; encrypted handshake is not gated on candidates",
                                    )
                                    .await;
                                (Vec::new(), HashMap::new())
                            } else {
                                self.wait_for_initial_candidate_set().await
                            }
                        }
                        candidates = self.wait_for_initial_candidate_set() => candidates,
                        changed = reservation.cancellation.changed() => {
                            if changed.is_err() || *reservation.cancellation.borrow() {
                                return Ok(None);
                            }
                            return Ok(None);
                        }
                    }
                }
            };
            if *reservation.cancellation.borrow() {
                return Ok(None);
            }

            let session_id = new_probe_session_id();
            let (probe_ephemeral, probe_ephemeral_public_key) = new_probe_ephemeral_keypair();
            let prepared = PreparedInitiatorHandshake {
                initiator,
                initiation_bytes,
                candidates,
                candidate_sources,
                session_id,
                probe_ephemeral,
                probe_ephemeral_public_key,
            };
            if !self.pending_handshakes.lock().store_prepared_if_current(
                &peer_id,
                reservation,
                prepared,
            ) {
                return Ok(None);
            }
        }

        // Re-enter the short mutation boundary.  A responder may have won
        // while gathering candidates; only the owner that is still current may
        // turn its reservation into a pending initiator transaction.
        let identity = HandshakeLeaseIdentity::new(
            &peer_id,
            HandshakeOwnerKind::EventInitiatorPublish,
            Some(reservation.owner),
            handshake_generation,
            Some(reservation.peer_session_generation),
            "publish",
        );
        let Ok(handshake_guard) = self.handshake_arbiter.try_acquire(identity) else {
            self.schedule_initiator_retry(
                &peer_id,
                reservation,
                InitiatorRetryPhase::Publish,
                "arbiter_contended",
            );
            return Ok(None);
        };
        let prepared = self
            .pending_handshakes
            .try_with(|state| state.take_prepared_if_current(&peer_id, reservation));
        drop(handshake_guard);
        let prepared = match prepared {
            Some(Some(prepared)) => prepared,
            Some(None) => {
                self.pending_handshakes
                    .lock()
                    .cancel_reservation_if_current(&peer_id, reservation.owner);
                return Ok(None);
            }
            None => {
                self.schedule_initiator_retry(
                    &peer_id,
                    reservation,
                    InitiatorRetryPhase::Publish,
                    "pending_state_contended",
                );
                return Ok(None);
            }
        };
        let PreparedInitiatorHandshake {
            initiator,
            initiation_bytes,
            candidates,
            candidate_sources,
            session_id,
            probe_ephemeral,
            probe_ephemeral_public_key,
        } = prepared;
        let publish_attempt = reservation.retry_attempt;
        let (attempt_no, pending_id) = {
            // The outbound worker establishes the canonical lifecycle order
            // `emit -> generation -> session/connection`. Every acquisition
            // after the short emit-registry lookup is try-only. Contention
            // restores the exact prepared initiation before waking the
            // supervised retry owner, so the emit fence can never be held
            // while waiting for epoch/session/connection state.
            self.timeline.emit(
                "initiator_publish_emit_lock_wait",
                None,
                None,
                Some(format!(
                    "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} wait_budget_us=0",
                    reservation.owner
                )),
            );
            let Some(emit_guard) = self.transport.try_acquire_outbound_emit_guard(&peer_id) else {
                self.timeline.emit(
                    "initiator_publish_emit_lock_contended",
                    None,
                    Some("emit_guard_contended"),
                    Some(format!(
                        "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} queued=false",
                        reservation.owner
                    )),
                );
                self.retain_prepared_initiator_publish_retry(
                    &peer_id,
                    reservation,
                    PreparedInitiatorHandshake {
                        initiator,
                        initiation_bytes,
                        candidates,
                        candidate_sources,
                        session_id,
                        probe_ephemeral,
                        probe_ephemeral_public_key,
                    },
                    "emit_guard_contended",
                );
                return Ok(None);
            };
            self.timeline.emit(
                "initiator_publish_emit_lock_acquired",
                None,
                None,
                Some(format!(
                    "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} wait_us=0",
                    reservation.owner
                )),
            );
            let epoch_gate = self.peers.network_epoch_gate();
            self.timeline.emit(
                "initiator_publish_epoch_gate_wait",
                None,
                None,
                Some(format!(
                    "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} wait_budget_us=0",
                    reservation.owner
                )),
            );
            let Ok(epoch_guard) = epoch_gate.try_lock() else {
                self.timeline.emit(
                    "initiator_publish_epoch_gate_contended",
                    None,
                    Some("network_epoch_contended"),
                    Some(format!(
                        "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} queued=false",
                        reservation.owner
                    )),
                );
                drop(emit_guard);
                self.retain_prepared_initiator_publish_retry(
                    &peer_id,
                    reservation,
                    PreparedInitiatorHandshake {
                        initiator,
                        initiation_bytes,
                        candidates,
                        candidate_sources,
                        session_id,
                        probe_ephemeral,
                        probe_ephemeral_public_key,
                    },
                    "network_epoch_contended",
                );
                return Ok(None);
            };
            self.timeline.emit(
                "initiator_publish_epoch_gate_acquired",
                None,
                None,
                Some(format!(
                    "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} wait_us=0",
                    reservation.owner
                )),
            );
            if *reservation.cancellation.borrow()
                || reservation.cancellation.has_changed().is_err()
                || self.peers.current_network_generation_sync() != handshake_generation
                || !self
                    .peers
                    .peer_session_is_current_sync(&peer_id, reservation.peer_session_generation)
            {
                drop(epoch_guard);
                drop(emit_guard);
                self.pending_handshakes
                    .lock()
                    .cancel_reservation_if_current(&peer_id, reservation.owner);
                return Ok(None);
            }
            let Some(status) = self.transport.try_session_status(&peer_id) else {
                self.timeline.emit(
                    "initiator_publish_session_status_contended",
                    None,
                    Some("transport_sessions_contended"),
                    Some(format!(
                        "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} queued=false",
                        reservation.owner
                    )),
                );
                drop(epoch_guard);
                drop(emit_guard);
                self.retain_prepared_initiator_publish_retry(
                    &peer_id,
                    reservation,
                    PreparedInitiatorHandshake {
                        initiator,
                        initiation_bytes,
                        candidates,
                        candidate_sources,
                        session_id,
                        probe_ephemeral,
                        probe_ephemeral_public_key,
                    },
                    "transport_sessions_contended",
                );
                return Ok(None);
            };
            self.timeline.emit(
                "initiator_publish_session_status_ready",
                None,
                None,
                Some(format!(
                    "peer={peer_id} owner={} generation={handshake_generation} retry={publish_attempt} has_active={} has_pending_responder={}",
                    reservation.owner, status.has_active, status.has_pending_responder
                )),
            );
            if status.has_active || status.has_pending_responder {
                drop(epoch_guard);
                drop(emit_guard);
                self.pending_handshakes
                    .lock()
                    .cancel_reservation_if_current(&peer_id, reservation.owner);
                return Ok(None);
            }

            let stage = self.peers.try_stage_probe_session_binding(
                &peer_id,
                session_id.clone(),
                Some(session_id.clone()),
                None,
                false,
            );
            match stage {
                None => {
                    let binding_contentions = publish_attempt.saturating_add(1);
                    self.timeline.emit(
                        "initiator_publish_probe_binding_contended",
                        None,
                        Some("connection_writer_contended"),
                        Some(format!(
                            "peer={peer_id} owner={} generation={handshake_generation} retry={binding_contentions}",
                            reservation.owner
                        )),
                    );
                    drop(epoch_guard);
                    drop(emit_guard);
                    self.retain_prepared_initiator_publish_retry(
                        &peer_id,
                        reservation,
                        PreparedInitiatorHandshake {
                            initiator,
                            initiation_bytes,
                            candidates,
                            candidate_sources,
                            session_id,
                            probe_ephemeral,
                            probe_ephemeral_public_key,
                        },
                        "connection_writer_contended",
                    );
                    return Ok(None);
                }
                Some(ProbeBindingStage::Staged | ProbeBindingStage::ReplayableDuplicate) => {
                    let mut initiator = Some(initiator);
                    let mut probe_ephemeral = Some(probe_ephemeral);
                    let insert_transaction = self.pending_handshakes.try_with(|state| {
                        state
                            .insert_reserved_if_current_with_generation(
                                peer_id.clone(),
                                reservation.owner,
                                initiator.take().expect("prepared initiator"),
                                Some(session_id.clone()),
                                probe_ephemeral.take(),
                                handshake_generation,
                                reservation.peer_session_generation,
                            )
                            .map(|pending_id| {
                                let attempts = state.attempts.entry(peer_id.clone()).or_insert(0);
                                *attempts = attempts.saturating_add(1);
                                (*attempts, pending_id)
                            })
                    });
                    let Some(inserted) = insert_transaction else {
                        drop(epoch_guard);
                        drop(emit_guard);
                        self.retain_prepared_initiator_publish_retry(
                            &peer_id,
                            reservation,
                            PreparedInitiatorHandshake {
                                initiator: initiator.take().expect("unconsumed initiator"),
                                initiation_bytes,
                                candidates,
                                candidate_sources,
                                session_id,
                                probe_ephemeral: probe_ephemeral
                                    .take()
                                    .expect("unconsumed Probe key"),
                                probe_ephemeral_public_key,
                            },
                            "pending_state_contended",
                        );
                        return Ok(None);
                    };
                    let Some((attempt_no, pending_id)) = inserted else {
                        drop(epoch_guard);
                        drop(emit_guard);
                        return Ok(None);
                    };
                    self.timeline.emit(
                        "initiator_publish_probe_binding_staged",
                        None,
                        None,
                        Some(format!(
                            "peer={peer_id} owner={} generation={handshake_generation} pending_id={pending_id} retries={publish_attempt}",
                            reservation.owner
                        )),
                    );
                    self.timeline.emit(
                        "initiator_publish_pending_inserted",
                        None,
                        None,
                        Some(format!(
                            "peer={peer_id} owner={} generation={handshake_generation} pending_id={pending_id}",
                            reservation.owner
                        )),
                    );
                    self.timeline.emit(
                        "initiator_session_staged",
                        None,
                        None,
                        Some(format!(
                            "peer={peer_id} owner={} generation={handshake_generation} pending_id={pending_id} session_fp={}",
                            reservation.owner,
                            handshake_token_fingerprint(Some(&session_id))
                        )),
                    );
                    drop(epoch_guard);
                    drop(emit_guard);
                    (attempt_no, pending_id)
                }
                Some(stage) => {
                    drop(epoch_guard);
                    drop(emit_guard);
                    self.pending_handshakes
                        .lock()
                        .cancel_reservation_if_current(&peer_id, reservation.owner);
                    return Err(DaemonError::Peer(format!(
                        "failed to stage Probe v2 handshake binding for {peer_id}: {stage:?}"
                    )));
                }
            }
        };

        // The pending-id now owns cleanup of the committed initiator. The
        // admission-only arbiter was released before any actor await above, so
        // an answer arriving while this POST is queued can consume the pending
        // transaction without self-locking the serial control loop.
        let punch_at_ms = relay_assisted_punch_at_ms();
        let Some(offer_result) = await_initiator_offer_or_cancellation(
            self.control.send_peer_offer_with_sources_punch_and_session(
                &peer_id,
                &candidates,
                &candidate_sources,
                &initiation_bytes,
                Some(punch_at_ms),
                Some(session_id.clone()),
                Some(probe_ephemeral_public_key),
            ),
            &mut reservation.cancellation,
        )
        .await
        else {
            self.timeline.emit(
                "initiator_offer_cancelled_before_control_result",
                None,
                Some("generation_cancelled"),
                Some(format!(
                    "peer={peer_id} owner={} generation={handshake_generation} session_fp={}",
                    reservation.owner,
                    handshake_token_fingerprint(Some(&session_id))
                )),
            );
            self.peers
                .discard_pending_probe_session_binding(&peer_id, &session_id)
                .await;
            return Ok(None);
        };

        self.timeline.emit(
            "initiator_offer_control_result",
            None,
            offer_result.as_ref().err().map(|_| "control_plane_error"),
            Some(format!(
                "peer={peer_id} owner={} generation={handshake_generation} session_fp={} delivered={}",
                reservation.owner,
                handshake_token_fingerprint(Some(&session_id)),
                offer_result.is_ok()
            )),
        );

        if offer_result.is_ok() {
            info!(
                "Sent WireGuard handshake initiation to {} ({} bytes, {} candidates, attempt {})",
                peer_id,
                initiation_bytes.len(),
                candidates.len(),
                attempt_no,
            );
            self.peers
                .record_direct_event(
                    &peer_id,
                    "peer_offer_sent",
                    None,
                    Some(candidates.len()),
                    None,
                    format!(
                        "sent offer handshake_bytes={} attempt={} punch_at_ms={punch_at_ms}",
                        initiation_bytes.len(),
                        attempt_no
                    ),
                )
                .await;
        } else {
            warn!(
                "WireGuard offer delivery to {} is ambiguous; retaining pending handshake until timeout",
                peer_id
            );
        }

        // Spawn timeout watcher that cleans up only the exact pending owner.
        let pending = self.pending_handshakes.clone();
        let timeout_peer = peer_id;
        let transport = self.transport.clone();
        let peers = self.peers.clone();
        let timeout_session_id = session_id;
        let generation = handshake_generation;
        let timeout_peer_session_generation = reservation.peer_session_generation;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)).await;
            // The pending transaction is the timeout's first authority.  A
            // matching answer, retry, leave/rejoin, or crossing responder may
            // have replaced this owner while the timer slept; in that case the
            // old timer must not publish a failure into the replacement
            // lifecycle (same-node ABA).
            let removed = {
                let mut state = pending.lock();
                if state.is_current(&timeout_peer, pending_id)
                    && state.peer_session_generation(&timeout_peer)
                        == Some(timeout_peer_session_generation)
                {
                    state.remove(&timeout_peer);
                    if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                        state.attempts.remove(&timeout_peer);
                    }
                    true
                } else {
                    false
                }
            };
            if !removed {
                return;
            }

            if peers.peer_session_is_current_sync(&timeout_peer, timeout_peer_session_generation)
                && !transport.has_session(&timeout_peer).await
                && peers
                    .peer_session_is_current_sync(&timeout_peer, timeout_peer_session_generation)
            {
                warn!("Handshake timeout for peer {timeout_peer}");
                let failed = peers
                    .record_direct_failure_for_generation_and_peer_session_with_local_endpoint(
                        &timeout_peer,
                        generation,
                        timeout_peer_session_generation,
                        REASON_HANDSHAKE_TIMEOUT,
                        "handshake timed out",
                        None,
                    )
                    .await;
                if failed {
                    peers
                        .mark_recovery_relay_backoff_for_peer_session(
                            &timeout_peer,
                            timeout_peer_session_generation,
                            "handshake timed out",
                        )
                        .await;
                }
            }
            peers
                .discard_pending_probe_session_binding(&timeout_peer, &timeout_session_id)
                .await;
        });

        offer_result?;
        Ok(Some(punch_at_ms))
    }

    /// Run the post-admission event work for PeerJoined/PeerUpdated.  This is
    /// deliberately called by the bounded control-event work set, never inline
    /// from the serial receiver loop.
    async fn run_event_initiator_handshake(
        &self,
        peer_info: control::PeerInfo,
        mut reservation: HandshakeStartReservation,
    ) {
        let peer_id = peer_info.node_id.clone();
        match self
            .run_reserved_initiator_handshake(&peer_info, &mut reservation)
            .await
        {
            Ok(Some(punch_at_ms)) => {
                self.start_hole_punch_at(&peer_id, Some(punch_at_ms), None, None)
                    .await;
            }
            Ok(None) if reservation.disposition == HandshakeStartDisposition::RetryScheduled => {}
            Ok(None) if !*reservation.cancellation.borrow() => {
                self.publish_current_candidates_to_peer(&peer_id, "peer event")
                    .await;
            }
            Ok(None) => {}
            Err(err) => {
                warn!("Failed to initiate WireGuard handshake with {peer_id}: {err}");
                self.start_hole_punch(&peer_id).await;
            }
        }
        if reservation.disposition != HandshakeStartDisposition::RetryScheduled {
            self.pending_handshakes
                .lock()
                .cancel_reservation_if_current(&peer_id, reservation.owner);
        }
    }
}
