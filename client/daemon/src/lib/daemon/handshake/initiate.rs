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

impl Daemon {
    /// Fast admission used by the serial control event loop before it puts
    /// potentially slow initiator work into its bounded work set.
    async fn reserve_event_initiator_handshake(
        &self,
        peer_id: &str,
    ) -> Option<HandshakeStartReservation> {
        // Serialize replacement cleanup with offer/answer processing.  Without
        // this short arbiter boundary a new-generation trigger could remove a
        // stale pending initiator while the responder path was simultaneously
        // staging its Probe binding for the same peer.
        let _handshake_guard = self.handshake_arbiter.acquire(peer_id).await;
        let network_generation = self.peers.current_network_generation_sync();
        let peer_session_generation = self.peers.peer_session_generation_sync(peer_id)?;
        let stale_session_id = self
            .pending_handshakes
            .lock()
            .await
            .remove_stale_pending_for_generation(
                peer_id,
                network_generation,
                peer_session_generation,
            );
        if let Some(session_id) = stale_session_id {
            self.peers
                .discard_pending_probe_session_binding(peer_id, &session_id)
                .await;
        }
        let mut state = self.pending_handshakes.lock().await;
        let reservation = state.reserve_start_with_owner_at_generation(
            peer_id,
            network_generation,
            peer_session_generation,
        )?;
        if state.attempts.get(peer_id).copied().unwrap_or(0) >= MAX_HANDSHAKE_ATTEMPTS {
            state.attempts.remove(peer_id);
        }
        self.timeline.emit(
            "initiator_handshake_reserved",
            None,
            None,
            Some(format!(
                "peer={peer_id} owner={} generation={network_generation}",
                reservation.owner
            )),
        );
        Some(reservation)
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
                .await
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }
        let lock_wait_started = Instant::now();
        self.timeline.emit(
            "initiator_handshake_lock_wait",
            None,
            None,
            Some(format!(
                "peer={} owner={} generation={} phase=preparation",
                peer_info.node_id, reservation.owner, handshake_generation
            )),
        );
        let handshake_guard = self.handshake_arbiter.acquire(&peer_info.node_id).await;
        self.timeline.emit(
            "initiator_handshake_lock_acquired",
            None,
            None,
            Some(format!(
                "peer={} owner={} generation={} phase=preparation wait_ms={}",
                peer_info.node_id,
                reservation.owner,
                handshake_generation,
                lock_wait_started.elapsed().as_millis()
            )),
        );
        if !self.peers.peer_session_is_current_sync(
            &peer_info.node_id,
            reservation.peer_session_generation,
        ) {
            drop(handshake_guard);
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }
        // This worker is cooperatively polled by the serial control loop. The
        // arbiter is an admission boundary only: keeping it across the actor
        // status await would self-deadlock if PeerLeft/offline entered the
        // serial branch, waited for this guard, and thereby stopped polling the
        // worker which owns it. The reservation/lifecycle stamp is revalidated
        // at the later publish transaction.
        drop(handshake_guard);
        let status = self.transport.session_status(&peer_info.node_id).await;
        if status.has_active || status.has_pending_responder {
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }

        let identity = match self.local_identity() {
            Ok(identity) => identity,
            Err(error) => {
                self.pending_handshakes
                    .lock()
                    .await
                    .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                return Err(error);
            }
        };
        let peer_public = match decode_x25519_key(&peer_info.public_key, "peer public key") {
            Ok(peer_public) => peer_public,
            Err(error) => {
                self.pending_handshakes
                    .lock()
                    .await
                    .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                return Err(error);
            }
        };
        if !local_is_designated_handshake_initiator(&identity.public_key(), &peer_public) {
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }

        let mut initiator = HandshakeInitiator::new(identity, peer_public, None);
        let initiation = match initiator.create_initiation() {
            Ok(initiation) => initiation,
            Err(error) => {
                self.pending_handshakes
                    .lock()
                    .await
                    .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                return Err(DaemonError::Peer(format!(
                    "WireGuard initiation failed: {error}"
                )));
            }
        };
        let initiation_bytes = initiation.to_bytes();

        // Candidate gathering may wait on a live STUN fan-out. Keep the owner
        // reservation; the arbiter was already released before actor I/O.
        let (candidates, candidate_sources) = {
            let snapshot = self.cached_local_candidate_set().await;
            let mut relay_available = self.relay_available_tx.subscribe();
            let relay_is_available = *relay_available.borrow();
            if let Some(snapshot) = relay_first_candidate_shortcut(
                snapshot.0,
                snapshot.1,
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
                            self.wait_for_local_candidate_set().await
                        }
                    }
                    candidates = self.wait_for_local_candidate_set() => candidates,
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

        // Re-enter the short mutation boundary.  A responder may have won
        // while gathering candidates; only the owner that is still current may
        // turn its reservation into a pending initiator transaction.
        let lock_wait_started = Instant::now();
        self.timeline.emit(
            "initiator_handshake_lock_wait",
            None,
            None,
            Some(format!(
                "peer={} owner={} generation={} phase=publish",
                peer_info.node_id, reservation.owner, handshake_generation
            )),
        );
        let handshake_guard = self.handshake_arbiter.acquire(&peer_info.node_id).await;
        self.timeline.emit(
            "initiator_handshake_lock_acquired",
            None,
            None,
            Some(format!(
                "peer={} owner={} generation={} phase=publish wait_ms={}",
                peer_info.node_id,
                reservation.owner,
                handshake_generation,
                lock_wait_started.elapsed().as_millis()
            )),
        );
        // As above, never let a cooperatively-polled worker own the arbiter
        // while awaiting the emit/session actors. Exact reservation, network
        // generation and peer lifecycle checks below form the commit fence.
        drop(handshake_guard);
        // The outbound worker establishes the canonical lifecycle order
        // `emit -> generation -> session/connection`. Acquire emit before the
        // generation gate so a rekey or generation advance cannot deadlock
        // against a live TUN encryption turn.
        let emit_guard = self
            .transport
            .acquire_outbound_emit_guard(&peer_info.node_id)
            .await;
        let epoch_gate = self.peers.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        if self.peers.current_network_generation_sync() != handshake_generation
            || !self.peers.peer_session_is_current_sync(
                &peer_info.node_id,
                reservation.peer_session_generation,
            )
        {
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }
        let status = self.transport.session_status(&peer_info.node_id).await;
        if status.has_active || status.has_pending_responder {
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }

        let peer_id = peer_info.node_id.clone();
        let session_id = new_probe_session_id();
        let (probe_ephemeral, probe_ephemeral_public_key) = new_probe_ephemeral_keypair();
        let Some((attempt_no, pending_id)) = ({
            let mut state = self.pending_handshakes.lock().await;
            state
                .insert_reserved_if_current_with_generation(
                    peer_id.clone(),
                    reservation.owner,
                    initiator,
                    Some(session_id.clone()),
                    Some(probe_ephemeral),
                    handshake_generation,
                    reservation.peer_session_generation,
                )
                .map(|pending_id| {
                    let attempts = state.attempts.entry(peer_id.clone()).or_insert(0);
                    *attempts = attempts.saturating_add(1);
                    (*attempts, pending_id)
                })
        }) else {
            return Ok(None);
        };
        if self
            .peers
            .stage_probe_session_binding(
                &peer_id,
                session_id.clone(),
                Some(session_id.clone()),
                None,
                false,
            )
            .await
            != ProbeBindingStage::Staged
        {
            let removed = {
                let mut state = self.pending_handshakes.lock().await;
                if state.is_current(&peer_id, pending_id) {
                    state.remove(&peer_id);
                    true
                } else {
                    false
                }
            };
            if removed {
                self.peers
                    .discard_pending_probe_session_binding(&peer_id, &session_id)
                    .await;
            }
            return Err(DaemonError::Peer(format!(
                "failed to stage Probe v2 handshake binding for {peer_id}"
            )));
        }
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
                let mut state = pending.lock().await;
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

            if peers.peer_session_is_current_sync(
                &timeout_peer,
                timeout_peer_session_generation,
            ) && !transport.has_session(&timeout_peer).await
                && peers.peer_session_is_current_sync(
                    &timeout_peer,
                    timeout_peer_session_generation,
                )
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
    }
}
