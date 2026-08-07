impl Daemon {
    /// Fast admission used by the serial control event loop before it puts
    /// potentially slow initiator work into its bounded work set.
    async fn reserve_event_initiator_handshake(
        &self,
        peer_id: &str,
    ) -> Option<HandshakeStartReservation> {
        let mut state = self.pending_handshakes.lock().await;
        let reservation = state.reserve_start_with_owner(peer_id)?;
        if state.attempts.get(peer_id).copied().unwrap_or(0) >= MAX_HANDSHAKE_ATTEMPTS {
            state.attempts.remove(peer_id);
        }
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

        let handshake_guard = self.handshake_arbiter.acquire(&peer_info.node_id).await;
        let status = self.transport.session_status(&peer_info.node_id).await;
        if status.has_active || status.has_pending_responder {
            drop(handshake_guard);
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
            return Ok(None);
        }

        let identity = match self.local_identity() {
            Ok(identity) => identity,
            Err(error) => {
                drop(handshake_guard);
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
                drop(handshake_guard);
                self.pending_handshakes
                    .lock()
                    .await
                    .cancel_reservation_if_current(&peer_info.node_id, reservation.owner);
                return Err(error);
            }
        };
        if !local_is_designated_handshake_initiator(&identity.public_key(), &peer_public) {
            drop(handshake_guard);
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
                drop(handshake_guard);
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

        // Candidate gathering may wait on a live STUN fan-out.  Keep the
        // owner reservation, but never keep the per-peer arbiter across it.
        drop(handshake_guard);
        let (candidates, candidate_sources) = tokio::select! {
            candidates = self.local_candidate_set_for_signal("handshake offer") => candidates,
            changed = reservation.cancellation.changed() => {
                if changed.is_err() || *reservation.cancellation.borrow() {
                    return Ok(None);
                }
                return Ok(None);
            }
        };
        if *reservation.cancellation.borrow() {
            return Ok(None);
        }

        // Re-enter the short mutation boundary.  A responder may have won
        // while gathering candidates; only the owner that is still current may
        // turn its reservation into a pending initiator transaction.
        let handshake_guard = self.handshake_arbiter.acquire(&peer_info.node_id).await;
        let status = self.transport.session_status(&peer_info.node_id).await;
        if status.has_active || status.has_pending_responder {
            drop(handshake_guard);
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
                .insert_reserved_if_current(
                    peer_id.clone(),
                    reservation.owner,
                    initiator,
                    Some(session_id.clone()),
                    Some(probe_ephemeral),
                )
                .map(|pending_id| {
                    let attempts = state.attempts.entry(peer_id.clone()).or_insert(0);
                    *attempts = attempts.saturating_add(1);
                    (*attempts, pending_id)
                })
        }) else {
            drop(handshake_guard);
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
            drop(handshake_guard);
            return Err(DaemonError::Peer(format!(
                "failed to stage Probe v2 handshake binding for {peer_id}"
            )));
        }

        // The pending-id now owns cleanup of the committed initiator.  Release
        // the arbiter before the HTTP request; an answer arriving while this
        // POST is queued must be able to consume the pending transaction.
        drop(handshake_guard);
        let punch_at_ms = relay_assisted_punch_at_ms();
        let offer_result = self
            .control
            .send_peer_offer_with_sources_punch_and_session(
                &peer_id,
                &candidates,
                &candidate_sources,
                &initiation_bytes,
                Some(punch_at_ms),
                Some(session_id.clone()),
                Some(probe_ephemeral_public_key),
            )
            .await;

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
        let generation = self.peers.current_network_generation().await;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)).await;
            if !transport.has_session(&timeout_peer).await {
                warn!("Handshake timeout for peer {timeout_peer}");
                peers
                    .record_direct_failure_for_generation(
                        &timeout_peer,
                        generation,
                        REASON_HANDSHAKE_TIMEOUT,
                        "handshake timed out",
                    )
                    .await;
            }
            let removed = {
                let mut state = pending.lock().await;
                if state.is_current(&timeout_peer, pending_id) {
                    state.remove(&timeout_peer);
                    if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                        state.attempts.remove(&timeout_peer);
                    }
                    true
                } else {
                    false
                }
            };
            if removed {
                peers
                    .discard_pending_probe_session_binding(&timeout_peer, &timeout_session_id)
                    .await;
            }
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
