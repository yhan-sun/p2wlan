impl UdpTransport {
    /// Commit a modern responder handshake transaction from an authenticated
    /// pending Probe-v2 packet. WireGuard is promoted first; Probe is only
    /// promoted for the same exact token after that succeeds.
    #[cfg(test)]
    async fn confirm_pending_probe_adoption(&self, peer_id: &str, token: &str) -> bool {
        let Some(wireguard) = self.wireguard_transport.as_ref() else {
            return false;
        };
        if !self
            .peers
            .confirm_probe_and_transport_transaction(peer_id, token, || async {
                matches!(
                    wireguard.confirm_responder_session(peer_id, token).await,
                    ResponderSessionConfirmation::Promoted
                        | ResponderSessionConfirmation::AlreadyActive
                )
            })
            .await
        {
            return false;
        }
        wireguard
            .acknowledge_promoted_responder_token(peer_id, token)
            .await;
        true
    }

    /// Commit the same cross-layer transaction when the inbound handler
    /// acquired WireGuard's emit guard before UDP adoption and the global
    /// network-epoch gate.
    async fn confirm_pending_probe_adoption_with_emit_guard(
        &self,
        peer_id: &str,
        token: &str,
        emit_guard: &tokio::sync::OwnedMutexGuard<()>,
    ) -> bool {
        let Some(wireguard) = self.wireguard_transport.as_ref() else {
            return false;
        };
        if !self
            .peers
            .confirm_probe_and_transport_transaction(peer_id, token, || async {
                matches!(
                    wireguard
                        .confirm_responder_session_with_emit_guard(peer_id, token, emit_guard)
                        .await,
                    ResponderSessionConfirmation::Promoted
                        | ResponderSessionConfirmation::AlreadyActive
                )
            })
            .await
        {
            return false;
        }
        wireguard
            .acknowledge_promoted_responder_token(peer_id, token)
            .await;
        true
    }

    /// Re-insert a matched pending probe after a failed transaction check,
    /// unless the peer was cleaned up since the probe was sent.
    ///
    /// The cleanup epoch check, the insert and the re-verification close the
    /// race with `clear_pending_probes_for_peer`: whichever of the two runs
    /// last decides, and a cleanup can never be undone by a late re-insertion
    /// of an old pending entry.  No lock nesting: the pending lock is never
    /// held while the socket-state lock is re-read.
    async fn restore_pending_probe_if_peer_still_clean(
        &self,
        nonce: ProbeNonce,
        pending: PendingProbe,
    ) -> bool {
        let Some(peer_id) = pending.peer_id.as_deref() else {
            return false;
        };
        if pending.is_expired(Instant::now()) {
            return false;
        }
        loop {
            let cleanup_epoch = self.peer_probe_cleanup_epoch(peer_id).await;
            if pending.cleanup_epoch != cleanup_epoch {
                return false;
            }
            self.pending_probes
                .lock()
                .await
                .entry(nonce)
                .or_insert_with(|| pending.clone());
            if self.peer_probe_cleanup_epoch(peer_id).await == cleanup_epoch {
                return true;
            }
            // A cleanup ran between the check and the insert: drop the entry
            // we just restored and retry (the retry will observe the new
            // epoch and refuse).
            self.pending_probes.lock().await.remove(&nonce);
        }
    }

    /// Whether the peer was NOT cleaned up since `pending` was sent.
    ///
    /// The ACK handler re-verifies this AFTER removing the matched pending
    /// entry and BEFORE any adoption (remember socket, learn endpoint, record
    /// direct success, promote Direct): a cleanup that raced the ACK must
    /// leave nothing behind.
    async fn peer_still_clean(&self, pending: &PendingProbe) -> bool {
        let Some(peer_id) = pending.peer_id.as_deref() else {
            return false;
        };
        let current = self.peer_probe_cleanup_epoch(peer_id).await;
        if current != pending.cleanup_epoch {
            debug!(
                "cleanup epoch mismatch for peer {peer_id}: pending ACK stamped epoch {} but the peer was cleaned to epoch {current}; adoption skipped",
                pending.cleanup_epoch
            );
            false
        } else if self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or(0)
            != pending.remote_candidate_epoch
        {
            debug!(
                "remote candidate epoch mismatch for peer {peer_id}; pending ACK stamped epoch {} but the peer is now on a newer candidate set; adoption skipped",
                pending.remote_candidate_epoch
            );
            false
        } else {
            true
        }
    }

    /// Receive encrypted UDP datagrams until the socket or channel closes.
    pub async fn run_inbound(
        self,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        let sockets = self.active_sockets().to_vec();
        let mut readers = JoinSet::new();
        for (socket_index, socket) in sockets.into_iter().enumerate() {
            let transport = self.clone();
            let inbound_tx = inbound_tx.clone();
            readers.spawn(async move {
                transport
                    .run_inbound_socket(socket_index, socket, inbound_tx)
                    .await
            });
        }

        match readers.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(DaemonError::Network(format!(
                "UDP socket reader task failed: {error}"
            ))),
            None => Ok(()),
        }
    }

    async fn run_inbound_socket(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        self.run_inbound_socket_inner(socket_index, socket, inbound_tx, None, None)
            .await
    }

    /// Run an inbound reader that stops when `shutdown_rx` turns true.
    ///
    /// Dedicated fresh-mapping punch sockets use this so a superseded punch
    /// generation can close its socket deterministically instead of leaking
    /// the reader loop.
    async fn run_dynamic_inbound_socket(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        mut shutdown_rx: watch::Receiver<bool>,
        reader_ready_tx: oneshot::Sender<bool>,
    ) {
        let Some(inbound_tx) = self.inbound_channel() else {
            debug!("Dropped dynamic UDP socket reader {socket_index}: no inbound channel attached");
            return;
        };
        let _ = self
            .run_inbound_socket_inner(
                socket_index,
                socket,
                inbound_tx,
                Some(&mut shutdown_rx),
                Some(reader_ready_tx),
            )
            .await;
    }

    /// Receive one datagram and publish the dynamic-reader readiness handshake
    /// from the first real pending poll of the socket future. A task spawn is
    /// not a scheduling barrier, and consuming an already-queued unrelated
    /// datagram is not a rearm barrier either: retain the sender across every
    /// immediately-ready packet until `recv_from` actually returns `Pending`
    /// and registers readiness for the next datagram.
    async fn recv_from_with_reader_ready(
        socket: &UdpSocket,
        buf: &mut [u8],
        reader_ready_tx: &mut Option<oneshot::Sender<bool>>,
    ) -> std::io::Result<(usize, SocketAddr)> {
        let receive = socket.recv_from(buf);
        tokio::pin!(receive);
        std::future::poll_fn(|context| {
            let result = std::future::Future::poll(receive.as_mut(), context);
            match &result {
                std::task::Poll::Pending => {
                    if let Some(reader_ready_tx) = reader_ready_tx.take() {
                        let _ = reader_ready_tx.send(true);
                    }
                }
                std::task::Poll::Ready(Err(_)) => {
                    if let Some(reader_ready_tx) = reader_ready_tx.take() {
                        let _ = reader_ready_tx.send(false);
                    }
                }
                std::task::Poll::Ready(Ok(_)) => {}
            }
            result
        })
        .await
    }

    async fn run_inbound_socket_inner(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
        mut shutdown_rx: Option<&mut watch::Receiver<bool>>,
        mut reader_ready_tx: Option<oneshot::Sender<bool>>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65_535];

        loop {
            // The shutdown signal is selected TOGETHER with the receive: a
            // reader parked in `recv_from` must never stay blocked forever
            // when the owning generation is cancelled before its socket was
            // ever inserted (the shutdown sender then drops, closing the
            // channel, and this arm fires).  Without the select, the reader
            // would block in `recv_from` for as long as the socket Arc it
            // itself holds keeps the file descriptor alive — a socket/reader
            // leak.
            //
            // The exit decision reads the VALUE itself (`borrow_and_update`)
            // and never relies on `has_changed()` after `changed()`: `changed`
            // consumes the notification, so `has_changed()` afterwards can
            // report false even though the stop value is already visible —
            // the reader would spin forever instead of exiting.
            let packet = match shutdown_rx.as_deref_mut() {
                Some(shutdown_rx) => {
                    tokio::select! {
                        change = shutdown_rx.changed() => {
                            match change {
                                // The sender was dropped (pre-insert
                                // cancellation) or the stop signal was sent
                                // (detach after the drain finished): either
                                // way the reader must exit.
                                Err(_) => return Ok(()),
                                Ok(()) if *shutdown_rx.borrow_and_update() => {
                                    return Ok(());
                                }
                                // A notification without the stop value (only
                                // possible if a future change type is added):
                                // keep receiving.
                                Ok(()) => continue,
                            }
                        }
                        packet = Self::recv_from_with_reader_ready(
                            &socket,
                            &mut buf,
                            &mut reader_ready_tx,
                        ) => packet,
                    }
                }
                None => socket.recv_from(&mut buf).await,
            };
            let (n, source) = match packet {
                Ok(packet) => packet,
                Err(err) if is_ignorable_udp_receive_error(&err) => {
                    debug!("Ignoring transient UDP receive error on direct transport: {err}");
                    continue;
                }
                Err(err) => {
                    return Err(DaemonError::Network(format!(
                        "UDP receive on direct transport failed: {err}"
                    )));
                }
            };

            if n == 0 {
                continue;
            }

            let data = &buf[..n];

            // STUN responses are completion signals for the live candidate
            // gather.  Dispatch them before any peer-manager or diagnostics
            // await: startup also receives a burst of direct probes and a
            // slow peer/diagnostic lock must not make a healthy observer look
            // like `UdpBlocked` after the bounded startup deadline.
            if let Some(transaction_id) = stun_transaction_id(data) {
                let waiter = self.stun_waiters.lock().await.remove(&transaction_id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send(StunResponse {
                        data: data.to_vec(),
                        source,
                    });
                } else {
                    trace!("Ignored unmatched STUN response from {source}");
                }
                continue;
            }

            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.datagrams_received = metrics.datagrams_received.saturating_add(1)
            })
            .await;

            let known_peer_ip = self.peers.has_known_public_candidate_ip(source.ip()).await;
            if known_peer_ip {
                self.update_socket_diagnostics(socket_index, |metrics| {
                    metrics.known_peer_ip_datagrams_received =
                        metrics.known_peer_ip_datagrams_received.saturating_add(1)
                })
                .await;
            }

            if is_authenticated_punch_candidate(data) {
                self.update_socket_diagnostics(socket_index, |metrics| {
                    metrics.authenticated_probe_packets_received = metrics
                        .authenticated_probe_packets_received
                        .saturating_add(1)
                })
                .await;
                let Some(identity) = peek_authenticated_punch_identity(data) else {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_malformed =
                            metrics.authenticated_probe_malformed.saturating_add(1)
                    })
                    .await;
                    trace!("Ignored malformed authenticated UDP probe from {source}");
                    continue;
                };
                let Some(local_node_id) = self.local_node_id.as_deref() else {
                    trace!(
                        "Ignored authenticated UDP probe from {source}; local node ID is unknown"
                    );
                    continue;
                };
                if identity.target_node_id != local_node_id {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_wrong_target =
                            metrics.authenticated_probe_wrong_target.saturating_add(1)
                    })
                    .await;
                    trace!(
                        "Ignored authenticated UDP probe from {} for target {}",
                        identity.source_node_id,
                        identity.target_node_id
                    );
                    continue;
                }
                let key_candidates = self
                    .peers
                    .probe_key_candidates_for_peer(&identity.source_node_id)
                    .await;
                if key_candidates.is_empty() {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_no_key =
                            metrics.authenticated_probe_no_key.saturating_add(1)
                    })
                    .await;
                    trace!(
                        "Ignored authenticated UDP probe from {}; no Probe v2 MAC key",
                        identity.source_node_id
                    );
                    continue;
                }
                let Some((packet, key_candidate)) =
                    key_candidates.into_iter().find_map(|candidate| {
                        decode_authenticated_punch_packet(data, &candidate.key)
                            .map(|packet| (packet, candidate))
                    })
                else {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.authenticated_probe_invalid_mac =
                            metrics.authenticated_probe_invalid_mac.saturating_add(1)
                    })
                    .await;
                    trace!(
                        "Ignored authenticated UDP probe from {}; invalid MAC",
                        identity.source_node_id
                    );
                    continue;
                };
                let pending_token = match &key_candidate.role {
                    ProbeKeyRole::Pending { token } => Some(token.clone()),
                    _ => None,
                };
                let matched_probe_session_id = key_candidate.session_id.clone();
                let peer_session_generation = key_candidate.session_generation;
                let key = key_candidate.key;
                #[cfg(test)]
                let authenticated_probe_verify_gate = self
                    .peers
                    .pause_after_authenticated_probe_verify_for_test(&identity.source_node_id)
                    .await;
                // A pending Probe key may promote the matching WireGuard
                // responder session. Reserve its counter-ordering turn before
                // either branch acquires adoption -> epoch, preserving the
                // canonical cross-layer order `emit -> adoption -> epoch`.
                // The lifecycle stamp below is still authoritative if the
                // peer changes while this per-peer lock is contended.
                let pending_emit_guard =
                    match (pending_token.as_ref(), self.wireguard_transport.as_ref()) {
                        (Some(_), Some(wireguard)) => {
                            #[cfg(test)]
                            if let Some(gate) = authenticated_probe_verify_gate.as_ref() {
                                gate.pending_emit_wait_started.notify_one();
                            }
                            Some(
                                wireguard
                                    .acquire_outbound_emit_guard(&identity.source_node_id)
                                    .await,
                            )
                        }
                        _ => None,
                    };
                // Probe v2 carries the *sender's* local generation.  Timeout
                // diagnostics are scoped to this daemon's punch generation,
                // so never use the remote counter as the local map key.
                // Matched ACKs below are attributed even more precisely to
                // the stamped pending-probe generation.
                let received_local_generation = self.peers.current_network_generation().await;
                match packet.kind {
                    PunchPacketKind::Punch => {
                        let mut hard_hard_winner_promoted = false;
                        // Bind every effect of the authenticated packet to the
                        // exact peer lifecycle that owned the MAC key.  The
                        // lifecycle writers use the shared epoch gate while
                        // publishing a new session generation; holding
                        // adoption -> epoch here therefore makes the check,
                        // replay/rate admission, ACK and all evidence adoption
                        // one transaction.  A verified packet from an old
                        // same-ID incarnation is rejected before it can even
                        // consume the replacement session's replay budget.
                        let adoption = self.adoption_lock_for(&identity.source_node_id).await;
                        let adoption_guard = adoption.lock().await;
                        let epoch_guard = self.network_epoch_gate.lock().await;
                        if !self.peers.peer_session_is_current_sync(
                            &identity.source_node_id,
                            peer_session_generation,
                        ) {
                            trace!(
                                "Ignored authenticated UDP punch from {}; peer lifecycle changed after MAC verification",
                                identity.source_node_id
                            );
                            continue;
                        }
                        self.update_peer_probe_rx_diagnostics(
                            &identity.source_node_id,
                            received_local_generation,
                            matched_probe_session_id.as_deref(),
                            |snapshot| {
                                if known_peer_ip {
                                    snapshot.known_peer_ip_datagrams_received =
                                        snapshot.known_peer_ip_datagrams_received.saturating_add(1);
                                }
                                snapshot.authenticated_probe_packets_received = snapshot
                                    .authenticated_probe_packets_received
                                    .saturating_add(1);
                            },
                        )
                        .await;
                        let punch_generation = packet.generation.unwrap_or(identity.generation);
                        match self
                            .admit_authenticated_punch(
                                &identity.source_node_id,
                                punch_generation,
                                packet.kind,
                                packet.nonce,
                                source,
                            )
                            .await
                        {
                            AuthenticatedPunchAdmission::Accepted => {
                                if let Some(token) = pending_token.as_deref() {
                                    let promoted = match pending_emit_guard.as_ref() {
                                        Some(emit_guard) => {
                                            self.confirm_pending_probe_adoption_with_emit_guard(
                                                &identity.source_node_id,
                                                token,
                                                emit_guard,
                                            )
                                            .await
                                        }
                                        None => false,
                                    };
                                    if promoted {
                                        debug!(
                                            "Promoted matching WireGuard and Probe v2 bindings for peer {} after accepted authenticated punch",
                                            identity.source_node_id
                                        );
                                    } else {
                                        self.rollback_authenticated_punch_replay_admission(
                                            &identity.source_node_id,
                                            punch_generation,
                                            packet.kind,
                                            packet.nonce,
                                        )
                                        .await;
                                        debug!(
                                            "Ignored accepted pending Probe v2 punch from {}; matching WireGuard/Probe transaction is unavailable",
                                            identity.source_node_id
                                        );
                                        continue;
                                    }
                                }
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.authenticated_probe_punches_received = metrics
                                        .authenticated_probe_punches_received
                                        .saturating_add(1)
                                })
                                .await;
                                if let Some(token) =
                                    self.hard_hard_socket_token(socket_index).await
                                {
                                    hard_hard_winner_promoted = self
                                        .promote_hard_hard_winner_in_epoch(
                                            &epoch_guard,
                                            &identity.source_node_id,
                                            &token,
                                            socket_index,
                                            received_local_generation,
                                        )
                                        .await;
                                }
                            }
                            AuthenticatedPunchAdmission::Replay => {
                                if pending_token.is_some() {
                                    // A replay that still authenticated only
                                    // as Pending means the original Accepted
                                    // packet did not finish the matching WG +
                                    // Probe transaction. ACKing it would let
                                    // the sender infer Direct success even
                                    // though this side deliberately refused
                                    // adoption.
                                    debug!(
                                        "Ignored replayed pending Probe v2 punch from peer {} at {}; transaction is not active",
                                        identity.source_node_id, source
                                    );
                                    continue;
                                }
                                let generation = self.peers.current_network_generation().await;
                                let ack = build_authenticated_punch_ack(
                                    packet.nonce,
                                    local_node_id,
                                    &identity.source_node_id,
                                    generation,
                                    &key,
                                );
                                match socket.send_to(&ack, source).await {
                                    Ok(_) => {
                                        self.update_socket_diagnostics(socket_index, |metrics| {
                                            metrics.probe_acks_sent += 1
                                        })
                                        .await;
                                        trace!(
                                            "ACKed replayed authenticated UDP punch from peer {} at {} without mutating candidate state",
                                            identity.source_node_id, source
                                        );
                                    }
                                    Err(err) => debug!(
                                        "Failed to ACK replayed authenticated UDP punch from peer {} at {}: {}",
                                        identity.source_node_id, source, err
                                    ),
                                }
                                continue;
                            }
                            AuthenticatedPunchAdmission::RateLimited => {
                                debug!(
                                    "Rate-limited authenticated UDP punch from peer {} at {}",
                                    identity.source_node_id, source
                                );
                                continue;
                            }
                        }

                        // Reply on the receiving socket before doing any peer
                        // learning or candidate bookkeeping. NAT filters keep
                        // the return window short, and the sender's nonce is
                        // only pending for this punch session.
                        let generation = self.peers.current_network_generation().await;
                        let ack = build_authenticated_punch_ack(
                            packet.nonce,
                            local_node_id,
                            &identity.source_node_id,
                            generation,
                            &key,
                        );
                        let ack_sent = match self
                            .send_punch_ack_burst(
                                socket_index,
                                socket.clone(),
                                ack,
                                source,
                                identity.source_node_id.clone(),
                            )
                            .await
                        {
                            Ok(()) => true,
                            Err(err) => {
                                warn!(
                                    "Failed to immediately ACK authenticated UDP punch from peer {} at {}: {}",
                                    identity.source_node_id, source, err
                                );
                                false
                            }
                        };

                        let learned = self
                            .peers
                            .learn_authenticated_endpoint_in_epoch(
                                &epoch_guard,
                                &identity.source_node_id,
                                source,
                            )
                            .await;
                        if !learned {
                            trace!(
                                "Ignored authenticated UDP punch from {}; peer disappeared before endpoint learning",
                                identity.source_node_id
                            );
                            continue;
                        }
                        self.peers
                            .record_predicted_window_hit_if_predicted(
                                &identity.source_node_id,
                                source,
                            )
                            .await;
                        self.peers
                            .record_direct_probe_success_with_local_endpoint(
                                &identity.source_node_id,
                                source,
                                socket.local_addr().ok(),
                            )
                            .await;
                        if packet.use_candidate {
                            self.peers
                                .record_direct_nomination_check_with_local_endpoint(
                                    &identity.source_node_id,
                                    source,
                                    socket.local_addr().ok(),
                                )
                                .await;
                        }
                        let _ = self
                            .remember_peer_socket_for_generation_in_epoch(
                                &epoch_guard,
                                &identity.source_node_id,
                                socket_index,
                                generation,
                                SocketEvidence::Fresh,
                            )
                            .await;
                        self.notify_peer_reflexive_observation(&identity.source_node_id, source)
                            .await;

                        // Triggered probes register pending state under the
                        // epoch gate themselves. Release this transaction
                        // first to preserve the single acquisition order.
                        drop(epoch_guard);
                        drop(adoption_guard);

                        if ack_sent {
                            debug!(
                                "Received authenticated UDP punch from peer {} at {}; sent immediate ACK burst",
                                identity.source_node_id, source
                            );
                            self.trigger_peer_reflexive_check(
                                socket_index,
                                &identity.source_node_id,
                                source,
                            )
                            .await;
                            if hard_hard_winner_promoted {
                                // The peer-reflexive worker also submits this
                                // observation, but it is asynchronous.  A
                                // newly selected Hard↔Hard winner must get a
                                // validation ingress on the already-finalized
                                // socket before the short rendezvous cleanup
                                // can race that worker.
                                self.trigger_encrypted_validation(
                                    &identity.source_node_id,
                                    source,
                                )
                                .await;
                            }
                        } else {
                            debug!(
                                "Received authenticated UDP punch from peer {} at {} without an ACK",
                                identity.source_node_id, source
                            );
                        }
                    }
                    PunchPacketKind::Ack => {
                        self.update_socket_diagnostics(socket_index, |metrics| {
                            metrics.authenticated_probe_acks_observed =
                                metrics.authenticated_probe_acks_observed.saturating_add(1)
                        })
                        .await;
                        // The whole match -> verify -> adopt sequence runs
                        // under the peer's adoption lock: a PeerLeft /
                        // offline / public-key-change cleanup can never
                        // interleave between the pending removal and the
                        // adoption awaits, so a late ACK can neither match
                        // nor recreate affinity/candidate/endpoint state for
                        // a peer that was cleaned.  The cleanup that loses
                        // the lock runs after and removes everything this
                        // ACK created; the cleanup that wins the lock bumps
                        // the epoch and the fence below refuses the adoption.
                        let adoption = self.adoption_lock_for(&identity.source_node_id).await;
                        let _adoption_guard = adoption.lock().await;
                        let epoch_guard = self.network_epoch_gate.lock().await;
                        if !self.peers.peer_session_is_current_sync(
                            &identity.source_node_id,
                            peer_session_generation,
                        ) {
                            trace!(
                                "Ignored authenticated UDP ACK from {}; peer lifecycle changed after MAC verification",
                                identity.source_node_id
                            );
                            continue;
                        }
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let remote_candidate_epoch = self
                                .peers
                                .current_remote_candidate_epoch(&identity.source_node_id)
                                .await
                                .unwrap_or(0);
                            let direct_commit_seq = self
                                .peers
                                .direct_commit_seq_sync(&identity.source_node_id)
                                .unwrap_or(0);
                            // The cleanup epoch is read under the socket-state
                            // lock and the pending match runs under it: an ACK
                            // can only match a pending probe whose stamped
                            // cleanup epoch still equals the peer's current
                            // one, so an ACK from before an offline /
                            // PeerLeft / endpoint / public-key cleanup can
                            // never match a probe sent after it.
                            let state = self.socket_state.lock().await;
                            let cleanup_epoch = state
                                .probe_cleanup_epochs
                                .get(identity.source_node_id.as_str())
                                .copied()
                                .unwrap_or(0);
                            let mut pending_probes = self.pending_probes.lock().await;
                            let now = Instant::now();
                            let pending = pending_probes.get(&packet.nonce).cloned();
                            let hard_hard_token = self
                                .hard_hard_probe_bindings
                                .lock()
                                .await
                                .get(&packet.nonce)
                                .cloned();
                            let matches_identity = |pending: &PendingProbe| {
                                pending.generation == generation
                                    && pending.socket_index == socket_index
                                    && pending.peer_id.as_deref()
                                        == Some(identity.source_node_id.as_str())
                                    && pending.remote_candidate_epoch == remote_candidate_epoch
                                    && pending.cleanup_epoch == cleanup_epoch
                                    && pending.direct_commit_seq == direct_commit_seq
                                    && pending.accepts_authenticated_ack
                            };
                            let expired = pending
                                .as_ref()
                                .filter(|pending| {
                                    matches_identity(pending) && pending.is_expired(now)
                                })
                                .cloned();
                            let matched = pending.filter(|pending| {
                                matches_identity(pending) && !pending.is_expired(now)
                            });
                            if matched.is_some() || expired.is_some() {
                                pending_probes.remove(&packet.nonce);
                            }
                            (matched, expired, hard_hard_token)
                        };

                        let (ack_match, expired_pending, hard_hard_token) = ack_match;
                        if let Some(expired) = expired_pending {
                            self.clear_hard_hard_pending_probe_token(packet.nonce).await;
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.authenticated_probe_acks_unmatched =
                                    metrics.authenticated_probe_acks_unmatched.saturating_add(1)
                            })
                            .await;
                            self.update_peer_probe_rx_diagnostics(
                                &identity.source_node_id,
                                received_local_generation,
                                matched_probe_session_id.as_deref(),
                                |snapshot| {
                                    if known_peer_ip {
                                        snapshot.known_peer_ip_datagrams_received = snapshot
                                            .known_peer_ip_datagrams_received
                                            .saturating_add(1);
                                    }
                                    snapshot.authenticated_probe_packets_received = snapshot
                                        .authenticated_probe_packets_received
                                        .saturating_add(1);
                                    snapshot.authenticated_probe_acks_observed = snapshot
                                        .authenticated_probe_acks_observed
                                        .saturating_add(1);
                                    snapshot.authenticated_probe_acks_unmatched = snapshot
                                        .authenticated_probe_acks_unmatched
                                        .saturating_add(1);
                                },
                            )
                            .await;
                            self.peers
                                .record_direct_event_for_generation_with_socket(
                                    &identity.source_node_id,
                                    expired.generation,
                                    "direct_probe_ack_expired",
                                    Some(source),
                                    Some(socket_index),
                                    Some(1),
                                    None,
                                    format!(
                                        "ignored authenticated UDP probe ACK after its terminal deadline: endpoint={} age_ms={} deadline_ms={}",
                                        expired.endpoint,
                                        expired.sent_at.elapsed().as_millis(),
                                        expired
                                            .expires_at
                                            .saturating_duration_since(expired.sent_at)
                                            .as_millis(),
                                    ),
                                )
                                .await;
                            continue;
                        }

                        if let Some(pending) = ack_match {
                            if let Some(token) = hard_hard_token.as_deref() {
                                if !self
                                    .peers
                                    .hard_hard_session_token_is_current(
                                        &identity.source_node_id,
                                        token,
                                    )
                                    .await
                                {
                                    self.clear_hard_hard_pending_probe_token(packet.nonce).await;
                                    self.update_socket_diagnostics(socket_index, |metrics| {
                                        metrics.authenticated_probe_acks_unmatched = metrics
                                            .authenticated_probe_acks_unmatched
                                            .saturating_add(1)
                                    })
                                    .await;
                                    trace!(
                                        "Ignored authenticated Hard↔Hard ACK for retired session token from {}",
                                        identity.source_node_id
                                    );
                                    continue;
                                }
                            }
                            // The peer must still be clean (no offline /
                            // PeerLeft / endpoint / public-key change since
                            // the probe was sent) before ANY adoption.  Under
                            // the adoption lock the epoch cannot move between
                            // this fence and the last adoption; the fence is
                            // still re-verified so a cleanup that won the
                            // lock first refuses the whole adoption.
                            if !self.peer_still_clean(&pending).await {
                                self.clear_hard_hard_pending_probe_token(packet.nonce).await;
                                continue;
                            }
                            if let Some(token) = pending_token.as_deref() {
                                let promoted = match pending_emit_guard.as_ref() {
                                    Some(emit_guard) => {
                                        self.confirm_pending_probe_adoption_with_emit_guard(
                                            &identity.source_node_id,
                                            token,
                                            emit_guard,
                                        )
                                        .await
                                    }
                                    None => false,
                                };
                                if promoted {
                                    debug!(
                                        "Promoted matching WireGuard and Probe v2 bindings for peer {} after matched authenticated ACK",
                                        identity.source_node_id
                                    );
                                } else {
                                    debug!(
                                        "Ignored matched pending Probe v2 ACK from {}; matching WireGuard/Probe transaction is unavailable",
                                        identity.source_node_id
                                    );
                                    // Re-inserting is only safe when the peer
                                    // was not cleaned up (offline, PeerLeft,
                                    // endpoint/public-key change) between the
                                    // probe send and this ACK: a cleanup that
                                    // raced this handler must never be undone
                                    // by a late re-insertion of the old
                                    // pending entry.
                                    self.restore_pending_probe_if_peer_still_clean(
                                        packet.nonce,
                                        pending,
                                    )
                                    .await;
                                    continue;
                                }
                            }
                            self.clear_hard_hard_pending_probe_token(packet.nonce).await;
                            let latency = pending.sent_at.elapsed();
                            let generation = pending.generation;
                            let probe_session_id = pending.probe_session_id.as_deref();
                            let local_endpoint = pending.local_endpoint;
                            let purpose = pending.purpose;
                            let socket_epoch = pending.socket_epoch;
                            if let Some(token) = hard_hard_token.as_deref() {
                                let _ = self
                                    .promote_hard_hard_winner_in_epoch(
                                        &epoch_guard,
                                        &identity.source_node_id,
                                        token,
                                        socket_index,
                                        generation,
                                    )
                                    .await;
                            }
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.probe_acks_received += 1
                            })
                            .await;
                            self.update_peer_probe_rx_diagnostics(
                                &identity.source_node_id,
                                generation,
                                probe_session_id,
                                |snapshot| {
                                    if known_peer_ip {
                                        snapshot.known_peer_ip_datagrams_received = snapshot
                                            .known_peer_ip_datagrams_received
                                            .saturating_add(1);
                                    }
                                    snapshot.authenticated_probe_packets_received = snapshot
                                        .authenticated_probe_packets_received
                                        .saturating_add(1);
                                    snapshot.authenticated_probe_acks_observed = snapshot
                                        .authenticated_probe_acks_observed
                                        .saturating_add(1);
                                    snapshot.probe_acks_received =
                                        snapshot.probe_acks_received.saturating_add(1);
                                },
                            )
                            .await;
                            let _ = self
                                .remember_peer_socket_for_generation_in_epoch(
                                    &epoch_guard,
                                    &identity.source_node_id,
                                    socket_index,
                                    generation,
                                    SocketEvidence::Stamped(socket_epoch),
                                )
                                .await;
                            self.peers
                                .learn_authenticated_endpoint_in_epoch(
                                    &epoch_guard,
                                    &identity.source_node_id,
                                    source,
                                )
                                .await;
                            let accepted = self
                                .peers
                                .record_direct_probe_success_with_latency_for_generation_and_local_endpoint_for_remote_epoch(
                                        &identity.source_node_id,
                                        source,
                                        Some(latency),
                                        generation,
                                        local_endpoint,
                                        Some(pending.remote_candidate_epoch),
                                )
                                .await;
                            if accepted {
                                self.notify_peer_reflexive_observation(
                                    &identity.source_node_id,
                                    source,
                                )
                                .await;
                                // A matched ACK is the most reliable proof that
                                // the peer's mapping works RIGHT NOW: fire the
                                // daemon-internal encrypted validation toward
                                // the ACK's source so both sides converge to
                                // Direct without user traffic.
                                //
                                // This is evidence ingress only. It is
                                // deliberately recorded before handing off to
                                // the bounded validation scheduler and never
                                // promotes Direct on its own. The explicit
                                // pending-probe generation/session prevents a
                                // later rekey or another peer's ACK from being
                                // presented as this validation request.
                                self.peers
                                    .record_direct_event_for_generation_with_socket(
                                        &identity.source_node_id,
                                        generation,
                                        "direct_validation_ingress_requested",
                                        Some(source),
                                        Some(socket_index),
                                        None,
                                        None,
                                        format!(
                                            "matched authenticated probe ACK; probe_session_id={} socket_index={} local_endpoint={} rtt_ms={}; requesting bounded encrypted validation ingress",
                                            probe_session_id.unwrap_or("legacy"),
                                            socket_index,
                                            format_optional_endpoint(local_endpoint),
                                            latency.as_millis(),
                                        ),
                                    )
                                    .await;
                                self.trigger_encrypted_validation(&identity.source_node_id, source)
                                    .await;
                                if purpose == PendingProbePurpose::ConsentCheck {
                                    self.peers
                                        .record_direct_event(
                                            &identity.source_node_id,
                                            "consent_ack_received",
                                            Some(source),
                                            Some(1),
                                            None,
                                            format!(
                                                "received direct UDP consent ACK from {source} rtt={}ms local_endpoint={}",
                                                latency.as_millis(),
                                                format_optional_endpoint(local_endpoint)
                                            ),
                                        )
                                        .await;
                                }
                                debug!(
                                    "Received authenticated UDP punch ACK from peer {} at {} (rtt={latency:?})",
                                    identity.source_node_id, source
                                );
                            } else {
                                trace!(
                                    "Ignored stale authenticated UDP punch ACK from peer {} at {}",
                                    identity.source_node_id,
                                    source
                                );
                            }
                        } else {
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.authenticated_probe_acks_unmatched =
                                    metrics.authenticated_probe_acks_unmatched.saturating_add(1)
                            })
                            .await;
                            self.update_peer_probe_rx_diagnostics(
                                &identity.source_node_id,
                                received_local_generation,
                                matched_probe_session_id.as_deref(),
                                |snapshot| {
                                    if known_peer_ip {
                                        snapshot.known_peer_ip_datagrams_received = snapshot
                                            .known_peer_ip_datagrams_received
                                            .saturating_add(1);
                                    }
                                    snapshot.authenticated_probe_packets_received = snapshot
                                        .authenticated_probe_packets_received
                                        .saturating_add(1);
                                    snapshot.authenticated_probe_acks_observed = snapshot
                                        .authenticated_probe_acks_observed
                                        .saturating_add(1);
                                    snapshot.authenticated_probe_acks_unmatched = snapshot
                                        .authenticated_probe_acks_unmatched
                                        .saturating_add(1);
                                },
                            )
                            .await;
                            trace!(
                                "Ignored unmatched authenticated UDP punch ACK from peer {} at {}",
                                identity.source_node_id,
                                source
                            );
                        }
                    }
                }
                continue;
            }

            if let Some(packet) = decode_punch_packet(data) {
                match packet.kind {
                    PunchPacketKind::Punch => {
                        let ack = build_punch_ack(packet.nonce).to_vec();
                        match self
                            .send_punch_ack_burst(
                                socket_index,
                                socket.clone(),
                                ack,
                                source,
                                source.to_string(),
                            )
                            .await
                        {
                            Ok(()) => {
                                debug!("Received UDP punch from {source}; sent ACK burst");
                                if let Some(peer_id) =
                                    self.peers.learn_endpoint_from_addr(source).await
                                {
                                    // Same adoption fence as the authenticated
                                    // punch: under the peer's adoption lock the
                                    // peer must still exist before any socket
                                    // pin or Direct promotion, so a PeerLeft
                                    // that raced this punch leaves nothing
                                    // behind.
                                    let adoption = self.adoption_lock_for(&peer_id).await;
                                    let _adoption_guard = adoption.lock().await;
                                    if !self.peers.peer_exists_sync(&peer_id) {
                                        continue;
                                    }
                                    self.peers
                                        .record_direct_probe_success_with_local_endpoint(
                                            &peer_id,
                                            source,
                                            socket.local_addr().ok(),
                                        )
                                        .await;
                                    self.remember_peer_socket(
                                        &peer_id,
                                        socket_index,
                                        SocketEvidence::Fresh,
                                    )
                                    .await;
                                    self.notify_peer_reflexive_observation(&peer_id, source)
                                        .await;
                                    self.trigger_peer_reflexive_check(
                                        socket_index,
                                        &peer_id,
                                        source,
                                    )
                                    .await;
                                    debug!(
                                        "Recorded direct UDP probe success from peer {peer_id} at {source}"
                                    );
                                }
                            }
                            Err(err) => warn!("Failed to ACK UDP punch from {source}: {err}"),
                        }
                    }
                    PunchPacketKind::Ack => {
                        self.update_socket_diagnostics(socket_index, |metrics| {
                            metrics.legacy_probe_acks_observed =
                                metrics.legacy_probe_acks_observed.saturating_add(1)
                        })
                        .await;
                        // Legacy ACKs have no authenticated sender identity.
                        // Enter the transaction only through the peer ID stamped
                        // on this exact pending nonce; an unmatched source must
                        // never be allowed to learn or mutate a peer.
                        let pending_peer_id = self
                            .pending_probes
                            .lock()
                            .await
                            .get(&packet.nonce)
                            .and_then(|pending| pending.peer_id.clone());
                        let Some(transaction_peer_id) = pending_peer_id else {
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.legacy_probe_acks_unmatched =
                                    metrics.legacy_probe_acks_unmatched.saturating_add(1)
                            })
                            .await;
                            trace!(
                                "Ignored legacy UDP punch ACK from {source}: no peer-owned pending nonce"
                            );
                            continue;
                        };

                        // Match and every resulting mutation are one peer and
                        // generation transaction. Lifecycle cleanup takes the
                        // adoption lock; local generation and remote-candidate
                        // writers take the epoch gate.
                        let adoption = self.adoption_lock_for(&transaction_peer_id).await;
                        let _adoption_guard = adoption.lock().await;
                        let epoch_guard = self.network_epoch_gate.lock().await;
                        let generation = self.peers.current_network_generation_sync();
                        let remote_candidate_epoch = self
                            .peers
                            .current_remote_candidate_epoch(&transaction_peer_id)
                            .await
                            .unwrap_or(0);
                        let cleanup_epoch =
                            self.peer_probe_cleanup_epoch(&transaction_peer_id).await;
                        let direct_commit_seq = self
                            .peers
                            .direct_commit_seq_sync(&transaction_peer_id)
                            .unwrap_or(0);
                        let (ack_match, expired_pending) = {
                            let mut pending_probes = self.pending_probes.lock().await;
                            let now = Instant::now();
                            let pending = pending_probes.get(&packet.nonce).cloned();
                            let expired = pending
                                .as_ref()
                                .filter(|pending| {
                                    pending.peer_id.as_deref() == Some(transaction_peer_id.as_str())
                                        && legacy_ack_matches_pending(
                                            pending,
                                            source,
                                            generation,
                                            remote_candidate_epoch,
                                            socket_index,
                                            cleanup_epoch,
                                            direct_commit_seq,
                                        )
                                        && pending.is_expired(now)
                                })
                                .cloned();
                            let matched = pending
                                .filter(|pending| {
                                    pending.peer_id.as_deref() == Some(transaction_peer_id.as_str())
                                        && legacy_ack_matches_pending(
                                            pending,
                                            source,
                                            generation,
                                            remote_candidate_epoch,
                                            socket_index,
                                            cleanup_epoch,
                                            direct_commit_seq,
                                        )
                                        && !pending.is_expired(now)
                                })
                                .map(|pending| {
                                    (
                                        pending.sent_at.elapsed(),
                                        pending.generation,
                                        pending.peer_id.clone(),
                                        pending.probe_session_id.clone(),
                                        pending.local_endpoint,
                                        pending.purpose,
                                        pending.socket_epoch,
                                        pending.cleanup_epoch,
                                        pending.direct_commit_seq,
                                    )
                                });
                            if matched.is_some() || expired.is_some() {
                                pending_probes.remove(&packet.nonce);
                            }
                            (matched, expired)
                        };
                        if let Some(expired) = expired_pending {
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.legacy_probe_acks_unmatched =
                                    metrics.legacy_probe_acks_unmatched.saturating_add(1)
                            })
                            .await;
                            if let Some(peer_id) = expired.peer_id.as_deref() {
                                self.peers
                                    .record_direct_event_for_generation_with_socket(
                                        peer_id,
                                        expired.generation,
                                        "direct_probe_ack_expired",
                                        Some(source),
                                        Some(socket_index),
                                        Some(1),
                                        None,
                                        format!(
                                            "ignored legacy UDP probe ACK after its terminal deadline: endpoint={} age_ms={} deadline_ms={}",
                                            expired.endpoint,
                                            expired.sent_at.elapsed().as_millis(),
                                            expired
                                                .expires_at
                                                .saturating_duration_since(expired.sent_at)
                                                .as_millis(),
                                        ),
                                    )
                                    .await;
                            }
                            continue;
                        }
                        // The peer identity comes from the matched pending
                        // probe (never from the source address alone, which
                        // would let a spoofed ACK drive endpoint learning).
                        let peer_id = Some(transaction_peer_id.clone());
                        if let Some(peer_id) = peer_id {
                            // The whole fence -> learn -> adopt sequence runs
                            // under the peer's adoption lock, and the cleanup
                            // fence runs BEFORE any endpoint learning: a
                            // legacy ACK must never learn an endpoint, pin a
                            // socket or promote Direct after the peer was
                            // cleaned (offline, PeerLeft, endpoint/public-key
                            // change).
                            let pending_cleanup_epoch = ack_match
                                .as_ref()
                                .map(|(_, _, _, _, _, _, _, epoch, _)| *epoch);
                            let still_clean = match pending_cleanup_epoch {
                                Some(stamped) => {
                                    self.peer_probe_cleanup_epoch(&peer_id).await == stamped
                                }
                                None => true,
                            };
                            if !still_clean {
                                debug!(
                                    "Ignoring legacy ACK from {source} for peer {peer_id}: the peer was cleaned after the probe was sent"
                                );
                                continue;
                            }
                            if let Some((
                                latency,
                                generation,
                                _,
                                probe_session_id,
                                local_endpoint,
                                purpose,
                                socket_epoch,
                                _,
                                direct_commit_seq_at_send,
                            )) = ack_match
                            {
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.probe_acks_received += 1
                                })
                                .await;
                                self.update_peer_probe_rx_diagnostics(
                                    &peer_id,
                                    generation,
                                    probe_session_id.as_deref(),
                                    |snapshot| {
                                        snapshot.legacy_probe_acks_observed =
                                            snapshot.legacy_probe_acks_observed.saturating_add(1);
                                        snapshot.probe_acks_received =
                                            snapshot.probe_acks_received.saturating_add(1);
                                    },
                                )
                                .await;
                                // Recheck every stamped authority immediately
                                // before the first mutation.  Adoption + epoch
                                // keep these values stable through the success
                                // commit, closing both local-generation and
                                // remote-candidate ABA races.
                                let stamps_current = self.peers.current_network_generation_sync()
                                    == generation
                                    && self
                                        .peers
                                        .current_remote_candidate_epoch(&peer_id)
                                        .await
                                        .unwrap_or(0)
                                        == remote_candidate_epoch
                                    && self.peer_probe_cleanup_epoch(&peer_id).await
                                        == pending_cleanup_epoch.unwrap_or(u64::MAX)
                                    && self.peers.direct_commit_seq_sync(&peer_id).unwrap_or(0)
                                        == direct_commit_seq_at_send;
                                if !stamps_current {
                                    trace!(
                                        "Ignored legacy UDP punch ACK from {source} for peer {peer_id}: lifecycle or generation changed before adoption"
                                    );
                                    continue;
                                }
                                if !self
                                    .peers
                                    .learn_correlated_probe_endpoint(&peer_id, source)
                                    .await
                                {
                                    continue;
                                }
                                let _affinity_adopted = self
                                    .remember_peer_socket_for_generation_in_epoch(
                                        &epoch_guard,
                                        &peer_id,
                                        socket_index,
                                        generation,
                                        SocketEvidence::Stamped(socket_epoch),
                                    )
                                    .await;
                                let accepted = self
                                    .peers
                                    .record_direct_probe_success_with_latency_for_generation_and_local_endpoint_for_remote_epoch(
                                        &peer_id,
                                        source,
                                        Some(latency),
                                        generation,
                                        local_endpoint,
                                        Some(remote_candidate_epoch),
                                    )
                                    .await;
                                if accepted {
                                    self.notify_peer_reflexive_observation(&peer_id, source)
                                        .await;
                                    // Legacy peers still need the same
                                    // per-pending-probe attribution. The ACK
                                    // remains only an ingress signal for the
                                    // encrypted validation worker.
                                    self.peers
                                        .record_direct_event_for_generation_with_socket(
                                            &peer_id,
                                            generation,
                                            "direct_validation_ingress_requested",
                                            Some(source),
                                            Some(socket_index),
                                            None,
                                            None,
                                            format!(
                                                "matched legacy probe ACK; probe_session_id={} socket_index={} local_endpoint={} rtt_ms={}; requesting bounded encrypted validation ingress",
                                                probe_session_id.as_deref().unwrap_or("legacy"),
                                                socket_index,
                                                format_optional_endpoint(local_endpoint),
                                                latency.as_millis(),
                                            ),
                                        )
                                        .await;
                                    self.trigger_encrypted_validation(&peer_id, source).await;
                                    if purpose == PendingProbePurpose::ConsentCheck {
                                        self.peers
                                            .record_direct_event(
                                                &peer_id,
                                                "consent_ack_received",
                                                Some(source),
                                                Some(1),
                                                None,
                                                format!(
                                                    "received direct UDP consent ACK from {source} rtt={}ms local_endpoint={}",
                                                    latency.as_millis(),
                                                    format_optional_endpoint(local_endpoint)
                                                ),
                                            )
                                            .await;
                                    }
                                    debug!(
                                        "Received UDP punch ACK from peer {peer_id} at {source} (rtt={latency:?} direct_commit_seq_at_send={direct_commit_seq_at_send})"
                                    );
                                } else {
                                    trace!(
                                        "Ignored stale UDP punch ACK from peer {peer_id} at {source}"
                                    );
                                }
                            } else {
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.legacy_probe_acks_unmatched =
                                        metrics.legacy_probe_acks_unmatched.saturating_add(1)
                                })
                                .await;
                                trace!("Ignored stale or unmatched UDP punch ACK from {source}");
                            }
                        } else {
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.legacy_probe_acks_unmatched =
                                    metrics.legacy_probe_acks_unmatched.saturating_add(1)
                            })
                            .await;
                            trace!("Received UDP punch ACK from unknown candidate {source}");
                        }
                    }
                }
                continue;
            }

            // Raw encrypted UDP is NOT fresh affinity evidence: the socket is
            // only adopted for the peer after WireGuard decryption proves the
            // datagram really belongs to it (see `run_inbound_with_peers`).
            // Endpoint learning may still run here, but it only records the
            // observed source, never the sending socket.
            if let Some(peer_id) = self.peers.learn_endpoint_from_addr(source).await {
                trace!("Learned encrypted UDP source {source} for peer {peer_id}");
            }

            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.encrypted_packets_received += 1
            })
            .await;

            inbound_tx
                .send(ReceivedEncryptedPacket {
                    source: Some(source),
                    local_endpoint: socket.local_addr().ok(),
                    relay_endpoint: None,
                    relay_connection_id: None,
                    relay_peer_id: None,
                    socket_index: Some(socket_index),
                    direct_socket: (socket_index >= DYNAMIC_SOCKET_INDEX_BASE)
                        .then(|| socket.clone()),
                    // The token is sampled at enqueue time, not when the
                    // WireGuard worker later decrypts this datagram. A
                    // publication replacement can therefore reject a queued
                    // packet from the retired reader instead of treating it
                    // as evidence for the replacement socket.
                    udp_transport_owner: Some(self.inbound_publication_owner()),
                    network_generation: Some(self.peers.current_network_generation_sync()),
                    wire_bytes: data.to_vec(),
                })
                .await
                .map_err(|_| {
                    DaemonError::Network("received encrypted packet channel closed".to_string())
                })?;

            debug!("Received {n} encrypted UDP bytes from {source}");
        }
    }
}
