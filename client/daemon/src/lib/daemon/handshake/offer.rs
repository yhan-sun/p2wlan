impl Daemon {
    /// Acquire the responder's short mutation turn with both cancellation and
    /// a hard lock-wait bound.  A control signal is already acknowledged when
    /// it enters the responder worker, so an unbounded arbiter wait would turn
    /// one stale initiator/lifecycle task into a permanent session blackout.
    async fn acquire_responder_handshake_guard(
        &self,
        from_node_id: &str,
        cancellation: Option<&mut tokio::sync::watch::Receiver<bool>>,
    ) -> Result<Option<tokio::sync::OwnedMutexGuard<()>>> {
        let wait_started = Instant::now();
        let generation = self.peers.current_network_generation_sync();
        self.timeline.emit(
            "peer_offer_responder_lock_wait",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={generation} wait_budget_ms={}",
                RESPONDER_HANDSHAKE_ARBITER_TIMEOUT.as_millis()
            )),
        );
        let guard = match cancellation {
            Some(cancellation) => {
                tokio::select! {
                    biased;
                    changed = cancellation.changed() => {
                        let _ = changed;
                        self.timeline.emit(
                            "peer_offer_responder_lock_cancelled",
                            None,
                            Some("generation_cancelled"),
                            Some(format!(
                                "peer={from_node_id} generation={generation} wait_ms={}",
                                wait_started.elapsed().as_millis()
                            )),
                        );
                        return Ok(None);
                    }
                    guard = self.handshake_arbiter.acquire_with_timeout(
                        from_node_id,
                        RESPONDER_HANDSHAKE_ARBITER_TIMEOUT,
                    ) => guard,
                }
            }
            None => {
                self.handshake_arbiter
                    .acquire_with_timeout(from_node_id, RESPONDER_HANDSHAKE_ARBITER_TIMEOUT)
                    .await
            }
        };
        match guard {
            Some(guard) => {
                self.timeline.emit(
                    "peer_offer_responder_lock_acquired",
                    None,
                    None,
                    Some(format!(
                        "peer={from_node_id} generation={generation} wait_ms={}",
                        wait_started.elapsed().as_millis()
                    )),
                );
                Ok(Some(guard))
            }
            None => {
                self.timeline.emit(
                    "peer_offer_responder_lock_timeout",
                    None,
                    Some(REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT),
                    Some(format!(
                        "peer={from_node_id} generation={generation} wait_ms={}",
                        RESPONDER_HANDSHAKE_ARBITER_TIMEOUT.as_millis()
                    )),
                );
                Err(DaemonError::Network(
                    REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT.to_string(),
                ))
            }
        }
    }

    #[allow(clippy::too_many_arguments, dead_code)]
    async fn handle_peer_offer(
        &self,
        from_node_id: &str,
        candidates: &[String],
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
    ) -> Result<()> {
        self.handle_peer_offer_with_cancellation(
            from_node_id,
            candidates,
            handshake_init,
            punch_at_ms,
            punch_at_server_ms,
            session_id,
            probe_ephemeral_public_key,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    async fn handle_event_peer_offer(
        &self,
        offer: PendingPeerOffer,
        owner: u64,
        cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let Some(peer_session_generation) = offer.peer_session_generation else {
            return Ok(());
        };
        if self.peers.current_network_generation_sync() != offer.network_generation
            || !self
                .peers
                .peer_session_is_current_sync(&offer.from_node_id, peer_session_generation)
        {
            self.timeline.emit(
                "peer_offer_rejected",
                None,
                Some("stale_network_generation"),
                Some(format!(
                    "peer={} offer_generation={} current_generation={}",
                    offer.from_node_id,
                    offer.network_generation,
                    self.peers.current_network_generation_sync()
                )),
            );
            return Ok(());
        }
        let sender_public_key = offer.sender_public_key.clone();
        self.handle_peer_offer_with_cancellation(
            &offer.from_node_id,
            &offer.candidates,
            &offer.handshake_init,
            offer.punch_at_ms,
            offer.punch_at_server_ms,
            offer.session_id,
            offer.probe_ephemeral_public_key,
            sender_public_key.as_deref(),
            Some(cancellation),
            Some(owner),
            Some(offer.network_generation),
            Some(peer_session_generation),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_peer_offer_with_cancellation(
        &self,
        from_node_id: &str,
        _candidates: &[String],
        handshake_init: &[u8],
        punch_at_ms: Option<u64>,
        punch_at_server_ms: Option<u64>,
        session_id: Option<String>,
        probe_ephemeral_public_key: Option<String>,
        sender_public_key: Option<&str>,
        mut cancellation: Option<&mut tokio::sync::watch::Receiver<bool>>,
        responder_work_owner: Option<u64>,
        expected_network_generation: Option<u64>,
        expected_peer_session_generation: Option<PeerSessionGeneration>,
    ) -> Result<()> {
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
        {
            return Ok(());
        }
        if expected_network_generation
            .is_some_and(|generation| self.peers.current_network_generation_sync() != generation)
        {
            self.timeline.emit(
                "peer_offer_rejected",
                None,
                Some("stale_network_generation"),
                Some(format!(
                    "peer={} offer_generation={:?} current_generation={}",
                    from_node_id,
                    expected_network_generation,
                    self.peers.current_network_generation_sync()
                )),
            );
            return Ok(());
        }
        if expected_peer_session_generation.is_some_and(|expected| {
            !self
                .peers
                .peer_session_is_current_sync(from_node_id, expected)
        }) {
            self.timeline.emit(
                "peer_offer_rejected",
                None,
                Some("stale_peer_session"),
                Some(format!("peer={from_node_id}")),
            );
            return Ok(());
        }
        if let Some(owner) = responder_work_owner {
            let current = self
                .pending_handshakes
                .lock()
                .await
                .responder_work_is_current(from_node_id, owner);
            if !current {
                return Ok(());
            }
        }
        // Identity lookup may wait behind control/connection state. Never hold
        // the per-peer arbiter across it: this responder future is cooperatively
        // polled by the serial control loop, whose lifecycle branch may itself
        // be waiting to acquire the same arbiter.
        if !self
            .signal_sender_identity_matches_peer(from_node_id, sender_public_key)
            .await
        {
            self.timeline.emit(
                "peer_offer_rejected",
                None,
                Some("stale_sender_identity"),
                Some(format!("peer={from_node_id}")),
            );
            return Ok(());
        }
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
        {
            return Ok(());
        }
        if expected_network_generation
            .is_some_and(|generation| self.peers.current_network_generation_sync() != generation)
            || expected_peer_session_generation.is_some_and(|expected| {
                !self
                    .peers
                    .peer_session_is_current_sync(from_node_id, expected)
            })
        {
            return Ok(());
        }
        if let Some(owner) = responder_work_owner {
            let current = self
                .pending_handshakes
                .lock()
                .await
                .responder_work_is_current(from_node_id, owner);
            if !current {
                return Ok(());
            }
        }
        let Some(handshake_guard) = self
            .acquire_responder_handshake_guard(from_node_id, cancellation.as_deref_mut())
            .await?
        else {
            return Ok(());
        };
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
        {
            return Ok(());
        }
        if expected_network_generation
            .is_some_and(|generation| self.peers.current_network_generation_sync() != generation)
            || expected_peer_session_generation.is_some_and(|expected| {
                !self
                    .peers
                    .peer_session_is_current_sync(from_node_id, expected)
            })
        {
            return Ok(());
        }
        // `responder_work` is cooperatively polled by the serial control task.
        // Holding this arbiter across any subsequent async lock/HTTP/session
        // await can self-deadlock when a lifecycle branch waits on the arbiter
        // and thereby stops polling the responder future. The arbiter is only
        // an admission barrier here; exact worker/lifecycle fences protect the
        // delayed staging and commit below.
        drop(handshake_guard);
        let initiation = MessageInitiation::from_bytes(handshake_init)
            .map_err(|e| DaemonError::Peer(format!("invalid WireGuard initiation: {e}")))?;
        // The static WireGuard public keys provide a deterministic role: the
        // lexicographically smaller key always initiates. Enforcing the same
        // rule on inbound offers prevents crossing rekeys from staging a
        // second responder transaction after this node already claimed the
        // initiator side.
        let known_peer_public_key = self
            .control
            .peers()
            .await
            .get(from_node_id)
            .map(|peer| peer.public_key.clone());
        let known_peer_public_key = match known_peer_public_key {
            Some(public_key) => Some(public_key),
            None => self
                .peers
                .get_connection(from_node_id)
                .await
                .map(|peer| peer.public_key),
        };
        let expected_peer_public = known_peer_public_key
            .as_deref()
            .map(|public_key| decode_x25519_key(public_key, "peer public key"))
            .transpose()?
            .ok_or_else(|| {
                DaemonError::Peer(format!(
                    "refusing WireGuard offer from {from_node_id}: peer identity is not known yet"
                ))
            })?;
        let local_public = self.local_identity()?.public_key();
        if local_public == expected_peer_public {
            return Err(DaemonError::Peer(format!(
                "refusing WireGuard offer from {from_node_id}: peer reuses the local static public key"
            )));
        }
        if local_is_designated_handshake_initiator(&local_public, &expected_peer_public) {
            return Err(DaemonError::Peer(format!(
                "refusing WireGuard offer from {from_node_id}: local node is the deterministic initiator"
            )));
        }
        let modern_probe_public_key = match session_id.as_deref() {
            Some(session_id) if session_id.trim().is_empty() => {
                return Err(DaemonError::Peer(format!(
                    "refusing WireGuard offer from {from_node_id}: empty modern session_id"
                )));
            }
            Some(_) => {
                let peer_probe_public_key = normalize_probe_ephemeral_public_key(
                    probe_ephemeral_public_key.as_deref(),
                )
                .ok_or_else(|| {
                        DaemonError::Peer(format!(
                            "refusing WireGuard offer from {from_node_id}: modern session is missing probe ephemeral public key"
                        ))
                    })?;
                // Reject malformed key material before consulting the replay
                // cache. A duplicate offer cannot use a cached valid answer to
                // bypass validation of the modern Probe-v2 fields it carries.
                derive_probe_ephemeral_shared(&DhKeyPair::generate(), &peer_probe_public_key)?;
                Some(peer_probe_public_key)
            }
            None => None,
        };
        let handshake_token = session_id
            .clone()
            .unwrap_or_else(|| format!("legacy-wg-{}", initiation.sender_index));
        let cached = {
            self.pending_handshakes.lock().await.responder_cache_lookup(
                from_node_id,
                &handshake_token,
                handshake_init,
                modern_probe_public_key.as_deref(),
                &expected_peer_public,
            )
        };
        let cache_state = match &cached {
            ResponderHandshakeCacheLookup::Hit(_) => "hit",
            ResponderHandshakeCacheLookup::Miss => "miss",
            ResponderHandshakeCacheLookup::FingerprintMismatch => "fingerprint_mismatch",
        };
        self.timeline.emit(
            "peer_offer_responder_cache_lookup",
            None,
            (cache_state == "fingerprint_mismatch").then_some("handshake_fingerprint_mismatch"),
            Some(format!(
                "peer={from_node_id} generation={} session_fp={} cache={cache_state}",
                expected_network_generation
                    .unwrap_or_else(|| self.peers.current_network_generation_sync()),
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );
        let (
            response_bytes,
            keys,
            response_probe_ephemeral_public_key,
            probe_ephemeral_shared,
            cached_replay,
            cache_entry_to_commit,
        ) = match cached {
            ResponderHandshakeCacheLookup::Hit(cached) => (
                cached.response_bytes,
                cached.transport_keys,
                cached.response_probe_ephemeral_public_key,
                cached.probe_ephemeral_shared,
                true,
                None,
            ),
            ResponderHandshakeCacheLookup::FingerprintMismatch => {
                return Err(DaemonError::Peer(format!(
                    "refusing WireGuard offer from {from_node_id}: reused session token has different handshake or Probe key material"
                )));
            }
            ResponderHandshakeCacheLookup::Miss => {
                let identity = self.local_identity()?;
                let timestamp_floor = self
                    .pending_handshakes
                    .lock()
                    .await
                    .responder_timestamp_floor(from_node_id, &expected_peer_public);
                let mut responder =
                    HandshakeResponder::new_with_timestamp_floor(identity, None, timestamp_floor);
                let (response, keys) = responder
                    .consume_initiation_and_respond(&initiation)
                    .map_err(|e| DaemonError::Peer(format!("WireGuard response failed: {e}")))?;

                if responder.initiator_public_key() != Some(&expected_peer_public) {
                    return Err(DaemonError::Peer(format!(
                        "WireGuard initiation public key mismatch for peer {from_node_id}"
                    )));
                }
                let authenticated_timestamp = responder.latest_timestamp().ok_or_else(|| {
                    DaemonError::Peer(format!(
                        "WireGuard initiation from {from_node_id} did not authenticate a timestamp"
                    ))
                })?;
                if !self
                    .pending_handshakes
                    .lock()
                    .await
                    .commit_responder_timestamp(
                        from_node_id,
                        expected_peer_public,
                        authenticated_timestamp,
                    )
                {
                    return Err(DaemonError::Peer(format!(
                        "refusing replayed WireGuard initiation from {from_node_id}"
                    )));
                }

                let (response_probe_ephemeral_public_key, probe_ephemeral_shared) =
                    match modern_probe_public_key.as_deref() {
                        Some(peer_probe_public_key) => {
                            let (local_probe_ephemeral, local_probe_public_key) =
                                new_probe_ephemeral_keypair();
                            let shared = derive_probe_ephemeral_shared(
                                &local_probe_ephemeral,
                                peer_probe_public_key,
                            )?;
                            (Some(local_probe_public_key), Some(shared))
                        }
                        None => (None, None),
                    };
                let response_bytes = response.to_bytes();
                let cache_entry = CachedResponderHandshake {
                    handshake_init: handshake_init.to_vec(),
                    initiator_static_public_key: expected_peer_public,
                    request_probe_ephemeral_public_key: modern_probe_public_key.clone(),
                    response_bytes: response_bytes.clone(),
                    transport_keys: keys.clone(),
                    response_probe_ephemeral_public_key: response_probe_ephemeral_public_key
                        .clone(),
                    probe_ephemeral_shared,
                    expires_at: Instant::now() + RESPONDER_HANDSHAKE_CACHE_TTL,
                };
                (
                    response_bytes,
                    keys,
                    response_probe_ephemeral_public_key,
                    probe_ephemeral_shared,
                    false,
                    Some(cache_entry),
                )
            }
        };

        // A valid offer from the designated initiator supersedes any stale
        // local initiator reservation left by an older retry path. Remove its
        // Probe binding as one transaction before staging the responder key.
        if expected_network_generation
            .is_some_and(|generation| self.peers.current_network_generation_sync() != generation)
            || expected_peer_session_generation.is_some_and(|expected| {
                !self
                    .peers
                    .peer_session_is_current_sync(from_node_id, expected)
            })
        {
            return Ok(());
        }
        let superseded_initiator_token = {
            let mut state = self.pending_handshakes.lock().await;
            let token = state.session_id(from_node_id).map(str::to_string);
            state.remove(from_node_id);
            state.cancel_reservation(from_node_id);
            state.attempts.remove(from_node_id);
            token
        };
        if let Some(token) = superseded_initiator_token {
            self.peers
                .discard_pending_probe_session_binding(from_node_id, &token)
                .await;
        }

        // Stage the responder key and its Probe binding as short per-peer
        // mutations. Do not hold the network-generation gate while waiting
        // for the transport ingress/session locks: the outbound actor uses
        // `emit -> generation`, and the old `generation -> ingress` order was
        // the source of a responder-answer deadlock.
        if expected_network_generation
            .is_some_and(|generation| self.peers.current_network_generation_sync() != generation)
            || expected_peer_session_generation.is_some_and(|expected| {
                !self
                    .peers
                    .peer_session_is_current_sync(from_node_id, expected)
            })
        {
            self.timeline.emit(
                "peer_offer_rejected",
                None,
                Some("stale_network_generation"),
                Some(format!(
                    "peer={} offer_generation={:?} current_generation={}",
                    from_node_id,
                    expected_network_generation,
                    self.peers.current_network_generation_sync()
                )),
            );
            return Ok(());
        }
        let responder_transport_session = TransportSession::new(keys.clone());
        let initial_stage = self
            .transport
            .stage_responder_session(
                from_node_id.to_string(),
                handshake_token.clone(),
                responder_transport_session,
            )
            .await;
        let (had_active, responder_staged_new) = match initial_stage {
            ResponderSessionStage::Staged { had_active } => (had_active, true),
            ResponderSessionStage::ReplayableDuplicate { had_active } if cached_replay => {
                (had_active, false)
            }
            ResponderSessionStage::StaleDuplicate if cached_replay => {
                match self
                    .transport
                    .restage_cached_responder_session(
                        from_node_id.to_string(),
                        handshake_token.clone(),
                        TransportSession::new(keys.clone()),
                    )
                    .await
                {
                    ResponderSessionStage::Staged { had_active } => (had_active, true),
                    ResponderSessionStage::ReplayableDuplicate { had_active } => {
                        (had_active, false)
                    }
                    ResponderSessionStage::StaleDuplicate | ResponderSessionStage::Busy => {
                        return Err(DaemonError::Peer(format!(
                            "refusing stale cached WireGuard answer for {from_node_id}: responder key is no longer safely restageable"
                        )));
                    }
                }
            }
            ResponderSessionStage::ReplayableDuplicate { .. }
            | ResponderSessionStage::StaleDuplicate
            | ResponderSessionStage::Busy => {
                return Err(DaemonError::Peer(format!(
                    "refusing duplicate WireGuard offer token from {from_node_id}; exact cached answer is unavailable"
                )));
            }
        };
        let staged_probe_binding = session_id.is_some() || probe_ephemeral_shared.is_some();
        if staged_probe_binding {
            match self
                .peers
                .stage_probe_session_binding(
                    from_node_id,
                    handshake_token.clone(),
                    session_id.clone(),
                    probe_ephemeral_shared,
                    true,
                )
                .await
            {
                ProbeBindingStage::Staged => {}
                ProbeBindingStage::ReplayableDuplicate if cached_replay => {}
                ProbeBindingStage::StaleDuplicate
                | ProbeBindingStage::Busy
                | ProbeBindingStage::ReplayableDuplicate
                | ProbeBindingStage::PeerMissing => {
                    if responder_staged_new {
                        self.transport
                            .discard_responder_session(from_node_id, &handshake_token)
                            .await;
                    }
                    return Err(DaemonError::Peer(format!(
                        "failed to stage Probe v2 responder binding for {from_node_id}"
                    )));
                }
            }
        }

        self.timeline.emit(
            "peer_answer_staged",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={} session_fp={} had_active={} cached_replay={} probe_binding={staged_probe_binding}",
                expected_network_generation
                    .unwrap_or_else(|| self.peers.current_network_generation_sync()),
                handshake_token_fingerprint(Some(&handshake_token)),
                had_active,
                cached_replay,
            )),
        );
        if expected_network_generation
            .is_some_and(|generation| self.peers.current_network_generation_sync() != generation)
            || expected_peer_session_generation.is_some_and(|expected| {
                !self
                    .peers
                    .peer_session_is_current_sync(from_node_id, expected)
            })
        {
            self.timeline.emit(
                "peer_answer_stage_invalidated",
                None,
                Some("stale_network_generation"),
                Some(format!(
                    "peer={from_node_id} answer_generation={expected_network_generation:?} current_generation={}",
                    self.peers.current_network_generation_sync()
                )),
            );
            if responder_staged_new {
                self.transport
                    .discard_responder_session(from_node_id, &handshake_token)
                    .await;
            }
            if staged_probe_binding {
                self.peers
                    .discard_pending_probe_session_binding(from_node_id, &handshake_token)
                    .await;
            }
            return Ok(());
        }

        // Publish newly generated responder bytes only after both transport
        // layers and the generation check accepted the offer. In particular,
        // an old-generation offer must not leave a cache entry that can be
        // replayed into a later session.
        if let Some(cache_entry) = cache_entry_to_commit {
            self.pending_handshakes
                .lock()
                .await
                .cache_responder_handshake(from_node_id, &handshake_token, cache_entry);
        }

        // All state required to replay/validate the response is now staged.
        // The answer never starts a new live STUN gather. It may wait briefly
        // for the already-running startup gather to replace the provisional
        // host-only snapshot; if relay is available, an empty snapshot still
        // lets the encrypted session/relay probe complete immediately.
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
                    snapshot
                } else {
                    self.wait_for_local_candidate_set().await
                }
            } else if relay_is_available {
                // The host-only bootstrap snapshot is intentionally not used
                // for a new answer when relay is already usable. The full
                // startup candidate publication will follow independently.
                (Vec::new(), HashMap::new())
            } else {
                match cancellation.as_deref_mut() {
                    Some(cancellation) => {
                        tokio::select! {
                            biased;
                            changed = relay_available.changed() => {
                                if changed.is_ok() && *relay_available.borrow() {
                                    (Vec::new(), HashMap::new())
                                } else {
                                    self.wait_for_initial_candidate_set().await
                                }
                            }
                            candidates = self.wait_for_initial_candidate_set() => candidates,
                            changed = cancellation.changed() => {
                                let _ = changed;
                                return Ok(());
                            }
                        }
                    }
                    None => {
                        tokio::select! {
                            biased;
                            changed = relay_available.changed() => {
                                if changed.is_ok() && *relay_available.borrow() {
                                    (Vec::new(), HashMap::new())
                                } else {
                                    self.wait_for_initial_candidate_set().await
                                }
                            }
                            candidates = self.wait_for_initial_candidate_set() => candidates,
                        }
                    }
                }
            }
        };
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
        {
            return Ok(());
        }

        let answer_result = match cancellation.as_deref_mut() {
            Some(cancellation) => {
                tokio::select! {
                    answer = self.control.send_peer_answer_with_sources_schedule_and_session(
                        from_node_id,
                        &candidates,
                        &candidate_sources,
                        &response_bytes,
                        // Echo the offer's server deadline so both peers use
                        // the same rendezvous window. WebSocket-only peers
                        // have no server deadline and retain the previous
                        // local fallback.
                        punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms())),
                        punch_at_server_ms,
                        session_id.clone(),
                        response_probe_ephemeral_public_key.clone(),
                    ) => answer,
                    _ = cancellation.changed() => return Ok(()),
                }
            }
            None => {
                self.control
                    .send_peer_answer_with_sources_schedule_and_session(
                        from_node_id,
                        &candidates,
                        &candidate_sources,
                        &response_bytes,
                        punch_at_ms.or_else(|| Some(relay_assisted_punch_at_ms())),
                        punch_at_server_ms,
                        session_id.clone(),
                        response_probe_ephemeral_public_key,
                    )
                    .await
            }
        };
        self.timeline.emit(
            "peer_answer_control_result",
            None,
            answer_result.as_ref().err().map(|_| "control_plane_error"),
            Some(format!(
                "peer={from_node_id} generation={} session_fp={} candidates={} delivered={}",
                expected_network_generation
                    .unwrap_or_else(|| self.peers.current_network_generation_sync()),
                handshake_token_fingerprint(Some(&handshake_token)),
                candidates.len(),
                answer_result.is_ok(),
            )),
        );

        // Re-enter the state boundary after the slow POST.  Lifecycle cleanup
        // can cancel this exact responder owner while the request is in
        // flight; a stale task must not refresh grace or commit a replacement.
        if let Some(owner) = responder_work_owner {
            let current = self
                .pending_handshakes
                .lock()
                .await
                .responder_work_is_current(from_node_id, owner);
            if !current {
                return Ok(());
            }
        }
        let Some(handshake_guard) = self
            .acquire_responder_handshake_guard(from_node_id, cancellation.as_deref_mut())
            .await?
        else {
            return Ok(());
        };
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
        {
            return Ok(());
        }
        drop(handshake_guard);
        // Refresh both pending slots after the HTTP attempt. This separates
        // potentially slow control-plane delivery from the wide direct
        // adoption window; an ambiguous error intentionally leaves both
        // staged so a retry can still authenticate the exact token.
        self.transport
            .refresh_responder_session_grace(from_node_id, &handshake_token)
            .await;
        if staged_probe_binding {
            self.peers
                .refresh_pending_probe_session_binding_grace(from_node_id, &handshake_token)
                .await;
        }
        // A transport error is delivery-ambiguous: the control server or peer
        // may already have received the answer. The `?` intentionally leaves
        // receive-only staged keys alive until their short TTL, allowing an
        // authenticated new-key packet to commit without changing outbound.
        answer_result?;
        self.timeline.emit(
            "peer_answer_control_accepted",
            None,
            None,
            Some(format!(
                "peer={} generation={} session_fp={}",
                from_node_id,
                expected_network_generation
                    .unwrap_or_else(|| self.peers.current_network_generation_sync()),
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );

        // Commit in the canonical order `emit -> generation -> sessions`.
        // In particular, never call `discard_*` or `commit_*` while holding
        // generation without first owning the emit guard.
        self.timeline.emit(
            "peer_answer_commit_emit_lock_wait",
            None,
            None,
            Some(format!(
                "peer={from_node_id} session_fp={} generation={}",
                handshake_token_fingerprint(Some(&handshake_token)),
                self.peers.current_network_generation_sync()
            )),
        );
        let emit_guard = self
            .transport
            .acquire_outbound_emit_guard(from_node_id)
            .await;
        self.timeline.emit(
            "peer_answer_commit_emit_lock_acquired",
            None,
            None,
            Some(format!(
                "peer={from_node_id} session_fp={} generation={}",
                handshake_token_fingerprint(Some(&handshake_token)),
                self.peers.current_network_generation_sync()
            )),
        );
        let epoch_gate = self.peers.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        if expected_network_generation
            .is_some_and(|generation| self.peers.current_network_generation_sync() != generation)
            || expected_peer_session_generation.is_some_and(|expected| {
                !self
                    .peers
                    .peer_session_is_current_sync(from_node_id, expected)
            })
        {
            drop(epoch_guard);
            drop(emit_guard);
            self.transport
                .discard_responder_session(from_node_id, &handshake_token)
                .await;
            if staged_probe_binding {
                self.peers
                    .discard_pending_probe_session_binding(from_node_id, &handshake_token)
                    .await;
            }
            self.timeline.emit(
                "peer_answer_rejected",
                None,
                Some("stale_network_generation"),
                Some(format!(
                    "peer={} session_fp={} answer_generation={:?} current_generation={}",
                    from_node_id,
                    handshake_token_fingerprint(Some(&handshake_token)),
                    expected_network_generation,
                    self.peers.current_network_generation_sync()
                )),
            );
            return Ok(());
        }
        self.timeline.emit(
            "peer_answer_commit_started",
            None,
            None,
            Some(format!(
                "peer={from_node_id} generation={} session_fp={}",
                self.peers.current_network_generation_sync(),
                handshake_token_fingerprint(Some(&handshake_token))
            )),
        );
        let commit = self
            .transport
            .commit_responder_session_locked(from_node_id, &handshake_token)
            .await;
        drop(epoch_guard);
        drop(emit_guard);
        if commit == ResponderSessionCommit::ActivatedInitial {
            self.transport
                .flush_pending_outbound_for_peer(from_node_id)
                .await;
        }
        self.timeline.emit(
            "peer_answer_commit_result",
            None,
            (commit == ResponderSessionCommit::Missing).then_some("responder_session_missing"),
            Some(format!(
                "peer={from_node_id} generation={} session_fp={} result={commit:?}",
                self.peers.current_network_generation_sync(),
                handshake_token_fingerprint(Some(&handshake_token))
            )),
        );
        if commit == ResponderSessionCommit::Missing {
            if staged_probe_binding {
                self.peers
                    .discard_pending_probe_session_binding(from_node_id, &handshake_token)
                    .await;
            }
            return Err(DaemonError::Peer(format!(
                "staged WireGuard responder session disappeared before answer commit for {from_node_id}"
            )));
        }
        let current_state = self
            .peers
            .get_connection(from_node_id)
            .await
            .map(|connection| connection.state);
        if should_mark_connecting_after_session_install(had_active, current_state) {
            if let Some(expected) = expected_peer_session_generation {
                if !self
                    .peers
                    .update_state_if_peer_session_current(
                        from_node_id,
                        expected,
                        ConnectionState::Connecting,
                    )
                    .await
                {
                    return Ok(());
                }
            } else {
                self.peers
                    .update_state(from_node_id, ConnectionState::Connecting)
                    .await;
            }
        }
        info!(
            "Committed WireGuard responder answer for {from_node_id} ({} bytes, {} candidates, rekey={had_active}, commit={commit:?})",
            response_bytes.len(),
            candidates.len()
        );
        self.peers
            .record_direct_event(
                from_node_id,
                "peer_answer_sent",
                None,
                Some(candidates.len()),
                None,
                format!(
                    "sent answer handshake_bytes={} session_fp={}",
                    response_bytes.len(),
                    handshake_token_fingerprint(session_id.as_deref())
                ),
            )
            .await;
        self.timeline.emit(
            "peer_answer_committed",
            None,
            None,
            Some(format!(
                "peer={} generation={} session_fp={} commit={commit:?}",
                from_node_id,
                self.peers.current_network_generation_sync(),
                handshake_token_fingerprint(session_id.as_deref())
            )),
        );

        // Candidate/endpoint publication is deliberately not awaited here.
        // The answer owner is latency-critical and must be released as soon
        // as the encrypted session is committed.  The regular candidate
        // refresh worker publishes the cached/new mapping independently;
        // doing that work in this owner made retransmissions wait behind an
        // otherwise harmless four-second best-effort operation.
        Ok(())
    }
}
