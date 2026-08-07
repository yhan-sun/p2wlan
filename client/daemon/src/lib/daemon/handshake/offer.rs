impl Daemon {
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
        )
        .await
    }

    async fn handle_event_peer_offer(
        &self,
        offer: PendingPeerOffer,
        owner: u64,
        cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        self.handle_peer_offer_with_cancellation(
            &offer.from_node_id,
            &offer.candidates,
            &offer.handshake_init,
            offer.punch_at_ms,
            offer.punch_at_server_ms,
            offer.session_id,
            offer.probe_ephemeral_public_key,
            Some(cancellation),
            Some(owner),
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
        mut cancellation: Option<&mut tokio::sync::watch::Receiver<bool>>,
        responder_work_owner: Option<u64>,
    ) -> Result<()> {
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
        {
            return Ok(());
        }
        let handshake_guard = self.handshake_arbiter.acquire(from_node_id).await;
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
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
            self.pending_handshakes
                .lock()
                .await
                .responder_cache_lookup(
                    from_node_id,
                    &handshake_token,
                    handshake_init,
                    modern_probe_public_key.as_deref(),
                    &expected_peer_public,
                )
        };
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
                let mut responder = HandshakeResponder::new(identity, None);
                let (response, keys) = responder
                    .consume_initiation_and_respond(&initiation)
                    .map_err(|e| DaemonError::Peer(format!("WireGuard response failed: {e}")))?;

                if responder.initiator_public_key() != Some(&expected_peer_public) {
                    return Err(DaemonError::Peer(format!(
                        "WireGuard initiation public key mismatch for peer {from_node_id}"
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
                    response_probe_ephemeral_public_key:
                        response_probe_ephemeral_public_key.clone(),
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
                    ResponderSessionStage::StaleDuplicate
                    | ResponderSessionStage::Busy => {
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

        // Publish newly generated responder bytes only after both transport
        // layers accepted the offer. In particular, an expired cache entry for
        // an already-active token must not be replaced by fresh key material
        // merely because the first duplicate request reached this handler.
        if let Some(cache_entry) = cache_entry_to_commit {
            self.pending_handshakes
                .lock()
                .await
                .cache_responder_handshake(from_node_id, &handshake_token, cache_entry);
        }

        // All state required to replay/validate the response is now staged.
        // STUN refresh and the control POST can take seconds, so neither may
        // retain the per-peer arbiter.  A crossing answer needs this mutex to
        // consume its pending initiator immediately.
        drop(handshake_guard);
        let (candidates, candidate_sources) = match cancellation.as_deref_mut() {
            Some(cancellation) => {
                tokio::select! {
                    candidates = self.local_candidate_set_for_signal("handshake answer") => candidates,
                    _ = cancellation.changed() => return Ok(()),
                }
            }
            None => self.local_candidate_set_for_signal("handshake answer").await,
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
            None => self
                .control
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
                .await,
        };

        // Re-enter the state boundary after the slow POST.  Lifecycle cleanup
        // can cancel this exact responder owner while the request is in
        // flight; a stale task must not refresh grace or commit a replacement.
        let _handshake_guard = self.handshake_arbiter.acquire(from_node_id).await;
        if cancellation
            .as_deref()
            .is_some_and(|cancellation| *cancellation.borrow())
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

        let commit = self
            .transport
            .commit_responder_session(from_node_id, &handshake_token)
            .await;
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
        if should_mark_connecting_after_session_install(
            had_active,
            current_state,
        ) {
            self.peers
                .update_state(from_node_id, ConnectionState::Connecting)
                .await;
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
                    "sent answer handshake_bytes={} session_id={}",
                    response_bytes.len(),
                    session_id.as_deref().unwrap_or("legacy")
                ),
            )
            .await;
        Ok(())
    }

}
