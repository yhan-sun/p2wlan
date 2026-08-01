impl Daemon {
    async fn maybe_initiate_handshake(
        &mut self,
        peer_info: &control::PeerInfo,
    ) -> Result<Option<u64>> {
        if self.transport.has_session(&peer_info.node_id).await {
            return Ok(None);
        }

        if self.config.node.public_key >= peer_info.public_key {
            return Ok(None);
        }

        let identity = self.local_identity()?;
        let peer_public = decode_x25519_key(&peer_info.public_key, "peer public key")?;

        // Claim this handshake before candidate gathering.  That work awaits,
        // and the background maintenance loop can otherwise observe an empty
        // `pending` map and overwrite this initiator with another one.
        let reserved = {
            let mut state = self.pending_handshakes.lock().await;
            if !state.reserve_start(&peer_info.node_id) {
                false
            } else {
                if state.attempts.get(&peer_info.node_id).copied().unwrap_or(0)
                    >= MAX_HANDSHAKE_ATTEMPTS
                {
                    state.attempts.remove(&peer_info.node_id);
                }
                true
            }
        };
        if !reserved {
            return Ok(None);
        }

        let mut initiator = HandshakeInitiator::new(identity, peer_public, None);
        let initiation = match initiator.create_initiation() {
            Ok(initiation) => initiation,
            Err(error) => {
                self.pending_handshakes
                    .lock()
                    .await
                    .cancel_reservation(&peer_info.node_id);
                return Err(DaemonError::Peer(format!(
                    "WireGuard initiation failed: {error}"
                )));
            }
        };
        let initiation_bytes = initiation.to_bytes();
        let (candidates, candidate_sources) = self.wait_for_local_candidate_set().await;

        let peer_id_clone = peer_info.node_id.clone();
        if self.transport.has_session(&peer_id_clone).await {
            self.pending_handshakes
                .lock()
                .await
                .cancel_reservation(&peer_id_clone);
            return Ok(None);
        }

        let session_id = new_probe_session_id();
        let (probe_ephemeral, probe_ephemeral_public_key) = new_probe_ephemeral_keypair();
        let Some((attempt_no, pending_id)) = ({
            let mut state = self.pending_handshakes.lock().await;
            state
                .insert_reserved(
                    peer_id_clone.clone(),
                    initiator,
                    Some(session_id.clone()),
                    Some(probe_ephemeral),
                )
                .map(|pending_id| {
                    let attempts = state.attempts.entry(peer_id_clone.clone()).or_insert(0);
                    *attempts = attempts.saturating_add(1);
                    (*attempts, pending_id)
                })
        }) else {
            return Ok(None);
        };
        self.peers
            .set_probe_session_id(&peer_id_clone, Some(session_id.clone()))
            .await;

        let punch_at_ms = relay_assisted_punch_at_ms();
        if let Err(error) = self
            .control
            .send_peer_offer_with_sources_punch_and_session(
                &peer_id_clone,
                &candidates,
                &candidate_sources,
                &initiation_bytes,
                Some(punch_at_ms),
                Some(session_id.clone()),
                Some(probe_ephemeral_public_key.clone()),
            )
            .await
        {
            let mut state = self.pending_handshakes.lock().await;
            if state.is_current(&peer_id_clone, pending_id) {
                state.remove(&peer_id_clone);
                self.peers.set_probe_session_id(&peer_id_clone, None).await;
            }
            return Err(error);
        }

        info!(
            "Sent WireGuard handshake initiation to {} ({} bytes, {} candidates, attempt {})",
            peer_id_clone,
            initiation_bytes.len(),
            candidates.len(),
            {
                let state = self.pending_handshakes.lock().await;
                state.attempts.get(&peer_id_clone).copied().unwrap_or(0)
            },
        );
        self.peers
            .record_direct_event(
                &peer_id_clone,
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

        // Spawn timeout watcher that cleans up pending entry on timeout.
        // Uses the shared Arc<Mutex<>> so the spawned task can remove the entry.
        let pending = self.pending_handshakes.clone();
        let timeout_peer = peer_id_clone;
        let transport = self.transport.clone();
        let peers = self.peers.clone();
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
            // Remove from pending so retry is possible.
            let mut state = pending.lock().await;
            if state.is_current(&timeout_peer, pending_id) {
                state.remove(&timeout_peer);
                if attempt_no >= MAX_HANDSHAKE_ATTEMPTS {
                    state.attempts.remove(&timeout_peer);
                }
            }
        });

        Ok(Some(punch_at_ms))
    }

}
