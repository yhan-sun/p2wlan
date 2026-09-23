use super::*;

impl WireGuardTransport {
    /// Decrypt one inbound WireGuard transport packet.
    pub async fn decrypt_inbound(&self, wire_bytes: &[u8]) -> Result<Option<InboundPacket>> {
        self.decrypt_inbound_classified(wire_bytes)
            .await
            .map_err(|error| DaemonError::Peer(error.to_string()))
    }

    pub(in crate::transport) async fn decrypt_inbound_classified(
        &self,
        wire_bytes: &[u8],
    ) -> std::result::Result<Option<InboundPacket>, InboundDecryptError> {
        let msg = MessageTransport::from_bytes(wire_bytes).map_err(InboundDecryptError::Parse)?;
        let receiver_index = msg.receiver_index;

        let mut sessions = self.sessions.lock().await;
        let now = Instant::now();
        for peer_sessions in sessions.values_mut() {
            peer_sessions.prune_expired(now);
        }

        let mut first_decrypt_error = None;
        // Peers whose session produced a replay-classified decrypt failure.
        // The same WireGuard ciphertext is legitimately delivered twice during
        // the Direct trial window (once per Direct path, once per relay hedge);
        // WireGuard's replay protection then rejects the second copy.  These
        // duplicates are counted and logged rate-limited instead of emitting a
        // warning storm, and they never touch path state.
        let mut replay_attributed_sessions: Vec<(String, u64)> = Vec::new();

        // Prefer the active session if an extremely unlikely receiver-index
        // collision occurs. Successfully receiving the new key confirms the
        // peer has completed the rekey, so the prior key can be retired early.
        let mut confirmed_active = None;
        for (peer_id, peer_sessions) in sessions.iter_mut() {
            let Some(active) = peer_sessions.active.as_mut() else {
                continue;
            };
            if active.session.our_index() != receiver_index {
                continue;
            }
            match active.session.decrypt(&msg) {
                Ok(packet) => {
                    let token = active
                        .awaiting_confirmation
                        .then(|| active.token.clone())
                        .flatten();
                    active.awaiting_confirmation = false;
                    confirmed_active =
                        Some((peer_id.clone(), packet, token, active.session_instance));
                    break;
                }
                Err(error) => {
                    if is_replay_decrypt_error(&error)
                        && !replay_attributed_sessions
                            .contains(&(peer_id.clone(), active.session_instance))
                    {
                        replay_attributed_sessions.push((peer_id.clone(), active.session_instance));
                    }
                    first_decrypt_error.get_or_insert(error);
                }
            }
        }
        if let Some((peer_id, packet, token, session_instance)) = confirmed_active {
            drop(sessions);
            if let Some(token) = token {
                self.remember_promoted_responder_token(&peer_id, token);
            }
            return Ok(Some(InboundPacket {
                peer_id,
                packet,
                session_instance: Some(session_instance),
                from_previous_session: false,
                trace: None,
            }));
        }

        // A responder stages the new receive key before publishing its answer.
        // The first authenticated packet under that key is the peer's commit
        // acknowledgement and atomically promotes it for outbound traffic.
        let mut promoted = None;
        'pending_sessions: for (peer_id, peer_sessions) in sessions.iter_mut() {
            for (pending_token, pending) in &mut peer_sessions.pending {
                if pending.slot.session.our_index() != receiver_index {
                    continue;
                }
                match pending.slot.session.decrypt(&msg) {
                    Ok(packet) => {
                        promoted = Some((
                            peer_id.clone(),
                            packet,
                            pending_token.clone(),
                            pending.slot.session_instance,
                        ));
                        break 'pending_sessions;
                    }
                    Err(error) => {
                        if is_replay_decrypt_error(&error)
                            && !replay_attributed_sessions
                                .contains(&(peer_id.clone(), pending.slot.session_instance))
                        {
                            replay_attributed_sessions
                                .push((peer_id.clone(), pending.slot.session_instance));
                        }
                        first_decrypt_error.get_or_insert(error);
                    }
                }
            }
        }
        if let Some((peer_id, packet, token, session_instance)) = promoted {
            drop(sessions);
            // The first packet under a staged responder key promotes that key
            // to active.  Do not perform that replacement while only the
            // sessions mutex is held: an outbound packet for the old active
            // key may already own the per-peer emit lock.  Recheck the exact
            // session instance after acquiring the lock; a concurrent
            // remove/replace is then a terminal stale packet rather than an
            // old-key packet published after the new key.
            let emit_lock = self.outbound_emit_lock(&peer_id).await;
            let _emit_guard = emit_lock.lock().await;
            let (promoted_now, still_retained) = {
                let mut sessions = self.sessions.lock().await;
                match sessions.get_mut(&peer_id) {
                    None => (false, false),
                    Some(existing) => {
                        // The key can expire while the outbound ordering lock is held.
                        // Revalidate its lifetime with the sessions lock reacquired.
                        let promotion_time = Instant::now();
                        existing.prune_expired(promotion_time);
                        if existing.pending.get(&token).is_some_and(|pending| {
                            pending.slot.session_instance == session_instance
                        }) {
                            let promoted = existing.promote_pending(&token, promotion_time);
                            (promoted, promoted)
                        } else {
                            (false, existing.has_session_instance(session_instance))
                        }
                    }
                }
            };
            drop(_emit_guard);
            drop(emit_lock);
            if !still_retained {
                debug!(
                    peer_id = %peer_id,
                    session_instance,
                    "dropping responder packet whose staged session was replaced before promotion"
                );
                return Ok(None);
            }
            self.remember_promoted_responder_token(&peer_id, token);
            if promoted_now {
                info!(
                    event = "wireguard_responder_session_promoted",
                    peer_id = %peer_id,
                    session_instance,
                    "authenticated inbound packet promoted the staged responder session"
                );
                self.flush_pending_outbound_for_peer(&peer_id).await;
            }
            return Ok(Some(InboundPacket {
                peer_id,
                packet,
                session_instance: Some(session_instance),
                from_previous_session: false,
                trace: None,
            }));
        }

        for (peer_id, peer_sessions) in sessions.iter_mut() {
            let Some(previous) = peer_sessions.previous.as_mut() else {
                continue;
            };
            if previous.slot.session.our_index() != receiver_index {
                continue;
            }
            match previous.slot.session.decrypt(&msg) {
                Ok(packet) => {
                    return Ok(Some(InboundPacket {
                        peer_id: peer_id.clone(),
                        packet,
                        session_instance: Some(previous.slot.session_instance),
                        from_previous_session: true,
                        trace: None,
                    }));
                }
                Err(error) => {
                    if is_replay_decrypt_error(&error)
                        && !replay_attributed_sessions
                            .contains(&(peer_id.clone(), previous.slot.session_instance))
                    {
                        replay_attributed_sessions
                            .push((peer_id.clone(), previous.slot.session_instance));
                    }
                    first_decrypt_error.get_or_insert(error);
                }
            }
        }

        if let Some(error) = first_decrypt_error {
            let replay_sessions = std::mem::take(&mut replay_attributed_sessions);
            if !replay_sessions.is_empty() {
                self.note_hedge_duplicate_replay(
                    &replay_sessions,
                    receiver_index,
                    msg.counter,
                    wire_fingerprint(wire_bytes),
                );
            }
            return Err(InboundDecryptError::Decrypt(error));
        }

        debug!(
            "No WireGuard session for receiver index {}; dropping inbound packet",
            receiver_index
        );
        Ok(None)
    }

    /// Number of replay-classified decrypt duplicates attributed to a peer.
    #[cfg(test)]
    pub(crate) fn hedge_replay_count(&self, peer_id: &str) -> u64 {
        self.hedge_replay_counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer_id)
            .map_or(0, |counter| counter.count)
    }

    /// Count a relay-hedge attributable replay for each peer and log
    /// rate-limited.
    ///
    /// WireGuard's counter-based replay protection already drops the duplicate
    /// copy of a ciphertext delivered on both the Direct and the relay hedge
    /// path.  The duplicate is a proof of duplicate delivery, not of an
    /// attack: it never changes Direct/Relay path state, never establishes
    /// affinity and never triggers validation (the decryption itself failed
    /// before any observation was created).  Counting it keeps the storm out
    /// of the WARN log while security-class errors (parse failures, unknown
    /// receiver index, wrong key) still log at WARN through the ordinary
    /// error path.
    pub(in crate::transport) fn note_hedge_duplicate_replay(
        &self,
        sessions: &[(String, u64)],
        receiver_index: u32,
        counter: u64,
        wire_fp: u64,
    ) {
        let mut counters = self
            .hedge_replay_counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (peer_id, session_instance) in sessions {
            let replay_counter = counters.entry(peer_id.clone()).or_default();
            replay_counter.count = replay_counter.count.saturating_add(1);
            let loud = replay_counter
                .last_loud_at
                .is_none_or(|at| at.elapsed() >= HEDGE_REPLAY_WARN_INTERVAL);
            if loud {
                replay_counter.last_loud_at = Some(Instant::now());
                warn!(
                    event = "hedge_duplicate_replay",
                    peer_id = %peer_id,
                    receiver_index,
                    session_instance,
                    wireguard_counter = counter,
                    wire_fp = format_args!("{wire_fp:016x}"),
                    total = replay_counter.count,
                    "WireGuard replay protection dropped a duplicate copy of an already-decrypted ciphertext; no path state changes"
                );
            } else {
                debug!(
                    event = "hedge_duplicate_replay",
                    peer_id = %peer_id,
                    receiver_index,
                    session_instance,
                    wireguard_counter = counter,
                    wire_fp = format_args!("{wire_fp:016x}"),
                    total = replay_counter.count,
                    "duplicate ciphertext copy dropped; no path state changes"
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "tests/decryption.rs"]
mod tests;
