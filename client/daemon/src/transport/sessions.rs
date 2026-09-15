use super::{
    debug, info, CurrentSessionEvidenceGuardOutcome, HashMap, Instant, Ordering, OwnedMutexGuard,
    PeerTransportSessions, PendingTransportSession, PromotedResponderToken, ResponderSessionCommit,
    ResponderSessionConfirmation, ResponderSessionStage, ResponderTokenDisposition,
    TransportSession, TransportSessionSlot, TransportSessionStatus, WireGuardTransport,
    MAX_PENDING_RESPONDER_SESSIONS_PER_PEER, PENDING_RESPONDER_SESSION_GRACE,
    REASON_SESSION_QUEUE_REMOVED, RESPONDER_SESSION_REPLAY_GRACE,
};

impl WireGuardTransport {
    pub(super) fn allocate_session_instance(&self) -> u64 {
        // Zero is reserved for “unset” in diagnostics. A wrapping process is
        // not expected, but skip zero if an extremely long-lived daemon ever
        // exhausts the counter.
        let instance = self.next_session_instance.fetch_add(1, Ordering::Relaxed);
        if instance == 0 {
            self.next_session_instance.fetch_add(1, Ordering::Relaxed)
        } else {
            instance
        }
    }

    /// Return `(retained, current)` for the exact session which authenticated
    /// an inbound datagram. This second lookup intentionally happens after the
    /// decrypt await: control-plane teardown may remove or replace the session
    /// while the datagram is waiting in the inbound worker. A retained
    /// previous key is acceptable only for delivery overlap, never as current
    /// path evidence.
    pub(super) async fn session_instance_state(
        &self,
        peer_id: &str,
        session_instance: u64,
    ) -> (bool, bool) {
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;
        Self::session_instance_state_locked(&mut sessions, peer_id, session_instance, now)
    }

    pub(super) fn session_instance_state_locked(
        sessions: &mut HashMap<String, PeerTransportSessions>,
        peer_id: &str,
        session_instance: u64,
        now: Instant,
    ) -> (bool, bool) {
        let Some(peer_sessions) = sessions.get_mut(peer_id) else {
            return (false, false);
        };
        peer_sessions.prune_expired(now);
        let retained = peer_sessions.has_session_instance(session_instance);
        let current = peer_sessions
            .active
            .as_ref()
            .is_some_and(|slot| slot.session_instance == session_instance)
            || peer_sessions
                .pending
                .values()
                .any(|pending| pending.slot.session_instance == session_instance);
        (retained, current)
    }

    /// Try-only form used after the per-peer emit fence has been acquired.
    /// Session lifecycle writers use the canonical `emit -> sessions` order,
    /// so waiting here would stall the serial inbound actor while it owns the
    /// emit guard. Contention is retryable on the next authenticated frame.
    pub(super) fn try_session_instance_state(
        &self,
        peer_id: &str,
        session_instance: u64,
    ) -> Option<(bool, bool)> {
        let mut sessions = self.sessions.try_lock().ok()?;
        Some(Self::session_instance_state_locked(
            &mut sessions,
            peer_id,
            session_instance,
            Instant::now(),
        ))
    }

    /// Re-check a decrypted packet's session immediately before it is allowed
    /// to mutate path/evidence state.  The initial check in the inbound loop
    /// only protects the decrypt-to-dispatch boundary; relay-slot and UDP
    /// validation awaits can otherwise let a rekey/remove publish a new
    /// session in between.
    pub(super) async fn session_instance_is_current(
        &self,
        peer_id: &str,
        session_instance: Option<u64>,
    ) -> bool {
        let Some(session_instance) = session_instance else {
            // Legacy standalone callers do not attach a process-local session
            // instance. Preserve their historical behavior; production
            // daemon packets always carry one.
            return true;
        };
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let Ok(_emit_guard) = emit_lock.try_lock() else {
            return false;
        };
        self.try_session_instance_state(peer_id, session_instance)
            .is_some_and(|(_, current)| current)
    }

    /// Acquire the per-peer emit guard and verify that a decrypted packet was
    /// authenticated by the currently published session. The guard remains
    /// held for the caller's evidence commit, so session replacement/removal
    /// cannot cross the check and the corresponding path-state mutation.
    pub(super) async fn acquire_current_session_evidence_guard(
        &self,
        peer_id: &str,
        session_instance: Option<u64>,
    ) -> Option<OwnedMutexGuard<()>> {
        match self
            .acquire_current_session_evidence_guard_outcome(peer_id, session_instance)
            .await
        {
            CurrentSessionEvidenceGuardOutcome::Current(guard) => Some(guard),
            CurrentSessionEvidenceGuardOutcome::Contended
            | CurrentSessionEvidenceGuardOutcome::Stale => None,
        }
    }

    pub(super) async fn acquire_current_session_evidence_guard_outcome(
        &self,
        peer_id: &str,
        session_instance: Option<u64>,
    ) -> CurrentSessionEvidenceGuardOutcome {
        let Some(session_instance) = session_instance else {
            return CurrentSessionEvidenceGuardOutcome::Stale;
        };
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let Ok(emit_guard) = emit_lock.try_lock_owned() else {
            return CurrentSessionEvidenceGuardOutcome::Contended;
        };
        match self.try_session_instance_state(peer_id, session_instance) {
            Some((_, true)) => CurrentSessionEvidenceGuardOutcome::Current(emit_guard),
            Some((_, false)) => CurrentSessionEvidenceGuardOutcome::Stale,
            None => CurrentSessionEvidenceGuardOutcome::Contended,
        }
    }

    /// Install or replace an established transport session for a peer.
    pub async fn add_session(&self, peer_id: impl Into<String>, session: TransportSession) -> bool {
        self.install_active_session(peer_id, None, session).await
    }

    /// Install the initiator side of a completed handshake as the active
    /// outbound session while retaining the former receive key briefly.
    pub async fn install_active_session(
        &self,
        peer_id: impl Into<String>,
        token: Option<String>,
        session: TransportSession,
    ) -> bool {
        let peer_id = peer_id.into();
        let token_present = token.is_some();
        // Session replacement is a lifecycle boundary for the same counter
        // stream.  Wait for any in-flight business/control emission before
        // publishing the new active key; otherwise an old-key ciphertext can
        // be handed to the network after the new key is visible and become a
        // previous-session packet with no current-path evidence.
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let emit_lock_started = Instant::now();
        let emit_guard = emit_lock.lock_owned().await;
        let replaced_existing = self
            .install_active_session_locked(&peer_id, token, session)
            .await;
        debug!(
            event = "wireguard_session_installed",
            peer_id = %peer_id,
            replaced_existing,
            token_present,
            emit_lock_wait_ms = emit_lock_started.elapsed().as_millis() as u64,
            "active WireGuard session published after the per-peer emit lock boundary"
        );
        drop(emit_guard);
        self.flush_pending_outbound_for_peer(&peer_id).await;
        replaced_existing
    }

    /// Publish an active session while the caller already owns the peer emit
    /// guard. Callers may compose this with the network-generation gate, but
    /// must acquire locks in the canonical order `emit -> generation ->
    /// sessions`.
    pub(crate) async fn install_active_session_locked(
        &self,
        peer_id: &str,
        token: Option<String>,
        session: TransportSession,
    ) -> bool {
        let now = Instant::now();
        let session_instance = self.allocate_session_instance();
        let replaced_existing = {
            let mut sessions = self.sessions.lock().await;
            if let Some(existing) = sessions.get_mut(peer_id) {
                existing.prune_expired(now);
                existing.install_with_overlap(
                    TransportSessionSlot::new(session, token, session_instance),
                    now,
                )
            } else {
                sessions.insert(
                    peer_id.to_string(),
                    PeerTransportSessions::new(TransportSessionSlot::new(
                        session,
                        token,
                        session_instance,
                    )),
                );
                false
            }
        };
        debug!(
            event = "wireguard_session_install_locked",
            peer_id = %peer_id,
            session_instance,
            replaced_existing,
            "active WireGuard session published under the caller-owned emit boundary"
        );
        replaced_existing
    }

    /// Stage responder keys before publishing the answer.  Staged keys can
    /// decrypt the initiator's first new-session packet but never replace a
    /// usable active outbound key until that packet confirms peer adoption.
    pub async fn stage_responder_session(
        &self,
        peer_id: impl Into<String>,
        token: String,
        session: TransportSession,
    ) -> ResponderSessionStage {
        self.stage_responder_session_inner(peer_id.into(), token, session, false)
            .await
    }

    /// Re-stage the exact cached responder keys after a committed pending
    /// session expired without receiving adoption traffic. The cache lookup
    /// has already verified identical handshake bytes, so removing the
    /// replay marker and installing the same key is safe and lets a delayed
    /// initiator retry recover instead of waiting for cache eviction.
    pub async fn restage_cached_responder_session(
        &self,
        peer_id: impl Into<String>,
        token: String,
        session: TransportSession,
    ) -> ResponderSessionStage {
        self.stage_responder_session_inner(peer_id.into(), token, session, true)
            .await
    }

    pub(super) async fn stage_responder_session_inner(
        &self,
        peer_id: String,
        token: String,
        session: TransportSession,
        allow_seen_restage: bool,
    ) -> ResponderSessionStage {
        // Staging is a session-lifecycle mutation even though it does not
        // publish an outbound key yet. Serialize it with remove/flush/live
        // ingress so a late responder answer cannot recreate a pending
        // session after the peer was removed.
        let ingress_lock = self.outbound_ingress_lock(&peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let now = Instant::now();
        let session_instance = self.allocate_session_instance();
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.get_mut(&peer_id) {
            existing.prune_expired(now);
            let had_active = existing.active.is_some();
            if existing
                .active
                .as_ref()
                .and_then(|active| active.token.as_deref())
                == Some(token.as_str())
            {
                return ResponderSessionStage::ReplayableDuplicate { had_active };
            }
            if let Some(pending) = existing.pending.get_mut(&token) {
                // Give an exact cached-answer replay a fresh delivery window.
                // The cached key is still installed, so replaying the same
                // answer remains safe and can recover an ambiguous send.
                pending.expires_at = now + PENDING_RESPONDER_SESSION_GRACE;
                return ResponderSessionStage::ReplayableDuplicate { had_active };
            }
            let token_disposition = existing
                .responder_token_states
                .get(&token)
                .map(|state| state.disposition);
            if existing
                .previous
                .as_ref()
                .and_then(|previous| previous.slot.token.as_deref())
                == Some(token.as_str())
            {
                // Never replay an answer whose receive key is no longer the
                // active or staged responder session. Doing so can make the
                // initiator install a key that this responder has discarded.
                return ResponderSessionStage::StaleDuplicate;
            }
            if let Some(disposition) = token_disposition {
                if disposition == ResponderTokenDisposition::Terminal || !allow_seen_restage {
                    return ResponderSessionStage::StaleDuplicate;
                }
                if existing.pending.len() >= MAX_PENDING_RESPONDER_SESSIONS_PER_PEER {
                    return ResponderSessionStage::Busy;
                }
            }
            if existing.pending.len() >= MAX_PENDING_RESPONDER_SESSIONS_PER_PEER {
                return ResponderSessionStage::Busy;
            }
            let pending_session_instance = session_instance;
            existing.pending.insert(
                token.clone(),
                PendingTransportSession {
                    slot: TransportSessionSlot::new(
                        session,
                        Some(token.clone()),
                        pending_session_instance,
                    ),
                    expires_at: now + PENDING_RESPONDER_SESSION_GRACE,
                    answer_committed: false,
                },
            );
            existing.remember_responder_token(token, ResponderTokenDisposition::Restageable, now);
            ResponderSessionStage::Staged { had_active }
        } else {
            let mut peer_sessions = PeerTransportSessions::pending_only(PendingTransportSession {
                slot: TransportSessionSlot::new(session, Some(token.clone()), session_instance),
                expires_at: now + PENDING_RESPONDER_SESSION_GRACE,
                answer_committed: false,
            });
            peer_sessions.remember_responder_token(
                token,
                ResponderTokenDisposition::Restageable,
                now,
            );
            sessions.insert(peer_id, peer_sessions);
            ResponderSessionStage::Staged { had_active: false }
        }
    }

    /// Extend the receive-only responder window after the control-plane
    /// answer delivery attempt completes. Signaling latency must not consume
    /// the authenticated adoption window.
    pub async fn refresh_responder_session_grace(&self, peer_id: &str, token: &str) -> bool {
        let started = Instant::now();
        info!(
            event = "responder_session_grace_refresh_started",
            peer_id = %peer_id,
            "responder post-answer WireGuard grace refresh started"
        );
        let ingress_wait_started = Instant::now();
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let ingress_wait_us = ingress_wait_started.elapsed().as_micros() as u64;
        info!(
            event = "responder_session_grace_outbound_ingress_acquired",
            peer_id = %peer_id,
            wait_us = ingress_wait_us,
            "responder post-answer outbound ingress lock acquired"
        );
        let sessions_wait_started = Instant::now();
        let mut sessions = self.sessions.lock().await;
        let sessions_wait_us = sessions_wait_started.elapsed().as_micros() as u64;
        let Some(existing) = sessions.get_mut(peer_id) else {
            info!(
                event = "responder_session_grace_refresh_finished",
                peer_id = %peer_id,
                outcome = "peer_missing",
                ingress_wait_us,
                sessions_wait_us,
                total_us = started.elapsed().as_micros() as u64,
                "responder post-answer WireGuard grace refresh finished"
            );
            return false;
        };
        let Some(pending) = existing.pending.get_mut(token) else {
            info!(
                event = "responder_session_grace_refresh_finished",
                peer_id = %peer_id,
                outcome = "pending_session_missing",
                ingress_wait_us,
                sessions_wait_us,
                total_us = started.elapsed().as_micros() as u64,
                "responder post-answer WireGuard grace refresh finished"
            );
            return false;
        };
        pending.expires_at = Instant::now() + PENDING_RESPONDER_SESSION_GRACE;
        info!(
            event = "responder_session_grace_refresh_finished",
            peer_id = %peer_id,
            outcome = "refreshed",
            ingress_wait_us,
            sessions_wait_us,
            total_us = started.elapsed().as_micros() as u64,
            "responder post-answer WireGuard grace refresh finished"
        );
        true
    }

    /// Mark a staged responder answer as durably published.  Initial
    /// handshakes have no old path to preserve and become active now; rekeys
    /// remain pending until authenticated new-session traffic arrives.
    pub async fn commit_responder_session(
        &self,
        peer_id: &str,
        token: &str,
    ) -> ResponderSessionCommit {
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let emit_guard = emit_lock.lock_owned().await;
        let result = self.commit_responder_session_locked(peer_id, token).await;
        let flush_pending = result == ResponderSessionCommit::ActivatedInitial;
        drop(emit_guard);
        if flush_pending {
            self.flush_pending_outbound_for_peer(peer_id).await;
        }
        result
    }

    /// Commit a staged responder session while the caller already owns the
    /// peer emit guard. This lets a handshake compose the operation with the
    /// network-generation gate without ever waiting for emit while holding
    /// that gate.
    pub(crate) async fn commit_responder_session_locked(
        &self,
        peer_id: &str,
        token: &str,
    ) -> ResponderSessionCommit {
        let mut sessions = self.sessions.lock().await;
        Self::commit_responder_session_in(&mut sessions, peer_id, token, Instant::now())
    }

    /// Try-only responder commit used while the handshake owns both the peer
    /// emit fence and the network epoch. A busy session actor is a typed retry
    /// outcome; it must never become an `emit -> epoch -> sessions` waiter.
    pub(crate) fn try_commit_responder_session_locked(
        &self,
        peer_id: &str,
        token: &str,
    ) -> Option<ResponderSessionCommit> {
        let mut sessions = self.sessions.try_lock().ok()?;
        Some(Self::commit_responder_session_in(
            &mut sessions,
            peer_id,
            token,
            Instant::now(),
        ))
    }

    pub(super) fn commit_responder_session_in(
        sessions: &mut HashMap<String, PeerTransportSessions>,
        peer_id: &str,
        token: &str,
        now: Instant,
    ) -> ResponderSessionCommit {
        let Some(existing) = sessions.get_mut(peer_id) else {
            return ResponderSessionCommit::Missing;
        };
        existing.prune_expired(now);
        if existing
            .active
            .as_ref()
            .and_then(|active| active.token.as_deref())
            == Some(token)
        {
            ResponderSessionCommit::AlreadyPromoted
        } else if existing.pending.contains_key(token) {
            let activate_initial = existing.active.is_none();
            {
                let pending = existing
                    .pending
                    .get_mut(token)
                    .expect("pending responder token checked above");
                pending.answer_committed = true;
                if activate_initial {
                    pending.slot.awaiting_confirmation = true;
                }
            }
            existing.remember_responder_token(token, ResponderTokenDisposition::Restageable, now);
            if activate_initial {
                existing.promote_pending(token, now);
                ResponderSessionCommit::ActivatedInitial
            } else {
                ResponderSessionCommit::PendingConfirmation
            }
        } else {
            ResponderSessionCommit::Missing
        }
    }

    /// Discard an unpublished responder session. Returns false when the token
    /// was already promoted by authenticated traffic, which proves the answer
    /// reached the peer despite a control-plane response error.
    pub async fn discard_responder_session(&self, peer_id: &str, token: &str) -> bool {
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        let mut sessions = self.sessions.lock().await;
        let Some(existing) = sessions.get_mut(peer_id) else {
            return true;
        };
        if existing
            .active
            .as_ref()
            .and_then(|active| active.token.as_deref())
            == Some(token)
        {
            return false;
        }
        existing.pending.remove(token);
        existing.remember_responder_token(
            token,
            ResponderTokenDisposition::Terminal,
            Instant::now(),
        );
        true
    }

    /// Confirm a responder session from an authenticated Probe-v2 packet.
    /// Probe authentication is bound to the same handshake token and therefore
    /// proves that the peer received and adopted the corresponding WireGuard
    /// answer. Promote WireGuard first; the UDP layer then promotes Probe-v2.
    #[cfg(test)]
    pub async fn confirm_responder_session(
        &self,
        peer_id: &str,
        token: &str,
    ) -> ResponderSessionConfirmation {
        let emit_guard = self.acquire_outbound_emit_guard(peer_id).await;
        self.confirm_responder_session_with_emit_guard(peer_id, token, &emit_guard)
            .await
    }

    /// Confirm a responder session while the caller already owns the peer's
    /// counter-ordering guard. Cross-layer UDP adoption uses this form so its
    /// lock order stays `emit -> adoption -> epoch -> sessions`; acquiring
    /// emit after the global epoch gate would invert the outbound data path.
    pub(crate) async fn confirm_responder_session_with_emit_guard(
        &self,
        peer_id: &str,
        token: &str,
        _emit_guard: &OwnedMutexGuard<()>,
    ) -> ResponderSessionConfirmation {
        let now = Instant::now();
        let (result, flush_pending) = {
            let mut sessions = self.sessions.lock().await;
            let Some(existing) = sessions.get_mut(peer_id) else {
                return ResponderSessionConfirmation::Missing;
            };
            // The caller has already authenticated a Probe-v2 packet under
            // this exact token's pending key. Treat that proof as authoritative
            // even at the TTL boundary; pruning first would discard the WG key
            // a few microseconds before the matching transaction can commit.
            let active_matches = existing
                .active
                .as_ref()
                .is_some_and(|active| active.token.as_deref() == Some(token));
            if active_matches {
                if existing
                    .active
                    .as_ref()
                    .is_some_and(|active| active.session.is_expired())
                {
                    (ResponderSessionConfirmation::Expired, false)
                } else {
                    if let Some(active) = existing.active.as_mut() {
                        active.awaiting_confirmation = false;
                    }
                    (ResponderSessionConfirmation::AlreadyActive, false)
                }
            } else if existing
                .pending
                .get(token)
                .is_some_and(|pending| pending.slot.session.is_expired())
            {
                existing.pending.remove(token);
                existing.remember_responder_token(
                    token,
                    ResponderTokenDisposition::Restageable,
                    now,
                );
                (ResponderSessionConfirmation::Expired, false)
            } else if existing.pending.contains_key(token) {
                existing.promote_pending(token, now);
                (ResponderSessionConfirmation::Promoted, true)
            } else {
                existing.prune_expired(now);
                (ResponderSessionConfirmation::Missing, false)
            }
        };
        if flush_pending {
            // Probe-v2 still has to commit the matching key before the caller
            // can ACK or learn Direct. Do not make that cross-layer commit
            // wait behind queued user traffic or a slow network egress retry.
            let transport = self.clone();
            let peer_id = peer_id.to_string();
            tokio::spawn(async move {
                transport.flush_pending_outbound_for_peer(&peer_id).await;
            });
        }
        if matches!(
            result,
            ResponderSessionConfirmation::Promoted | ResponderSessionConfirmation::AlreadyActive
        ) {
            self.remember_promoted_responder_token(peer_id, token.to_string());
        }
        result
    }

    pub(super) fn remember_promoted_responder_token(&self, peer_id: &str, token: String) {
        const MAX_PENDING_CONFIRMATIONS: usize = 8;
        let now = Instant::now();
        let mut promoted = self
            .promoted_responder_tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let queue = promoted.entry(peer_id.to_string()).or_default();
        queue.retain(|item| item.expires_at > now);
        if queue.iter().any(|item| item.token == token) {
            return;
        }
        while queue.len() >= MAX_PENDING_CONFIRMATIONS {
            queue.pop_front();
        }
        queue.push_back(PromotedResponderToken {
            token,
            expires_at: now + RESPONDER_SESSION_REPLAY_GRACE,
        });
    }

    pub(super) fn pending_promoted_responder_tokens(&self, peer_id: &str) -> Vec<String> {
        let now = Instant::now();
        let mut promoted = self
            .promoted_responder_tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(queue) = promoted.get_mut(peer_id) else {
            return Vec::new();
        };
        queue.retain(|item| item.expires_at > now);
        let tokens = queue
            .iter()
            .map(|item| item.token.clone())
            .collect::<Vec<_>>();
        if tokens.is_empty() {
            promoted.remove(peer_id);
        }
        tokens
    }

    pub(crate) fn acknowledge_promoted_responder_token(&self, peer_id: &str, token: &str) {
        let mut promoted = self
            .promoted_responder_tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(queue) = promoted.get_mut(peer_id) {
            queue.retain(|item| item.token != token);
            if queue.is_empty() {
                promoted.remove(peer_id);
            }
        }
    }

    /// Replace a session and return the previous value for transactional rollback.
    pub async fn replace_session(
        &self,
        peer_id: impl Into<String>,
        session: TransportSession,
    ) -> Option<TransportSession> {
        let peer_id = peer_id.into();
        let emit_lock = self.outbound_emit_lock(&peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        let now = Instant::now();
        let mut sessions = self.sessions.lock().await;
        if let Some(existing) = sessions.get_mut(&peer_id) {
            existing.previous = None;
            existing.mark_all_responder_tokens_terminal(now);
            existing.clear_pending_as_terminal(now);
            existing
                .active
                .replace(TransportSessionSlot::new(
                    session,
                    None,
                    self.allocate_session_instance(),
                ))
                .map(|previous| previous.session)
        } else {
            sessions.insert(
                peer_id,
                PeerTransportSessions::new(TransportSessionSlot::new(
                    session,
                    None,
                    self.allocate_session_instance(),
                )),
            );
            None
        }
    }

    /// Restore the session state captured before a transactional replacement.
    pub async fn restore_session(&self, peer_id: &str, previous: Option<TransportSession>) {
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let _emit_guard = emit_lock.lock().await;
        let restored_previous = previous.is_some();
        let mut sessions = self.sessions.lock().await;
        if let Some(previous) = previous {
            sessions.insert(
                peer_id.to_string(),
                PeerTransportSessions::new(TransportSessionSlot::new(
                    previous,
                    None,
                    self.allocate_session_instance(),
                )),
            );
        } else {
            sessions.remove(peer_id);
        }
        drop(sessions);
        drop(_emit_guard);
        drop(emit_lock);
        if restored_previous {
            self.flush_pending_outbound_for_peer(peer_id).await;
        } else {
            self.remove_idle_outbound_emit_lock(peer_id).await;
        }
    }

    /// Remove a peer session with a structured lifecycle cause.
    pub async fn remove_session_with_reason(
        &self,
        peer_id: &str,
        reason: &'static str,
        caller: &'static str,
    ) {
        // A session flush may already have removed its queue and be forwarding
        // raw packets. Wait for that per-peer ingress turn before clearing the
        // session/backlog, so a live packet cannot be inserted behind a
        // removal and later resurrect an obsolete session queue.
        let ingress_lock = self.outbound_ingress_lock(peer_id).await;
        let _ingress_guard = ingress_lock.lock().await;
        // Keep active-session removal and the legacy pending queue removal
        // behind the same per-peer emit lock used by encryption.  A packet
        // that already owns the lock is allowed to finish; after this point
        // no old-key packet can be created or handed to a transport.
        let emit_lock = self.outbound_emit_lock(peer_id).await;
        let emit_lock_started = Instant::now();
        let _emit_guard = emit_lock.lock().await;
        let removed_session = self.sessions.lock().await.remove(peer_id).is_some();
        let removed = self.pending_outbound.lock().await.remove(peer_id);
        let removed_queue_packets = removed.as_ref().map_or(0, |queue| queue.len());
        let removed_queue_bytes = removed.as_ref().map_or(0, |queue| {
            queue
                .iter()
                .map(|item| item.packet.packet.len())
                .sum::<usize>()
        });
        info!(
            event = "wireguard_session_removed",
            peer_id = %peer_id,
            reason,
            caller,
            removed_session,
            removed_queue_packets,
            removed_queue_bytes,
            emit_lock_wait_ms = emit_lock_started.elapsed().as_millis() as u64,
            "WireGuard session and legacy session backlog were removed at one per-peer lifecycle boundary"
        );
        drop(_emit_guard);
        drop(emit_lock);
        if let Some(queue) = removed {
            let bytes = queue
                .iter()
                .map(|item| item.packet.packet.len())
                .sum::<usize>();
            self.record_outbound_drop(REASON_SESSION_QUEUE_REMOVED, queue.len(), bytes)
                .await;
            self.record_outbound_queue_event(
                "drop",
                peer_id,
                REASON_SESSION_QUEUE_REMOVED,
                queue.len(),
                bytes,
            )
            .await;
        }
        self.promoted_responder_tokens
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(peer_id);
        self.remove_idle_outbound_emit_lock(peer_id).await;
    }

    /// Compatibility wrapper for tests and legacy callers. Production
    /// lifecycle boundaries should use `remove_session_with_reason` so a
    /// session disappearance can be correlated with the caller that caused it.
    pub async fn remove_session(&self, peer_id: &str) {
        self.remove_session_with_reason(peer_id, "unspecified", "legacy_callsite")
            .await;
    }

    /// Return whether a peer has an encrypting session.
    pub async fn has_session(&self, peer_id: &str) -> bool {
        self.session_status(peer_id).await.has_active
    }

    /// Return one consistent active/pending snapshot under a single lock.
    pub async fn session_status(&self, peer_id: &str) -> TransportSessionStatus {
        let now = Instant::now();
        let (status, remove_idle_emit_lock) = {
            let mut sessions = self.sessions.lock().await;
            let Some(existing) = sessions.get_mut(peer_id) else {
                drop(sessions);
                self.remove_idle_outbound_emit_lock(peer_id).await;
                return TransportSessionStatus::default();
            };
            existing.prepare_active(now);
            let status = existing.status();
            let remove_empty = !status.has_active
                && !status.has_pending_responder
                && existing.previous.is_none()
                && existing.responder_token_states.is_empty();
            if remove_empty {
                sessions.remove(peer_id);
            }
            (status, remove_empty)
        };
        if remove_idle_emit_lock {
            self.remove_idle_outbound_emit_lock(peer_id).await;
        }
        status
    }

    /// Read the active/pending session state without joining the session
    /// mutex wait queue. Handshake publication calls this while it owns the
    /// per-peer emit fence; returning `None` lets the exact prepared
    /// transaction retry after releasing that fence instead of creating an
    /// `emit -> sessions` wait edge.
    pub(crate) fn try_session_status(&self, peer_id: &str) -> Option<TransportSessionStatus> {
        let now = Instant::now();
        let mut sessions = self.sessions.try_lock().ok()?;
        let Some(existing) = sessions.get_mut(peer_id) else {
            return Some(TransportSessionStatus::default());
        };
        existing.prepare_active(now);
        Some(existing.status())
    }

    /// Return whether a peer's session needs rekey.
    pub async fn session_needs_rekey(&self, peer_id: &str) -> bool {
        self.session_status(peer_id).await.needs_rekey
    }

    /// Return whether a peer's session has expired (reject threshold exceeded).
    pub async fn session_is_expired(&self, peer_id: &str) -> bool {
        self.session_status(peer_id).await.expired
    }
}
