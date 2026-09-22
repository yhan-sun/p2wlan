impl PeerManager {
    /// Mirror a connection's accepted remote daemon incarnation into the
    /// bounded identity ledger. Callers already own `network_epoch_gate` and
    /// the connection writer, so `add_peer`/`remove_peer` use the same
    /// `epoch -> connections -> identity-ledger` order.
    fn record_remote_candidate_incarnation_high_water(
        &self,
        node_id: &str,
        public_key: &str,
        incarnation: u64,
    ) {
        self.remote_identity_ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_candidate_incarnation(node_id, public_key, incarnation);
    }

    /// Raise the encoded candidate replay floor in the bounded identity
    /// ledger. Candidate apply records the accepted generation itself; ingress
    /// preflight records its strict predecessor so a same-key PeerLeft/rejoin
    /// before apply cannot admit a lower counter. Legacy generations are
    /// ignored by the ledger implementation.
    fn record_remote_candidate_generation_replay_floor(
        &self,
        node_id: &str,
        public_key: &str,
        generation: u64,
    ) {
        self.remote_identity_ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .record_candidate_generation_replay_floor(node_id, public_key, generation);
    }

    /// Snapshot the currently published peer identity without waiting on the
    /// async connection map.  The identity ledger is populated before the
    /// membership lifecycle is published; re-checking that lifecycle after
    /// the ledger read closes a concurrent remove/rejoin boundary.
    pub(crate) fn peer_identity_public_key_sync(&self, node_id: &str) -> Option<String> {
        let lifecycle = self.peer_session_generation_sync(node_id)?;
        let public_key = self
            .remote_identity_ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(node_id)
            .map(|identity| identity.public_key.clone())?;
        self.peer_session_is_current_sync(node_id, lifecycle)
            .then_some(public_key)
    }

    /// Returns the peer's recorded public key from the identity ledger if known,
    /// regardless of whether the peer is currently online or offline.
    #[allow(dead_code)]
    pub(crate) fn peer_identity_recorded_public_key_sync(&self, node_id: &str) -> Option<String> {
        self.remote_identity_ledger
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(node_id)
            .map(|identity| identity.public_key.clone())
    }

    pub(crate) fn signal_sender_identity_matches_peer_sync(
        &self,
        node_id: &str,
        sender_public_key: Option<&str>,
    ) -> bool {
        let Some(sender_public_key) = sender_public_key.map(str::trim) else {
            return true;
        };
        !sender_public_key.is_empty()
            && self
                .peer_identity_public_key_sync(node_id)
                .is_some_and(|known| known.trim() == sender_public_key)
    }

    fn claim_remote_candidate_incarnation_in_connection(
        &self,
        node_id: &str,
        candidate_generation: u64,
        sender_public_key: Option<&str>,
        conn: Option<&mut PeerConnection>,
    ) -> RemoteCandidateIncarnationClaim {
        let sender_public_key = sender_public_key.map(str::trim);
        let Some(conn) = conn else {
            return if sender_public_key.is_some() {
                RemoteCandidateIncarnationClaim::IdentityMismatch
            } else {
                RemoteCandidateIncarnationClaim::NoReset
            };
        };
        if sender_public_key
            .is_some_and(|public_key| public_key.is_empty() || conn.public_key.trim() != public_key)
        {
            return RemoteCandidateIncarnationClaim::IdentityMismatch;
        }
        if crate::control::candidate_generation_is_malformed_encoded(candidate_generation) {
            return RemoteCandidateIncarnationClaim::RejectedLifecycle;
        }
        let Some(new_incarnation) =
            crate::control::candidate_generation_incarnation(candidate_generation)
        else {
            return RemoteCandidateIncarnationClaim::NoReset;
        };
        let Some(claim_floor) =
            crate::control::candidate_generation_predecessor_floor(candidate_generation)
        else {
            return RemoteCandidateIncarnationClaim::NoReset;
        };
        if conn
            .remote_candidate_incarnation_high_water
            .is_some_and(|accepted| new_incarnation < accepted)
            || (conn.remote_candidate_incarnation_high_water == Some(new_incarnation)
                && candidate_generation < conn.last_candidate_generation)
        {
            return RemoteCandidateIncarnationClaim::RejectedLifecycle;
        }
        conn.last_candidate_generation = conn.last_candidate_generation.max(claim_floor);
        self.record_remote_candidate_generation_replay_floor(
            node_id,
            &conn.public_key,
            claim_floor,
        );
        let Some(old_incarnation) = conn.remote_candidate_incarnation_high_water else {
            conn.remote_candidate_incarnation_high_water = Some(new_incarnation);
            self.record_remote_candidate_incarnation_high_water(
                node_id,
                &conn.public_key,
                new_incarnation,
            );
            return RemoteCandidateIncarnationClaim::NoReset;
        };
        if new_incarnation <= old_incarnation {
            return RemoteCandidateIncarnationClaim::NoReset;
        }
        conn.remote_candidate_incarnation_high_water = Some(new_incarnation);
        self.record_remote_candidate_incarnation_high_water(
            node_id,
            &conn.public_key,
            new_incarnation,
        );
        RemoteCandidateIncarnationClaim::Reset {
            old_incarnation,
            new_incarnation,
        }
    }

    /// Publish the strict replay floor for one valid encoded generation, then
    /// claim a strictly newer remote daemon incarnation when necessary.
    ///
    /// The replay floor is published for first-incarnation and same-incarnation
    /// signals too: candidate apply happens after this helper returns, so a
    /// PeerLeft/rejoin in that gap must not admit a lower counter. A new
    /// incarnation claim remains the high-water linearization point before
    /// slow WireGuard/UDP cleanup.
    pub(crate) async fn claim_remote_candidate_incarnation_for_identity(
        &self,
        node_id: &str,
        candidate_generation: u64,
        sender_public_key: Option<&str>,
    ) -> RemoteCandidateIncarnationClaim {
        let (_epoch_guard, mut connections) = self.lock_epoch_and_connections_write().await;
        self.claim_remote_candidate_incarnation_in_connection(
            node_id,
            candidate_generation,
            sender_public_key,
            connections.get_mut(node_id),
        )
    }

    /// Non-queuing remote-incarnation transaction for the inbound control
    /// coordinator.  It preserves the canonical `epoch -> connections`
    /// ordering, but never joins either wait queue.
    pub(crate) fn try_claim_remote_candidate_incarnation_for_identity(
        &self,
        node_id: &str,
        candidate_generation: u64,
        sender_public_key: Option<&str>,
    ) -> RemoteCandidateIncarnationTryClaim {
        // The synchronous ledger is published in the same transaction as the
        // connection high-water.  Once this incarnation is already current,
        // a later revision needs no lifecycle mutation and must not touch the
        // fair connection lock at all.  This is the common candidate-first ->
        // handshake sequence: candidate application may already be queued on
        // the writer, while the responder can still proceed immediately.
        let sender_public_key = sender_public_key.map(str::trim);
        let lifecycle = self.peer_session_generation_sync(node_id);
        let known_identity = lifecycle.and_then(|expected| {
            let identity = {
                self.remote_identity_ledger
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .get(node_id)
                    .cloned()
            };
            identity.filter(|_| self.peer_session_is_current_sync(node_id, expected))
        });
        if sender_public_key.is_some_and(|sender| {
            sender.is_empty()
                || known_identity
                    .as_ref()
                    .is_some_and(|identity| identity.public_key.trim() != sender)
        }) {
            return RemoteCandidateIncarnationTryClaim::Committed(
                RemoteCandidateIncarnationClaim::IdentityMismatch,
            );
        }
        if crate::control::candidate_generation_is_malformed_encoded(candidate_generation) {
            return RemoteCandidateIncarnationTryClaim::Committed(
                RemoteCandidateIncarnationClaim::RejectedLifecycle,
            );
        }
        match crate::control::candidate_generation_incarnation(candidate_generation) {
            None if sender_public_key.is_none() || known_identity.is_some() => {
                return RemoteCandidateIncarnationTryClaim::Committed(
                    RemoteCandidateIncarnationClaim::NoReset,
                );
            }
            Some(incoming) => {
                if let Some(identity) = known_identity.as_ref() {
                    match identity.candidate_incarnation_high_water {
                        Some(accepted) if incoming < accepted => {
                            return RemoteCandidateIncarnationTryClaim::Committed(
                                RemoteCandidateIncarnationClaim::RejectedLifecycle,
                            );
                        }
                        Some(accepted) if incoming == accepted => {
                            let outcome = if candidate_generation
                                < identity.candidate_generation_replay_floor
                            {
                                RemoteCandidateIncarnationClaim::RejectedLifecycle
                            } else {
                                if let Some(claim_floor) =
                                    crate::control::candidate_generation_predecessor_floor(
                                        candidate_generation,
                                    )
                                {
                                    self.record_remote_candidate_generation_replay_floor(
                                        node_id,
                                        &identity.public_key,
                                        claim_floor,
                                    );
                                }
                                RemoteCandidateIncarnationClaim::NoReset
                            };
                            return RemoteCandidateIncarnationTryClaim::Committed(outcome);
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }

        let epoch_gate = self.network_epoch_gate();
        let Ok(_epoch_guard) = epoch_gate.try_lock() else {
            return RemoteCandidateIncarnationTryClaim::ContendedEpoch;
        };
        let Ok(mut connections) = self.connections.try_write() else {
            return RemoteCandidateIncarnationTryClaim::ContendedConnections;
        };
        RemoteCandidateIncarnationTryClaim::Committed(
            self.claim_remote_candidate_incarnation_in_connection(
                node_id,
                candidate_generation,
                sender_public_key,
                connections.get_mut(node_id),
            ),
        )
    }

    /// Compatibility wrapper for internal tests that exercise only incarnation
    /// ordering and do not model the server-bound sender identity.
    #[cfg(test)]
    pub(crate) async fn claim_remote_candidate_incarnation_if_newer(
        &self,
        node_id: &str,
        candidate_generation: u64,
    ) -> Option<(u64, u64)> {
        match self
            .claim_remote_candidate_incarnation_for_identity(node_id, candidate_generation, None)
            .await
        {
            RemoteCandidateIncarnationClaim::Reset {
                old_incarnation,
                new_incarnation,
            } => Some((old_incarnation, new_incarnation)),
            RemoteCandidateIncarnationClaim::IdentityMismatch
            | RemoteCandidateIncarnationClaim::RejectedLifecycle
            | RemoteCandidateIncarnationClaim::NoReset => None,
        }
    }

    /// Finish a previously claimed remote restart after old WireGuard and UDP
    /// work has been stopped. The high-water equality check prevents an older
    /// cleanup owner from resetting state claimed by a later incarnation.
    pub(crate) async fn finish_claimed_remote_incarnation_reset(
        &self,
        node_id: &str,
        old_incarnation: u64,
        claimed_incarnation: u64,
        reason: &str,
    ) -> bool {
        let (had_relay_confirmation, direct_first_deadline_changed) = {
            let (_epoch_guard, mut connections) = self.lock_epoch_and_connections_write().await;
            let Some(conn) = connections.get_mut(node_id) else {
                return false;
            };
            if conn.remote_candidate_incarnation_high_water != Some(claimed_incarnation) {
                return false;
            }
            let had_relay_confirmation = conn.relay_confirmed_at.is_some();
            conn.reset_for_peer_session();
            let published_generation = self
                .peer_membership
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .publish(node_id, conn.online, true);
            if let Some(peer_session_generation) = published_generation {
                let epoch = PathEpoch::new(
                    self.current_network_generation_sync(),
                    peer_session_generation,
                    conn.remote_candidate_epoch(),
                );
                let event = if conn.online {
                    PathEvent::PeerOnline { epoch }
                } else {
                    PathEvent::PeerLeft { epoch }
                };
                conn.commit_path_transition(event, |_| {});
                let direct_first_deadline_changed = conn.online
                    && conn
                        .start_direct_first(epoch, self.config.relay.effective_path_policy(true));
                if had_relay_confirmation {
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    self.bump_relay_confirm_seq(node_id);
                }
                (had_relay_confirmation, direct_first_deadline_changed)
            } else {
                warn!(
                    "Peer lifecycle generation exhausted while resetting remote incarnation for {node_id}; authentication disabled"
                );
                if had_relay_confirmation {
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    self.bump_relay_confirm_seq(node_id);
                }
                (had_relay_confirmation, false)
            }
        };
        if direct_first_deadline_changed {
            self.direct_first_deadline_change_tx
                .send_modify(|sequence| *sequence = sequence.wrapping_add(1));
        }
        self.clear_hard_hard_sessions(Some(node_id)).await;
        self.emit_timeline(
            "peer_restart_detected",
            None,
            Some(reason),
            Some(format!(
                "peer={node_id} reason={reason} old_incarnation={old_incarnation} new_incarnation={claimed_incarnation} relay_confirmation_cleared={had_relay_confirmation}"
            )),
        );
        true
    }

    /// Convenience wrapper for tests and callers that do not need to compose
    /// transport cleanup between the claim and connection reset.
    #[cfg(test)]
    pub(crate) async fn reset_peer_session_if_remote_incarnation_changed(
        &self,
        node_id: &str,
        candidate_generation: u64,
        reason: &str,
    ) -> bool {
        let Some((old_incarnation, claimed_incarnation)) = self
            .claim_remote_candidate_incarnation_if_newer(node_id, candidate_generation)
            .await
        else {
            return false;
        };
        self.finish_claimed_remote_incarnation_reset(
            node_id,
            old_incarnation,
            claimed_incarnation,
            reason,
        )
        .await
    }
}
