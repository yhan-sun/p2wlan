/// Re-advertise the current local candidate snapshot without blocking the
/// serial control receiver. A remote daemon restart can invalidate the peer's
/// copy of our candidates even when our own candidate snapshot did not change;
/// this worker is the explicit lifecycle replay for that case.
fn schedule_candidate_republication<'a>(
    daemon: &'a Daemon,
    work: &mut FuturesUnordered<ControlEventWork<'a>>,
    peer_id: String,
    reason: &'static str,
) {
    work.push(Box::pin(async move {
        daemon
            .publish_current_candidates_to_peer(&peer_id, reason)
            .await;
    }));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteIncarnationResetWork {
    ClearAll,
    PreserveInitiator,
    PreserveResponder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RemoteIncarnationResetOutcome {
    Unchanged,
    Changed,
    RejectedIdentity,
    RejectedLifecycle,
    PendingCleanup,
    ContendedEpoch,
    ContendedConnections,
}

impl RemoteIncarnationResetOutcome {
    const fn retryable(self) -> bool {
        matches!(
            self,
            Self::PendingCleanup | Self::ContendedEpoch | Self::ContendedConnections
        )
    }

    const fn reason_code(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Changed => "changed",
            Self::RejectedIdentity => "stale_sender_identity",
            Self::RejectedLifecycle => "remote_incarnation_cleanup_rejected",
            Self::PendingCleanup => "remote_incarnation_cleanup_pending",
            Self::ContendedEpoch => "network_epoch_busy",
            Self::ContendedConnections => "connections_busy",
        }
    }
}

impl Daemon {
    fn kick_handshake_after_remote_incarnation_rotation(
        &self,
        peer_id: &str,
        claimed_incarnation: u64,
    ) {
        // Rotating PeerSessionGeneration correctly invalidates every starting
        // initiator reservation stamped by the retired incarnation. Publish a
        // separate commit-before-wake edge so the supervised maintenance
        // owner immediately reserves a replacement under the new generation
        // when this node is the deterministic initiator. The responder role
        // observes the same edge and exits without claiming a reservation.
        self.path_setup_kick_tx
            .send_modify(|revision| *revision = revision.wrapping_add(1));
        self.timeline.emit(
            "remote_incarnation_handshake_restart_kicked",
            None,
            Some("peer_session_generation_rotated"),
            Some(format!("peer={peer_id} incarnation={claimed_incarnation}")),
        );
    }

    fn clear_peer_handshake_lifecycle(&self, peer_id: &str, phase: &'static str) {
        let identity = HandshakeLeaseIdentity::new(
            peer_id,
            HandshakeOwnerKind::Cleanup,
            None,
            self.peers.current_network_generation_sync(),
            self.peers.peer_session_generation_sync(peer_id),
            phase,
        );
        let lease = self.handshake_arbiter.try_acquire(identity);
        match lease {
            Ok(lease) => {
                let cleared = self
                    .pending_handshakes
                    .try_with(|state| state.clear_peer(peer_id))
                    .is_some();
                drop(lease);
                if !cleared {
                    // Authoritative lifecycle cancellation may briefly wait
                    // for another short pending-state transaction, but never
                    // while owning the handshake mutation turn.
                    self.pending_handshakes.lock().clear_peer(peer_id);
                }
            }
            Err(contention) => {
                self.pending_handshakes.lock().clear_peer(peer_id);
                let holder = contention
                    .holder
                    .as_ref()
                    .map(HandshakeHolderSnapshot::detail)
                    .unwrap_or_else(|| "holder_kind=unknown holder_phase=unknown".to_string());
                self.timeline.emit(
                    "handshake_cleanup_turn_contended",
                    None,
                    Some("arbiter_contended"),
                    Some(format!("peer={peer_id} phase={phase} {holder}")),
                );
            }
        }
    }

    /// A same-node remote restart is identified by the encoded candidate
    /// generation carried in its offer. Keep this narrow: endpoint metadata is
    /// also changed by ordinary NAT churn and is not safe as a lifecycle
    /// signal. PeerManager's claimed-incarnation transaction and the exact
    /// peer-session generation provide the boundary; the handshake arbiter is
    /// intentionally absent because this cleanup crosses actor awaits.
    #[cfg(test)]
    async fn reset_peer_for_remote_incarnation_if_needed(
        &self,
        peer_id: &str,
        candidate_generation: u64,
        pending_work: RemoteIncarnationResetWork,
    ) -> bool {
        self.reset_peer_for_remote_incarnation_if_needed_for_identity(
            peer_id,
            candidate_generation,
            None,
            pending_work,
        )
        .await
            == RemoteIncarnationResetOutcome::Changed
    }

    /// Identity-aware production preflight.  Responder/candidate owners use
    /// the non-queuing claim and receive explicit contention; other lifecycle
    /// callers retain their existing serialized claim transaction.
    async fn reset_peer_for_remote_incarnation_if_needed_for_identity(
        &self,
        peer_id: &str,
        candidate_generation: u64,
        sender_public_key: Option<&str>,
        pending_work: RemoteIncarnationResetWork,
    ) -> RemoteIncarnationResetOutcome {
        if pending_work == RemoteIncarnationResetWork::PreserveResponder {
            // A claim publishes the incarnation high-water before its slow
            // transport cleanup commits. Candidate and responder futures are
            // independently polled, so fence that interval explicitly: the
            // second future must not reinterpret the claimed high-water as a
            // completed NoReset lifecycle.
            if let Some(pending_incarnation) = self
                .pending_handshakes
                .lock()
                .remote_incarnation_reset_in_progress(peer_id)
            {
                return if crate::control::candidate_generation_incarnation(candidate_generation)
                    .is_some_and(|incoming| incoming < pending_incarnation)
                {
                    RemoteIncarnationResetOutcome::RejectedLifecycle
                } else {
                    RemoteIncarnationResetOutcome::PendingCleanup
                };
            }
            let claim = self
                .peers
                .try_claim_remote_candidate_incarnation_for_identity(
                    peer_id,
                    candidate_generation,
                    sender_public_key,
                );
            let (old_incarnation, claimed_incarnation) = match claim {
                crate::peer::RemoteCandidateIncarnationTryClaim::ContendedEpoch => {
                    return RemoteIncarnationResetOutcome::ContendedEpoch;
                }
                crate::peer::RemoteCandidateIncarnationTryClaim::ContendedConnections => {
                    return RemoteIncarnationResetOutcome::ContendedConnections;
                }
                crate::peer::RemoteCandidateIncarnationTryClaim::Committed(
                    crate::peer::RemoteCandidateIncarnationClaim::IdentityMismatch,
                ) => {
                    self.peers
                        .record_direct_event(
                            peer_id,
                            "remote_signal_stale_identity",
                            None,
                            None,
                            None,
                            format!(
                                "ignored signal before incarnation/handshake/candidate mutation candidate_generation={candidate_generation}"
                            ),
                        )
                        .await;
                    self.timeline.emit(
                        "remote_signal_rejected",
                        None,
                        Some("stale_sender_identity"),
                        Some(format!(
                            "peer={peer_id} candidate_generation={candidate_generation}"
                        )),
                    );
                    return RemoteIncarnationResetOutcome::RejectedIdentity;
                }
                crate::peer::RemoteCandidateIncarnationTryClaim::Committed(
                    crate::peer::RemoteCandidateIncarnationClaim::RejectedLifecycle,
                ) => return RemoteIncarnationResetOutcome::RejectedLifecycle,
                crate::peer::RemoteCandidateIncarnationTryClaim::Committed(
                    crate::peer::RemoteCandidateIncarnationClaim::NoReset,
                ) => return RemoteIncarnationResetOutcome::Unchanged,
                crate::peer::RemoteCandidateIncarnationTryClaim::Committed(
                    crate::peer::RemoteCandidateIncarnationClaim::Reset {
                        old_incarnation,
                        new_incarnation,
                    },
                ) => (old_incarnation, new_incarnation),
            };
            if !self
                .pending_handshakes
                .lock()
                .begin_remote_incarnation_reset(peer_id, claimed_incarnation)
            {
                return RemoteIncarnationResetOutcome::PendingCleanup;
            }

            let retiring_peer_session = self.peers.peer_session_generation_sync(peer_id);
            if let Some(retiring_peer_session) = retiring_peer_session {
                self.punch_attempts
                    .retire_peer_session(peer_id, retiring_peer_session);
            } else {
                self.punch_attempts.cancel(peer_id);
            }
            info!(
                event = "peer_restart_detected",
                peer_id = %peer_id,
                old_incarnation,
                new_incarnation = claimed_incarnation,
                caller = "control_events.remote_incarnation_responder",
                "remote daemon incarnation advanced; rotating the peer session"
            );
            self.transport
                .remove_session_with_reason(
                    peer_id,
                    "remote_incarnation_changed",
                    "control_events.remote_incarnation_responder",
                )
                .await;
            let udp_slot = self.udp_transport.read().await;
            let changed = if let Some(udp) = udp_slot.clone() {
                // Keep the UDP adoption fence held from old-session cleanup
                // through publication of the rotated PeerSessionGeneration.
                udp.cleanup_peer_lifecycle_and_finish_remote_incarnation_reset(
                    peer_id,
                    "remote_incarnation_changed",
                    old_incarnation,
                    claimed_incarnation,
                )
                .await
            } else {
                // The slot read guard prevents a replacement UDP transport
                // from publishing before the reset commit completes.
                self.peers
                    .finish_claimed_remote_incarnation_reset(
                        peer_id,
                        old_incarnation,
                        claimed_incarnation,
                        "remote_incarnation_changed",
                    )
                    .await
            };
            if changed {
                self.pending_handshakes
                    .lock()
                    .clear_peer_except_responder_owner(peer_id);
            }
            self.pending_handshakes
                .lock()
                .finish_remote_incarnation_reset(peer_id, claimed_incarnation);
            drop(udp_slot);
            if changed {
                self.kick_handshake_after_remote_incarnation_rotation(peer_id, claimed_incarnation);
            }
            return if changed {
                RemoteIncarnationResetOutcome::Changed
            } else {
                RemoteIncarnationResetOutcome::RejectedLifecycle
            };
        }

        let claim = self
            .peers
            .claim_remote_candidate_incarnation_for_identity(
                peer_id,
                candidate_generation,
                sender_public_key,
            )
            .await;
        let (old_incarnation, claimed_incarnation) = match claim {
            crate::peer::RemoteCandidateIncarnationClaim::IdentityMismatch => {
                self.peers
                    .record_direct_event(
                        peer_id,
                        "remote_signal_stale_identity",
                        None,
                        None,
                        None,
                        format!(
                            "ignored signal before incarnation/handshake/candidate mutation candidate_generation={candidate_generation}"
                        ),
                    )
                    .await;
                self.timeline.emit(
                    "remote_signal_rejected",
                    None,
                    Some("stale_sender_identity"),
                    Some(format!(
                        "peer={peer_id} candidate_generation={candidate_generation}"
                    )),
                );
                return RemoteIncarnationResetOutcome::RejectedIdentity;
            }
            crate::peer::RemoteCandidateIncarnationClaim::RejectedLifecycle => {
                return RemoteIncarnationResetOutcome::RejectedLifecycle;
            }
            crate::peer::RemoteCandidateIncarnationClaim::NoReset => {
                return RemoteIncarnationResetOutcome::Unchanged;
            }
            crate::peer::RemoteCandidateIncarnationClaim::Reset {
                old_incarnation,
                new_incarnation,
            } => (old_incarnation, new_incarnation),
        };

        // Stop old key material and UDP adoption before resetting/publishing
        // the claimed lifecycle. An old Probe handler either finishes before
        // cleanup and is erased by the final reset, or resumes afterwards with
        // a retired PeerSessionGeneration and fails closed.
        let retiring_peer_session = self.peers.peer_session_generation_sync(peer_id);
        if let Some(retiring_peer_session) = retiring_peer_session {
            self.punch_attempts
                .retire_peer_session(peer_id, retiring_peer_session);
        } else {
            self.punch_attempts.cancel(peer_id);
        }
        info!(
            event = "peer_restart_detected",
            peer_id = %peer_id,
            old_incarnation,
            new_incarnation = claimed_incarnation,
            caller = "control_events.remote_incarnation",
            "remote daemon incarnation advanced; rotating the peer session"
        );
        self.transport
            .remove_session_with_reason(
                peer_id,
                "remote_incarnation_changed",
                "control_events.remote_incarnation",
            )
            .await;
        let udp_slot = self.udp_transport.read().await;
        let changed = if let Some(udp) = udp_slot.clone() {
            udp.cleanup_peer_lifecycle_and_finish_remote_incarnation_reset(
                peer_id,
                "remote_incarnation_changed",
                old_incarnation,
                claimed_incarnation,
            )
            .await
        } else {
            self.peers
                .finish_claimed_remote_incarnation_reset(
                    peer_id,
                    old_incarnation,
                    claimed_incarnation,
                    "remote_incarnation_changed",
                )
                .await
        };
        if changed {
            let mut pending = self.pending_handshakes.lock();
            match pending_work {
                RemoteIncarnationResetWork::ClearAll => pending.clear_peer(peer_id),
                RemoteIncarnationResetWork::PreserveInitiator => {
                    pending.clear_peer_except_pending_initiator(peer_id);
                    // The reset deliberately rotates PeerSessionGeneration. The
                    // exact initiator transaction survives, so rebind only that
                    // transaction to the just-published generation before its
                    // answer is consumed.
                    if pending.pending.contains_key(peer_id) {
                        if let Some(session_generation) =
                            self.peers.peer_session_generation_sync(peer_id)
                        {
                            pending
                                .pending_peer_session_generations
                                .insert(peer_id.to_string(), session_generation);
                        }
                    }
                }
                RemoteIncarnationResetWork::PreserveResponder => {
                    pending.clear_peer_except_responder_owner(peer_id)
                }
            }
        }
        drop(udp_slot);
        if changed {
            self.kick_handshake_after_remote_incarnation_rotation(peer_id, claimed_incarnation);
            RemoteIncarnationResetOutcome::Changed
        } else {
            RemoteIncarnationResetOutcome::RejectedLifecycle
        }
    }
}
