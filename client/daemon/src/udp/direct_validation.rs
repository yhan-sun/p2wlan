use super::*;

impl UdpTransport {
    /// Allocate one direct-validation worker lease or merge an observation
    /// into the currently owned worker.
    ///
    /// The registry is the single-flight authority.  For a matching peer and
    /// generation it never returns a second lease: it only publishes the
    /// newest endpoint through the existing worker's watch channel.  A new
    /// generation revokes the old owner before installing the new one, so an
    /// old worker can neither continue emitting packets nor remove the new
    /// owner's expectation during cleanup.
    #[cfg(test)]
    pub(crate) async fn begin_or_merge_direct_validation(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        generation: u64,
    ) -> DirectValidationSessionStart {
        let remote_candidate_epoch = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or(0);
        self.begin_or_merge_direct_validation_with_remote_epoch(
            peer_id,
            endpoint,
            generation,
            remote_candidate_epoch,
        )
        .await
    }

    pub(crate) async fn begin_or_merge_direct_validation_with_remote_epoch(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        generation: u64,
        remote_candidate_epoch: u64,
    ) -> DirectValidationSessionStart {
        // Generation lookup + registry insertion must share the same epoch
        // boundary as `PeerManager::advance_*`: otherwise a scheduler could
        // read generation N, lose the race to an advance to N+1, then create
        // an old owner after that advance had already cleared every old
        // session.  The gate makes the check and insert one transaction.
        let _epoch_gate = self.network_epoch_gate.lock().await;
        let current_generation = self.peers.current_network_generation_sync();
        if current_generation != generation {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                requested_generation = generation,
                current_generation,
                reason_code = "direct_validation_stale_generation",
                "direct validation admission rejected before registry lookup"
            );
            return DirectValidationSessionStart::IgnoredStaleGeneration;
        }
        let Some(peer_session_generation) = self.peers.peer_session_generation_sync(peer_id) else {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                reason_code = "direct_validation_peer_session_unavailable",
                "direct validation admission rejected for an offline peer lifecycle"
            );
            return DirectValidationSessionStart::IgnoredInactive;
        };
        let current_remote_candidate_epoch = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or(0);
        if current_remote_candidate_epoch != remote_candidate_epoch {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                requested_remote_candidate_epoch = remote_candidate_epoch,
                current_remote_candidate_epoch,
                reason_code = "direct_validation_stale_remote_candidate_epoch",
                "direct validation admission rejected for a retired remote candidate epoch"
            );
            return DirectValidationSessionStart::IgnoredStaleGeneration;
        }
        // Direct promotion and its registry cancellation share this epoch
        // gate. A queued observation that waited behind the promotion must
        // therefore be suppressed instead of recreating the session it just
        // cancelled.
        let direct_confirmed = self.peers.is_direct_sync(peer_id);
        let peer_eligible = self
            .peers
            .is_direct_validation_eligible_for_endpoint(peer_id, endpoint)
            .await;
        let transport_closed = self.direct_validation.is_closed();
        let slow_relay_suppressed = self
            .direct_validation
            .is_slow_relay_validation_suppressed(peer_id, generation)
            .await;
        if !peer_eligible || transport_closed || slow_relay_suppressed {
            let reason_code = if direct_confirmed && !peer_eligible {
                "direct_validation_peer_already_direct"
            } else if !peer_eligible {
                "direct_validation_peer_ineligible"
            } else if transport_closed {
                "direct_validation_transport_registry_closed"
            } else {
                "direct_validation_slow_relay_cooldown"
            };
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                reason_code,
                direct_confirmed,
                peer_eligible,
                transport_closed,
                slow_relay_suppressed,
                "direct validation admission rejected by lifecycle gate"
            );
            return DirectValidationSessionStart::IgnoredInactive;
        }
        let mut sessions = self.direct_validation.sessions.lock().await;
        // `cancel_all` does not need the network epoch gate during transport
        // teardown. Recheck after waiting for its sessions lock so a stale
        // scheduler cannot create an owner after the terminal cancellation.
        if self.direct_validation.is_closed() {
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_admission_rejected",
                peer_id = %peer_id,
                remote_endpoint = %endpoint,
                generation,
                reason_code = "direct_validation_transport_registry_closed_after_lock",
                "direct validation admission rejected after waiting for registry lock"
            );
            return DirectValidationSessionStart::IgnoredInactive;
        }
        if let Some((target_tx, current)) = sessions
            .get(peer_id)
            .map(|session| (session.target_tx.clone(), *session.target_tx.borrow()))
        {
            if !current.cancelled
                && current.generation == generation
                && current.peer_session_generation == peer_session_generation
                && current.remote_candidate_epoch == remote_candidate_epoch
            {
                let replace_target = self
                    .peers
                    .should_replace_direct_validation_target(peer_id, current.endpoint, endpoint)
                    .await;
                let target_endpoint = if replace_target {
                    endpoint
                } else {
                    current.endpoint
                };
                let updated = DirectValidationTarget {
                    endpoint: target_endpoint,
                    ..current
                };
                target_tx.send_replace(updated);
                let target_class_upgraded = target_endpoint != current.endpoint
                    && self
                        .peers
                        .is_direct_validation_target_on_link_upgrade(
                            peer_id,
                            current.endpoint,
                            target_endpoint,
                        )
                        .await;
                if target_class_upgraded {
                    // A request sent to the lower-priority endpoint must not
                    // be promoted after a LAN target takes over.  The worker
                    // will observe the watch update and retry the preferred
                    // target; owner-bound cleanup rejects the old ACK.
                    let mut expectations = self.direct_validation.expectations.lock().await;
                    if expectations
                        .get(peer_id)
                        .is_some_and(|expectation| expectation.owner_token == current.owner_token)
                    {
                        expectations.remove(peer_id);
                    }
                }
                debug!(target: "p2pnet_daemon::direct_validation",
                    event = "direct_validation_observation_merged",
                    peer_id = %peer_id,
                    remote_endpoint = %endpoint,
                    previous_endpoint = %current.endpoint,
                    selected_endpoint = %target_endpoint,
                    target_replaced = target_endpoint != current.endpoint,
                    target_class_upgraded,
                    generation,
                    remote_candidate_epoch,
                    "merged direct-validation endpoint into existing worker"
                );
                return DirectValidationSessionStart::Merged;
            }

            // The old receiver sees cancellation before this map entry is
            // replaced.  Its owner-only cleanup becomes a no-op once the new
            // entry below owns the peer.
            target_tx.send_replace(DirectValidationTarget {
                cancelled: true,
                ..current
            });
            debug!(target: "p2pnet_daemon::direct_validation",
                event = "direct_validation_session_replaced",
                peer_id = %peer_id,
                previous_endpoint = %current.endpoint,
                previous_generation = current.generation,
                previous_remote_candidate_epoch = current.remote_candidate_epoch,
                replacement_endpoint = %endpoint,
                replacement_generation = generation,
                replacement_remote_candidate_epoch = remote_candidate_epoch,
                "replaced stale direct-validation worker before spawning the new generation"
            );
            let mut expectations = self.direct_validation.expectations.lock().await;
            if expectations
                .get(peer_id)
                .is_some_and(|expectation| expectation.owner_token == current.owner_token)
            {
                expectations.remove(peer_id);
            }
        }

        let owner_token = next_direct_validation_owner_token();
        let target = DirectValidationTarget {
            endpoint,
            generation,
            peer_session_generation,
            remote_candidate_epoch,
            owner_token,
            cancelled: false,
        };
        let (target_tx, target_rx) = watch::channel(target);
        sessions.insert(peer_id.to_string(), DirectValidationSession { target_tx });
        debug!(target: "p2pnet_daemon::direct_validation",
            event = "direct_validation_session_spawned",
            peer_id = %peer_id,
            remote_endpoint = %endpoint,
            generation,
            remote_candidate_epoch,
            "created one owned direct-validation worker"
        );
        DirectValidationSessionStart::Spawn(DirectValidationSessionLease {
            peer_id: peer_id.to_string(),
            owner_token,
            target_rx,
        })
    }

    /// Cancel all validation workers, for a UDP transport shutdown or
    /// replacement.  This is intentionally stronger than the generation
    /// helper: no expectation owned by the old transport may survive.
    pub(crate) async fn cancel_all_direct_validation_sessions(&self) {
        self.direct_validation.cancel_all().await;
    }

    /// Quarantine new Direct validation owners after an encrypted ACK proved
    /// the candidate only through a delayed mapping while the relay remained
    /// confirmed.  This is peer/generation scoped, so a later generation can
    /// start relay-first validation afresh without inheriting old state.
    pub(crate) async fn suppress_direct_validation_for_slow_relay(
        &self,
        peer_id: &str,
        generation: u64,
    ) {
        self.direct_validation
            .suppress_slow_relay_validation(peer_id, generation)
            .await;
    }

    /// Return whether a peer/generation is currently in the slow-relay
    /// quarantine.  The scheduler uses this only to attach a structured
    /// diagnostic reason to an ignored observation.
    pub(crate) async fn direct_validation_suppressed_by_slow_relay(
        &self,
        peer_id: &str,
        generation: u64,
    ) -> bool {
        self.direct_validation
            .is_slow_relay_validation_suppressed(peer_id, generation)
            .await
    }

    /// Remove a session only when the completing worker is still its owner.
    /// Returns whether the owner was current.  The expectation is cleared by
    /// the same owner check, preventing a retired worker from deleting a new
    /// session's request token.
    pub(crate) async fn finish_direct_validation_session(
        &self,
        peer_id: &str,
        owner_token: u64,
    ) -> bool {
        // A worker's session removal and owner-conditional expectation cleanup
        // share one lock boundary. This prevents a replacement session from
        // being observed between the two operations and keeps the registry
        // lock order identical to registration and ACK consumption.
        let mut sessions = self.direct_validation.sessions.lock().await;
        let owned_target = sessions.get(peer_id).and_then(|session| {
            let target = *session.target_tx.borrow();
            (target.owner_token == owner_token).then_some(target)
        });
        let owned = owned_target.is_some();
        if owned {
            // Removing the map entry is not enough: the worker owns a clone
            // of the watch receiver and can otherwise keep sending its
            // already-scheduled bounded request sequence after an ACK, a
            // slow-ACK retention decision, or a terminal timeout. Publish a
            // terminal state before removal so every worker that still holds
            // the receiver observes cancellation and exits before another
            // request is prepared.
            if let Some(session) = sessions.get(peer_id) {
                let current = *session.target_tx.borrow();
                session.target_tx.send_replace(DirectValidationTarget {
                    cancelled: true,
                    ..current
                });
            }
            sessions.remove(peer_id);
        }
        let mut expectations = self.direct_validation.expectations.lock().await;
        if expectations
            .get(peer_id)
            .is_some_and(|expectation| expectation.owner_token == owner_token)
        {
            expectations.remove(peer_id);
        }
        drop(expectations);
        drop(sessions);
        if let Some(target) = owned_target {
            self.peers
                .finish_direct_validation_attempt(
                    peer_id,
                    DirectValidationIdentity::owned(
                        crate::peer::PathEpoch::new(
                            target.generation,
                            target.peer_session_generation,
                            target.remote_candidate_epoch,
                        ),
                        owner_token,
                        None,
                        Some(target.endpoint),
                    ),
                )
                .await;
        }
        owned
    }

    /// Register the token an ACK must carry to confirm the direct-validation
    /// request this daemon is about to send to `peer_id`.
    ///
    /// Compatibility helper for focused token tests.  Runtime validation uses
    /// `expect_direct_validation_ack_owned` so cleanup is owner-bound.
    #[cfg(test)]
    pub(crate) async fn expect_direct_validation_ack(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
    ) {
        self.direct_validation.expectations.lock().await.insert(
            peer_id.to_string(),
            DirectValidationExpectation {
                request_id,
                generation,
                peer_session_generation: self
                    .peers
                    .peer_session_generation_sync(peer_id)
                    .unwrap_or(PeerSessionGeneration::UNBOUND),
                remote_candidate_epoch: 0,
                owner_token: 0,
                endpoint: None,
                socket_index: None,
                lease: None,
                sent_at: None,
                expires_at: Instant::now() + crate::DIRECT_VALIDATION_EXPECTATION_TTL,
            },
        );
    }

    /// Register an ACK expectation for exactly one validation worker.
    #[cfg(test)]
    pub(crate) async fn expect_direct_validation_ack_owned(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
        owner_token: u64,
        endpoint: SocketAddr,
    ) -> bool {
        self.expect_direct_validation_ack_owned_on_socket(
            peer_id,
            request_id,
            generation,
            owner_token,
            endpoint,
            None,
        )
        .await
    }

    /// Register an ACK expectation with the exact UDP socket used by the
    /// owned encrypted request.
    #[cfg(test)]
    pub(crate) async fn expect_direct_validation_ack_owned_on_socket(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
        owner_token: u64,
        endpoint: SocketAddr,
        socket_index: Option<usize>,
    ) -> bool {
        let remote_candidate_epoch = self
            .peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .unwrap_or(0);
        let peer_session_generation = self
            .peers
            .peer_session_generation_sync(peer_id)
            .unwrap_or(PeerSessionGeneration::UNBOUND);
        self.register_direct_validation_expectation(
            peer_id,
            DirectValidationExpectation {
                request_id,
                generation,
                peer_session_generation,
                remote_candidate_epoch,
                owner_token,
                endpoint: Some(endpoint),
                socket_index,
                lease: None,
                sent_at: None,
                expires_at: Instant::now() + crate::DIRECT_VALIDATION_EXPECTATION_TTL,
            },
        )
        .await
    }

    /// Register an ACK expectation while holding the send lease of the exact
    /// socket that will carry the request.  `expectations` then owns the
    /// lease until the ACK, a cancellation, a timeout or a generation
    /// invalidation removes the expectation, which guarantees the socket's
    /// reader stays alive for the whole ACK window even if the socket is
    /// detached immediately after the send.
    pub(super) async fn register_direct_validation_expectation(
        &self,
        peer_id: &str,
        expectation: DirectValidationExpectation,
    ) -> bool {
        // Keep the session lock while taking the expectation lock.  Lifecycle
        // cancellation follows this same order, so an owner can never insert
        // an expectation after it has already been removed from the session
        // registry.
        let sessions = self.direct_validation.sessions.lock().await;
        let active_owner = sessions.get(peer_id).is_some_and(|session| {
            let target = *session.target_tx.borrow();
            !target.cancelled
                && target.generation == expectation.generation
                && target.peer_session_generation == expectation.peer_session_generation
                && target.remote_candidate_epoch == expectation.remote_candidate_epoch
                && target.owner_token == expectation.owner_token
                && expectation.endpoint == Some(target.endpoint)
        });
        if !active_owner {
            return false;
        }
        self.direct_validation
            .expectations
            .lock()
            .await
            .insert(peer_id.to_string(), expectation);
        true
    }

    /// Resolve the socket that will actually carry one encrypted
    /// direct-validation request and hold its send lease.
    ///
    /// The resolution and the expectation registration happen in ONE logic
    /// path: the returned index is the exact socket the ACK must arrive on
    /// and the send uses the returned socket directly (never a re-resolution
    /// that could observe a detach or an affinity switch in between).  For a
    /// dynamic socket the lease is stored inside the expectation, so the
    /// socket's reader stays alive until the ACK or the expectation cleanup;
    /// a pool socket uses a noop lease.  When the owner no longer owns the
    /// endpoint, the lease is dropped and no expectation is left behind.
    pub(crate) async fn prepare_direct_validation_send(
        &self,
        peer_id: &str,
        validation: DirectValidationIdentity,
    ) -> std::result::Result<PreparedDirectValidationSend, DirectValidationSendError> {
        let request_id = validation
            .request_id
            .expect("Direct validation send identity has a request id");
        let generation = validation.epoch.network_generation;
        let peer_session_generation = validation.epoch.peer_session_generation;
        let remote_candidate_epoch = validation.epoch.remote_candidate_epoch;
        let owner_token = validation
            .owner_token
            .expect("Direct validation send identity has an owner token");
        let endpoint = validation
            .request_endpoint()
            .expect("Direct validation send identity has an endpoint");
        let (socket_index, socket, lease) = self
            .resolve_send_socket_with_lease_for_endpoint(peer_id, Some(endpoint))
            .await
            .ok_or(DirectValidationSendError::NoSocket)?;
        let registered = self
            .register_direct_validation_expectation(
                peer_id,
                DirectValidationExpectation {
                    request_id,
                    generation,
                    peer_session_generation,
                    remote_candidate_epoch,
                    owner_token,
                    endpoint: Some(endpoint),
                    socket_index: Some(socket_index),
                    lease: Some(lease),
                    sent_at: None,
                    expires_at: Instant::now() + crate::DIRECT_VALIDATION_EXPECTATION_TTL,
                },
            )
            .await;
        if !registered {
            return Err(DirectValidationSendError::OwnerRevoked);
        }
        // Publish the exact request/endpoint identity before the packet can be
        // sent. The ACK reducer then requires this full identity rather than
        // accepting any request that happens to reuse the worker owner token.
        if !self
            .peers
            .mark_direct_validation_started(peer_id, validation)
            .await
        {
            self.clear_direct_validation_expectation_if_owned(peer_id, owner_token)
                .await;
            return Err(DirectValidationSendError::OwnerRevoked);
        }
        Ok(PreparedDirectValidationSend {
            socket_index,
            socket,
        })
    }

    /// Stamp the monotonic boundary immediately before an owned encrypted
    /// validation request is handed to the UDP socket.  The ACK handler uses
    /// this value to measure the real encrypted Request -> ACK RTT.
    pub(crate) async fn mark_direct_validation_send_started(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
        owner_token: u64,
    ) -> bool {
        let mut expectations = self.direct_validation.expectations.lock().await;
        let Some(expectation) = expectations.get_mut(peer_id) else {
            return false;
        };
        if expectation.request_id != request_id
            || expectation.generation != generation
            || expectation.owner_token != owner_token
            || expectation.expires_at <= Instant::now()
        {
            return false;
        }
        expectation.sent_at = Some(Instant::now());
        true
    }

    /// Drop an expectation only if `owner_token` still owns its slot.  Used
    /// by the validation worker to withdraw a request that failed to send, so
    /// a late ACK can never match a request that never left this daemon.
    /// Dropping the expectation releases the socket send lease it held.
    pub(crate) async fn clear_direct_validation_expectation_if_owned(
        &self,
        peer_id: &str,
        owner_token: u64,
    ) -> bool {
        let mut expectations = self.direct_validation.expectations.lock().await;
        if expectations
            .get(peer_id)
            .is_some_and(|expectation| expectation.owner_token == owner_token)
        {
            expectations.remove(peer_id);
            true
        } else {
            false
        }
    }

    /// Consume a matched direct-validation ACK only while the caller holds
    /// the network epoch transaction for `current_generation`.
    ///
    /// The expectation's token generation, owner token and active registry
    /// target are verified under the registry's session -> expectation lock
    /// boundary.  The caller then uses the returned explicit generation for
    /// Direct promotion; it must not re-read current generation after this
    /// point.  Passing a stale `current_generation` is rejected before any
    /// expectation is consumed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn consume_direct_validation_ack(
        &self,
        peer_id: &str,
        request_id: u16,
        token_generation: u64,
        token_owner: u64,
        current_generation: u64,
        source: SocketAddr,
        socket_index: Option<usize>,
        endpoint_authenticated: bool,
    ) -> std::result::Result<DirectValidationExpectation, crate::udp::DirectValidationAckRejectReason>
    {
        if token_generation != current_generation {
            return Err(crate::udp::DirectValidationAckRejectReason::TokenGenerationMismatch);
        }
        let Some(current_peer_session_generation) =
            self.peers.peer_session_generation_sync(peer_id)
        else {
            return Err(
                crate::udp::DirectValidationAckRejectReason::ExpectationPeerSessionMismatch,
            );
        };
        let sessions = self.direct_validation.sessions.lock().await;
        let mut expectations = self.direct_validation.expectations.lock().await;
        let now = Instant::now();
        {
            let Some(expectation) = expectations.get(peer_id) else {
                return Err(crate::udp::DirectValidationAckRejectReason::NoExpectation);
            };
            if expectation.expires_at <= now {
                expectations.remove(peer_id);
                return Err(crate::udp::DirectValidationAckRejectReason::ExpectationExpired);
            }
            if expectation.request_id != request_id {
                return Err(crate::udp::DirectValidationAckRejectReason::RequestIdMismatch);
            }
            if expectation.generation != token_generation {
                return Err(
                    crate::udp::DirectValidationAckRejectReason::ExpectationGenerationMismatch,
                );
            }
            if expectation.peer_session_generation != current_peer_session_generation {
                return Err(
                    crate::udp::DirectValidationAckRejectReason::ExpectationPeerSessionMismatch,
                );
            }
            if expectation.owner_token != token_owner {
                return Err(crate::udp::DirectValidationAckRejectReason::OwnerMismatch);
            }
            if expectation
                .endpoint
                .is_some_and(|endpoint| endpoint != source)
                && !endpoint_authenticated
            {
                return Err(crate::udp::DirectValidationAckRejectReason::EndpointMismatch);
            }
            if expectation
                .socket_index
                .is_some_and(|expected| Some(expected) != socket_index)
            {
                return Err(crate::udp::DirectValidationAckRejectReason::SocketMismatch);
            }
        }
        let Some(session) = sessions.get(peer_id) else {
            return Err(crate::udp::DirectValidationAckRejectReason::SessionMissing);
        };
        let target = *session.target_tx.borrow();
        // `expectation.owner_token` equals `token_owner` (verified above), so
        // the active target is checked against the same owner the consumed
        // expectation carried.
        if target.cancelled {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetCancelled);
        }
        if target.generation != current_generation {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetGenerationMismatch);
        }
        if target.peer_session_generation != current_peer_session_generation {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetPeerSessionMismatch);
        }
        if target.remote_candidate_epoch
            != expectations
                .get(peer_id)
                .map(|expectation| expectation.remote_candidate_epoch)
                .unwrap_or(target.remote_candidate_epoch)
        {
            return Err(
                crate::udp::DirectValidationAckRejectReason::TargetRemoteCandidateEpochMismatch,
            );
        }
        if target.owner_token != token_owner {
            return Err(crate::udp::DirectValidationAckRejectReason::TargetOwnerMismatch);
        }
        // Move the expectation out: it owns the send lease of the socket that
        // carried the request, released exactly when the caller drops the
        // consumed expectation after the promotion transaction.
        Ok(expectations
            .remove(peer_id)
            .expect("expectation remained present while the registry locks were held"))
    }

    /// Whether an ACK token confirms the outstanding validation request for
    /// `peer_id`.  Retained for callers that only need a boolean; new inbound
    /// transaction code should use `consume_direct_validation_ack` to retain
    /// the owner token and explicit generation.
    #[cfg(test)]
    pub(crate) async fn confirm_direct_validation_ack(
        &self,
        peer_id: &str,
        request_id: u16,
        generation: u64,
    ) -> bool {
        let mut expectations = self.direct_validation.expectations.lock().await;
        let now = Instant::now();
        let Some(expectation) = expectations.get(peer_id) else {
            return false;
        };
        if expectation.expires_at <= now {
            expectations.remove(peer_id);
            return false;
        }
        if expectation.request_id != request_id || expectation.generation != generation {
            return false;
        }
        expectations.remove(peer_id);
        true
    }

    /// Whether any direct-validation expectation is outstanding for a peer
    /// (used by tests).
    #[cfg(test)]
    pub(crate) async fn has_direct_validation_expectation(&self, peer_id: &str) -> bool {
        let expectations = self.direct_validation.expectations.lock().await;
        let now = Instant::now();
        expectations
            .get(peer_id)
            .is_some_and(|expectation| expectation.expires_at > now)
    }

    /// Snapshot the active validation target for a peer (test-only).
    #[cfg(test)]
    pub(crate) async fn direct_validation_target(
        &self,
        peer_id: &str,
    ) -> Option<DirectValidationTarget> {
        self.direct_validation
            .sessions
            .lock()
            .await
            .get(peer_id)
            .map(|session| *session.target_tx.borrow())
    }

    /// Submit any authenticated endpoint observation to the daemon's one
    /// validation scheduler.  This is intentionally synchronous because the
    /// registered implementation is a bounded `try_send`; callers on the UDP
    /// receive path never await behind validation work.
    pub(crate) fn enqueue_direct_validation_observation(
        &self,
        observation: PeerReflexiveObservation,
    ) {
        // Endpoint-aware admission below still suppresses ordinary alternate
        // candidates for a Direct peer.  Keep this ingress open so a matched
        // LAN probe ACK can request a make-before-break validation while the
        // current public/UU path remains active.
        if self.peers.is_direct_sync(&observation.peer_id)
            && !self.peers.is_direct_validation_eligible_for_endpoint_sync(
                &observation.peer_id,
                observation.observed_endpoint,
            )
        {
            return;
        }
        let Some(trigger) = self.validation_trigger.as_ref() else {
            debug!(
                peer_id = %observation.peer_id,
                remote_endpoint = %observation.observed_endpoint,
                "no direct-validation scheduler ingress registered"
            );
            return;
        };
        trigger(observation);
    }

    /// Feed a matched authenticated ACK into the same observation ingress as
    /// the peer-reflexive loop.  The session registry, rather than a separate
    /// endpoint cooldown, supplies the hard worker bound and newest-wins
    /// endpoint policy.
    pub(super) async fn trigger_encrypted_validation(&self, peer_id: &str, endpoint: SocketAddr) {
        self.enqueue_direct_validation_observation(PeerReflexiveObservation {
            peer_id: peer_id.to_string(),
            observed_endpoint: endpoint,
        });
    }
}
