impl PeerManager {
    #[cfg(test)]
    pub(crate) fn install_relay_probe_snapshot_gate_for_test(
        &self,
        node_id: &str,
        gate: Arc<RelayProbeSnapshotTestGate>,
    ) {
        *self
            .relay_probe_snapshot_test_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some((node_id.to_string(), gate));
    }

    #[cfg(test)]
    async fn pause_relay_probe_snapshot_for_test(
        &self,
        connections: &HashMap<String, PeerConnection>,
    ) {
        let gate = {
            let mut installed = self
                .relay_probe_snapshot_test_gate
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if installed
                .as_ref()
                .is_some_and(|(peer_id, _)| connections.contains_key(peer_id))
            {
                installed.take().map(|(_, gate)| gate)
            } else {
                None
            }
        };
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.notified().await;
        }
    }
}

impl PeerManager {
    /// Register the token of a forced-relay probe the local daemon just sent,
    /// against which a relay-ingress ACK is verified.  Newest-wins per peer;
    /// the map is bounded by the per-peer probe loop's single in-flight probe.
    #[cfg(test)]
    pub fn register_relay_probe_expectation(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
    ) -> bool {
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        self.register_relay_probe_expectation_inner(
            node_id,
            generation,
            request_id,
            owner_token,
            relay_endpoint,
            None,
            peer_session_generation,
            Instant::now(),
            crate::relay_probe::RelayProbePurpose::Confirmation,
        )
    }

    /// Register a probe expectation bound to one local relay connection
    /// incarnation.  Endpoint + network generation are not enough during a
    /// make-before-break renewal because the old and new connections may use
    /// the same endpoint and peer session.
    #[cfg(test)]
    pub(crate) fn register_relay_probe_expectation_for_transport(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
        relay_connection_id: u64,
    ) -> bool {
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        self.register_relay_probe_expectation_inner(
            node_id,
            generation,
            request_id,
            owner_token,
            relay_endpoint,
            Some(relay_connection_id),
            peer_session_generation,
            Instant::now(),
            crate::relay_probe::RelayProbePurpose::Confirmation,
        )
    }

    /// Commit a forced-confirmation expectation at the relay writer's actual
    /// `write_all` boundary. The peer lifecycle was snapshotted before
    /// encryption; re-checking it here prevents an old queued ciphertext from
    /// registering against a same-node replacement peer.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_relay_probe_expectation_at_write_boundary(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
        relay_connection_id: u64,
        peer_session_generation: PeerSessionGeneration,
        sent_at: Instant,
    ) -> bool {
        self.register_relay_probe_expectation_inner(
            node_id,
            generation,
            request_id,
            owner_token,
            relay_endpoint,
            Some(relay_connection_id),
            peer_session_generation,
            sent_at,
            crate::relay_probe::RelayProbePurpose::Confirmation,
        )
    }

    /// Register a periodic RTT sample only while the peer is already
    /// confirmed on this exact network/relay incarnation.  This prevents the
    /// slower health sampler from overwriting the forced-confirmation probe
    /// when confirmation is revoked between target selection and emit.
    pub(crate) async fn relay_validation_write_permit_for_transport(
        &self,
        node_id: &str,
        generation: u64,
        relay_endpoint: &str,
        relay_connection_id: u64,
    ) -> Option<PeerSessionGeneration> {
        let (_epoch_guard, conns) = self.lock_epoch_and_connections_read().await;
        if generation != self.current_network_generation_sync() {
            return None;
        }
        let peer_session_generation = self.peer_session_generation_sync(node_id)?;
        let confirmed_on_transport = conns.get(node_id).is_some_and(|conn| {
            conn.online
                && conn.state != ConnectionState::Closed
                && conn.relay_confirmed_at.is_some()
                && conn.relay_confirmed_generation == Some(generation)
                && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
                && conn.relay_confirmed_connection_id == Some(relay_connection_id)
        });
        if !confirmed_on_transport {
            return None;
        }
        self.peer_session_is_current_sync(node_id, peer_session_generation)
            .then_some(peer_session_generation)
    }

    /// Install a periodic health expectation at the relay writer boundary.
    /// A forced-confirmation expectation owns the per-peer slot and cannot be
    /// displaced by this lower-priority sampler.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_relay_validation_expectation_at_write_boundary(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
        relay_connection_id: u64,
        peer_session_generation: PeerSessionGeneration,
        sent_at: Instant,
    ) -> bool {
        self.register_relay_probe_expectation_inner(
            node_id,
            generation,
            request_id,
            owner_token,
            relay_endpoint,
            Some(relay_connection_id),
            peer_session_generation,
            sent_at,
            crate::relay_probe::RelayProbePurpose::Validation,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn register_relay_probe_expectation_inner(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
        peer_session_generation: PeerSessionGeneration,
        sent_at: Instant,
        purpose: crate::relay_probe::RelayProbePurpose,
    ) -> bool {
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }
        let mut expectations = self
            .relay_probe_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if purpose == crate::relay_probe::RelayProbePurpose::Validation
            && expectations.get(node_id).is_some_and(|existing| {
                existing.purpose == crate::relay_probe::RelayProbePurpose::Confirmation
                    && existing.fresh(sent_at)
                    && existing.generation == generation
                    && self.peer_session_is_current_sync(node_id, existing.peer_session_generation)
            })
        {
            return false;
        }
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }
        let retransmitted = expectations.get(node_id).is_some_and(|existing| {
            existing.purpose == purpose
                && existing.generation == generation
                && existing.request_id == request_id
                && existing.owner_token == owner_token
                && existing.relay_endpoint == relay_endpoint
                && existing.relay_connection_id == relay_connection_id
                && existing.peer_session_generation == peer_session_generation
        });
        expectations.insert(
            node_id.to_string(),
            crate::relay_probe::RelayProbeExpectation {
                purpose,
                peer_session_generation,
                generation,
                request_id,
                owner_token,
                relay_endpoint: relay_endpoint.to_string(),
                relay_connection_id,
                sent_at,
                rtt_sample_eligible: !retransmitted,
            },
        );
        true
    }

    /// Remove a send-boundary expectation only when it is still the exact
    /// request whose local relay handoff failed.  A concurrent newer request
    /// must never be cancelled by the older send's completion path.
    pub(crate) fn cancel_relay_probe_expectation_if_matches(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_connection_id: Option<u64>,
    ) {
        let mut expectations = self
            .relay_probe_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if expectations.get(node_id).is_some_and(|expectation| {
            expectation.generation == generation
                && expectation.request_id == request_id
                && expectation.owner_token == owner_token
                && expectation.relay_connection_id == relay_connection_id
        }) {
            expectations.remove(node_id);
        }
    }

    /// Consume a forced-relay probe ACK.  The ACK confirms the relay path only
    /// when:
    ///   - its token mirrors the outstanding expectation (request id +
    ///     generation + owner), and
    ///   - the expectation is still fresh, and
    ///   - the ACK ACTUALLY arrived over the same relay the probe was sent on
    ///     (`ack_ingress == expectation.relay_endpoint`), so a late ACK from an
    ///     old relay can never admit the path, and
    ///   - the local network generation has not advanced past the probe's
    ///     generation (a stale-generation ACK is not evidence for the current
    ///     path).
    ///
    /// Returns whether the ACK matched and promoted the peer.
    #[cfg(test)]
    pub(crate) async fn consume_relay_probe_ack(
        &self,
        node_id: &str,
        token: crate::relay_probe::RelayProbeToken,
        ack_ingress: &str,
    ) -> bool {
        self.consume_relay_probe_ack_inner(node_id, token, ack_ingress, None, Some(0))
    }

    /// Consume an ACK from a live relay reader, including the local relay
    /// connection incarnation that delivered it.
    #[cfg(test)]
    pub(crate) async fn consume_relay_probe_ack_with_transport(
        &self,
        node_id: &str,
        token: crate::relay_probe::RelayProbeToken,
        ack_ingress: &str,
        relay_connection_id: Option<u64>,
    ) -> bool {
        self.consume_relay_probe_ack_inner(
            node_id,
            token,
            ack_ingress,
            relay_connection_id,
            Some(0),
        )
    }

    pub(crate) fn consume_relay_probe_ack_with_transport_for_session(
        &self,
        node_id: &str,
        token: crate::relay_probe::RelayProbeToken,
        ack_ingress: &str,
        relay_connection_id: Option<u64>,
        wireguard_session_instance: u64,
    ) -> bool {
        self.consume_relay_probe_ack_inner(
            node_id,
            token,
            ack_ingress,
            relay_connection_id,
            Some(wireguard_session_instance),
        )
    }

    fn consume_relay_probe_ack_inner(
        &self,
        node_id: &str,
        token: crate::relay_probe::RelayProbeToken,
        ack_ingress: &str,
        ack_connection_id: Option<u64>,
        wireguard_session_instance: Option<u64>,
    ) -> bool {
        // Quarantine is mirrored synchronously.  The serial inbound actor
        // must not await manager state before deciding whether this ACK can
        // enter the lifecycle commit.
        if self.peer_quarantined_sync(node_id) {
            let removed = self
                .relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id)
                .is_some();
            if removed {
                self.emit_timeline(
                    "relay_probe_ack_stale",
                    Some("relay"),
                    Some("peer_quarantined"),
                    Some(format!(
                        "peer={node_id} request_id={} generation={} owner_present=true ingress={ack_ingress}",
                        token.request_id, token.generation
                    )),
                );
            }
            return false;
        }
        let now = Instant::now();
        let expectation = {
            let expectations = self
                .relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            expectations.get(node_id).cloned()
        };
        let Some(expectation) = expectation else {
            debug!(
                event = "relay_probe_ack_unmatched",
                peer_id = %node_id,
                request_id = token.request_id,
                generation = token.generation,
                owner_present = true,
                "relay probe ACK had no fresh matching expectation"
            );
            return false;
        };
        let token_and_endpoint_ok = expectation.accepts(&token, now, ack_ingress);
        let connection_ok = expectation.accepts_connection(ack_connection_id);
        if !token_and_endpoint_ok || !connection_ok {
            // Distinguish a mismatched INGRESS relay from a generic stale ACK
            // so diagnostics can tell "old relay" from "late ACK".
            let token_ok = expectation.matches(&token) && expectation.fresh(now);
            let reason_code = if token_ok && expectation.relay_endpoint != ack_ingress {
                "relay_mismatch"
            } else if token_and_endpoint_ok && !connection_ok {
                "relay_transport_replaced"
            } else {
                "stale"
            };
            self.emit_timeline(
                "relay_probe_ack_stale",
                Some("relay"),
                Some(reason_code),
                Some(format!(
                    "peer={node_id} request_id={} generation={} owner_present=true expected_relay={} ack_ingress={ack_ingress} expected_connection_id={:?} ack_connection_id={:?}",
                    token.request_id,
                    token.generation,
                    expectation.relay_endpoint,
                    expectation.relay_connection_id,
                    ack_connection_id,
                )),
            );
            return false;
        }
        if !self.peer_session_is_current_sync(node_id, expectation.peer_session_generation) {
            self.emit_timeline(
                "relay_probe_ack_stale",
                Some("relay"),
                Some("peer_lifecycle_changed"),
                Some(format!(
                    "peer={node_id} request_id={} generation={} ingress={ack_ingress}",
                    token.request_id, expectation.generation
                )),
            );
            return false;
        }
        // A probe whose local network generation has advanced is not evidence
        // for the current path (the candidate/NAT mapping changed).
        if expectation.generation != self.current_network_generation_sync() {
            self.emit_timeline(
                "relay_probe_ack_stale",
                Some("relay"),
                Some("generation_changed"),
                Some(format!(
                    "peer={node_id} request_id={} expected_generation={} current_generation={}",
                    token.request_id,
                    expectation.generation,
                    self.current_network_generation_sync()
                )),
            );
            return false;
        }
        let relay_endpoint = expectation.relay_endpoint.clone();
        let generation = expectation.generation;
        let relay_rtt = expectation
            .rtt_sample_eligible
            .then(|| now.saturating_duration_since(expectation.sent_at));
        let confirmation_changed = self.confirm_relay_peer_with_transport_for_lifecycle(
            node_id,
            &relay_endpoint,
            generation,
            ack_connection_id,
            Some(expectation.peer_session_generation),
            wireguard_session_instance,
        );
        // A periodic timed probe normally hits an already-confirmed relay, so
        // confirmation_changed is false.  Commit the RTT only after re-checking
        // the exact online peer/network/relay lifecycle at the write boundary.
        let accepted = self.accept_relay_probe_ack_for_current_lifecycle(
            node_id,
            &relay_endpoint,
            generation,
            ack_connection_id,
            Some(expectation.peer_session_generation),
            RelayHealthObservationIdentity {
                owner_token: expectation.owner_token,
                request_id: expectation.request_id,
            },
            relay_rtt,
        );
        if confirmation_changed || accepted {
            // Consume only after the lifecycle-bound commit succeeded.  A
            // contended try-write keeps the exact expectation available for
            // the next independently encrypted probe ACK instead of losing
            // the sole proof to local lock scheduling.
            let mut expectations = self
                .relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if expectations.get(node_id).is_some_and(|current| {
                current.generation == expectation.generation
                    && current.request_id == expectation.request_id
                    && current.owner_token == expectation.owner_token
                    && current.relay_connection_id == expectation.relay_connection_id
                    && current.peer_session_generation == expectation.peer_session_generation
            }) {
                expectations.remove(node_id);
            }
        }
        info!(
            event = "relay_probe_ack_consumed",
            peer_id = %node_id,
            relay_endpoint = %relay_endpoint,
            generation = generation,
            request_id = token.request_id,
            confirmed = confirmation_changed || accepted,
            relay_rtt_ms = ?relay_rtt.map(|rtt| rtt.as_millis() as u64),
            "relay_probe_ack_consumed peer_id={node_id} relay_endpoint={relay_endpoint} request_id={} confirmed={}",
            token.request_id,
            confirmation_changed || accepted,
        );
        confirmation_changed || accepted
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_relay_probe_ack_for_current_lifecycle(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
        peer_session_generation: Option<PeerSessionGeneration>,
        observation: RelayHealthObservationIdentity,
        relay_rtt: Option<Duration>,
    ) -> bool {
        let epoch_gate = self.network_epoch_gate();
        let Ok(_epoch_guard) = epoch_gate.try_lock() else {
            return false;
        };
        if generation != self.current_network_generation_sync() {
            return false;
        }
        let Some(expected_lifecycle) = peer_session_generation else {
            return false;
        };
        if !self.peer_session_is_current_sync(node_id, expected_lifecycle) {
            return false;
        }
        let Ok(mut conns) = self.connections.try_write() else {
            return false;
        };
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        let current = conn.online
            && conn.state != ConnectionState::Closed
            && conn.relay_confirmed_at.is_some()
            && conn.relay_confirmed_generation == Some(generation)
            && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
            && conn.relay_confirmed_connection_id == relay_connection_id;
        if !current {
            return false;
        }
        let Some(relay_rtt) = relay_rtt else {
            return true;
        };
        let relay = RelayConnectionIdentity::new(
            PathEpoch::new(
                generation,
                expected_lifecycle,
                conn.remote_candidate_epoch(),
            ),
            relay_endpoint,
            relay_connection_id,
        );
        conn.commit_path_transition(
            PathEvent::RelayHealthObserved { relay, observation },
            |conn| conn.relay_health.record_success_with_latency(relay_rtt),
        )
        .accepted()
    }

    /// Peers that still need a forced-relay probe: online and not yet relay
    /// confirmed.  Direct peers remain in this list because Direct validation
    /// is a background upgrade and must not suppress relay-first confirmation.
    /// The relay probe loop further filters by WireGuard session readiness (it
    /// owns the transport) and sends one probe per returned peer
    /// (newest-wins expectation), repeating until confirmed or the peer is
    /// quarantined/offline.
    pub async fn relay_probe_targets(&self) -> Vec<(String, String, u64)> {
        let generation = self.current_network_generation().await;
        let connections = self.connections.read().await;
        #[cfg(test)]
        self.pause_relay_probe_snapshot_for_test(&connections).await;
        let candidates: Vec<_> = connections
            .values()
            .filter(|conn| {
                conn.online
                    && conn.state != ConnectionState::Closed
                    && conn.relay_confirmed_at.is_none()
            })
            .map(|conn| (conn.node_id.clone(), conn.virtual_ip.clone(), generation))
            .collect();
        drop(connections);
        let mut targets = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if !self.peer_quarantined(&candidate.0).await {
                targets.push(candidate);
            }
        }
        targets
    }

    /// Peers whose relay fallback business evidence is still pending on the
    /// confirmed relay while Direct is already encrypted-confirmed. For these
    /// peers a synthetic path-commit request can complete the standby evidence
    /// (one-way traffic has no natural inbound business — audit P0-4). Direct
    /// is already primary; the predicate is exactly the current-generation
    /// relay/Direct state with neither natural exchange nor path-commit done.
    pub async fn path_commit_targets(&self) -> Vec<(String, String, u64)> {
        let generation = self.current_network_generation().await;
        let candidates: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .filter(|conn| {
                conn.online
                    && conn.state == ConnectionState::Direct
                    && conn.relay_confirmed_generation == Some(generation)
                    && conn
                        .relay_confirmed_endpoint
                        .as_deref()
                        .is_some_and(|endpoint| !endpoint.is_empty())
                    && conn.relay_first.business_gate_completed_generation != Some(generation)
                    && conn.relay_first.business_exchange_generation != Some(generation)
                    && conn.relay_first.business_pathcommit_generation != Some(generation)
            })
            .map(|conn| (conn.node_id.clone(), conn.virtual_ip.clone(), generation))
            .collect();
        let mut targets = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            if !self.peer_quarantined(&candidate.0).await {
                targets.push(candidate);
            }
        }
        targets
    }

    /// Whether a path-commit expectation is currently installed for the peer.
    pub(crate) fn path_commit_expectation_present(&self, node_id: &str) -> bool {
        let now = Instant::now();
        let mut expectations = self
            .path_commit_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let present = expectations.get(node_id).is_some_and(|expectation| {
            expectation.fresh(now)
                && expectation.generation == self.current_network_generation_sync()
                && self.peer_session_is_current_sync(node_id, expectation.peer_session_generation)
        });
        if !present {
            expectations.remove(node_id);
        }
        present
    }

    /// Whether the current forced-relay probe expectation is still installed.
    ///
    /// A relay `peer_not_found` removes the expectation immediately. The
    /// probe loop uses that transition to rotate the token before retrying;
    /// otherwise an ACK for a probe that the relay rejected could be accepted
    /// after the next registration attempt and resurrect a stale path.
    pub(crate) fn relay_probe_expectation_present(&self, node_id: &str) -> bool {
        let now = Instant::now();
        let mut expectations = self
            .relay_probe_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let present = expectations.get(node_id).is_some_and(|expectation| {
            expectation.fresh(now)
                && expectation.generation == self.current_network_generation_sync()
                && self.peer_session_is_current_sync(node_id, expectation.peer_session_generation)
        });
        if !present {
            expectations.remove(node_id);
        }
        present
    }
}

impl PeerManager {
    /// Register the expectation for one outstanding path-commit request.  The
    /// initiator sends a synthetic path-commit request over the confirmed relay
    /// and records its token here so only a matching, same-relay, fresh ACK can
    /// close the relay-first business gate.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn register_path_commit_expectation_at_write_boundary(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
        relay_connection_id: u64,
        peer_session_generation: PeerSessionGeneration,
        sent_at: Instant,
    ) -> bool {
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }
        let mut expectations = self
            .path_commit_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }
        expectations.insert(
            node_id.to_string(),
            crate::path_commit::PathCommitExpectation {
                peer_session_generation,
                generation,
                request_id,
                owner_token,
                relay_endpoint: relay_endpoint.to_string(),
                relay_connection_id,
                sent_at,
            },
        );
        true
    }

    pub(crate) fn cancel_path_commit_expectation_if_matches(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_connection_id: u64,
    ) {
        let mut expectations = self
            .path_commit_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if expectations.get(node_id).is_some_and(|expectation| {
            expectation.generation == generation
                && expectation.request_id == request_id
                && expectation.owner_token == owner_token
                && expectation.relay_connection_id == relay_connection_id
        }) {
            expectations.remove(node_id);
        }
    }

    /// Consume a path-commit ACK.  It closes the relay-first business gate only
    /// when its token mirrors the outstanding expectation, the expectation is
    /// still fresh, and the ACK ACTUALLY arrived over the same relay the request
    /// was sent on.  A late ACK from an old relay must never release the current
    /// generation's gate.  Returns whether the ACK matched and committed the
    /// path-commit marker.
    #[cfg(test)]
    pub(crate) async fn consume_path_commit_ack_with_transport(
        &self,
        node_id: &str,
        token: crate::path_commit::PathCommitToken,
        ack_ingress: &str,
        relay_connection_id: Option<u64>,
    ) -> bool {
        matches!(
            self.try_consume_path_commit_ack_with_transport(
                node_id,
                token,
                ack_ingress,
                relay_connection_id,
            ),
            PathCommitCommitOutcome::Committed | PathCommitCommitOutcome::AlreadyCurrent
        )
    }

    pub(crate) fn try_consume_path_commit_ack_with_transport(
        &self,
        node_id: &str,
        token: crate::path_commit::PathCommitToken,
        ack_ingress: &str,
        relay_connection_id: Option<u64>,
    ) -> PathCommitCommitOutcome {
        let now = Instant::now();
        // Retain the short bounded expectation-map guard from exact clone
        // through the try-only state transaction. This prevents a concurrent
        // newest-wins owner replacement from being crossed by the old ACK.
        let mut expectations = self
            .path_commit_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let expectation = expectations.get(node_id).cloned();
        let Some(expectation) = expectation else {
            return PathCommitCommitOutcome::RejectedLifecycle;
        };
        if !expectation.accepts(&token, now, ack_ingress)
            || !expectation.accepts_connection(relay_connection_id)
            || expectation.generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, expectation.peer_session_generation)
        {
            return PathCommitCommitOutcome::RejectedLifecycle;
        }
        let outcome = self.try_mark_relay_first_business_pathcommit_for_lifecycle(
            node_id,
            token.generation,
            ack_ingress,
            relay_connection_id,
            expectation.peer_session_generation,
            true,
        );
        if matches!(
            outcome,
            PathCommitCommitOutcome::Committed | PathCommitCommitOutcome::AlreadyCurrent
        ) {
            // Delete only the exact expectation which was cloned above.
            if expectations.get(node_id).is_some_and(|current| {
                current.generation == expectation.generation
                    && current.request_id == expectation.request_id
                    && current.owner_token == expectation.owner_token
                    && current.relay_endpoint == expectation.relay_endpoint
                    && current.relay_connection_id == expectation.relay_connection_id
                    && current.peer_session_generation == expectation.peer_session_generation
                    && current.sent_at == expectation.sent_at
            }) {
                expectations.remove(node_id);
            }
        }
        outcome
    }
}
