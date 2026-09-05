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
            .unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((node_id.to_string(), gate));
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

    fn pending_relay_business_evidence_matches(
        current: &PendingRelayBusinessEvidence,
        expected: &PendingRelayBusinessEvidence,
    ) -> bool {
        current.peer_id == expected.peer_id
            && current.network_generation == expected.network_generation
            && current.peer_session_generation == expected.peer_session_generation
            && current.wireguard_session_instance == expected.wireguard_session_instance
            && current.relay_endpoint == expected.relay_endpoint
            && current.relay_connection_id == expected.relay_connection_id
            && current.received_at == expected.received_at
    }

    fn prune_pending_relay_business_evidence_locked(
        pending: &mut HashMap<String, PendingRelayBusinessEvidence>,
        now: Instant,
    ) {
        pending.retain(|_, evidence| {
            now.saturating_duration_since(evidence.received_at)
                <= PENDING_RELAY_BUSINESS_EVIDENCE_TTL
        });
    }

    /// Save authenticated evidence before attempting either async-owned lock.
    /// The ordinary mutex protects only a bounded in-memory map and is never
    /// held across an await. Newer evidence for one peer replaces older
    /// evidence; at global capacity the oldest peer entry is evicted.
    fn retain_pending_relay_business_evidence(
        &self,
        evidence: PendingRelayBusinessEvidence,
    ) -> bool {
        let mut pending = self
            .pending_relay_business_evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = Instant::now();
        Self::prune_pending_relay_business_evidence_locked(&mut pending, now);
        if now.saturating_duration_since(evidence.received_at)
            > PENDING_RELAY_BUSINESS_EVIDENCE_TTL
        {
            return false;
        }

        if pending
            .get(&evidence.peer_id)
            .is_some_and(|current| current.received_at > evidence.received_at)
        {
            return false;
        }
        if !pending.contains_key(&evidence.peer_id)
            && pending.len() >= MAX_PENDING_RELAY_BUSINESS_EVIDENCE
        {
            let oldest_peer = pending
                .iter()
                .min_by_key(|(_, current)| current.received_at)
                .map(|(peer_id, _)| peer_id.clone());
            if let Some(oldest_peer) = oldest_peer {
                pending.remove(&oldest_peer);
            }
        }
        pending.insert(evidence.peer_id.clone(), evidence);
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn pending_relay_business_evidence_for_lifecycle(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
        wireguard_session_instance: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
        now: Instant,
    ) -> Option<PendingRelayBusinessEvidence> {
        let mut pending = self
            .pending_relay_business_evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_pending_relay_business_evidence_locked(&mut pending, now);
        pending.get(node_id).filter(|evidence| {
            evidence.network_generation == generation
                && evidence.peer_session_generation == peer_session_generation
                && evidence.wireguard_session_instance == wireguard_session_instance
                && evidence.relay_endpoint == relay_endpoint
                && evidence.relay_connection_id == relay_connection_id
        }).cloned()
    }

    fn remove_pending_relay_business_evidence_if_exact(
        &self,
        evidence: &PendingRelayBusinessEvidence,
    ) {
        let mut pending = self
            .pending_relay_business_evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if pending
            .get(&evidence.peer_id)
            .is_some_and(|current| Self::pending_relay_business_evidence_matches(current, evidence))
        {
            pending.remove(&evidence.peer_id);
        }
    }

    fn pending_relay_business_evidence_is_exact(
        &self,
        evidence: &PendingRelayBusinessEvidence,
        now: Instant,
    ) -> bool {
        let mut pending = self
            .pending_relay_business_evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_pending_relay_business_evidence_locked(&mut pending, now);
        pending.get(&evidence.peer_id).is_some_and(|current| {
            Self::pending_relay_business_evidence_matches(current, evidence)
        })
    }

    #[cfg(test)]
    pub(crate) fn pending_relay_business_evidence_present(&self, node_id: &str) -> bool {
        let now = Instant::now();
        let mut pending = self
            .pending_relay_business_evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_pending_relay_business_evidence_locked(&mut pending, now);
        pending.contains_key(node_id)
    }

    #[cfg(test)]
    pub(crate) fn pending_relay_business_evidence_len(&self) -> usize {
        let now = Instant::now();
        let mut pending = self
            .pending_relay_business_evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Self::prune_pending_relay_business_evidence_locked(&mut pending, now);
        pending.len()
    }

    /// Whether the peer is direct in a specific generation.
    pub async fn is_direct_for_generation(&self, node_id: &str, generation: u64) -> bool {
        generation == self.current_network_generation().await && self.is_direct(node_id).await
    }

    /// Set the relay server for a peer.
    pub async fn set_relay(&self, node_id: &str, relay_server: &str) {
        self.record_relay_success(node_id, relay_server, true).await;
    }

    /// Record a successful relay-path event.
    pub async fn record_relay_success(
        &self,
        node_id: &str,
        relay_server: &str,
        switch_to_relay: bool,
    ) {
        self.record_relay_success_inner(node_id, relay_server, switch_to_relay, None)
            .await;
    }

    /// Record a successful relay-path event with measured peer round-trip latency.
    pub async fn record_relay_success_with_latency(
        &self,
        node_id: &str,
        relay_server: &str,
        switch_to_relay: bool,
        latency: Duration,
    ) {
        self.record_relay_success_inner(node_id, relay_server, switch_to_relay, Some(latency))
            .await;
    }

    /// Record decrypted relay ingress as a health observation only.
    ///
    /// A frame reaching this daemon proves that this daemon can decrypt a
    /// frame received from the relay, but it does not prove that the peer has
    /// received anything, nor that the current generation's forced-relay
    /// probe was acknowledged.  Production transport code must use this
    /// method instead of [`Self::record_relay_success`], so a validation
    /// packet, writer completion, or unsolicited business frame cannot make
    /// an unconfirmed relay appear as the active path.
    #[cfg(test)]
    pub(crate) async fn record_relay_observation(&self, node_id: &str, relay_server: &str) {
        self.try_record_relay_observation(node_id, relay_server);
    }

    pub(crate) fn try_record_relay_observation(&self, node_id: &str, relay_server: &str) {
        // This method runs after an authenticated Relay frame on the single
        // WireGuard inbound actor.  Observation is advisory and retried by
        // every later frame, so it must never enqueue a writer behind an
        // unrelated connection-map reader and stop the actor.
        let Ok(mut connections) = self.connections.try_write() else {
            let generation = self.current_network_generation_sync();
            self.emit_timeline_first(
                node_id,
                generation,
                "relay_observation_connections_contended",
                Some("relay"),
                Some("fair_rwlock_writer_unavailable"),
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_server} wait_us=0 queued_writer=false retry=next_authenticated_frame"
                )),
            );
            return;
        };
        if let Some(conn) = connections.get_mut(node_id) {
            conn.relay_server = Some(relay_server.to_string());
            // Untimed ingress is useful liveness evidence, but it must not
            // refresh the timestamp used to schedule a real RTT probe.
            // Otherwise one-way business traffic can suppress timed relay
            // validation forever and leave the UI on a stale/empty sample.
            conn.relay_health.record_observation();
        }
    }

    async fn record_relay_success_inner(
        &self,
        node_id: &str,
        relay_server: &str,
        _switch_to_relay: bool,
        latency: Option<Duration>,
    ) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            let previous_relay = conn.relay_server.clone();
            let previous_path = conn.active_path();
            conn.relay_server = Some(relay_server.to_string());
            if let Some(latency) = latency {
                conn.relay_health.record_success_with_latency(latency);
            } else {
                conn.relay_health.record_success();
            }
            // A relay validation packet must NEVER demote a confirmed Direct
            // peer: the direct keepalive/probe machinery is the only
            // authoritative demoter (it transitions Direct -> FallbackToRelay
            // on ACK timeouts), after which the relay path can heal the peer
            // back to Relay.  Relay keepalives arriving on a healthy Direct
            // path only refresh the relay health bookkeeping.
            if conn.state != ConnectionState::Direct {
                let was_relay = conn.state == ConnectionState::Relay;
                let relay_changed = previous_relay.as_deref() != Some(relay_server);
                conn.transition(ConnectionState::Relay);
                let selected_path = conn.active_path();
                let dedupe_key = format!("{node_id}:{relay_server}");
                let deduped = was_relay && !relay_changed;
                if deduped {
                    debug!(
                        event = "relay_fallback_selected",
                        peer_id = %node_id,
                        relay_server = %relay_server,
                        previous_path = ?previous_path,
                        selected_path = ?selected_path,
                        event_deduped = true,
                        dedupe_key = %dedupe_key,
                        "relay_fallback_selected deduplicated peer_id={} relay_server={}",
                        node_id,
                        relay_server
                    );
                } else {
                    conn.record_direct_event(
                        conn.direct_generation,
                        "relay_fallback_selected",
                        conn.endpoint,
                        None,
                        None,
                        format!("relay {relay_server} selected; dedupe_key={dedupe_key}"),
                    );
                    info!(
                        event = "relay_fallback_selected",
                        peer_id = %node_id,
                        local_endpoint = "relay",
                        remote_endpoint = %relay_server,
                        direct_endpoint = ?conn.endpoint,
                        relay_server = %relay_server,
                        candidate_source = ?conn.endpoint.and_then(|endpoint| {
                            conn.candidate_pairs
                                .iter()
                                .find(|pair| {
                                    pair.remote_endpoint == endpoint
                                        && conn.pair_belongs_to_current_remote_epoch(pair)
                                })
                                .map(|pair| pair.source)
                        }),
                        rtt_ms = ?conn.relay_health.rtt_ewma_ms.or(conn.relay_health.latency_ms),
                        previous_path = ?previous_path,
                        selected_path = ?selected_path,
                        event_deduped = false,
                        dedupe_key = %dedupe_key,
                        reason = %format!("relay {relay_server} selected"),
                        "relay_fallback_selected peer_id={} relay_server={}",
                        node_id,
                        relay_server
                    );
                }
            }
        }
    }

    /// Record that a relay transport became READY to carry this peer's traffic
    /// (the shared relay slot published an endpoint while the peer had an
    /// encrypting session).  This is the per-peer `RelayTransportConnected`
    /// milestone: a local TCP/TLS connect or a queued registration is NOT
    /// delivery — only [`Self::confirm_relay_peer`] (a matching forced-relay
    /// probe ACK) confirms the path.
    ///
    /// The relay-ready instant is the FIRST time the current endpoint became
    /// ready, so the per-daemon relay-ready -> first-usable delta stays
    /// meaningful across probe retries within one relay generation.
    pub async fn mark_relay_transport_ready(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
    ) {
        self.mark_relay_transport_ready_with_transport(node_id, relay_endpoint, generation, None)
            .await;
    }

    /// Record relay readiness together with the process-local transport
    /// incarnation that produced it.  A relay endpoint can be reused during
    /// reconnect/renewal, so a same-generation, same-endpoint replacement
    /// must invalidate the old encrypted confirmation before the new probe
    /// loop is allowed to use it.
    pub(crate) async fn mark_relay_transport_ready_with_transport(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
    ) {
        let _ = self.try_mark_relay_transport_ready_with_transport(
            node_id,
            relay_endpoint,
            generation,
            relay_connection_id,
        );
    }

    /// Attempt the exact relay-ready transaction without ever joining either
    /// the epoch mutex or writer-preferred connection-map wait queue.
    ///
    /// The forced-relay probe loop and authenticated ingress both retry this
    /// idempotent transaction.  Returning typed contention is therefore safer
    /// than parking the process-wide serial inbound actor while it owns the
    /// per-peer WireGuard evidence guard.
    pub(crate) fn try_mark_relay_transport_ready_with_transport(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
    ) -> RelayReadyCommitOutcome {
        let started = Instant::now();
        let finish = |outcome: RelayReadyCommitOutcome, connections_wait_us: Option<u128>| {
            self.emit_timeline_first(
                node_id,
                generation,
                "relay_ready_commit_finished",
                Some("relay"),
                match outcome {
                    RelayReadyCommitOutcome::ContendedEpoch => Some("network_epoch_busy"),
                    RelayReadyCommitOutcome::ContendedConnections => {
                        Some("fair_rwlock_writer_unavailable")
                    }
                    RelayReadyCommitOutcome::Rejected => Some("lifecycle_rejected"),
                    RelayReadyCommitOutcome::Committed
                    | RelayReadyCommitOutcome::AlreadyCurrent => None,
                },
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} outcome={outcome:?} total_us={} connections_wait_us={}",
                    started.elapsed().as_micros(),
                    connections_wait_us
                        .map(|wait| wait.to_string())
                        .unwrap_or_else(|| "not_attempted".to_string())
                )),
            );
            outcome
        };
        self.emit_timeline_first(
            node_id,
            generation,
            "relay_ready_commit_started",
            Some("relay"),
            None,
            Some(format!(
                "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?}"
            )),
        );
        // READY is part of the same per-generation path state as the
        // confirmation and first-business markers.  Hold the epoch gate from
        // the generation check through the connection write so a network
        // advance cannot clear the state between those two operations.
        let epoch_gate = self.network_epoch_gate();
        let Ok(_epoch_guard) = epoch_gate.try_lock() else {
            self.emit_timeline_first(
                node_id,
                generation,
                "relay_ready_epoch_contended",
                Some("relay"),
                Some("network_epoch_busy"),
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} wait_us={} retry=next_probe_or_authenticated_frame",
                    started.elapsed().as_micros()
                )),
            );
            return finish(RelayReadyCommitOutcome::ContendedEpoch, None);
        };
        let current_generation = self.current_network_generation_sync();
        if generation != current_generation || self.peer_quarantined_sync(node_id) {
            self.emit_timeline(
                "relay_transport_ready_rejected",
                Some("relay"),
                Some("stale_generation_or_quarantine"),
                Some(format!(
                    "peer={node_id} generation={generation} current_generation={current_generation} relay_endpoint={relay_endpoint}"
                )),
            );
            return finish(RelayReadyCommitOutcome::Rejected, None);
        }
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return finish(RelayReadyCommitOutcome::Rejected, None);
        };
        let now = Instant::now();
        let mut invalidated_confirmation = None;
        let connection_wait_started = Instant::now();
        let Ok(mut connections) = self.connections.try_write() else {
            let connections_wait_us = connection_wait_started.elapsed().as_micros();
            self.emit_timeline_first(
                node_id,
                generation,
                "relay_ready_connections_contended",
                Some("relay"),
                Some("fair_rwlock_writer_unavailable"),
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} wait_us={} queued_writer=false retry=next_probe_or_authenticated_frame",
                    connection_wait_started.elapsed().as_micros()
                )),
            );
            return finish(
                RelayReadyCommitOutcome::ContendedConnections,
                Some(connections_wait_us),
            );
        };
        let connections_wait_us = connection_wait_started.elapsed().as_micros();
        let mut commit_outcome = RelayReadyCommitOutcome::AlreadyCurrent;
        if let Some(conn) = connections.get_mut(node_id) {
            // Re-check quarantine after acquiring the connection lock. The
            // first check above only avoids needless work; quarantine can be
            // committed while this task is waiting for the lock.
            if !conn.online
                || conn.state == ConnectionState::Closed
                || self.peer_quarantined_sync(node_id)
            {
                return finish(
                    RelayReadyCommitOutcome::Rejected,
                    Some(connections_wait_us),
                );
            }
            let endpoint_changed = conn.relay_ready_endpoint.as_deref() != Some(relay_endpoint);
            let transport_replaced = relay_connection_id.is_some_and(|new_id| {
                conn.relay_ready_connection_id
                    .is_some_and(|old_id| old_id != new_id)
                    || conn
                        .relay_confirmed_connection_id
                        .is_some_and(|old_id| old_id != new_id)
            });
            let ready_incarnation_unknown_or_changed = relay_connection_id
                .is_some_and(|new_id| conn.relay_ready_connection_id != Some(new_id));
            if endpoint_changed
                || conn.relay_ready_generation != Some(generation)
                || ready_incarnation_unknown_or_changed
            {
                let relay_identity = RelayConnectionIdentity::new(
                    PathEpoch::new(
                        generation,
                        peer_session_generation,
                        conn.remote_candidate_epoch(),
                    ),
                    relay_endpoint,
                    relay_connection_id,
                );
                let outcome = conn.commit_path_transition(
                    PathEvent::RelayTransportReady {
                        relay: relay_identity,
                    },
                    |conn| {
                // RTT belongs to an exact network + relay transport lifecycle.
                // Clear it before publishing replacement readiness so neither
                // diagnostics nor path scoring can reuse the retired sample.
                conn.relay_health.clear_timing_for_lifecycle_change();
                let confirmation_must_be_invalidated = endpoint_changed
                    || conn.relay_ready_generation != Some(generation)
                    || transport_replaced
                    || ready_incarnation_unknown_or_changed;
                if confirmation_must_be_invalidated && conn.relay_confirmed_at.is_some() {
                    invalidated_confirmation = Some((
                        conn.relay_confirmed_endpoint.clone(),
                        conn.relay_confirmed_generation,
                        conn.relay_confirmed_connection_id,
                    ));
                    conn.relay_confirmed_at = None;
                    conn.relay_confirmed_generation = None;
                    conn.relay_confirmed_endpoint = None;
                    conn.relay_confirmed_connection_id = None;
                    conn.relay_first.business_sent_generation = None;
                    conn.relay_first.business_received_generation = None;
                    conn.relay_first.business_exchange_generation = None;
                    conn.relay_first.business_pathcommit_generation = None;
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    // Keep the synchronous waiter mirror aligned with the
                    // state transition while the epoch gate is held.
                    self.bump_relay_confirm_seq(node_id);
                }
                conn.relay_ready_generation = Some(generation);
                conn.relay_ready_at = Some(now);
                conn.relay_ready_endpoint = Some(relay_endpoint.to_string());
                conn.relay_ready_connection_id = relay_connection_id;
                // The relay-first gate may have been armed from the catalog
                // before this transport slot was published. Do not reset its
                // start time here: doing so reopens the Direct-before-relay
                // race and also makes the startup deadline depend on relay
                // supervisor scheduling. For a dynamically discovered peer,
                // arm it at the transport-ready boundary.
                if conn.relay_first.gate_generation != Some(generation) {
                    conn.relay_first.gate_generation = Some(generation);
                    conn.relay_first.gate_started_at = Some(now);
                } else {
                    conn.relay_first.gate_started_at.get_or_insert(now);
                }
                conn.relay_first.business_sent_generation = None;
                conn.relay_first.business_received_generation = None;
                conn.relay_first.business_exchange_generation = None;
                conn.relay_first.business_pathcommit_generation = None;
                debug!(
                    event = "relay_transport_ready_peer",
                    peer_id = %node_id,
                    relay_endpoint = %relay_endpoint,
                    relay_connection_id = ?relay_connection_id,
                    generation = generation,
                    "relay transport ready for peer peer_id={node_id} relay_endpoint={relay_endpoint}",
                );
                self.emit_timeline(
                    "relay_transport_ready_peer",
                    Some("relay"),
                    None,
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?}"
                    )),
                );
                    },
                );
                if !outcome.accepted() {
                    return finish(
                        RelayReadyCommitOutcome::Rejected,
                        Some(connections_wait_us),
                    );
                }
                commit_outcome = RelayReadyCommitOutcome::Committed;
            }
        } else {
            return finish(
                RelayReadyCommitOutcome::Rejected,
                Some(connections_wait_us),
            );
        }
        drop(connections);
        if let Some((previous_endpoint, previous_generation, previous_connection_id)) =
            invalidated_confirmation
        {
            self.emit_timeline(
                "relay_peer_confirmed_revoked",
                Some("relay"),
                Some("relay_transport_replaced"),
                Some(format!(
                    "peer={node_id} previous_endpoint={} previous_generation={previous_generation:?} previous_connection_id={previous_connection_id:?} replacement_endpoint={relay_endpoint} replacement_connection_id={relay_connection_id:?}",
                    previous_endpoint.as_deref().unwrap_or("unknown")
                )),
            );
        }
        finish(commit_outcome, Some(connections_wait_us))
    }

    /// Confirm the relay path to a peer after a matching forced-relay probe ACK
    /// whose real ingress was relay.  Sets `RelayPeerConfirmed`, bumps the
    /// relay-confirm sequence (notifying outbound waiters) and transitions the
    /// peer to Relay state.
    ///
    /// This is the relay-path confirmation milestone ONLY — it never records
    /// `first_usable`.  First usability must be proven by a normal,
    /// authenticated, decrypted production overlay ingress
    /// (`record_verified_first_usable`).  The optional validation harness adds
    /// a stronger bidirectional nonce/echo check, but neither a confirmation,
    /// TCP/TLS connect, nor queued registration is business evidence.
    ///
    /// Returns `true` when this call changed the confirmation (later
    /// identical confirmations no-op). A changed endpoint in the same
    /// generation is a new transport confirmation and must wake the outbound
    /// FIFO just like the first confirmation.
    pub async fn confirm_relay_peer(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
    ) -> bool {
        let peer_session_generation = self.peer_session_generation_sync(node_id);
        self.confirm_relay_peer_inner(
            node_id,
            relay_endpoint,
            generation,
            None,
            peer_session_generation,
            Some(0),
            "encrypted_probe_ack",
        )
    }

    /// Confirm a relay path and bind the proof to one local relay transport
    /// incarnation.  The endpoint and network generation remain part of the
    /// proof, but are not sufficient across same-endpoint renewal.
    #[cfg(test)]
    pub(crate) async fn confirm_relay_peer_with_transport(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
    ) -> bool {
        let peer_session_generation = self.peer_session_generation_sync(node_id);
        self.confirm_relay_peer_with_transport_for_lifecycle(
            node_id,
            relay_endpoint,
            generation,
            relay_connection_id,
            peer_session_generation,
            Some(0),
        )
    }

    fn confirm_relay_peer_with_transport_for_lifecycle(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
        peer_session_generation: Option<PeerSessionGeneration>,
        wireguard_session_instance: Option<u64>,
    ) -> bool {
        self.confirm_relay_peer_inner(
            node_id,
            relay_endpoint,
            generation,
            relay_connection_id,
            peer_session_generation,
            wireguard_session_instance,
            "encrypted_probe_ack",
        )
    }

    /// Confirm a relay from a real encrypted business packet that arrived
    /// through the current relay transport.  A normal decrypted overlay
    /// packet is independently stronger than a local writer completion and
    /// is also a valid end-to-end relay echo: it proves that the peer's
    /// encrypted session, the relay forwarding path, and this daemon's
    /// receiver all worked.  It may therefore close the startup race where
    /// the business packet arrives a few milliseconds before the forced
    /// relay path-probe ACK.
    ///
    /// This does not make Direct active.  Direct promotion still requires its
    /// own generation-bound encrypted validation and the relay-first business
    /// exchange gate.  It only prevents a valid relay business packet from
    /// being discarded as "before peer confirmation" and leaving the peer
    /// without a first-usable relay proof.
    pub(crate) async fn confirm_relay_peer_from_business_ingress(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
    ) -> bool {
        let peer_session_generation = self.peer_session_generation_sync(node_id);
        self.confirm_relay_peer_inner(
            node_id,
            relay_endpoint,
            generation,
            relay_connection_id,
            peer_session_generation,
            Some(0),
            "encrypted_business_ingress",
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn confirm_relay_peer_from_business_ingress_for_session(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
        peer_session_generation: PeerSessionGeneration,
        wireguard_session_instance: u64,
    ) -> bool {
        self.confirm_relay_peer_inner(
            node_id,
            relay_endpoint,
            generation,
            relay_connection_id,
            Some(peer_session_generation),
            Some(wireguard_session_instance),
            "encrypted_business_ingress",
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn confirm_relay_peer_inner(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
        peer_session_generation: Option<PeerSessionGeneration>,
        wireguard_session_instance: Option<u64>,
        confirmation_source: &'static str,
    ) -> bool {
        // The ACK expectation is checked before this method is called, but
        // that check is not the commit boundary: an Air/network generation
        // can advance after the expectation is consumed.  Re-check and
        // commit under the shared epoch gate so an old ACK can never install
        // RelayPeerConfirmed in the new generation.
        let now = Instant::now();
        let pending_evidence = peer_session_generation.and_then(|peer_lifecycle| {
            wireguard_session_instance.and_then(|session_instance| {
                self.pending_relay_business_evidence_for_lifecycle(
                    node_id,
                    generation,
                    peer_lifecycle,
                    session_instance,
                    relay_endpoint,
                    relay_connection_id,
                    now,
                )
            })
        });
        let (
            confirmation_changed,
            pending_committed,
            exchange_confirmed,
            first_usable_recorded,
            first_business_sent,
            first_business_received,
            first_business_exchange,
        ) = {
            let epoch_gate = self.network_epoch_gate();
            let Ok(_epoch_guard) = epoch_gate.try_lock() else {
                self.emit_timeline_first(
                    node_id,
                    generation,
                    "relay_confirmation_epoch_contended",
                    Some("relay"),
                    Some("network_epoch_busy"),
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} queued_waiter=false retry=next_probe_or_business_frame"
                    )),
                );
                return false;
            };
            let current_generation = self.current_network_generation_sync();
            if generation != current_generation {
                self.emit_timeline(
                    "relay_peer_confirmation_rejected",
                    Some("relay"),
                    Some("stale_generation"),
                    Some(format!(
                        "peer={node_id} generation={generation} current_generation={current_generation} relay_endpoint={relay_endpoint}"
                    )),
                );
                return false;
            }
            if peer_session_generation
                .is_none_or(|expected| !self.peer_session_is_current_sync(node_id, expected))
            {
                self.emit_timeline(
                    "relay_peer_confirmation_rejected",
                    Some("relay"),
                    Some("peer_lifecycle_changed"),
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                    )),
                );
                return false;
            }
            // Quarantine is authoritative isolation after a sustained relay
            // `peer_not_found`.  Check it immediately before taking the
            // connection lock so a late ACK cannot re-admit the stale peer.
            if self.peer_quarantined_sync(node_id) {
                self.emit_timeline(
                    "relay_peer_confirmation_rejected",
                    Some("relay"),
                    Some("peer_quarantined"),
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                    )),
                );
                return false;
            }
            let result = {
                let Ok(mut conns) = self.connections.try_write() else {
                    self.emit_timeline_first(
                        node_id,
                        generation,
                        "relay_confirmation_connections_contended",
                        Some("relay"),
                        Some("fair_rwlock_writer_unavailable"),
                        Some(format!(
                            "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} queued_writer=false retry=next_probe_or_business_frame"
                        )),
                    );
                    return false;
                };
                let Some(conn) = conns.get_mut(node_id) else {
                    return false;
                };
                if !conn.online || conn.state == ConnectionState::Closed {
                    self.emit_timeline(
                        "relay_peer_confirmation_rejected",
                        Some("relay"),
                        Some("peer_offline_or_closed"),
                        Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                    )),
                    );
                    return false;
                }
                // Close the lock-acquisition race with quarantine: a late ACK
                // cannot re-admit an old relay registration after quarantine has
                // committed while this task waited for the connection lock.
                if self.peer_quarantined_sync(node_id) {
                    return false;
                }
                if peer_session_generation
                    .is_none_or(|expected| !self.peer_session_is_current_sync(node_id, expected))
                {
                    return false;
                }
                // The ready milestone is bound to the currently published relay
                // transport.  Once a replacement has been published, an ACK from
                // the retired same-endpoint connection must not be able to
                // recreate RelayPeerConfirmed in this generation.  Legacy/unit
                // callers may have no incarnation id; an unknown ready id is
                // therefore accepted and is filled by the confirmation below.
                let live_transport_mismatch = relay_connection_id.is_some()
                    && !(conn.relay_ready_generation == Some(generation)
                        && conn.relay_ready_endpoint.as_deref() == Some(relay_endpoint)
                        && conn.relay_ready_connection_id == relay_connection_id);
                if live_transport_mismatch {
                    self.emit_timeline(
                    "relay_peer_confirmation_rejected",
                    Some("relay"),
                    Some("relay_transport_replaced"),
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} ready_connection_id={:?} ack_connection_id={relay_connection_id:?}",
                        conn.relay_ready_connection_id
                    )),
                );
                    return false;
                }
                let relay_identity = RelayConnectionIdentity::new(
                    PathEpoch::new(
                        generation,
                        peer_session_generation
                            .expect("relay confirmation validated a peer lifecycle"),
                        conn.remote_candidate_epoch(),
                    ),
                    relay_endpoint,
                    relay_connection_id,
                );
                let pending_is_current = pending_evidence.as_ref().is_some_and(|evidence| {
                    self.pending_relay_business_evidence_is_exact(evidence, Instant::now())
                });
                let mut result = (false, false, false, false, false, false, false);
                let outcome = conn.commit_path_transition(
                    PathEvent::RelayPeerConfirmed {
                        relay: relay_identity,
                    },
                    |conn| {
                        let confirmation_lifecycle_changed = conn.relay_confirmed_generation
                            != Some(generation)
                            || conn.relay_confirmed_endpoint.as_deref() != Some(relay_endpoint)
                            || conn.relay_confirmed_connection_id != relay_connection_id;
                        if confirmation_lifecycle_changed {
                            conn.relay_health.clear_timing_for_lifecycle_change();
                        }
                        let changed = if conn.relay_confirmed_at.is_some()
                            && conn.relay_confirmed_generation == Some(generation)
                            && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
                            && conn.relay_confirmed_connection_id == relay_connection_id
                        {
                            // The exact endpoint and generation was already confirmed.
                            // Duplicate encrypted ACKs are deliberately idempotent.
                            false
                        } else if conn.relay_confirmed_at.is_some()
                            && conn.relay_confirmed_generation == Some(generation)
                        {
                            // A new relay transport in the same network generation needs
                            // a fresh encrypted ACK, but it is still a real confirmation.
                            conn.relay_confirmed_generation = Some(generation);
                            conn.relay_confirmed_at = Some(now);
                            conn.relay_confirmed_endpoint = Some(relay_endpoint.to_string());
                            conn.relay_confirmed_connection_id = relay_connection_id;
                            if conn.relay_ready_generation == Some(generation)
                                && conn.relay_ready_endpoint.as_deref() == Some(relay_endpoint)
                            {
                                conn.relay_ready_connection_id = relay_connection_id;
                            }
                            conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                            conn.relay_first.gate_generation = None;
                            conn.relay_first.gate_started_at = None;
                            conn.relay_first.business_sent_generation = None;
                            conn.relay_first.business_received_generation = None;
                            conn.relay_first.business_exchange_generation = None;
                            conn.relay_first.business_pathcommit_generation = None;
                            true
                        } else {
                            // A confirmation from an older generation is never reused.
                            if conn.relay_confirmed_endpoint.as_deref() != Some(relay_endpoint) {
                                conn.relay_confirmed_endpoint = None;
                            }
                            conn.relay_confirmed_generation = Some(generation);
                            conn.relay_confirmed_at = Some(now);
                            conn.relay_confirmed_endpoint = Some(relay_endpoint.to_string());
                            conn.relay_confirmed_connection_id = relay_connection_id;
                            if conn.relay_ready_generation == Some(generation)
                                && conn.relay_ready_endpoint.as_deref() == Some(relay_endpoint)
                            {
                                conn.relay_ready_connection_id = relay_connection_id;
                            }
                            conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                            conn.relay_first.gate_generation = None;
                            conn.relay_first.gate_started_at = None;
                            conn.relay_first.business_sent_generation = None;
                            // A packet received while the transport was merely READY is
                            // not relay delivery evidence.  Only a matching encrypted
                            // peer ACK authorizes the business marker for this generation.
                            conn.relay_first.business_received_generation = None;
                            conn.relay_first.business_exchange_generation = None;
                            conn.relay_first.business_pathcommit_generation = None;
                            true
                        };
                        let mut pending_committed = false;
                        let mut exchange_confirmed = false;
                        let mut first_usable_recorded = false;
                        if pending_is_current {
                            pending_committed = conn.relay_first.business_received_generation
                                != Some(generation);
                            conn.relay_first.business_received_generation = Some(generation);
                            if conn.relay_first.business_sent_generation == Some(generation)
                                && conn.relay_first.business_exchange_generation
                                    != Some(generation)
                            {
                                conn.relay_first.business_exchange_generation = Some(generation);
                                conn.relay_first.business_gate_completed_generation =
                                    Some(generation);
                                exchange_confirmed = true;
                            }
                            first_usable_recorded =
                                conn.record_first_usable(NetworkPath::Relay, generation);
                        }
                        let first_business_sent = first_usable_recorded
                            && conn.relay_first.business_sent_generation == Some(generation);
                        let first_business_received = first_usable_recorded
                            && conn.relay_first.business_received_generation == Some(generation);
                        let first_business_exchange = first_usable_recorded
                            && conn.relay_first.business_exchange_generation == Some(generation);
                        result = (
                            changed,
                            pending_committed,
                            exchange_confirmed,
                            first_usable_recorded,
                            first_business_sent,
                            first_business_received,
                            first_business_exchange,
                        );
                        if changed {
                            // Keep the synchronous waiter mirror in the same critical
                            // section as the connection state transition.  Otherwise a
                            // waiter could observe the state before its notification
                            // sequence is visible and miss the wake-up.
                            self.bump_relay_confirm_seq(node_id);
                        }
                    },
                );
                if !outcome.accepted() {
                    return false;
                }
                result
            };
            result
        };
        if let Some(pending_evidence) = pending_evidence.as_ref() {
            self.remove_pending_relay_business_evidence_if_exact(pending_evidence);
        }
        if confirmation_changed {
            info!(
                event = "relay_peer_confirmed",
                peer_id = %node_id,
                relay_endpoint = %relay_endpoint,
                relay_connection_id = ?relay_connection_id,
                generation = generation,
                confirmation_source,
                "relay_peer_confirmed peer_id={node_id} relay_endpoint={relay_endpoint} generation={generation} connection_id={relay_connection_id:?} source={confirmation_source}"
            );
            self.emit_timeline(
                "relay_peer_confirmed",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={} source={confirmation_source}",
                    relay_connection_id.map_or_else(|| "none".to_string(), |id| id.to_string())
                )),
            );
        }
        if pending_committed {
            // This is a production TUN ingress fact retained from before the
            // ACK, not a writer/queue success or a probe result.  Publish it
            // only after the matching relay confirmation has established the
            // same generation/endpoint/transport binding.
            self.emit_timeline(
                "relay_first_business_received",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={} retained_preconfirmation_business=true"
                    , relay_connection_id.map_or_else(|| "none".to_string(), |id| id.to_string())
                )),
            );
        }
        if exchange_confirmed {
            self.emit_timeline(
                "relay_first_business_exchange_confirmed",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} retained_preconfirmation_business=true"
                )),
            );
        }
        if first_usable_recorded {
            self.emit_timeline_first_usable(
                node_id,
                generation,
                "relay",
                None,
                Some(format!(
                    "peer={node_id} generation={generation} ingress=relay:{relay_endpoint} retained_preconfirmation_business=true"
                )),
                first_business_sent,
                first_business_received,
                first_business_exchange,
                Some(relay_endpoint),
                relay_connection_id,
            );
            self.emit_timeline(
                "relay_first_business_evidence_promoted",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                )),
            );
        }
        confirmation_changed
    }

    /// Record the FIRST confirmed usable path for a peer, proven ONLY by real
    /// authenticated decrypted business traffic. Production TUN ingress calls
    /// this after a normal encrypted packet decrypts; the independent overlay
    /// validation harness additionally requires a locally-sent matching-nonce
    /// echo. In both cases the real ingress (`relay:<endpoint>` or `direct`)
    /// is known — never a confirmation, a single UDP send, or a TCP connect.
    ///
    /// Emits the `first_usable_path` timeline milestone per peer + generation
    /// and records the path on the connection.  Returns whether this call
    /// recorded the milestone (the first verified evidence wins).
    pub async fn record_verified_first_usable(
        &self,
        node_id: &str,
        generation: u64,
        path: NetworkPath,
        ingress_label: &str,
    ) -> bool {
        // Normal business traffic continues after the first milestone.  Do
        // not make every later packet queue behind the global network-epoch
        // mutex and a connection write lock just to rediscover that the
        // generation was already recorded.  This is only a read-side fast
        // path; a racing generation advance is harmless because the method
        // does not mutate state before the guarded commit below.
        if generation == self.current_network_generation_sync()
            && self
                .connections
                .read()
                .await
                .get(node_id)
                .is_some_and(|conn| {
                    conn.first_usable_generation == Some(generation)
                        && conn.first_usable_at.is_some()
                })
        {
            return false;
        }
        // Linearize the generation check and the connection-state write with
        // Air/network generation advance.  Without this gate, an inbound
        // packet could observe generation N, then advance_network_generation
        // could clear N's state, and the packet could still write first_usable
        // for the retired generation afterwards.
        let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
        self.record_verified_first_usable_in_epoch(
            &mut conns,
            node_id,
            generation,
            path,
            ingress_label,
        )
    }

    /// Serial-inbound Direct business fast path. It preserves the same
    /// lifecycle/generation gates as `record_verified_first_usable`, but never
    /// joins the epoch or connection writer queues while the WireGuard
    /// current-session evidence guard is held.
    pub(crate) fn try_record_verified_direct_first_usable_for_lifecycle(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
    ) -> bool {
        let epoch_gate = self.network_epoch_gate();
        let Ok(_epoch_guard) = epoch_gate.try_lock() else {
            self.emit_timeline_first(
                node_id,
                generation,
                "direct_first_usable_epoch_contended",
                Some("direct"),
                Some("network_epoch_busy"),
                Some(format!(
                    "peer={node_id} generation={generation} queued_waiter=false retry=next_authenticated_frame"
                )),
            );
            return false;
        };
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }
        let Ok(mut conns) = self.connections.try_write() else {
            self.emit_timeline_first(
                node_id,
                generation,
                "direct_first_usable_connections_contended",
                Some("direct"),
                Some("fair_rwlock_writer_unavailable"),
                Some(format!(
                    "peer={node_id} generation={generation} queued_writer=false retry=next_authenticated_frame"
                )),
            );
            return false;
        };
        let Some(conn) = conns.get_mut(node_id) else {
            return false;
        };
        if !conn.online
            || conn.state == ConnectionState::Closed
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
        {
            return false;
        }
        let (recorded, rejected_reason, fallback_reason) =
            if conn.is_on_link_direct_for_generation(generation) {
                (conn.record_first_usable(NetworkPath::Direct, generation), None, None)
            } else if !conn.has_current_authoritative_direct(generation)
                && conn.relay_confirmed_generation == Some(generation)
                && conn.relay_confirmed_endpoint.is_some()
                && conn.relay_first.business_gate_completed_generation != Some(generation)
                && conn.relay_first.business_exchange_generation != Some(generation)
            {
                (false, Some(REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS), None)
            } else if !conn.has_current_authoritative_direct(generation)
                && (conn.relay_ready_generation == Some(generation)
                    || conn.relay_first.gate_generation == Some(generation))
                && conn.relay_confirmed_generation != Some(generation)
            {
                let gate_expired = conn
                    .relay_ready_at
                    .or(conn.relay_first.gate_started_at)
                    .is_some_and(|started_at| {
                        started_at.elapsed() >= RELAY_FIRST_CONFIRMATION_GRACE
                    });
                if gate_expired {
                    (
                        conn.record_first_usable(NetworkPath::Direct, generation),
                        None,
                        Some(REASON_FIRST_DIRECT_AFTER_RELAY_BUSINESS_DEADLINE),
                    )
                } else {
                    (false, Some(REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS), None)
                }
            } else {
                (conn.record_first_usable(NetworkPath::Direct, generation), None, None)
            };
        drop(conns);
        if let Some(reason_code) = rejected_reason {
            self.emit_timeline(
                "first_usable_rejected",
                Some("direct"),
                Some(reason_code),
                Some(format!("peer={node_id} generation={generation}")),
            );
            return false;
        }
        if recorded {
            if let Some(reason_code) = fallback_reason {
                self.emit_timeline(
                    "first_usable_fallback",
                    Some("direct"),
                    Some(reason_code),
                    Some(format!(
                        "peer={node_id} generation={generation} ingress=direct"
                    )),
                );
            }
            self.emit_timeline_first_usable(
                node_id,
                generation,
                "direct",
                fallback_reason,
                Some(format!(
                    "peer={node_id} generation={generation} ingress=direct"
                )),
                false,
                true,
                false,
                None,
                None,
            );
        }
        recorded
    }

    fn record_verified_first_usable_in_epoch(
        &self,
        conns: &mut HashMap<String, PeerConnection>,
        node_id: &str,
        generation: u64,
        path: NetworkPath,
        ingress_label: &str,
    ) -> bool {
        // A delayed overlay echo from an older Air/network generation is not
        // evidence for the current mapping. The caller's token carries the
        // generation, so reject it before touching per-peer state.
        if generation != self.current_network_generation_sync() {
            self.emit_timeline(
                "first_usable_stale",
                None,
                Some("generation_changed"),
                Some(format!(
                    "peer={node_id} evidence_generation={generation} current_generation={}",
                    self.current_network_generation_sync()
                )),
            );
            return false;
        }
        let (recorded, rejected_reason, fallback_reason) = match conns.get_mut(node_id) {
                None => (false, Some("peer_missing"), None),
                Some(conn) => {
                    // A WireGuard packet can race with the control-plane
                    // offline or peer-session teardown event. Once the manager
                    // has marked the peer offline/closed, that packet belongs
                    // to the retired session, even if it still decrypts under
                    // a short rekey overlap. Do not let it create first-usable
                    // evidence for the new session.
                    if !conn.online || conn.state == ConnectionState::Closed {
                        (false, Some("peer_offline_or_closed"), None)
                    } else if path == NetworkPath::Relay
                        && !(conn.relay_confirmed_generation == Some(generation)
                            && ingress_label
                                .strip_prefix("relay:")
                                .is_some_and(|relay_endpoint| {
                                    conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
                                }))
                    {
                        // A relay socket may decrypt an unsolicited frame
                        // before the forced relay probe has been ACKed.  That
                        // is diagnostic ingress, not a usable relay path.
                        // Keep it out of first_usable so TCP connect, writer
                        // completion, or an unconfirmed peer cannot satisfy
                        // the relay-first contract.
                        (false, Some(REASON_FIRST_RELAY_BEFORE_CONFIRMATION), None)
                    } else if conn.is_on_link_direct_for_generation(generation) {
                        // A validated Host candidate inside one of our local
                        // interface prefixes is already a physical LAN proof.
                        // It must not wait for the off-link relay-first
                        // business exchange, which exists to protect public
                        // UDP hole punching from winning before relay delivery
                        // has been proven.
                        (conn.record_first_usable(path, generation), None, None)
                    } else if path == NetworkPath::Direct
                        && !conn.has_current_authoritative_direct(generation)
                        && (conn.relay_confirmed_generation == Some(generation)
                            && conn.relay_confirmed_endpoint.is_some())
                        && conn.relay_first.business_gate_completed_generation != Some(generation)
                        && conn.relay_first.business_exchange_generation != Some(generation)
                    {
                        // Before an authoritative Direct commit, a confirmed
                        // relay remains the business safety path until both
                        // same-generation relay business directions have been
                        // observed.  The authoritative Direct case is handled
                        // above by the current Selected-pair check.
                        (false, Some(REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS), None)
                    } else if path == NetworkPath::Direct
                        && !conn.has_current_authoritative_direct(generation)
                        && (conn.relay_ready_generation == Some(generation)
                            || conn.relay_first.gate_generation == Some(generation))
                        && conn.relay_confirmed_generation != Some(generation)
                    {
                        // If relay peer confirmation itself is still pending,
                        // keep the bounded startup fallback for an uncommitted
                        // Direct trial.  A separately encrypted-confirmed
                        // Direct path has already been admitted above.
                        let gate_expired = conn
                            .relay_ready_at
                            .or(conn.relay_first.gate_started_at)
                            .is_some_and(|started_at| {
                                started_at.elapsed() >= RELAY_FIRST_CONFIRMATION_GRACE
                            });
                        if gate_expired {
                            (
                                conn.record_first_usable(path, generation),
                                None,
                                Some(REASON_FIRST_DIRECT_AFTER_RELAY_BUSINESS_DEADLINE),
                            )
                        } else {
                            (false, Some(REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS), None)
                        }
                    } else {
                        (conn.record_first_usable(path, generation), None, None)
                    }
                }
            };
        if let Some(reason_code) = rejected_reason {
            self.emit_timeline(
                "first_usable_rejected",
                Some(match path {
                    NetworkPath::Direct => "direct",
                    NetworkPath::Relay => "relay",
                }),
                Some(reason_code),
                Some(format!("peer={node_id} generation={generation}")),
            );
            return false;
        }
        if recorded {
            if let Some(reason_code) = fallback_reason {
                self.emit_timeline(
                    "first_usable_fallback",
                    Some("direct"),
                    Some(reason_code),
                    Some(format!(
                        "peer={node_id} generation={generation} ingress={ingress_label}"
                    )),
                );
            }
            self.emit_timeline_first_usable(
                node_id,
                generation,
                match path {
                    NetworkPath::Direct => "direct",
                    NetworkPath::Relay => "relay",
                },
                fallback_reason,
                Some(format!(
                    "peer={node_id} generation={generation} ingress={ingress_label}"
                )),
                false,
                true,
                false,
                ingress_label.strip_prefix("relay:"),
                None,
            );
        }
        recorded
    }

    /// Whether the peer currently has a confirmed relay path
    /// (`RelayPeerConfirmed`).  Never true from a local connect or a queued
    /// registration.
    pub async fn is_relay_peer_confirmed(&self, node_id: &str) -> bool {
        let generation = self.current_network_generation().await;
        self.is_relay_peer_confirmed_for_generation(node_id, generation)
            .await
    }

    /// Whether a relay path was confirmed by encrypted evidence in exactly the
    /// requested network generation. This is the only predicate the outbound
    /// data plane may use for relay-first admission.
    pub async fn is_relay_peer_confirmed_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(|conn| {
                conn.online
                    && conn.state != ConnectionState::Closed
                    && conn.relay_confirmed_at.is_some()
                    && conn.relay_confirmed_generation == Some(generation)
                    && conn
                        .relay_confirmed_endpoint
                        .as_deref()
                        .is_some_and(|endpoint| !endpoint.is_empty())
            })
    }

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
        let confirmed_on_transport = conns
            .get(node_id)
            .is_some_and(|conn| {
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

    /// Snapshot peers currently inside the transient relay-registration grace
    /// window. This is intentionally a snapshot rather than a mutation: an
    /// expired entry is re-tested by the next scheduled probe, preserving the
    /// existing bounded grace/quarantine state machine.
    async fn relay_not_found_grace_peers(&self) -> HashSet<String> {
        let now = Instant::now();
        self.relay_not_found_grace
            .lock()
            .await
            .iter()
            .filter(|(_, state)| {
                now.saturating_duration_since(state.started_at) < RELAY_PEER_NOT_FOUND_GRACE
            })
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// The per-peer relay-ready instant, if any (daemon-local monotonic).
    pub async fn relay_ready_at(&self, node_id: &str) -> Option<Instant> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.relay_ready_at)
    }

    pub async fn relay_ready_at_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> Option<Instant> {
        self.connections
            .read()
            .await
            .get(node_id)
            .filter(|conn| conn.relay_ready_generation == Some(generation))
            .and_then(|conn| conn.relay_ready_at)
    }

    /// The per-peer relay-confirmed instant, if any (daemon-local monotonic).
    pub async fn relay_confirmed_at(&self, node_id: &str) -> Option<Instant> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.relay_confirmed_at)
    }

    /// Commit the first real business packet sent through a same-generation
    /// confirmed relay.  This is intentionally separate from probe/control
    /// sends and is called only after the relay writer reports success.
    #[cfg(test)]
    pub(crate) async fn mark_relay_first_business_sent_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> bool {
        self.mark_relay_first_business_sent_for_generation_inner(node_id, generation, None, None)
            .await
    }

    pub(crate) async fn mark_relay_first_business_sent_for_generation_with_transport(
        &self,
        node_id: &str,
        generation: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
    ) -> bool {
        self.mark_relay_first_business_sent_for_generation_inner(
            node_id,
            generation,
            Some(relay_endpoint),
            relay_connection_id,
        )
        .await
    }

    async fn mark_relay_first_business_sent_for_generation_inner(
        &self,
        node_id: &str,
        generation: u64,
        relay_endpoint: Option<&str>,
        relay_connection_id: Option<u64>,
    ) -> bool {
        let (changed, exchange_confirmed, relay_endpoint) = {
            let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
            if generation != self.current_network_generation_sync() {
                return false;
            }
            let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
                return false;
            };
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let confirmed = conn.online
                && conn.state != ConnectionState::Closed
                && conn.relay_confirmed_at.is_some()
                && conn.relay_confirmed_generation == Some(generation)
                && conn
                    .relay_confirmed_endpoint
                    .as_deref()
                    .is_some_and(|endpoint| !endpoint.is_empty())
                && relay_endpoint.is_none_or(|expected| {
                    conn.relay_confirmed_endpoint.as_deref() == Some(expected)
                        && conn.relay_confirmed_connection_id == relay_connection_id
                });
            if !confirmed || conn.relay_first.business_sent_generation == Some(generation) {
                return false;
            }
            let relay_identity = RelayConnectionIdentity::new(
                PathEpoch::new(
                    generation,
                    peer_session_generation,
                    conn.remote_candidate_epoch(),
                ),
                conn.relay_confirmed_endpoint
                    .clone()
                    .expect("confirmed relay has an endpoint"),
                conn.relay_confirmed_connection_id,
            );
            let mut exchange_confirmed = false;
            let outcome = conn.commit_path_transition(
                PathEvent::RelayBusinessUsable {
                    relay: relay_identity,
                    observation: RelayBusinessObservation::Sent,
                },
                |conn| {
                    conn.relay_first.business_sent_generation = Some(generation);
                    exchange_confirmed = conn.relay_first.business_received_generation
                        == Some(generation)
                        && conn.relay_first.business_exchange_generation != Some(generation);
                    if exchange_confirmed {
                        conn.relay_first.business_exchange_generation = Some(generation);
                        conn.relay_first.business_gate_completed_generation = Some(generation);
                    }
                },
            );
            if !outcome.accepted() {
                return false;
            }
            (
                true,
                exchange_confirmed,
                conn.relay_confirmed_endpoint.clone(),
            )
        };
        if changed {
            self.emit_timeline(
                "relay_first_business_sent",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={}",
                    relay_endpoint.as_deref().unwrap_or("unknown")
                )),
            );
        }
        if exchange_confirmed {
            self.emit_timeline(
                "relay_first_business_exchange_confirmed",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={}",
                    relay_endpoint.as_deref().unwrap_or("unknown")
                )),
            );
        }
        changed
    }

    /// Compatibility helper for manager unit tests which do not model the
    /// process-local WireGuard session instance.
    #[cfg(test)]
    pub(crate) async fn mark_relay_first_business_received_for_generation(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
    ) -> bool {
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        matches!(
            self.try_commit_relay_business_evidence(
                node_id,
                generation,
                peer_session_generation,
                0,
                relay_endpoint,
                None,
                Instant::now(),
            ),
            RelayBusinessEvidenceCommitOutcome::Committed
        )
    }

    #[cfg(test)]
    pub(crate) async fn mark_relay_first_business_received_for_generation_with_transport(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
    ) -> bool {
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        matches!(
            self.try_commit_relay_business_evidence(
                node_id,
                generation,
                peer_session_generation,
                0,
                relay_endpoint,
                relay_connection_id,
                Instant::now(),
            ),
            RelayBusinessEvidenceCommitOutcome::Committed
        )
    }

    /// Retain and attempt one exact authenticated Relay business transaction.
    /// Both async-owned locks are try-only; a contended packet is handed to TUN
    /// immediately while its evidence remains in the bounded ledger.
    #[allow(clippy::too_many_arguments)]
    fn relay_business_evidence_for_current_lifecycle(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
        wireguard_session_instance: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
        received_at: Instant,
    ) -> Option<PendingRelayBusinessEvidence> {
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
            || self.peer_quarantined_sync(node_id)
        {
            return None;
        }
        Some(PendingRelayBusinessEvidence {
            peer_id: node_id.to_string(),
            network_generation: generation,
            peer_session_generation,
            wireguard_session_instance,
            relay_endpoint: relay_endpoint.to_string(),
            relay_connection_id,
            received_at,
        })
    }

    /// Preserve authenticated Relay business evidence when the final
    /// current-session fence itself is contended. The evidence is deliberately
    /// retained without committing: only a later frame authenticated by the
    /// same exact WireGuard session/Relay incarnation can retry it.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn retain_relay_business_evidence_for_retry(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
        wireguard_session_instance: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
        received_at: Instant,
    ) -> bool {
        let Some(evidence) = self.relay_business_evidence_for_current_lifecycle(
            node_id,
            generation,
            peer_session_generation,
            wireguard_session_instance,
            relay_endpoint,
            relay_connection_id,
            received_at,
        ) else {
            return false;
        };
        self.retain_pending_relay_business_evidence(evidence)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_commit_relay_business_evidence(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
        wireguard_session_instance: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
        received_at: Instant,
    ) -> RelayBusinessEvidenceCommitOutcome {
        let Some(evidence) = self.relay_business_evidence_for_current_lifecycle(
            node_id,
            generation,
            peer_session_generation,
            wireguard_session_instance,
            relay_endpoint,
            relay_connection_id,
            received_at,
        ) else {
            return RelayBusinessEvidenceCommitOutcome::RejectedLifecycle;
        };
        // Save before either try-lock. WireGuard replay protection can make
        // this the only copy of the authenticated business evidence.
        let _ = self.retain_pending_relay_business_evidence(evidence.clone());
        self.try_commit_retained_relay_business_evidence(evidence)
    }

    /// Retry the ledger entry matching a later authenticated frame.  The
    /// caller owns the exact current-session evidence guard and has already
    /// verified the Relay transport slot incarnation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn try_commit_pending_relay_business_evidence_for_session(
        &self,
        node_id: &str,
        generation: u64,
        peer_session_generation: PeerSessionGeneration,
        wireguard_session_instance: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
    ) -> Option<RelayBusinessEvidenceCommitOutcome> {
        let evidence = self.pending_relay_business_evidence_for_lifecycle(
            node_id,
            generation,
            peer_session_generation,
            wireguard_session_instance,
            relay_endpoint,
            relay_connection_id,
            Instant::now(),
        )?;
        Some(self.try_commit_retained_relay_business_evidence(evidence))
    }

    fn try_commit_retained_relay_business_evidence(
        &self,
        evidence: PendingRelayBusinessEvidence,
    ) -> RelayBusinessEvidenceCommitOutcome {
        let node_id = evidence.peer_id.as_str();
        let generation = evidence.network_generation;
        let relay_endpoint = evidence.relay_endpoint.as_str();
        let relay_connection_id = evidence.relay_connection_id;
        let finish = |outcome| {
            self.emit_timeline_first(
                node_id,
                generation,
                "relay_business_evidence_commit",
                Some("relay"),
                match outcome {
                    RelayBusinessEvidenceCommitOutcome::PendingConfirmation => {
                        Some("awaiting_relay_probe_confirmation")
                    }
                    RelayBusinessEvidenceCommitOutcome::ContendedEpoch => {
                        Some("network_epoch_busy")
                    }
                    RelayBusinessEvidenceCommitOutcome::ContendedConnections => {
                        Some("fair_rwlock_writer_unavailable")
                    }
                    RelayBusinessEvidenceCommitOutcome::RejectedLifecycle => {
                        Some("lifecycle_rejected")
                    }
                    RelayBusinessEvidenceCommitOutcome::Committed
                    | RelayBusinessEvidenceCommitOutcome::AlreadyCurrent => None,
                },
                Some(format!(
                    "peer={node_id} generation={generation} peer_session_generation={} wireguard_session_instance={} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?} outcome={outcome:?} queued_writer=false",
                    evidence.peer_session_generation.0,
                    evidence.wireguard_session_instance,
                )),
            );
            outcome
        };

        let epoch_gate = self.network_epoch_gate();
        let Ok(_epoch_guard) = epoch_gate.try_lock() else {
            return finish(RelayBusinessEvidenceCommitOutcome::ContendedEpoch);
        };
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, evidence.peer_session_generation)
            || self.peer_quarantined_sync(node_id)
        {
            self.remove_pending_relay_business_evidence_if_exact(&evidence);
            return finish(RelayBusinessEvidenceCommitOutcome::RejectedLifecycle);
        }
        let Ok(mut conns) = self.connections.try_write() else {
            return finish(RelayBusinessEvidenceCommitOutcome::ContendedConnections);
        };
        let Some(conn) = conns.get_mut(node_id) else {
            drop(conns);
            self.remove_pending_relay_business_evidence_if_exact(&evidence);
            return finish(RelayBusinessEvidenceCommitOutcome::RejectedLifecycle);
        };
        if !conn.online
            || conn.state == ConnectionState::Closed
            || !self.peer_session_is_current_sync(node_id, evidence.peer_session_generation)
            || self.peer_quarantined_sync(node_id)
        {
            drop(conns);
            self.remove_pending_relay_business_evidence_if_exact(&evidence);
            return finish(RelayBusinessEvidenceCommitOutcome::RejectedLifecycle);
        }
        if !self.pending_relay_business_evidence_is_exact(&evidence, Instant::now()) {
            return finish(RelayBusinessEvidenceCommitOutcome::RejectedLifecycle);
        }
        let confirmed = conn.relay_confirmed_at.is_some()
            && conn.relay_confirmed_generation == Some(generation)
            && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
            && conn.relay_confirmed_connection_id == relay_connection_id;
        if !confirmed {
            let current_relay_incarnation_mismatch =
                (conn.relay_ready_generation == Some(generation)
                    && (conn.relay_ready_endpoint.as_deref() != Some(relay_endpoint)
                        || conn.relay_ready_connection_id != relay_connection_id))
                    || (conn.relay_confirmed_at.is_some()
                        && conn.relay_confirmed_generation == Some(generation)
                        && (conn.relay_confirmed_endpoint.as_deref() != Some(relay_endpoint)
                            || conn.relay_confirmed_connection_id != relay_connection_id));
            if current_relay_incarnation_mismatch {
                drop(conns);
                self.remove_pending_relay_business_evidence_if_exact(&evidence);
                return finish(RelayBusinessEvidenceCommitOutcome::RejectedLifecycle);
            }
            // A READY marker may itself have lost a try-write race. Keep the
            // exact evidence bounded until a later authenticated frame first
            // retries READY and then retries this transaction. A mismatched
            // generation/session/Relay incarnation can never pass the exact
            // confirmation predicate above and expires without side effects.
            return finish(RelayBusinessEvidenceCommitOutcome::PendingConfirmation);
        }

        let relay_identity = RelayConnectionIdentity::new(
            PathEpoch::new(
                generation,
                evidence.peer_session_generation,
                conn.remote_candidate_epoch(),
            ),
            relay_endpoint,
            relay_connection_id,
        );
        let mut first_receive = false;
        let mut exchange_confirmed = false;
        let mut first_usable_recorded = false;
        let mut first_business_sent = false;
        let mut first_business_received = false;
        let mut first_business_exchange = false;
        let outcome = conn.commit_path_transition(
            PathEvent::RelayBusinessUsable {
                relay: relay_identity,
                observation: RelayBusinessObservation::Received,
            },
            |conn| {
                first_receive =
                    conn.relay_first.business_received_generation != Some(generation);
                if first_receive {
                    conn.relay_first.business_received_generation = Some(generation);
                }
                exchange_confirmed = conn.relay_first.business_sent_generation == Some(generation)
                    && conn.relay_first.business_exchange_generation != Some(generation);
                if exchange_confirmed {
                    conn.relay_first.business_exchange_generation = Some(generation);
                    conn.relay_first.business_gate_completed_generation = Some(generation);
                }
                first_usable_recorded = conn.record_first_usable(NetworkPath::Relay, generation);
                first_business_sent = first_usable_recorded
                    && conn.relay_first.business_sent_generation == Some(generation);
                first_business_received = first_usable_recorded
                    && conn.relay_first.business_received_generation == Some(generation);
                first_business_exchange = first_usable_recorded
                    && conn.relay_first.business_exchange_generation == Some(generation);
            },
        );
        if !outcome.accepted() {
            drop(conns);
            self.remove_pending_relay_business_evidence_if_exact(&evidence);
            return finish(RelayBusinessEvidenceCommitOutcome::RejectedLifecycle);
        }
        drop(conns);
        self.remove_pending_relay_business_evidence_if_exact(&evidence);

        if first_receive {
            self.emit_timeline(
                "relay_first_business_received",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?}"
                )),
            );
        }
        if exchange_confirmed {
            self.emit_timeline(
                "relay_first_business_exchange_confirmed",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                )),
            );
        }
        if first_usable_recorded {
            self.emit_timeline_first_usable(
                node_id,
                generation,
                "relay",
                None,
                Some(format!(
                    "peer={node_id} generation={generation} ingress=relay:{relay_endpoint}"
                )),
                first_business_sent,
                first_business_received,
                first_business_exchange,
                Some(relay_endpoint),
                relay_connection_id,
            );
        }
        finish(if first_receive || exchange_confirmed || first_usable_recorded {
            RelayBusinessEvidenceCommitOutcome::Committed
        } else {
            RelayBusinessEvidenceCommitOutcome::AlreadyCurrent
        })
    }

    /// The per-peer first-usable instant, if any (daemon-local monotonic).
    pub async fn first_usable_at(&self, node_id: &str) -> Option<Instant> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.first_usable_at)
    }

    /// Commit a synthetic path-commit proof for one generation.
    ///
    /// Called when a matching forced-relay path-commit ACK arrives (a
    /// business-shaped authenticated packet round-tripped over the confirmed
    /// relay). This completes relay-first business evidence as an *alternative*
    /// to natural two-way business: it proves the same bidirectional relay-data
    /// invariant without depending on traffic that may never flow one way
    /// (audit P0-4). It does not itself make Direct active — Direct promotion
    /// still requires its own generation-bound encrypted validation.
    ///
    /// Returns `true` when the marker was newly committed for this generation.
    #[cfg(test)]
    pub(crate) async fn mark_relay_first_business_pathcommit_for_generation(
        &self,
        node_id: &str,
        generation: u64,
        relay_endpoint: &str,
    ) -> bool {
        let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
            return false;
        };
        matches!(
            self.try_mark_relay_first_business_pathcommit_for_lifecycle(
                node_id,
                generation,
                relay_endpoint,
                None,
                peer_session_generation,
                false,
            ),
            PathCommitCommitOutcome::Committed
        )
    }

    fn try_mark_relay_first_business_pathcommit_for_lifecycle(
        &self,
        node_id: &str,
        generation: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
        peer_session_generation: PeerSessionGeneration,
        bind_transport: bool,
    ) -> PathCommitCommitOutcome {
        let epoch_gate = self.network_epoch_gate();
        let Ok(_epoch_guard) = epoch_gate.try_lock() else {
            return PathCommitCommitOutcome::ContendedEpoch;
        };
        if generation != self.current_network_generation_sync()
            || !self.peer_session_is_current_sync(node_id, peer_session_generation)
            || self.peer_quarantined_sync(node_id)
        {
            return PathCommitCommitOutcome::RejectedLifecycle;
        }
        let Ok(mut conns) = self.connections.try_write() else {
            return PathCommitCommitOutcome::ContendedConnections;
        };
        let Some(conn) = conns.get_mut(node_id) else {
            return PathCommitCommitOutcome::RejectedLifecycle;
        };
        let confirmed = conn.online
            && conn.state != ConnectionState::Closed
            && self.peer_session_is_current_sync(node_id, peer_session_generation)
            && !self.peer_quarantined_sync(node_id)
            && conn.relay_confirmed_at.is_some()
            && conn.relay_confirmed_generation == Some(generation)
            && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
            && (!bind_transport || conn.relay_confirmed_connection_id == relay_connection_id);
        if !confirmed {
            return PathCommitCommitOutcome::RejectedLifecycle;
        }
        if conn.relay_first.business_pathcommit_generation == Some(generation) {
            return PathCommitCommitOutcome::AlreadyCurrent;
        }
        conn.relay_first.business_pathcommit_generation = Some(generation);
        conn.relay_first.business_gate_completed_generation = Some(generation);
        drop(conns);
        self.emit_timeline(
            "relay_first_business_pathcommit",
            Some("relay"),
            None,
            Some(format!(
                "peer={node_id} generation={generation} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id:?}"
            )),
        );
        PathCommitCommitOutcome::Committed
    }

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

    /// Whether a peer is inside the network-generation window that the first
    /// business packet may wait in (used by the outbound actor to restart a
    /// shared deadline when the generation advances mid-wait).
    pub(crate) async fn peer_online(&self, node_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(node_id)
            .is_some_and(|conn| conn.online && conn.state != ConnectionState::Closed)
    }

    /// Record that a relay path was attempted without treating TCP write success as delivery.
    pub async fn record_relay_attempt(&self, node_id: &str, relay_server: &str) {
        // Writer completion is on the serial WireGuard inbound actor when it
        // emits a Probe ACK.  This field is advisory and every later relay
        // write retries it, so never queue a connection-map writer after the
        // ciphertext has already crossed the relay writer boundary.  Doing so
        // would make a retained diagnostics reader stop the entire inbound
        // actor even though the peer has received the ACK.
        let Ok(mut connections) = self.connections.try_write() else {
            let generation = self.current_network_generation_sync();
            self.emit_timeline_first(
                node_id,
                generation,
                "relay_attempt_connections_contended",
                Some("relay"),
                Some("fair_rwlock_writer_unavailable"),
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_server} wait_us=0 queued_writer=false write_already_completed=true retry=next_relay_write"
                )),
            );
            return;
        };
        if let Some(conn) = connections.get_mut(node_id) {
            conn.relay_server = Some(relay_server.to_string());
        }
    }

    /// Record a relay-path failure for a specific peer.
    pub async fn record_relay_failure(
        &self,
        node_id: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        let code = code.into();
        let reason = reason.into();
        // A relay 404 may be a short registration handoff/reconnect window.
        // Keep an online peer's current recovery/fresh mapping alive during a
        // bounded grace period; only confirmed offline evidence or a sustained
        // 404 after that window reaches the destructive quarantine path. A
        // repeated 404 in the same grace window is also one failure sample:
        // it must not inflate peer health diagnostics on every relay frame.
        //
        // RelayPeerConfirmed is different: the relay is telling us this peer
        // is NOT registered, so the confirmed relay path is invalid from the
        // FIRST peer_not_found — even while the recovery grace window stays
        // open.  Revoking it immediately (and notifying outbound waiters)
        // stops the data plane from sending on a path the relay will 404.
        let record_failure = if code == "peer_not_found" {
            // A 404 invalidates any in-flight forced-relay probe expectation
            // for this registration.  Without this clear, an old encrypted
            // ACK could re-confirm the peer during the bounded handoff grace
            // window after the existing RelayPeerConfirmed was revoked.
            self.relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(node_id);
            let revoked = self.revoke_relay_peer_confirmation(node_id).await;
            if revoked {
                info!(
                    event = "relay_peer_confirmed_revoked",
                    peer_id = %node_id,
                    reason = "peer_not_found",
                    detail = %reason,
                    "RelayPeerConfirmed revoked after the relay reported peer_not_found peer_id={node_id}"
                );
            }
            self.handle_relay_peer_not_found(node_id, &reason).await
        } else {
            true
        };
        if record_failure {
            let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
            let Some(peer_session_generation) = self.peer_session_generation_sync(node_id) else {
                return;
            };
            if let Some(conn) = conns.get_mut(node_id) {
                let relay_identity = RelayConnectionIdentity::new(
                    PathEpoch::new(
                        self.current_network_generation_sync(),
                        peer_session_generation,
                        conn.remote_candidate_epoch(),
                    ),
                    conn.relay_confirmed_endpoint
                        .clone()
                        .or_else(|| conn.relay_ready_endpoint.clone())
                        .or_else(|| conn.relay_server.clone())
                        .unwrap_or_else(|| "compatibility-relay".to_string()),
                    conn.relay_confirmed_connection_id
                        .or(conn.relay_ready_connection_id),
                );
                conn.commit_path_transition(
                    PathEvent::RelayPathFailed {
                        relay: relay_identity,
                    },
                    |conn| conn.relay_health.record_failure(code, reason),
                );
            }
        }
    }

    /// Revoke a peer's RelayPeerConfirmed (set it to unconfirmed, bump the
    /// relay-confirm sequence and notify waiters).  Returns whether the peer
    /// was confirmed before this call.  The relay path must be re-established
    /// by a fresh forced-probe ACK (matching ingress + generation) before the
    /// peer is usable over the relay again.
    pub(crate) async fn revoke_relay_peer_confirmation(&self, node_id: &str) -> bool {
        let (revoked, ready_cleared, previous_endpoint, previous_generation) = {
            let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
            let generation_now = self.current_network_generation_sync();
            let peer_session_generation = self.peer_session_generation_any_sync(node_id);
            match conns.get_mut(node_id) {
                Some(conn)
                    if conn.relay_confirmed_at.is_some() || conn.relay_ready_at.is_some() =>
                {
                    let endpoint = conn.relay_confirmed_endpoint.clone();
                    let generation = conn.relay_confirmed_generation;
                    let had_confirmed = conn.relay_confirmed_at.is_some();
                    let had_ready = conn.relay_ready_at.is_some();
                    let Some(peer_session_generation) = peer_session_generation else {
                        return false;
                    };
                    let relay_identity = RelayConnectionIdentity::new(
                        PathEpoch::new(
                            generation_now,
                            peer_session_generation,
                            conn.remote_candidate_epoch(),
                        ),
                        conn.relay_confirmed_endpoint
                            .clone()
                            .or_else(|| conn.relay_ready_endpoint.clone())
                            .or_else(|| conn.relay_server.clone())
                            .unwrap_or_else(|| "compatibility-relay".to_string()),
                        conn.relay_confirmed_connection_id
                            .or(conn.relay_ready_connection_id),
                    );
                    let outcome = conn.commit_path_transition(
                        PathEvent::RelayTransportLost {
                            relay: relay_identity,
                        },
                        |conn| {
                            conn.relay_confirmed_at = None;
                            conn.relay_confirmed_generation = None;
                            conn.relay_confirmed_endpoint = None;
                            conn.relay_confirmed_connection_id = None;
                            conn.relay_first.gate_generation = None;
                            conn.relay_first.gate_started_at = None;
                            conn.relay_first.business_sent_generation = None;
                            conn.relay_first.business_received_generation = None;
                            conn.relay_first.business_exchange_generation = None;
                            conn.relay_first.business_pathcommit_generation = None;
                            conn.relay_ready_generation = None;
                            conn.relay_ready_at = None;
                            conn.relay_ready_endpoint = None;
                            conn.relay_ready_connection_id = None;
                            conn.relay_health.clear_timing_for_lifecycle_change();
                            if had_confirmed {
                                conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                            }
                            if had_confirmed {
                                // Keep the waiter mirror synchronized with the
                                // revocation while the epoch gate is still held.
                                self.bump_relay_confirm_seq(node_id);
                            }
                        },
                    );
                    if !outcome.accepted() {
                        return false;
                    }
                    (had_confirmed, had_ready, endpoint, generation)
                }
                _ => (false, false, None, None),
            }
        };
        if revoked {
            self.emit_timeline(
                "relay_peer_confirmed_revoked",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} relay_endpoint={} generation={:?}",
                    previous_endpoint.as_deref().unwrap_or("unknown"),
                    previous_generation
                )),
            );
        } else if ready_cleared {
            self.emit_timeline(
                "relay_transport_ready_cleared",
                Some("relay"),
                Some("relay_peer_confirmation_revoked"),
                Some(format!("peer={node_id}")),
            );
        }
        revoked
    }

    /// Handle a relay 404 and report whether this observation should become a
    /// new peer-health failure sample. Repeated errors while one grace window
    /// is open return false so diagnostics stay representative of the window,
    /// rather than the relay's frame count.
    async fn handle_relay_peer_not_found(&self, node_id: &str, reason: &str) -> bool {
        let now = Instant::now();
        // A peer already under an ACTIVE relay-404 quarantine is already
        // isolated and its episode is deduplicated.  Every later 404 for the
        // same episode is absorbed here: no peer-health failure sample, no
        // state transition, no repeated WARN log (the relay can keep sending
        // 404 frames every few seconds while the stale peer's registration
        // stays absent).  Only after the quarantine expires does the next 404
        // re-enter the grace/quarantine machinery.
        if self.peer_quarantined_sync(node_id) {
            return false;
        }
        let Some(connection) = self.get_connection(node_id).await else {
            // A missing connection is already authoritative offline evidence;
            // retain the existing anti-storm isolation behavior.
            self.quarantine_peer(node_id, reason).await;
            return true;
        };
        if !connection.online {
            self.quarantine_peer(node_id, reason).await;
            return true;
        }

        let mut emit_grace_event = false;
        let mut grace_remaining = RELAY_PEER_NOT_FOUND_GRACE;
        let should_quarantine = {
            let mut grace = self.relay_not_found_grace.lock().await;
            // Only an IDENTITY change (public-key rotation / reinstall) is a
            // newer incarnation that supersedes the pending 404 observation.
            // `last_seen` growth and ordinary NAT endpoint churn belong to
            // the SAME stale incarnation (field evidence: every control poll
            // advanced last_seen and moved the endpoint while the relay
            // registration stayed absent) — restarting the grace window on
            // them would keep the peer in perpetual "transient 404" limbo
            // and re-quarantine storms alive forever.
            let identity_changed = grace
                .get(node_id)
                .is_some_and(|state| state.public_key != connection.public_key);
            if identity_changed {
                // A newer incarnation supersedes the old 404 observation.
                // Start a fresh handoff grace window for this evidence
                // rather than destroying the new recovery.
                grace.remove(node_id);
            }
            let state =
                grace
                    .entry(node_id.to_string())
                    .or_insert_with(|| RelayNotFoundGraceState {
                        started_at: now,
                        public_key: connection.public_key.clone(),
                        event_recorded: false,
                    });
            let elapsed = now.saturating_duration_since(state.started_at);
            if elapsed >= RELAY_PEER_NOT_FOUND_GRACE {
                grace.remove(node_id);
                true
            } else {
                grace_remaining = RELAY_PEER_NOT_FOUND_GRACE.saturating_sub(elapsed);
                if !state.event_recorded {
                    state.event_recorded = true;
                    emit_grace_event = true;
                }
                false
            }
        };

        if should_quarantine {
            self.quarantine_peer(node_id, reason).await;
            true
        } else if emit_grace_event {
            self.record_direct_event(
                node_id,
                "relay_peer_not_found_grace",
                connection.signaled_endpoint,
                None,
                None,
                format!(
                    "relay peer_not_found treated as transient while control plane reports online; preserving recovery for {}ms reason={reason}",
                    grace_remaining.as_millis()
                ),
            )
            .await;
            true
        } else {
            false
        }
    }

    /// Invalidate every peer confirmation associated with a relay transport.
    pub async fn invalidate_relay_transport(
        &self,
        relay_server: &str,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.invalidate_relay_transport_for_connection(relay_server, None, code, reason)
            .await;
    }

    /// Invalidate state belonging to one relay transport incarnation.  This
    /// is required for make-before-break renewal: endpoint-level cleanup can
    /// otherwise erase a replacement connection that became ready between
    /// publishing the new transport and retiring the old one.
    pub(crate) async fn invalidate_relay_transport_for_connection(
        &self,
        relay_server: &str,
        relay_connection_id: Option<u64>,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) {
        let code = code.into();
        let reason = reason.into();
        let (cancelled, cancelled_expectations, cancelled_path_commits) = {
            let (_epoch_guard, mut conns) = self.lock_epoch_and_connections_write().await;
            let mut peer_cancelled = Vec::new();
            for conn in conns.values_mut() {
                // A peer is bound to this relay either because its last traffic
                // rode it (`relay_server`) or because its probe confirmation
                // was earned on it (`relay_confirmed_endpoint`) — both must be
                // revoked when the transport is gone.
                let transport_matches = relay_connection_id.is_none_or(|retired_id| {
                    [
                        conn.relay_ready_connection_id,
                        conn.relay_confirmed_connection_id,
                    ]
                    .into_iter()
                    .flatten()
                    .all(|known_id| known_id == retired_id)
                });
                let bound_via_server =
                    transport_matches && conn.relay_server.as_deref() == Some(relay_server);
                let bound_via_ready =
                    transport_matches && conn.relay_ready_endpoint.as_deref() == Some(relay_server);
                let bound_via_confirmation = transport_matches
                    && conn.relay_confirmed_endpoint.as_deref() == Some(relay_server);
                if !bound_via_server && !bound_via_ready && !bound_via_confirmation {
                    continue;
                }
                let Some(peer_session_generation) =
                    self.peer_session_generation_any_sync(&conn.node_id)
                else {
                    continue;
                };
                let relay_identity = RelayConnectionIdentity::new(
                    PathEpoch::new(
                        self.current_network_generation_sync(),
                        peer_session_generation,
                        conn.remote_candidate_epoch(),
                    ),
                    relay_server,
                    relay_connection_id
                        .or(conn.relay_confirmed_connection_id)
                        .or(conn.relay_ready_connection_id),
                );
                let had_confirmed = conn.relay_confirmed_at.is_some();
                let outcome = conn.commit_path_transition(
                    PathEvent::RelayTransportLost {
                        relay: relay_identity,
                    },
                    |conn| {
                        conn.relay_health.clear_timing_for_lifecycle_change();
                        conn.relay_health
                            .record_failure(code.clone(), reason.clone());
                        conn.relay_server = None;
                        conn.relay_ready_generation = None;
                        conn.relay_ready_at = None;
                        conn.relay_ready_endpoint = None;
                        conn.relay_ready_connection_id = None;
                        // The relay path is gone: RelayPeerConfirmed must be revoked so
                        // a future relay requires a fresh forced-probe confirmation
                        // (per relay endpoint).  Direct stays authoritative.
                        conn.relay_confirmed_at = None;
                        conn.relay_confirmed_generation = None;
                        conn.relay_confirmed_endpoint = None;
                        conn.relay_confirmed_connection_id = None;
                        conn.relay_first.gate_generation = None;
                        conn.relay_first.gate_started_at = None;
                        conn.relay_first.business_sent_generation = None;
                        conn.relay_first.business_received_generation = None;
                        conn.relay_first.business_exchange_generation = None;
                        conn.relay_first.business_pathcommit_generation = None;
                        if had_confirmed {
                            conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                            self.bump_relay_confirm_seq(&conn.node_id);
                        }
                    },
                );
                if !outcome.accepted() {
                    continue;
                }
                peer_cancelled.push(conn.node_id.clone());
            }
            let mut expectations = self
                .relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut expectation_cancelled = Vec::new();
            expectations.retain(|node_id, expectation| {
                let keep = expectation.relay_endpoint != relay_server
                    || relay_connection_id.is_some_and(|retired_id| {
                        expectation.relay_connection_id != Some(retired_id)
                    });
                if !keep {
                    expectation_cancelled.push(node_id.clone());
                }
                keep
            });
            let mut path_expectations = self
                .path_commit_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut path_commit_cancelled = Vec::new();
            path_expectations.retain(|node_id, expectation| {
                let keep = expectation.relay_endpoint != relay_server
                    || relay_connection_id
                        .is_some_and(|retired_id| expectation.relay_connection_id != retired_id);
                if !keep {
                    path_commit_cancelled.push(node_id.clone());
                }
                keep
            });
            (peer_cancelled, expectation_cancelled, path_commit_cancelled)
        };
        for node_id in cancelled_expectations {
            self.emit_timeline(
                "relay_probe_expectation_cancelled",
                Some("relay"),
                Some("relay_transport_failed"),
                Some(format!(
                    "peer={node_id} relay_endpoint={relay_server} reason={reason}"
                )),
            );
        }
        for node_id in cancelled_path_commits {
            self.emit_timeline(
                "path_commit_expectation_cancelled",
                Some("relay"),
                Some("relay_transport_failed"),
                Some(format!(
                    "peer={node_id} relay_endpoint={relay_server} reason={reason}"
                )),
            );
        }
        for node_id in cancelled {
            self.cancel_relay_backoff_heartbeat(&node_id);
        }
    }

    /// Cancel in-flight relay control expectations belonging to a superseded
    /// local relay connection.  Existing confirmed state is intentionally left
    /// alone during make-before-break; the next probe loop tick binds a fresh
    /// expectation to the replacement connection.  This closes the tiny
    /// handoff race in which an old ACK could otherwise be consumed before the
    /// replacement has published its first expectation.
    pub(crate) fn cancel_relay_probe_expectations_for_transport(
        &self,
        relay_endpoint: &str,
        relay_connection_id: u64,
    ) {
        let cancelled = {
            let mut expectations = self
                .relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut cancelled = Vec::new();
            expectations.retain(|node_id, expectation| {
                let keep = !(expectation.relay_endpoint == relay_endpoint
                    && expectation.relay_connection_id == Some(relay_connection_id));
                if !keep {
                    cancelled.push(node_id.clone());
                }
                keep
            });
            cancelled
        };
        for node_id in cancelled {
            self.emit_timeline(
                "relay_probe_expectation_cancelled",
                Some("relay"),
                Some("relay_transport_replaced"),
                Some(format!(
                    "peer={node_id} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id}"
                )),
            );
        }
        let path_cancelled = {
            let mut expectations = self
                .path_commit_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut cancelled = Vec::new();
            expectations.retain(|node_id, expectation| {
                let keep = !(expectation.relay_endpoint == relay_endpoint
                    && expectation.relay_connection_id == relay_connection_id);
                if !keep {
                    cancelled.push(node_id.clone());
                }
                keep
            });
            cancelled
        };
        for node_id in path_cancelled {
            self.emit_timeline(
                "path_commit_expectation_cancelled",
                Some("relay"),
                Some("relay_transport_replaced"),
                Some(format!(
                    "peer={node_id} relay_endpoint={relay_endpoint} relay_connection_id={relay_connection_id}"
                )),
            );
        }
    }
}
