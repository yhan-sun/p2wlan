impl PeerManager {
    /// Whether the peer is direct in a specific generation.
    pub async fn is_direct_for_generation(&self, node_id: &str, generation: u64) -> bool {
        generation == self.current_network_generation().await && self.is_direct(node_id).await
    }

    /// Set the relay server for a peer.
    pub async fn set_relay(&self, node_id: &str, relay_server: &str) {
        self.record_relay_success(node_id, relay_server, true).await;
    }
}

impl PeerManager {
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
}

impl PeerManager {
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
}
