impl PeerManager {
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
}

impl PeerManager {
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
}
