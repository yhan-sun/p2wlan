impl PeerManager {
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
}

impl PeerManager {
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
