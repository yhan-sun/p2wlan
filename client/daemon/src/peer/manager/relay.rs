impl PeerManager {
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
                                .find(|pair| pair.remote_endpoint == endpoint)
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

    /// Record that a relay path was attempted without treating TCP write success as delivery.
    pub async fn record_relay_attempt(&self, node_id: &str, relay_server: &str) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
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
        let record_failure = if code == "peer_not_found" {
            self.handle_relay_peer_not_found(node_id, &reason).await
        } else {
            true
        };
        if record_failure {
            if let Some(conn) = self.connections.write().await.get_mut(node_id) {
                conn.relay_health.record_failure(code, reason);
                if conn.state == ConnectionState::Relay {
                    conn.transition(ConnectionState::FallbackToRelay);
                }
            }
        }
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
            let state = grace
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
        let code = code.into();
        let reason = reason.into();
        let cancelled = {
            let mut cancelled = Vec::new();
            for conn in self.connections.write().await.values_mut() {
                if conn.relay_server.as_deref() != Some(relay_server) {
                    continue;
                }
                conn.relay_health
                    .record_failure(code.clone(), reason.clone());
                conn.relay_server = None;
                if conn.state == ConnectionState::Relay {
                    conn.transition(ConnectionState::FallbackToRelay);
                }
                cancelled.push(conn.node_id.clone());
            }
            cancelled
        };
        for node_id in cancelled {
            self.cancel_relay_backoff_heartbeat(&node_id);
        }
    }
}
