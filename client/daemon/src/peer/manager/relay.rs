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
        let now = Instant::now();
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            let endpoint_changed =
                conn.relay_ready_endpoint.as_deref() != Some(relay_endpoint);
            if endpoint_changed || conn.relay_ready_generation.is_none() {
                conn.relay_ready_generation = Some(generation);
                conn.relay_ready_at = Some(now);
                conn.relay_ready_endpoint = Some(relay_endpoint.to_string());
                debug!(
                    event = "relay_transport_ready_peer",
                    peer_id = %node_id,
                    relay_endpoint = %relay_endpoint,
                    generation = generation,
                    "relay transport ready for peer peer_id={node_id} relay_endpoint={relay_endpoint}",
                );
                self.emit_timeline(
                    "relay_transport_ready_peer",
                    Some("relay"),
                    None,
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                    )),
                );
            }
        }
    }

    /// Confirm the relay path to a peer after a matching forced-relay probe ACK
    /// whose real ingress was relay.  Sets `RelayPeerConfirmed`, bumps the
    /// relay-confirm sequence (notifying outbound waiters) and transitions the
    /// peer to Relay state.
    ///
    /// This is the relay-path confirmation milestone ONLY — it never records
    /// `first_usable`.  First usability must be proven by real bidirectional
    /// decrypted overlay business traffic (`record_verified_first_usable`),
    /// never by a confirmation, a TCP/TLS connect, or a queued registration.
    ///
    /// Returns `true` only when this call NEWLY confirmed the peer (later
    /// identical confirmations no-op).
    pub async fn confirm_relay_peer(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
    ) -> bool {
        // Quarantine is authoritative isolation after a sustained relay
        // `peer_not_found`.  Check it immediately before taking the
        // connection lock so a late ACK cannot re-admit the stale peer.
        if self.peer_quarantined(node_id).await {
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
        let now = Instant::now();
        let newly_confirmed = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            if conn.relay_confirmed_at.is_some()
                && conn.relay_confirmed_generation == Some(generation)
                && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
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
                conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                false
            } else {
                // A confirmation from an older generation is never reused.
                if conn.relay_confirmed_endpoint.as_deref() != Some(relay_endpoint) {
                    conn.relay_confirmed_endpoint = None;
                }
                conn.relay_confirmed_generation = Some(generation);
                conn.relay_confirmed_at = Some(now);
                conn.relay_confirmed_endpoint = Some(relay_endpoint.to_string());
                conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                if conn.state != ConnectionState::Direct {
                    conn.transition(ConnectionState::Relay);
                }
                info!(
                    event = "relay_peer_confirmed",
                    peer_id = %node_id,
                    relay_endpoint = %relay_endpoint,
                    generation = generation,
                    relay_confirm_seq = conn.relay_confirm_seq,
                    "relay_peer_confirmed peer_id={node_id} relay_endpoint={relay_endpoint} generation={generation}",
                );
                self.emit_timeline(
                    "relay_peer_confirmed",
                    Some("relay"),
                    None,
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                    )),
                );
                true
            }
        };
        if newly_confirmed {
            self.bump_relay_confirm_seq(node_id);
        }
        newly_confirmed
    }

    /// Record the FIRST confirmed usable path for a peer, proven ONLY by real
    /// decrypted business traffic. Production TUN ingress calls this after a
    /// normal encrypted packet decrypts; the independent overlay validation
    /// harness additionally requires a locally-sent matching-nonce echo. In
    /// both cases the real ingress (`relay:<endpoint>` or `direct`) is known —
    /// never a confirmation, a single UDP send, or a TCP connect.
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
        let recorded = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            conn.record_first_usable(path, generation)
        };
        if recorded {
            self.emit_timeline_first(
                node_id,
                generation,
                "first_usable_path",
                Some(match path {
                    NetworkPath::Direct => "direct",
                    NetworkPath::Relay => "relay",
                }),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} ingress={ingress_label}"
                )),
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
                conn.relay_confirmed_at.is_some()
                    && conn.relay_confirmed_generation == Some(generation)
            })
    }

    /// Register the token of a forced-relay probe the local daemon just sent,
    /// against which a relay-ingress ACK is verified.  Newest-wins per peer;
    /// the map is bounded by the per-peer probe loop's single in-flight probe.
    pub fn register_relay_probe_expectation(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
    ) {
        let mut expectations = self
            .relay_probe_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        expectations.insert(
            node_id.to_string(),
            crate::relay_probe::RelayProbeExpectation {
                generation,
                request_id,
                owner_token,
                relay_endpoint: relay_endpoint.to_string(),
                sent_at: Instant::now(),
            },
        );
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
    pub(crate) async fn consume_relay_probe_ack(
        &self,
        node_id: &str,
        token: crate::relay_probe::RelayProbeToken,
        ack_ingress: &str,
    ) -> bool {
        // Remove any outstanding expectation before returning.  A late ACK
        // must not revive a peer that was quarantined after the relay stopped
        // registering it, even if its token is otherwise syntactically valid.
        if self.peer_quarantined(node_id).await {
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
                        "peer={node_id} request_id={} generation={} owner={} ingress={ack_ingress}",
                        token.request_id, token.generation, token.owner_token
                    )),
                );
            }
            return false;
        }
        let now = Instant::now();
        let expectation = {
            let mut expectations = self
                .relay_probe_expectations
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let expectation = expectations.get(node_id).cloned();
            // A consumed (matched) expectation is removed so duplicate or late
            // ACKs are no-ops.
            if expectation.as_ref().is_some_and(|expectation| {
                expectation.accepts(&token, now, ack_ingress)
            }) {
                expectations.remove(node_id);
            }
            expectation
        };
        let Some(expectation) = expectation else {
            debug!(
                "Ignored relay probe ACK from {node_id}: no fresh matching expectation (request_id={} generation={} owner={})",
                token.request_id, token.generation, token.owner_token
            );
            return false;
        };
        if !expectation.accepts(&token, now, ack_ingress) {
            // Distinguish a mismatched INGRESS relay from a generic stale ACK
            // so diagnostics can tell "old relay" from "late ACK".
            let token_ok = expectation.matches(&token) && expectation.fresh(now);
            let reason_code = if token_ok && expectation.relay_endpoint != ack_ingress {
                "relay_mismatch"
            } else {
                "stale"
            };
            self.emit_timeline(
                "relay_probe_ack_stale",
                Some("relay"),
                Some(reason_code),
                Some(format!(
                    "peer={node_id} request_id={} generation={} owner={} expected_relay={} ack_ingress={ack_ingress}",
                    token.request_id,
                    token.generation,
                    token.owner_token,
                    expectation.relay_endpoint
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
        let confirmed = self
            .confirm_relay_peer(node_id, &relay_endpoint, generation)
            .await;
        info!(
            event = "relay_probe_ack_consumed",
            peer_id = %node_id,
            relay_endpoint = %relay_endpoint,
            generation = generation,
            request_id = token.request_id,
            confirmed = confirmed,
            "relay_probe_ack_consumed peer_id={node_id} relay_endpoint={relay_endpoint} request_id={} confirmed={confirmed}",
            token.request_id,
        );
        confirmed
    }

    /// Peers that still need a forced-relay probe: online, not Direct, and the
    /// relay path is not yet confirmed.  The relay probe loop further filters
    /// by WireGuard session readiness (it owns the transport) and sends one
    /// probe per returned peer (newest-wins expectation), repeating until
    /// confirmed or the peer becomes Direct.
    pub async fn relay_probe_targets(&self) -> Vec<(String, String, u64)> {
        let generation = self.current_network_generation().await;
        let candidates: Vec<_> = self
            .connections
            .read()
            .await
            .values()
            .filter(|conn| {
                conn.online
                    && conn.state != ConnectionState::Closed
                    && conn.state != ConnectionState::Direct
                    && conn.relay_confirmed_at.is_none()
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

    /// The per-peer first-usable instant, if any (daemon-local monotonic).
    pub async fn first_usable_at(&self, node_id: &str) -> Option<Instant> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.first_usable_at)
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
            if let Some(conn) = self.connections.write().await.get_mut(node_id) {
                conn.relay_health.record_failure(code, reason);
                if conn.state == ConnectionState::Relay {
                    conn.transition(ConnectionState::FallbackToRelay);
                }
            }
        }
    }

    /// Revoke a peer's RelayPeerConfirmed (set it to unconfirmed, bump the
    /// relay-confirm sequence and notify waiters).  Returns whether the peer
    /// was confirmed before this call.  The relay path must be re-established
    /// by a fresh forced-probe ACK (matching ingress + generation) before the
    /// peer is usable over the relay again.
    pub(crate) async fn revoke_relay_peer_confirmation(&self, node_id: &str) -> bool {
        let (revoked, previous_endpoint, previous_generation) = {
            let mut conns = self.connections.write().await;
            match conns.get_mut(node_id) {
                Some(conn) if conn.relay_confirmed_at.is_some() => {
                    let endpoint = conn.relay_confirmed_endpoint.clone();
                    let generation = conn.relay_confirmed_generation;
                    conn.relay_confirmed_at = None;
                    conn.relay_confirmed_generation = None;
                    conn.relay_confirmed_endpoint = None;
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    if conn.state == ConnectionState::Relay {
                        conn.transition(ConnectionState::FallbackToRelay);
                    }
                    (true, endpoint, generation)
                }
                _ => (false, None, None),
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
            self.bump_relay_confirm_seq(node_id);
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
                // A peer is bound to this relay either because its last traffic
                // rode it (`relay_server`) or because its probe confirmation
                // was earned on it (`relay_confirmed_endpoint`) — both must be
                // revoked when the transport is gone.
                let bound_via_server = conn.relay_server.as_deref() == Some(relay_server);
                let bound_via_confirmation =
                    conn.relay_confirmed_endpoint.as_deref() == Some(relay_server);
                if !bound_via_server && !bound_via_confirmation {
                    continue;
                }
                conn.relay_health
                    .record_failure(code.clone(), reason.clone());
                conn.relay_server = None;
                // The relay path is gone: RelayPeerConfirmed must be revoked so
                // a future relay requires a fresh forced-probe confirmation
                // (per relay endpoint).  Direct stays authoritative.
                let had_confirmed = conn.relay_confirmed_at.take().is_some();
                conn.relay_confirmed_generation = None;
                conn.relay_confirmed_endpoint = None;
                if had_confirmed {
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                }
                if conn.state == ConnectionState::Relay {
                    conn.transition(ConnectionState::FallbackToRelay);
                }
                cancelled.push(conn.node_id.clone());
            }
            cancelled
        };
        for node_id in cancelled {
            if let Some(conn) = self.connections.write().await.get_mut(&node_id) {
                if conn.relay_confirm_seq > 0 {
                    self.bump_relay_confirm_seq(&node_id);
                }
            }
            self.cancel_relay_backoff_heartbeat(&node_id);
        }
    }
}
