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

    /// Record decrypted relay ingress as a health observation only.
    ///
    /// A frame reaching this daemon proves that this daemon can decrypt a
    /// frame received from the relay, but it does not prove that the peer has
    /// received anything, nor that the current generation's forced-relay
    /// probe was acknowledged.  Production transport code must use this
    /// method instead of [`Self::record_relay_success`], so a validation
    /// packet, writer completion, or unsolicited business frame cannot make
    /// an unconfirmed relay appear as the active path.
    pub(crate) async fn record_relay_observation(
        &self,
        node_id: &str,
        relay_server: &str,
        latency: Option<Duration>,
    ) {
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            conn.relay_server = Some(relay_server.to_string());
            if let Some(latency) = latency {
                conn.relay_health.record_success_with_latency(latency);
            } else {
                conn.relay_health.record_success();
            }
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
        self.mark_relay_transport_ready_with_transport(
            node_id,
            relay_endpoint,
            generation,
            None,
        )
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
        // READY is part of the same per-generation path state as the
        // confirmation and first-business markers.  Hold the epoch gate from
        // the generation check through the connection write so a network
        // advance cannot clear the state between those two operations.
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        let current_generation = self.current_network_generation_sync();
        if generation != current_generation || self.peer_quarantined(node_id).await {
            self.emit_timeline(
                "relay_transport_ready_rejected",
                Some("relay"),
                Some("stale_generation_or_quarantine"),
                Some(format!(
                    "peer={node_id} generation={generation} current_generation={current_generation} relay_endpoint={relay_endpoint}"
                )),
            );
            return;
        }
        let now = Instant::now();
        let mut invalidated_confirmation = None;
        if let Some(conn) = self.connections.write().await.get_mut(node_id) {
            // Re-check quarantine after acquiring the connection lock. The
            // first check above only avoids needless work; quarantine can be
            // committed while this task is waiting for the lock.
            if !conn.online
                || conn.state == ConnectionState::Closed
                || self.peer_quarantined_sync(node_id)
            {
                return;
            }
            let endpoint_changed =
                conn.relay_ready_endpoint.as_deref() != Some(relay_endpoint);
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
                    conn.relay_first_business_sent_generation = None;
                    conn.relay_first_business_received_generation = None;
                    conn.relay_first_business_exchange_generation = None;
                    conn.relay_preconfirmation_business = None;
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    if conn.state == ConnectionState::Relay {
                        conn.transition(ConnectionState::FallbackToRelay);
                    }
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
                if conn.relay_first_gate_generation != Some(generation) {
                    conn.relay_first_gate_generation = Some(generation);
                    conn.relay_first_gate_started_at = Some(now);
                } else {
                    conn.relay_first_gate_started_at.get_or_insert(now);
                }
                conn.relay_first_business_sent_generation = None;
                conn.relay_first_business_received_generation = None;
                conn.relay_first_business_exchange_generation = None;
                conn.relay_preconfirmation_business = None;
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
            }
        }
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
        self.confirm_relay_peer_inner(
            node_id,
            relay_endpoint,
            generation,
            None,
            "encrypted_probe_ack",
        )
            .await
    }

    /// Confirm a relay path and bind the proof to one local relay transport
    /// incarnation.  The endpoint and network generation remain part of the
    /// proof, but are not sufficient across same-endpoint renewal.
    pub(crate) async fn confirm_relay_peer_with_transport(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
    ) -> bool {
        self.confirm_relay_peer_inner(
            node_id,
            relay_endpoint,
            generation,
            relay_connection_id,
            "encrypted_probe_ack",
        )
        .await
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
        self.confirm_relay_peer_inner(
            node_id,
            relay_endpoint,
            generation,
            relay_connection_id,
            "encrypted_business_ingress",
        )
        .await
    }

    async fn confirm_relay_peer_inner(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
        confirmation_source: &'static str,
    ) -> bool {
        // The ACK expectation is checked before this method is called, but
        // that check is not the commit boundary: an Air/network generation
        // can advance after the expectation is consumed.  Re-check and
        // commit under the shared epoch gate so an old ACK can never install
        // RelayPeerConfirmed in the new generation.
        let (confirmation_changed, preconfirmation_business_received) = {
            let epoch_gate = self.network_epoch_gate();
            let _epoch_guard = epoch_gate.lock().await;
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
            let result = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            // Close the lock-acquisition race with quarantine: a late ACK
            // cannot re-admit an old relay registration after quarantine has
            // committed while this task waited for the connection lock.
            if self.peer_quarantined_sync(node_id) {
                return false;
            }
            // The ready milestone is bound to the currently published relay
            // transport.  Once a replacement has been published, an ACK from
            // the retired same-endpoint connection must not be able to
            // recreate RelayPeerConfirmed in this generation.  Legacy/unit
            // callers may have no incarnation id; an unknown ready id is
            // therefore accepted and is filled by the confirmation below.
            if conn.relay_ready_generation == Some(generation)
                && conn.relay_ready_endpoint.as_deref() == Some(relay_endpoint)
                && conn
                    .relay_ready_connection_id
                    .is_some_and(|ready_id| relay_connection_id != Some(ready_id))
            {
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
            // A real overlay packet can arrive from the relay before this
            // daemon consumes the matching path-probe ACK.  Keep that
            // evidence only across the bounded confirmation grace period and
            // only for the exact relay transport incarnation.  The packet has
            // already crossed WireGuard's replay window, so it cannot be
            // replayed after confirmation to reconstruct the evidence.
            let preconfirmation_business_received = conn
                .relay_preconfirmation_business
                .take()
                .filter(|pending| {
                    pending.generation == generation
                        && pending.relay_endpoint == relay_endpoint
                        && pending.relay_connection_id == relay_connection_id
                        && now.saturating_duration_since(pending.received_at)
                            <= RELAY_FIRST_CONFIRMATION_GRACE
                })
                .is_some();
            let result = if conn.relay_confirmed_at.is_some()
                && conn.relay_confirmed_generation == Some(generation)
                && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
                && conn.relay_confirmed_connection_id == relay_connection_id
            {
                // The exact endpoint and generation was already confirmed.
                // Duplicate encrypted ACKs are deliberately idempotent.
                (false, preconfirmation_business_received)
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
                conn.relay_first_gate_generation = None;
                conn.relay_first_gate_started_at = None;
                conn.relay_first_business_sent_generation = None;
                conn.relay_first_business_received_generation = None;
                conn.relay_first_business_exchange_generation = None;
                conn.relay_preconfirmation_business = None;
                if conn.state != ConnectionState::Direct {
                    conn.transition(ConnectionState::Relay);
                }
                (true, preconfirmation_business_received)
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
                conn.relay_first_gate_generation = None;
                conn.relay_first_gate_started_at = None;
                conn.relay_first_business_sent_generation = None;
                // A packet received while the transport was merely READY is
                // not relay delivery evidence.  Only a matching encrypted
                // peer ACK authorizes the business marker for this generation.
                conn.relay_first_business_received_generation = None;
                conn.relay_first_business_exchange_generation = None;
                conn.relay_preconfirmation_business = None;
                if conn.state != ConnectionState::Direct {
                    conn.transition(ConnectionState::Relay);
                }
                (true, preconfirmation_business_received)
            };
            if preconfirmation_business_received {
                conn.relay_first_business_received_generation = Some(generation);
                if conn.relay_first_business_sent_generation == Some(generation) {
                    conn.relay_first_business_exchange_generation = Some(generation);
                }
            }
            if result.0 {
                // Keep the synchronous waiter mirror in the same critical
                // section as the connection state transition.  Otherwise a
                // waiter could observe the state before its notification
                // sequence is visible and miss the wake-up.
                self.bump_relay_confirm_seq(node_id);
            }
                result
            };
            (result.0, result.1)
        };
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
        if preconfirmation_business_received {
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
            if self
                .record_verified_first_usable(
                    node_id,
                    generation,
                    NetworkPath::Relay,
                    &format!("relay:{relay_endpoint}"),
                )
                .await
            {
                self.emit_timeline(
                    "relay_first_business_evidence_promoted",
                    Some("relay"),
                    None,
                    Some(format!(
                        "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                    )),
                );
            }
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
        // Linearize the generation check and the connection-state write with
        // Air/network generation advance.  Without this gate, an inbound
        // packet could observe generation N, then advance_network_generation
        // could clear N's state, and the packet could still write first_usable
        // for the retired generation afterwards.
        let epoch_gate = self.network_epoch_gate();
        let _epoch_guard = epoch_gate.lock().await;
        self.record_verified_first_usable_in_epoch(node_id, generation, path, ingress_label)
            .await
    }

    async fn record_verified_first_usable_in_epoch(
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
        let (recorded, rejected_reason, fallback_reason) = {
            let mut conns = self.connections.write().await;
            match conns.get_mut(node_id) {
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
                        (
                            false,
                            Some(REASON_FIRST_RELAY_BEFORE_CONFIRMATION),
                            None,
                        )
                    } else if path == NetworkPath::Direct
                        && (conn.relay_confirmed_generation == Some(generation)
                            && conn.relay_confirmed_endpoint.is_some())
                        && conn.relay_first_business_exchange_generation != Some(generation)
                    {
                        // A confirmed relay remains the business safety path
                        // until both same-generation relay business
                        // directions have been observed.  Direct validation
                        // is deliberately background-only here; a timer must
                        // never convert missing relay ingress into a false
                        // Direct first-usable result.
                        (false, Some(REASON_FIRST_DIRECT_BEFORE_RELAY_BUSINESS), None)
                    } else if path == NetworkPath::Direct
                        && (conn.relay_ready_generation == Some(generation)
                            || conn.relay_first_gate_generation == Some(generation))
                        && conn.relay_confirmed_generation != Some(generation)
                    {
                        // If relay peer confirmation itself is still pending,
                        // keep the bounded startup fallback: after the gate
                        // expires, a separately encrypted-confirmed Direct
                        // path may establish first usable because no relay
                        // delivery proof exists for this generation.
                        let gate_expired = conn
                            .relay_ready_at
                            .or(conn.relay_first_gate_started_at)
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
            self.emit_timeline_first(
                node_id,
                generation,
                "first_usable_path",
                Some(match path {
                    NetworkPath::Direct => "direct",
                    NetworkPath::Relay => "relay",
                }),
                fallback_reason,
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
    pub fn register_relay_probe_expectation(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
    ) {
        self.register_relay_probe_expectation_inner(
            node_id,
            generation,
            request_id,
            owner_token,
            relay_endpoint,
            None,
        );
    }

    /// Register a probe expectation bound to one local relay connection
    /// incarnation.  Endpoint + network generation are not enough during a
    /// make-before-break renewal because the old and new connections may use
    /// the same endpoint and peer session.
    pub(crate) fn register_relay_probe_expectation_for_transport(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
        relay_connection_id: u64,
    ) {
        self.register_relay_probe_expectation_inner(
            node_id,
            generation,
            request_id,
            owner_token,
            relay_endpoint,
            Some(relay_connection_id),
        );
    }

    fn register_relay_probe_expectation_inner(
        &self,
        node_id: &str,
        generation: u64,
        request_id: u16,
        owner_token: u64,
        relay_endpoint: &str,
        relay_connection_id: Option<u64>,
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
                relay_connection_id,
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
    #[cfg(test)]
    pub(crate) async fn consume_relay_probe_ack(
        &self,
        node_id: &str,
        token: crate::relay_probe::RelayProbeToken,
        ack_ingress: &str,
    ) -> bool {
        self.consume_relay_probe_ack_inner(node_id, token, ack_ingress, None)
            .await
    }

    /// Consume an ACK from a live relay reader, including the local relay
    /// connection incarnation that delivered it.
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
        )
        .await
    }

    async fn consume_relay_probe_ack_inner(
        &self,
        node_id: &str,
        token: crate::relay_probe::RelayProbeToken,
        ack_ingress: &str,
        ack_connection_id: Option<u64>,
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
                        "peer={node_id} request_id={} generation={} owner_present=true ingress={ack_ingress}",
                        token.request_id, token.generation
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
                    && expectation.accepts_connection(ack_connection_id)
            }) {
                expectations.remove(node_id);
            }
            expectation
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
            .confirm_relay_peer_with_transport(
                node_id,
                &relay_endpoint,
                generation,
                ack_connection_id,
            )
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

    /// Peers that still need a forced-relay probe: online and not yet relay
    /// confirmed.  Direct peers remain in this list because Direct validation
    /// is a background upgrade and must not suppress relay-first confirmation.
    /// The relay probe loop further filters by WireGuard session readiness (it
    /// owns the transport) and sends one probe per returned peer
    /// (newest-wins expectation), repeating until confirmed or the peer is
    /// quarantined/offline.
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

    /// Whether the current forced-relay probe expectation is still installed.
    ///
    /// A relay `peer_not_found` removes the expectation immediately. The
    /// probe loop uses that transition to rotate the token before retrying;
    /// otherwise an ACK for a probe that the relay rejected could be accepted
    /// after the next registration attempt and resurrect a stale path.
    pub(crate) fn relay_probe_expectation_present(&self, node_id: &str) -> bool {
        self.relay_probe_expectations
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(node_id)
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
    pub(crate) async fn mark_relay_first_business_sent_for_generation(
        &self,
        node_id: &str,
        generation: u64,
    ) -> bool {
        let (changed, exchange_confirmed, relay_endpoint) = {
            let epoch_gate = self.network_epoch_gate();
            let _epoch_guard = epoch_gate.lock().await;
            if generation != self.current_network_generation_sync() {
                return false;
            }
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let confirmed = conn.relay_confirmed_at.is_some()
                && conn.relay_confirmed_generation == Some(generation)
                && conn
                    .relay_confirmed_endpoint
                    .as_deref()
                    .is_some_and(|endpoint| !endpoint.is_empty());
            if !confirmed || conn.relay_first_business_sent_generation == Some(generation) {
                return false;
            }
            conn.relay_first_business_sent_generation = Some(generation);
            let exchange_confirmed = conn.relay_first_business_received_generation == Some(generation)
                && conn.relay_first_business_exchange_generation != Some(generation);
            if exchange_confirmed {
                conn.relay_first_business_exchange_generation = Some(generation);
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

    /// Commit the first normal business packet received through the
    /// same-generation confirmed relay.  This is deliberately separate from
    /// writer completion: Direct may not become the active path until both
    /// the local send and the remote-to-local receive direction have crossed
    /// the same relay transport.  The two markers may arrive in either order;
    /// their generation/endpoint binding, not local event ordering, is the
    /// invariant.
    #[cfg(test)]
    pub(crate) async fn mark_relay_first_business_received_for_generation(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
    ) -> bool {
        self.mark_relay_first_business_received_for_generation_with_transport(
            node_id,
            relay_endpoint,
            generation,
            None,
        )
        .await
    }

    /// Record a decrypted relay business packet with the local relay
    /// transport incarnation.  Before the path-probe ACK this stores a
    /// bounded pending tuple; after confirmation it commits the normal
    /// receive/exchange markers.  The ACK and packet may therefore arrive in
    /// either order without trying to replay a WireGuard ciphertext.
    pub(crate) async fn mark_relay_first_business_received_for_generation_with_transport(
        &self,
        node_id: &str,
        relay_endpoint: &str,
        generation: u64,
        relay_connection_id: Option<u64>,
    ) -> bool {
        let now = Instant::now();
        let (first_receive, exchange_confirmed, endpoint, pending) = {
            let epoch_gate = self.network_epoch_gate();
            let _epoch_guard = epoch_gate.lock().await;
            if generation != self.current_network_generation_sync() {
                self.emit_timeline(
                    "relay_first_business_received_rejected",
                    Some("relay"),
                    Some("stale_generation"),
                    Some(format!(
                        "peer={node_id} generation={generation} current_generation={} relay_endpoint={relay_endpoint}",
                        self.current_network_generation_sync()
                    )),
                );
                return false;
            }
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let relay_session_matches = conn.online
                    && conn.state != ConnectionState::Closed
                    && conn.relay_confirmed_generation == Some(generation)
                    && conn.relay_confirmed_endpoint.as_deref() == Some(relay_endpoint)
                    && conn.relay_confirmed_connection_id == relay_connection_id;
            let result = if !relay_session_matches {
                let ready_session_matches = conn.online
                    && conn.state != ConnectionState::Closed
                    && conn.relay_ready_generation == Some(generation)
                    && conn.relay_ready_endpoint.as_deref() == Some(relay_endpoint);
                let pending = if ready_session_matches {
                    let should_replace = conn
                        .relay_preconfirmation_business
                        .as_ref()
                        .is_none_or(|existing| {
                            existing.generation != generation
                                || existing.relay_endpoint != relay_endpoint
                                || existing.relay_connection_id != relay_connection_id
                                || now.saturating_duration_since(existing.received_at)
                                    > RELAY_FIRST_CONFIRMATION_GRACE
                        });
                    if should_replace {
                        conn.relay_preconfirmation_business =
                            Some(PendingRelayBusinessEvidence {
                                generation,
                                relay_endpoint: relay_endpoint.to_string(),
                                relay_connection_id,
                                received_at: now,
                            });
                    }
                    should_replace
                } else {
                    false
                };
                (false, false, None, pending)
            } else {
                let first_receive =
                    conn.relay_first_business_received_generation != Some(generation);
                if first_receive {
                    conn.relay_first_business_received_generation = Some(generation);
                }
                let exchange_confirmed =
                    conn.relay_first_business_sent_generation == Some(generation)
                        && conn.relay_first_business_exchange_generation != Some(generation);
                if exchange_confirmed {
                    conn.relay_first_business_exchange_generation = Some(generation);
                }
                if !first_receive && !exchange_confirmed {
                    (false, false, None, false)
                } else {
                    (
                        first_receive,
                        exchange_confirmed,
                        conn.relay_confirmed_endpoint
                            .clone()
                            .or_else(|| conn.relay_ready_endpoint.clone())
                            .or_else(|| Some(relay_endpoint.to_string())),
                        false,
                    )
                }
            };
            result
        };
        if pending {
            self.emit_timeline(
                "relay_first_business_received_pending",
                Some("relay"),
                Some("awaiting_relay_probe_confirmation"),
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={relay_endpoint}"
                )),
            );
        }
        if first_receive {
            self.emit_timeline(
                "relay_first_business_received",
                Some("relay"),
                None,
                Some(format!(
                    "peer={node_id} generation={generation} relay_endpoint={}",
                    endpoint.as_deref().unwrap_or("unknown")
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
                    endpoint.as_deref().unwrap_or("unknown")
                )),
            );
        }
        first_receive || exchange_confirmed
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
        let (revoked, ready_cleared, previous_endpoint, previous_generation) = {
            let epoch_gate = self.network_epoch_gate();
            let _epoch_guard = epoch_gate.lock().await;
            let mut conns = self.connections.write().await;
            match conns.get_mut(node_id) {
                Some(conn)
                    if conn.relay_confirmed_at.is_some() || conn.relay_ready_at.is_some() =>
                {
                    let endpoint = conn.relay_confirmed_endpoint.clone();
                    let generation = conn.relay_confirmed_generation;
                    let had_confirmed = conn.relay_confirmed_at.is_some();
                    conn.relay_confirmed_at = None;
                    conn.relay_confirmed_generation = None;
                    conn.relay_confirmed_endpoint = None;
                    conn.relay_confirmed_connection_id = None;
                    conn.relay_first_gate_generation = None;
                    conn.relay_first_gate_started_at = None;
                    conn.relay_first_business_sent_generation = None;
                    conn.relay_first_business_received_generation = None;
                    conn.relay_first_business_exchange_generation = None;
                    conn.relay_preconfirmation_business = None;
                    let had_ready = conn.relay_ready_at.is_some();
                    conn.relay_ready_generation = None;
                    conn.relay_ready_at = None;
                    conn.relay_ready_endpoint = None;
                    conn.relay_ready_connection_id = None;
                    if had_confirmed {
                        conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    }
                    if had_confirmed && conn.state == ConnectionState::Relay {
                        conn.transition(ConnectionState::FallbackToRelay);
                    }
                    if had_confirmed {
                        // Keep the waiter mirror synchronized with the
                        // revocation while the epoch gate is still held.
                        self.bump_relay_confirm_seq(node_id);
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
        let (cancelled, cancelled_expectations) = {
            let epoch_gate = self.network_epoch_gate();
            let _epoch_guard = epoch_gate.lock().await;
            let mut peer_cancelled = Vec::new();
            for conn in self.connections.write().await.values_mut() {
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
                let bound_via_server = transport_matches
                    && conn.relay_server.as_deref() == Some(relay_server);
                let bound_via_ready = transport_matches
                    && conn.relay_ready_endpoint.as_deref() == Some(relay_server);
                let bound_via_confirmation = transport_matches
                    && conn.relay_confirmed_endpoint.as_deref() == Some(relay_server);
                if !bound_via_server && !bound_via_ready && !bound_via_confirmation {
                    continue;
                }
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
                let had_confirmed = conn.relay_confirmed_at.take().is_some();
                conn.relay_confirmed_generation = None;
                conn.relay_confirmed_endpoint = None;
                conn.relay_confirmed_connection_id = None;
                conn.relay_first_gate_generation = None;
                conn.relay_first_gate_started_at = None;
                conn.relay_first_business_sent_generation = None;
                conn.relay_first_business_received_generation = None;
                conn.relay_first_business_exchange_generation = None;
                conn.relay_preconfirmation_business = None;
                if had_confirmed {
                    conn.relay_confirm_seq = conn.relay_confirm_seq.wrapping_add(1);
                    self.bump_relay_confirm_seq(&conn.node_id);
                }
                if conn.state == ConnectionState::Relay {
                    conn.transition(ConnectionState::FallbackToRelay);
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
            (peer_cancelled, expectation_cancelled)
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
        for node_id in cancelled {
            self.cancel_relay_backoff_heartbeat(&node_id);
        }
    }

    /// Cancel only in-flight probe expectations belonging to a superseded
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
    }
}
