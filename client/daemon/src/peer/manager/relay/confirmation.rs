impl PeerManager {
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
}

impl PeerManager {
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
                            pending_committed =
                                conn.relay_first.business_received_generation != Some(generation);
                            conn.relay_first.business_received_generation = Some(generation);
                            if conn.relay_first.business_sent_generation == Some(generation)
                                && conn.relay_first.business_exchange_generation != Some(generation)
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
}

impl PeerManager {
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
        let (recorded, rejected_reason, fallback_reason) = if conn
            .is_on_link_direct_for_generation(generation)
        {
            (
                conn.record_first_usable(NetworkPath::Direct, generation),
                None,
                None,
            )
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
                .is_some_and(|started_at| started_at.elapsed() >= RELAY_FIRST_CONFIRMATION_GRACE);
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
            (
                conn.record_first_usable(NetworkPath::Direct, generation),
                None,
                None,
            )
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
}

impl PeerManager {
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
}

impl PeerManager {
    /// The per-peer relay-confirmed instant, if any (daemon-local monotonic).
    pub async fn relay_confirmed_at(&self, node_id: &str) -> Option<Instant> {
        self.connections
            .read()
            .await
            .get(node_id)
            .and_then(|conn| conn.relay_confirmed_at)
    }
}
