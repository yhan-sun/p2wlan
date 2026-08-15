impl PeerManager {
    /// Record a successful direct-path event.
    pub async fn record_direct_success(&self, node_id: &str, endpoint: Option<SocketAddr>) {
        self.record_direct_success_with_local_endpoint(node_id, endpoint, None)
            .await;
    }

    /// Record a successful direct-path event with the local UDP endpoint that received it.
    pub async fn record_direct_success_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_success_for_generation_with_local_endpoint(
            node_id,
            endpoint,
            generation,
            local_endpoint,
        )
        .await;
    }

    /// Record a successful direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_success_for_generation(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
    ) -> bool {
        self.record_direct_success_for_generation_with_local_endpoint(
            node_id, endpoint, generation, None,
        )
        .await
    }

    /// Record a successful direct-path event for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_success_for_generation_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        // The whole promotion (state -> Direct, mirror update) runs under the
        // shared network-epoch gate: the UDP eviction path re-verifies the
        // Direct mirror inside the same gate, so a peer that becomes Direct
        // here can never lose its working dynamic socket to a concurrent
        // eviction that read the pre-promotion mirror.
        let epoch_gate = self.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        self.record_direct_success_for_generation_with_local_endpoint_in_epoch(
            &epoch_guard,
            node_id,
            endpoint,
            generation,
            local_endpoint,
        )
        .await
    }

    /// Record Direct success while the caller holds the shared network epoch
    /// gate.  This is the ACK-commit primitive: token validation, expectation
    /// consumption and the Direct state transition can use one uninterrupted
    /// epoch transaction rather than checking a generation before acquiring
    /// the lock and promoting after it has changed.
    ///
    /// The guard is deliberately an argument instead of an implicit lock: it
    /// makes callers that compose the ACK transaction prove that they are
    /// inside an epoch critical section.  `UdpTransport` and `PeerManager`
    /// share this gate.
    pub(crate) async fn record_direct_success_for_generation_with_local_endpoint_in_epoch(
        &self,
        _epoch_guard: &tokio::sync::MutexGuard<'_, ()>,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        self.record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch(
            _epoch_guard,
            node_id,
            endpoint,
            generation,
            local_endpoint,
            None,
        )
        .await
    }

    /// Record Direct success from an encrypted validation ACK and, when
    /// present, replace probe-derived RTT with that exact Request -> ACK
    /// measurement.  The generation gate and promotion transaction are shared
    /// with the ordinary confirmation path.
    pub(crate) async fn record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch(
        &self,
        _epoch_guard: &tokio::sync::MutexGuard<'_, ()>,
        node_id: &str,
        endpoint: Option<SocketAddr>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
        validation_latency: Option<Duration>,
    ) -> bool {
        // The lock-free mirror is written while this very gate is held by a
        // generation advance.  Reading it here therefore cannot race an
        // advance between validation and mutation.
        if generation != self.current_network_generation_sync() {
            return false;
        }
        // An exact, decrypted validation ACK is authoritative evidence for
        // this request/generation/endpoint.  Its RTT is recorded for path
        // quality and the make-before-break selector can switch immediately.
        // Probe-only ACKs still use the slow-candidate quarantine below; an
        // owned encrypted Request -> ACK is stronger evidence and must not be
        // hidden behind an arbitrary relay cooldown.
        let pair_success = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let was_direct = conn.state == ConnectionState::Direct;
            let previous_endpoint = conn.endpoint;
            let previous_generation = conn.direct_generation;
            let relay_first_required = self.relay_first_required();
            if relay_first_required && conn.relay_first_gate_generation != Some(generation) {
                // Direct validation can complete before the relay supervisor
                // publishes its transport. Arm the gate here as well as at
                // catalog/peer admission so an inbound peer cannot use this
                // ACK to become the first business path.
                conn.relay_first_gate_generation = Some(generation);
                conn.relay_first_gate_started_at = Some(Instant::now());
                self.emit_timeline(
                    "relay_first_gate_armed",
                    Some("relay"),
                    Some("direct_ack_raced_relay_startup"),
                    Some(format!(
                        "peer={node_id} generation={generation} source=direct_ack"
                    )),
                );
            }
            let selected_endpoint = endpoint.or(conn.endpoint);
            let pair_success = selected_endpoint.map(|endpoint| {
                    conn.endpoint = Some(endpoint);
                    if let Some(latency) = validation_latency {
                        conn.mark_candidate_pair_authoritative_success(
                            endpoint,
                            generation,
                            latency,
                            true,
                            local_endpoint,
                        )
                    } else {
                        conn.mark_candidate_pair_success(
                            endpoint,
                            generation,
                            None,
                            true,
                            local_endpoint,
                        )
                    }
                });
            let direct_confirmation_changed = !was_direct
                || previous_endpoint != selected_endpoint
                || previous_generation != generation;
            conn.direct_generation = generation;
            if let Some(latency) = validation_latency {
                conn.direct_health
                    .record_success_with_authoritative_latency(latency);
            } else {
                conn.direct_health.record_success();
            }
            conn.clear_direct_reclaim_window();
            if direct_confirmation_changed {
                // The direct-commit sequence is bumped inside the SAME
                // network-epoch critical section as the state transition, so
                // an outbound punch loop that gates every UDP send on this
                // sequence can never miss a promotion that already committed.
                conn.direct_commit_seq = conn.direct_commit_seq.wrapping_add(1);
                self.bump_direct_commit_seq(node_id);
                conn.record_direct_event(
                    generation,
                    "direct_confirmed",
                    selected_endpoint,
                    selected_endpoint.map(|_| 1),
                    None,
                    format!(
                        "encrypted data path confirmed Direct UDP; direct_commit_seq={}",
                        conn.direct_commit_seq
                    ),
                );
            }
            conn.transition(ConnectionState::Direct);
            // Keep the persisted selector in lock-step with the Direct
            // promotion.  A selector snapshot taken before this ACK may
            // still say Relay, but it can never be written after this commit
            // without observing the newer connection state.
            if let Some(endpoint) = selected_endpoint {
                let mut direct_selection =
                    conn.select_path_for_data(generation, true, relay_first_required);
                if direct_selection.path == Some(NetworkPath::Direct) {
                    direct_selection.path = Some(NetworkPath::Direct);
                    direct_selection.direct_endpoint = Some(endpoint);
                    direct_selection.direct_confirmed = true;
                    direct_selection.reason_code = REASON_PATH_DIRECT_CONFIRMED;
                }
                conn.record_path_selection_event(generation, &direct_selection, local_endpoint);
                conn.last_path_selection = Some(direct_selection);
            }
            if let (Some(endpoint), Some((source, _))) = (selected_endpoint, pair_success) {
                let direct_type = classify_confirmed_direct_endpoint(endpoint, source);
                let local_endpoint_text = format_log_endpoint(local_endpoint);
                if direct_confirmation_changed {
                    info!(
                        event = "candidate_pair_selected",
                        peer_id = %node_id,
                        local_endpoint = %local_endpoint_text,
                        remote_endpoint = %endpoint,
                        candidate_source = ?source,
                        rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                        reason = "encrypted data path confirmed Direct UDP",
                        "candidate_pair_selected peer_id={} remote_endpoint={} reason=encrypted data path confirmed Direct UDP",
                        node_id,
                        endpoint
                    );
                }
                let selection_is_direct = conn
                    .last_path_selection
                    .as_ref()
                    .is_some_and(|selection| selection.path == Some(NetworkPath::Direct));
                if !was_direct && selection_is_direct {
                    info!(
                        event = "direct_path_promoted",
                        peer_id = %node_id,
                        local_endpoint = %local_endpoint_text,
                        remote_endpoint = %endpoint,
                        candidate_source = ?source,
                        rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                        reason = "encrypted data path confirmed Direct UDP",
                        "direct_path_promoted peer_id={} remote_endpoint={} reason=encrypted data path confirmed Direct UDP",
                        node_id,
                        endpoint
                    );
                }
                if direct_confirmation_changed && selection_is_direct {
                    match direct_type {
                        DirectPathType::PublicUdp => info!(
                            event = "public_udp_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "public_udp_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::PeerReflexive => info!(
                            event = "peer_reflexive_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "peer_reflexive_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::Overlay => info!(
                            event = "overlay_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "overlay_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        DirectPathType::Lan => info!(
                            event = "lan_direct_selected",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = ?conn.direct_health.rtt_ewma_ms.or(conn.direct_health.latency_ms),
                            reason = "encrypted data path confirmed Direct UDP",
                            "lan_direct_selected peer_id={} remote_endpoint={}",
                            node_id,
                            endpoint
                        ),
                        _ => {}
                    }
                }
            }
            pair_success
        };
        // Direct validation is a background upgrade, not permission to tear
        // down the relay safety path. Keep the relay heartbeat alive so a
        // later Direct failure can fall back without waiting for a new relay
        // registration. The peer lifecycle/revoke paths still cancel it.
        // A confirmed Direct path supersedes every outstanding validation
        // lease for this peer.  This happens under the same epoch gate as the
        // state transition, so a worker from the just-confirmed generation
        // cannot keep sending requests or leave an ACK expectation behind.
        if let Some(registry) = self.direct_validation_registry.read().await.clone() {
            registry
                .cancel_peer_with_reason(node_id, "direct_confirmed")
                .await;
        }
        // The recovery epoch for this peer is over: Direct is confirmed, so
        // no traversal work may continue under the old plan.
        self.recovery_epoch_end(node_id, "direct_confirmed").await;
        if let Some((source, true)) = pair_success {
            self.record_traversal_success(source).await;
        }
        true
    }

    /// Record that a UDP punch endpoint is reachable. A matched ACK confirms
    /// bidirectional UDP reachability; an inbound punch alone remains provisional.
    pub async fn record_direct_probe_success(&self, node_id: &str, endpoint: SocketAddr) {
        self.record_direct_probe_success_with_local_endpoint(node_id, endpoint, None)
            .await;
    }

    /// Record that a UDP punch endpoint is reachable with the local socket that saw it.
    pub async fn record_direct_probe_success_with_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        local_endpoint: Option<SocketAddr>,
    ) {
        self.record_direct_probe_success_with_latency_and_local_endpoint(
            node_id,
            endpoint,
            None,
            local_endpoint,
        )
        .await;
    }

    /// Record a successful direct-path probe and its measured round-trip time.
    pub async fn record_direct_probe_success_with_latency(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
    ) {
        self.record_direct_probe_success_with_latency_and_local_endpoint(
            node_id, endpoint, latency, None,
        )
        .await;
    }

    /// Record a successful direct-path probe, latency, and local UDP endpoint.
    pub async fn record_direct_probe_success_with_latency_and_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        local_endpoint: Option<SocketAddr>,
    ) {
        let generation = self.current_network_generation().await;
        self.record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            node_id,
            endpoint,
            latency,
            generation,
            local_endpoint,
        )
        .await;
    }

    /// Record a direct-path probe result for a specific local network generation.
    /// Returns false when the result belongs to an old generation and was ignored.
    pub async fn record_direct_probe_success_with_latency_for_generation(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        generation: u64,
    ) -> bool {
        self.record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
            node_id, endpoint, latency, generation, None,
        )
        .await
    }

    /// Record a direct-path probe result for a specific local network generation.
    /// Returns false when the result belongs to an old generation or when a
    /// slow ACK was retained as candidate evidence without starting Direct
    /// validation over a confirmed relay.
    pub async fn record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
        &self,
        node_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
        generation: u64,
        local_endpoint: Option<SocketAddr>,
    ) -> bool {
        if generation != self.current_network_generation().await {
            return false;
        }
        let mut record_ack_feedback = false;
        let retain_relay_for_slow_probe;
        let pair_success = {
            let mut conns = self.connections.write().await;
            let Some(conn) = conns.get_mut(node_id) else {
                return false;
            };
            let ack_confirmed = latency.is_some();
            let slow_probe_retained = ack_confirmed
                && latency.is_some_and(|latency| {
                    duration_millis(latency) >= SLOW_DIRECT_RELAY_VALIDATION_RTT_MS
                })
                && conn.relay_peer_confirmed_for_generation(generation)
                && conn.state != ConnectionState::Direct;
            retain_relay_for_slow_probe = slow_probe_retained;
            let pair_success = if ack_confirmed {
                if slow_probe_retained {
                    Some(conn.mark_candidate_pair_slow_validation(
                        endpoint,
                        generation,
                        latency.expect("slow probe retention requires an RTT"),
                        local_endpoint,
                    ))
                } else {
                    // A probe ACK is only allowed to replace the connection's
                    // current endpoint when it is eligible to become the
                    // active path.  In particular, a slow ACK that is
                    // quarantined behind a confirmed relay is candidate
                    // evidence, not an active-endpoint update.  Writing it to
                    // `conn.endpoint` here would make the ranking code prefer
                    // the very endpoint we just quarantined and would cause
                    // delayed ACKs from other sockets to keep re-validating
                    // the same queue-prone mapping.
                    conn.endpoint = Some(endpoint);
                    Some(conn.mark_candidate_pair_success(
                        endpoint,
                        generation,
                        latency,
                        false,
                        local_endpoint,
                    ))
                }
            } else {
                conn.mark_candidate_pair_probing_with_local_endpoint(
                    endpoint,
                    generation,
                    local_endpoint,
                );
                None
            };
            match latency {
                Some(latency) => {
                    if !slow_probe_retained {
                        conn.direct_health.record_success_with_latency(latency);
                    }
                    if let Some((source, true)) = pair_success {
                        // Matched-ACK feedback: the recovery stage machine
                        // resets to Initial so a live path is never expanded
                        // by a later no-ACK batch.
                        // Do not await it while the process-wide connection
                        // write guard is held.  The recovery ledger is
                        // independent state, and waiting here can block
                        // PeerJoined/PeerAnswer handling for every peer.
                        record_ack_feedback = true;
                        conn.record_direct_event(
                            generation,
                            "probe_ack_received",
                            Some(endpoint),
                            Some(1),
                            None,
                            format!(
                                "received UDP punch ACK from {endpoint} rtt={}ms",
                                duration_millis(latency)
                            ),
                        );
                        let local_endpoint_text = format_log_endpoint(local_endpoint);
                        info!(
                            event = "candidate_pair_probe_succeeded",
                            peer_id = %node_id,
                            local_endpoint = %local_endpoint_text,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms = duration_millis(latency),
                            reason = "received UDP punch ACK",
                            "candidate_pair_probe_succeeded peer_id={} remote_endpoint={} rtt_ms={}",
                            node_id,
                            endpoint,
                            duration_millis(latency)
                        );
                        self.emit_timeline(
                            "candidate_pair_probe_succeeded",
                            Some("direct"),
                            None,
                            Some(format!(
                                "peer={node_id} remote_endpoint={endpoint} rtt_ms={}",
                                duration_millis(latency)
                            )),
                        );
                    }
                    if slow_probe_retained {
                        let rtt_ms = duration_millis(latency);
                        let source = pair_success
                            .map(|(source, _)| source)
                            .unwrap_or_else(|| conn.candidate_source_for_endpoint(endpoint));
                        conn.record_direct_event(
                            generation,
                            "direct_probe_succeeded_relay_retained",
                            Some(endpoint),
                            Some(1),
                            None,
                            format!(
                                "probe ACK was bidirectionally valid but rtt={rtt_ms}ms; retaining confirmed relay and continuing candidate recovery"
                            ),
                        );
                        info!(
                            event = "direct_probe_succeeded_relay_retained",
                            peer_id = %node_id,
                            local_endpoint = ?local_endpoint,
                            remote_endpoint = %endpoint,
                            candidate_source = ?source,
                            rtt_ms,
                            reason_code = REASON_DIRECT_PROBE_SLOW_RELAY_RETAINED,
                            relay_rtt_floor_ms = SLOW_DIRECT_RELAY_VALIDATION_RTT_MS,
                            "slow Direct probe ACK retained confirmed relay"
                        );
                        self.emit_timeline(
                            "direct_probe_succeeded_relay_retained",
                            Some("relay"),
                            Some(REASON_DIRECT_PROBE_SLOW_RELAY_RETAINED),
                            Some(format!(
                                "peer={node_id} generation={generation} remote_endpoint={endpoint} rtt_ms={rtt_ms} relay_rtt_floor_ms={SLOW_DIRECT_RELAY_VALIDATION_RTT_MS}"
                            )),
                        );
                    }
                }
                None => conn.direct_health.record_success(),
            }
            if !ack_confirmed {
                conn.record_direct_event(
                    generation,
                    "inbound_probe_received",
                    Some(endpoint),
                    Some(1),
                    None,
                    format!("received inbound UDP probe from {endpoint}"),
                );
            }
            if conn.state != ConnectionState::Direct
                && matches!(
                    conn.state,
                    ConnectionState::Idle
                        | ConnectionState::Connecting
                        | ConnectionState::FallbackToRelay
                )
            {
                conn.transition(ConnectionState::HolePunching);
            }
            pair_success
        };
        if record_ack_feedback {
            self.record_recovery_ack_feedback(node_id, endpoint).await;
        }
        if let Some((source, true)) = pair_success {
            self.record_traversal_success(source).await;
        }
        // `false` here means that the authenticated probe was valid but must
        // not start encrypted Direct validation: a slow candidate cannot
        // displace a same-generation confirmed relay.  The pair evidence and
        // ACK feedback were recorded above, so the recovery scheduler can
        // continue toward another candidate.
        !retain_relay_for_slow_probe
    }
}
