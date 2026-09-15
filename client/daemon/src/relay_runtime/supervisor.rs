use super::*;

impl RelaySupervisor {
    pub(crate) async fn run(self) {
        let mut retry_delay = Duration::from_millis(100);
        let max_retry_delay = Duration::from_secs(30);
        let mut cooldowns: HashMap<String, Instant> = HashMap::new();
        loop {
            let now = Instant::now();
            cooldowns.retain(|_, until| *until > now);

            self.timeline.emit(
                "relay_selection_started",
                None,
                None,
                Some(format!("candidates={}", self.relay_candidates.len())),
            );

            let RelaySelectionOutcome {
                transport,
                relay_rx,
                diagnostics,
            } = select_relay_with_cooldowns(
                &self.relay_candidates,
                &self.preferred_regions,
                self.selection_timeout,
                &self.node_id,
                self.peers.clone(),
                self.ticket_cache.clone(),
                self.relay_ticket.clone(),
                self.allow_insecure_plaintext,
                self.ca_cert_path.clone(),
                &cooldowns,
            )
            .await;
            let permanent_auth = diagnostics
                .candidates
                .iter()
                .any(|candidate| candidate.error_code.as_deref() == Some("permanent_auth"));
            let failure_summary = relay_failure_summary(&diagnostics);
            *self.relay_selection.write().await = diagnostics;

            if let (Some(relay), Some(relay_rx)) = (transport, relay_rx) {
                info!(
                    "Selected relay region {} at {} ({} ms connect latency)",
                    relay.region(),
                    relay.endpoint(),
                    relay.connect_latency_ms()
                );
                *self.relay_transport.write().await = Some(relay.clone());
                // Flip the availability watch BEFORE the first packet waiter
                // polls, so the outbound path wakes event-driven.
                let _ = self.relay_available_tx.send(true);
                self.timeline.emit(
                    "relay_transport_connected",
                    Some("relay"),
                    None,
                    Some(format!(
                        "region={} endpoint={} connect_latency_ms={}",
                        relay.region(),
                        relay.endpoint(),
                        relay.connect_latency_ms()
                    )),
                );
                retry_delay = Duration::from_millis(100);

                let endpoint = relay.endpoint().to_string();
                // The proactive ticket renewal runs make-before-break: a
                // replacement connection with a fresh ticket is established
                // BEFORE the old ticket expires, and the swap is atomic
                // (relay_transport is replaced, the hub's newest-wins register
                // closes the old connection).  The inbound drain runs in a
                // background task so a renewal swap never interrupts it: the
                // OLD connection keeps draining until the hub closes it, so
                // there is no data-path gap.  A renewal failure leaves the
                // current connection untouched and the supervisor falls back
                // to the existing reconnect path.
                //
                // The whole lifecycle is generation-tagged so the old EOF
                // that the hub sends after a successful renewal can never be
                // misclassified as a connection failure.
                let renewal_ticket_cache = self.ticket_cache.clone();
                let renewal_node_id = self.node_id.clone();
                let renewal_peers = self.peers.clone();
                let renewal_allow_insecure = self.allow_insecure_plaintext;
                let renewal_ca_cert_path = self.ca_cert_path.clone();
                let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
                let ended = self
                    .supervise_relay_connection(
                        &endpoint,
                        relay,
                        relay_rx,
                        connection_generation.clone(),
                        move |expected_generation, transport| {
                            // Re-arm the next renewal from the (possibly
                            // swapped) connection's own ticket deadline,
                            // bound to the current generation so a stale
                            // renewal can never register over a newer link.
                            Box::pin(spawn_relay_renewal_task_impl(
                                renewal_ticket_cache.clone(),
                                renewal_node_id.clone(),
                                renewal_peers.clone(),
                                renewal_allow_insecure,
                                renewal_ca_cert_path.clone(),
                                connection_generation.clone(),
                                expected_generation,
                                transport,
                            ))
                        },
                    )
                    .await;
                *self.relay_transport.write().await = None;
                let _ = self.relay_available_tx.send(false);
                let (peer_failure_code, peer_failure_reason) = match &ended {
                    Ok(()) => (
                        "relay_transport_closed",
                        format!("relay {endpoint} transport closed"),
                    ),
                    Err(error) => (
                        "relay_transport_failed",
                        format!("relay {endpoint} transport failed: {error}"),
                    ),
                };
                self.timeline.emit(
                    if ended.is_ok() {
                        "relay_transport_closed"
                    } else {
                        "relay_transport_failed"
                    },
                    Some("relay"),
                    if ended.is_ok() {
                        Some("relay_transport_closed")
                    } else {
                        Some("relay_transport_failed")
                    },
                    Some(peer_failure_reason.clone()),
                );
                self.peers
                    .invalidate_relay_transport(&endpoint, peer_failure_code, peer_failure_reason)
                    .await;

                let route_changed = matches!(&ended, Err(DaemonError::RelayRouteChanged { .. }));
                let should_cooldown = self.relay_candidates.len() > 1 && !route_changed;
                let cooldown_ms = duration_millis(RELAY_RUNTIME_FAILURE_COOLDOWN);
                if should_cooldown {
                    cooldowns.insert(
                        endpoint.clone(),
                        Instant::now() + RELAY_RUNTIME_FAILURE_COOLDOWN,
                    );
                }

                let (reason, fallback_code) = match (ended, should_cooldown) {
                    (Err(DaemonError::RelayRouteChanged { .. }), _) => (
                        format!("local network route changed; reconnecting relay {endpoint}"),
                        "network_route_changed",
                    ),
                    (Ok(()), true) => (
                        format!(
                            "relay {endpoint} disconnected; cooling down for {cooldown_ms} ms before reselection"
                        ),
                        "runtime_disconnected",
                    ),
                    (Ok(()), false) => (
                        format!("relay {endpoint} disconnected; reconnecting"),
                        "runtime_disconnected",
                    ),
                    (Err(error), true) => (
                        format!(
                            "relay {endpoint} failed: {error}; cooling down for {cooldown_ms} ms before reselection"
                        ),
                        "runtime_failed",
                    ),
                    (Err(error), false) => (
                        format!("relay {endpoint} failed: {error}; reconnecting"),
                        "runtime_failed",
                    ),
                };

                let mut diagnostics = self.relay_selection.write().await;
                diagnostics.last_error = Some(reason.clone());
                if diagnostics.last_error_code.is_none() {
                    diagnostics.last_error_code = Some(fallback_code.to_string());
                }
                if let Some(candidate) = diagnostics
                    .candidates
                    .iter_mut()
                    .find(|candidate| candidate.endpoint == endpoint)
                {
                    if should_cooldown {
                        candidate.cooldown_remaining_ms = Some(cooldown_ms);
                        candidate.error = Some(format!(
                            "relay runtime failure; cooling down for {cooldown_ms} ms"
                        ));
                    } else {
                        candidate.error = Some("relay runtime failure; reconnecting".to_string());
                    }
                    candidate.error_code = Some(fallback_code.to_string());
                }
                drop(diagnostics);
                warn!("{reason}");
            } else {
                *self.relay_transport.write().await = None;
                let _ = self.relay_available_tx.send(false);
                if permanent_auth {
                    retry_delay = max_retry_delay;
                }
                warn!(
                    "No configured relay candidate was reachable ({failure_summary}); retrying in {:?}",
                    retry_delay
                );
            }

            // Bounded exponential backoff with full-range jitter: every retry
            // sleeps base + U(0, base) so multiple nodes that fail together
            // (e.g. a relay-side close of many connections) do not reconnect
            // synchronously in lockstep.
            let jittered = relay_retry_delay_with_jitter(retry_delay);
            debug!(
                "Relay supervisor sleeping {jittered:?} before the next selection attempt (base={retry_delay:?})"
            );
            sleep(jittered).await;
            retry_delay = retry_delay.saturating_mul(2).min(max_retry_delay);
        }
    }
}

/// Bounded exponential backoff with full jitter.
///
/// Returns a delay in `[base, 2*base)` (bounded by the caller's cap applied
/// to `base` before the jitter is added).  The jitter range equals the base,
/// so two nodes that fail at the same instant spread their retries over one
/// full backoff interval instead of reconnecting in lockstep.
pub(super) fn relay_retry_delay_with_jitter(base: Duration) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let base_ms = base.as_millis().min(u64::MAX as u128) as u64;
    if base_ms == 0 {
        return Duration::from_millis(1);
    }
    use rand::Rng;
    // The jitter is drawn from [0, base_ms) so the delay stays strictly
    // below 2*base (the `..=` variant could yield exactly base_ms and the
    // caller's bounds would be violated).
    let jitter_ms = rand::thread_rng().gen_range(0..base_ms);
    Duration::from_millis(base_ms.saturating_add(jitter_ms))
}

pub(super) fn relay_failure_summary(diagnostics: &RelaySelectionDiagnostics) -> String {
    if diagnostics.candidates.is_empty() {
        return diagnostics
            .last_error
            .clone()
            .unwrap_or_else(|| "no relay candidates configured".to_string());
    }

    diagnostics
        .candidates
        .iter()
        .find(|candidate| candidate.error.is_some() || candidate.error_code.is_some())
        .map(|candidate| {
            let code = candidate.error_code.as_deref().unwrap_or("unknown_error");
            let error = candidate.error.as_deref().unwrap_or("no detail");
            format!("{}: {code}: {error}", candidate.endpoint)
        })
        .or_else(|| diagnostics.last_error.clone())
        .unwrap_or_else(|| "no candidate failure detail".to_string())
}

pub(super) fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}
