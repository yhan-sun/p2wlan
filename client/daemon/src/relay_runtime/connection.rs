use super::*;

/// Time until the renewal deadline: `expiry - margin` (clamped to at least
/// 1s so the renewal task always has a bounded wait and never spins).
pub(crate) fn relay_renewal_deadline(expires_at_unix: i64, now_unix: i64) -> Duration {
    let remaining = expires_at_unix.saturating_sub(now_unix);
    Duration::from_secs(
        remaining
            .saturating_sub(RELAY_TICKET_RENEWAL_MARGIN_SECS)
            .max(1) as u64,
    )
}

/// Confirm a kernel-route handover twice before retiring a live Relay TCP
/// connection. Route inspection can be momentarily empty while DHCP updates;
/// empty samples never tear down a healthy connection.
pub(super) struct RelayRouteMonitor {
    baseline: Vec<String>,
    pending: Option<(Vec<String>, u8)>,
    ticker: tokio::time::Interval,
}

impl RelayRouteMonitor {
    fn new(baseline: Vec<String>) -> Self {
        let mut ticker = interval(RELAY_ROUTE_POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            baseline,
            pending: None,
            ticker,
        }
    }

    fn enabled(&self) -> bool {
        !self.baseline.is_empty()
    }

    fn reset(&mut self, baseline: Vec<String>) {
        self.baseline = baseline;
        self.pending = None;
    }

    fn observe(&mut self, observed: Vec<String>) -> Option<Vec<String>> {
        if observed.is_empty() {
            self.pending = None;
            return None;
        }
        if observed == self.baseline {
            self.pending = None;
            return None;
        }
        match &mut self.pending {
            Some((candidate, samples)) if *candidate == observed => {
                *samples = samples.saturating_add(1);
                if *samples >= RELAY_ROUTE_STABILITY_SAMPLES {
                    self.pending = None;
                    Some(observed)
                } else {
                    None
                }
            }
            _ => {
                self.pending = Some((observed, 1));
                None
            }
        }
    }

    async fn wait_for_change(&mut self) -> Vec<String> {
        loop {
            self.ticker.tick().await;
            let observed =
                tokio::task::spawn_blocking(|| crate::netenv::network_route_signature(&[]))
                    .await
                    .unwrap_or_default();
            if let Some(changed) = self.observe(observed) {
                return changed;
            }
        }
    }
}

impl RelaySupervisor {
    /// Supervise one relay connection through its renewal lifecycle.
    ///
    /// Deterministic handling of the renewal-vs-old-EOF race:
    ///
    /// - Every inbound task is tagged with the connection generation that
    ///   spawned it.  When the relay hub's newest-wins register closes the
    ///   OLD connection after a renewal registered the replacement, the old
    ///   inbound task ends with the OLD generation: that EOF is an expected
    ///   handoff, never a reconnect trigger.
    /// - The renewal result and the old EOF may be ready simultaneously;
    ///   whichever branch the scheduler picks, the outcome is the same: the
    ///   replacement transport is swapped in atomically (with its own ticket
    ///   metadata for the next renewal), the replacement inbound drain is
    ///   started BEFORE the old one is allowed to exit, and an old-generation
    ///   EOF can never abort a successful renewal.  When the old EOF races in
    ///   while its renewal is already connecting, it is held until the
    ///   renewal resolves instead of aborting the handoff; a renewal failure
    ///   then surfaces the held EOF unchanged.
    /// - Renewal tasks carry the generation token their connection was armed
    ///   with and re-check it immediately before connecting; a stale renewal
    ///   of an ended connection (real failure or a newer handoff) aborts and
    ///   can never "newest-wins" over the supervisor's current link.
    /// - Only the CURRENT generation's inbound end (no registered
    ///   replacement) is a real connection failure; its close reason is
    ///   preserved and classified by the caller.  With no ticket (legacy
    ///   relay) the renewal branch stays disarmed, so the end branch is the
    ///   only live one: a bounded select, never a spin.
    ///
    /// Returns the end of the CURRENT connection: `Ok(())` for a clean
    /// server-side close, `Err` for a real transport failure.  Renewal
    /// handoffs never surface here.
    pub(super) async fn supervise_relay_connection<F>(
        &self,
        endpoint: &str,
        current_transport: RelayTransport,
        relay_rx: mpsc::Receiver<RelayMessage>,
        connection_generation: Arc<std::sync::atomic::AtomicU64>,
        mut spawn_renewal: F,
    ) -> Result<()>
    where
        F: FnMut(
            u64,
            RelayTransport,
        )
            -> Pin<Box<dyn std::future::Future<Output = Option<ArmedRelayRenewal>> + Send>>,
    {
        // `generation` is the local label of the connection currently serving;
        // `connection_generation` is the SHARED token the renewal tasks check
        // right before connecting.  Bumping it aborts any still-sleeping or
        // half-connecting renewal of a connection that has since ended, so a
        // stale renewal can never "newest-wins" over the supervisor's current
        // link after a real failure.
        let mut generation: u64 = 0;
        let mut current_transport = current_transport;
        let mut route_monitor =
            RelayRouteMonitor::new(current_transport.route_signature().to_vec());
        let mut inbound_ended =
            self.spawn_inbound_task(generation, current_transport.clone(), relay_rx);
        let mut renewal = spawn_renewal(
            connection_generation.load(std::sync::atomic::Ordering::SeqCst),
            current_transport.clone(),
        )
        .await;
        // An end of the CURRENT connection that arrived while its renewal was
        // already connecting.  This is almost always the hub's newest-wins
        // close of the superseded connection racing the handoff; it is held
        // until the renewal resolves so a successful handoff is never aborted
        // by its own predecessor's EOF.
        let mut pending_current_end: Option<Result<()>> = None;
        let mut renewal_retry_at: Option<tokio::time::Instant> = None;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(renewal_retry_at.unwrap_or_else(tokio::time::Instant::now)), if renewal_retry_at.is_some() => {
                    renewal_retry_at = None;
                    renewal = spawn_renewal(
                        connection_generation.load(std::sync::atomic::Ordering::SeqCst),
                        current_transport.clone(),
                    ).await;
                }
                hint = wait_for_android_network_change(self.android_network_change_rx.clone()), if self.android_network_change_rx.is_some() => {
                    let Some(hint) = hint else {
                        return Err(DaemonError::Relay(
                            "Android network hint channel closed".to_string(),
                        ));
                    };
                    connection_generation.fetch_add(
                        1,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    current_transport.abort_writer();
                    self.timeline.emit(
                        "relay_transport_network_changed",
                        Some("relay"),
                        Some("physical_network_changed"),
                        Some(format!(
                            "endpoint={endpoint} connection_id={} kotlin_network_generation={} network_identity_hash={}",
                            current_transport.connection_id(),
                            hint.kotlin_network_generation,
                            hint.network_identity_hash,
                        )),
                    );
                    return Err(DaemonError::RelayRouteChanged {
                        endpoint: endpoint.to_string(),
                        signature: vec![format!(
                            "android_network_identity_hash={}",
                            hint.network_identity_hash,
                        )],
                    });
                }
                changed = route_monitor.wait_for_change(), if route_monitor.enabled() => {
                    connection_generation.fetch_add(
                        1,
                        std::sync::atomic::Ordering::SeqCst,
                    );
                    current_transport.abort_writer();
                    self.timeline.emit(
                        "relay_transport_route_changed",
                        Some("relay"),
                        Some("network_route_changed"),
                        Some(format!(
                            "endpoint={endpoint} connection_id={} signature={changed:?}",
                            current_transport.connection_id(),
                        )),
                    );
                    return Err(DaemonError::RelayRouteChanged {
                        endpoint: endpoint.to_string(),
                        signature: changed,
                    });
                }
                ended = relay_oneshot_wait(&mut inbound_ended), if inbound_ended.is_some() => {
                    match ended {
                        Some(Ok((ended_generation, result))) => {
                            if ended_generation != generation {
                                // An OLD-generation EOF: the hub closed the
                                // connection this generation superseded during
                                // a renewal handoff.  Expected — not a
                                // reconnect.
                                debug!(
                                    event = "relay_renewal_superseded_close_ignored",
                                    relay_endpoint = %endpoint,
                                    superseded_generation = ended_generation,
                                    current_generation = generation,
                                    "ignored EOF of relay connection generation {} superseded by renewal handoff (current generation {})",
                                    ended_generation,
                                    generation,
                                );
                                inbound_ended = None;
                            } else if renewal.as_ref().is_some_and(|armed| {
                                armed.connecting.load(std::sync::atomic::Ordering::SeqCst)
                            }) {
                                // The renewal is already connecting its
                                // replacement: this EOF is the handoff's own
                                // superseded-close racing in.  Hold it; the
                                // renewal result is imminent.
                                pending_current_end = Some(result);
                                inbound_ended = None;
                            } else {
                                // No renewal in flight, or it is still sleeping
                                // toward its deadline: a genuine end.  Abort
                                // any orphaned renewal before leaving, and
                                // attribute the close diagnostics NOW that it
                                // is classified as a real failure (a superseded
                                // connection's expected EOF never reaches
                                // here).
                                connection_generation.fetch_add(
                                    1,
                                    std::sync::atomic::Ordering::SeqCst,
                                );
                                current_transport.abort_writer();
                                self.record_connection_close_diagnostics(&result)
                                    .await;
                                return result;
                            }
                        }
                        Some(Err(_)) | None => {
                            // The inbound task vanished without a classified
                            // close.  Hold a synthetic end while a renewal is
                            // connecting; otherwise this is a real failure.
                            if renewal.as_ref().is_some_and(|armed| {
                                armed.connecting.load(std::sync::atomic::Ordering::SeqCst)
                            }) {
                                pending_current_end = Some(Err(DaemonError::Relay(
                                    "relay inbound task ended without a classified close"
                                        .to_string(),
                                )));
                                inbound_ended = None;
                            } else {
                                connection_generation.fetch_add(
                                    1,
                                    std::sync::atomic::Ordering::SeqCst,
                                );
                                current_transport.abort_writer();
                                return Err(DaemonError::Relay(
                                    "relay inbound task ended without a classified close"
                                        .to_string(),
                                ));
                            }
                        }
                    }
                }
                renewal_result = relay_renewal_wait(&mut renewal), if renewal.is_some() => {
                    let result = renewal_result;
                    match result {
                        Some(Ok(Some((new_transport, new_rx)))) => {
                            let (new_transport, new_rx) = current_transport
                                .handoff_rendezvous(new_transport, new_rx).await;
                            // The replacement is connected AND its ticket
                            // metadata (including the new expiry) is attached:
                            // swap it in, start its inbound drain, and only
                            // then is the old connection allowed to exit.
                            let new_endpoint = new_transport.endpoint().to_string();
                            generation = generation.wrapping_add(1);
                            let new_expiry = new_transport.ticket_expiry();
                            let ttl_secs = new_expiry
                                .as_ref()
                                .map(|(_, _, expires_at_unix)| {
                                    let now_unix = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs() as i64;
                                    expires_at_unix.saturating_sub(now_unix).max(0)
                                })
                                .unwrap_or(0);
                            info!(
                                event = "relay_renewal_handoff_completed",
                                relay_endpoint = %endpoint,
                                replacement_endpoint = %new_endpoint,
                                swap_generation = generation,
                                ticket_ttl_secs = ttl_secs,
                                audience = ?new_expiry.as_ref().map(|(audience, _, _)| audience),
                                "relay_renewal_handoff_completed relay_endpoint={} replacement_endpoint={} swap_generation={} ticket_ttl_secs={}",
                                endpoint,
                                new_endpoint,
                                generation,
                                ttl_secs,
                            );
                            connection_generation.fetch_add(
                                1,
                                std::sync::atomic::Ordering::SeqCst,
                            );
                            *self.relay_transport.write().await = Some(new_transport.clone());
                            // Publish the replacement first, synchronously
                            // retire callbacks queued by the old writer, then
                            // clear the old incarnation's expectations and
                            // confirmations. Retirement holds the same mutex
                            // as boundary registration: an old hook either is
                            // rejected, or finishes registering before the
                            // exact cancellation below. Network and peer
                            // generations alone cannot close this race because
                            // a same-endpoint renewal changes neither.
                            current_transport.retire_write_boundaries();
                            self.peers
                                .cancel_relay_probe_expectations_for_transport(
                                    endpoint,
                                    current_transport.connection_id(),
                                );
                            self.peers
                                .invalidate_relay_transport_for_connection(
                                    endpoint,
                                    Some(current_transport.connection_id()),
                                    "relay_transport_replaced",
                                    format!(
                                        "relay connection {} replaced by {}",
                                        current_transport.connection_id(),
                                        new_transport.connection_id()
                                    ),
                                )
                                .await;
                            let _ = self.relay_available_tx.send(true);
                            self.timeline.emit(
                                "relay_transport_connected",
                                Some("relay"),
                                None,
                                Some(format!(
                                    "region={} endpoint={} renewal_handoff=true",
                                    new_transport.region(),
                                    new_transport.endpoint()
                                )),
                            );
                            inbound_ended = self.spawn_inbound_task(
                                generation,
                                new_transport.clone(),
                                new_rx,
                            );
                            current_transport = new_transport;
                            route_monitor.reset(current_transport.route_signature().to_vec());
                            pending_current_end = None;
                            renewal = spawn_renewal(
                                connection_generation.load(std::sync::atomic::Ordering::SeqCst),
                                current_transport.clone(),
                            )
                            .await;
                        }
                        Some(Ok(None)) => {
                            // Renewal fetch/connect failed: the current
                            // connection keeps serving until its REAL expiry,
                            // then the caller's bounded reconnect path runs.
                            warn!(
                                event = "relay_renewal_failed",
                                relay_endpoint = %endpoint,
                                generation = generation,
                                "relay ticket renewal failed; the current connection stays until expiry and the supervisor reconnects if needed",
                            );
                            if let Some(ended) = pending_current_end.take() {
                                // The renewal failed and the connection really
                                // ended: the held close is now confirmed as a
                                // genuine failure, so attribute it.
                                connection_generation.fetch_add(
                                    1,
                                    std::sync::atomic::Ordering::SeqCst,
                                );
                                current_transport.abort_writer();
                                self.record_connection_close_diagnostics(&ended).await;
                                return ended;
                            }
                            renewal = None;
                            renewal_retry_at = Some(tokio::time::Instant::now() + RELAY_TICKET_RENEWAL_RETRY);
                        }
                        Some(Err(_)) | None => {
                            // The renewal task was dropped without a result;
                            // the current connection stays and a new renewal
                            // is armed from the current deadline.
                            if let Some(ended) = pending_current_end.take() {
                                // Same attribution: the renewal is gone and
                                // the connection really ended, so the held
                                // close is a genuine failure.
                                connection_generation.fetch_add(
                                    1,
                                    std::sync::atomic::Ordering::SeqCst,
                                );
                                current_transport.abort_writer();
                                self.record_connection_close_diagnostics(&ended).await;
                                return ended;
                            }
                            renewal = None;
                            renewal_retry_at = Some(tokio::time::Instant::now() + RELAY_TICKET_RENEWAL_RETRY);
                        }
                    }
                }
            }
        }
    }
}

impl RelaySupervisor {
    /// Spawn the inbound drain for one connection generation, returning the
    /// oneshot that reports `(generation, end result)`.
    pub(super) fn spawn_inbound_task(
        &self,
        generation: u64,
        transport: RelayTransport,
        relay_rx: mpsc::Receiver<RelayMessage>,
    ) -> Option<oneshot::Receiver<RelayInboundEnd>> {
        let (ended_tx, ended_rx) = oneshot::channel();
        let inbound_tx = self.inbound_tx.clone();
        let diags = self.relay_selection.clone();
        tokio::spawn(async move {
            let result = transport
                .run_inbound(relay_rx, inbound_tx, Some(diags))
                .await;
            let _ = ended_tx.send((generation, result));
        });
        Some(ended_rx)
    }
}

impl RelaySupervisor {
    /// Record relay-selection diagnostics for a GENUINE end of the CURRENT
    /// connection — the deferred counterpart of the inbound task's close
    /// handling.  The inbound task no longer writes close diagnostics itself,
    /// because a hub newest-wins EOF of a SUPERSEDED connection is expected
    /// and must never count as a failure; only the supervisor, after
    /// classifying the end (current generation, no in-flight renewal that can
    /// resolve it), knows it is real.  Non-close failures (transport errors
    /// without a close reason) keep their original behavior and are not
    /// counted here.
    pub(super) async fn record_connection_close_diagnostics(&self, result: &Result<()>) {
        let Some(label) = result
            .as_ref()
            .err()
            .and_then(relay_close_reason_label_from_error)
        else {
            return;
        };
        let mut d = self.relay_selection.write().await;
        d.selected_error_count = d.selected_error_count.saturating_add(1);
        d.last_error = Some(format!("relay connection closed: reason={label}"));
        d.last_error_code = Some(label);
    }
}

pub(super) async fn wait_for_android_network_change(
    receiver: Option<crate::AndroidNetworkChangeReceiver>,
) -> Option<crate::AndroidNetworkChangeHint> {
    let receiver = receiver?;
    let mut receiver = receiver.lock().await;
    loop {
        match receiver.recv().await {
            Ok(hint) => return Some(hint),
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
            Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
        }
    }
}

/// End signal of one relay inbound drain: `(connection generation, result)`.
pub(super) type RelayInboundEnd = (u64, Result<()>);

/// Result of a renewal attempt: the replacement transport (with its new
/// ticket metadata attached) plus its inbound receiver.
pub(super) type RelayRenewalResult = Option<(RelayTransport, mpsc::Receiver<RelayMessage>)>;

/// An armed make-before-break renewal.
pub(super) struct ArmedRelayRenewal {
    /// Result of the renewal task (awaited BY REFERENCE when the select branch
    /// polls it, so an un-selected branch future never consumes the receiver).
    result: Option<oneshot::Receiver<RelayRenewalResult>>,
    /// Set by the renewal task immediately BEFORE it connects the replacement
    /// transport.  The supervisor uses it to tell a genuine connection end
    /// apart from the hub's newest-wins close of the superseded connection:
    /// an EOF that arrives while the renewal is already connecting is held
    /// until the renewal resolves instead of aborting a successful handoff.
    connecting: Arc<std::sync::atomic::AtomicBool>,
    /// Abort the detached ticket-fetch/connect task when the supervisor moves
    /// to a new network generation or drops the renewal for any other reason.
    /// Without this handle a route change could leave a stale task running
    /// long enough to register an orphaned newest-wins relay connection.
    abort_handle: Option<tokio::task::AbortHandle>,
}

impl Drop for ArmedRelayRenewal {
    fn drop(&mut self) {
        if let Some(abort_handle) = self.abort_handle.take() {
            abort_handle.abort();
        }
    }
}

/// Await an optional inbound-end oneshot receiver (used inside `tokio::select!`
/// where the branch must be a future): `None` when no receiver is armed.
pub(super) async fn relay_oneshot_wait(
    rx: &mut Option<oneshot::Receiver<RelayInboundEnd>>,
) -> Option<std::result::Result<RelayInboundEnd, oneshot::error::RecvError>> {
    match rx {
        Some(receiver) => Some(receiver.await),
        None => None,
    }
}

/// Extract the close-reason label from a transport-close error produced by
/// [`RelayTransport::run_inbound`] for `RelayMessage::Closed` (the message
/// format is `relay {endpoint} connection closed; reason={label}`), or `None`
/// for any other failure.  The supervisor uses this to attribute the deferred
/// close diagnostics only to GENUINE ends of the current connection.
pub(super) fn relay_close_reason_label_from_error(error: &DaemonError) -> Option<String> {
    let message = error.to_string();
    let marker = "closed; reason=";
    let label = message
        .rfind(marker)
        .map(|idx| message[idx + marker.len()..].trim())
        .filter(|label| !label.is_empty())?;
    Some(label.to_string())
}

/// Await the armed renewal result (see [`ArmedRelayRenewal`]) by reference,
/// without taking the receiver out of the armed struct.  `tokio::select!` may
/// poll this branch future and then drop it un-selected when another branch
/// (e.g. an inbound EOF) wins the same round; taking the receiver at poll time
/// would drop the pending renewal result and leave `armed.result` consumed,
/// tripping the caller's next round.  Awaiting by reference means a dropped
/// branch future loses nothing and the receiver stays re-pollable.
pub(super) async fn relay_renewal_wait(
    renewal: &mut Option<ArmedRelayRenewal>,
) -> Option<std::result::Result<RelayRenewalResult, oneshot::error::RecvError>> {
    match renewal {
        Some(armed) => {
            let receiver = armed.result.as_mut().expect("renewal result missing");
            Some(receiver.await)
        }
        None => None,
    }
}

/// Implementation of the make-before-break renewal task.  A free function so
/// the supervisor can hand a `'static`-captured closure (cloned configuration,
/// no `&self` borrow) to the generation-tagged connection supervisor.
///
/// The task sleeps until `expiry - margin`, then — after verifying that its
/// connection generation is still the current one — fetches a fresh ticket and
/// connects the replacement transport CONCURRENTLY with the current
/// connection's inbound drain, so the swap (which the caller performs
/// atomically) never produces a data-path gap.  A fetch or connect failure
/// sends `None` and leaves the current connection untouched; the supervisor
/// then falls back to its existing reconnect path at expiry.
///
/// The replacement transport carries the NEW ticket metadata (audience,
/// region, expires-at) attached before it is returned, so the next renewal is
/// scheduled from the replacement's own deadline instead of being lost after
/// the first swap.
///
/// Returns `None` when the connection has no ticket (legacy relay).
#[allow(clippy::too_many_arguments)]
pub(super) async fn spawn_relay_renewal_task_impl(
    ticket_cache: Option<Arc<RelayTicketCache>>,
    node_id: String,
    peers: Arc<PeerManager>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
    generation_token: Arc<std::sync::atomic::AtomicU64>,
    expected_generation: u64,
    transport: RelayTransport,
) -> Option<ArmedRelayRenewal> {
    let (audience, region, expires_at_unix) = transport.ticket_expiry()?;
    let ticket_cache = ticket_cache?;
    let endpoint = transport.endpoint().to_string();
    let region = region.clone();
    let (tx, rx) = oneshot::channel();
    let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let connecting_task = connecting.clone();
    let task = tokio::spawn(async move {
        // Sleep until the renewal deadline (expiry - margin), re-checking
        // in bounded steps so the wait always ends before the server's
        // expiry close.
        loop {
            let now_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let step = relay_renewal_deadline(expires_at_unix, now_unix);
            if step <= RELAY_TICKET_RENEWAL_RETRY {
                break;
            }
            sleep(RELAY_TICKET_RENEWAL_RETRY).await;
        }
        // The connection this renewal belongs to may have ended (a real
        // failure or a superseding handoff) while the renewal was sleeping.
        // Abort instead of registering an orphaned replacement that would
        // "newest-wins" over the supervisor's current link.
        if generation_token.load(std::sync::atomic::Ordering::SeqCst) != expected_generation {
            let _ = tx.send(None);
            return;
        }
        connecting_task.store(true, std::sync::atomic::Ordering::SeqCst);
        // Fetch a fresh ticket and connect the replacement; the caller
        // swaps it in only after this succeeded, so the old connection
        // keeps serving until the new one is ready.  The replacement
        // keeps the ticket expiry metadata attached so the NEXT renewal
        // is scheduled from the new deadline.
        let result = async {
            let (ticket, expires_at) =
                ticket_cache.refresh_ticket(&audience, &region).await.ok()?;
            if generation_token.load(std::sync::atomic::Ordering::SeqCst) != expected_generation {
                return None;
            }
            let (transport, relay_rx) = RelayTransport::connect_secure(
                &endpoint,
                &region,
                &node_id,
                peers,
                Some(ticket),
                allow_insecure_plaintext,
                ca_cert_path,
            )
            .await
            .ok()?;
            if generation_token.load(std::sync::atomic::Ordering::SeqCst) != expected_generation {
                transport.abort_writer();
                return None;
            }
            Some((
                transport.with_ticket_metadata(&audience, &region, expires_at),
                relay_rx,
            ))
        }
        .await;
        let _ = tx.send(result);
    });
    Some(ArmedRelayRenewal {
        result: Some(rx),
        connecting,
        abort_handle: Some(task.abort_handle()),
    })
}

#[cfg(test)]
#[path = "tests/connection.rs"]
mod tests;
