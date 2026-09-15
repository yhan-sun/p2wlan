//! Relay runtime helpers: default relay inference, candidate assembly, the
//! relay supervisor task, and proactive relay peer validation.
//!
//! Split out of the crate root to keep `lib.rs` focused on daemon orchestration.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::join_all;
use p2pnet_relay::RelayMessage;
use p2pnet_tun::Ipv4Packet;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tokio::time::{interval, sleep};
use tracing::{debug, info, warn};

use crate::control::RelayCatalogEntry;
use crate::dataplane::OutboundPacket;
use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;
use crate::relay::{
    select_relay_with_cooldowns, RelayCandidateConfig, RelaySelectionDiagnostics,
    RelaySelectionOutcome, RelayTicketCache, RelayTransport,
};
#[cfg(test)]
use crate::transport::build_relay_validation_payload;
use crate::transport::{ReceivedEncryptedPacket, WireGuardTransport};

use super::{is_stun_clear_value, unix_time_millis};

mod configuration;
pub(super) use configuration::{
    effective_relay_allow_insecure_plaintext, infer_default_relay_servers,
    relay_candidates_from_sources, udp_observers_from_sources,
};
mod renewal;
#[cfg(test)]
pub(crate) use renewal::relay_renewal_deadline;
use renewal::{
    relay_close_reason_label_from_error, relay_oneshot_wait, relay_renewal_wait,
    spawn_relay_renewal_task_impl, ArmedRelayRenewal,
};
mod peer_validation;
pub(super) use peer_validation::{run_relay_peer_probe_loop, run_relay_peer_validation_loop};

/// Short cooldown after a selected Relay fails at runtime before trying it again.
const RELAY_RUNTIME_FAILURE_COOLDOWN: Duration = Duration::from_secs(10);
const RELAY_ROUTE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const RELAY_ROUTE_STABILITY_SAMPLES: u8 = 2;
/// Confirm relay peer reachability proactively instead of waiting for user traffic.
const RELAY_PEER_VALIDATION_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_PEER_VALIDATION_READY_POLL_INTERVAL: Duration = Duration::from_millis(250);
const RELAY_PEER_VALIDATION_MAX_AGE: Duration = Duration::from_secs(15);

/// Per-command deadline ownership shared by the timeout branch and the relay
/// writer callback. The mutex deliberately spans expectation registration:
/// if the writer wins, timeout waits for registration and can then remove it;
/// if timeout wins, the late-dequeued hook observes `live == false` and cannot
/// register or write. A bare AtomicBool has a Claiming→register race here.
#[derive(Clone, Debug)]
struct RelayWriteBoundaryPermit {
    live: Arc<std::sync::Mutex<bool>>,
}

impl RelayWriteBoundaryPermit {
    fn new() -> Self {
        Self {
            live: Arc::new(std::sync::Mutex::new(true)),
        }
    }

    fn commit(&self, register: impl FnOnce() -> bool) -> bool {
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !*live {
            return false;
        }
        let accepted = register();
        *live = false;
        accepted
    }

    fn revoke(&self) {
        *self
            .live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = false;
    }
}

pub(super) struct RelaySupervisor {
    pub(super) relay_candidates: Vec<RelayCandidateConfig>,
    pub(super) preferred_regions: Vec<String>,
    pub(super) selection_timeout: Duration,
    pub(super) node_id: String,
    pub(super) peers: Arc<PeerManager>,
    pub(super) relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    pub(super) relay_selection: Arc<RwLock<RelaySelectionDiagnostics>>,
    pub(super) inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    /// Android's physical-network callback stream. `None` on desktop, where
    /// the existing stable route monitor remains the authority.
    pub(super) android_network_change_rx: Option<crate::AndroidNetworkChangeReceiver>,
    /// Watch flipped whenever the shared relay transport slot is set/cleared,
    /// so the outbound path can wait event-driven for relay availability.
    pub(super) relay_available_tx: watch::Sender<bool>,
    /// Per-process connection timeline.
    pub(super) timeline: Arc<crate::connection_timeline::ConnectionTimeline>,
    // A2 fields
    pub(super) ticket_cache: Option<Arc<RelayTicketCache>>,
    pub(super) relay_ticket: Option<String>,
    pub(super) allow_insecure_plaintext: bool,
    pub(super) ca_cert_path: Option<String>,
}

/// How long before ticket expiry (unix seconds) the make-before-break renewal
/// connects the replacement.  The server's ticket-expiry close fires exactly
/// at expiry, so renewing well before the deadline leaves a full data-path
/// margin.
const RELAY_TICKET_RENEWAL_MARGIN_SECS: i64 = 60;
/// Retry cadence for a failed renewal fetch.
const RELAY_TICKET_RENEWAL_RETRY: Duration = Duration::from_secs(5);

/// Confirm a kernel-route handover twice before retiring a live Relay TCP
/// connection. Route inspection can be momentarily empty while DHCP updates;
/// empty samples never tear down a healthy connection.
struct RelayRouteMonitor {
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
    async fn supervise_relay_connection<F>(
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

    /// Spawn the inbound drain for one connection generation, returning the
    /// oneshot that reports `(generation, end result)`.
    fn spawn_inbound_task(
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

    /// Record relay-selection diagnostics for a GENUINE end of the CURRENT
    /// connection — the deferred counterpart of the inbound task's close
    /// handling.  The inbound task no longer writes close diagnostics itself,
    /// because a hub newest-wins EOF of a SUPERSEDED connection is expected
    /// and must never count as a failure; only the supervisor, after
    /// classifying the end (current generation, no in-flight renewal that can
    /// resolve it), knows it is real.  Non-close failures (transport errors
    /// without a close reason) keep their original behavior and are not
    /// counted here.
    async fn record_connection_close_diagnostics(&self, result: &Result<()>) {
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

async fn wait_for_android_network_change(
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
type RelayInboundEnd = (u64, Result<()>);

impl RelaySupervisor {
    pub(super) async fn run(self) {
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
fn relay_retry_delay_with_jitter(base: Duration) -> Duration {
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

fn relay_failure_summary(diagnostics: &RelaySelectionDiagnostics) -> String {
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

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// Cadence of the forced-relay probe loop while any peer still needs a relay
/// confirmation.  Fast enough that the first business packet's wait (bounded
/// by `relay_startup_timeout_ms`) is not materially extended by probe latency,
/// and it is kicked event-driven by the outbound actor when a packet actually
/// waits.
const RELAY_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(250);
/// Cadence of re-sending a forced-relay probe to an unconfirmed peer. The
/// first send is event-driven/250ms polled; a lost ACK gets a second chance
/// inside the 1s relay-first target instead of waiting 5s. The token is stable
/// per peer (never overwritten), and the expectation is refreshed every tick,
/// so this only bounds wire sends, not ACK validity.
const RELAY_PROBE_RETRY_INTERVAL: Duration = Duration::from_millis(750);
/// Relay control traffic is not a reason to hold the probe/validation loop (or
/// another peer's control packet) behind a stalled relay writer. If this
/// boundary is reached the encrypted counter is terminal and the relay writer
/// is invalidated; the next attempt allocates a fresh counter from plaintext.
const RELAY_CONTROL_SEND_TIMEOUT: Duration = Duration::from_millis(500);

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) use peer_validation::{send_relay_validation_packet, RelayValidationPacket};

#[cfg(test)]
pub(super) use configuration::relay_spec_is_plaintext;
