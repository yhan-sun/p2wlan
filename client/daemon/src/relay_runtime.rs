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
use crate::transport::{
    build_relay_validation_payload, ReceivedEncryptedPacket, WireGuardTransport,
};

use super::{is_stun_clear_value, unix_time_millis};

/// Short cooldown after a selected Relay fails at runtime before trying it again.
const RELAY_RUNTIME_FAILURE_COOLDOWN: Duration = Duration::from_secs(10);
/// Confirm relay peer reachability proactively instead of waiting for user traffic.
const RELAY_PEER_VALIDATION_INTERVAL: Duration = Duration::from_secs(5);
const RELAY_PEER_VALIDATION_READY_POLL_INTERVAL: Duration = Duration::from_millis(250);
const RELAY_PEER_VALIDATION_MAX_AGE: Duration = Duration::from_secs(15);

pub(super) fn infer_default_relay_servers(control_server_url: &str) -> Vec<String> {
    if std::env::var("P2WLAN_DISABLE_DEFAULT_RELAY").as_deref() == Ok("1") {
        return Vec::new();
    }
    if let Ok(configured) = std::env::var("P2WLAN_DEFAULT_RELAY") {
        return configured
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect();
    }

    let Some(host) = control_server_host(control_server_url) else {
        return Vec::new();
    };
    let normalized = host.trim_matches(['[', ']']);
    if normalized.is_empty()
        || normalized.eq_ignore_ascii_case("localhost")
        || normalized.eq_ignore_ascii_case("ctrl.test")
        || normalized.ends_with(".test")
        || normalized == "127.0.0.1"
        || normalized == "::1"
    {
        return Vec::new();
    }

    let endpoint = if host.starts_with('[') {
        format!("{host}:18081")
    } else if host.contains(':') {
        format!("[{host}]:18081")
    } else {
        format!("{host}:18081")
    };
    vec![format!("default@tcp://{endpoint}")]
}

pub(super) fn effective_relay_allow_insecure_plaintext(
    control_server_url: &str,
    relay_catalog: &[RelayCatalogEntry],
    relay_servers: &[String],
    configured: bool,
) -> bool {
    if configured {
        return true;
    }

    if !control_server_uses_plaintext_http(control_server_url) {
        return false;
    }

    if !relay_catalog.is_empty() {
        return relay_catalog
            .iter()
            .any(|entry| relay_spec_is_plaintext(&entry.endpoint));
    }

    relay_servers
        .iter()
        .any(|server| relay_spec_is_plaintext(server))
}

fn control_server_uses_plaintext_http(control_server_url: &str) -> bool {
    control_server_url
        .trim_start()
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
}

pub(super) fn relay_spec_is_plaintext(spec: &str) -> bool {
    let endpoint = spec
        .trim()
        .split_once('@')
        .map(|(_, endpoint)| endpoint)
        .unwrap_or_else(|| spec.trim())
        .trim();
    !endpoint.is_empty()
        && !endpoint
            .get(..6)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("tls://"))
}

fn control_server_host(control_server_url: &str) -> Option<String> {
    let trimmed = control_server_url.trim();
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let authority = without_scheme.split('/').next()?.split('@').next_back()?;
    if authority.starts_with('[') {
        let end = authority.find(']')?;
        return Some(authority[..=end].to_string());
    }
    authority
        .split(':')
        .next()
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToString::to_string)
}

pub(super) fn relay_candidates_from_sources(
    relay_catalog: &[RelayCatalogEntry],
    relay_servers: &[String],
) -> Vec<RelayCandidateConfig> {
    if !relay_catalog.is_empty() {
        return relay_catalog
            .iter()
            .map(|entry| {
                RelayCandidateConfig::catalog(
                    entry.region.clone(),
                    entry.audience.clone(),
                    entry.endpoint.clone(),
                )
            })
            .collect();
    }

    relay_servers
        .iter()
        .cloned()
        .map(RelayCandidateConfig::legacy)
        .collect()
}

pub(super) fn udp_observers_from_sources(
    relay_catalog: &[RelayCatalogEntry],
    configured_observers: &[String],
) -> Vec<String> {
    let configured = configured_observers
        .iter()
        .map(|observer| observer.trim())
        .filter(|observer| !observer.is_empty())
        .collect::<Vec<_>>();
    if configured
        .iter()
        .any(|observer| is_stun_clear_value(observer))
    {
        return configured.into_iter().map(ToString::to_string).collect();
    }

    let mut observers = Vec::new();
    for observer in configured {
        push_unique_udp_observer(&mut observers, observer);
    }
    for entry in relay_catalog {
        if let Some(observer) = entry.udp_observer_endpoint.as_deref() {
            push_unique_udp_observer(&mut observers, observer);
        }
        for observer in &entry.udp_observer_endpoints {
            push_unique_udp_observer(&mut observers, observer);
        }
    }
    observers
}

fn push_unique_udp_observer(observers: &mut Vec<String>, observer: &str) {
    let observer = observer
        .trim()
        .strip_prefix("udp://")
        .unwrap_or_else(|| observer.trim())
        .trim();
    if observer.is_empty() {
        return;
    }
    if !observers.iter().any(|existing| existing == observer) {
        observers.push(observer.to_string());
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
        loop {
            tokio::select! {
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
                                self.record_connection_close_diagnostics(&ended).await;
                                return ended;
                            }
                            renewal = spawn_renewal(
                                connection_generation.load(std::sync::atomic::Ordering::SeqCst),
                                current_transport.clone(),
                            )
                            .await;
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
                                self.record_connection_close_diagnostics(&ended).await;
                                return ended;
                            }
                            renewal = spawn_renewal(
                                connection_generation.load(std::sync::atomic::Ordering::SeqCst),
                                current_transport.clone(),
                            )
                            .await;
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

/// End signal of one relay inbound drain: `(connection generation, result)`.
type RelayInboundEnd = (u64, Result<()>);

/// Result of a renewal attempt: the replacement transport (with its new
/// ticket metadata attached) plus its inbound receiver.
type RelayRenewalResult = Option<(RelayTransport, mpsc::Receiver<RelayMessage>)>;

/// An armed make-before-break renewal.
struct ArmedRelayRenewal {
    /// Result of the renewal task (awaited BY REFERENCE when the select branch
    /// polls it, so an un-selected branch future never consumes the receiver).
    result: Option<oneshot::Receiver<RelayRenewalResult>>,
    /// Set by the renewal task immediately BEFORE it connects the replacement
    /// transport.  The supervisor uses it to tell a genuine connection end
    /// apart from the hub's newest-wins close of the superseded connection:
    /// an EOF that arrives while the renewal is already connecting is held
    /// until the renewal resolves instead of aborting a successful handoff.
    connecting: Arc<std::sync::atomic::AtomicBool>,
}

/// Await an optional inbound-end oneshot receiver (used inside `tokio::select!`
/// where the branch must be a future): `None` when no receiver is armed.
async fn relay_oneshot_wait(
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
fn relay_close_reason_label_from_error(error: &DaemonError) -> Option<String> {
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
async fn relay_renewal_wait(
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
async fn spawn_relay_renewal_task_impl(
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
    tokio::spawn(async move {
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
    })
}

impl RelaySupervisor {
    pub(super) async fn run(self) {
        let mut retry_delay = Duration::from_secs(1);
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
                retry_delay = Duration::from_secs(1);

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

                let should_cooldown = self.relay_candidates.len() > 1;
                let cooldown_ms = duration_millis(RELAY_RUNTIME_FAILURE_COOLDOWN);
                if should_cooldown {
                    cooldowns.insert(
                        endpoint.clone(),
                        Instant::now() + RELAY_RUNTIME_FAILURE_COOLDOWN,
                    );
                }

                let (reason, fallback_code) = match (ended, should_cooldown) {
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
                    "No configured relay candidate was reachable ({failure_summary}); retrying in {} seconds",
                    retry_delay.as_secs()
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

pub(super) async fn run_relay_peer_validation_loop(
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    local_virtual_ip: String,
) {
    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!("Skipping relay peer validation; local virtual IP '{local_virtual_ip}' is not IPv4");
        return;
    };
    let mut ticker = interval(RELAY_PEER_VALIDATION_READY_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_validation_at: Option<Instant> = None;
    let mut last_relay_endpoint: Option<String> = None;

    loop {
        ticker.tick().await;
        let Some(relay) = relay_transport.read().await.clone() else {
            last_relay_endpoint = None;
            continue;
        };
        let relay_endpoint = relay.endpoint().to_string();
        let relay_changed = last_relay_endpoint.as_deref() != Some(relay_endpoint.as_str());
        if !relay_changed
            && last_validation_at.is_some_and(|at| at.elapsed() < RELAY_PEER_VALIDATION_INTERVAL)
        {
            continue;
        }

        let targets = peers
            .relay_validation_targets(RELAY_PEER_VALIDATION_MAX_AGE)
            .await;
        if targets.is_empty() {
            last_relay_endpoint = Some(relay_endpoint);
            continue;
        }
        last_relay_endpoint = Some(relay_endpoint.clone());

        let validation_id = unix_time_millis() as u16;
        let mut sends = Vec::new();
        for (sequence, (peer_id, peer_virtual_ip)) in targets.into_iter().enumerate() {
            let Ok(peer_ip) = peer_virtual_ip.parse::<Ipv4Addr>() else {
                debug!(
                    "Skipping relay peer validation for {peer_id}; peer virtual IP '{peer_virtual_ip}' is not IPv4"
                );
                continue;
            };
            let send_transport = transport.clone();
            let send_relay = relay.clone();
            let send_peer_id = peer_id;
            let send_peer_virtual_ip = peer_virtual_ip;
            let send_sequence = sequence as u16;
            sends.push(async move {
                let packet = RelayValidationPacket {
                    peer_id: &send_peer_id,
                    peer_virtual_ip: &send_peer_virtual_ip,
                    local_ip,
                    peer_ip,
                    validation_id,
                    sequence: send_sequence,
                };
                let result = tokio::time::timeout(
                    RELAY_CONTROL_SEND_TIMEOUT,
                    send_relay_validation_packet(packet, &send_transport, &send_relay),
                )
                .await;
                (send_peer_id, result)
            });
        }

        let mut sent_count = 0usize;
        let mut transport_failed = false;
        for (peer_id, result) in join_all(sends).await {
            match result {
                Ok(Ok(())) => sent_count = sent_count.saturating_add(1),
                Ok(Err(err)) => {
                    debug!("Relay peer validation skipped for {peer_id}: {err}");
                }
                Err(_) => {
                    transport_failed = true;
                    relay.abort_writer();
                    warn!(
                        event = "relay_validation_send_timeout",
                        peer_id = %peer_id,
                        relay_endpoint = %relay_endpoint,
                        timeout_ms = RELAY_CONTROL_SEND_TIMEOUT.as_millis(),
                        "relay validation writer completion timed out; relay transport invalidated"
                    );
                }
            }
        }
        if sent_count > 0 && !transport_failed {
            last_validation_at = Some(Instant::now());
        }
    }
}

pub(super) struct RelayValidationPacket<'a> {
    pub(super) peer_id: &'a str,
    pub(super) peer_virtual_ip: &'a str,
    pub(super) local_ip: Ipv4Addr,
    pub(super) peer_ip: Ipv4Addr,
    pub(super) validation_id: u16,
    pub(super) sequence: u16,
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

/// Drive forced-relay path-probes to every peer that has an encrypting
/// WireGuard session, relay connected, Direct unconfirmed and RelayPeerConfirmed
/// not yet set.  Each probe registers a newest-wins expectation on the peer
/// manager; only the matching ACK whose real ingress is relay sets
/// `RelayPeerConfirmed` (never a local connect or a queued registration).
///
/// The loop ticks at [`RELAY_PROBE_POLL_INTERVAL`] and is also kicked
/// immediately (`kick_rx`) by the outbound actor when a first business packet
/// starts waiting, so a peer that becomes relay-ready does not wait for the
/// next tick.
pub(super) async fn run_relay_peer_probe_loop(
    peers: Arc<PeerManager>,
    transport: WireGuardTransport,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    local_virtual_ip: String,
    timeline: Arc<crate::connection_timeline::ConnectionTimeline>,
    mut kick_rx: watch::Receiver<u64>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let Ok(local_ip) = local_virtual_ip.parse::<Ipv4Addr>() else {
        debug!("Skipping relay peer probe; local virtual IP '{local_virtual_ip}' is not IPv4");
        return;
    };
    let mut ticker = interval(RELAY_PROBE_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // Per-peer STABLE probe token: (owner token, request id).  It is chosen
    // once per peer (while the peer still needs a probe) and re-sent verbatim,
    // so a late ACK — relay latency up to the expectation TTL — always echoes
    // the token the expectation currently holds.  A fresh expectation is never
    // overwritten with a mismatched token.
    let mut probe_tokens: HashMap<String, (u64, u16)> = HashMap::new();
    // Per-peer last-send time, to pace re-sends (bounded cadence) without
    // changing the token.
    let mut last_sent: HashMap<String, Instant> = HashMap::new();
    // Per-peer + generation probe attempt counts, so the timeline can report a
    // bounded summary instead of one `relay_probe_sent` event per re-send
    // (which would crowd out the startup/roster/session/confirmed milestones
    // in the 64-event ring).
    let mut attempt_counts: HashMap<String, (u64, u64)> = HashMap::new();
    let mut next_request_id: u16 = 0;
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            changed = kick_rx.changed() => {
                if changed.is_err() {
                    return;
                }
                kick_rx.borrow_and_update();
            }
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow_and_update() {
                    return;
                }
            }
        }
        let Some(relay) = relay_transport.read().await.clone() else {
            continue;
        };
        let relay_endpoint = relay.endpoint().to_string();
        let targets = peers.relay_probe_targets().await;
        if targets.is_empty() {
            probe_tokens.clear();
            last_sent.clear();
            // Report attempt summaries for peers that stopped needing probes.
            emit_probe_attempt_summaries(&timeline, &attempt_counts);
            attempt_counts.clear();
            continue;
        }
        let now = Instant::now();
        let mut sends = Vec::new();
        for (peer_id, peer_virtual_ip, target_generation) in &targets {
            let Ok(peer_ip) = peer_virtual_ip.parse::<Ipv4Addr>() else {
                debug!("Skipping relay probe for {peer_id}; peer virtual IP '{peer_virtual_ip}' is not IPv4");
                continue;
            };
            if !transport.session_status(peer_id).await.has_active {
                continue;
            }
            // The relay is genuinely usable for this peer: record the
            // per-peer RelayTransportConnected milestone.
            peers
                .mark_relay_transport_ready(peer_id, &relay_endpoint, *target_generation)
                .await;
            // Stable per-peer token: chosen once, reused for every re-send.
            let (owner_token, request_id) = match probe_tokens.get(peer_id) {
                Some(&token) => token,
                None => {
                    next_request_id = next_request_id.wrapping_add(1);
                    let token = (unix_time_millis(), next_request_id);
                    probe_tokens.insert(peer_id.clone(), token);
                    token
                }
            };
            // (Re)register the expectation with the SAME token.  This refreshes
            // the expectation's validity window, so an ACK that lags the probe
            // by up to the expectation TTL still matches.
            peers.register_relay_probe_expectation(
                peer_id,
                *target_generation,
                request_id,
                owner_token,
                &relay_endpoint,
            );
            // Pace the re-send cadence (the expectation above is refreshed on
            // every tick regardless, so a late ACK always has a live window).
            if last_sent
                .get(peer_id)
                .is_some_and(|at| now.saturating_duration_since(*at) < RELAY_PROBE_RETRY_INTERVAL)
            {
                continue;
            }
            let payload = crate::relay_probe::build_relay_probe_payload(
                crate::relay_probe::RelayProbeKind::Request,
                *target_generation,
                request_id,
                owner_token,
            );
            let packet =
                Ipv4Packet::build_icmp_echo_request(local_ip, peer_ip, request_id, 1, &payload);
            let send_transport = transport.clone();
            let send_relay = relay.clone();
            let send_peer_id = peer_id.clone();
            let send_peer_virtual_ip = peer_virtual_ip.clone();
            let send_relay_endpoint = relay_endpoint.clone();
            let send_generation = *target_generation;
            sends.push(async move {
                let result = tokio::time::timeout(
                    RELAY_CONTROL_SEND_TIMEOUT,
                    send_transport.encrypt_and_emit_outbound(
                        OutboundPacket {
                            peer_id: send_peer_id.clone(),
                            dst_ip: send_peer_virtual_ip,
                            packet,
                        },
                        |encrypted| async move { send_relay.send_packet(&encrypted).await },
                    ),
                )
                .await;
                (
                    send_peer_id,
                    send_generation,
                    request_id,
                    send_relay_endpoint,
                    result,
                )
            });
        }

        // Do not serialize probe delivery across peers.  A blocked writer is a
        // relay-connection failure, but it must not make peer B wait behind
        // peer A's 500ms boundary before B can even allocate/send its probe.
        for (peer_id, generation, request_id, endpoint, result) in join_all(sends).await {
            match result {
                Ok(Ok(true)) => {
                    last_sent.insert(peer_id.clone(), now);
                    let count = attempt_counts
                        .entry(peer_id.clone())
                        .or_insert((0, generation));
                    count.0 = count.0.saturating_add(1);
                    count.1 = generation;
                    debug!(
                        event = "relay_probe_sent",
                        peer_id = %peer_id,
                        relay_endpoint = %endpoint,
                        generation = generation,
                        request_id = request_id,
                        "relay probe sent peer_id={peer_id} request_id={request_id}",
                    );
                    // Only the FIRST probe per peer + generation lands in the
                    // bounded timeline; re-sends are counted in the summary
                    // event emitted when the peer leaves the probe set, so the
                    // 64-event ring cannot be flooded by retries.
                    let scope = format!("peer:{peer_id}:{generation}");
                    timeline.emit_first_scoped(
                        &scope,
                        "relay_probe_sent",
                        Some("relay"),
                        None,
                        Some(format!(
                            "peer={peer_id} relay_endpoint={endpoint} generation={generation} request_id={request_id}"
                        )),
                    );
                }
                Ok(Ok(false)) => {
                    debug!("Relay probe skipped for {peer_id}: WireGuard session is not ready");
                }
                Ok(Err(err)) => {
                    debug!("Relay probe send failed for {peer_id} via {endpoint}: {err}");
                }
                Err(_) => {
                    // The probe already consumed its counter when encryption
                    // succeeded.  Never retry that ciphertext.  Invalidating
                    // the writer also wakes any other completion waiters and
                    // lets the supervisor establish a replacement transport.
                    relay.abort_writer();
                    timeline.emit(
                        "relay_probe_send_timeout",
                        Some("relay"),
                        Some("relay_writer_timeout"),
                        Some(format!(
                            "peer={peer_id} generation={generation} relay_endpoint={endpoint} request_id={request_id} timeout_ms={}",
                            RELAY_CONTROL_SEND_TIMEOUT.as_millis()
                        )),
                    );
                    warn!(
                        event = "relay_probe_send_timeout",
                        peer_id = %peer_id,
                        relay_endpoint = %endpoint,
                        generation = generation,
                        request_id = request_id,
                        "relay probe writer completion timed out; relay transport invalidated"
                    );
                }
            }
        }
        // Drop token/last-sent state for peers that no longer need a probe
        // (now confirmed, Direct, offline), so the maps stay bounded, and
        // report each such peer's total probe-attempt count as a summary
        // milestone (one event per peer + generation, never per re-send).
        let departed: Vec<(String, u64, u64)> = attempt_counts
            .iter()
            .filter(|(peer_id, _)| {
                !targets
                    .iter()
                    .any(|(target_id, _, _)| target_id == *peer_id)
            })
            .map(|(peer_id, (count, generation))| (peer_id.clone(), *count, *generation))
            .collect();
        for (peer_id, count, generation) in departed {
            let scope = format!("peer:{peer_id}:{generation}");
            timeline.emit_first_scoped(
                &scope,
                "relay_probe_attempts",
                Some("relay"),
                None,
                Some(format!(
                    "peer={peer_id} generation={generation} attempts={count}"
                )),
            );
        }
        probe_tokens
            .retain(|peer_id, _| targets.iter().any(|(target_id, _, _)| target_id == peer_id));
        last_sent.retain(|peer_id, _| targets.iter().any(|(target_id, _, _)| target_id == peer_id));
        attempt_counts
            .retain(|peer_id, _| targets.iter().any(|(target_id, _, _)| target_id == peer_id));
    }
}

/// Emit bounded `relay_probe_attempts` summary milestones for every tracked
/// peer + generation (used when the target set empties as a whole).
fn emit_probe_attempt_summaries(
    timeline: &crate::connection_timeline::ConnectionTimeline,
    attempt_counts: &HashMap<String, (u64, u64)>,
) {
    for (peer_id, (count, generation)) in attempt_counts {
        let scope = format!("peer:{peer_id}:{generation}");
        timeline.emit_first_scoped(
            &scope,
            "relay_probe_attempts",
            Some("relay"),
            None,
            Some(format!(
                "peer={peer_id} generation={generation} attempts={count}"
            )),
        );
    }
}

pub(super) async fn send_relay_validation_packet(
    validation: RelayValidationPacket<'_>,
    transport: &WireGuardTransport,
    relay: &RelayTransport,
) -> Result<()> {
    let payload = build_relay_validation_payload(unix_time_millis());
    let packet = Ipv4Packet::build_icmp_echo_request(
        validation.local_ip,
        validation.peer_ip,
        validation.validation_id,
        validation.sequence,
        &payload,
    );
    let sent = transport
        .encrypt_and_emit_outbound(
            OutboundPacket {
                peer_id: validation.peer_id.to_string(),
                dst_ip: validation.peer_virtual_ip.to_string(),
                packet,
            },
            |encrypted| async move { relay.send_packet(&encrypted).await },
        )
        .await?;
    if !sent {
        return Err(DaemonError::Peer(format!(
            "WireGuard session for peer {} is not ready",
            validation.peer_id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ticket_renewal_deadline_precedes_expiry_with_margin() {
        // With a 5-minute ticket the renewal fires 60s before expiry: the
        // old connection is still fully valid while the replacement connects
        // (make-before-break), so there is no transport gap.
        let now = 1_000_000i64;
        let expires = now + 300; // 5-minute ticket
        let deadline = relay_renewal_deadline(expires, now);
        assert_eq!(deadline, Duration::from_secs(240));
        // The deadline is always at least 1s (never a spin).
        assert_eq!(
            relay_renewal_deadline(now + 60, now),
            Duration::from_secs(1)
        );
        assert_eq!(
            relay_renewal_deadline(now + 10, now),
            Duration::from_secs(1)
        );
        assert_eq!(relay_renewal_deadline(now, now), Duration::from_secs(1));
        // An already-expired ticket has no future deadline.
        assert_eq!(relay_renewal_deadline(now - 5, now), Duration::from_secs(1));
        // A short ticket still leaves a real margin: renew at T-60 is
        // impossible, so the renewal waits only for the bounded retry step.
        let deadline_short = relay_renewal_deadline(now + 120, now);
        assert_eq!(deadline_short, Duration::from_secs(60));
    }

    #[test]
    fn relay_ticket_expiry_metadata_roundtrip_is_auditable() {
        use crate::Config;
        // The transport's ticket metadata is what the supervisor reads to
        // schedule the renewal; it must survive the clone the supervisor
        // hands to the renewal task.
        let mut transport = RelayTransport::connect_for_test(
            "default",
            "tcp://relay.test:18081",
            Arc::new(PeerManager::new(
                Config::generate_default("http://ctrl.test", "net1").unwrap(),
            )),
        );
        transport = transport.with_ticket_metadata("aud-1", "default", 1_000_300);
        let (audience, region, expires) = transport
            .ticket_expiry()
            .expect("ticket metadata must be attached");
        assert_eq!(audience, "aud-1");
        assert_eq!(region, "default");
        assert_eq!(expires, 1_000_300);
        let transport2 = transport.clone();
        assert_eq!(
            transport2.ticket_expiry(),
            Some(("aud-1".to_string(), "default".to_string(), 1_000_300)),
            "the cloned transport (handed to the renewal task) must carry the same ticket deadline"
        );
    }

    #[test]
    fn relay_reconnect_backoff_is_bounded_and_jittered() {
        // Full-jitter backoff: every retry sleeps in [base, 2*base) so nodes
        // that fail together do not reconnect in lockstep.
        for _ in 0..200 {
            let delay = relay_retry_delay_with_jitter(Duration::from_secs(1));
            assert!(
                delay >= Duration::from_secs(1) && delay < Duration::from_secs(2),
                "jittered delay must stay in [base, 2*base), got {delay:?}"
            );
        }
        let mut observed = std::collections::HashSet::new();
        for _ in 0..50 {
            observed.insert(relay_retry_delay_with_jitter(Duration::from_secs(1)).as_millis());
        }
        assert!(
            observed.len() > 1,
            "the jitter must actually spread the retry delays, got {observed:?}"
        );
        assert_eq!(
            relay_retry_delay_with_jitter(Duration::ZERO),
            Duration::ZERO
        );

        // The supervisor's exponential doubling is capped: simulate the
        // sequence of bases after repeated failures (1s, 2s, 4s, ... capped at
        // the 30s max) and verify each jittered delay respects its own bound.
        let mut retry_delay = Duration::from_secs(1);
        let max_retry_delay = Duration::from_secs(30);
        for _ in 0..10 {
            let jittered = relay_retry_delay_with_jitter(retry_delay);
            assert!(jittered >= retry_delay);
            assert!(jittered < retry_delay.saturating_mul(2));
            retry_delay = retry_delay.saturating_mul(2).min(max_retry_delay);
        }
        assert_eq!(retry_delay, max_retry_delay, "the backoff must be capped");
    }

    fn test_supervisor(ticket_cache: Option<Arc<RelayTicketCache>>) -> RelaySupervisor {
        let config = crate::Config::generate_default("https://ctrl.test", "net1").unwrap();
        let peers = Arc::new(PeerManager::new(config));
        let (inbound_tx, _inbound_rx) = mpsc::channel(4);
        let (relay_available_tx, _relay_available_rx) = tokio::sync::watch::channel(false);
        RelaySupervisor {
            relay_candidates: Vec::new(),
            preferred_regions: Vec::new(),
            selection_timeout: Duration::from_millis(500),
            node_id: "node-a".to_string(),
            peers,
            relay_transport: Arc::new(RwLock::new(None)),
            relay_selection: Arc::new(RwLock::new(RelaySelectionDiagnostics::default())),
            relay_available_tx,
            timeline: crate::connection_timeline::ConnectionTimeline::new("node-a", 0),
            inbound_tx,
            ticket_cache,
            relay_ticket: None,
            allow_insecure_plaintext: true,
            ca_cert_path: None,
        }
    }

    /// Deterministic arm/release for the fake renewal closure: the closure
    /// signals when the supervisor has invoked it (via `armed`), then blocks
    /// until the test sends the `go` watch value, then pops the next armed
    /// renewal (or returns `None` when the queue is exhausted).
    struct FakeRenewalQueue {
        armed: mpsc::Sender<()>,
        go: tokio::sync::watch::Sender<bool>,
        go_rx: tokio::sync::watch::Receiver<bool>,
        queue: std::sync::Mutex<Vec<ArmedRelayRenewal>>,
    }

    impl FakeRenewalQueue {
        fn new(queue: Vec<ArmedRelayRenewal>) -> (Arc<Self>, mpsc::Receiver<()>) {
            let (armed, armed_rx) = mpsc::channel(1);
            let (go, go_rx) = tokio::sync::watch::channel(false);
            (
                Arc::new(Self {
                    armed,
                    go,
                    go_rx,
                    queue: std::sync::Mutex::new(queue),
                }),
                armed_rx,
            )
        }

        fn release(&self) {
            self.go.send(true).unwrap();
        }

        fn closure(
            self: &Arc<Self>,
        ) -> impl FnMut(
            u64,
            RelayTransport,
        )
            -> Pin<Box<dyn std::future::Future<Output = Option<ArmedRelayRenewal>> + Send>>
               + '_ {
            let queue = self.clone();
            move |_expected: u64, _transport: RelayTransport| {
                let queue = queue.clone();
                let mut go_rx = queue.go_rx.clone();
                Box::pin(async move {
                    queue.armed.send(()).await.unwrap();
                    while !*go_rx.borrow() {
                        if go_rx.changed().await.is_err() {
                            break;
                        }
                    }
                    queue.queue.lock().unwrap().pop()
                })
            }
        }
    }

    #[tokio::test]
    async fn relay_supervisor_legacy_connection_ends_promptly_without_renewal_spin() {
        // A legacy (no-ticket) relay arms no renewal: the renewal branch of
        // the supervisor's select must stay DISARMED so a server EOF is served
        // immediately.  Previously the always-pending renewal branch starved
        // the EOF and the supervisor spun forever.
        let supervisor = test_supervisor(None);
        let transport = RelayTransport::connect_for_test(
            "default",
            "tcp://relay.test:18081",
            supervisor.peers.clone(),
        );
        let endpoint = transport.endpoint().to_string();
        let (relay_tx, relay_rx) = mpsc::channel(4);
        let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ended = tokio::spawn(async move {
            supervisor
                .supervise_relay_connection(
                    &endpoint,
                    transport,
                    relay_rx,
                    connection_generation,
                    |_expected, _transport| Box::pin(async move { None::<ArmedRelayRenewal> }),
                )
                .await
        });
        sleep(Duration::from_millis(20)).await;
        drop(relay_tx);
        let result = tokio::time::timeout(Duration::from_secs(2), ended)
            .await
            .expect("the supervisor must return after a legacy connection ends, not spin")
            .expect("the supervisor task must not panic");
        assert!(
            result.is_ok(),
            "a clean end must surface Ok, got {result:?}"
        );
    }

    #[tokio::test]
    async fn relay_supervisor_renewal_handoff_survives_superseded_connection_eof() {
        // Make-before-break handoff with the full race: the OLD connection's
        // EOF arrives while its renewal is already connecting (the hub's
        // newest-wins close of the superseded connection).  The supervisor
        // must hold that EOF, swap in the replacement, and only then surface
        // the replacement's own end — the handoff can never be aborted by its
        // predecessor's EOF.
        let supervisor = test_supervisor(None);
        let relay_transport = supervisor.relay_transport.clone();
        let relay_selection = supervisor.relay_selection.clone();
        let transport_a = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-a.test:18081",
            supervisor.peers.clone(),
        )
        .with_ticket_metadata("aud-1", "default", 1_000_300);
        let endpoint = transport_a.endpoint().to_string();
        let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
        let (renewal_tx, renewal_rx) = oneshot::channel();
        let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![ArmedRelayRenewal {
            result: Some(renewal_rx),
            connecting: connecting.clone(),
        }]);
        let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let fake_task = fake.clone();

        let ended = tokio::spawn(async move {
            supervisor
                .supervise_relay_connection(
                    &endpoint,
                    transport_a,
                    relay_rx_a,
                    connection_generation,
                    fake_task.closure(),
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
            .await
            .expect("supervisor must arm the renewal closure")
            .expect("armed channel closed");
        // The renewal begins connecting...
        connecting.store(true, std::sync::atomic::Ordering::SeqCst);
        // ...and the superseded connection ends WHILE it is connecting: this
        // EOF is the handoff's own close racing in and must be held, never
        // treated as a real failure.
        relay_tx_a
            .send(RelayMessage::Closed {
                reason: p2pnet_relay::RelayCloseReason::ServerEof,
            })
            .await
            .unwrap();
        fake.release();
        // The renewal resolves with the replacement connection.
        let peers_b =
            PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
        let transport_b = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-b.test:18081",
            Arc::new(peers_b),
        )
        .with_ticket_metadata("aud-1", "default", 1_000_600);
        let (relay_tx_b, relay_rx_b) = mpsc::channel(4);
        assert!(
            renewal_tx
                .send(Some((transport_b.clone(), relay_rx_b)))
                .is_ok(),
            "the supervisor must still be awaiting the renewal result"
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let current = relay_transport.read().await.clone();
                if current
                    .as_ref()
                    .is_some_and(|t| t.endpoint() == transport_b.endpoint())
                {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the supervisor must publish the renewal replacement");
        // The replacement's own stream ends cleanly: that end surfaces, not
        // the held superseded EOF.
        drop(relay_tx_b);
        let result = tokio::time::timeout(Duration::from_secs(2), ended)
            .await
            .expect("the supervisor must return after the replacement ends")
            .expect("the supervisor task must not panic");
        assert!(
            result.is_ok(),
            "the handoff must end cleanly, got {result:?}"
        );
        // The superseded connection's EOF was an EXPECTED handoff close: it
        // must never surface as a relay failure in the diagnostics.
        let diags = relay_selection.read().await;
        assert_eq!(
            diags.selected_error_count, 0,
            "a superseded connection's expected EOF must not count as an error"
        );
        assert_eq!(
            diags.last_error, None,
            "a superseded connection's expected EOF must not set last_error"
        );
        assert_eq!(
            diags.last_error_code, None,
            "a superseded connection's expected EOF must not set last_error_code"
        );
    }

    #[tokio::test]
    async fn relay_supervisor_renewal_failure_surfaces_held_connection_end() {
        // When the renewal fails WHILE its connection is ending, the held EOF
        // is a real failure: it must be surfaced with its close reason intact
        // (never swallowed, never converted into a spurious reconnect).
        let supervisor = test_supervisor(None);
        let relay_selection = supervisor.relay_selection.clone();
        let transport_a = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-a.test:18081",
            supervisor.peers.clone(),
        )
        .with_ticket_metadata("aud-1", "default", 1_000_300);
        let endpoint = transport_a.endpoint().to_string();
        let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
        let (renewal_tx, renewal_rx) = oneshot::channel();
        let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![ArmedRelayRenewal {
            result: Some(renewal_rx),
            connecting: connecting.clone(),
        }]);
        let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let fake_task = fake.clone();

        let ended = tokio::spawn(async move {
            supervisor
                .supervise_relay_connection(
                    &endpoint,
                    transport_a,
                    relay_rx_a,
                    connection_generation,
                    fake_task.closure(),
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
            .await
            .expect("supervisor must arm the renewal closure")
            .expect("armed channel closed");
        connecting.store(true, std::sync::atomic::Ordering::SeqCst);
        relay_tx_a
            .send(RelayMessage::Closed {
                reason: p2pnet_relay::RelayCloseReason::ServerEof,
            })
            .await
            .unwrap();
        fake.release();
        assert!(
            renewal_tx.send(None).is_ok(),
            "the supervisor must still be awaiting the renewal result"
        );
        let result = tokio::time::timeout(Duration::from_secs(2), ended)
            .await
            .expect("the supervisor must return after a failed renewal with a held end")
            .expect("the supervisor task must not panic");
        let error =
            result.expect_err("a failed renewal with an ending connection must surface an error");
        assert!(
            error.to_string().contains("server_eof"),
            "the held close reason must be preserved, got {error}"
        );
        // The held end was a GENUINE failure of the current connection (the
        // renewal did not resolve it), so the deferred attribution must record
        // it exactly once with the real close reason.
        let diags = relay_selection.read().await;
        assert_eq!(
            diags.selected_error_count, 1,
            "a genuine close with a failed renewal must be counted exactly once"
        );
        assert_eq!(
            diags.last_error.as_deref(),
            Some("relay connection closed: reason=server_eof"),
            "the deferred diagnostics must attribute the real close"
        );
        assert_eq!(
            diags.last_error_code.as_deref(),
            Some("server_eof"),
            "the deferred diagnostics must keep the real close code"
        );
    }

    async fn wait_for_relay_transport(
        relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
        endpoint: &str,
    ) {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let current = relay_transport.read().await.clone();
                if current.as_ref().is_some_and(|t| t.endpoint() == endpoint) {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the supervisor must publish the renewal replacement");
    }

    #[tokio::test]
    async fn relay_supervisor_superseded_connection_eof_after_handoff_keeps_diagnostics_clean() {
        // The field-reported scenario: the hub's newest-wins close of the
        // SUPERSEDED connection arrives AFTER the renewal handoff already
        // published the replacement.  The old-generation EOF is expected and
        // must be ignored — no diagnostics entry, no reconnect, no panic —
        // while the replacement keeps serving.
        let supervisor = test_supervisor(None);
        let relay_transport = supervisor.relay_transport.clone();
        let relay_selection = supervisor.relay_selection.clone();
        let transport_a = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-a.test:18081",
            supervisor.peers.clone(),
        )
        .with_ticket_metadata("aud-1", "default", 1_000_300);
        let endpoint = transport_a.endpoint().to_string();
        let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
        let (renewal_tx, renewal_rx) = oneshot::channel();
        let connecting = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![ArmedRelayRenewal {
            result: Some(renewal_rx),
            connecting: connecting.clone(),
        }]);
        let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let fake_task = fake.clone();

        let ended = tokio::spawn(async move {
            supervisor
                .supervise_relay_connection(
                    &endpoint,
                    transport_a,
                    relay_rx_a,
                    connection_generation,
                    fake_task.closure(),
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
            .await
            .expect("supervisor must arm the renewal closure")
            .expect("armed channel closed");
        fake.release();
        let peers_b =
            PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
        let transport_b = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-b.test:18081",
            Arc::new(peers_b),
        )
        .with_ticket_metadata("aud-1", "default", 1_000_600);
        let (relay_tx_b, relay_rx_b) = mpsc::channel(4);
        assert!(
            renewal_tx
                .send(Some((transport_b.clone(), relay_rx_b)))
                .is_ok(),
            "the supervisor must still be awaiting the renewal result"
        );
        wait_for_relay_transport(&relay_transport, transport_b.endpoint()).await;

        // The hub now closes the superseded connection (old-generation EOF).
        relay_tx_a
            .send(RelayMessage::Closed {
                reason: p2pnet_relay::RelayCloseReason::ServerEof,
            })
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;
        assert!(
            !ended.is_finished(),
            "a superseded EOF must not end the supervisor (no reconnect)"
        );
        let current = relay_transport.read().await.clone();
        assert!(
            current.is_some_and(|t| t.endpoint() == transport_b.endpoint()),
            "the replacement must keep serving after a superseded EOF"
        );
        let diags = relay_selection.read().await;
        assert_eq!(
            diags.selected_error_count, 0,
            "an old-generation EOF after handoff must not count as an error"
        );
        assert_eq!(diags.last_error, None);
        assert_eq!(diags.last_error_code, None);

        // The replacement's own stream ends cleanly.
        drop(relay_tx_b);
        let result = tokio::time::timeout(Duration::from_secs(2), ended)
            .await
            .expect("the supervisor must return after the replacement ends")
            .expect("the supervisor task must not panic");
        assert!(result.is_ok(), "clean end, got {result:?}");
    }

    #[tokio::test]
    async fn relay_supervisor_genuine_server_eof_records_diagnostics_once() {
        // A REAL close of the CURRENT connection (no renewal in flight) is a
        // genuine failure: it must return the failure AND record exactly one
        // diagnostics entry with the server_eof attribution — never swallowed,
        // never duplicated.
        let supervisor = test_supervisor(None);
        let relay_selection = supervisor.relay_selection.clone();
        let transport = RelayTransport::connect_for_test(
            "default",
            "tcp://relay.test:18081",
            supervisor.peers.clone(),
        );
        let endpoint = transport.endpoint().to_string();
        let (relay_tx, relay_rx) = mpsc::channel(4);
        let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let ended = tokio::spawn(async move {
            supervisor
                .supervise_relay_connection(
                    &endpoint,
                    transport,
                    relay_rx,
                    connection_generation,
                    |_expected, _transport| Box::pin(async move { None::<ArmedRelayRenewal> }),
                )
                .await
        });
        sleep(Duration::from_millis(20)).await;
        relay_tx
            .send(RelayMessage::Closed {
                reason: p2pnet_relay::RelayCloseReason::ServerEof,
            })
            .await
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), ended)
            .await
            .expect("the supervisor must return after a genuine server EOF")
            .expect("the supervisor task must not panic");
        let error = result.expect_err("a genuine server EOF must surface as a failure");
        assert!(
            error.to_string().contains("server_eof"),
            "the close reason must be preserved, got {error}"
        );
        let diags = relay_selection.read().await;
        assert_eq!(
            diags.selected_error_count, 1,
            "a genuine server EOF must be counted exactly once"
        );
        assert_eq!(
            diags.last_error.as_deref(),
            Some("relay connection closed: reason=server_eof"),
            "the last_error must attribute the real close"
        );
        assert_eq!(
            diags.last_error_code.as_deref(),
            Some("server_eof"),
            "the error code must attribute server_eof"
        );
    }

    #[tokio::test]
    async fn relay_supervisor_two_renewal_cycles_preserve_ticket_metadata_and_diagnostics() {
        // Two consecutive make-before-break cycles: each handoff publishes the
        // replacement WITH its own ticket expiry (so the next renewal is
        // scheduled from the new deadline), superseded connections' EOFs are
        // ignored, and the diagnostics accumulate NO false errors across the
        // whole lifecycle.
        let supervisor = test_supervisor(None);
        let relay_transport = supervisor.relay_transport.clone();
        let relay_selection = supervisor.relay_selection.clone();
        let transport_a = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-a.test:18081",
            supervisor.peers.clone(),
        )
        .with_ticket_metadata("aud-1", "default", 1_000_300);
        let endpoint = transport_a.endpoint().to_string();
        let (relay_tx_a, relay_rx_a) = mpsc::channel(4);
        let (renewal_tx_1, renewal_rx_1) = oneshot::channel();
        let (renewal_tx_2, renewal_rx_2) = oneshot::channel();
        let connecting_1 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let connecting_2 = Arc::new(std::sync::atomic::AtomicBool::new(false));
        // The queue is popped LIFO, so the FIRST pop is renewal 1.
        let (fake, mut armed_rx) = FakeRenewalQueue::new(vec![
            ArmedRelayRenewal {
                result: Some(renewal_rx_2),
                connecting: connecting_2.clone(),
            },
            ArmedRelayRenewal {
                result: Some(renewal_rx_1),
                connecting: connecting_1.clone(),
            },
        ]);
        let connection_generation = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let fake_task = fake.clone();

        let ended = tokio::spawn(async move {
            supervisor
                .supervise_relay_connection(
                    &endpoint,
                    transport_a,
                    relay_rx_a,
                    connection_generation,
                    fake_task.closure(),
                )
                .await
        });

        tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
            .await
            .expect("supervisor must arm the first renewal")
            .expect("armed channel closed");
        fake.release();

        // Cycle 1: renewal resolves with a replacement carrying its OWN expiry.
        let peers_b =
            PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
        let transport_b = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-b.test:18081",
            Arc::new(peers_b),
        )
        .with_ticket_metadata("aud-1", "default", 1_000_600);
        let (relay_tx_b, relay_rx_b) = mpsc::channel(4);
        assert!(
            renewal_tx_1
                .send(Some((transport_b.clone(), relay_rx_b)))
                .is_ok(),
            "the supervisor must still be awaiting the first renewal result"
        );
        wait_for_relay_transport(&relay_transport, transport_b.endpoint()).await;
        // The hub closes the superseded connection A after handoff 1.
        relay_tx_a
            .send(RelayMessage::Closed {
                reason: p2pnet_relay::RelayCloseReason::ServerEof,
            })
            .await
            .unwrap();

        // Cycle 2: the supervisor re-armed (queue pop 2); resolve it.
        tokio::time::timeout(Duration::from_secs(2), armed_rx.recv())
            .await
            .expect("supervisor must re-arm the second renewal")
            .expect("armed channel closed");
        let peers_c =
            PeerManager::new(crate::Config::generate_default("https://ctrl.test", "net1").unwrap());
        let transport_c = RelayTransport::connect_for_test(
            "default",
            "tcp://relay-c.test:18081",
            Arc::new(peers_c),
        )
        .with_ticket_metadata("aud-1", "default", 1_001_200);
        let (relay_tx_c, relay_rx_c) = mpsc::channel(4);
        assert!(
            renewal_tx_2
                .send(Some((transport_c.clone(), relay_rx_c)))
                .is_ok(),
            "the supervisor must still be awaiting the second renewal result"
        );
        wait_for_relay_transport(&relay_transport, transport_c.endpoint()).await;
        // The hub closes the superseded connection B after handoff 2.
        relay_tx_b
            .send(RelayMessage::Closed {
                reason: p2pnet_relay::RelayCloseReason::ServerEof,
            })
            .await
            .unwrap();
        sleep(Duration::from_millis(100)).await;

        // The current replacement still carries its own ticket expiry so the
        // NEXT renewal is scheduled from the new deadline.
        let current = relay_transport
            .read()
            .await
            .clone()
            .expect("the second replacement must be published");
        assert_eq!(
            current.ticket_expiry(),
            Some(("aud-1".to_string(), "default".to_string(), 1_001_200)),
            "the second replacement must keep its own ticket expiry for the next renewal"
        );
        // Two handoffs and two superseded EOFs: NO false errors accumulated.
        let diags = relay_selection.read().await;
        assert_eq!(
            diags.selected_error_count, 0,
            "successful renewal cycles must not accumulate false errors"
        );
        assert_eq!(diags.last_error, None);
        assert_eq!(diags.last_error_code, None);

        // The current connection ends cleanly.
        drop(relay_tx_c);
        let result = tokio::time::timeout(Duration::from_secs(2), ended)
            .await
            .expect("the supervisor must return after the current connection ends")
            .expect("the supervisor task must not panic");
        assert!(result.is_ok(), "clean end, got {result:?}");
    }
}
