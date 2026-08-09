//! Relay runtime helpers: default relay inference, candidate assembly, the
//! relay supervisor task, and proactive relay peer validation.
//!
//! Split out of the crate root to keep `lib.rs` focused on daemon orchestration.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pnet_relay::RelayMessage;
use p2pnet_tun::Ipv4Packet;
use tokio::sync::{mpsc, oneshot, RwLock};
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
    /// Spawn the make-before-break renewal task for an authenticated relay
    /// connection, returning its result oneshot receiver.
    ///
    /// The task sleeps until `expiry - margin`, fetches a fresh ticket and
    /// connects the replacement transport — all CONCURRENTLY with the current
    /// connection's inbound drain, so the swap (which the caller performs
    /// atomically) never produces a data-path gap.  A fetch or connect
    /// failure sends `None` and leaves the current connection untouched; the
    /// supervisor then falls back to its existing reconnect path at expiry.
    ///
    /// Returns `None` when the connection has no ticket (legacy relay).
    async fn spawn_relay_renewal_task(
        &self,
        transport: RelayTransport,
    ) -> Option<oneshot::Receiver<Option<(RelayTransport, mpsc::Receiver<RelayMessage>)>>> {
        let (audience, region, expires_at_unix) = transport.ticket_expiry()?;
        let ticket_cache = self.ticket_cache.clone()?;
        let node_id = self.node_id.clone();
        let peers = self.peers.clone();
        let allow_insecure_plaintext = self.allow_insecure_plaintext;
        let ca_cert_path = self.ca_cert_path.clone();
        let endpoint = transport.endpoint().to_string();
        let region = region.clone();
        let (tx, rx) = oneshot::channel();
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
            // Fetch a fresh ticket and connect the replacement; the caller
            // swaps it in only after this succeeded, so the old connection
            // keeps serving until the new one is ready.
            let result = async {
                let (ticket, _expires_at) =
                    ticket_cache.refresh_ticket(&audience, &region).await.ok()?;
                RelayTransport::connect_secure(
                    &endpoint,
                    &region,
                    &node_id,
                    peers,
                    Some(ticket),
                    allow_insecure_plaintext,
                    ca_cert_path,
                )
                .await
                .ok()
            }
            .await;
            let _ = tx.send(result);
        });
        Some(rx)
    }
}

impl RelaySupervisor {
    pub(super) async fn run(self) {
        let mut retry_delay = Duration::from_secs(1);
        let max_retry_delay = Duration::from_secs(30);
        let mut cooldowns: HashMap<String, Instant> = HashMap::new();
        loop {
            let now = Instant::now();
            cooldowns.retain(|_, until| *until > now);

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
                type RelayRenewalResult = Option<(RelayTransport, mpsc::Receiver<RelayMessage>)>;
                let mut current_transport = relay;
                let mut renewal: Option<oneshot::Receiver<RelayRenewalResult>> = self
                    .spawn_relay_renewal_task(current_transport.clone())
                    .await;
                let mut inbound_task = {
                    let (ended_tx, ended_rx) = oneshot::channel();
                    let transport = current_transport.clone();
                    let rx = relay_rx;
                    let inbound_tx = self.inbound_tx.clone();
                    let diags = self.relay_selection.clone();
                    let handle = tokio::spawn(async move {
                        let result = transport.run_inbound(rx, inbound_tx, Some(diags)).await;
                        let _ = ended_tx.send(result);
                    });
                    (handle, ended_rx)
                };
                let ended = loop {
                    let Some(mut renewal_rx) = renewal.take() else {
                        // No ticket on this connection (legacy relay): await
                        // the inbound drain directly.
                        let result = inbound_task.1.await;
                        break match result {
                            Ok(Ok(())) => Ok(()),
                            Ok(Err(error)) => Err(error),
                            Err(_) => Err(DaemonError::Network(
                                "relay inbound task ended unexpectedly".into(),
                            )),
                        };
                    };
                    tokio::select! {
                        ended = &mut inbound_task.1 => {
                            break match ended {
                                Ok(Ok(())) => Ok(()),
                                Ok(Err(error)) => Err(error),
                                Err(_) => Err(DaemonError::Network(
                                    "relay inbound task ended unexpectedly".into(),
                                )),
                            };
                        }
                        result = &mut renewal_rx => {
                            // The renewal task finished (success or failure);
                            // the inbound stream kept draining the whole time,
                            // so there is no data-path gap.
                            let result = result.ok().flatten();
                            match result {
                                Some((new_transport, new_rx)) => {
                                    let new_endpoint = new_transport.endpoint().to_string();
                                    info!(
                                        "Renewed relay ticket: swapped {} -> {} before ticket expiry",
                                        endpoint, new_endpoint
                                    );
                                    *self.relay_transport.write().await =
                                        Some(new_transport.clone());
                                    // Start the replacement's inbound drain;
                                    // the old task keeps draining until the
                                    // hub closes the old connection.
                                    let (ended_tx, ended_rx) = oneshot::channel();
                                    let transport = new_transport.clone();
                                    let inbound_tx = self.inbound_tx.clone();
                                    let diags = self.relay_selection.clone();
                                    inbound_task = (
                                        tokio::spawn(async move {
                                            let result =
                                                transport.run_inbound(new_rx, inbound_tx, Some(diags)).await;
                                            let _ = ended_tx.send(result);
                                        }),
                                        ended_rx,
                                    );
                                    current_transport = new_transport;
                                }
                                None => {
                                    warn!(
                                        "Relay ticket renewal for {} failed; the current connection stays until expiry and the supervisor reconnects if needed",
                                        endpoint
                                    );
                                }
                            }
                            // Re-arm the next renewal for the (possibly
                            // swapped) connection.
                            renewal = self.spawn_relay_renewal_task(current_transport.clone()).await;
                        }
                    }
                };
                let _ = inbound_task.0.await;
                *self.relay_transport.write().await = None;
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
        last_relay_endpoint = Some(relay_endpoint);

        let validation_id = unix_time_millis() as u16;
        let mut sent_count = 0usize;
        for (sequence, (peer_id, peer_virtual_ip)) in targets.into_iter().enumerate() {
            let Ok(peer_ip) = peer_virtual_ip.parse::<Ipv4Addr>() else {
                debug!(
                    "Skipping relay peer validation for {peer_id}; peer virtual IP '{peer_virtual_ip}' is not IPv4"
                );
                continue;
            };
            let packet = RelayValidationPacket {
                peer_id: &peer_id,
                peer_virtual_ip: &peer_virtual_ip,
                local_ip,
                peer_ip,
                validation_id,
                sequence: sequence as u16,
            };
            match send_relay_validation_packet(packet, &transport, &relay).await {
                Ok(()) => sent_count = sent_count.saturating_add(1),
                Err(err) => debug!("Relay peer validation skipped for {peer_id}: {err}"),
            }
        }
        if sent_count > 0 {
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
}
