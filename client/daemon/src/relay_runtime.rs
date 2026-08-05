//! Relay runtime helpers: default relay inference, candidate assembly, the
//! relay supervisor task, and proactive relay peer validation.
//!
//! Split out of the crate root to keep `lib.rs` focused on daemon orchestration.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use p2pnet_tun::Ipv4Packet;
use tokio::sync::{mpsc, RwLock};
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
                let ended = relay
                    .run_inbound(
                        relay_rx,
                        self.inbound_tx.clone(),
                        Some(self.relay_selection.clone()),
                    )
                    .await;
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

            sleep(retry_delay).await;
            retry_delay = retry_delay.saturating_mul(2).min(max_retry_delay);
        }
    }
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
