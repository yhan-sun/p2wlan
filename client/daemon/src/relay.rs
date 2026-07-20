//! Relay transport adapter for encrypted peer packets.
//!
//! This layer bridges the daemon's WireGuard packet model to the DERP-like
//! relay client. Relay payloads remain encrypted WireGuard datagrams; the relay
//! server only sees source/destination node IDs and opaque bytes.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use p2pnet_relay::{RelayClient, RelayClientConfig, RelayMessage};
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::control::ControlClient;
use crate::error::{DaemonError, Result};
use crate::peer::PeerManager;
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

const RELAY_INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
const RELAY_TICKET_REFRESH_MARGIN_SECS: i64 = 60;

/// Diagnostics for one configured relay candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCandidateDiagnostics {
    pub region: String,
    pub endpoint: String,
    pub connect_latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cooldown_remaining_ms: Option<u64>,
    pub error: Option<String>,
    pub error_code: Option<String>,
}

/// Result of the most recent relay selection pass.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelaySelectionDiagnostics {
    pub selected_region: Option<String>,
    pub selected_endpoint: Option<String>,
    pub selected_connect_latency_ms: Option<u64>,
    pub selected_last_pong_at_unix_ms: Option<u64>,
    pub selected_last_pong_age_ms: Option<u64>,
    pub selected_last_pong_rtt_ms: Option<u64>,
    pub selected_rtt_ewma_ms: Option<u64>,
    pub selected_jitter_ms: Option<u64>,
    pub selected_pong_count: u64,
    pub selected_error_count: u64,
    pub candidates: Vec<RelayCandidateDiagnostics>,
    pub last_error: Option<String>,
    pub last_error_code: Option<String>,
}

impl RelaySelectionDiagnostics {
    pub fn refresh_runtime_ages(&mut self) {
        let now_ms = now_unix_millis();
        if let Some(last_pong_at) = self.selected_last_pong_at_unix_ms {
            self.selected_last_pong_age_ms = Some(now_ms.saturating_sub(last_pong_at));
        }
    }
}

#[derive(Debug, Clone)]
struct RelayCandidate {
    index: usize,
    region: String,
    audience: Option<String>,
    endpoint: String,
    preference_rank: usize,
}

struct ConnectedCandidate {
    candidate: RelayCandidate,
    transport: RelayTransport,
    relay_rx: mpsc::Receiver<RelayMessage>,
}

/// Relay selector output. A failed pass still returns diagnostics.
pub struct RelaySelectionOutcome {
    pub transport: Option<RelayTransport>,
    pub relay_rx: Option<mpsc::Receiver<RelayMessage>>,
    pub diagnostics: RelaySelectionDiagnostics,
}

/// A relay candidate after control-plane/catalog normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCandidateConfig {
    pub region: String,
    pub audience: Option<String>,
    pub endpoint: String,
}

impl RelayCandidateConfig {
    pub fn catalog(
        region: impl Into<String>,
        audience: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            region: region.into(),
            audience: Some(audience.into()),
            endpoint: endpoint.into(),
        }
    }

    pub fn legacy(spec: impl Into<String>) -> Self {
        Self {
            region: String::new(),
            audience: None,
            endpoint: spec.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RelayTicketKey {
    audience: String,
    region: String,
}

#[derive(Debug, Clone)]
struct CachedRelayTicket {
    ticket: String,
    expires_at: i64,
}

/// In-memory relay ticket cache keyed by (audience, region).
///
/// Tokens are never persisted or placed in diagnostics. A per-key async lock
/// merges concurrent refreshes for the same relay audience.
pub struct RelayTicketCache {
    control_client: ControlClient,
    entries: Mutex<HashMap<RelayTicketKey, CachedRelayTicket>>,
    refresh_locks: Mutex<HashMap<RelayTicketKey, Arc<Mutex<()>>>>,
}

impl RelayTicketCache {
    pub fn new(control_client: ControlClient) -> Self {
        Self {
            control_client,
            entries: Mutex::new(HashMap::new()),
            refresh_locks: Mutex::new(HashMap::new()),
        }
    }

    pub async fn ticket_for(&self, audience: &str, region: &str) -> Result<String> {
        let key = RelayTicketKey {
            audience: audience.to_string(),
            region: region.to_string(),
        };

        if let Some(ticket) = self.cached_ticket(&key).await {
            return Ok(ticket);
        }

        let refresh_lock = {
            let mut locks = self.refresh_locks.lock().await;
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };

        let _guard = refresh_lock.lock().await;

        if let Some(ticket) = self.cached_ticket(&key).await {
            return Ok(ticket);
        }

        let (ticket, expires_at) = self
            .control_client
            .fetch_relay_ticket(&key.audience, &key.region)
            .await?;

        if ticket.trim().is_empty() {
            return Err(DaemonError::ControlPlane(
                "relay ticket response contained an empty ticket".into(),
            ));
        }
        if expires_at <= now_unix() + RELAY_TICKET_REFRESH_MARGIN_SECS {
            return Err(DaemonError::ControlPlane(
                "relay ticket expires too soon".into(),
            ));
        }

        self.entries.lock().await.insert(
            key.clone(),
            CachedRelayTicket {
                ticket: ticket.clone(),
                expires_at,
            },
        );

        Ok(ticket)
    }

    async fn cached_ticket(&self, key: &RelayTicketKey) -> Option<String> {
        self.entries.lock().await.get(key).and_then(|entry| {
            if entry.expires_at > now_unix() + RELAY_TICKET_REFRESH_MARGIN_SECS {
                Some(entry.ticket.clone())
            } else {
                None
            }
        })
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn now_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn update_latency_ewma(ewma_ms: &mut Option<u64>, jitter_ms: &mut Option<u64>, sample_ms: u64) {
    match *ewma_ms {
        Some(previous) => {
            let delta = sample_ms.abs_diff(previous);
            let next_ewma = ((previous as u128 * 7) + sample_ms as u128).div_ceil(8) as u64;
            let next_jitter = match *jitter_ms {
                Some(previous_jitter) => {
                    ((previous_jitter as u128 * 3) + delta as u128).div_ceil(4) as u64
                }
                None => delta,
            };
            *ewma_ms = Some(next_ewma);
            *jitter_ms = Some(next_jitter);
        }
        None => {
            *ewma_ms = Some(sample_ms);
            *jitter_ms = Some(0);
        }
    }
}

fn record_relay_pong(
    diagnostics: &mut RelaySelectionDiagnostics,
    ping_timestamp_ms: u64,
    received_at_ms: u64,
) {
    let rtt_ms = received_at_ms.saturating_sub(ping_timestamp_ms);
    diagnostics.selected_last_pong_at_unix_ms = Some(received_at_ms);
    diagnostics.selected_last_pong_age_ms = Some(0);
    diagnostics.selected_last_pong_rtt_ms = Some(rtt_ms);
    diagnostics.selected_pong_count = diagnostics.selected_pong_count.saturating_add(1);
    update_latency_ewma(
        &mut diagnostics.selected_rtt_ewma_ms,
        &mut diagnostics.selected_jitter_ms,
        rtt_ms,
    );
}

#[derive(Debug)]
enum RelayAttemptError {
    Relay(p2pnet_relay::RelayError),
    Daemon(DaemonError),
}

impl RelayAttemptError {
    fn error_code(&self) -> String {
        match self {
            RelayAttemptError::Relay(error) => error
                .error_code()
                .map(|code| code.to_snake_case().to_string())
                .unwrap_or_else(|| error.to_snake_case().to_string()),
            RelayAttemptError::Daemon(error) => match error {
                DaemonError::Auth(_) => "permanent_auth".to_string(),
                DaemonError::ControlPlane(message) if message.contains("permanent auth") => {
                    "permanent_auth".to_string()
                }
                DaemonError::ControlPlane(_) => "ticket_fetch_failed".to_string(),
                _ => "connect_failed".to_string(),
            },
        }
    }
}

impl fmt::Display for RelayAttemptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RelayAttemptError::Relay(error) => write!(f, "{error}"),
            RelayAttemptError::Daemon(error) => write!(f, "{error}"),
        }
    }
}

fn parse_candidate(
    index: usize,
    spec: &RelayCandidateConfig,
    preferred_regions: &[String],
) -> std::result::Result<RelayCandidate, String> {
    let raw_endpoint = spec.endpoint.trim();
    if raw_endpoint.is_empty() {
        return Err("empty relay candidate".to_string());
    }

    let (region, endpoint) = if spec.region.trim().is_empty() {
        match raw_endpoint.split_once('@') {
            Some((region, endpoint)) if !region.trim().is_empty() => {
                (region.trim().to_string(), endpoint.trim())
            }
            Some(_) => {
                return Err(format!(
                    "relay candidate '{}' has an empty region",
                    spec.endpoint
                ))
            }
            None => ("default".to_string(), raw_endpoint),
        }
    } else {
        (spec.region.trim().to_string(), raw_endpoint)
    };

    // Endpoints now support tls://host:port, tcp://host:port, or bare host:port.
    // Validation is done by the relay client's endpoint parser.
    if endpoint.is_empty() {
        return Err(format!(
            "relay candidate '{}' has an empty endpoint",
            spec.endpoint
        ));
    }

    let audience = spec
        .audience
        .as_ref()
        .map(|audience| audience.trim().to_string())
        .filter(|audience| !audience.is_empty());

    let preference_rank = preferred_regions
        .iter()
        .position(|preferred| preferred.eq_ignore_ascii_case(&region))
        .unwrap_or(preferred_regions.len());

    Ok(RelayCandidate {
        index,
        region,
        audience,
        endpoint: endpoint.to_string(),
        preference_rank,
    })
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// Connect to all valid relay candidates concurrently and select the best one.
/// Preferred regions win first; connection latency and config order break ties.
///
/// A2 parameters (ticket, TLS config) are passed through to the relay client.
#[allow(clippy::too_many_arguments)]
pub async fn select_relay(
    specs: &[RelayCandidateConfig],
    preferred_regions: &[String],
    selection_timeout: Duration,
    node_id: &str,
    peers: Arc<PeerManager>,
    ticket_cache: Option<Arc<RelayTicketCache>>,
    static_relay_ticket: Option<String>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
) -> RelaySelectionOutcome {
    let cooldowns = HashMap::new();
    select_relay_with_cooldowns(
        specs,
        preferred_regions,
        selection_timeout,
        node_id,
        peers,
        ticket_cache,
        static_relay_ticket,
        allow_insecure_plaintext,
        ca_cert_path,
        &cooldowns,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn select_relay_with_cooldowns(
    specs: &[RelayCandidateConfig],
    preferred_regions: &[String],
    selection_timeout: Duration,
    node_id: &str,
    peers: Arc<PeerManager>,
    ticket_cache: Option<Arc<RelayTicketCache>>,
    static_relay_ticket: Option<String>,
    allow_insecure_plaintext: bool,
    ca_cert_path: Option<String>,
    cooldowns: &HashMap<String, Instant>,
) -> RelaySelectionOutcome {
    let mut diagnostics = RelaySelectionDiagnostics::default();
    let mut candidates = Vec::new();
    let mut seen_endpoints = HashSet::new();
    let now = Instant::now();

    for (index, spec) in specs.iter().enumerate() {
        match parse_candidate(index, spec, preferred_regions) {
            Ok(candidate) => {
                if let Some(remaining) = cooldowns
                    .get(&candidate.endpoint)
                    .and_then(|until| until.checked_duration_since(now))
                {
                    let remaining_ms = duration_millis(remaining);
                    diagnostics.candidates.push(RelayCandidateDiagnostics {
                        region: candidate.region,
                        endpoint: candidate.endpoint,
                        connect_latency_ms: None,
                        cooldown_remaining_ms: Some(remaining_ms),
                        error: Some(format!(
                            "relay candidate cooling down for {remaining_ms} ms"
                        )),
                        error_code: Some("cooling_down".to_string()),
                    });
                    continue;
                }

                if seen_endpoints.insert(candidate.endpoint.clone()) {
                    diagnostics.candidates.push(RelayCandidateDiagnostics {
                        region: candidate.region.clone(),
                        endpoint: candidate.endpoint.clone(),
                        connect_latency_ms: None,
                        cooldown_remaining_ms: None,
                        error: None,
                        error_code: None,
                    });
                    candidates.push(candidate);
                } else {
                    diagnostics.candidates.push(RelayCandidateDiagnostics {
                        region: candidate.region,
                        endpoint: candidate.endpoint,
                        connect_latency_ms: None,
                        cooldown_remaining_ms: None,
                        error: Some("duplicate relay endpoint".to_string()),
                        error_code: Some("duplicate_endpoint".to_string()),
                    });
                }
            }
            Err(error) => diagnostics.candidates.push(RelayCandidateDiagnostics {
                region: "unknown".to_string(),
                endpoint: spec.endpoint.trim().to_string(),
                connect_latency_ms: None,
                cooldown_remaining_ms: None,
                error: Some(error),
                error_code: Some("invalid_spec".to_string()),
            }),
        }
    }

    let mut tasks = JoinSet::new();
    for candidate in candidates {
        let node_id = node_id.to_string();
        let peers = peers.clone();
        let ticket_cache = ticket_cache.clone();
        let static_ticket = static_relay_ticket.clone();
        let ca_path = ca_cert_path.clone();
        tasks.spawn(async move {
            let started = Instant::now();
            let result = timeout(selection_timeout, async {
                let ticket =
                    relay_ticket_for_candidate(&candidate, ticket_cache, static_ticket).await?;
                RelayTransport::connect_in_region(
                    &candidate.endpoint,
                    &candidate.region,
                    &node_id,
                    peers,
                    ticket,
                    allow_insecure_plaintext,
                    ca_path,
                )
                .await
                .map_err(RelayAttemptError::Relay)
            })
            .await;
            let latency_ms = duration_millis(started.elapsed());
            (candidate, latency_ms, result)
        });
    }

    let mut connected = Vec::new();
    while let Some(task_result) = tasks.join_next().await {
        let Ok((candidate, latency_ms, result)) = task_result else {
            continue;
        };
        let candidate_diagnostics = &mut diagnostics.candidates[candidate.index];
        candidate_diagnostics.connect_latency_ms = Some(latency_ms);

        match result {
            Ok(Ok((transport, relay_rx))) => connected.push(ConnectedCandidate {
                candidate,
                transport,
                relay_rx,
            }),
            Ok(Err(error)) => {
                candidate_diagnostics.error = Some(error.to_string());
                candidate_diagnostics.error_code = Some(error.error_code());
            }
            Err(_) => {
                candidate_diagnostics.error = Some(format!(
                    "relay selection timed out after {} ms",
                    duration_millis(selection_timeout)
                ));
                candidate_diagnostics.error_code = Some("timeout".to_string());
            }
        }
    }

    connected.sort_by_key(|connected| {
        (
            connected.candidate.preference_rank,
            connected.transport.connect_latency_ms,
            connected.candidate.index,
        )
    });

    if let Some(selected) = connected.into_iter().next() {
        diagnostics.selected_region = Some(selected.candidate.region.clone());
        diagnostics.selected_endpoint = Some(selected.candidate.endpoint.clone());
        diagnostics.selected_connect_latency_ms = Some(selected.transport.connect_latency_ms);
        RelaySelectionOutcome {
            transport: Some(selected.transport),
            relay_rx: Some(selected.relay_rx),
            diagnostics,
        }
    } else {
        diagnostics.last_error = Some(if specs.is_empty() {
            "no relay candidates configured".to_string()
        } else {
            "all relay candidates failed".to_string()
        });
        if let Some(first_failed) = diagnostics.candidates.iter().find(|c| c.error.is_some()) {
            diagnostics.last_error_code = first_failed.error_code.clone();
        } else {
            diagnostics.last_error_code = Some("no_candidates".to_string());
        }
        RelaySelectionOutcome {
            transport: None,
            relay_rx: None,
            diagnostics,
        }
    }
}

async fn relay_ticket_for_candidate(
    candidate: &RelayCandidate,
    ticket_cache: Option<Arc<RelayTicketCache>>,
    static_relay_ticket: Option<String>,
) -> std::result::Result<Option<String>, RelayAttemptError> {
    if let (Some(cache), Some((audience, region))) =
        (ticket_cache, relay_ticket_lookup_key(candidate))
    {
        return cache
            .ticket_for(audience, region)
            .await
            .map(Some)
            .map_err(RelayAttemptError::Daemon);
    }

    Ok(static_relay_ticket)
}

fn relay_ticket_lookup_key(candidate: &RelayCandidate) -> Option<(&str, &str)> {
    candidate
        .audience
        .as_deref()
        .map(|audience| (audience, candidate.region.as_str()))
}

/// Sends and receives encrypted WireGuard datagrams through a relay server.
#[derive(Clone)]
pub struct RelayTransport {
    relay_region: String,
    relay_endpoint: String,
    connect_latency_ms: u64,
    client: Arc<Mutex<RelayClient>>,
    peers: Arc<PeerManager>,
}

impl RelayTransport {
    /// Connect to a relay server and register this node ID (legacy, no TLS/ticket).
    /// Prefers tcp:// prefix if not already present for bare host:port.
    pub async fn connect(
        relay_endpoint: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        // For backward compat, prefix bare host:port with tcp://
        let wire_endpoint = if !relay_endpoint.contains("://") {
            format!("tcp://{relay_endpoint}")
        } else {
            relay_endpoint.to_string()
        };
        let (mut transport, rx) =
            Self::connect_in_region(&wire_endpoint, "default", node_id, peers, None, true, None)
                .await
                .map_err(|e| {
                    DaemonError::Relay(format!("failed to connect to relay {relay_endpoint}: {e}"))
                })?;
        // Store the original endpoint for diagnostics consistency
        transport.relay_endpoint = relay_endpoint.to_string();
        Ok((transport, rx))
    }

    /// Connect with full A2 support: TLS endpoint, ticket, and CA cert.
    pub async fn connect_secure(
        relay_endpoint: &str,
        relay_region: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
        relay_ticket: Option<String>,
        allow_insecure_plaintext: bool,
        ca_cert_path: Option<String>,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_in_region(
            relay_endpoint,
            relay_region,
            node_id,
            peers,
            relay_ticket,
            allow_insecure_plaintext,
            ca_cert_path,
        )
        .await
        .map_err(|e| {
            DaemonError::Relay(format!("failed to connect to relay {relay_endpoint}: {e}"))
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_in_region(
        relay_endpoint: &str,
        relay_region: &str,
        node_id: &str,
        peers: Arc<PeerManager>,
        relay_ticket: Option<String>,
        allow_insecure_plaintext: bool,
        ca_cert_path: Option<String>,
    ) -> std::result::Result<(Self, mpsc::Receiver<RelayMessage>), p2pnet_relay::RelayError> {
        let started = Instant::now();
        let mut config = RelayClientConfig {
            idle_timeout: RELAY_INBOUND_IDLE_TIMEOUT,
            keepalive_interval: RELAY_INBOUND_IDLE_TIMEOUT / 2,
            allow_insecure_plaintext,
            relay_ticket,
            ..Default::default()
        };

        // Set CA cert path if provided
        if let Some(ca_path) = &ca_cert_path {
            config.tls_ca_cert_path = Some(std::path::PathBuf::from(ca_path));
        }

        // Use the new A2 endpoint-based connection which supports tls:// and tcp://
        let (client, relay_rx) =
            RelayClient::connect_with_endpoint(relay_endpoint, node_id, config).await?;

        info!(
            "Connected to relay {} (region={}, {}ms)",
            relay_endpoint,
            relay_region,
            duration_millis(started.elapsed())
        );

        Ok((
            Self {
                relay_region: relay_region.to_string(),
                relay_endpoint: relay_endpoint.to_string(),
                connect_latency_ms: duration_millis(started.elapsed()),
                client: Arc::new(Mutex::new(client)),
                peers,
            },
            relay_rx,
        ))
    }

    /// Selected relay region label.
    pub fn region(&self) -> &str {
        &self.relay_region
    }

    /// Selected relay endpoint.
    pub fn endpoint(&self) -> &str {
        &self.relay_endpoint
    }

    /// TCP connect plus relay registration latency.
    pub fn connect_latency_ms(&self) -> u64 {
        self.connect_latency_ms
    }

    /// Send a single encrypted packet through the relay.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<()> {
        self.client
            .lock()
            .await
            .send_data(&packet.peer_id, &packet.wire_bytes)
            .await
            .map_err(|e| {
                DaemonError::Relay(format!(
                    "relay send to peer {} via {} failed: {e}",
                    packet.peer_id, self.relay_endpoint
                ))
            })?;

        self.peers
            .set_relay(&packet.peer_id, &self.relay_endpoint)
            .await;
        self.peers
            .record_sent(&packet.peer_id, packet.wire_bytes.len() as u64)
            .await;
        debug!(
            "Sent {} encrypted bytes to peer {} through relay {}",
            packet.wire_bytes.len(),
            packet.peer_id,
            self.relay_endpoint
        );
        Ok(())
    }

    /// Convert relay messages into inbound encrypted datagrams for WireGuard.
    pub async fn run_inbound(
        self,
        mut relay_rx: mpsc::Receiver<RelayMessage>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
        relay_selection: Option<Arc<tokio::sync::RwLock<RelaySelectionDiagnostics>>>,
    ) -> Result<()> {
        while let Some(message) = relay_rx.recv().await {
            match message {
                RelayMessage::Closed => {
                    if let Some(ref diags) = relay_selection {
                        let mut d = diags.write().await;
                        d.selected_error_count = d.selected_error_count.saturating_add(1);
                        d.last_error = Some("relay connection closed by remote".to_string());
                        d.last_error_code = Some("transport_closed".to_string());
                    }
                    return Err(DaemonError::Relay(format!(
                        "relay {} connection closed",
                        self.relay_endpoint
                    )));
                }
                RelayMessage::Error { code, message } => {
                    warn!(
                        "Received relay runtime error: code={}, message={}",
                        code, message
                    );
                    if let Some(ref diags) = relay_selection {
                        let mut d = diags.write().await;
                        d.selected_error_count = d.selected_error_count.saturating_add(1);
                        d.last_error = Some(message.clone());
                        if let Some(ec) = p2pnet_relay::RelayErrorCode::from_u16(code) {
                            d.last_error_code = Some(ec.to_snake_case().to_string());
                        } else {
                            d.last_error_code = Some(format!("error_{}", code));
                        }
                    }
                }
                RelayMessage::Pong { timestamp } => {
                    let received_at_ms = now_unix_millis();
                    if let Some(ref diags) = relay_selection {
                        let mut d = diags.write().await;
                        record_relay_pong(&mut d, timestamp, received_at_ms);
                    }
                    debug!(
                        "Received ping-pong keepalive response from relay {} with timestamp {} rtt={}ms",
                        self.relay_endpoint,
                        timestamp,
                        received_at_ms.saturating_sub(timestamp)
                    );
                }
                RelayMessage::Data { from_node, data } => {
                    self.peers
                        .record_relay_success(&from_node, &self.relay_endpoint, false)
                        .await;
                    inbound_tx
                        .send(ReceivedEncryptedPacket {
                            source: None,
                            wire_bytes: data,
                        })
                        .await
                        .map_err(|_| {
                            DaemonError::Network("relay inbound packet channel closed".to_string())
                        })?;
                }
            }
        }

        warn!("Relay inbound stream from {} ended", self.relay_endpoint);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use p2pnet_relay::RelayServer;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::{ConnectionState, PeerManager};

    fn peer(node_id: &str, virtual_ip: &str) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            device_name: String::new(),
            public_key: "pk".to_string(),
            endpoint: String::new(),
            nat_type: "Unknown".to_string(),
            virtual_ip: virtual_ip.to_string(),
            online: true,
            last_seen: 0,
        }
    }

    fn peer_manager() -> Arc<PeerManager> {
        Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ))
    }

    #[test]
    fn relay_pong_updates_runtime_health() {
        let mut diagnostics = RelaySelectionDiagnostics::default();

        record_relay_pong(&mut diagnostics, 900, 1_000);
        assert_eq!(diagnostics.selected_last_pong_at_unix_ms, Some(1_000));
        assert_eq!(diagnostics.selected_last_pong_age_ms, Some(0));
        assert_eq!(diagnostics.selected_last_pong_rtt_ms, Some(100));
        assert_eq!(diagnostics.selected_rtt_ewma_ms, Some(100));
        assert_eq!(diagnostics.selected_jitter_ms, Some(0));
        assert_eq!(diagnostics.selected_pong_count, 1);

        record_relay_pong(&mut diagnostics, 1_000, 1_120);
        assert_eq!(diagnostics.selected_last_pong_rtt_ms, Some(120));
        assert_eq!(diagnostics.selected_rtt_ewma_ms, Some(103));
        assert_eq!(diagnostics.selected_jitter_ms, Some(5));
        assert_eq!(diagnostics.selected_pong_count, 2);

        diagnostics.refresh_runtime_ages();
        assert!(diagnostics.selected_last_pong_age_ms.unwrap() > 0);
    }

    #[tokio::test]
    async fn relay_transport_sends_encrypted_datagrams() {
        let server = RelayServer::start_random().await.unwrap();
        let relay_endpoint = server.addr.to_string();

        let peers_a = peer_manager();
        let peers_b = peer_manager();
        peers_a.add_peer(&peer("node-b", "10.20.0.2")).await;
        peers_b.add_peer(&peer("node-a", "10.20.0.1")).await;

        let (relay_a, _rx_a) = RelayTransport::connect(&relay_endpoint, "node-a", peers_a.clone())
            .await
            .unwrap();
        let (relay_b, rx_b) = RelayTransport::connect(&relay_endpoint, "node-b", peers_b.clone())
            .await
            .unwrap();

        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let inbound_worker = tokio::spawn(relay_b.run_inbound(rx_b, inbound_tx, None));

        let payload = vec![4, 1, 2, 3, 4, 5];
        relay_a
            .send_packet(&EncryptedPeerPacket {
                peer_id: "node-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                wire_bytes: payload.clone(),
            })
            .await
            .unwrap();

        let received = timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.source, None);
        assert_eq!(received.wire_bytes, payload);

        let conn_a = peers_a.get_connection("node-b").await.unwrap();
        assert_eq!(conn_a.state, ConnectionState::Relay);
        assert_eq!(conn_a.relay_server, Some(relay_endpoint.clone()));

        let conn_b = peers_b.get_connection("node-a").await.unwrap();
        assert_eq!(conn_b.state, ConnectionState::Relay);
        assert_eq!(conn_b.relay_server, Some(relay_endpoint));

        inbound_worker.abort();
        server.shutdown().await;
    }

    #[test]
    fn relay_candidate_parses_region_and_legacy_endpoint() {
        let preferred = vec!["cn-east".to_string()];
        let regional = parse_candidate(
            0,
            &RelayCandidateConfig::legacy("cn-east@127.0.0.1:8080"),
            &preferred,
        )
        .unwrap();
        assert_eq!(regional.region, "cn-east");
        assert_eq!(regional.endpoint, "127.0.0.1:8080");
        assert_eq!(regional.audience, None);
        assert_eq!(regional.preference_rank, 0);

        let legacy = parse_candidate(
            1,
            &RelayCandidateConfig::legacy("127.0.0.1:8081"),
            &preferred,
        )
        .unwrap();
        assert_eq!(legacy.region, "default");
        assert_eq!(legacy.endpoint, "127.0.0.1:8081");
        assert_eq!(legacy.preference_rank, 1);
    }

    #[test]
    fn relay_candidate_preserves_catalog_audience() {
        let candidate = parse_candidate(
            0,
            &RelayCandidateConfig::catalog("sg", "relay-sg-1", "tls://relay.example.com:18081"),
            &["sg".to_string()],
        )
        .unwrap();

        assert_eq!(candidate.region, "sg");
        assert_eq!(candidate.audience.as_deref(), Some("relay-sg-1"));
        assert_eq!(candidate.endpoint, "tls://relay.example.com:18081");
        assert_eq!(candidate.preference_rank, 0);
    }

    #[test]
    fn relay_ticket_lookup_uses_catalog_audience_for_tcp_too() {
        let candidate = parse_candidate(
            0,
            &RelayCandidateConfig::catalog("dev", "relay-dev-1", "tcp://127.0.0.1:18081"),
            &[],
        )
        .unwrap();

        assert_eq!(
            relay_ticket_lookup_key(&candidate),
            Some(("relay-dev-1", "dev"))
        );
    }

    #[tokio::test]
    async fn relay_selector_prefers_configured_region() {
        let east = RelayServer::start_random().await.unwrap();
        let west = RelayServer::start_random().await.unwrap();
        let specs = vec![
            RelayCandidateConfig::legacy(format!("east@{}", east.addr)),
            RelayCandidateConfig::legacy(format!("west@{}", west.addr)),
        ];

        let outcome = select_relay(
            &specs,
            &["west".to_string()],
            Duration::from_secs(1),
            "node-a",
            peer_manager(),
            None,
            None,
            true,
            None,
        )
        .await;

        let transport = outcome.transport.as_ref().unwrap();
        assert_eq!(transport.region(), "west");
        assert_eq!(transport.endpoint(), west.addr.to_string());
        assert_eq!(outcome.diagnostics.selected_region.as_deref(), Some("west"));
        assert_eq!(outcome.diagnostics.candidates.len(), 2);
        assert!(outcome
            .diagnostics
            .candidates
            .iter()
            .all(|c| c.error.is_none()));

        drop(outcome);
        east.shutdown().await;
        west.shutdown().await;
    }

    #[tokio::test]
    async fn relay_selector_skips_cooled_down_candidate() {
        let primary = RelayServer::start_random().await.unwrap();
        let standby = RelayServer::start_random().await.unwrap();
        let specs = vec![
            RelayCandidateConfig::legacy(format!("primary@{}", primary.addr)),
            RelayCandidateConfig::legacy(format!("standby@{}", standby.addr)),
        ];
        let mut cooldowns = HashMap::new();
        cooldowns.insert(
            primary.addr.to_string(),
            Instant::now() + Duration::from_secs(30),
        );

        let outcome = select_relay_with_cooldowns(
            &specs,
            &["primary".to_string()],
            Duration::from_secs(1),
            "node-a",
            peer_manager(),
            None,
            None,
            true,
            None,
            &cooldowns,
        )
        .await;

        let transport = outcome.transport.as_ref().unwrap();
        assert_eq!(transport.region(), "standby");
        assert_eq!(transport.endpoint(), standby.addr.to_string());
        assert_eq!(
            outcome.diagnostics.candidates[0].error_code.as_deref(),
            Some("cooling_down")
        );
        assert!(outcome.diagnostics.candidates[0]
            .cooldown_remaining_ms
            .is_some());
        assert!(outcome.diagnostics.candidates[1].error.is_none());

        drop(outcome);
        primary.shutdown().await;
        standby.shutdown().await;
    }

    #[tokio::test]
    async fn relay_selector_falls_back_when_preferred_region_is_unreachable() {
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_listener.local_addr().unwrap();
        drop(dead_listener);
        let fallback = RelayServer::start_random().await.unwrap();
        let specs = vec![
            RelayCandidateConfig::legacy(format!("preferred@{dead_addr}")),
            RelayCandidateConfig::legacy(format!("fallback@{}", fallback.addr)),
        ];

        let outcome = select_relay(
            &specs,
            &["preferred".to_string()],
            Duration::from_secs(1),
            "node-a",
            peer_manager(),
            None,
            None,
            true,
            None,
        )
        .await;

        let transport = outcome.transport.as_ref().unwrap();
        assert_eq!(transport.region(), "fallback");
        assert_eq!(transport.endpoint(), fallback.addr.to_string());
        assert!(outcome.diagnostics.candidates[0].error.is_some());
        assert!(outcome.diagnostics.candidates[1].error.is_none());
        assert_eq!(outcome.diagnostics.last_error, None);

        drop(outcome);
        fallback.shutdown().await;
    }
}
