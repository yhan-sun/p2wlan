//! UDP transport for encrypted peer packets.
//!
//! The WireGuard adapter produces serialized transport messages keyed by peer
//! ID. This module is the direct UDP sink: it resolves each peer endpoint from
//! `PeerManager` and sends the encrypted datagram to that socket address.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use p2pnet_nat::{
    build_authenticated_punch_ack, build_authenticated_punch_packet_with_nomination,
    build_punch_ack, build_punch_packet, build_punch_packet_with_nonce,
    candidate_report_from_observations, decode_authenticated_punch_packet, decode_punch_packet,
    gather_candidate_report, peek_authenticated_punch_identity, CandidateGatherReport, IceConfig,
    MappingBehavior, PunchPacketKind, StunAttribute, StunClient, StunMessage, StunObservation,
    BINDING_RESPONSE, MAGIC_COOKIE,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinSet;
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, info, trace, warn};

use crate::error::{DaemonError, Result};
use crate::peer::{PeerManager, REASON_DIRECT_SEND_FAILED};
use crate::transport::{EncryptedPeerPacket, ReceivedEncryptedPacket};

mod probe_budget;
use probe_budget::{
    default_global_outbound_probe_budget, GlobalOutboundProbeBudget, OutboundProbeAdmission,
    OutboundProbeBudgetKey, OutboundProbeBudgetState, OUTBOUND_PROBE_BUDGET_PER_NETWORK,
    OUTBOUND_PROBE_BUDGET_PER_PEER, OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP,
    OUTBOUND_PROBE_BUDGET_WINDOW,
};
#[cfg(test)]
use probe_budget::{
    global_probe_remote_ip_key, unix_time_millis, write_global_probe_budget_entries,
};
#[cfg(test)]
use std::fs::OpenOptions;
#[cfg(test)]
use std::net::IpAddr;
#[cfg(test)]
use std::path::PathBuf;

type ProbeNonce = [u8; 8];
type PendingProbes = Arc<Mutex<HashMap<ProbeNonce, PendingProbe>>>;
type StunTransactionId = [u8; 12];
type StunResponse = (Vec<u8>, SocketAddr);
type StunWaiters = Arc<Mutex<HashMap<StunTransactionId, oneshot::Sender<StunResponse>>>>;
type PeerReflexiveNotificationState = Arc<Mutex<HashMap<(String, SocketAddr), Instant>>>;
type TriggeredCheckState = Arc<Mutex<HashMap<(String, SocketAddr, usize), Instant>>>;
type AuthPunchReplayKey = (String, u64, ProbeNonce, u8);
type AuthPunchReplayState = Arc<Mutex<HashMap<AuthPunchReplayKey, Instant>>>;
type AuthPunchRateState = Arc<Mutex<HashMap<(String, SocketAddr), VecDeque<Instant>>>>;

const DIRECT_KEEPALIVE_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const PUNCH_PROBE_RETRANSMIT_DELAYS_MS: [u64; 2] = [25, 75];
const PUNCH_ACK_RETRANSMIT_DELAYS_MS: [u64; 2] = [20, 80];
const PEER_REFLEXIVE_NOTIFY_COOLDOWN: Duration = Duration::from_secs(2);
const TRIGGERED_CHECK_COOLDOWN: Duration = Duration::from_millis(750);
const AUTH_PUNCH_REPLAY_WINDOW: Duration = Duration::from_secs(60);
const AUTH_PUNCH_REPLAY_MAX_ENTRIES: usize = 4096;
const AUTH_PUNCH_REPLAY_TARGET_ENTRIES: usize = 3072;
const AUTH_PUNCH_RATE_WINDOW: Duration = Duration::from_secs(1);
const AUTH_PUNCH_RATE_LIMIT_PER_SOURCE: usize = 16;
/// Two STUN observers per experimental socket are enough to publish that
/// socket's observed mapping and infer a small per-socket port-delta prediction
/// window without turning the bounded traversal experiment into a large STUN
/// burst. The primary socket still uses the complete configured observer set
/// for NAT profiling.
const SOCKET_POOL_STUN_OBSERVERS_PER_SOCKET: usize = 2;

/// Counters for one local UDP socket in the bounded traversal experiment.
/// They deliberately contain no endpoint or peer identity so diagnostics can
/// expose experiment progress without disclosing local network topology.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UdpSocketPoolMemberDiagnostics {
    /// Stable index for the lifetime of the transport; zero is the primary socket.
    pub socket_index: usize,
    /// Successful UDP punch probes sent from this socket.
    pub probes_sent: u64,
    /// Punch ACKs sent from this socket after receiving a probe.
    pub probe_acks_sent: u64,
    /// Matching punch ACKs received on this socket.
    pub probe_acks_received: u64,
    /// Encrypted direct datagrams sent from this socket.
    pub encrypted_packets_sent: u64,
    /// Encrypted direct datagrams received on this socket.
    pub encrypted_packets_received: u64,
    /// Server-reflexive mappings learned for this socket and published to peers.
    pub stun_mappings_discovered: u64,
}

/// A peer-reflexive UDP source observed on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerReflexiveObservation {
    /// Peer whose UDP source was observed.
    pub peer_id: String,
    /// Public/source endpoint observed by this node.
    pub observed_endpoint: SocketAddr,
}

#[derive(Debug, Clone)]
struct PendingProbe {
    sent_at: Instant,
    endpoint: SocketAddr,
    local_endpoint: Option<SocketAddr>,
    socket_index: usize,
    generation: u64,
    peer_id: Option<String>,
    purpose: PendingProbePurpose,
    accepts_authenticated_ack: bool,
    accepts_legacy_ack: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingProbePurpose {
    ConnectivityCheck,
    ConsentCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthenticatedPunchAdmission {
    Accepted,
    Replay,
    RateLimited,
}

fn punch_kind_code(kind: PunchPacketKind) -> u8 {
    match kind {
        PunchPacketKind::Punch => 1,
        PunchPacketKind::Ack => 2,
    }
}

fn legacy_ack_matches_pending(
    pending: &PendingProbe,
    source: SocketAddr,
    generation: u64,
    socket_index: usize,
) -> bool {
    pending.generation == generation
        && pending.socket_index == socket_index
        && pending.accepts_legacy_ack
        && (pending.endpoint == source
            || (pending.peer_id.is_some() && pending.endpoint.ip() == source.ip()))
}

fn format_optional_endpoint(endpoint: Option<SocketAddr>) -> String {
    endpoint
        .map(|endpoint| endpoint.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeScheduleRound {
    delay_before: Duration,
    endpoints: Vec<SocketAddr>,
}

fn build_probe_schedule(
    candidates: &[SocketAddr],
    probe_interval: Duration,
    attempts: u32,
) -> Vec<ProbeScheduleRound> {
    if candidates.is_empty() || attempts == 0 {
        return Vec::new();
    }

    let mut unique = Vec::new();
    for candidate in candidates {
        if !unique.contains(candidate) {
            unique.push(*candidate);
        }
    }

    (0..attempts)
        .map(|round| {
            let is_final_round = round + 1 == attempts;
            let width = if attempts == 1 || is_final_round {
                unique.len()
            } else {
                match round {
                    0 | 1 => unique.len().min(24),
                    2 => unique.len().min(48),
                    _ => unique.len(),
                }
            };

            ProbeScheduleRound {
                delay_before: probe_round_delay(round, probe_interval),
                endpoints: unique.iter().take(width).copied().collect(),
            }
        })
        .filter(|round| !round.endpoints.is_empty())
        .collect()
}

fn probe_round_delay(round: u32, probe_interval: Duration) -> Duration {
    if round == 0 || probe_interval.is_zero() {
        return Duration::ZERO;
    }

    let burst_delay = match round {
        1 => Duration::from_millis(60),
        2 => Duration::from_millis(140),
        _ => probe_interval,
    };

    burst_delay.min(probe_interval)
}

/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    /// The primary socket is used for STUN and remains the single-socket
    /// fallback. Additional sockets, when explicitly enabled, are only used
    /// for bounded symmetric-NAT traversal experiments.
    socket: Arc<UdpSocket>,
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    peers: Arc<PeerManager>,
    pending_probes: PendingProbes,
    stun_waiters: StunWaiters,
    peer_socket_affinity: Arc<Mutex<HashMap<String, usize>>>,
    socket_pool_active: Arc<AtomicBool>,
    socket_pool_diagnostics: Arc<Mutex<Vec<UdpSocketPoolMemberDiagnostics>>>,
    peer_reflexive_tx: Option<mpsc::Sender<PeerReflexiveObservation>>,
    peer_reflexive_notifications: PeerReflexiveNotificationState,
    triggered_checks: TriggeredCheckState,
    authenticated_punch_replay: AuthPunchReplayState,
    authenticated_punch_rate: AuthPunchRateState,
    outbound_probe_budget: OutboundProbeBudgetState,
    global_outbound_probe_budget: Option<Arc<GlobalOutboundProbeBudget>>,
    local_node_id: Option<String>,
}

impl UdpTransport {
    /// Bind a UDP socket for direct peer traffic.
    pub async fn bind(bind_addr: SocketAddr, peers: Arc<PeerManager>) -> Result<Self> {
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DaemonError::Network(format!("failed to bind UDP socket at {bind_addr}: {e}"))
        })?;

        Ok(Self {
            socket: Arc::new(socket),
            sockets: Arc::new(Vec::new()),
            peers,
            pending_probes: Arc::new(Mutex::new(HashMap::new())),
            stun_waiters: Arc::new(Mutex::new(HashMap::new())),
            peer_socket_affinity: Arc::new(Mutex::new(HashMap::new())),
            socket_pool_active: Arc::new(AtomicBool::new(false)),
            socket_pool_diagnostics: Arc::new(Mutex::new(vec![UdpSocketPoolMemberDiagnostics {
                socket_index: 0,
                ..Default::default()
            }])),
            peer_reflexive_tx: None,
            peer_reflexive_notifications: Arc::new(Mutex::new(HashMap::new())),
            triggered_checks: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_replay: Arc::new(Mutex::new(HashMap::new())),
            authenticated_punch_rate: Arc::new(Mutex::new(HashMap::new())),
            outbound_probe_budget: Arc::new(Mutex::new(HashMap::new())),
            global_outbound_probe_budget: default_global_outbound_probe_budget(),
            local_node_id: None,
        })
    }

    #[cfg(test)]
    fn with_global_probe_budget_path(mut self, path: PathBuf) -> Self {
        self.global_outbound_probe_budget = Some(Arc::new(GlobalOutboundProbeBudget::new(path)));
        self
    }

    /// Add up to `count - 1` ephemeral sockets for an explicitly enabled
    /// traversal experiment. The primary socket is always slot zero.
    pub async fn with_socket_pool(mut self, count: usize) -> Result<Self> {
        const MAX_SOCKET_POOL_SIZE: usize = 4;
        let requested = count.clamp(1, MAX_SOCKET_POOL_SIZE);
        let bind_addr = self.local_addr()?;
        let pool_bind_addr = SocketAddr::new(bind_addr.ip(), 0);
        let mut sockets = vec![self.socket.clone()];

        for _ in 1..requested {
            let socket = UdpSocket::bind(pool_bind_addr).await.map_err(|e| {
                DaemonError::Network(format!(
                    "failed to bind UDP socket pool member at {pool_bind_addr}: {e}"
                ))
            })?;
            sockets.push(Arc::new(socket));
        }

        self.sockets = Arc::new(sockets);
        *self.socket_pool_diagnostics.lock().await = (0..requested)
            .map(|socket_index| UdpSocketPoolMemberDiagnostics {
                socket_index,
                ..Default::default()
            })
            .collect();
        Ok(self)
    }

    fn active_sockets(&self) -> &[Arc<UdpSocket>] {
        if self.sockets.is_empty() {
            std::slice::from_ref(&self.socket)
        } else {
            self.sockets.as_slice()
        }
    }

    /// Number of live UDP sockets, including the primary data socket.
    pub fn socket_count(&self) -> usize {
        self.active_sockets().len()
    }

    /// Enable additional socket probing after the NAT profile has qualified
    /// this network for the experiment. Receive ownership remains active for
    /// every socket regardless, so an already-open mapping is never missed.
    pub fn set_socket_pool_active(&self, active: bool) {
        self.socket_pool_active.store(active, Ordering::Relaxed);
    }

    pub fn socket_pool_active(&self) -> bool {
        self.socket_pool_active.load(Ordering::Relaxed) && self.socket_count() > 1
    }

    /// A stable, endpoint-free view of the bounded socket pool activity.
    pub async fn socket_pool_diagnostics(&self) -> Vec<UdpSocketPoolMemberDiagnostics> {
        self.socket_pool_diagnostics.lock().await.clone()
    }

    async fn update_socket_diagnostics(
        &self,
        socket_index: usize,
        update: impl FnOnce(&mut UdpSocketPoolMemberDiagnostics),
    ) {
        if let Some(diagnostics) = self
            .socket_pool_diagnostics
            .lock()
            .await
            .get_mut(socket_index)
        {
            update(diagnostics);
        }
    }

    fn punch_socket_count(&self) -> usize {
        if self.socket_pool_active() {
            self.socket_count()
        } else {
            1
        }
    }

    async fn socket_index_for_peer(&self, peer_id: Option<&str>) -> usize {
        let socket_count = self.socket_count();
        let Some(peer_id) = peer_id else {
            return 0;
        };
        self.peer_socket_affinity
            .lock()
            .await
            .get(peer_id)
            .copied()
            .filter(|index| *index < socket_count)
            .unwrap_or(0)
    }

    async fn remember_peer_socket(&self, peer_id: &str, socket_index: usize) {
        if socket_index < self.socket_count() {
            self.peer_socket_affinity
                .lock()
                .await
                .insert(peer_id.to_string(), socket_index);
        }
    }

    /// Attach the local control-plane node ID used by authenticated UDP Probe v2.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        self.local_node_id = Some(node_id.into());
        self
    }

    /// Attach a best-effort channel for relay-assisted peer-reflexive observations.
    pub fn with_peer_reflexive_observer(
        mut self,
        tx: mpsc::Sender<PeerReflexiveObservation>,
    ) -> Self {
        self.peer_reflexive_tx = Some(tx);
        self
    }

    async fn admit_authenticated_punch(
        &self,
        peer_id: &str,
        generation: u64,
        kind: PunchPacketKind,
        nonce: ProbeNonce,
        source: SocketAddr,
    ) -> AuthenticatedPunchAdmission {
        let now = Instant::now();
        let mut rate = self.authenticated_punch_rate.lock().await;
        rate.retain(|_, seen| {
            while seen
                .front()
                .is_some_and(|seen_at| now.duration_since(*seen_at) >= AUTH_PUNCH_RATE_WINDOW)
            {
                seen.pop_front();
            }
            !seen.is_empty()
        });
        let seen = rate.entry((peer_id.to_string(), source)).or_default();
        while seen
            .front()
            .is_some_and(|seen_at| now.duration_since(*seen_at) >= AUTH_PUNCH_RATE_WINDOW)
        {
            seen.pop_front();
        }
        if seen.len() >= AUTH_PUNCH_RATE_LIMIT_PER_SOURCE {
            return AuthenticatedPunchAdmission::RateLimited;
        }
        seen.push_back(now);
        drop(rate);

        {
            let mut replay = self.authenticated_punch_replay.lock().await;
            replay.retain(|_, seen_at| seen_at.elapsed() < AUTH_PUNCH_REPLAY_WINDOW);
            let key = (
                peer_id.to_string(),
                generation,
                nonce,
                punch_kind_code(kind),
            );
            if replay.contains_key(&key) {
                return AuthenticatedPunchAdmission::Replay;
            }
            replay.insert(key, now);

            if replay.len() > AUTH_PUNCH_REPLAY_MAX_ENTRIES {
                let mut entries = replay
                    .iter()
                    .map(|(key, seen_at)| (key.clone(), *seen_at))
                    .collect::<Vec<_>>();
                entries.sort_by_key(|(_, seen_at)| *seen_at);
                let remove_count = replay
                    .len()
                    .saturating_sub(AUTH_PUNCH_REPLAY_TARGET_ENTRIES);
                for (key, _) in entries.into_iter().take(remove_count) {
                    replay.remove(&key);
                }
            }
        }

        AuthenticatedPunchAdmission::Accepted
    }

    async fn admit_outbound_connectivity_probe(
        &self,
        peer_id: &str,
        peer_addr: SocketAddr,
    ) -> OutboundProbeAdmission {
        let now = Instant::now();
        let network_key = OutboundProbeBudgetKey::Network;
        let peer_key = OutboundProbeBudgetKey::Peer(peer_id.to_string());
        let remote_ip_key =
            OutboundProbeBudgetKey::PeerRemoteIp(peer_id.to_string(), peer_addr.ip());
        let mut budget = self.outbound_probe_budget.lock().await;
        budget.retain(|_, sent| {
            while sent
                .front()
                .is_some_and(|sent_at| now.duration_since(*sent_at) >= OUTBOUND_PROBE_BUDGET_WINDOW)
            {
                sent.pop_front();
            }
            !sent.is_empty()
        });

        if budget.get(&network_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_NETWORK {
            return OutboundProbeAdmission::NetworkRateLimited;
        }
        if budget.get(&peer_key).map_or(0, VecDeque::len) >= OUTBOUND_PROBE_BUDGET_PER_PEER {
            return OutboundProbeAdmission::PeerRateLimited;
        }
        if budget.get(&remote_ip_key).map_or(0, VecDeque::len)
            >= OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP
        {
            return OutboundProbeAdmission::RemoteIpRateLimited;
        }

        if let Some(global_budget) = self.global_outbound_probe_budget.as_ref() {
            match global_budget.admit(peer_id, peer_addr) {
                Ok(OutboundProbeAdmission::Accepted) => {}
                Ok(limited) => return limited,
                Err(err) => {
                    debug!(
                        "Global outbound UDP probe budget unavailable; continuing with in-process budget only: {err}"
                    );
                }
            }
        }

        budget.entry(network_key).or_default().push_back(now);
        budget.entry(peer_key).or_default().push_back(now);
        budget.entry(remote_ip_key).or_default().push_back(now);
        OutboundProbeAdmission::Accepted
    }

    async fn notify_peer_reflexive_observation(
        &self,
        peer_id: &str,
        observed_endpoint: SocketAddr,
    ) {
        let Some(tx) = self.peer_reflexive_tx.as_ref() else {
            return;
        };
        let key = (peer_id.to_string(), observed_endpoint);
        {
            let mut notifications = self.peer_reflexive_notifications.lock().await;
            notifications.retain(|_, sent_at| sent_at.elapsed() < PEER_REFLEXIVE_NOTIFY_COOLDOWN);
            if notifications.contains_key(&key) {
                return;
            }
            notifications.insert(key, Instant::now());
        }

        if let Err(err) = tx.try_send(PeerReflexiveObservation {
            peer_id: peer_id.to_string(),
            observed_endpoint,
        }) {
            debug!(
                "Dropping peer-reflexive observation for {peer_id} at {observed_endpoint}: {err}"
            );
        }
    }

    async fn trigger_peer_reflexive_check(
        &self,
        socket_index: usize,
        peer_id: &str,
        observed_endpoint: SocketAddr,
    ) {
        let key = (peer_id.to_string(), observed_endpoint, socket_index);
        {
            let mut checks = self.triggered_checks.lock().await;
            checks.retain(|_, sent_at| sent_at.elapsed() < TRIGGERED_CHECK_COOLDOWN);
            if checks.contains_key(&key) {
                return;
            }
            checks.insert(key, Instant::now());
        }

        let local_endpoint = self
            .active_sockets()
            .get(socket_index)
            .and_then(|socket| socket.local_addr().ok());
        match self
            .send_probe_from_socket(socket_index, Some(peer_id), observed_endpoint)
            .await
        {
            Ok(_) => info!(
                event = "candidate_pair_triggered_check",
                peer_id = %peer_id,
                local_endpoint = %local_endpoint.map(|endpoint| endpoint.to_string()).unwrap_or_else(|| "unknown".to_string()),
                remote_endpoint = %observed_endpoint,
                candidate_source = "peer_reflexive",
                reason = "authenticated inbound punch observed",
                "candidate_pair_triggered_check peer_id={} remote_endpoint={} reason=authenticated inbound punch observed",
                peer_id,
                observed_endpoint
            ),
            Err(err) => debug!(
                "Failed triggered UDP check from socket {socket_index} to peer {peer_id} at {observed_endpoint}: {err}"
            ),
        }
    }

    #[cfg(test)]
    async fn send_probe(&self, peer_id: Option<&str>, peer_addr: SocketAddr) -> Result<ProbeNonce> {
        let socket_index = self.socket_index_for_peer(peer_id).await;
        self.send_probe_from_socket_with_nomination(
            socket_index,
            peer_id,
            peer_addr,
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
    }

    async fn send_probe_from_socket(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
    ) -> Result<ProbeNonce> {
        self.send_probe_from_socket_with_nomination(
            socket_index,
            peer_id,
            peer_addr,
            false,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await
    }

    async fn send_probe_from_socket_with_nomination(
        &self,
        socket_index: usize,
        peer_id: Option<&str>,
        peer_addr: SocketAddr,
        use_candidate: bool,
        purpose: PendingProbePurpose,
    ) -> Result<ProbeNonce> {
        let socket = self
            .active_sockets()
            .get(socket_index)
            .cloned()
            .ok_or_else(|| {
                DaemonError::Network(format!(
                    "UDP socket pool member {socket_index} is unavailable"
                ))
            })?;
        let generation = self.peers.current_network_generation().await;
        let authenticated_probe = match (peer_id, self.local_node_id.as_deref()) {
            (Some(peer_id), Some(local_node_id))
                if local_node_id.len() <= u8::MAX as usize && peer_id.len() <= u8::MAX as usize =>
            {
                self.peers.probe_key_for_peer(peer_id).await.map(|key| {
                    let (bytes, nonce) = build_authenticated_punch_packet_with_nomination(
                        local_node_id,
                        peer_id,
                        generation,
                        use_candidate,
                        &key,
                    );
                    (bytes, nonce)
                })
            }
            _ => None,
        };

        let (bytes, nonce, accepts_authenticated_ack, compat_legacy_probe) =
            if let Some((bytes, nonce)) = authenticated_probe {
                // Compatibility bridge for pre-v2 peers. v0.1.24 and older only
                // understand PNCH v1 and otherwise forward PNCH v2 into the
                // WireGuard parser, producing "invalid message type: 80".
                // Send a legacy probe with the same nonce so either ACK form clears
                // the same pending probe without weakening the v2 path between
                // upgraded peers.
                (
                    bytes,
                    nonce,
                    true,
                    Some(build_punch_packet_with_nonce(nonce).to_vec()),
                )
            } else {
                let bytes = build_punch_packet();
                let nonce = decode_punch_packet(&bytes)
                    .map(|packet| packet.nonce)
                    .ok_or_else(|| {
                        DaemonError::Network("failed to create UDP probe".to_string())
                    })?;
                (bytes.to_vec(), nonce, false, None)
            };

        {
            let mut pending = self.pending_probes.lock().await;
            pending.retain(|_, pending| {
                pending.sent_at.elapsed() < Duration::from_secs(60)
                    && pending.generation == generation
            });
            pending.insert(
                nonce,
                PendingProbe {
                    sent_at: Instant::now(),
                    endpoint: peer_addr,
                    local_endpoint: socket.local_addr().ok(),
                    socket_index,
                    generation,
                    peer_id: peer_id.map(str::to_string),
                    purpose,
                    accepts_authenticated_ack,
                    accepts_legacy_ack: true,
                },
            );
        }

        if let Err(error) = socket.send_to(&bytes, peer_addr).await {
            self.pending_probes.lock().await.remove(&nonce);
            return Err(DaemonError::Network(format!(
                "UDP probe send to {peer_addr} failed: {error}"
            )));
        }

        self.update_socket_diagnostics(socket_index, |metrics| metrics.probes_sent += 1)
            .await;

        if let Some(legacy_probe) = compat_legacy_probe.clone() {
            match socket.send_to(&legacy_probe, peer_addr).await {
                Ok(_) => {
                    self.update_socket_diagnostics(socket_index, |metrics| {
                        metrics.probes_sent += 1
                    })
                    .await;
                    trace!(
                        "Sent compatibility legacy UDP punch probe to peer {} at {}",
                        peer_id.unwrap_or("unknown"),
                        peer_addr
                    );
                    self.retransmit_probe_burst(
                        socket.clone(),
                        legacy_probe,
                        peer_addr,
                        peer_id.map(str::to_string),
                    );
                }
                Err(err) => {
                    debug!(
                        "Failed to send compatibility legacy UDP punch probe to peer {} at {}: {}",
                        peer_id.unwrap_or("unknown"),
                        peer_addr,
                        err
                    );
                }
            }
        }

        self.retransmit_probe_burst(socket, bytes, peer_addr, peer_id.map(str::to_string));
        Ok(nonce)
    }

    /// Send an authenticated ICE-style nominated connectivity check for a direct trial.
    pub async fn send_nomination_probe(&self, peer_id: &str, peer_addr: SocketAddr) -> Result<()> {
        let socket_index = self.socket_index_for_peer(Some(peer_id)).await;
        self.send_probe_from_socket_with_nomination(
            socket_index,
            Some(peer_id),
            peer_addr,
            true,
            PendingProbePurpose::ConnectivityCheck,
        )
        .await?;
        Ok(())
    }

    fn retransmit_probe_burst(
        &self,
        socket: Arc<UdpSocket>,
        probe: Vec<u8>,
        peer_addr: SocketAddr,
        peer_id: Option<String>,
    ) {
        let peer_label = peer_id.unwrap_or_else(|| peer_addr.to_string());
        tokio::spawn(async move {
            for delay_ms in PUNCH_PROBE_RETRANSMIT_DELAYS_MS {
                sleep(Duration::from_millis(delay_ms)).await;
                match socket.send_to(&probe, peer_addr).await {
                    Ok(_) => trace!(
                        "Retransmitted UDP punch probe to peer {} at {} after {}ms",
                        peer_label,
                        peer_addr,
                        delay_ms
                    ),
                    Err(err) => {
                        debug!(
                            "Failed to retransmit UDP punch probe to peer {} at {} after {}ms: {}",
                            peer_label, peer_addr, delay_ms, err
                        );
                        break;
                    }
                }
            }
        });
    }

    async fn send_punch_ack_burst(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        ack: Vec<u8>,
        source: SocketAddr,
        peer_label: impl Into<String>,
    ) -> std::io::Result<()> {
        socket.send_to(&ack, source).await?;
        self.update_socket_diagnostics(socket_index, |metrics| metrics.probe_acks_sent += 1)
            .await;

        let peer_label = peer_label.into();
        tokio::spawn(async move {
            for delay_ms in PUNCH_ACK_RETRANSMIT_DELAYS_MS {
                sleep(Duration::from_millis(delay_ms)).await;
                match socket.send_to(&ack, source).await {
                    Ok(_) => trace!(
                        "Retransmitted UDP punch ACK to peer {} at {} after {}ms",
                        peer_label,
                        source,
                        delay_ms
                    ),
                    Err(err) => {
                        debug!(
                            "Failed to retransmit UDP punch ACK to peer {} at {} after {}ms: {}",
                            peer_label, source, delay_ms, err
                        );
                        break;
                    }
                }
            }
        });
        Ok(())
    }

    /// Return the local UDP socket address.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| DaemonError::Network(format!("failed to read UDP local addr: {e}")))
    }

    /// Gather ICE-style candidate endpoints for this UDP socket.
    pub async fn gather_candidates(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<Vec<String>> {
        let report = self
            .gather_candidate_report(stun_servers, stun_timeout)
            .await?;

        Ok(report
            .candidates
            .into_iter()
            .map(|candidate| candidate.endpoint.to_string())
            .collect())
    }

    /// Gather ICE-style candidates plus STUN/NAT behavior diagnostics.
    pub async fn gather_candidate_report(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        let config = IceConfig {
            stun_servers,
            stun_timeout,
            gather_host: true,
            gather_srflx: true,
        };

        let mut report = gather_candidate_report(&self.socket, &config)
            .await
            .map_err(|e| DaemonError::Network(format!("ICE candidate gathering failed: {e}")))?;

        self.set_socket_pool_active(socket_pool_is_eligible(&report));
        self.append_pool_socket_candidates_direct(&mut report, &config)
            .await;
        Ok(report)
    }

    /// Gather candidates while `run_inbound` owns all reads from the UDP socket.
    pub async fn gather_candidate_report_live(
        &self,
        stun_servers: Vec<SocketAddr>,
        stun_timeout: Duration,
    ) -> Result<CandidateGatherReport> {
        let local_addr = self.local_addr()?;
        let mut observations = Vec::with_capacity(stun_servers.len());

        for server in &stun_servers {
            if server.is_ipv4() != local_addr.is_ipv4() {
                continue;
            }
            observations.push(
                self.query_stun_live_on_socket(&self.socket, *server, stun_timeout)
                    .await,
            );
        }

        let mut report = candidate_report_from_observations(local_addr, true, observations);
        self.set_socket_pool_active(socket_pool_is_eligible(&report));
        self.append_pool_socket_candidates_live(&mut report, &stun_servers, stun_timeout)
            .await;
        Ok(report)
    }

    async fn query_stun_live_on_socket(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
        stun_timeout: Duration,
    ) -> StunObservation {
        let started = Instant::now();
        let mut request = StunMessage::binding_request();
        request.add_attribute(StunAttribute::Software("P2WLAN/0.1".to_string()));
        let transaction_id = request.transaction_id;
        let encoded = request.encode();
        let (response_tx, response_rx) = oneshot::channel();

        self.stun_waiters
            .lock()
            .await
            .insert(transaction_id, response_tx);

        let result = async {
            socket
                .send_to(&encoded, server)
                .await
                .map_err(|error| format!("send_to failed: {error}"))?;
            let (data, source) = timeout(stun_timeout, response_rx)
                .await
                .map_err(|_| format!("no response from {server} after {stun_timeout:?}"))?
                .map_err(|_| "STUN response dispatcher closed".to_string())?;
            if source != server {
                return Err(format!(
                    "response source mismatch: expected {server}, received {source}"
                ));
            }
            let response = StunMessage::decode(&data)
                .map_err(|error| format!("invalid STUN response: {error}"))?;
            if response.transaction_id != transaction_id {
                return Err("STUN transaction ID mismatch".to_string());
            }
            if response.msg_type != BINDING_RESPONSE {
                if let Some((code, reason)) = response.get_error_code() {
                    return Err(format!("STUN error response: {code} {reason}"));
                }
                return Err(format!(
                    "unexpected STUN message type: 0x{:04X}",
                    response.msg_type
                ));
            }
            response
                .get_reflexive_address()
                .ok_or_else(|| "STUN response has no mapped address".to_string())
        }
        .await;

        self.stun_waiters.lock().await.remove(&transaction_id);
        match result {
            Ok(mapped_address) => StunObservation {
                server: server.to_string(),
                mapped_address: Some(mapped_address.to_string()),
                rtt_ms: Some(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
                error: None,
            },
            Err(error) => StunObservation {
                server: server.to_string(),
                mapped_address: None,
                rtt_ms: None,
                error: Some(error),
            },
        }
    }

    async fn append_pool_socket_candidates_direct(
        &self,
        report: &mut CandidateGatherReport,
        config: &IceConfig,
    ) {
        if !self.socket_pool_active() {
            return;
        }

        let servers = pool_stun_servers(&config.stun_servers, self.local_addr().ok());
        for (socket_index, socket) in self.active_sockets().iter().enumerate().skip(1) {
            let observations = self
                .query_stun_direct(socket, &servers, config.stun_timeout)
                .await;
            let Some(local_addr) = socket.local_addr().ok() else {
                continue;
            };
            let pool_report = candidate_report_from_observations(local_addr, false, observations);
            self.append_pool_candidates(report, pool_report.candidates, socket_index)
                .await;
        }
    }

    async fn append_pool_socket_candidates_live(
        &self,
        report: &mut CandidateGatherReport,
        stun_servers: &[SocketAddr],
        stun_timeout: Duration,
    ) {
        if !self.socket_pool_active() {
            return;
        }

        let servers = pool_stun_servers(stun_servers, self.local_addr().ok());
        for (socket_index, socket) in self.active_sockets().iter().enumerate().skip(1) {
            let mut observations = Vec::with_capacity(servers.len());
            for server in &servers {
                observations.push(
                    self.query_stun_live_on_socket(socket, *server, stun_timeout)
                        .await,
                );
            }
            let Some(local_addr) = socket.local_addr().ok() else {
                continue;
            };
            let pool_report = candidate_report_from_observations(local_addr, false, observations);
            self.append_pool_candidates(report, pool_report.candidates, socket_index)
                .await;
        }
    }

    async fn query_stun_direct(
        &self,
        socket: &UdpSocket,
        servers: &[SocketAddr],
        stun_timeout: Duration,
    ) -> Vec<StunObservation> {
        if socket.local_addr().is_err() {
            return Vec::new();
        }
        let client = StunClient::with_timeout(stun_timeout);
        let mut observations = Vec::with_capacity(servers.len());
        for server in servers {
            let started = Instant::now();
            let observation = match client.binding_request(socket, *server).await {
                Ok(response) => StunObservation {
                    server: server.to_string(),
                    mapped_address: response
                        .reflexive_address
                        .map(|address| address.to_string()),
                    rtt_ms: Some(started.elapsed().as_millis().try_into().unwrap_or(u64::MAX)),
                    error: None,
                },
                Err(error) => StunObservation {
                    server: server.to_string(),
                    mapped_address: None,
                    rtt_ms: None,
                    error: Some(error.to_string()),
                },
            };
            observations.push(observation);
        }
        observations
    }

    async fn append_pool_candidates(
        &self,
        report: &mut CandidateGatherReport,
        candidates: Vec<p2pnet_nat::IceCandidate>,
        socket_index: usize,
    ) {
        let mut added_stun_observed = 0u64;
        for candidate in candidates {
            let is_stun_observed = candidate.source == p2pnet_nat::CandidateSource::StunObserved;
            let endpoint = candidate.endpoint.to_string();
            if report
                .candidates
                .iter()
                .all(|existing| existing.endpoint.to_string() != endpoint)
            {
                report.candidates.push(candidate);
                if is_stun_observed {
                    added_stun_observed += 1;
                }
            }
        }
        if added_stun_observed > 0 {
            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.stun_mappings_discovered = metrics
                    .stun_mappings_discovered
                    .saturating_add(added_stun_observed)
            })
            .await;
        }
    }

    /// Send active UDP probes to every candidate for a peer.
    pub async fn punch_candidates(
        &self,
        peer_id: &str,
        candidates: Vec<SocketAddr>,
        probe_interval: Duration,
        attempts: u32,
    ) -> Result<u32> {
        if candidates.is_empty() || attempts == 0 {
            return Ok(0);
        }

        let schedule = build_probe_schedule(&candidates, probe_interval, attempts);
        trace!(
            "Built adaptive UDP probe schedule for peer {}: {} rounds across {} candidates",
            peer_id,
            schedule.len(),
            candidates.len()
        );

        let mut packets_sent = 0;
        let mut budget_skipped = 0u32;
        let mut last_budget_reason = None;
        for (round_index, round) in schedule.iter().enumerate() {
            if !round.delay_before.is_zero() {
                sleep(round.delay_before).await;
            }

            for &candidate in &round.endpoints {
                // Before a direct path is authenticated, each bounded pool
                // member gets one independently mapped chance at the remote
                // candidate. Once a peer has an affinity, normal sends use
                // that socket rather than changing its NAT mapping.
                for socket_index in 0..self.punch_socket_count() {
                    match self
                        .admit_outbound_connectivity_probe(peer_id, candidate)
                        .await
                    {
                        OutboundProbeAdmission::Accepted => {}
                        OutboundProbeAdmission::NetworkRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("network_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: network probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::PeerRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("peer_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: peer probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::RemoteIpRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("remote_ip_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: remote IP probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalNetworkRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_network_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global network probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalPeerRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_peer_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global peer probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                        OutboundProbeAdmission::GlobalRemoteIpRateLimited => {
                            budget_skipped = budget_skipped.saturating_add(1);
                            last_budget_reason = Some("global_remote_ip_rate_limited");
                            trace!(
                                "Skipped UDP punch probe from socket {} to peer {} candidate {}: global remote IP probe budget exhausted",
                                socket_index, peer_id, candidate
                            );
                            continue;
                        }
                    }

                    match self
                        .send_probe_from_socket(socket_index, Some(peer_id), candidate)
                        .await
                    {
                        Ok(_) => {
                            packets_sent += 1;
                            self.peers
                                .record_direct_probe_sent(peer_id, candidate)
                                .await;
                            trace!(
                                "Sent adaptive punch probe round {} from socket {} to peer {} candidate {}",
                                round_index + 1,
                                socket_index,
                                peer_id,
                                candidate
                            );
                        }
                        Err(err) => {
                            debug!(
                                "Failed to send punch probe from socket {} to peer {} candidate {}: {}",
                                socket_index, peer_id, candidate, err
                            );
                        }
                    }
                }
            }
        }

        if budget_skipped > 0 {
            let reason = last_budget_reason.unwrap_or("probe_budget_limited");
            self.peers
                .record_direct_event(
                    peer_id,
                    "probe_budget_limited",
                    candidates.first().copied(),
                    Some(candidates.len()),
                    Some(packets_sent),
                    format!(
                        "skipped {budget_skipped} UDP punch probes due to outbound {reason}; sent {packets_sent}"
                    ),
                )
                .await;
        }

        Ok(packets_sent)
    }

    /// Send a single encrypted packet.
    ///
    /// Returns `Ok(Some(bytes))` when sent, `Ok(None)` when no endpoint is known
    /// for the destination peer, and `Err` for socket-level failures.
    pub async fn send_packet(&self, packet: &EncryptedPeerPacket) -> Result<Option<usize>> {
        let Some(endpoint) = self.peers.direct_endpoint_for_send(&packet.peer_id).await else {
            trace!(
                "No UDP endpoint for {}; dropping {} byte encrypted packet",
                packet.peer_id,
                packet.wire_bytes.len()
            );
            return Ok(None);
        };

        self.send_packet_to(packet, endpoint).await.map(Some)
    }

    /// Send a single encrypted packet to a selector-provided direct endpoint.
    pub async fn send_packet_to(
        &self,
        packet: &EncryptedPeerPacket,
        endpoint: SocketAddr,
    ) -> Result<usize> {
        let socket_index = self.socket_index_for_peer(Some(&packet.peer_id)).await;
        let socket = self
            .active_sockets()
            .get(socket_index)
            .cloned()
            .unwrap_or_else(|| self.socket.clone());
        let sent = socket
            .send_to(&packet.wire_bytes, endpoint)
            .await
            .map_err(|e| {
                DaemonError::Network(format!(
                    "UDP send to {} for peer {} failed: {}",
                    endpoint, packet.peer_id, e
                ))
            })?;

        if sent != packet.wire_bytes.len() {
            return Err(DaemonError::Network(format!(
                "short UDP send to {} for peer {}: sent {} of {} bytes",
                endpoint,
                packet.peer_id,
                sent,
                packet.wire_bytes.len()
            )));
        }

        self.update_socket_diagnostics(socket_index, |metrics| metrics.encrypted_packets_sent += 1)
            .await;

        debug!(
            "Sent {} encrypted bytes to peer {} at {} (dst={})",
            sent, packet.peer_id, endpoint, packet.dst_ip
        );
        Ok(sent)
    }

    /// Consume encrypted packets until the channel closes.
    pub async fn run_outbound(self, mut encrypted_rx: mpsc::Receiver<EncryptedPeerPacket>) {
        while let Some(packet) = encrypted_rx.recv().await {
            match self.send_packet(&packet).await {
                Ok(Some(_)) => {}
                Ok(None) => {
                    debug!(
                        "Encrypted packet for peer {} has no UDP endpoint yet",
                        packet.peer_id
                    );
                }
                Err(err) => {
                    warn!("UDP transport send failed: {err}");
                }
            }
        }
    }

    /// Periodically refresh direct UDP NAT mappings.
    pub async fn run_keepalives(self, keepalive_interval: Duration) {
        if keepalive_interval.is_zero() {
            return;
        }

        let mut ticker = interval(keepalive_interval);
        loop {
            ticker.tick().await;

            self.run_keepalive_round(DIRECT_KEEPALIVE_ACK_TIMEOUT).await;
        }
    }

    async fn run_keepalive_round(&self, ack_timeout: Duration) {
        let mut sent = Vec::new();

        for (peer_id, endpoint) in self.peers.direct_endpoints().await {
            let socket_index = self.socket_index_for_peer(Some(&peer_id)).await;
            match self
                .send_probe_from_socket_with_nomination(
                    socket_index,
                    Some(&peer_id),
                    endpoint,
                    false,
                    PendingProbePurpose::ConsentCheck,
                )
                .await
            {
                Ok(nonce) => {
                    let local_endpoint = self
                        .pending_probes
                        .lock()
                        .await
                        .get(&nonce)
                        .and_then(|pending| pending.local_endpoint);
                    self.peers
                        .record_direct_event(
                            &peer_id,
                            "consent_check_sent",
                            Some(endpoint),
                            Some(1),
                            Some(1),
                            format!(
                                "sent direct UDP consent check to {endpoint} local_endpoint={}",
                                format_optional_endpoint(local_endpoint)
                            ),
                        )
                        .await;
                    trace!("Sent direct UDP keepalive to peer {peer_id} at {endpoint}");
                    sent.push((peer_id, endpoint, nonce));
                }
                Err(err) => {
                    self.peers
                        .record_direct_failure_with_code(
                            &peer_id,
                            REASON_DIRECT_SEND_FAILED,
                            format!("direct keepalive to {endpoint} failed: {err}"),
                        )
                        .await;
                    debug!(
                        "Failed to send direct UDP keepalive to peer {peer_id} at {endpoint}: {err}"
                    );
                }
            }
        }

        if sent.is_empty() {
            return;
        }

        sleep(ack_timeout).await;
        for (peer_id, endpoint, nonce) in sent {
            let unanswered = self.pending_probes.lock().await.remove(&nonce);
            let Some(pending) = unanswered else {
                continue;
            };
            if pending.peer_id.as_deref() != Some(peer_id.as_str()) || pending.endpoint != endpoint
            {
                continue;
            }
            if pending.purpose == PendingProbePurpose::ConsentCheck {
                self.peers
                    .record_direct_event(
                        &peer_id,
                        "consent_timeout",
                        Some(endpoint),
                        Some(1),
                        None,
                        format!(
                            "direct UDP consent ACK timed out for {endpoint} local_endpoint={}",
                            format_optional_endpoint(pending.local_endpoint)
                        ),
                    )
                    .await;
            }

            if self
                .peers
                .record_direct_keepalive_timeout_for_generation_with_local_endpoint(
                    &peer_id,
                    endpoint,
                    pending.generation,
                    pending.local_endpoint,
                )
                .await
            {
                debug!("Direct UDP keepalive ACK timed out for peer {peer_id} at {endpoint}");
            }
        }
    }

    /// Receive encrypted UDP datagrams until the socket or channel closes.
    pub async fn run_inbound(
        self,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        let sockets = self.active_sockets().to_vec();
        let mut readers = JoinSet::new();
        for (socket_index, socket) in sockets.into_iter().enumerate() {
            let transport = self.clone();
            let inbound_tx = inbound_tx.clone();
            readers.spawn(async move {
                transport
                    .run_inbound_socket(socket_index, socket, inbound_tx)
                    .await
            });
        }

        match readers.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(DaemonError::Network(format!(
                "UDP socket reader task failed: {error}"
            ))),
            None => Ok(()),
        }
    }

    async fn run_inbound_socket(
        &self,
        socket_index: usize,
        socket: Arc<UdpSocket>,
        inbound_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    ) -> Result<()> {
        let mut buf = vec![0u8; 65_535];

        loop {
            let (n, source) = match socket.recv_from(&mut buf).await {
                Ok(packet) => packet,
                Err(err) if is_ignorable_udp_receive_error(&err) => {
                    debug!("Ignoring transient UDP receive error on direct transport: {err}");
                    continue;
                }
                Err(err) => {
                    return Err(DaemonError::Network(format!(
                        "UDP receive on direct transport failed: {err}"
                    )));
                }
            };

            if n == 0 {
                continue;
            }

            let data = &buf[..n];

            if let Some(transaction_id) = stun_transaction_id(data) {
                let waiter = self.stun_waiters.lock().await.remove(&transaction_id);
                if let Some(waiter) = waiter {
                    let _ = waiter.send((data.to_vec(), source));
                } else {
                    trace!("Ignored unmatched STUN response from {source}");
                }
                continue;
            }

            if is_authenticated_punch_candidate(data) {
                let Some(identity) = peek_authenticated_punch_identity(data) else {
                    trace!("Ignored malformed authenticated UDP probe from {source}");
                    continue;
                };
                let Some(local_node_id) = self.local_node_id.as_deref() else {
                    trace!(
                        "Ignored authenticated UDP probe from {source}; local node ID is unknown"
                    );
                    continue;
                };
                if identity.target_node_id != local_node_id {
                    trace!(
                        "Ignored authenticated UDP probe from {} for target {}",
                        identity.source_node_id,
                        identity.target_node_id
                    );
                    continue;
                }
                let keys = self
                    .peers
                    .probe_keys_for_peer(&identity.source_node_id)
                    .await;
                if keys.is_empty() {
                    trace!(
                        "Ignored authenticated UDP probe from {}; no Probe v2 MAC key",
                        identity.source_node_id
                    );
                    continue;
                }
                let Some((packet, key)) = keys.into_iter().find_map(|key| {
                    decode_authenticated_punch_packet(data, &key).map(|packet| (packet, key))
                }) else {
                    trace!(
                        "Ignored authenticated UDP probe from {}; invalid MAC",
                        identity.source_node_id
                    );
                    continue;
                };

                match packet.kind {
                    PunchPacketKind::Punch => {
                        match self
                            .admit_authenticated_punch(
                                &identity.source_node_id,
                                packet.generation.unwrap_or(identity.generation),
                                packet.kind,
                                packet.nonce,
                                source,
                            )
                            .await
                        {
                            AuthenticatedPunchAdmission::Accepted => {}
                            AuthenticatedPunchAdmission::Replay => {
                                let generation = self.peers.current_network_generation().await;
                                let ack = build_authenticated_punch_ack(
                                    packet.nonce,
                                    local_node_id,
                                    &identity.source_node_id,
                                    generation,
                                    &key,
                                );
                                match socket.send_to(&ack, source).await {
                                    Ok(_) => {
                                        self.update_socket_diagnostics(socket_index, |metrics| {
                                            metrics.probe_acks_sent += 1
                                        })
                                        .await;
                                        trace!(
                                            "ACKed replayed authenticated UDP punch from peer {} at {} without mutating candidate state",
                                            identity.source_node_id, source
                                        );
                                    }
                                    Err(err) => debug!(
                                        "Failed to ACK replayed authenticated UDP punch from peer {} at {}: {}",
                                        identity.source_node_id, source, err
                                    ),
                                }
                                continue;
                            }
                            AuthenticatedPunchAdmission::RateLimited => {
                                debug!(
                                    "Rate-limited authenticated UDP punch from peer {} at {}",
                                    identity.source_node_id, source
                                );
                                continue;
                            }
                        }

                        let learned = self
                            .peers
                            .learn_authenticated_endpoint(&identity.source_node_id, source)
                            .await;
                        if !learned {
                            trace!(
                                "Ignored authenticated UDP punch from {}; peer disappeared before endpoint learning",
                                identity.source_node_id
                            );
                            continue;
                        }
                        self.peers
                            .record_direct_probe_success_with_local_endpoint(
                                &identity.source_node_id,
                                source,
                                socket.local_addr().ok(),
                            )
                            .await;
                        if packet.use_candidate {
                            self.peers
                                .record_direct_nomination_check_with_local_endpoint(
                                    &identity.source_node_id,
                                    source,
                                    socket.local_addr().ok(),
                                )
                                .await;
                        }
                        self.remember_peer_socket(&identity.source_node_id, socket_index)
                            .await;
                        self.notify_peer_reflexive_observation(&identity.source_node_id, source)
                            .await;

                        let generation = self.peers.current_network_generation().await;
                        let ack = build_authenticated_punch_ack(
                            packet.nonce,
                            local_node_id,
                            &identity.source_node_id,
                            generation,
                            &key,
                        );
                        match self
                            .send_punch_ack_burst(
                                socket_index,
                                socket.clone(),
                                ack,
                                source,
                                identity.source_node_id.clone(),
                            )
                            .await
                        {
                            Ok(()) => {
                                debug!(
                                    "Received authenticated UDP punch from peer {} at {}; sent ACK burst",
                                    identity.source_node_id, source
                                );
                                self.trigger_peer_reflexive_check(
                                    socket_index,
                                    &identity.source_node_id,
                                    source,
                                )
                                .await;
                            }
                            Err(err) => warn!(
                                "Failed to ACK authenticated UDP punch from peer {} at {}: {}",
                                identity.source_node_id, source, err
                            ),
                        }
                    }
                    PunchPacketKind::Ack => {
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending_probes = self.pending_probes.lock().await;
                            let matched = pending_probes
                                .get(&packet.nonce)
                                .filter(|pending| {
                                    pending.generation == generation
                                        && pending.socket_index == socket_index
                                        && pending.peer_id.as_deref()
                                            == Some(identity.source_node_id.as_str())
                                        && pending.accepts_authenticated_ack
                                })
                                .map(|pending| {
                                    (
                                        pending.sent_at.elapsed(),
                                        pending.generation,
                                        pending.local_endpoint,
                                        pending.purpose,
                                    )
                                });
                            if matched.is_some() {
                                pending_probes.remove(&packet.nonce);
                            }
                            matched
                        };

                        if let Some((latency, generation, local_endpoint, purpose)) = ack_match {
                            self.update_socket_diagnostics(socket_index, |metrics| {
                                metrics.probe_acks_received += 1
                            })
                            .await;
                            self.remember_peer_socket(&identity.source_node_id, socket_index)
                                .await;
                            self.peers
                                .learn_authenticated_endpoint(&identity.source_node_id, source)
                                .await;
                            self.notify_peer_reflexive_observation(
                                &identity.source_node_id,
                                source,
                            )
                            .await;
                            let accepted = self
                                .peers
                                .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
                                    &identity.source_node_id,
                                    source,
                                    Some(latency),
                                    generation,
                                    local_endpoint,
                                )
                                .await;
                            if accepted {
                                if purpose == PendingProbePurpose::ConsentCheck {
                                    self.peers
                                        .record_direct_event(
                                            &identity.source_node_id,
                                            "consent_ack_received",
                                            Some(source),
                                            Some(1),
                                            None,
                                            format!(
                                                "received direct UDP consent ACK from {source} rtt={}ms local_endpoint={}",
                                                latency.as_millis(),
                                                format_optional_endpoint(local_endpoint)
                                            ),
                                        )
                                        .await;
                                }
                                debug!(
                                    "Received authenticated UDP punch ACK from peer {} at {} (rtt={latency:?})",
                                    identity.source_node_id, source
                                );
                            } else {
                                trace!(
                                    "Ignored stale authenticated UDP punch ACK from peer {} at {}",
                                    identity.source_node_id,
                                    source
                                );
                            }
                        } else {
                            trace!(
                                "Ignored unmatched authenticated UDP punch ACK from peer {} at {}",
                                identity.source_node_id,
                                source
                            );
                        }
                    }
                }
                continue;
            }

            if let Some(packet) = decode_punch_packet(data) {
                match packet.kind {
                    PunchPacketKind::Punch => {
                        let ack = build_punch_ack(packet.nonce).to_vec();
                        match self
                            .send_punch_ack_burst(
                                socket_index,
                                socket.clone(),
                                ack,
                                source,
                                source.to_string(),
                            )
                            .await
                        {
                            Ok(()) => {
                                debug!("Received UDP punch from {source}; sent ACK burst");
                                if let Some(peer_id) =
                                    self.peers.learn_endpoint_from_addr(source).await
                                {
                                    self.peers
                                        .record_direct_probe_success_with_local_endpoint(
                                            &peer_id,
                                            source,
                                            socket.local_addr().ok(),
                                        )
                                        .await;
                                    self.remember_peer_socket(&peer_id, socket_index).await;
                                    self.notify_peer_reflexive_observation(&peer_id, source)
                                        .await;
                                    self.trigger_peer_reflexive_check(
                                        socket_index,
                                        &peer_id,
                                        source,
                                    )
                                    .await;
                                    debug!(
                                        "Recorded direct UDP probe success from peer {peer_id} at {source}"
                                    );
                                }
                            }
                            Err(err) => warn!("Failed to ACK UDP punch from {source}: {err}"),
                        }
                    }
                    PunchPacketKind::Ack => {
                        let ack_match = {
                            let generation = self.peers.current_network_generation().await;
                            let mut pending_probes = self.pending_probes.lock().await;
                            let matched = pending_probes
                                .get(&packet.nonce)
                                .filter(|pending| {
                                    legacy_ack_matches_pending(
                                        pending,
                                        source,
                                        generation,
                                        socket_index,
                                    )
                                })
                                .map(|pending| {
                                    (
                                        pending.sent_at.elapsed(),
                                        pending.generation,
                                        pending.peer_id.clone(),
                                        pending.local_endpoint,
                                        pending.purpose,
                                    )
                                });
                            if matched.is_some() {
                                pending_probes.remove(&packet.nonce);
                            }
                            matched
                        };
                        let pending_peer_id = ack_match
                            .as_ref()
                            .and_then(|(_, _, peer_id, _, _)| peer_id.clone());
                        let peer_id = match pending_peer_id.as_ref() {
                            Some(peer_id) => {
                                self.peers
                                    .learn_correlated_probe_endpoint(peer_id, source)
                                    .await;
                                Some(peer_id.clone())
                            }
                            None => self.peers.learn_endpoint_from_addr(source).await,
                        };
                        if let Some(peer_id) = peer_id {
                            if let Some((latency, generation, _, local_endpoint, purpose)) =
                                ack_match
                            {
                                self.update_socket_diagnostics(socket_index, |metrics| {
                                    metrics.probe_acks_received += 1
                                })
                                .await;
                                self.remember_peer_socket(&peer_id, socket_index).await;
                                self.notify_peer_reflexive_observation(&peer_id, source)
                                    .await;
                                let accepted = self
                                    .peers
                                    .record_direct_probe_success_with_latency_for_generation_and_local_endpoint(
                                        &peer_id,
                                        source,
                                        Some(latency),
                                        generation,
                                        local_endpoint,
                                    )
                                    .await;
                                if accepted {
                                    if purpose == PendingProbePurpose::ConsentCheck {
                                        self.peers
                                            .record_direct_event(
                                                &peer_id,
                                                "consent_ack_received",
                                                Some(source),
                                                Some(1),
                                                None,
                                                format!(
                                                    "received direct UDP consent ACK from {source} rtt={}ms local_endpoint={}",
                                                    latency.as_millis(),
                                                    format_optional_endpoint(local_endpoint)
                                                ),
                                            )
                                            .await;
                                    }
                                    debug!(
                                        "Received UDP punch ACK from peer {peer_id} at {source} (rtt={latency:?})"
                                    );
                                } else {
                                    trace!(
                                        "Ignored stale UDP punch ACK from peer {peer_id} at {source}"
                                    );
                                }
                            } else {
                                trace!("Ignored stale or unmatched UDP punch ACK from {source}");
                            }
                        } else {
                            trace!("Received UDP punch ACK from unknown candidate {source}");
                        }
                    }
                }
                continue;
            }

            if let Some(peer_id) = self.peers.learn_endpoint_from_addr(source).await {
                self.remember_peer_socket(&peer_id, socket_index).await;
                trace!("Learned encrypted UDP source {source} for peer {peer_id}");
            }

            self.update_socket_diagnostics(socket_index, |metrics| {
                metrics.encrypted_packets_received += 1
            })
            .await;

            inbound_tx
                .send(ReceivedEncryptedPacket {
                    source: Some(source),
                    local_endpoint: socket.local_addr().ok(),
                    relay_endpoint: None,
                    relay_peer_id: None,
                    wire_bytes: data.to_vec(),
                })
                .await
                .map_err(|_| {
                    DaemonError::Network("received encrypted packet channel closed".to_string())
                })?;

            debug!("Received {n} encrypted UDP bytes from {source}");
        }
    }
}

fn socket_pool_is_eligible(report: &CandidateGatherReport) -> bool {
    report.nat_profile.mapping_behavior == MappingBehavior::AddressOrPortDependent
        && !report.nat_profile.udp_blocked
}

fn pool_stun_servers(
    stun_servers: &[SocketAddr],
    local_addr: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let Some(local_addr) = local_addr else {
        return Vec::new();
    };
    stun_servers
        .iter()
        .copied()
        .filter(|server| server.is_ipv4() == local_addr.is_ipv4())
        .take(SOCKET_POOL_STUN_OBSERVERS_PER_SOCKET)
        .collect()
}

fn is_ignorable_udp_receive_error(error: &std::io::Error) -> bool {
    #[cfg(target_os = "windows")]
    {
        error.raw_os_error() == Some(10054) || error.kind() == std::io::ErrorKind::ConnectionReset
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = error;
        false
    }
}

fn is_authenticated_punch_candidate(data: &[u8]) -> bool {
    data.len() >= 5 && data.starts_with(&[0x50, 0x4e, 0x43, 0x48]) && data[4] == 2
}

fn stun_transaction_id(data: &[u8]) -> Option<StunTransactionId> {
    if data.len() < 20 || data[0] & 0xc0 != 0 {
        return None;
    }
    if u32::from_be_bytes(data[4..8].try_into().ok()?) != MAGIC_COOKIE {
        return None;
    }
    let declared_len = u16::from_be_bytes(data[2..4].try_into().ok()?) as usize;
    if data.len() < 20 + declared_len {
        return None;
    }
    data[8..20].try_into().ok()
}

#[cfg(test)]
#[path = "udp/tests.rs"]
mod tests;
