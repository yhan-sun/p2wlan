type ProbeNonce = [u8; 8];
type PendingProbes = Arc<Mutex<HashMap<ProbeNonce, PendingProbe>>>;
type StunTransactionId = [u8; 12];
type StunResponse = (Vec<u8>, SocketAddr);
type StunWaiters = Arc<Mutex<HashMap<StunTransactionId, oneshot::Sender<StunResponse>>>>;
type PeerReflexiveNotificationState = Arc<Mutex<HashMap<(String, SocketAddr), Instant>>>;
type TriggeredCheckState = Arc<Mutex<HashMap<(String, SocketAddr, usize), Instant>>>;
type NatMaintainerState = Arc<Mutex<HashMap<(String, SocketAddr), Instant>>>;
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
/// Pace connectivity checks below the per-peer/public-IP admission ceiling.
/// A large symmetric-NAT sweep must cover the full candidate window instead
/// of consuming its one-second budget in one burst and dropping the tail.
#[cfg(not(test))]
const OUTBOUND_CONNECTIVITY_PROBE_SPACING: Duration = Duration::from_millis(6);
#[cfg(test)]
const OUTBOUND_CONNECTIVITY_PROBE_SPACING: Duration = Duration::ZERO;
/// Hard bound on primary connectivity-check datagrams emitted by one punch
/// session. Retransmissions are reserved for nomination and consent checks.
const MAX_PUNCH_PROBES_PER_SESSION: u32 = 512;
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
    /// Single-socket NAT-state maintainer probes sent from this socket.
    pub nat_maintainer_probes_sent: u64,
    /// NAT-state maintainer probes skipped by the outbound admission budget.
    pub nat_maintainer_probe_skips: u64,
    /// Nomination/consent probe retransmissions sent from this socket.
    pub probe_retransmissions_sent: u64,
    /// Punch ACKs sent from this socket after receiving a probe.
    pub probe_acks_sent: u64,
    /// Punch ACK retransmissions sent from this socket.
    pub probe_ack_retransmissions_sent: u64,
    /// Matching punch ACKs received on this socket.
    pub probe_acks_received: u64,
    /// UDP datagrams received on this socket, including STUN and data traffic.
    pub datagrams_received: u64,
    /// Datagrams carrying the authenticated Probe v2 framing.
    pub authenticated_probe_packets_received: u64,
    /// Probe v2 frames rejected because their MAC did not match.
    pub authenticated_probe_invalid_mac: u64,
    /// Probe v2 frames addressed to another local node ID.
    pub authenticated_probe_wrong_target: u64,
    /// Probe v2 frames rejected before a peer key was available.
    pub authenticated_probe_no_key: u64,
    /// Probe v2-looking datagrams whose authenticated header was malformed.
    pub authenticated_probe_malformed: u64,
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
enum PunchSocketPolicy {
    ActivePool,
    RemoteScatterPool,
    PrimaryOnly,
}

impl PunchSocketPolicy {
    fn socket_count(self, transport: &UdpTransport) -> usize {
        match self {
            Self::ActivePool => transport.punch_socket_count(),
            Self::RemoteScatterPool => transport.socket_count(),
            Self::PrimaryOnly => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ActivePool => "active_pool",
            Self::RemoteScatterPool => "remote_scatter_pool",
            Self::PrimaryOnly => "primary_only",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpProbeRxSnapshot {
    pub authenticated_probe_packets_received: u64,
    pub probe_acks_received: u64,
}

impl UdpProbeRxSnapshot {
    pub fn delta_since(self, earlier: Self) -> Self {
        Self {
            authenticated_probe_packets_received: self
                .authenticated_probe_packets_received
                .saturating_sub(earlier.authenticated_probe_packets_received),
            probe_acks_received: self
                .probe_acks_received
                .saturating_sub(earlier.probe_acks_received),
        }
    }
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
            let width = if round == 0 || attempts == 1 || is_final_round {
                unique.len()
            } else {
                match round {
                    1 => unique.len().min(24),
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
