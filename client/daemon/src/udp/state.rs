type ProbeNonce = [u8; 8];
type PendingProbes = Arc<Mutex<HashMap<ProbeNonce, PendingProbe>>>;
type StunTransactionId = [u8; 12];
type StunResponse = (Vec<u8>, SocketAddr);
type StunWaiters = Arc<Mutex<HashMap<StunTransactionId, oneshot::Sender<StunResponse>>>>;
type PeerReflexiveNotificationState = Arc<Mutex<HashMap<(String, SocketAddr), Instant>>>;
type TriggeredCheckState = Arc<Mutex<HashMap<(String, SocketAddr, usize), Instant>>>;
type NatMaintainerKey = (String, SocketAddr, usize);
type NatMaintainerState = Arc<Mutex<HashMap<NatMaintainerKey, NatMaintainerLease>>>;
type AuthPunchReplayKey = (String, u64, ProbeNonce, u8);
type AuthPunchReplayState = Arc<Mutex<HashMap<AuthPunchReplayKey, Instant>>>;
type AuthPunchRateState = Arc<Mutex<HashMap<(String, SocketAddr), VecDeque<Instant>>>>;
type DynamicSocketIndex = usize;
type DynamicSocketState = Arc<Mutex<HashMap<DynamicSocketIndex, DynamicPunchSocket>>>;

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
/// Hard bound for the easy-side remote-port scatter sweep.
///
/// When the peer has an address/port-dependent mapping, the stable side must
/// cover a much wider peer-port window while the hard-NAT side keeps one
/// destination-specific binding warm.  The one-second outbound budgets still
/// pace this over time; this cap only prevents the session from stopping after
/// the first few hundred ports.
const MAX_REMOTE_SCATTER_PUNCH_PROBES_PER_SESSION: u32 = 3_072;
/// Two STUN observers per experimental socket are enough to publish that
/// socket's observed mapping and infer a small per-socket port-delta prediction
/// window without turning the bounded traversal experiment into a large STUN
/// burst. The primary socket still uses the complete configured observer set
/// for NAT profiling.
const SOCKET_POOL_STUN_OBSERVERS_PER_SOCKET: usize = 2;

/// Fresh punch sockets are indexed from this base so their indices never
/// collide with the fixed pool sockets (0..socket_count).
pub(crate) const DYNAMIC_SOCKET_INDEX_BASE: usize = 4096;
/// Maximum concurrent dynamic punch sockets across all peers.
pub(crate) const MAX_DYNAMIC_PUNCH_SOCKETS: usize = 8;
/// How long a measured mapping model stays trustworthy before the next punch
/// generation must re-measure.
pub(crate) const FRESH_MAPPING_MODEL_MAX_AGE: Duration = Duration::from_millis(2_500);
/// Per-sample STUN timeout for fresh-mapping measurements.  Kept far below the
/// normal STUN timeout so the measure-then-punch flow stays inside the
/// synchronized NAT opening window.
pub(crate) const FRESH_MAPPING_STUN_TIMEOUT: Duration = Duration::from_millis(350);
/// Number of distinct STUN observers contacted per fresh mapping batch.
pub(crate) const FRESH_MAPPING_OBSERVERS_PER_BATCH: usize = 4;
/// Hard budget for the whole measurement phase.
pub(crate) const FRESH_MAPPING_MEASURE_BUDGET: Duration = Duration::from_millis(1_200);
/// Deltas further apart than this never form a linear model.
pub(crate) const FRESH_MAPPING_MAX_ABS_STEP: i16 = 2_048;

/// One dedicated punch socket owned by a per-peer fresh-mapping generation.
///
/// The socket is bound fresh for the generation, measures the NAT port
/// sequence through several distinct STUN observers in send order, and then
/// carries the authenticated punch that creates the peer-facing mapping.  On
/// Direct confirmation the same socket continues as the peer's data path
/// socket (`peer_socket_affinity`), so the confirmed mapping is never
/// abandoned for a different socket.
#[derive(Debug)]
pub(crate) struct DynamicPunchSocket {
    pub(crate) socket_index: usize,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) peer_id: String,
    pub(crate) network_generation: u64,
    pub(crate) punch_generation: u64,
    pub(crate) created_at: Instant,
    pub(crate) shutdown_tx: watch::Sender<bool>,
    pub(crate) reader: tokio::task::JoinHandle<()>,
}

impl DynamicPunchSocket {
    pub(crate) fn local_endpoint(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }
}

/// Outcome of one fresh-mapping punch generation.
#[derive(Debug, Clone)]
pub(crate) enum FreshMappingOutcome {
    /// The generation measured, modeled and punched successfully.
    Accepted(Box<FreshMappingResult>),
    /// The generation could not produce a trustworthy prediction and the
    /// caller must fall back to the legacy punch strategy.
    Rejected(FreshMappingRejection),
}

/// A successful fresh-mapping generation result.
#[derive(Debug, Clone)]
pub(crate) struct FreshMappingResult {
    /// Per-peer punch generation counter.
    pub(crate) punch_generation: u64,
    /// Network generation the measurement ran in.
    pub(crate) network_generation: u64,
    /// Local endpoint of the dedicated punch socket.
    pub(crate) socket_local_endpoint: SocketAddr,
    /// Dynamic socket index for diagnostics/affinity.
    pub(crate) socket_index: usize,
    /// Model inferred from the send-ordered STUN sequence.
    pub(crate) model: p2pnet_nat::PortModel,
    /// Rank-ordered predicted public ports (rank 0 = top-1).
    pub(crate) predicted_ports: Vec<u16>,
    /// Public IP the mapping belongs to.
    pub(crate) public_ip: Option<std::net::IpAddr>,
    /// First and last authenticated punch send timestamps (monotonic ms).
    pub(crate) first_punch_sent_at_ms: u64,
    pub(crate) last_punch_sent_at_ms: u64,
}

/// Why a fresh-mapping generation was rejected and the legacy flow continued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FreshMappingRejection {
    /// Local NAT profile is stable; no dynamic mapping to predict.
    StableLocalNat,
    /// No stable authoritative peer endpoint to punch toward.
    NoStablePeerEndpoint,
    /// Fewer than three successful STUN samples in send order.
    InsufficientSamples,
    /// The batch mixed sockets/generations/duplicate sequences.
    InconsistentBatch,
    /// The batch was too old before the model could be used.
    BatchStale,
    /// Observed public addresses changed mid-batch.
    PublicIpChanged,
    /// The port sequence had no consistent linear behavior.
    UnpredictableSequence,
    /// The dedicated socket could not be bound.
    BindFailed,
    /// No local node ID / probe key for authenticated punching.
    MissingProbeKey,
    /// The generation was superseded or the peer went away.
    Superseded,
}

impl FreshMappingRejection {
    pub(crate) fn label(&self) -> &'static str {
        match self {
            Self::StableLocalNat => "stable_local_nat",
            Self::NoStablePeerEndpoint => "no_stable_peer_endpoint",
            Self::InsufficientSamples => "insufficient_samples",
            Self::InconsistentBatch => "inconsistent_batch",
            Self::BatchStale => "batch_stale",
            Self::PublicIpChanged => "public_ip_changed",
            Self::UnpredictableSequence => "unpredictable_sequence",
            Self::BindFailed => "bind_failed",
            Self::MissingProbeKey => "missing_probe_key",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Debug, Clone)]
struct NatMaintainerLease {
    expires_at: Instant,
    worker_token: Arc<()>,
}

impl NatMaintainerLease {
    fn new(expires_at: Instant) -> Self {
        Self {
            expires_at,
            worker_token: Arc::new(()),
        }
    }

    fn renew_until(&mut self, expires_at: Instant) {
        self.expires_at = self.expires_at.max(expires_at);
    }

    fn is_owned_by(&self, worker_token: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.worker_token, worker_token)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatMaintainerLeaseStatus {
    Active(Instant),
    Expired,
    Replaced,
}

fn nat_maintainer_lease_status(
    maintainers: &mut HashMap<NatMaintainerKey, NatMaintainerLease>,
    key: &NatMaintainerKey,
    worker_token: &Arc<()>,
    now: Instant,
) -> NatMaintainerLeaseStatus {
    let Some(lease) = maintainers.get(key) else {
        return NatMaintainerLeaseStatus::Replaced;
    };
    if !lease.is_owned_by(worker_token) {
        return NatMaintainerLeaseStatus::Replaced;
    }
    if lease.expires_at > now {
        return NatMaintainerLeaseStatus::Active(lease.expires_at);
    }

    maintainers.remove(key);
    NatMaintainerLeaseStatus::Expired
}

fn remove_nat_maintainer_lease_if_owned(
    maintainers: &mut HashMap<NatMaintainerKey, NatMaintainerLease>,
    key: &NatMaintainerKey,
    worker_token: &Arc<()>,
) -> bool {
    if !maintainers
        .get(key)
        .is_some_and(|lease| lease.is_owned_by(worker_token))
    {
        return false;
    }

    maintainers.remove(key);
    true
}

/// Estimate the hard deadline for a wide remote-scatter punch session.
///
/// The fixed 24s bound kills an 831-candidate sweep mid-scan, so a
/// remote-scatter session derives its deadline from the actual probe schedule:
/// `min(planned_packets, session cap) × per-probe pacing + round delays +
/// ACK grace + margin`, floored at 45s. Non-scatter sessions keep the fixed
/// short bound because their candidate sets are small by construction.
pub(crate) fn estimate_remote_scatter_punch_deadline(
    candidates: &[SocketAddr],
    probe_interval: Duration,
    attempts: u32,
    socket_count: usize,
    ack_grace: Duration,
) -> Duration {
    const MIN_REMOTE_SCATTER_SESSION_DEADLINE: Duration = Duration::from_secs(45);
    const REMOTE_SCATTER_DEADLINE_MARGIN: Duration = Duration::from_secs(5);

    let schedule = build_probe_schedule(candidates, probe_interval, attempts);
    let planned_packets = schedule
        .iter()
        .map(|round| round.endpoints.len().saturating_mul(socket_count))
        .sum::<usize>();
    let paced_send_time = OUTBOUND_CONNECTIVITY_PROBE_SPACING
        .saturating_mul(planned_packets.min(MAX_REMOTE_SCATTER_PUNCH_PROBES_PER_SESSION as usize) as u32);
    let round_delays = schedule.iter().map(|round| round.delay_before).sum::<Duration>();
    paced_send_time
        .saturating_add(round_delays)
        .saturating_add(ack_grace)
        .saturating_add(REMOTE_SCATTER_DEADLINE_MARGIN)
        .max(MIN_REMOTE_SCATTER_SESSION_DEADLINE)
}

/// Counters for one local UDP socket in the bounded traversal experiment.
/// They deliberately contain no endpoint or peer identity so diagnostics can
/// expose experiment progress without disclosing local network topology.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UdpSocketPoolMemberDiagnostics {
    /// Stable index for the lifetime of the transport; zero is the primary socket.
    pub socket_index: usize,
    /// Successful UDP punch probes sent from this socket.
    pub probes_sent: u64,
    /// Pool-aware NAT-state maintainer probes sent from this socket.
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
    /// UDP datagrams received from an IP address that matches a known peer
    /// public candidate, before any protocol/auth parsing.
    pub known_peer_ip_datagrams_received: u64,
    /// Datagrams carrying the authenticated Probe v2 framing.
    pub authenticated_probe_packets_received: u64,
    /// Authenticated Probe v2 punch packets accepted before sending an ACK.
    pub authenticated_probe_punches_received: u64,
    /// Authenticated Probe v2 ACK packets observed before pending-probe match.
    pub authenticated_probe_acks_observed: u64,
    /// Authenticated Probe v2 ACK packets whose nonce/socket/generation did not
    /// match a pending outbound probe.
    pub authenticated_probe_acks_unmatched: u64,
    /// Legacy Probe v1 ACK packets observed before pending-probe match.
    pub legacy_probe_acks_observed: u64,
    /// Legacy Probe v1 ACK packets whose nonce/socket/generation did not match
    /// a pending outbound probe.
    pub legacy_probe_acks_unmatched: u64,
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
    StableUniqueScatter,
    PrimaryOnly,
}

impl PunchSocketPolicy {
    fn socket_count(self, transport: &UdpTransport) -> usize {
        match self {
            Self::ActivePool => transport.punch_socket_count(),
            Self::RemoteScatterPool => transport.socket_count(),
            Self::StableUniqueScatter => 1,
            Self::PrimaryOnly => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ActivePool => "active_pool",
            Self::RemoteScatterPool => "remote_scatter_pool",
            Self::StableUniqueScatter => "stable_unique_scatter",
            Self::PrimaryOnly => "primary_only",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PunchSendReport {
    pub packets_sent: u32,
    pub unique_target_endpoints: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpProbeRxSnapshot {
    pub known_peer_ip_datagrams_received: u64,
    pub authenticated_probe_packets_received: u64,
    pub authenticated_probe_acks_observed: u64,
    pub authenticated_probe_acks_unmatched: u64,
    pub legacy_probe_acks_observed: u64,
    pub legacy_probe_acks_unmatched: u64,
    pub probe_acks_received: u64,
}

impl UdpProbeRxSnapshot {
    pub fn delta_since(self, earlier: Self) -> Self {
        Self {
            known_peer_ip_datagrams_received: self
                .known_peer_ip_datagrams_received
                .saturating_sub(earlier.known_peer_ip_datagrams_received),
            authenticated_probe_packets_received: self
                .authenticated_probe_packets_received
                .saturating_sub(earlier.authenticated_probe_packets_received),
            authenticated_probe_acks_observed: self
                .authenticated_probe_acks_observed
                .saturating_sub(earlier.authenticated_probe_acks_observed),
            authenticated_probe_acks_unmatched: self
                .authenticated_probe_acks_unmatched
                .saturating_sub(earlier.authenticated_probe_acks_unmatched),
            legacy_probe_acks_observed: self
                .legacy_probe_acks_observed
                .saturating_sub(earlier.legacy_probe_acks_observed),
            legacy_probe_acks_unmatched: self
                .legacy_probe_acks_unmatched
                .saturating_sub(earlier.legacy_probe_acks_unmatched),
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
