type ProbeNonce = [u8; 8];
type PendingProbes = Arc<Mutex<HashMap<ProbeNonce, PendingProbe>>>;
type HardHardProbeBindings = Arc<Mutex<HashMap<ProbeNonce, String>>>;
type StunTransactionId = [u8; 12];
struct StunResponse {
    data: Vec<u8>,
    source: SocketAddr,
}
type StunWaiters = Arc<Mutex<HashMap<StunTransactionId, oneshot::Sender<StunResponse>>>>;
/// Bounded, per-peer newest-wins ingress for peer-reflexive observations.
///
/// The UDP reader cannot await a downstream worker or enqueue one task per
/// port change.  A synchronous short-held map keeps the newest endpoint for
/// every admitted peer and a Notify wakes the single consumer.  Existing peers
/// always replace their slot; only a genuinely new peer is rejected at the
/// hard bound.
pub(crate) const MAX_PENDING_PEER_REFLEXIVE_INGRESS_PEERS: usize = 128;

/// Per-peer reverse-check pacing state.  `latest_endpoint` is updated even
/// while a check is in flight or inside its cooldown, so port churn cannot
/// bypass the peer-level rate limit and the next admitted check uses the
/// newest observed endpoint.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TriggeredCheckRecord {
    pub(crate) latest_endpoint: SocketAddr,
    pub(crate) last_sent_at: Instant,
    pub(crate) in_flight: bool,
}

type TriggeredCheckState = Arc<Mutex<HashMap<String, TriggeredCheckRecord>>>;
type NatMaintainerKey = (String, SocketAddr, usize);
type NatMaintainerState = Arc<Mutex<HashMap<NatMaintainerKey, NatMaintainerLease>>>;
/// Dedicated per-(peer, local socket) NAT maintainer probe budget, isolated
/// from the recovery-epoch traversal credit and the shared outbound budgets.
pub(super) type NatMaintainerBudgetState = Arc<Mutex<HashMap<(String, usize), VecDeque<Instant>>>>;
/// Process-wide low-priority relay-backoff heartbeat budget. It is separate
/// from the recovery epoch, but still accounts for every actual socket/target
/// send globally.
pub(super) type RelayBackoffHeartbeatBudgetState = Arc<GlobalRelayBackoffHeartbeatBudget>;
/// One owner lease for a relay-backoff heartbeat worker. The sender is kept in
/// a synchronous registry so lifecycle hooks can cancel without awaiting while
/// holding a peer-manager lock.
#[derive(Clone)]
pub(super) struct RelayBackoffHeartbeatLease {
    pub(super) owner_token: u64,
    #[cfg(test)]
    pub(super) started_at: Instant,
    pub(super) cancel_tx: watch::Sender<bool>,
}

/// A recovery trigger that arrived while the peer still had an exiting
/// heartbeat worker. The trigger is remembered so exactly one replacement
/// worker starts after the old worker confirms it stopped sending.
pub(super) struct PendingRelayBackoffHeartbeatRestart {
    pub(super) interval: Duration,
}

/// Send-capability registry for relay-backoff heartbeat workers.
///
/// The invariant this registry enforces is stronger than "one map entry per
/// peer": a worker is send-capable only while its lease sits in `active`.
/// Cancellation moves the lease to `quitting` before a replacement can be
/// requested, so the old worker's per-send owner gate fails immediately and a
/// replacement can only become send-capable after the old worker confirmed it
/// stopped sending (`complete_relay_backoff_heartbeat_exit`).  Recovery
/// triggers arriving during the quit handshake are recorded in
/// `pending_restarts` and start exactly one replacement after the old worker
/// exits.
#[derive(Default)]
pub(super) struct RelayBackoffHeartbeatRegistry {
    pub(super) active: HashMap<String, RelayBackoffHeartbeatLease>,
    pub(super) quitting: HashMap<String, RelayBackoffHeartbeatLease>,
    pub(super) pending_restarts: HashMap<String, PendingRelayBackoffHeartbeatRestart>,
    /// Set permanently when the transport is withdrawn (rebind/shutdown):
    /// nothing may start or restart a worker afterwards.
    pub(super) closed: Arc<AtomicBool>,
}

impl RelayBackoffHeartbeatRegistry {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn mark_closed(&mut self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// Registry for relay-backoff heartbeat tasks: at most one send-capable
/// worker per peer, with a quit handshake before replacement.
pub(super) type RelayBackoffHeartbeatState = Arc<std::sync::Mutex<RelayBackoffHeartbeatRegistry>>;

fn remove_heartbeat_lease_if_owned(
    leases: &mut HashMap<String, RelayBackoffHeartbeatLease>,
    peer_id: &str,
    owner_token: u64,
) -> bool {
    if leases
        .get(peer_id)
        .is_none_or(|lease| lease.owner_token != owner_token)
    {
        return false;
    }
    leases.remove(peer_id);
    true
}

#[cfg(test)]
pub(crate) struct HeartbeatSendGate {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Barrier,
}

#[cfg(test)]
impl HeartbeatSendGate {
    pub(crate) fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Barrier::new(2),
        }
    }
}

/// Deterministic one-shot seam after UDP lifecycle cleanup but before the
/// remote-incarnation reset is published. The transaction still owns the
/// peer adoption lock while parked here.
#[cfg(test)]
pub(crate) struct RemoteIncarnationCleanupGate {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Barrier,
}

#[cfg(test)]
impl RemoteIncarnationCleanupGate {
    pub(crate) fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Barrier::new(2),
        }
    }
}

static NEXT_RELAY_BACKOFF_HEARTBEAT_OWNER_TOKEN: AtomicU64 = AtomicU64::new(1);

fn next_relay_backoff_heartbeat_owner_token() -> u64 {
    NEXT_RELAY_BACKOFF_HEARTBEAT_OWNER_TOKEN
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .expect("relay-backoff heartbeat owner token space exhausted")
}
type AuthPunchReplayKey = (String, u64, ProbeNonce, u8);
type AuthPunchReplayState = Arc<Mutex<HashMap<AuthPunchReplayKey, Instant>>>;
type AuthPunchRateState = Arc<Mutex<HashMap<(String, SocketAddr), VecDeque<Instant>>>>;
/// A peer owns at most one direct-validation worker for one network
/// generation.  The watch value carries the newest observed endpoint so a
/// burst of peer-reflexive observations cannot fan out into validation tasks.
type DirectValidationSessionState = Arc<Mutex<HashMap<String, DirectValidationSession>>>;
/// Per-peer outstanding direct-validation request that may still be answered
/// by an ACK: keyed by peer, one at a time (newer requests replace older
/// ones), with the token the peer's ACK must carry and a bounded TTL.
type DirectValidationExpectationState = Arc<Mutex<HashMap<String, DirectValidationExpectation>>>;
/// Peer/generation-level quarantine for a Direct validation that arrived after
/// the confirmed relay had already carried the request for too long.  The
/// candidate-level quarantine is intentionally not enough: peer-reflexive
/// endpoint churn can otherwise create a fresh owner for every new endpoint
/// and keep sending delayed validation requests indefinitely.
type SlowRelayValidationCooldownState = Arc<Mutex<HashMap<String, (u64, Instant)>>>;

/// Process-wide owner sequence for direct-validation sessions.
///
/// A token is mirrored into the encrypted request/ACK payload, so it must not
/// restart when a UDP socket is rebound.  Otherwise a delayed ACK from a
/// retired transport could collide with a new same-generation session after
/// both registries started their local counters at one.
static NEXT_DIRECT_VALIDATION_OWNER_TOKEN: AtomicU64 = AtomicU64::new(1);

pub(crate) fn next_direct_validation_owner_token() -> u64 {
    NEXT_DIRECT_VALIDATION_OWNER_TOKEN
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
            current.checked_add(1)
        })
        .expect("direct-validation owner token space exhausted")
}

/// Cloneable direct-validation registry shared with `PeerManager`.
///
/// Keeping the session and expectation maps in one handle lets a network
/// generation advance cancel both while it holds the common epoch gate.  The
/// transport and the manager therefore operate on the exact same ownership
/// records rather than attempting best-effort cross-component cleanup.
#[derive(Clone)]
pub(crate) struct DirectValidationRegistry {
    pub(crate) sessions: DirectValidationSessionState,
    pub(crate) expectations: DirectValidationExpectationState,
    pub(crate) slow_relay_cooldowns: SlowRelayValidationCooldownState,
    /// Set permanently when the UDP transport is withdrawn. A stale
    /// scheduler/receiver may still wake after teardown, but it can never
    /// install a fresh session into the retired registry.
    pub(crate) closed: Arc<AtomicBool>,
}

impl DirectValidationRegistry {
    pub(crate) fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            expectations: Arc::new(Mutex::new(HashMap::new())),
            slow_relay_cooldowns: Arc::new(Mutex::new(HashMap::new())),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Suppress new validation owners for this peer and generation until the
    /// relay has had time to remain the stable active path.  Extending an
    /// existing same-generation deadline is safe; a different generation
    /// replaces it because no old-generation cooldown may affect a rejoin.
    pub(crate) async fn suppress_slow_relay_validation(&self, peer_id: &str, generation: u64) {
        let deadline = Instant::now() + crate::peer::SLOW_DIRECT_RELAY_RETRY_COOLDOWN;
        let mut cooldowns = self.slow_relay_cooldowns.lock().await;
        match cooldowns.get_mut(peer_id) {
            Some((stored_generation, stored_deadline)) if *stored_generation == generation => {
                if deadline > *stored_deadline {
                    *stored_deadline = deadline;
                }
            }
            _ => {
                cooldowns.insert(peer_id.to_string(), (generation, deadline));
            }
        }
    }

    /// Check and lazily remove an expired or old-generation cooldown.  The
    /// caller does not retain this lock while touching the session map, which
    /// keeps the cooldown check outside the registry's session -> expectation
    /// transaction and avoids introducing a reverse lock order.
    pub(crate) async fn is_slow_relay_validation_suppressed(
        &self,
        peer_id: &str,
        generation: u64,
    ) -> bool {
        let now = Instant::now();
        let mut cooldowns = self.slow_relay_cooldowns.lock().await;
        match cooldowns.get(peer_id).copied() {
            Some((stored_generation, deadline))
                if stored_generation == generation && deadline > now =>
            {
                true
            }
            Some(_) => {
                cooldowns.remove(peer_id);
                false
            }
            None => false,
        }
    }

    /// Revoke one peer's worker and every expectation it owns.  This is safe
    /// to call from lifecycle cleanup and may race a worker: registration
    /// takes the session lock before the expectation lock, so either the
    /// expectation is inserted first and removed here, or the worker observes
    /// no matching owner and refuses to insert it.
    /// Cancel one peer's validation ownership and publish the lifecycle
    /// reason. The reason is diagnostic only; the cleanup transaction is
    /// shared by every caller so improving observability cannot weaken
    /// stale-worker invalidation.
    pub(crate) async fn cancel_peer_with_reason(&self, peer_id: &str, reason_code: &str) {
        // Keep the session guard while taking the expectation guard. Session
        // creation and expectation registration use this same order, so a
        // same-ID rejoin cannot install a replacement expectation between the
        // old session's removal and its conditional cleanup.
        let mut sessions = self.sessions.lock().await;
        let owner_token = if let Some(session) = sessions.remove(peer_id) {
            let current = *session.target_tx.borrow();
            session.target_tx.send_replace(DirectValidationTarget {
                cancelled: true,
                ..current
            });
            Some(current.owner_token)
        } else {
            None
        };
        let mut expectations = self.expectations.lock().await;
        let expectation_before = expectations.contains_key(peer_id);
        let mut expectation_cancelled = false;
        match owner_token {
            Some(owner_token) => {
                if expectations
                    .get(peer_id)
                    .is_some_and(|expectation| expectation.owner_token == owner_token)
                {
                    expectations.remove(peer_id);
                    expectation_cancelled = true;
                }
            }
            // An expectation without a session is stale state (the
            // compatibility test helper can create one); clean it while the
            // session lock still excludes a concurrent replacement.
            None => {
                expectation_cancelled = expectations.remove(peer_id).is_some();
            }
        }
        let cooldown_cancelled = self
            .slow_relay_cooldowns
            .lock()
            .await
            .remove(peer_id)
            .is_some();
        debug!(target: "p2pnet_daemon::direct_validation",
            event = "direct_validation_registry_peer_cancelled",
            peer_id = %peer_id,
            reason_code,
            session_cancelled = owner_token.is_some(),
            expectation_present_before = expectation_before,
            expectation_cancelled,
            cooldown_cancelled,
            "direct validation ownership cancelled peer_id={} reason_code={}",
            peer_id,
            reason_code,
        );
        drop(sessions);
    }

    /// Revoke every session and expectation that does not belong to the
    /// newly-current generation.  `PeerManager` calls this while it owns the
    /// shared network epoch gate, making the generation publication and this
    /// invalidation one transaction.
    pub(crate) async fn cancel_before_generation(&self, current_generation: u64) {
        let mut cancelled_peers = HashSet::new();
        let mut cancelled_session_count = 0usize;
        // Keep the session guard through expectation cleanup. This is the
        // registry's cancellation transaction and follows the same
        // session -> expectation order as registration/ACK consumption.
        let mut sessions = self.sessions.lock().await;
        sessions.retain(|peer_id, session| {
            let current = *session.target_tx.borrow();
            if current.generation == current_generation && !current.cancelled {
                return true;
            }
            session.target_tx.send_replace(DirectValidationTarget {
                cancelled: true,
                ..current
            });
            cancelled_peers.insert(peer_id.clone());
            cancelled_session_count = cancelled_session_count.saturating_add(1);
            false
        });
        let mut expectations = self.expectations.lock().await;
        let mut cancelled_expectation_count = 0usize;
        expectations.retain(|peer_id, expectation| {
            let keep =
                !cancelled_peers.contains(peer_id) && expectation.generation == current_generation;
            if !keep {
                cancelled_expectation_count = cancelled_expectation_count.saturating_add(1);
            }
            keep
        });
        let mut cancelled_cooldown_count = 0usize;
        self.slow_relay_cooldowns
            .lock()
            .await
            .retain(|_, (generation, _)| {
                let keep = *generation == current_generation;
                if !keep {
                    cancelled_cooldown_count = cancelled_cooldown_count.saturating_add(1);
                }
                keep
            });
        debug!(target: "p2pnet_daemon::direct_validation",
            event = "direct_validation_registry_generation_cancelled",
            generation = current_generation,
            cancelled_session_count,
            cancelled_expectation_count,
            cancelled_cooldown_count,
            "direct validation ownership cancelled before generation={current_generation}"
        );
        drop(sessions);
    }

    /// Revoke all direct-validation ownership during UDP shutdown or
    /// transport replacement.
    pub(crate) async fn cancel_all(&self) {
        // Publish terminal state before acquiring the map locks. A scheduler
        // that checked just before this store rechecks after it obtains the
        // session lock, so it cannot recreate an owner after teardown.
        self.closed.store(true, Ordering::Release);
        // Keep the session lock while clearing expectations so a queued
        // scheduler observation cannot create a new owner in the middle of
        // transport teardown.
        let mut sessions_guard = self.sessions.lock().await;
        let sessions = std::mem::take(&mut *sessions_guard);
        let cancelled_session_count = sessions.len();
        for session in sessions.into_values() {
            let current = *session.target_tx.borrow();
            session.target_tx.send_replace(DirectValidationTarget {
                cancelled: true,
                ..current
            });
        }
        let mut expectations = self.expectations.lock().await;
        let cancelled_expectation_count = expectations.len();
        expectations.clear();
        let mut cooldowns = self.slow_relay_cooldowns.lock().await;
        let cancelled_cooldown_count = cooldowns.len();
        cooldowns.clear();
        debug!(target: "p2pnet_daemon::direct_validation",
            event = "direct_validation_registry_cancelled_all",
            cancelled_session_count,
            cancelled_expectation_count,
            cancelled_cooldown_count,
            "all direct validation ownership cancelled for UDP transport teardown"
        );
        drop(sessions_guard);
    }
}

/// The mutable target owned by a direct-validation worker.
///
/// A same-generation observation replaces `endpoint` (newest-wins).  A
/// generation change or lifecycle cleanup sets `cancelled`, so an old worker
/// cannot keep validating after its ownership was revoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectValidationTarget {
    pub(crate) endpoint: SocketAddr,
    pub(crate) generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) owner_token: u64,
    pub(crate) cancelled: bool,
}

/// Session record held by `UdpTransport`.  The sender remains owned by the
/// registry; workers only receive updates and therefore cannot resurrect a
/// completed or cancelled session.
pub(crate) struct DirectValidationSession {
    pub(crate) target_tx: watch::Sender<DirectValidationTarget>,
}

/// Ownership lease returned exactly once when the scheduler must spawn a
/// validation worker.  Future observations merge into the watch value rather
/// than receiving another lease.
pub(crate) struct DirectValidationSessionLease {
    pub(crate) peer_id: String,
    pub(crate) owner_token: u64,
    pub(crate) target_rx: watch::Receiver<DirectValidationTarget>,
}

pub(crate) enum DirectValidationSessionStart {
    Spawn(DirectValidationSessionLease),
    Merged,
    /// The scheduler read a generation that advanced before it acquired the
    /// shared epoch gate.  It must drop this stale observation rather than
    /// creating an old-generation worker after the advance completed.
    IgnoredStaleGeneration,
    /// The peer is already Direct or this UDP registry was withdrawn. Neither
    /// case may allocate a replacement validation worker from queued evidence.
    IgnoredInactive,
}

/// Why an authenticated direct-validation ACK did not consume the currently
/// owned request expectation.  These values are diagnostic classifications;
/// they do not weaken the exact-match checks below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectValidationAckRejectReason {
    TokenGenerationMismatch,
    NoExpectation,
    ExpectationExpired,
    RequestIdMismatch,
    ExpectationGenerationMismatch,
    OwnerMismatch,
    EndpointMismatch,
    SocketMismatch,
    SessionMissing,
    TargetCancelled,
    TargetGenerationMismatch,
    TargetRemoteCandidateEpochMismatch,
    TargetOwnerMismatch,
}

impl DirectValidationAckRejectReason {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            Self::TokenGenerationMismatch => "direct_validation_ack_generation_mismatch",
            Self::NoExpectation => "direct_validation_ack_no_expectation",
            Self::ExpectationExpired => "direct_validation_ack_expectation_expired",
            Self::RequestIdMismatch => "direct_validation_ack_request_id_mismatch",
            Self::ExpectationGenerationMismatch => {
                "direct_validation_ack_expectation_generation_mismatch"
            }
            Self::OwnerMismatch => "direct_validation_ack_owner_mismatch",
            Self::EndpointMismatch => "direct_validation_ack_endpoint_mismatch",
            Self::SocketMismatch => "direct_validation_ack_socket_mismatch",
            Self::SessionMissing => "direct_validation_ack_session_missing",
            Self::TargetCancelled => "direct_validation_ack_target_cancelled",
            Self::TargetGenerationMismatch => "direct_validation_ack_target_generation_mismatch",
            Self::TargetRemoteCandidateEpochMismatch => {
                "direct_validation_ack_target_remote_candidate_epoch_mismatch"
            }
            Self::TargetOwnerMismatch => "direct_validation_ack_target_owner_mismatch",
        }
    }
}

/// The token a daemon-internal direct-validation ACK must carry to confirm a
/// request this daemon sent.
///
/// The expectation owns the send lease of the exact socket that carried the
/// request.  The lease is acquired in the same critical section that resolves
/// the sending socket (see `UdpTransport::prepare_direct_validation_send`), so
/// a dynamic socket detach or affinity switch can never separate the socket
/// the ACK arrives on from the socket the request actually left on: the ACK
/// handler consumes this expectation on the receiving socket's index, and the
/// lease keeps that socket's reader alive until the ACK, a cancellation, a
/// timeout or a generation invalidation releases it.
///
/// Not `Clone`: the lease is moved exactly once and every release is paired
/// with the single acquire inside the prepare path.
#[derive(Debug)]
pub(crate) struct DirectValidationExpectation {
    pub(crate) request_id: u16,
    pub(crate) generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    /// The validation worker that registered this request.  Conditional
    /// cleanup prevents an old worker from deleting a newer worker's slot.
    pub(crate) owner_token: u64,
    /// Exact direct tuple used by the owned request.  Peer/generation matching
    /// alone cannot distinguish a retired socket or a stale endpoint.
    pub(crate) endpoint: Option<SocketAddr>,
    /// Index of the UDP socket that actually sent the request.  The ACK's
    /// receive socket must match it exactly.
    pub(crate) socket_index: Option<usize>,
    /// Send lease of the resolved socket.  Holding it through the ACK wait
    /// guarantees the socket's reader stays alive even when the socket is
    /// detached right after the send, so a legitimate ACK can still be
    /// matched.  Released when the expectation is consumed, cleared, expired
    /// or removed by owner cancellation.
    #[allow(dead_code)]
    pub(crate) lease: Option<DynamicSocketSendLease>,
    /// Monotonic instant immediately before the encrypted validation datagram
    /// is handed to the kernel. Promotion must score the exact Request -> ACK
    /// exchange instead of reusing an older candidate-probe RTT.
    pub(crate) sent_at: Option<Instant>,
    pub(crate) expires_at: Instant,
}

/// All socket ownership state under one mutex.
///
/// The dynamic punch socket map, the per-peer affinity pins and the affinity
/// epoch counter are deliberately merged: every ownership transition
/// (attach, evict, detach, commit, affinity adoption) happens under this one
/// lock, so there is no cross-lock ordering between the former
/// `dynamic_sockets` and `peer_socket_affinity` maps and ABBA deadlocks are
/// impossible by construction.
pub(crate) struct SocketState {
    pub(crate) dynamic: HashMap<usize, DynamicPunchSocket>,
    pub(crate) affinity: HashMap<String, PeerSocketPin>,
    /// Monotonic evidence counter. Every affinity adoption and every
    /// fresh-mapping commit stamps the pin with a strictly newer value, so
    /// stale ACKs and late generations can never downgrade a newer path.
    pub(crate) affinity_epoch: u64,
    /// Per-peer pending-probe cleanup epochs.  `clear_pending_probes_for_peer`
    /// bumps the peer's epoch while it drops the peer's pending probes, and a
    /// pending probe stamps the epoch that was current when it was sent: an
    /// ACK handler whose transaction check failed may only re-insert the
    /// pending probe when the peer was NOT cleaned up since the probe was
    /// sent, so a cleanup that raced the ACK can never be undone by a late
    /// re-insertion.
    pub(crate) probe_cleanup_epochs: HashMap<String, u64>,
    /// Per-peer punch generation of the newest socket that actually committed.
    /// `commit_and_pin` re-verifies this high-water inside its lock
    /// transaction: an older generation's commit must never overwrite the pin
    /// of a generation that already committed, no matter how the sessions'
    /// awaits interleave.
    pub(crate) committed_punch_generations: HashMap<String, u64>,
}

impl SocketState {
    pub(crate) fn next_epoch(&mut self) -> u64 {
        self.affinity_epoch = self.affinity_epoch.saturating_add(1);
        self.affinity_epoch
    }
}

/// Per-peer pin of the UDP socket that should carry the peer's traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerSocketPin {
    /// Pool socket index (< DYNAMIC_SOCKET_INDEX_BASE) or dynamic index.
    pub(crate) socket_index: usize,
    /// Evidence epoch that established this pin. Adoption is only allowed
    /// when the incoming evidence is at least as new as the pin's epoch.
    pub(crate) epoch: u64,
}
/// Evidence backing an affinity adoption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SocketEvidence {
    /// Evidence tied to the instant a probe was sent (matched ACK): the
    /// epoch recorded on the pending probe at send time.
    Stamped(u64),
    /// Fresh inbound evidence (authenticated punch or encrypted packet
    /// received on this socket right now): the mapping demonstrably works
    /// at arrival time.
    Fresh,
}

const DIRECT_KEEPALIVE_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const PUNCH_PROBE_RETRANSMIT_DELAYS_MS: [u64; 2] = [25, 75];
const PUNCH_ACK_RETRANSMIT_DELAYS_MS: [u64; 2] = [20, 80];
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
///
/// v0.1.116 lowered this from 512 to 192: field evidence (Mini real log) shows
/// a 96-candidate wide window was emitted as 512 physical datagrams with 416
/// repeated target ports across attempt rounds, and the repeat rounds never
/// hit a destination-dependent CGNAT mapping that had moved to a completely
/// different port range.  One CONTROLLED coverage of a 64-candidate window
/// from a 3-socket pool is 192 datagrams (zero repeats) and matches the
/// successful cold-start profile (a 32-candidate scan converged in ~0.5 s with
/// 64 datagrams).  The wide scatter stages are bounded by the same 192 ceiling
/// (`RECOVERY_STAGE_*_MAX_PROBES`) so a planned window always fits one session.
const MAX_PUNCH_PROBES_PER_SESSION: u32 = 192;
/// Hard bound for the easy-side remote-port scatter sweep.
///
/// When the peer has an address/port-dependent mapping, the stable side must
/// cover a much wider peer-port window while the hard-NAT side keeps one
/// destination-specific binding warm.  The one-second outbound budgets still
/// pace this over time; this cap only prevents the session from stopping after
/// the first few hundred ports.  Lowered 4x in v0.1.116 (3072 -> 768): the
/// easy-side scatter is one controlled per-session sweep, not an open-ended
/// burst, and the ACK-feedback stage machine widens the window across sessions.
const MAX_REMOTE_SCATTER_PUNCH_PROBES_PER_SESSION: u32 = 768;
/// A punch session stops after this many consecutive budget rejections
/// without a single send: the whole candidate window is being refused by the
/// admission layer, so continuing to enumerate it only burns CPU and log
/// capacity.  The recovery epoch's budget-exhausted backoff then freezes the
/// plan instead of rebuilding it on the next tick.
pub(super) const MAX_BUDGET_REJECTIONS_PER_SESSION: u32 = 3_072;
/// Maximum number of probes emitted between scheduler yields in one punch
/// session.  A large candidate set is split into these finite batches; each
/// batch boundary yields and re-checks Direct, the network generation and the
/// session cap, so a promotion or a network change always preempts the sweep
/// before the next batch starts.
pub(super) const OUTBOUND_PROBE_BATCH_SIZE: usize = 64;
/// Two STUN observers per experimental socket are enough to publish that
/// socket's observed mapping and infer a small per-socket port-delta prediction
/// window without turning the bounded traversal experiment into a large STUN
/// burst. The primary socket still uses the complete configured observer set
/// for NAT profiling.
const SOCKET_POOL_STUN_OBSERVERS_PER_SOCKET: usize = 2;

/// Dedicated small budget for NAT-state binding maintainer probes.
///
/// The maintainer keeps destination-specific bindings warm while the easier
/// peer scans this side's moving port window.  It runs at a fixed cadence
/// (tens of probes per second across the socket pool) and must NEVER consume
/// the recovery epoch's one-time traversal credit: on a failing hard-NAT
/// peer the maintainer would otherwise burn the whole 4,000-probe epoch in a
/// few minutes and starve the real punches that could actually connect.
/// This budget is per (peer, local socket), small, and independent of every
/// other probe budget; a skipped maintainer beat just repeats at the next
/// interval.
const NAT_MAINTAINER_BUDGET_WINDOW: Duration = Duration::from_secs(60);
const NAT_MAINTAINER_BUDGET_PER_PEER_SOCKET: usize = 1_200;

/// Per-beat probe cap and per-beat socket policy session cap.
pub(super) const RELAY_BACKOFF_HEARTBEAT_MAX_PROBES_PER_BEAT: u32 = 16;

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
/// Upper bound for how long a dynamic socket detach waits for outstanding
/// send leases to drain before aborting the reader.
///
/// The lease bound to each pending probe keeps the reader alive until the
/// probe's ACK arrives or the pending entry times out, so a detach that raced
/// a send must give the in-flight ACK a chance to be matched.  The bound
/// covers the probe retransmission window (25/75 ms) plus the caller's ACK
/// grace (1-2 s); after it, the detach proceeds, drops the socket's pending
/// entries and aborts the reader.
pub(crate) const DYNAMIC_SOCKET_LEASE_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// Monotonic counter of AUTHENTICATED post-attach evidence observed on
    /// this socket: a matched Probe-v2 ACK, an accepted authenticated punch,
    /// or a successfully decrypted WireGuard datagram received on it.
    ///
    /// Evidence is the socket's own record, never an indirect inference from
    /// the affinity epoch: `commit_and_pin` snapshots this value into the
    /// commit outcome, and the watcher's rollback promotes the socket to
    /// Finalized when the counter moved since the commit — a working data
    /// path is never deleted by a cancellation that raced it.  Only evidence
    /// validated against this exact entry (peer identity, network
    /// generation, usable phase) increments the counter, so stale evidence
    /// from an old socket, an old generation or an old network epoch can
    /// never upgrade a new owner.
    pub(crate) authenticated_evidence: u64,
    /// Lifecycle phase of this generation's socket. A Provisional socket is
    /// owned by its in-flight generation and may be detached by the
    /// generation's watcher or its own error paths; a Committed socket has
    /// met the generation's commit conditions and only peer-level cleanup or
    /// the generation's own post-commit rollback may remove it.
    pub(crate) phase: DynamicSocketPhase,
    pub(crate) shutdown_tx: watch::Sender<bool>,
    pub(crate) reader: tokio::task::JoinHandle<()>,
    /// Send-lease bookkeeping shared with every outstanding
    /// [`DynamicSocketSendLease`]: a detach removes the entry from the map
    /// immediately but waits for the leases to drain before aborting the
    /// reader, so a probe whose send raced the detach still receives its ACK
    /// on a live reader.
    pub(crate) send_leases: Arc<DynamicSocketLeaseState>,
}

/// Reference-counted send-lease state for one dynamic socket.
///
/// The counter lives outside the socket-state lock so dropping a lease never
/// needs to acquire it (a Drop that blocked on a lock held by the very task
/// that was cancelled would deadlock).
#[derive(Debug, Default)]
pub(crate) struct DynamicSocketLeaseState {
    count: std::sync::atomic::AtomicUsize,
}

impl DynamicSocketLeaseState {
    fn acquire(&self) {
        self.count.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }

    fn release(&self) {
        // Never underflow: `noop` leases start at 0 and their Drop must not
        // wrap the counter (a wrapped counter would look like a huge
        // outstanding count and block every future detach).
        self.count
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |count| Some(count.saturating_sub(1)),
            )
            .ok();
    }

    /// Number of outstanding leases (in-flight sends on this socket).
    pub(crate) fn outstanding(&self) -> usize {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// RAII send-lease on one dynamic punch socket.
///
/// Acquired under the socket-state lock when a probe send resolves a dynamic
/// socket, released on drop — including when the sending future is cancelled.
/// The detach path removes the map entry immediately (so no new resolver can
/// acquire a lease) but waits for outstanding leases to drain before aborting
/// the reader, which closes the resolve -> send -> ACK race: the ACK of a
/// send that raced the detach still arrives at a reader that is alive.
#[derive(Debug)]
pub(crate) struct DynamicSocketSendLease {
    state: Arc<DynamicSocketLeaseState>,
    #[allow(dead_code)]
    socket_index: usize,
}

impl DynamicSocketSendLease {
    /// A lease that never blocks any detach; used for pool sockets that have
    /// no reader-lifetime requirement.
    pub(crate) fn noop(socket_index: usize) -> Self {
        Self {
            state: Arc::new(DynamicSocketLeaseState::default()),
            socket_index,
        }
    }
}

impl Drop for DynamicSocketSendLease {
    fn drop(&mut self) {
        self.state.release();
    }
}

/// Lifecycle phase of one fresh-mapping punch socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DynamicSocketPhase {
    /// Bound and attached, owned by an in-flight generation. Cancellation or
    /// an abandoned future detaches it.
    Provisional,
    /// The generation met its commit conditions and pinned this socket as the
    /// peer's data path, but the durable handoff (the fresh prediction was
    /// advertised to the peer) has NOT been confirmed yet.  The guard watcher
    /// may still roll the peer back to the predecessor pin and detach this
    /// socket when the owning session is cancelled or the future is dropped.
    CommittedPendingHandoff,
    /// Durable handoff confirmed (the fresh prediction was advertised and the
    /// watcher acknowledged the finalize): the socket IS the peer's long-term
    /// data path.  Only peer-level cleanup (PeerLeft, public-key change, a
    /// newer commit's predecessor detach, network-generation change) may
    /// remove it; a session cancellation can never roll it back.
    Finalized,
}

impl DynamicSocketPhase {
    /// Whether a dynamic socket may be handed out as the peer's traffic path.
    ///
    /// A Provisional socket is owned by its in-flight generation; everything
    /// else (pending handoff or finalized) is pinned and usable.
    pub(crate) fn is_usable(self) -> bool {
        !matches!(self, DynamicSocketPhase::Provisional)
    }
}

impl DynamicPunchSocket {
    pub(crate) fn local_endpoint(&self) -> Option<SocketAddr> {
        self.socket.local_addr().ok()
    }
}

/// Why a dynamic punch socket could not be attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DynamicSocketAttachError {
    /// The owning punch/network generation was cancelled or superseded before
    /// the attach transaction acquired the network-epoch gate.
    Superseded,
    /// The dynamic socket cap is full and no entry could be evicted safely
    /// (the same peer's predecessor and Direct peers are never evicted).
    CapacityRejected,
    /// The transport has no inbound channel, so the socket reader could not
    /// deliver anything; the attach is rolled back.
    NoInboundChannel,
    /// The spawned reader exited or failed to poll its socket within the
    /// bounded startup handshake; the provisional attach is rolled back.
    ReaderStartupFailed,
}

/// Outcome of one fresh-mapping punch generation.
#[derive(Debug)]
pub(crate) enum FreshMappingOutcome {
    /// The generation measured, modeled and punched successfully.  The guard
    /// is returned with the result: the durable handoff (`finalize`) runs in
    /// the caller AFTER the fresh prediction was advertised, so an advertise
    /// failure or a session cancellation can still roll the socket back.
    /// Until `finalize` the socket is `CommittedPendingHandoff`; a guard that
    /// is dropped without finalizing rolls the peer back to its previous
    /// path.
    Accepted(Box<FreshMappingResult>, Box<ProvisionalSocketGuard>),
    /// The generation could not produce a trustworthy prediction and the
    /// caller must fall back to the legacy punch strategy.
    Rejected(FreshMappingRejection),
}

impl std::fmt::Debug for ProvisionalSocketGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The guard contains live channels and a task handle; only its
        // identity is stable for debugging.
        f.debug_struct("ProvisionalSocketGuard")
            .field("socket_index", &self.socket_index)
            .field("peer_id", &self.peer_id)
            .finish_non_exhaustive()
    }
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
    /// The dynamic socket cap had no safely evictable entry, so the new
    /// generation's socket was refused without exceeding the cap.
    CapacityRejected,
    /// No local node ID / probe key for authenticated punching.
    MissingProbeKey,
    /// The generation was superseded or the peer went away.
    Superseded,
    /// The peer-facing punch loop sent no probe into the kernel queue
    /// (attempts=0, all sends failed, or every send was aborted by
    /// cancellation). The generation must not claim success.
    NoProbesSent,
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
            Self::CapacityRejected => "capacity_rejected",
            Self::MissingProbeKey => "missing_probe_key",
            Self::Superseded => "superseded",
            Self::NoProbesSent => "no_probes_sent",
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
/// The fixed 24s bound killed an 831-candidate sweep mid-scan, so a
/// remote-scatter session derives its deadline from the actual bounded probe
/// schedule. The current session cap is 768 physical probes, so at the
/// production 6ms pacing a complete window fits inside ten seconds. A
/// ten-second floor gives the scheduler enough room for that bounded window
/// while guaranteeing that the next recovery stage is not held behind the old
/// ten-second floor. Non-scatter sessions keep the fixed short bound because
/// their candidate sets are small by construction.
pub(crate) fn estimate_remote_scatter_punch_deadline(
    candidates: &[SocketAddr],
    probe_interval: Duration,
    attempts: u32,
    socket_count: usize,
    ack_grace: Duration,
) -> Duration {
    const MIN_REMOTE_SCATTER_SESSION_DEADLINE: Duration = Duration::from_secs(10);
    const REMOTE_SCATTER_DEADLINE_MARGIN: Duration = Duration::from_secs(1);

    let schedule = build_probe_schedule(candidates, probe_interval, attempts);
    let planned_packets = schedule
        .iter()
        .map(|round| round.endpoints.len().saturating_mul(socket_count))
        .sum::<usize>();
    let paced_send_time = OUTBOUND_CONNECTIVITY_PROBE_SPACING.saturating_mul(
        planned_packets.min(MAX_REMOTE_SCATTER_PUNCH_PROBES_PER_SESSION as usize) as u32,
    );
    let round_delays = schedule
        .iter()
        .map(|round| round.delay_before)
        .sum::<Duration>();
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
    /// Relay-backoff heartbeat probe datagrams sent from this socket.
    pub relay_backoff_heartbeat_probes_sent: u64,
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

#[derive(Clone)]
pub struct PeerReflexiveIngress {
    latest: Arc<std::sync::Mutex<HashMap<String, PeerReflexiveObservation>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl PeerReflexiveIngress {
    /// Create an empty ingress with one bounded newest-wins slot per peer.
    pub fn new() -> Self {
        Self {
            latest: Arc::new(std::sync::Mutex::new(HashMap::new())),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Submit without awaiting.  A full map rejects only a new peer; an
    /// already-admitted peer always wins with its newest endpoint.
    pub fn submit(&self, observation: PeerReflexiveObservation) -> bool {
        let peer_id = observation.peer_id.clone();
        let accepted = {
            let mut latest = self
                .latest
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if latest.contains_key(&peer_id)
                || latest.len() < MAX_PENDING_PEER_REFLEXIVE_INGRESS_PEERS
            {
                latest.insert(peer_id, observation);
                true
            } else {
                false
            }
        };
        if accepted {
            self.notify.notify_one();
        }
        accepted
    }

    /// Wait for and remove one pending observation.
    ///
    /// The ingress is designed for one consumer. If several tasks call this,
    /// each observation is delivered to only one of them.
    pub async fn next(&self) -> PeerReflexiveObservation {
        loop {
            // Register before checking the map so a concurrent submit cannot
            // fall into the check/await gap and strand an observation.
            let notified = self.notify.notified();
            let observation = {
                let mut latest = self
                    .latest
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                latest
                    .keys()
                    .next()
                    .cloned()
                    .and_then(|peer_id| latest.remove(&peer_id))
            };
            if let Some(observation) = observation {
                return observation;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.latest
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

impl Default for PeerReflexiveIngress {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct PendingProbe {
    sent_at: Instant,
    /// Monotonic terminal deadline for this probe's ACK.  Keeping the nonce
    /// in the bounded map for cleanup is not permission to accept an ACK
    /// forever: a delayed datagram must never become fresh path evidence.
    expires_at: Instant,
    endpoint: SocketAddr,
    local_endpoint: Option<SocketAddr>,
    socket_index: usize,
    generation: u64,
    /// Remote candidate set epoch at the moment this probe was sent. A late
    /// ACK must not become proof for a newer remote endpoint set.
    remote_candidate_epoch: u64,
    /// Active Probe session at send time. It binds receive diagnostics to the
    /// same handshake generation without changing protocol matching rules.
    probe_session_id: Option<String>,
    peer_id: Option<String>,
    purpose: PendingProbePurpose,
    accepts_authenticated_ack: bool,
    accepts_legacy_ack: bool,
    /// Affinity evidence epoch at the moment this probe was sent. A matched
    /// ACK may only adopt the sending socket when this epoch is at least as
    /// new as the currently pinned one.
    socket_epoch: u64,
    /// Peer cleanup epoch at the moment this probe was sent.  An ACK handler
    /// may only re-insert this pending entry after a failed transaction check
    /// when the peer was not cleaned up since then, so a racing cleanup can
    /// never be undone by a late re-insertion.
    cleanup_epoch: u64,
    /// Direct-commit sequence at the moment this probe was sent.  A matched
    /// ACK can prove whether any newer Direct commit superseded the send.
    direct_commit_seq: u64,
}

impl PendingProbe {
    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingProbePurpose {
    ConnectivityCheck,
    ConsentCheck,
    RelayBackoffHeartbeat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchSocketPolicy {
    /// Bounded latency-sensitive prefix: use every already-bound socket for
    /// this one sweep without changing the transport-wide NAT-profile gate.
    FastPrefixPool,
    ActivePool,
    RemoteScatterPool,
    StableUniqueScatter,
    PrimaryOnly,
    /// Low-rate relay-backed recovery heartbeat: the relay is the data plane,
    /// so this policy probes the trusted endpoints with a small dedicated
    /// budget that never touches the recovery-epoch traversal credit.  It
    /// keeps the five-tuple punch windows alive for hours while a
    /// double-NAT / rotating-egress pair waits for a rare match.
    RelayBackoffHeartbeat,
}

impl PunchSocketPolicy {
    fn socket_count(self, transport: &UdpTransport) -> usize {
        match self {
            Self::FastPrefixPool => transport.socket_count(),
            Self::ActivePool => transport.punch_socket_count(),
            Self::RemoteScatterPool => transport.socket_count(),
            Self::StableUniqueScatter => 1,
            Self::PrimaryOnly => 1,
            Self::RelayBackoffHeartbeat => transport.socket_count(),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::FastPrefixPool => "fast_prefix_pool",
            Self::ActivePool => "active_pool",
            Self::RemoteScatterPool => "remote_scatter_pool",
            Self::StableUniqueScatter => "stable_unique_scatter",
            Self::PrimaryOnly => "primary_only",
            Self::RelayBackoffHeartbeat => "relay_backoff_heartbeat",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PunchSendReport {
    pub packets_sent: u32,
    pub unique_target_endpoints: u32,
    /// Wall-clock UNIX milliseconds captured immediately after the first
    /// successful kernel UDP send in this punch session.  `None` means the
    /// session emitted no datagram; dispatch timestamps must never be used as
    /// a substitute for this field.
    pub first_send_at_ms: Option<u64>,
    /// Physical datagrams accepted by the kernel, grouped by the actual
    /// socket index used for each send.  Legacy compatibility copies count as
    /// separate datagrams here even though `packets_sent` remains the logical
    /// probe count for recovery accounting.
    pub per_socket_sent: Vec<(usize, u32)>,
    /// How many candidate probes were rejected by the admission layer
    /// (rate limits, epoch credit, quarantine) during this session.
    pub budget_skipped: u32,
    /// The session ended because the recovery-epoch probe credit was
    /// exhausted: no further probe may be emitted this epoch, and the caller
    /// must treat a zero-send session as a budget-exhausted verdict instead
    /// of an empty success.
    pub epoch_budget_exhausted: bool,
    /// The session stopped enumerating candidates because the epoch's hard
    /// candidate-iteration budget was reached.
    pub candidate_iteration_capped: bool,
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

/// Bounded, authenticated receive counters scoped to one remote peer, local
/// network generation and Probe session. Socket-pool diagnostics intentionally
/// remain topology-free and aggregate; recovery timeout diagnostics must
/// instead use this map so traffic for peer B or an older peer-A handshake
/// cannot be presented as current peer-A ACK evidence.
type PeerProbeRxDiagnostics = Arc<Mutex<HashMap<(String, u64, Option<String>), PeerProbeRxEntry>>>;

struct PeerProbeRxEntry {
    snapshot: UdpProbeRxSnapshot,
    last_updated: Instant,
}

const PEER_PROBE_RX_DIAGNOSTICS_MAX_ENTRIES: usize = 512;
const PEER_PROBE_RX_DIAGNOSTICS_RETENTION: Duration = Duration::from_secs(90);

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
    remote_candidate_epoch: u64,
    socket_index: usize,
    cleanup_epoch: u64,
    direct_commit_seq: u64,
) -> bool {
    pending.generation == generation
        && pending.remote_candidate_epoch == remote_candidate_epoch
        && pending.socket_index == socket_index
        && pending.cleanup_epoch == cleanup_epoch
        && pending.direct_commit_seq == direct_commit_seq
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
