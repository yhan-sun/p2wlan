// ============================================================
// Peer Manager
// ============================================================

type NetworkGenerationHandshakeCancellation = (usize, usize, Vec<(String, String)>);
type NetworkGenerationHandshakeCancelHook =
    Arc<dyn Fn(u64) -> NetworkGenerationHandshakeCancellation + Send + Sync>;
type NetworkGenerationHandshakeCancelHookSlot =
    Arc<std::sync::Mutex<Option<NetworkGenerationHandshakeCancelHook>>>;

/// The local, non-wire identity fence for one Hard↔Hard rendezvous.
///
/// The session id alone is not sufficient: a late response from an older
/// network/profile/candidate epoch must never be allowed to reuse a currently
/// attached dynamic socket.  All four domains are captured independently and
/// checked by the runtime before every synchronized send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardHardSessionState {
    AwaitingPeer,
    Sweeping,
    Retiring,
}

/// Exact identity of the dedicated socket that produced one synchronized
/// mapping.  The dynamic index is monotonic, while the other fields prevent a
/// future implementation from accidentally treating a reused or superseded
/// entry as this session's socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HardHardFreshSocketIdentity {
    pub(crate) peer_id: String,
    pub(crate) session_token: String,
    pub(crate) network_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) local_profile_generation: u64,
    pub(crate) remote_profile_generation: u64,
    pub(crate) punch_generation: u64,
    pub(crate) socket_index: usize,
    pub(crate) socket_local_endpoint: SocketAddr,
}

/// Lock-free snapshot of the pair selected by the latest authoritative Direct
/// commit.  The snapshot is published while the network-epoch gate and the
/// connection writer are held, then consumed by the Hard↔Hard confirmation
/// wait without reacquiring the connection map.  The Direct-set mirror still
/// supplies the active/inactive bit; this value only proves the exact local
/// endpoint and remote candidate epoch of the commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectCommitPairSnapshot {
    pub(crate) generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) local_endpoint: Option<SocketAddr>,
}

#[derive(Debug, Clone)]
pub(crate) struct HardHardSessionRecord {
    pub(crate) session_id: String,
    /// Authoritative Probe receive-session identity captured before the
    /// punch-at deadline path.  Hard↔Hard diagnostics reuse this exact value
    /// before and after the sweep, even if the connection map is contended at
    /// punch time; the full value is never emitted in diagnostics.
    pub(crate) probe_session_id: Option<String>,
    pub(crate) session_token: String,
    pub(crate) peer_id: String,
    pub(crate) initiator: bool,
    /// The network generation observed at the other endpoint.  The initiator
    /// learns it from the responder envelope; zero means it was not known in
    /// the first directional offer.
    pub(crate) remote_network_generation: u64,
    pub(crate) local_network_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) local_profile_generation: u64,
    pub(crate) remote_profile_generation: u64,
    pub(crate) local_prediction_confidence: u8,
    pub(crate) remote_prediction_confidence: u8,
    /// Original Birthday level selected before candidate signaling is capped.
    /// Zero denotes the predictable fresh-mapping lane, which has no Birthday
    /// level.  This local ledger value is authoritative for the reciprocal
    /// response path; it is never reconstructed from the signaled window.
    pub(crate) requested_birthday_level: usize,
    pub(crate) generated_candidate_count: usize,
    pub(crate) signaled_candidate_count: usize,
    pub(crate) birthday: bool,
    /// Exact dynamic sockets created for this session.  A later scheduler
    /// snapshot may find only a subset still attached/usable; it must never
    /// replace a missing member with a pool socket.
    pub(crate) requested_socket_indices: Vec<usize>,
    pub(crate) requested_socket_count: usize,
    pub(crate) prediction_window: Vec<SocketAddr>,
    pub(crate) remote_prediction: Vec<SocketAddr>,
    pub(crate) fresh_socket: HardHardFreshSocketIdentity,
    pub(crate) punch_at_ms: u64,
    pub(crate) expires_at_ms: u64,
    pub(crate) state: HardHardSessionState,
    pub(crate) attempt_count: u8,
    pub(crate) created_at: Instant,
    pub(crate) cancellation: Arc<crate::PunchSessionCancellation>,
}

#[cfg(test)]
pub(crate) struct HardHardCleanupGate {
    pub(crate) reached: tokio::sync::Notify,
    pub(crate) release: tokio::sync::Notify,
    pub(crate) completed: tokio::sync::Notify,
    #[cfg(test)]
    reached_flag: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    released_flag: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    completed_flag: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl HardHardCleanupGate {
    pub(crate) fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
            completed: tokio::sync::Notify::new(),
            reached_flag: std::sync::atomic::AtomicBool::new(false),
            released_flag: std::sync::atomic::AtomicBool::new(false),
            completed_flag: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn signal_reached(&self) {
        self.reached_flag
            .store(true, std::sync::atomic::Ordering::Release);
        self.reached.notify_one();
        self.reached.notify_waiters();
    }

    pub(crate) async fn wait_for_reached(&self) {
        loop {
            if self
                .reached_flag
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            let notified = self.reached.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .reached_flag
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn release(&self) {
        self.released_flag
            .store(true, std::sync::atomic::Ordering::Release);
        self.release.notify_one();
        self.release.notify_waiters();
    }

    pub(crate) async fn wait_for_release(&self) {
        loop {
            if self
                .released_flag
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            let notified = self.release.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .released_flag
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn signal_completed(&self) {
        self.completed_flag
            .store(true, std::sync::atomic::Ordering::Release);
        self.completed.notify_one();
        self.completed.notify_waiters();
    }

    pub(crate) async fn wait_for_completed(&self) {
        loop {
            if self
                .completed_flag
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            let notified = self.completed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .completed_flag
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
struct HardHardCleanupGateRegistration {
    peer_id: String,
    session_id: String,
    session_token: String,
    gate: Arc<HardHardCleanupGate>,
}

#[cfg(test)]
pub(crate) struct HardHardCleanupGateGuard {
    slot: Arc<std::sync::Mutex<Option<HardHardCleanupGateRegistration>>>,
    installed: Arc<HardHardCleanupGate>,
    previous: Option<HardHardCleanupGateRegistration>,
}

#[cfg(test)]
impl Drop for HardHardCleanupGateGuard {
    fn drop(&mut self) {
        let mut slot = self
            .slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if slot
            .as_ref()
            .is_some_and(|registration| Arc::ptr_eq(&registration.gate, &self.installed))
        {
            *slot = self.previous.take();
        }
        self.installed.release();
    }
}

/// Hard ceiling for remote identity tombstones retained after `PeerLeft`.
///
/// The ledger is only a cross-connection replay fence; a live connection keeps
/// its own generation and incarnation high-waters. Recent departures are
/// touched before their connection is removed, so ordinary leave/rejoin races
/// retain both fences while unbounded node-ID churn cannot grow process memory
/// forever.
const MAX_REMOTE_IDENTITY_TOMBSTONES: usize = 4_096;

#[derive(Debug, Clone)]
struct RemoteIdentityTombstone {
    public_key: String,
    candidate_incarnation_high_water: Option<u64>,
    /// Highest encoded candidate revision that must be rejected for this exact
    /// public-key identity. Usually this is the last accepted generation. While
    /// a newer incarnation is claimed but not yet applied, it is that incoming
    /// generation's strict predecessor, so the trigger itself remains
    /// admissible while lower same-boot counters are fenced across PeerLeft.
    /// Legacy clock generations are deliberately never persisted.
    candidate_generation_replay_floor: u64,
}

#[derive(Debug, Default)]
struct RemoteIdentityLedger {
    entries: HashMap<String, RemoteIdentityTombstone>,
    /// Oldest-to-newest insertion/touch order. Each node ID occurs exactly once.
    order: VecDeque<String>,
}

impl RemoteIdentityLedger {
    fn get(&self, node_id: &str) -> Option<&RemoteIdentityTombstone> {
        self.entries.get(node_id)
    }

    /// Insert or refresh one identity at the newest end of the bounded ledger.
    fn upsert_and_touch(
        &mut self,
        node_id: &str,
        public_key: &str,
        candidate_incarnation_high_water: Option<u64>,
        candidate_generation_replay_floor: u64,
    ) {
        let candidate_generation_replay_floor =
            if crate::control::candidate_generation_incarnation(candidate_generation_replay_floor)
                .is_some()
            {
                candidate_generation_replay_floor
            } else {
                0
            };
        if self.entries.contains_key(node_id) {
            self.order.retain(|known| known != node_id);
        }
        let (candidate_incarnation_high_water, candidate_generation_replay_floor) = self
            .entries
            .get(node_id)
            .filter(|identity| identity.public_key == public_key)
            .map_or(
                (
                    candidate_incarnation_high_water,
                    candidate_generation_replay_floor,
                ),
                |identity| {
                    (
                        match (
                            identity.candidate_incarnation_high_water,
                            candidate_incarnation_high_water,
                        ) {
                            (Some(existing), Some(incoming)) => Some(existing.max(incoming)),
                            (existing, incoming) => existing.or(incoming),
                        },
                        identity
                            .candidate_generation_replay_floor
                            .max(candidate_generation_replay_floor),
                    )
                },
            );
        self.entries.insert(
            node_id.to_string(),
            RemoteIdentityTombstone {
                public_key: public_key.to_string(),
                candidate_incarnation_high_water,
                candidate_generation_replay_floor,
            },
        );
        self.order.push_back(node_id.to_string());
        while self.entries.len() > MAX_REMOTE_IDENTITY_TOMBSTONES {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
    }

    /// Raise the incarnation high-water without turning high-volume candidate
    /// refreshes into O(n) recency-list updates.
    fn record_candidate_incarnation(&mut self, node_id: &str, public_key: &str, incarnation: u64) {
        if let Some(identity) = self.entries.get_mut(node_id) {
            if identity.public_key == public_key {
                identity.candidate_incarnation_high_water = Some(
                    identity
                        .candidate_incarnation_high_water
                        .map_or(incarnation, |accepted| accepted.max(incarnation)),
                );
                return;
            }
            identity.public_key = public_key.to_string();
            identity.candidate_incarnation_high_water = Some(incarnation);
            identity.candidate_generation_replay_floor = 0;
            return;
        }
        self.upsert_and_touch(node_id, public_key, Some(incarnation), 0);
    }

    /// Raise the candidate-generation replay floor without changing tombstone
    /// recency. The value is either a completely accepted generation or the
    /// strict predecessor published during ingress preflight. This complements
    /// the independently claimed incarnation high-water: a PeerLeft/readd with
    /// the same key must reject both an older boot and an older/equal counter
    /// in the same boot.
    fn record_candidate_generation_replay_floor(
        &mut self,
        node_id: &str,
        public_key: &str,
        generation: u64,
    ) {
        // Legacy generations are wall-clock based and may legitimately move
        // backwards after PeerLeft. They have no daemon-incarnation namespace,
        // so persisting them would strand a same-key legacy rejoin.
        if crate::control::candidate_generation_incarnation(generation).is_none() {
            return;
        }
        if let Some(identity) = self.entries.get_mut(node_id) {
            if identity.public_key == public_key {
                identity.candidate_generation_replay_floor =
                    identity.candidate_generation_replay_floor.max(generation);
                return;
            }
            identity.public_key = public_key.to_string();
            identity.candidate_incarnation_high_water =
                crate::control::candidate_generation_incarnation(generation);
            identity.candidate_generation_replay_floor = generation;
            return;
        }
        self.upsert_and_touch(
            node_id,
            public_key,
            crate::control::candidate_generation_incarnation(generation),
            generation,
        );
    }
}

#[cfg(test)]
type AuthenticatedProbeVerifyGateSlot =
    Arc<std::sync::Mutex<Option<(String, Arc<AuthenticatedProbeVerifyGate>)>>>;

#[cfg(test)]
type RelayProbeSnapshotTestGateSlot =
    Arc<std::sync::Mutex<Option<(String, Arc<RelayProbeSnapshotTestGate>)>>>;

/// Manages all peer connections.
pub struct PeerManager {
    /// Active peer connections, indexed by node ID.
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    /// No-await mirror of connection-map membership and peer lifecycle.
    ///
    /// The serial control-signal consumer must be able to decide whether an
    /// offer raced PeerJoined without waiting behind an unrelated, long-lived
    /// `connections` writer.  The same mirror also gives UDP adoption paths a
    /// precise lifecycle fence instead of treating `try_read` contention as a
    /// missing peer. Structural add/remove, identity, online, and remote
    /// incarnation transitions update this state while they own the network
    /// epoch and connection writer; ordinary metadata/endpoint refreshes do
    /// not rotate the session generation.
    peer_membership: Arc<std::sync::Mutex<PeerMembershipState>>,
    #[cfg(test)]
    authenticated_probe_verify_gate: AuthenticatedProbeVerifyGateSlot,
    #[cfg(test)]
    relay_probe_snapshot_test_gate: RelayProbeSnapshotTestGateSlot,
    #[cfg(test)]
    hard_hard_cleanup_gate:
        Arc<std::sync::Mutex<Option<HardHardCleanupGateRegistration>>>,
    /// Last complete diagnostics snapshot.  Diagnostics must never turn a
    /// contended connection writer into a false empty roster; the snapshot is
    /// only a fallback while the live lock is unavailable.
    diagnostics_cache: Arc<std::sync::Mutex<Option<Vec<PeerDiagnostics>>>>,
    /// No-await projection of the typed state machine's committed business
    /// path. Unlike `diagnostics_cache`, this is updated at the sole path commit
    /// point and therefore never reports stale readiness under writer pressure.
    committed_business_paths:
        Arc<std::sync::Mutex<HashMap<String, CommittedBusinessPathSnapshot>>>,
    /// Latest-value notification for committed path/lifecycle/epoch changes.
    committed_business_path_change_tx: tokio::sync::watch::Sender<u64>,
    /// Session-bound DPLPMTUD capability mirror.  The immutable map survives
    /// a UDP transport replacement, so a modern peer cannot temporarily fall
    /// back to legacy business sending while the replacement exact path is
    /// still re-confirming BASE.
    dplpmtud_capability_tx:
        tokio::sync::watch::Sender<Arc<HashMap<String, PeerSessionGeneration>>>,
    /// Latest-value wakeup for Direct business-budget publication changes.
    /// The actual budget remains owned by the concrete UDP transport; this
    /// sequence is only an event-driven queue wakeup.
    direct_business_budget_change_tx: tokio::sync::watch::Sender<u64>,
    /// Bounded local packet injection channel used for ICMP PMTU/unreachable
    /// feedback.  `DataPlane` owns the production receiver.
    local_mtu_feedback_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    local_mtu_feedback_limiter:
        Arc<std::sync::Mutex<crate::business_mtu::LocalMtuFeedbackRateLimiter>>,
    /// Virtual IP → node ID mapping for routing.
    ip_to_node: Arc<RwLock<HashMap<String, String>>>,
    /// Monotonic local network generation. Incremented when local UDP candidates change.
    network_generation: Arc<RwLock<u64>>,
    /// Lock-free mirror of `network_generation`, updated in the same critical
    /// section as the lock so the UDP socket-state layer can read the CURRENT
    /// generation without awaiting (the socket-state checks must never read
    /// the generation before acquiring their own lock: a generation that
    /// advances between the read and the lock would let a stale entry pass the
    /// check).
    network_generation_sync: Arc<std::sync::atomic::AtomicU64>,
    /// Nonblocking daemon hook that cancels exact handshake reservations from
    /// older generations in the same generation-advance transaction.  The
    /// hook performs only a short synchronous pending-state mutation.
    network_generation_handshake_cancel_hook: NetworkGenerationHandshakeCancelHookSlot,
    /// Shared network-epoch gate serializing every generation advance against
    /// every UDP socket-state mutation that stamps, commits, finalizes or
    /// adopts socket ownership for a generation.
    ///
    /// The UDP layer reads the generation through the lock-free mirror inside
    /// its socket-state critical section; without a common gate an advance
    /// could bump the mirror BETWEEN the UDP read and the UDP write of the
    /// same critical section, letting an old-generation commit, finalize or
    /// pending-probe registration land AFTER the generation already moved on.
    /// Both the advances and the UDP mutation sites hold this gate first
    /// (gate -> socket_state -> pending probes), so a generation update is
    /// atomic with respect to every generation-sensitive socket transition.
    network_epoch_gate: Arc<tokio::sync::Mutex<()>>,
    /// The currently published UDP direct-validation registry.  The UDP
    /// transport registers this handle when it binds; generation advances use
    /// it while holding `network_epoch_gate` to revoke old validation owners
    /// and their ACK expectations atomically with the new generation.
    direct_validation_registry: Arc<RwLock<Option<crate::udp::DirectValidationRegistry>>>,
    /// DPLPMTUD registry published by the current UDP transport.  It is kept
    /// beside the validation registry so lifecycle/generation transitions can
    /// cancel exact-path probe ownership under the same network epoch fence.
    dplpmtud_runtime: Arc<RwLock<Option<crate::dplpmtud::DplpmtudRuntime>>>,
    /// Latest local NAT profile used to decide whether bounded birthday probing is suitable.
    local_nat_profile: Arc<RwLock<Option<NatProfile>>>,
    /// Monotonic generation of the local NAT profile itself.  This is a
    /// separate domain from the local network generation: a profile refresh
    /// can invalidate a Hard↔Hard session without implying a link handover.
    local_profile_generation: Arc<std::sync::atomic::AtomicU64>,
    /// Directly-connected local interface prefixes used by the Host fast lane.
    local_interface_networks: Arc<RwLock<Vec<LocalNetwork>>>,
    /// Anonymous local traversal outcome history.
    traversal_history: Arc<RwLock<TraversalHistory>>,
    /// Optional persistent history path.
    traversal_history_path: Option<PathBuf>,
    /// Per-peer punch generation counters for fresh-mapping batches.
    punch_generations: Arc<RwLock<HashMap<String, u64>>>,
    /// Per-peer fresh-mapping state produced by measure-then-punch generations.
    local_fresh_mappings: Arc<RwLock<HashMap<String, LocalFreshMapping>>>,
    /// Active Hard↔Hard rendezvous fences.  The control signal carries the
    /// session identity, but the receiver also needs a local record tying it
    /// to the four generation domains and the exact dynamic socket that was
    /// measured.  Entries are short-lived and bounded; they are not a path
    /// selector or a Direct authority.
    hard_hard_sessions: Arc<tokio::sync::Mutex<HashMap<(String, String), HardHardSessionRecord>>>,
    /// Exact cleanup ownership claims. A duplicate registration must not
    /// start a second watcher that could later race a replacement session.
    hard_hard_cleanup_owners: Arc<tokio::sync::Mutex<HashSet<(String, String, String)>>>,
    /// First authenticated socket selected by a bounded Hard↔Hard session.
    /// Kept outside the wire/session record so old test fixtures and the
    /// compact envelope remain compatible while a late packet cannot replace
    /// the winner with another speculative socket.
    hard_hard_winners: Arc<tokio::sync::Mutex<HashMap<(String, String), usize>>>,
    /// Time-limited prediction-error fingerprint per peer.
    fresh_mapping_history:
        Arc<std::sync::Mutex<HashMap<String, VecDeque<FreshMappingPredictionResult>>>>,
    /// Per-peer high-water of the remote's fresh-mapping prediction identity.
    ///
    /// The remote signals fresh predictions as `predicted_fresh:<boot>:<gen>`.
    /// Only a strictly newer (boot, generation) may be applied: a superseded
    /// generation that an old task managed to send late is rejected before it
    /// can overwrite the current candidate set or start a punch session.  The
    /// high-water follows the peer's incarnation: public-key identity changes
    /// reset it, while a plain PeerLeft does not (a late old-incarnation
    /// signal must stay rejected after the peer rejoins).
    remote_fresh_generations: Arc<std::sync::Mutex<HashMap<String, crate::FreshPredictionId>>>,
    /// Immutable candidate snapshots bound to committed fresh identities.
    ///
    /// An idempotent retry of an identity can only ever punch toward the
    /// snapshot the identity was committed with, and a retry whose payload
    /// differs is rejected instead of applied.
    remote_fresh_snapshots:
        Arc<std::sync::Mutex<HashMap<(String, crate::FreshPredictionId), FreshPredictionSnapshot>>>,
    /// Fresh applies recorded between apply and commit, so a commit can
    /// promote the applied payload to the durable snapshot or a losing
    /// commit can roll exactly its own candidates back.
    pending_fresh_applies:
        Arc<std::sync::Mutex<HashMap<(String, crate::FreshPredictionId), PendingFreshApply>>>,
    /// Serializes one remote fresh-prediction apply + commit transaction.
    ///
    /// `prepare` is intentionally optimistic, so two control workers can both
    /// observe an admissible identity.  Only one of them may replace the live
    /// candidate set before the durable high-water is committed; otherwise a
    /// late older apply can erase the newer winner and then lose its CAS.  The
    /// production transaction re-checks the high-water while holding this gate
    /// and keeps it through apply + commit/rollback.
    remote_fresh_transaction_gate: Arc<tokio::sync::Mutex<()>>,
    /// Bounded identity tombstones surviving `remove_peer`.
    ///
    /// The remote fresh-prediction space is bound to the peer's identity: a
    /// PeerLeft followed by a rejoin with a NEW public key must not inherit
    /// the old incarnation's high-water (its predictions would be judged
    /// stale forever).  The identity map outlives the connection so
    /// `add_peer` can compare the rejoining key even when `is_new`. The same
    /// entry retains the encoded candidate-incarnation high-water, preventing
    /// a delayed old signal from becoming fresh merely because PeerLeft
    /// removed the live connection.
    remote_identity_ledger: Arc<std::sync::Mutex<RemoteIdentityLedger>>,
    /// Synchronous mirror of which peers are currently Direct.
    ///
    /// Kept in lockstep with every `ConnectionState` transition (the single
    /// choke point for state changes), so the UDP dynamic-socket eviction can
    /// re-verify "is this peer Direct?" inside its socket-state lock without
    /// ever awaiting the async peer manager there.
    direct_peers: Arc<std::sync::Mutex<HashSet<String>>>,
    /// Whether this daemon currently has a relay-backed topology. This is
    /// set from the resolved relay catalog, not only from the initial static
    /// config, so a peer cannot become the first Direct data path merely
    /// because the relay supervisor has not published its transport slot yet.
    /// The value is process-wide; the generation-bound gate lives on each
    /// `PeerConnection`.
    relay_first_required: Arc<std::sync::atomic::AtomicBool>,
    /// The authoritative failure-recovery scheduler: one traversal plan per
    /// `(peer_id, network_generation, recovery_epoch)` with hard per-epoch
    /// budgets (probe credit, fresh generations, HTTP publishes) and the
    /// feedback-driven stage machine.
    recovery_epochs: Arc<RwLock<HashMap<String, RecoveryEpochState>>>,
    /// Process-monotonic identity for concrete recovery-epoch allocations.
    /// Numeric per-peer epochs restart after teardown, so delayed reservations
    /// use this non-reused allocation ID to fail closed across epoch ABA.
    recovery_epoch_allocation_id: std::sync::atomic::AtomicU64,
    /// Outbound-UDP liveness verdict cache, keyed by `(peer_id, generation)`.
    /// TTL-bounded (`config.network.udp_liveness_ttl_ms`) and invalidated on
    /// generation change (a new egress IP makes the old verdict meaningless —
    /// same reset semantics as the adaptive port-learner cache).  Written by
    /// the spawned probe task; consumed at the next tick's admission
    /// (`apply_cached_liveness_block`, called from `recovery_epoch_admit`
    /// before its `recovery_epochs` write lock).
    outbound_liveness_cache: Arc<RwLock<HashMap<(String, u64), LivenessCacheEntry>>>,
    /// Bounded C=0 (mutual-APD, no mutually-admitted endpoint pair)
    /// fresh-fresh attempt ledger, keyed by `(peer_id, generation)`.  Written
    /// by `c0_pair_attempt`; read by `c0_pair_admission` before scheduling a
    /// fresh-fresh synchronized pair.  Reset on generation change (a new
    /// egress IP invalidates every old pair — same reset semantics as the
    /// adaptive port-learner and liveness caches).
    c0_pair_ledgers: Arc<RwLock<HashMap<(String, u64), C0PairLedger>>>,
    /// Lock-free per-peer direct-commit sequence mirror.  Bumped inside the
    /// network-epoch critical section together with the Direct state
    /// transition, so outbound punch loops can gate every actual UDP send on
    /// it and prove post-promotion sends are impossible.
    direct_commit_seq_mirror: Arc<std::sync::Mutex<HashMap<String, u64>>>,
    /// Wake-up for any direct-commit bump.  Waiters re-check the peer's
    /// sequence after waking.
    direct_commit_notify: Arc<Notify>,
    /// Lock-free exact pair selected by the latest Direct commit.  Hard↔Hard
    /// confirmation reads this beside `direct_commit_seq_mirror` so a
    /// contended connection writer cannot delay the grace timer.
    direct_commit_pair_mirror:
        Arc<std::sync::Mutex<HashMap<String, DirectCommitPairSnapshot>>>,
    /// Lock-free per-peer relay-confirm sequence mirror.  Bumped (and notified)
    /// whenever a peer's forced-relay encrypted probe/ACK confirms the relay
    /// path, so the outbound actor can flush a waiting first packet the moment
    /// RelayPeerConfirmed lands.
    relay_confirm_seq_mirror: Arc<std::sync::Mutex<HashMap<String, u64>>>,
    /// Wake-up for any relay-confirm bump.  Waiters re-check the peer's
    /// sequence after waking.
    relay_confirm_notify: Arc<Notify>,
    /// Bounded per-peer relay probe expectations: the token the local daemon
    /// sent in a forced-relay probe request, against which a relay-ingress ACK
    /// is verified before RelayPeerConfirmed is set.
    relay_probe_expectations:
        Arc<std::sync::Mutex<HashMap<String, crate::relay_probe::RelayProbeExpectation>>>,
    /// Authenticated Relay business evidence which could not immediately take
    /// the epoch/connection transaction. One newest-wins entry per peer, with
    /// a strict TTL and global capacity bound.
    pending_relay_business_evidence:
        Arc<std::sync::Mutex<HashMap<String, PendingRelayBusinessEvidence>>>,
    /// Bounded per-peer path-commit expectations: the token the local daemon
    /// sent in a synthetic path-commit request, against which a relay-ingress
    /// ACK is verified before the relay-first business gate is closed for
    /// one-directional traffic (audit P0-4).
    path_commit_expectations:
        Arc<std::sync::Mutex<HashMap<String, crate::path_commit::PathCommitExpectation>>>,
    /// Stale-peer quarantine metadata (relay 404 reason/backoff history).
    ///
    /// Dataplane admission never reads this async map: benign Tokio-lock
    /// contention must not turn an active quarantine into a false negative.
    quarantined_peers: Arc<tokio::sync::Mutex<HashMap<String, PeerQuarantineState>>>,
    /// Authoritative no-await quarantine deadline mirror.
    ///
    /// Quarantine, unquarantine, and peer removal publish this map while they
    /// own `network_epoch_gate`; synchronous relay/UDP admission paths take
    /// this ordinary mutex and therefore cannot fail open on lock contention.
    quarantine_deadline_mirror: Arc<std::sync::Mutex<HashMap<String, Instant>>>,
    /// Short-lived relay registration grace state. A relay `peer_not_found`
    /// can race a reconnect/handoff while control still reports the same
    /// incarnation online; keep the active recovery alive until this bounded
    /// confirmation window expires.
    relay_not_found_grace: Arc<tokio::sync::Mutex<HashMap<String, RelayNotFoundGraceState>>>,
    /// Hook cancelling an active punch session when a peer is quarantined;
    /// registered by the daemon with its `PunchAttemptDeduplicator`.
    punch_cancel_hook: PunchCancelHookSlot,
    /// Hook cancelling the transport-owned relay-backoff heartbeat when a
    /// peer becomes Direct, leaves, or loses its relay safety net.
    relay_backoff_heartbeat_cancel_hook: PunchCancelHookSlot,
    /// Optional per-process connection timeline.  The daemon installs it after
    /// construction; path-confirmation events (`first_direct_probe_sent`,
    /// `relay_peer_confirmed`, `direct_promoted`) emit through it, no-oping
    /// when it is not installed (unit tests).
    timeline: std::sync::Mutex<Option<Arc<ConnectionTimeline>>>,
    /// Process-wide outbound loss counters: terminal DROPS (packets/bytes) by
    /// stable reason code plus observable send-failure ATTEMPTS.  `/status`
    /// reports both structurally so business-packet loss is observable
    /// without log greps.  The daemon shares the SAME sink with the WireGuard
    /// transport (session-not-ready queue loss) so one `/status.stats` shows
    /// every loss source.
    outbound_loss_slot:
        Arc<std::sync::Mutex<Option<Arc<tokio::sync::Mutex<OutboundLossCounters>>>>>,
    outbound_loss_default: Arc<tokio::sync::Mutex<OutboundLossCounters>>,
    /// Configuration.
    config: Config,
}

/// Aggregate counter of lost outbound business packets for one reason code.
#[derive(Debug, Clone, Copy, Default, serde::Serialize, serde::Deserialize)]
pub struct OutboundDropCounters {
    pub packets: u64,
    pub bytes: u64,
}

/// Shared outbound loss accounting: terminal drops by reason code plus
/// transient send-failure attempts (never double-counted with drops).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct OutboundLossCounters {
    /// Packets that were TERMINALLY dropped (never handed to a transport).
    pub drops: HashMap<String, OutboundDropCounters>,
    /// Transient send attempts that failed (the packet was re-parked and
    /// retried; a later terminal drop lands in `drops`, never both).
    pub send_failures: HashMap<String, OutboundDropCounters>,
    /// Bounded event ledger for answering which peer/generation lost or
    /// retried a packet.  The aggregate maps above remain for inexpensive
    /// counters, while this ledger carries the correlation and time data
    /// needed by the acceptance harness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<OutboundLossEvent>,
}

/// One structured outbound-loss or send-failure event.  Every production
/// dataplane event has a peer, generation, stable reason, byte/packet counts,
/// and the daemon timeline correlation id; there is no log-only loss path.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OutboundLossEvent {
    pub kind: String,
    pub peer_id: String,
    pub generation: u64,
    pub reason_code: String,
    pub packets: u64,
    pub bytes: u64,
    pub correlation_id: String,
    pub at_ms: u64,
}

/// Metadata changes observed while applying one control-plane peer snapshot.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerUpdate {
    pub is_new: bool,
    pub virtual_ip_changed: bool,
    pub endpoint_changed: bool,
    pub public_key_changed: bool,
    /// The control-plane heartbeat advanced only user-visible liveness time;
    /// no identity, reachability, NAT, path or relay metadata changed.
    pub last_seen_only: bool,
}

fn derive_probe_mac_key(config: &Config, peer_public_key: &str) -> Option<ProbeMacKey> {
    let local_private = decode_x25519_key_bytes(&config.node.private_key).ok()?;
    let peer_public = decode_x25519_key_bytes(peer_public_key).ok()?;
    let identity = NodeIdentity::from_private_key(local_private);
    let shared = identity.diffie_hellman(&peer_public).ok()?;
    Some(hmac(&shared, PROBE_MAC_KEY_DOMAIN))
}

fn derive_session_probe_mac_key(base_key: &ProbeMacKey, session_id: &str) -> ProbeMacKey {
    let mut input = Vec::with_capacity(PROBE_MAC_SESSION_KEY_DOMAIN.len() + session_id.len());
    input.extend_from_slice(PROBE_MAC_SESSION_KEY_DOMAIN);
    input.extend_from_slice(session_id.as_bytes());
    hmac(base_key, &input)
}

fn derive_ephemeral_session_probe_mac_key(
    base_key: &ProbeMacKey,
    session_id: &str,
    ephemeral_shared: &[u8; 32],
) -> ProbeMacKey {
    let mut input = Vec::with_capacity(
        PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN.len() + session_id.len() + ephemeral_shared.len(),
    );
    input.extend_from_slice(PROBE_MAC_EPHEMERAL_SESSION_KEY_DOMAIN);
    input.extend_from_slice(session_id.as_bytes());
    input.extend_from_slice(ephemeral_shared);
    hmac(base_key, &input)
}

fn probe_mac_key_for_binding(base_key: ProbeMacKey, binding: &ProbeSessionBinding) -> ProbeMacKey {
    match binding.session_id.as_deref() {
        Some(session_id) if !session_id.is_empty() => match binding.ephemeral_shared.as_ref() {
            Some(shared) => derive_ephemeral_session_probe_mac_key(&base_key, session_id, shared),
            None => derive_session_probe_mac_key(&base_key, session_id),
        },
        _ => base_key,
    }
}

fn active_probe_binding(conn: &PeerConnection) -> ProbeSessionBinding {
    ProbeSessionBinding {
        token: conn.probe_binding_token.clone(),
        session_id: conn.probe_session_id.clone(),
        ephemeral_shared: conn.probe_ephemeral_shared,
    }
}

fn effective_probe_mac_key(conn: &PeerConnection) -> Option<ProbeMacKey> {
    let base_key = conn.probe_mac_key?;
    Some(probe_mac_key_for_binding(
        base_key,
        &active_probe_binding(conn),
    ))
}

fn probe_key_type(conn: &PeerConnection) -> &'static str {
    if conn.probe_mac_key.is_none() {
        "none"
    } else if conn.probe_session_id.is_none() {
        "static"
    } else if conn.probe_ephemeral_shared.is_some() {
        "ephemeral_session"
    } else {
        "session"
    }
}

fn decode_x25519_key_bytes(hex_value: &str) -> std::result::Result<[u8; 32], ()> {
    let bytes = hex::decode(hex_value.trim()).map_err(|_| ())?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ())
}
