// ============================================================
// Peer Manager
// ============================================================

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

#[derive(Debug, Clone)]
pub(crate) struct HardHardSessionRecord {
    pub(crate) session_id: String,
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

/// Manages all peer connections.
pub struct PeerManager {
    /// Active peer connections, indexed by node ID.
    connections: Arc<RwLock<HashMap<String, PeerConnection>>>,
    /// Last complete diagnostics snapshot.  Diagnostics must never turn a
    /// contended connection writer into a false empty roster; the snapshot is
    /// only a fallback while the live lock is unavailable.
    diagnostics_cache: Arc<std::sync::Mutex<Option<Vec<PeerDiagnostics>>>>,
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
    hard_hard_sessions:
        Arc<tokio::sync::Mutex<HashMap<(String, String), HardHardSessionRecord>>>,
    /// Time-limited prediction-error fingerprint per peer.
    fresh_mapping_history: Arc<std::sync::Mutex<HashMap<String, VecDeque<FreshMappingPredictionResult>>>>,
    /// Per-peer high-water of the remote's fresh-mapping prediction identity.
    ///
    /// The remote signals fresh predictions as `predicted_fresh:<boot>:<gen>`.
    /// Only a strictly newer (boot, generation) may be applied: a superseded
    /// generation that an old task managed to send late is rejected before it
    /// can overwrite the current candidate set or start a punch session.  The
    /// high-water follows the peer's incarnation: public-key identity changes
    /// reset it, while a plain PeerLeft does not (a late old-incarnation
    /// signal must stay rejected after the peer rejoins).
    remote_fresh_generations:
        Arc<std::sync::Mutex<HashMap<String, crate::FreshPredictionId>>>,
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
    /// The last public key each node ID joined with, surviving `remove_peer`.
    ///
    /// The remote fresh-prediction space is bound to the peer's identity: a
    /// PeerLeft followed by a rejoin with a NEW public key must not inherit
    /// the old incarnation's high-water (its predictions would be judged
    /// stale forever).  The identity map outlives the connection so
    /// `add_peer` can compare the rejoining key even when `is_new`.
    remote_fresh_identity_keys: Arc<std::sync::Mutex<HashMap<String, String>>>,
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
    /// Bounded per-peer path-commit expectations: the token the local daemon
    /// sent in a synthetic path-commit request, against which a relay-ingress
    /// ACK is verified before the relay-first business gate is closed for
    /// one-directional traffic (audit P0-4).
    path_commit_expectations:
        Arc<std::sync::Mutex<HashMap<String, crate::path_commit::PathCommitExpectation>>>,
    /// Authoritative stale-peer quarantine state (relay 404 isolation).
    quarantined_peers: Arc<tokio::sync::Mutex<HashMap<String, PeerQuarantineState>>>,
    /// Short-lived relay registration grace state. A relay `peer_not_found`
    /// can race a reconnect/handoff while control still reports the same
    /// incarnation online; keep the active recovery alive until this bounded
    /// confirmation window expires.
    relay_not_found_grace:
        Arc<tokio::sync::Mutex<HashMap<String, RelayNotFoundGraceState>>>,
    /// Hook cancelling an active punch session when a peer is quarantined;
    /// registered by the daemon with its `PunchAttemptDeduplicator`.
    punch_cancel_hook: PunchCancelHookSlot,
    /// Hook cancelling the transport-owned relay-backoff heartbeat when a
    /// peer becomes Direct, leaves, or loses its relay safety net.
    relay_backoff_heartbeat_cancel_hook: PunchCancelHookSlot,
    /// Hook requesting an immediate, bounded candidate re-publication and
    /// synchronized direct retry after a direct probe has failed.  The hook
    /// is installed by the daemon's UDP runtime and must be nonblocking.
    direct_recovery_kick_hook: DirectRecoveryKickHookSlot,
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
    outbound_loss_slot: Arc<
        std::sync::Mutex<Option<Arc<tokio::sync::Mutex<OutboundLossCounters>>>>,
    >,
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

fn probe_mac_key_for_binding(
    base_key: ProbeMacKey,
    binding: &ProbeSessionBinding,
) -> ProbeMacKey {
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
    Some(probe_mac_key_for_binding(base_key, &active_probe_binding(conn)))
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
