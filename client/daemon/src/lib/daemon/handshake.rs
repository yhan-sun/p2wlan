#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandshakeOwnerKind {
    EventInitiatorReserve,
    EventInitiatorPrepare,
    EventInitiatorPublish,
    MaintenanceInitiator,
    Responder,
    InitiatorAnswer,
    Cleanup,
}

impl HandshakeOwnerKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::EventInitiatorReserve => "event_initiator_reserve",
            Self::EventInitiatorPrepare => "event_initiator_prepare",
            Self::EventInitiatorPublish => "event_initiator_publish",
            Self::MaintenanceInitiator => "maintenance_initiator",
            Self::Responder => "responder",
            Self::InitiatorAnswer => "initiator_answer",
            Self::Cleanup => "cleanup",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HandshakeLeaseIdentity {
    peer_id: String,
    owner_kind: HandshakeOwnerKind,
    reservation_owner: Option<u64>,
    network_generation: u64,
    peer_session_generation: Option<PeerSessionGeneration>,
    phase: &'static str,
}

impl HandshakeLeaseIdentity {
    fn new(
        peer_id: &str,
        owner_kind: HandshakeOwnerKind,
        reservation_owner: Option<u64>,
        network_generation: u64,
        peer_session_generation: Option<PeerSessionGeneration>,
        phase: &'static str,
    ) -> Self {
        Self {
            peer_id: peer_id.to_string(),
            owner_kind,
            reservation_owner,
            network_generation,
            peer_session_generation,
            phase,
        }
    }

    fn detail(&self) -> String {
        format!(
            "peer={} owner_kind={} phase={} reservation_owner={} generation={} peer_session_generation={}",
            self.peer_id,
            self.owner_kind.as_str(),
            self.phase,
            self.reservation_owner
                .map_or_else(|| "none".to_string(), |owner| owner.to_string()),
            self.network_generation,
            self.peer_session_generation
                .map_or_else(|| "none".to_string(), |generation| generation.value().to_string()),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct HandshakeHolderSnapshot {
    identity: HandshakeLeaseIdentity,
    held_for: Duration,
}

impl HandshakeHolderSnapshot {
    fn detail(&self) -> String {
        format!(
            "holder_kind={} holder_phase={} holder_reservation_owner={} holder_generation={} holder_peer_session_generation={} holder_held_ms={}",
            self.identity.owner_kind.as_str(),
            self.identity.phase,
            self.identity
                .reservation_owner
                .map_or_else(|| "none".to_string(), |owner| owner.to_string()),
            self.identity.network_generation,
            self.identity
                .peer_session_generation
                .map_or_else(|| "none".to_string(), |generation| generation.value().to_string()),
            self.held_for.as_millis(),
        )
    }
}

struct HandshakeHolderMetadata {
    lease_id: u64,
    identity: HandshakeLeaseIdentity,
    acquired_at: Instant,
}

struct HandshakePeerTurn {
    turn: Arc<Mutex<()>>,
    holder: std::sync::Mutex<Option<HandshakeHolderMetadata>>,
}

impl HandshakePeerTurn {
    fn new() -> Self {
        Self {
            turn: Arc::new(Mutex::new(())),
            holder: std::sync::Mutex::new(None),
        }
    }

    fn holder_snapshot(&self) -> Option<HandshakeHolderSnapshot> {
        self.holder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .map(|holder| HandshakeHolderSnapshot {
                identity: holder.identity.clone(),
                held_for: holder.acquired_at.elapsed(),
            })
    }
}

#[derive(Clone)]
struct HandshakeArbiter {
    peer_locks: Arc<std::sync::Mutex<HashMap<String, Weak<HandshakePeerTurn>>>>,
    next_lease_id: Arc<std::sync::atomic::AtomicU64>,
    timeline: Option<Arc<ConnectionTimeline>>,
}

impl Default for HandshakeArbiter {
    fn default() -> Self {
        Self {
            peer_locks: Arc::new(std::sync::Mutex::new(HashMap::new())),
            next_lease_id: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            timeline: None,
        }
    }
}

struct HandshakeLease {
    _guard: tokio::sync::OwnedMutexGuard<()>,
    peer_turn: Arc<HandshakePeerTurn>,
    identity: HandshakeLeaseIdentity,
    lease_id: u64,
    acquired_at: Instant,
    timeline: Option<Arc<ConnectionTimeline>>,
    /// Compile-time proof that a mutation turn cannot cross an `.await` in a
    /// `Send` production future.  The underlying Tokio guard is Send; this
    /// marker deliberately makes the higher-level lease non-Send.
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl Drop for HandshakeLease {
    fn drop(&mut self) {
        let held_for = self.acquired_at.elapsed();
        let mut holder = self
            .peer_turn
            .holder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if holder.as_ref().map(|holder| holder.lease_id) == Some(self.lease_id) {
            holder.take();
        }
        drop(holder);
        if let Some(timeline) = self.timeline.as_ref() {
            timeline.emit(
                "handshake_arbiter_released",
                None,
                None,
                Some(format!(
                    "{} held_us={}",
                    self.identity.detail(),
                    held_for.as_micros()
                )),
            );
        }
    }
}

#[derive(Clone, Debug)]
struct HandshakeAcquireContention {
    holder: Option<HandshakeHolderSnapshot>,
}

struct HandshakeWaitTelemetry {
    arbiter: HandshakeArbiter,
    identity: HandshakeLeaseIdentity,
    peer_turn: Arc<HandshakePeerTurn>,
    started_at: Instant,
    completed: bool,
}

impl HandshakeWaitTelemetry {
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for HandshakeWaitTelemetry {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.arbiter.emit_wait_result(
            "handshake_arbiter_cancelled",
            &self.identity,
            self.started_at.elapsed(),
            self.peer_turn.holder_snapshot().as_ref(),
            Some("acquisition_cancelled"),
        );
    }
}

impl HandshakeArbiter {
    fn new(timeline: Arc<ConnectionTimeline>) -> Self {
        Self {
            timeline: Some(timeline),
            ..Self::default()
        }
    }

    fn peer_turn(&self, peer_id: &str) -> Arc<HandshakePeerTurn> {
        let mut peer_locks = self
            .peer_locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(peer_lock) = peer_locks.get(peer_id).and_then(Weak::upgrade) {
            return peer_lock;
        }
        peer_locks.retain(|_, peer_lock| peer_lock.strong_count() > 0);
        let peer_lock = Arc::new(HandshakePeerTurn::new());
        peer_locks.insert(peer_id.to_string(), Arc::downgrade(&peer_lock));
        peer_lock
    }

    fn emit_wait_started(
        &self,
        identity: &HandshakeLeaseIdentity,
        holder: Option<&HandshakeHolderSnapshot>,
        wait_budget: Duration,
    ) {
        if let Some(timeline) = self.timeline.as_ref() {
            let holder = holder
                .map(HandshakeHolderSnapshot::detail)
                .unwrap_or_else(|| "holder_kind=none holder_phase=none".to_string());
            timeline.emit(
                "handshake_arbiter_wait_started",
                None,
                None,
                Some(format!(
                    "{} wait_budget_us={} {holder}",
                    identity.detail(),
                    wait_budget.as_micros()
                )),
            );
        }
    }

    fn emit_wait_result(
        &self,
        event: &'static str,
        identity: &HandshakeLeaseIdentity,
        waited: Duration,
        holder: Option<&HandshakeHolderSnapshot>,
        reason_code: Option<&'static str>,
    ) {
        if let Some(timeline) = self.timeline.as_ref() {
            let holder = holder
                .map(HandshakeHolderSnapshot::detail)
                .unwrap_or_else(|| "holder_kind=none holder_phase=none".to_string());
            timeline.emit(
                event,
                None,
                reason_code,
                Some(format!(
                    "{} wait_us={} {holder}",
                    identity.detail(),
                    waited.as_micros()
                )),
            );
        }
    }

    fn finish_acquire(
        &self,
        peer_turn: Arc<HandshakePeerTurn>,
        guard: tokio::sync::OwnedMutexGuard<()>,
        identity: HandshakeLeaseIdentity,
        waited: Duration,
    ) -> HandshakeLease {
        let lease_id = self
            .next_lease_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_add(1);
        let acquired_at = Instant::now();
        *peer_turn
            .holder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(HandshakeHolderMetadata {
            lease_id,
            identity: identity.clone(),
            acquired_at,
        });
        self.emit_wait_result("handshake_arbiter_acquired", &identity, waited, None, None);
        HandshakeLease {
            _guard: guard,
            peer_turn,
            identity,
            lease_id,
            acquired_at,
            timeline: self.timeline.clone(),
            _not_send: std::marker::PhantomData,
        }
    }

    fn try_acquire(
        &self,
        identity: HandshakeLeaseIdentity,
    ) -> std::result::Result<HandshakeLease, HandshakeAcquireContention> {
        let peer_turn = self.peer_turn(&identity.peer_id);
        let started_at = Instant::now();
        let holder = peer_turn.holder_snapshot();
        self.emit_wait_started(&identity, holder.as_ref(), Duration::ZERO);
        match peer_turn.turn.clone().try_lock_owned() {
            Ok(guard) => Ok(self.finish_acquire(peer_turn, guard, identity, started_at.elapsed())),
            Err(_) => {
                let holder = peer_turn.holder_snapshot();
                self.emit_wait_result(
                    "handshake_arbiter_contended",
                    &identity,
                    started_at.elapsed(),
                    holder.as_ref(),
                    Some("mutation_turn_contended"),
                );
                Err(HandshakeAcquireContention { holder })
            }
        }
    }

    /// Acquire one short mutation turn with a hard wait bound. External
    /// cancellation drops the future and is recorded by `HandshakeWaitTelemetry`.
    async fn acquire_with_timeout(
        &self,
        identity: HandshakeLeaseIdentity,
        wait_budget: Duration,
    ) -> Option<HandshakeLease> {
        let peer_turn = self.peer_turn(&identity.peer_id);
        let started_at = Instant::now();
        self.emit_wait_started(&identity, peer_turn.holder_snapshot().as_ref(), wait_budget);
        let mut telemetry = HandshakeWaitTelemetry {
            arbiter: self.clone(),
            identity: identity.clone(),
            peer_turn: peer_turn.clone(),
            started_at,
            completed: false,
        };
        match tokio::time::timeout(wait_budget, peer_turn.turn.clone().lock_owned()).await {
            Ok(guard) => {
                telemetry.complete();
                Some(self.finish_acquire(peer_turn, guard, identity, started_at.elapsed()))
            }
            Err(_) => {
                telemetry.complete();
                self.emit_wait_result(
                    "handshake_arbiter_timeout",
                    &identity,
                    started_at.elapsed(),
                    peer_turn.holder_snapshot().as_ref(),
                    Some("mutation_turn_timeout"),
                );
                None
            }
        }
    }

    #[cfg(test)]
    fn current_holder(&self, peer_id: &str) -> Option<HandshakeHolderSnapshot> {
        self.peer_turn(peer_id).holder_snapshot()
    }
}

/// A responder offer must never wait indefinitely behind an initiator or
/// lifecycle cleanup worker.  This is deliberately a lock-wait bound, not a
/// network/handshake timeout: the responder worker retries the same idempotent
/// offer when this bound is hit.
const RESPONDER_HANDSHAKE_ARBITER_TIMEOUT: Duration = Duration::from_millis(750);
const REASON_RESPONDER_HANDSHAKE_ARBITER_TIMEOUT: &str = "responder_handshake_arbiter_timeout";
const RESPONDER_SESSION_STAGE_TIMEOUT: Duration = Duration::from_millis(750);
const REASON_RESPONDER_SESSION_STAGE_TIMEOUT: &str = "responder_session_stage_timeout";
const REASON_RESPONDER_PROBE_BINDING_CONTENDED: &str =
    "responder_probe_binding_connections_contended";
const REASON_RESPONDER_COMMIT_CONTENDED: &str = "responder_answer_commit_contended";
const INITIATOR_ANSWER_HANDSHAKE_ARBITER_TIMEOUT: Duration = Duration::from_millis(100);
/// Correlate one control-plane session without writing the raw session token
/// to logs. This uses the existing local diagnostic fingerprint only; it is
/// not an authentication or identity value.
fn handshake_token_fingerprint(token: Option<&str>) -> String {
    token
        .map(|token| {
            format!(
                "{:016x}",
                crate::transport::wire_fingerprint(token.as_bytes())
            )
        })
        .unwrap_or_else(|| "legacy".to_string())
}

/// Deterministic pause after responder transport-grace refresh and before the
/// non-queuing Probe-binding connection transaction. Tests use this exact
/// production boundary to inject startup contention without timing sleeps.
#[cfg(test)]
#[derive(Debug)]
struct ResponderPostAnswerTestGate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Barrier,
}

#[cfg(test)]
impl ResponderPostAnswerTestGate {
    fn new() -> Self {
        Self {
            reached: tokio::sync::Notify::new(),
            release: tokio::sync::Barrier::new(2),
        }
    }
}

fn local_is_designated_handshake_initiator(
    local_public_key: &[u8; 32],
    peer_public_key: &[u8; 32],
) -> bool {
    local_public_key < peer_public_key
}

/// Return whether an already decoded, distinct peer identity should cause
/// this daemon to start an initiator transaction.  Equal keys are invalid
/// configuration and intentionally return true so the normal handshake path
/// emits its explicit identity error instead of silently suppressing it.
fn should_start_initiator_for_keys(
    local_public_key: &[u8; 32],
    peer_public_key: &[u8; 32],
) -> bool {
    local_public_key == peer_public_key
        || local_is_designated_handshake_initiator(local_public_key, peer_public_key)
}

fn should_start_initiator_for_encoded_keys(
    local_private_key: &str,
    peer_public_key: &str,
) -> Option<bool> {
    let local_private_key = decode_x25519_key(local_private_key, "node private key").ok()?;
    let peer_public_key = decode_x25519_key(peer_public_key, "peer public key").ok()?;
    let local_public_key = NodeIdentity::from_private_key(local_private_key).public_key();
    Some(should_start_initiator_for_keys(
        &local_public_key,
        &peer_public_key,
    ))
}

fn handshake_public_key_fingerprint(key: &[u8; 32]) -> String {
    format!("{:016x}", crate::transport::wire_fingerprint(key))
}

impl Daemon {
    /// Avoid creating a competing initiator worker when the static identity
    /// ordering already says this daemon is the responder.  Unknown or
    /// malformed identity material is allowed through so the normal handshake
    /// path can report the precise configuration error instead of silently
    /// suppressing it.
    fn should_start_initiator_handshake(&self, peer_info: &control::PeerInfo) -> bool {
        let local_public_fingerprint =
            decode_x25519_key(&self.config.node.private_key, "node private key")
                .ok()
                .map(|private_key| {
                    let identity = NodeIdentity::from_private_key(private_key);
                    handshake_public_key_fingerprint(&identity.public_key())
                })
                .unwrap_or_else(|| "invalid".to_string());
        let peer_public_fingerprint = decode_x25519_key(&peer_info.public_key, "peer public key")
            .ok()
            .map(|public_key| handshake_public_key_fingerprint(&public_key))
            .unwrap_or_else(|| "invalid".to_string());
        let Some(should_start) = should_start_initiator_for_encoded_keys(
            &self.config.node.private_key,
            &peer_info.public_key,
        ) else {
            self.timeline.emit(
                "initiator_handshake_role",
                None,
                Some("invalid_identity_material"),
                Some(format!(
                    "peer={} role=unknown local_public_fp={} peer_public_fp={}",
                    peer_info.node_id, local_public_fingerprint, peer_public_fingerprint
                )),
            );
            return true;
        };
        self.timeline.emit(
            "initiator_handshake_role",
            None,
            None,
            Some(format!(
                "peer={} role={} local_public_fp={} peer_public_fp={}",
                peer_info.node_id,
                if should_start {
                    "initiator"
                } else {
                    "responder"
                },
                local_public_fingerprint,
                peer_public_fingerprint,
            )),
        );
        if !should_start {
            self.timeline.emit(
                "initiator_handshake_suppressed",
                None,
                Some("deterministic_responder_role"),
                Some(format!("peer={} local_role=responder", peer_info.node_id)),
            );
        }
        should_start
    }
}

fn should_mark_connecting_after_session_install(
    replaced_existing_session: bool,
    current_state: Option<ConnectionState>,
) -> bool {
    !replaced_existing_session
        && matches!(
            current_state,
            Some(ConnectionState::Idle | ConnectionState::Failed)
        )
}

include!("handshake/init.rs");
include!("handshake/initiate.rs");
include!("handshake/candidates.rs");
include!("handshake/offer.rs");
include!("handshake/answer.rs");
include!("handshake/identity.rs");
