use p2pnet_nat::adaptive::{DirectionPattern, ReverseDetector, StepLearner};
use p2pnet_nat::mapping::{
    build_model_for_batch, infer_allocation_model, predict_ports_with_learning, MappingBatch,
    MappingObservation, ModelRejection, PortModel, PortModelKind,
};

const MEASUREMENT_SOFTWARE_TAG: &str = "P2WLAN/0.2";
/// A spawned dynamic reader should reach its first socket receive poll
/// immediately.  Bound the handshake so a broken runtime/task cannot leave a
/// fresh-mapping generation waiting forever before its first STUN request.
const DYNAMIC_READER_READY_TIMEOUT: Duration = Duration::from_secs(1);
const HARD_HARD_BIRTHDAY_WAVE_INTERVAL: Duration = Duration::from_millis(20);
const HARD_HARD_BIRTHDAY_WAVES: usize = 2;

/// Adaptive-prediction learner state for one network generation, scoped by
/// destination so a stride learned toward STUN observers is not blindly applied
/// to a real peer (audit P1-B: complex CGNAT may bucket allocation by target;
/// Mini-Air observed the peer-facing mapping diverge from the STUN direction).
#[derive(Debug)]
struct LearningCache {
    /// The network generation this cache was last synced to; any other value
    /// forces a full reset (a new allocator invalidates every learned stride
    /// and direction).
    network_generation: u64,
    /// (destination scope) -> (cross-batch step learner, direction detector).
    /// The scope separates STUN-observer allocation from per-peer allocation so
    /// a peer whose real direction differs from the STUN direction is not
    /// dragged toward the STUN-learned stride.
    entries: HashMap<DestinationScope, (StepLearner, ReverseDetector)>,
}

/// The destination an allocation-sequence measurement was taken toward.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DestinationScope {
    /// The measurement was a batch of STUN-observer requests on a fresh socket.
    /// This is the shared prior used when no peer-scope evidence exists.
    Stun,
    /// The measurement/observation was toward one specific peer (its actual
    /// mapping port observed on the wire).  Peer-scope evidence, when present,
    /// is authoritative for that peer over the STUN prior.
    Peer(String),
}

impl LearningCache {
    /// An empty cache that resets on first use (its generation starts out of
    /// sync with any real one).
    fn new() -> Self {
        Self {
            network_generation: u64::MAX,
            entries: HashMap::new(),
        }
    }

    /// Drop all learned state when the network generation moved on.
    fn reset_if_generation_changed(&mut self, generation: u64) {
        if generation != self.network_generation {
            self.entries.clear();
            self.network_generation = generation;
        }
    }

    fn entry(&mut self, scope: DestinationScope) -> &mut (StepLearner, ReverseDetector) {
        self.entries
            .entry(scope)
            .or_insert_with(|| (StepLearner::new(), ReverseDetector::new()))
    }

    /// The peer-scope learner for `peer_id`, or `None` when no peer-scope
    /// evidence was ever observed for it.
    fn peer_scope(&self, peer_id: &str) -> Option<&(StepLearner, ReverseDetector)> {
        self.entries
            .get(&DestinationScope::Peer(peer_id.to_string()))
    }
}

/// A point-in-time read of the adaptive learner for one public IP, used both as
/// the predictor input and as the fields logged/recorded for diagnostics.
#[derive(Debug, Clone, Copy)]
struct LearningSnapshot {
    /// Cross-batch EWMA stride estimate (signed — a reverse allocator learns a
    /// negative stride) when the learner has a valid reading, else `None`.  A
    /// `Some(0)` reading is a no-consensus placeholder the predictor treats as
    /// "no useful stride".
    step_estimate: Option<i16>,
    /// How many times the estimate changed (learning trajectory).
    revision_count: u32,
    /// Detected allocation direction of the peer's fresh mappings.
    direction: DirectionPattern,
}



/// The standalone exact-socket API returns a complete report to its caller,
/// so it performs the terminal all-physical-failure classification itself.
/// Birthday workers intentionally do not call this helper: their scheduler
/// must first give every target and bounded wave an opportunity to send.
fn finalize_physical_send_failure(report: &mut PunchSendReport) {
    if report.failure_kind.is_none()
        && report.logical_probes_attempted > 0
        && report.logical_probes_sent == 0
        && report.logical_probe_send_failures > 0
        && report.physical_send_errors > 0
    {
        report.failure_kind = Some(BirthdaySweepFailureKind::Send);
    }
}

fn model_deltas(batch: &MappingBatch) -> Vec<i16> {
    let ports = batch.ordered_ports();
    ports
        .windows(2)
        .map(|pair| p2pnet_nat::modular_difference(pair[0], pair[1]))
        .collect()
}

/// Whether a target endpoint may receive a fresh-mapping punch.
///
/// Production filters to real public probe endpoints; unit tests simulate the
/// peer's public side on the loopback NAT address, and the NAT-sim harness
/// (`config.network.fresh_mapping_harness_loopback`) deliberately allows
/// loopback endpoints so the deterministic dual-NAT simulation exercises the
/// production fresh path.
fn fresh_mapping_target_eligible(endpoint: SocketAddr, allow_loopback: bool) -> bool {
    if is_public_probe_endpoint(endpoint) {
        return true;
    }
    if allow_loopback && endpoint.ip().is_loopback() {
        return true;
    }
    #[cfg(test)]
    {
        endpoint.ip().is_loopback()
    }
    #[cfg(not(test))]
    {
        let _ = endpoint;
        false
    }
}

fn monotonic_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Generate a bounded, token-scoped birthday window. It deliberately uses a
/// permutation stride over the UDP port ring and stops at the negotiated
/// level; it never enumerates the full 65,535-port space.
fn hard_hard_birthday_candidates(
    public_ip: IpAddr,
    observed_ports: &[u16],
    level: usize,
    session_token: &str,
) -> Vec<SocketAddr> {
    let mut seed = 0xcbf29ce484222325u64;
    for byte in public_ip.to_string().bytes().chain(session_token.bytes()) {
        seed ^= u64::from(byte);
        seed = seed.wrapping_mul(0x100000001b3);
    }
    // Walk the non-zero UDP port ring with an odd stride.  Keep the stride
    // below 65535: a stride equal to the modulus would repeat one port and
    // could make a bounded level appear shorter than requested.
    let modulus = u64::from(u16::MAX);
    let stride = (seed % (modulus - 1)) | 1;
    let mut candidates = Vec::with_capacity(level);
    let mut seen = HashSet::new();
    for port in observed_ports {
        if *port != 0 && seen.insert(*port) {
            candidates.push(SocketAddr::new(public_ip, *port));
            if candidates.len() == level {
                return candidates;
            }
        }
    }
    let origin = seed % modulus;
    for index in 0..level.saturating_mul(4) {
        let port = ((origin + (index as u64).saturating_mul(stride)) % modulus + 1) as u16;
        if seen.insert(port) {
            candidates.push(SocketAddr::new(public_ip, port));
            if candidates.len() == level {
                break;
            }
        }
    }
    candidates
}

pub(crate) fn hard_hard_birthday_socket_count(level: usize) -> usize {
    match level {
        0..=64 => 2,
        65..=128 => 4,
        _ => 8,
    }
}

fn hard_hard_birthday_capacity_plan(
    requested_level: usize,
    attached_socket_count: usize,
) -> Option<(usize, usize)> {
    let requested_level = match requested_level {
        0..=64 => 64,
        65..=128 => 128,
        _ => 256,
    };
    let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
    let available_socket_count = if attached_socket_count >= 8 {
        8
    } else if attached_socket_count >= 4 {
        4
    } else if attached_socket_count >= 2 {
        2
    } else {
        return None;
    };
    let actual_socket_count = available_socket_count.min(requested_socket_count);
    let actual_level = match actual_socket_count {
        2 => 64,
        4 => 128,
        8 => 256,
        _ => return None,
    };
    Some((actual_level, actual_socket_count))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BirthdaySocketPlan {
    requested_socket_count: usize,
    attached_socket_count: usize,
    usable_socket_count: usize,
    unavailable_socket_count: usize,
    usable_socket_indices: Vec<usize>,
}

/// Convert the exact session socket snapshot into the only socket list the
/// birthday scheduler is allowed to use.  This deliberately has no pool
/// lookup or "best effort" substitution: a missing requested member remains
/// unavailable and lowers the wave plan.
fn hard_hard_birthday_socket_plan(
    requested_level: usize,
    snapshot: Vec<HardHardSocketSnapshot>,
) -> BirthdaySocketPlan {
    let requested_socket_count = hard_hard_birthday_socket_count(requested_level);
    let attached_socket_count = snapshot.iter().filter(|entry| entry.attached).count();
    let usable_socket_indices = snapshot
        .into_iter()
        .filter(|entry| entry.usable)
        .map(|entry| entry.socket_index)
        .collect::<Vec<_>>();
    let usable_socket_count = usable_socket_indices.len();
    BirthdaySocketPlan {
        requested_socket_count,
        attached_socket_count,
        usable_socket_count,
        unavailable_socket_count: requested_socket_count.saturating_sub(usable_socket_count),
        usable_socket_indices,
    }
}

fn record_birthday_worker_result(
    wave_report: &mut PunchSendReport,
    wave_fully_completed: &mut bool,
    failure_kind: &mut Option<BirthdaySweepFailureKind>,
    joined: std::result::Result<(usize, Result<PunchSendReport>), tokio::task::JoinError>,
) {
    match joined {
        Ok((_assigned_count, Ok(report))) => {
            *wave_fully_completed &=
                report.target_processing_completed && report.failure_kind.is_none();
            *failure_kind = combine_birthday_failure_kind(*failure_kind, report.failure_kind);
            merge_punch_send_reports(wave_report, report);
        }
        Ok((assigned_count, Err(_error))) => {
            *wave_fully_completed = false;
            *failure_kind = combine_birthday_failure_kind(
                *failure_kind,
                Some(BirthdaySweepFailureKind::from_probe_failure(
                    ProbeSendFailureKind::ProbeRegistrationFailed,
                )),
            );
            wave_report.probe_path_errors = wave_report.probe_path_errors.saturating_add(1);
            wave_report.targets_cancelled = wave_report
                .targets_cancelled
                .saturating_add(u32::try_from(assigned_count).unwrap_or(u32::MAX));
        }
        Err(_join_error) => {
            *wave_fully_completed = false;
            *failure_kind = combine_birthday_failure_kind(
                *failure_kind,
                Some(BirthdaySweepFailureKind::WorkerJoin),
            );
            wave_report.worker_failed = true;
        }
    }
}

fn combine_birthday_failure_kind(
    left: Option<BirthdaySweepFailureKind>,
    right: Option<BirthdaySweepFailureKind>,
) -> Option<BirthdaySweepFailureKind> {
    match (left, right) {
        (None, value) | (value, None) => value,
        (Some(left), Some(right)) => {
            if birthday_failure_priority(right) > birthday_failure_priority(left) {
                Some(right)
            } else {
                Some(left)
            }
        }
    }
}

const fn birthday_failure_priority(kind: BirthdaySweepFailureKind) -> u8 {
    match kind {
        BirthdaySweepFailureKind::WorkerJoin => 100,
        BirthdaySweepFailureKind::NetworkGenerationChanged => 90,
        BirthdaySweepFailureKind::CandidateEpochChanged => 80,
        BirthdaySweepFailureKind::ProfileGenerationChanged => 70,
        BirthdaySweepFailureKind::PeerSessionChanged => 60,
        BirthdaySweepFailureKind::SessionRetired => 50,
        BirthdaySweepFailureKind::SocketRevoked => 40,
        BirthdaySweepFailureKind::SocketUnavailable => 30,
        BirthdaySweepFailureKind::ProbeRegistrationFailed => 20,
        BirthdaySweepFailureKind::ProbeEncodingFailed => 10,
        BirthdaySweepFailureKind::Send => 1,
    }
}

fn merge_punch_send_reports(destination: &mut PunchSendReport, source: PunchSendReport) {
    let source_logical_sent = source.logical_probes_sent.max(source.packets_sent);
    let source_logical_attempted = source.logical_probes_attempted.max(source_logical_sent);
    let source_targets_examined = source.targets_examined.max(source.targets_attempted);
    let source_physical_datagrams_sent = source
        .physical_datagrams_sent
        .max(source.per_socket_sent.iter().map(|(_, sent)| *sent).sum());
    destination.packets_sent = destination.packets_sent.saturating_add(source_logical_sent);
    destination.logical_probes_sent = destination
        .logical_probes_sent
        .saturating_add(source_logical_sent);
    destination.logical_probes_attempted = destination
        .logical_probes_attempted
        .saturating_add(source_logical_attempted);
    destination.logical_probe_send_failures = destination
        .logical_probe_send_failures
        .saturating_add(source.logical_probe_send_failures);
    destination.physical_datagrams_sent = destination
        .physical_datagrams_sent
        .saturating_add(source_physical_datagrams_sent);
    destination.physical_send_errors = destination
        .physical_send_errors
        .saturating_add(source.physical_send_errors);
    destination.partial_physical_send_errors = destination
        .partial_physical_send_errors
        .saturating_add(source.partial_physical_send_errors);
    destination.probe_path_errors = destination
        .probe_path_errors
        .saturating_add(source.probe_path_errors);
    destination.budget_skipped = destination
        .budget_skipped
        .saturating_add(source.budget_skipped);
    destination.targets_assigned = destination
        .targets_assigned
        .saturating_add(source.targets_assigned);
    destination.targets_examined = destination
        .targets_examined
        .saturating_add(source_targets_examined);
    destination.targets_attempted = destination
        .targets_attempted
        .saturating_add(source.targets_attempted);
    destination.targets_cancelled = destination
        .targets_cancelled
        .saturating_add(source.targets_cancelled);
    if destination.targets_assigned == 0 {
        destination.target_processing_completed = source.target_processing_completed;
    } else {
        destination.target_processing_completed &= source.target_processing_completed;
    }
    destination.worker_failed |=
        source.worker_failed || source.failure_kind == Some(BirthdaySweepFailureKind::WorkerJoin);
    destination.failure_kind =
        combine_birthday_failure_kind(destination.failure_kind, source.failure_kind);
    destination.epoch_budget_exhausted |= source.epoch_budget_exhausted;
    destination.candidate_iteration_capped |= source.candidate_iteration_capped;
    destination.first_send_at_ms = match (destination.first_send_at_ms, source.first_send_at_ms) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, right) => right,
        (left, None) => left,
    };
    destination.last_send_at_ms = match (destination.last_send_at_ms, source.last_send_at_ms) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (None, right) => right,
        (left, None) => left,
    };
    for endpoint in source.sent_target_endpoints {
        if !destination.sent_target_endpoints.contains(&endpoint) {
            destination.sent_target_endpoints.push(endpoint);
        }
    }
    for (socket_index, sent) in source.per_socket_sent {
        if let Some((_, existing)) = destination
            .per_socket_sent
            .iter_mut()
            .find(|(index, _)| *index == socket_index)
        {
            *existing = existing.saturating_add(sent);
        } else {
            destination.per_socket_sent.push((socket_index, sent));
        }
    }
    normalize_physical_send_dimensions(destination);
}

/// Keep the terminal/live physical-send invariant exact after reports from
/// several workers have been merged.  Every production Hard↔Hard physical
/// send records the actual socket, so the histogram is the authoritative
/// successful-datagram total rather than a lower/upper-bound diagnostic.
fn normalize_physical_send_dimensions(report: &mut PunchSendReport) {
    report
        .per_socket_sent
        .sort_unstable_by_key(|(socket_index, _)| *socket_index);
    report.physical_datagrams_sent = report.per_socket_sent.iter().map(|(_, sent)| *sent).sum();
}

pub(crate) fn update_birthday_sweep_counters(
    birthday: &mut BirthdaySweepReport,
    aggregate: &PunchSendReport,
) {
    birthday.targets_assigned = birthday
        .targets_assigned
        .max(aggregate.targets_assigned as usize);
    birthday.targets_attempted = aggregate.targets_attempted as usize;
    birthday.targets_examined =
        aggregate.targets_examined.max(aggregate.targets_attempted) as usize;
    let logical_probes_sent = aggregate.logical_probes_sent.max(aggregate.packets_sent);
    birthday.logical_probes_attempted =
        aggregate.logical_probes_attempted.max(logical_probes_sent) as usize;
    birthday.logical_probes_sent = logical_probes_sent as usize;
    birthday.logical_probe_send_failures = aggregate.logical_probe_send_failures as usize;
    birthday.physical_datagrams_sent = aggregate
        .per_socket_sent
        .iter()
        .map(|(_, sent)| *sent)
        .sum::<u32>() as usize;
    birthday.physical_send_errors = aggregate.physical_send_errors as usize;
    birthday.partial_physical_send_errors = aggregate.partial_physical_send_errors as usize;
    birthday.targets_budget_skipped = aggregate.budget_skipped as usize;
    birthday.targets_cancelled = aggregate.targets_cancelled as usize;
}

fn update_live_birthday_counters(
    live: &Option<Arc<StdMutex<LiveBirthdayProgress>>>,
    update: impl FnOnce(&mut LiveBirthdayCounters),
) {
    update_live_birthday_progress(live, |progress| update(&mut progress.counters));
}

fn update_live_birthday_progress(
    live: &Option<Arc<StdMutex<LiveBirthdayProgress>>>,
    update: impl FnOnce(&mut LiveBirthdayProgress),
) {
    let Some(live) = live else {
        return;
    };
    let mut progress = live.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    update(&mut progress);
}

pub(crate) fn apply_live_birthday_counters(
    report: &mut PunchSendReport,
    live: &LiveBirthdayProgress,
) {
    let counters = &live.counters;
    report.targets_assigned = report.targets_assigned.max(counters.targets_assigned);
    report.targets_examined = report.targets_examined.max(counters.targets_examined);
    report.targets_attempted = report.targets_attempted.max(counters.targets_attempted);
    report.targets_cancelled = report.targets_cancelled.max(counters.targets_cancelled);
    report.budget_skipped = report.budget_skipped.max(counters.budget_skipped);
    report.logical_probes_sent = report
        .logical_probes_sent
        .max(counters.logical_probes_sent)
        .max(report.packets_sent);
    report.logical_probes_attempted = report
        .logical_probes_attempted
        .max(counters.logical_probes_attempted)
        .max(report.logical_probes_sent);
    report.logical_probe_send_failures = report
        .logical_probe_send_failures
        .max(counters.logical_probe_send_failures);
    report.packets_sent = report.packets_sent.max(report.logical_probes_sent);
    report.physical_datagrams_sent = report
        .physical_datagrams_sent
        .max(counters.physical_datagrams_sent);
    report.physical_send_errors = report
        .physical_send_errors
        .max(counters.physical_send_errors);
    report.partial_physical_send_errors = report
        .partial_physical_send_errors
        .max(counters.partial_physical_send_errors);
    report.probe_path_errors = report.probe_path_errors.max(counters.probe_path_errors);
    for endpoint in &live.sent_target_endpoints {
        if !report.sent_target_endpoints.contains(endpoint) {
            report.sent_target_endpoints.push(*endpoint);
        }
    }
    report.unique_target_endpoints =
        u32::try_from(report.sent_target_endpoints.len()).unwrap_or(u32::MAX);
    for (socket_index, sent) in &live.per_socket_sent {
        if let Some((_, existing)) = report
            .per_socket_sent
            .iter_mut()
            .find(|(index, _)| index == socket_index)
        {
            *existing = (*existing).max(*sent);
        } else {
            report.per_socket_sent.push((*socket_index, *sent));
        }
    }
    report.first_send_at_ms = match (report.first_send_at_ms, live.first_send_at_ms) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (None, right) => right,
        (left, None) => left,
    };
    report.last_send_at_ms = match (report.last_send_at_ms, live.last_send_at_ms) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (None, right) => right,
        (left, None) => left,
    };
    normalize_physical_send_dimensions(report);
}

async fn publish_birthday_sweep_progress(
    progress: &Option<Arc<Mutex<BirthdaySweepProgress>>>,
    birthday: &BirthdaySweepReport,
    aggregate: &PunchSendReport,
) {
    let Some(progress) = progress else {
        return;
    };
    let live = {
        let current = progress.lock().await;
        current.live.clone()
    };
    let live_snapshot = live
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let mut published_aggregate = aggregate.clone();
    apply_live_birthday_counters(&mut published_aggregate, &live_snapshot);
    let mut published_birthday = birthday.clone();
    published_birthday.targets_assigned = published_birthday
        .targets_assigned
        .max(published_aggregate.targets_assigned as usize);
    update_birthday_sweep_counters(&mut published_birthday, &published_aggregate);
    let mut current = progress.lock().await;
    current.birthday = published_birthday;
    current.aggregate = published_aggregate;
}

pub(crate) fn hard_hard_birthday_wave_count(socket_count: usize) -> usize {
    match socket_count {
        0 => 0,
        1 => 1,
        _ => HARD_HARD_BIRTHDAY_WAVES,
    }
}

fn hard_hard_birthday_packets_planned(socket_count: usize, target_count: usize) -> usize {
    target_count.saturating_mul(hard_hard_birthday_wave_count(socket_count))
}

fn hard_hard_birthday_wave_assignments(
    socket_count: usize,
    targets: Vec<SocketAddr>,
    wave: usize,
) -> Vec<Vec<SocketAddr>> {
    if socket_count == 0 {
        return Vec::new();
    }
    let mut assignments = vec![Vec::new(); socket_count];
    let socket_offset = wave % socket_count;
    for (index, target) in targets.into_iter().enumerate() {
        assignments[(index + socket_offset) % socket_count].push(target);
    }
    assignments
}

/// Outcome of one atomic commit phase transition.
#[derive(Debug, Clone, Copy)]
struct CommitOutcome {
    /// Whether the socket transitioned from Provisional to
    /// CommittedPendingHandoff. A birthday speculative commit deliberately
    /// leaves `installed` empty so it can remain a receiver without replacing
    /// the window's single affinity pin.
    committed: bool,
    /// The affinity pin the commit replaced, captured under the same
    /// socket-state lock.  A cancelled generation must restore it so the
    /// peer keeps its previous working path — but only while the affinity
    /// still equals THIS commit's pin (a newer commit owns the affinity
    /// after that and a blind restore would downgrade it).
    predecessor: Option<PeerSocketPin>,
    /// The pin this commit installed. Post-commit rollback compares the live
    /// affinity against this pin before touching anything. `None` identifies
    /// a birthday speculative receiver, whose rollback never changes peer
    /// affinity.
    installed: Option<PeerSocketPin>,
    /// The committed-generation high-water value that fences this guard's
    /// handoff. Birthday speculative receivers share the first socket's
    /// value; a later generation therefore invalidates every old guard.
    generation_fence: u64,
    /// The entry's authenticated-evidence counter at commit time, snapshotted
    /// under the same lock.  The watcher's rollback promotes the socket to
    /// Finalized when the counter moved afterwards: fresh authenticated
    /// evidence observed AFTER the commit proves the mapping carries the
    /// peer's traffic and the socket must never be rolled back and deleted.
    evidence_at_commit: u64,
}

/// How long `finalize` waits for the watcher's explicit acknowledgement
/// before treating the handoff as durable (the watcher may be gone, in which
/// case nothing can roll the socket back anymore).
const FINALIZE_ACK_TIMEOUT: Duration = Duration::from_secs(1);

/// Read the latest commit outcome from the watcher's watch channel without
/// holding any lock: `borrow_and_update` marks the value as seen so the next
/// `changed()` parks until a NEW publish, while `borrow` re-reads the same
/// value — the watcher re-verifies plain values on every wake to stay immune
/// to lost notifications.
fn watched_commit_outcome(
    commit_rx: &mut tokio::sync::watch::Receiver<Option<CommitOutcome>>,
) -> Option<CommitOutcome> {
    (*commit_rx.borrow_and_update())
        .as_ref()
        .map(|outcome| *outcome)
}

/// Cancellation-safe ownership for a provisional fresh-mapping punch socket.
///
/// The generation's future can be dropped at any await point when the owning
/// punch session is preempted (the session `select` aborts the work future),
/// so the explicit error paths never run.  This guard watches the session's
/// cancellation and the guard's own drop from an independent task and detaches
/// the socket unless the generation committed and then finalized the durable
/// handoff.
///
/// The guard is created by `attach_dynamic_punch_socket` BEFORE the map
/// insert, so there is never an await between the insert and the guard
/// existing: every drop of the generation future is covered.
///
/// Lifecycle state machine:
///
/// - `Provisional`: the socket is owned by its in-flight generation; the
///   watcher detaches it on cancellation / dropped future.
/// - `CommittedPendingHandoff`: `commit_and_pin` re-validated ownership (peer
///   id, socket index, network generation, per-peer committed-generation
///   high-water) and the session's cancellation, flipped the phase and pinned
///   the affinity in one socket-state lock transaction.  The watcher stays
///   armed: a cancellation or dropped future rolls the peer back to the
///   predecessor pin and detaches the socket — conditionally, only while the
///   affinity still equals the pin THIS commit installed.
/// - `Finalized`: `finalize` flipped the phase under the lock, published the
///   durable handoff and WAITED for the watcher's explicit acknowledgement —
///   no racing stop signal can win after that.  Only peer-level cleanup
///   (PeerLeft, public-key change, a newer commit's predecessor detach) may
///   remove the socket.
pub(crate) struct ProvisionalSocketGuard {
    transport: UdpTransport,
    socket_index: usize,
    peer_id: String,
    cancellation: Arc<crate::PunchSessionCancellation>,
    stop_tx: tokio::sync::watch::Sender<bool>,
    commit_tx: tokio::sync::watch::Sender<Option<CommitOutcome>>,
    finalize_tx: tokio::sync::watch::Sender<bool>,
    /// The watcher's finalize acknowledgement, taken by `finalize` and awaited
    /// with a bounded timeout.
    finalize_ack: std::sync::Mutex<Option<oneshot::Receiver<()>>>,
    /// The outcome of the commit that succeeded for this guard, captured under
    /// the socket-state lock; `finalize` uses it for the predecessor detach.
    outcome: std::sync::Mutex<Option<CommitOutcome>>,
    #[allow(dead_code)]
    watcher: tokio::task::JoinHandle<()>,
}

impl ProvisionalSocketGuard {
    fn spawn(
        transport: UdpTransport,
        socket_index: usize,
        peer_id: String,
        cancellation: Arc<crate::PunchSessionCancellation>,
    ) -> Self {
        let watcher_transport = transport.clone();
        let watcher_cancellation = cancellation.clone();
        let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
        let (commit_tx, mut commit_rx) = tokio::sync::watch::channel::<Option<CommitOutcome>>(None);
        let (finalize_tx, mut finalize_rx) = tokio::sync::watch::channel(false);
        let (finalize_ack_tx, finalize_ack) = oneshot::channel();
        let watcher = tokio::spawn(async move {
            // Wake-verification loop.  watch `changed()` has subtle initial-
            // value semantics (a fresh receiver's first poll may resolve
            // immediately, and a notification can be lost between polls), so
            // every wake is re-verified against the plain values and the
            // loop re-checks everything periodically.  The watcher can never
            // miss a state change: a cancellation, a guard drop, a commit
            // publish or a finalize is observed at the latest 50 ms after it
            // happened.
            //
            // The FINALIZE check is ordered BEFORE the stop/cancellation
            // check on every wake: `finalize` flips the entry phase to
            // Finalized under the socket-state lock before publishing, so a
            // stop signal that races the durable handoff can never win.
            let mut committed: Option<CommitOutcome> = None;
            loop {
                // Re-verify the plain values first: deterministic, immune to
                // lost wake-ups.
                if let Some(outcome) = watched_commit_outcome(&mut commit_rx) {
                    if outcome.committed {
                        committed = Some(outcome);
                    }
                }
                if *finalize_rx.borrow() {
                    // Durable handoff: the peer's long-term ownership owns
                    // this socket now; the watcher's job is done.  Ack so the
                    // guard's `finalize` never times out on a healthy
                    // watcher.
                    let _ = finalize_ack_tx.send(());
                    return;
                }
                if watcher_cancellation.is_cancelled() || *stop_rx.borrow() {
                    break;
                }
                // Park until a wake or the re-verify deadline.
                tokio::select! {
                    _ = watcher_cancellation.cancelled() => {}
                    _ = stop_rx.changed() => {}
                    _ = commit_rx.changed() => {}
                    _ = finalize_rx.changed() => {}
                    _ = sleep(Duration::from_millis(50)) => {}
                }
            }
            // One final re-verification after the wake: a commit or finalize
            // published while the select was parked must win over the stop
            // signal that woke us.
            if let Some(outcome) = watched_commit_outcome(&mut commit_rx) {
                if outcome.committed {
                    committed = Some(outcome);
                }
            }
            if *finalize_rx.borrow() {
                let _ = finalize_ack_tx.send(());
                return;
            }
            // The rollback decision runs under ONE socket-state lock
            // acquisition: `rollback_committed_entry` never re-acquires the
            // lock, so the watcher can never self-deadlock.
            let detached: Option<DynamicPunchSocket> = {
                let mut state = watcher_transport.socket_state.lock().await;
                // The durable handoff may have flipped the phase while the
                // watcher waited for the lock: a Finalized entry is never
                // rolled back.
                let Some(entry) = state.dynamic.get(&socket_index) else {
                    // Never attached (pre-insert drop) or already detached by
                    // an explicit path; the reader exits via the shutdown
                    // channel closure.  Ack if the finalize raced us anyway.
                    if *finalize_rx.borrow() {
                        drop(state);
                        let _ = finalize_ack_tx.send(());
                    }
                    return;
                };
                if *finalize_rx.borrow() || entry.phase == DynamicSocketPhase::Finalized {
                    drop(state);
                    let _ = finalize_ack_tx.send(());
                    return;
                }
                match committed {
                    None => {
                        if entry.phase == DynamicSocketPhase::Provisional {
                            // Pre-commit abandonment: detach the provisional
                            // socket.
                            let entry = state
                                .dynamic
                                .remove(&socket_index)
                                .expect("provisional socket verified above");
                            if state
                                .affinity
                                .get(&entry.peer_id)
                                .is_some_and(|pin| pin.socket_index == socket_index)
                            {
                                state.affinity.remove(&entry.peer_id);
                            }
                            Some(entry)
                        } else {
                            // A commit slipped in before this wake-up won the
                            // lock.  The outcome is published under the same
                            // lock before the phase flip, so it is visible
                            // now; without it the commit is still in flight
                            // and the generation owns the socket.
                            match watched_commit_outcome(&mut commit_rx) {
                                Some(outcome) if outcome.committed => watcher_transport
                                    .rollback_committed_entry(&mut state, &socket_index, &outcome),
                                _ => None,
                            }
                        }
                    }
                    Some(outcome) => watcher_transport.rollback_committed_entry(
                        &mut state,
                        &socket_index,
                        &outcome,
                    ),
                }
            };
            if let Some(entry) = detached {
                watcher_transport
                    .detach_dynamic_entry(entry, "generation_cancelled")
                    .await;
            }
        });
        Self {
            transport,
            socket_index,
            peer_id,
            cancellation,
            stop_tx,
            commit_tx,
            finalize_tx,
            finalize_ack: std::sync::Mutex::new(Some(finalize_ack)),
            outcome: std::sync::Mutex::new(None),
            watcher,
        }
    }

    /// Atomically transition the provisional socket to
    /// `CommittedPendingHandoff` and pin it as the peer's traffic socket,
    /// after re-validating ownership in the same lock transaction.
    ///
    /// The commit re-checks, under the socket-state lock:
    /// - the entry still exists, still belongs to `peer_id` and is still
    ///   `Provisional` at `socket_index`;
    /// - the entry's network generation still equals the current network
    ///   generation (read from the lock-free mirror inside the lock, so a
    ///   generation advance can never slip between the read and the check);
    /// - the session is not cancelled;
    /// - no NEWER generation already committed for this peer (the per-peer
    ///   committed-generation high-water), so an older generation can never
    ///   pin over a newer commit no matter how the awaits interleaved.
    ///
    /// The whole transition runs under the shared network-epoch gate: a
    /// generation advance can never bump the mirror between the in-lock
    /// generation read and the phase flip + pin insert, so a stale generation
    /// can never commit once the generation has moved on.
    ///
    /// The outcome (predecessor + installed pin) is published to the watcher
    /// inside the same critical section, so the watcher's post-commit
    /// rollback always knows exactly which pin this commit installed.
    ///
    /// Returns `committed == false` when any check fails; the provisional
    /// socket is then left for the watcher (which may already be waking on
    /// the cancellation).
    async fn commit_and_pin(
        &self,
        transport: &UdpTransport,
        peer_id: &str,
        socket_index: usize,
        network_generation: u64,
        punch_generation: u64,
    ) -> CommitOutcome {
        let refused = CommitOutcome {
            committed: false,
            predecessor: None,
            installed: None,
            evidence_at_commit: 0,
            generation_fence: 0,
        };
        let _epoch_gate = transport.network_epoch_gate.lock().await;
        let mut state = transport.socket_state.lock().await;
        let Some(entry) = state.dynamic.get(&socket_index) else {
            return refused;
        };
        // The network generation is re-read UNDER the lock (lock-free mirror)
        // and must match both the entry's stamped generation and the value
        // the generation measured with: a stale generation can never commit a
        // mapping that belongs to an old network.
        let current_network_generation = transport.peers.current_network_generation_sync();
        if entry.phase != DynamicSocketPhase::Provisional
            || entry.peer_id != peer_id
            || entry.network_generation != network_generation
            || entry.network_generation != current_network_generation
            || entry.punch_generation != punch_generation
        {
            return refused;
        }
        if self.cancellation.is_cancelled() {
            // Cancelled before the commit took the lock: leave the
            // provisional socket for the watcher (already woken) and abort.
            return refused;
        }
        // A newer generation that already committed for this peer must never
        // be pinned over by this older commit.
        if state
            .committed_punch_generations
            .get(peer_id)
            .is_some_and(|committed| *committed > punch_generation)
        {
            debug!(
                "stale commit refused for socket index={socket_index} peer={peer_id}: generation {punch_generation} is older than the committed generation {}",
                state
                    .committed_punch_generations
                    .get(peer_id)
                    .copied()
                    .unwrap_or(0)
            );
            return refused;
        }
        let predecessor = state.affinity.get(peer_id).copied();
        let epoch = state.next_epoch();
        let installed = PeerSocketPin {
            socket_index,
            epoch,
        };
        state.affinity.insert(peer_id.to_string(), installed);
        state
            .committed_punch_generations
            .entry(peer_id.to_string())
            .and_modify(|committed| *committed = (*committed).max(punch_generation))
            .or_insert(punch_generation);
        // Snapshot the entry's authenticated evidence at commit time: the
        // watcher compares this against the live counter on rollback, so
        // evidence observed AFTER this commit keeps the socket.
        let evidence_at_commit = state
            .dynamic
            .get(&socket_index)
            .map(|entry| entry.authenticated_evidence)
            .unwrap_or(0);
        let outcome = CommitOutcome {
            committed: true,
            predecessor,
            installed: Some(installed),
            evidence_at_commit,
            generation_fence: punch_generation,
        };
        *self.outcome.lock().expect("guard outcome mutex") = Some(outcome);
        // Publish under the same lock the entry was flipped under: the
        // watcher can never observe a CommittedPendingHandoff entry without
        // the outcome.
        let _ = self.commit_tx.send(Some(outcome));
        // Flip the phase last, still inside the lock: a concurrent watcher
        // that wins the lock between the publish and the phase flip sees the
        // outcome and the Provisional entry, and its rollback only runs for
        // committed entries, so the ordering cannot mislead it.
        state
            .dynamic
            .get_mut(&socket_index)
            .expect("committed entry verified above")
            .phase = DynamicSocketPhase::CommittedPendingHandoff;
        outcome
    }

    /// Commit a birthday receiver without changing peer affinity.
    ///
    /// The first socket in a birthday window owns the affinity pin. Every
    /// other socket still needs the committed phase (so its reader can admit
    /// authenticated Probe v2 traffic and its watcher can survive the
    /// rendezvous), but must not overwrite that pin. `installed = None` in
    /// the outcome gives rollback/finalize the corresponding no-affinity
    /// semantics.
    async fn commit_speculative(
        &self,
        transport: &UdpTransport,
        peer_id: &str,
        socket_index: usize,
        network_generation: u64,
        punch_generation: u64,
    ) -> CommitOutcome {
        let refused = CommitOutcome {
            committed: false,
            predecessor: None,
            installed: None,
            evidence_at_commit: 0,
            generation_fence: 0,
        };
        let _epoch_gate = transport.network_epoch_gate.lock().await;
        let mut state = transport.socket_state.lock().await;
        let Some(entry) = state.dynamic.get(&socket_index) else {
            return refused;
        };
        let current_network_generation = transport.peers.current_network_generation_sync();
        if entry.phase != DynamicSocketPhase::Provisional
            || entry.peer_id != peer_id
            || entry.network_generation != network_generation
            || entry.network_generation != current_network_generation
            || entry.punch_generation != punch_generation
            || self.cancellation.is_cancelled()
        {
            return refused;
        }
        if state
            .committed_punch_generations
            .get(peer_id)
            .is_some_and(|committed| *committed > punch_generation)
        {
            return refused;
        }
        let Some(generation_fence) = state.committed_punch_generations.get(peer_id).copied() else {
            return refused;
        };
        let evidence_at_commit = state
            .dynamic
            .get(&socket_index)
            .map(|entry| entry.authenticated_evidence)
            .unwrap_or(0);
        let outcome = CommitOutcome {
            committed: true,
            predecessor: None,
            installed: None,
            evidence_at_commit,
            generation_fence,
        };
        *self.outcome.lock().expect("guard outcome mutex") = Some(outcome);
        let _ = self.commit_tx.send(Some(outcome));
        state
            .dynamic
            .get_mut(&socket_index)
            .expect("speculative entry verified above")
            .phase = DynamicSocketPhase::CommittedPendingHandoff;
        outcome
    }

    #[cfg(test)]
    pub(crate) async fn commit_and_pin_for_test(
        &self,
        transport: &UdpTransport,
        peer_id: &str,
        socket_index: usize,
        network_generation: u64,
        punch_generation: u64,
    ) -> bool {
        self.commit_and_pin(
            transport,
            peer_id,
            socket_index,
            network_generation,
            punch_generation,
        )
        .await
        .committed
    }

    /// Hand the committed socket to the peer's long-term ownership.
    ///
    /// Called only after the generation's durable handoff (the fresh mapping
    /// was recorded AND the prediction was advertised to the peer).  The
    /// entry phase is flipped to `Finalized` under the socket-state lock —
    /// from that point the watcher can never roll the socket back — then the
    /// finalize value is published and the watcher's EXPLICIT acknowledgement
    /// is awaited, so a racing stop signal can never be processed before the
    /// finalize.  Only then is the superseded predecessor detached (unless it
    /// was re-pinned by authenticated traffic).
    ///
    /// The flip re-verifies under the lock (and under the shared network-epoch
    /// gate) that the entry still belongs to this guard's peer, still matches
    /// the punch generation this guard committed, is still pinned as THIS
    /// commit installed it, still matches the current network generation, and
    /// the session was not cancelled meanwhile: a stale or superseded entry is
    /// never finalized.
    ///
    /// Returns `false` when the socket was already rolled back (entry gone)
    /// or never committed: the durable handoff did not happen and the caller
    /// must not treat the socket as the peer's long-term path.
    pub(crate) async fn finalize(&self) -> bool {
        // Phase flip under the gate and the lock: after this, the watcher can
        // never roll the socket back.
        let flipped = {
            let _epoch_gate = self.transport.network_epoch_gate.lock().await;
            let mut state = self.transport.socket_state.lock().await;
            let (phase, peer_id, punch_generation, network_generation) =
                match state.dynamic.get(&self.socket_index) {
                    Some(entry) => (
                        entry.phase,
                        entry.peer_id.clone(),
                        entry.punch_generation,
                        entry.network_generation,
                    ),
                    // Rolled back (or evicted) before the durable handoff: the
                    // watcher already restored the predecessor.
                    None => return false,
                };
            if phase == DynamicSocketPhase::Provisional {
                // Never committed; the generation's own cleanup owns it.
                return false;
            }
            if phase != DynamicSocketPhase::Finalized {
                let (committed_punch_generation, current_network_generation, outcome) = {
                    let outcome = self.outcome.lock().expect("guard outcome mutex");
                    (
                        state
                            .committed_punch_generations
                            .get(&self.peer_id)
                            .copied()
                            .unwrap_or(0),
                        self.transport.peers.current_network_generation_sync(),
                        *outcome,
                    )
                };
                let revalidated = outcome.is_some_and(|outcome| {
                    if !outcome.committed
                        || peer_id != self.peer_id
                        || network_generation != current_network_generation
                        || committed_punch_generation != outcome.generation_fence
                        || self.cancellation.is_cancelled()
                    {
                        return false;
                    }
                    match outcome.installed {
                        Some(installed) => {
                            punch_generation == committed_punch_generation
                                && state.affinity.get(&self.peer_id).copied() == Some(installed)
                        }
                        None => {
                            // Birthday speculative receivers share the first
                            // socket's generation fence but intentionally do
                            // not own the peer affinity pin.
                            punch_generation != 0
                                && state.dynamic.get(&self.socket_index).is_some_and(|entry| {
                                    entry.phase == DynamicSocketPhase::CommittedPendingHandoff
                                })
                        }
                    }
                });
                if !revalidated {
                    debug!(
                        "finalize refused for socket index={} peer={}: ownership, punch generation, network generation, affinity or cancellation changed since the commit",
                        self.socket_index,
                        self.peer_id
                    );
                    return false;
                }
                state
                    .dynamic
                    .get_mut(&self.socket_index)
                    .expect("finalize entry verified above")
                    .phase = DynamicSocketPhase::Finalized;
            }
            true
        };
        if !flipped {
            return false;
        }
        // Publish the durable handoff and WAIT for the watcher's explicit
        // acknowledgement (bounded: a dead watcher cannot roll back anyway).
        let _ = self.finalize_tx.send(true);
        let ack = self.finalize_ack.lock().expect("finalize ack mutex").take();
        if let Some(ack) = ack {
            let _ = tokio::time::timeout(FINALIZE_ACK_TIMEOUT, ack).await;
        }
        // The predecessor detach runs only now, after the durable handoff: a
        // cancellation between the commit and this point must still be able
        // to roll the peer back to the predecessor.
        let predecessor = self
            .outcome
            .lock()
            .expect("guard outcome mutex")
            .and_then(|outcome| outcome.predecessor);
        if let Some(predecessor) = predecessor.filter(|pin| {
            pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE && pin.socket_index != self.socket_index
        }) {
            self.transport
                .detach_predecessor_unless_repinned(
                    &self.peer_id,
                    predecessor,
                    self.socket_index,
                    "superseded_by_new_generation",
                )
                .await;
        }
        true
    }
}

impl UdpTransport {
    /// Post-commit rollback decision for one socket, executed under a SINGLE
    /// socket-state lock acquisition (the guard watcher holds the lock while
    /// calling this, so it must never re-acquire it).
    ///
    /// Returns the entry to detach, or `None` when nothing must be detached:
    /// - the entry is already `Finalized` or gone;
    /// - authenticated evidence was observed on the entry AFTER the commit
    ///   (matched ACK, accepted authenticated punch, or decrypted WireGuard
    ///   data received on this socket): the socket demonstrably carries the
    ///   peer's traffic, so it is promoted to `Finalized` and kept — the
    ///   evidence counter is the socket's own record and can never be faked
    ///   by a stale pin or an old network epoch;
    /// - the affinity still equals THIS commit's installed pin (and no
    ///   post-commit evidence exists) → full rollback: restore the
    ///   predecessor pin (or clear the affinity) and detach this
    ///   generation's socket;
    /// - a newer commit or evidence owns the affinity → detach this socket
    ///   WITHOUT restoring the predecessor (a restore would downgrade the
    ///   current owner — the "G2 rollback overwrites G3 commit" race).
    fn rollback_committed_entry(
        &self,
        state: &mut SocketState,
        socket_index: &usize,
        outcome: &CommitOutcome,
    ) -> Option<DynamicPunchSocket> {
        if outcome.installed.is_none() {
            let entry = state.dynamic.get(socket_index)?;
            if entry.phase == DynamicSocketPhase::Finalized {
                return None;
            }
            let has_post_commit_evidence =
                entry.authenticated_evidence > outcome.evidence_at_commit;
            if has_post_commit_evidence {
                state
                    .dynamic
                    .get_mut(socket_index)
                    .expect("speculative socket verified above")
                    .phase = DynamicSocketPhase::Finalized;
                return None;
            }
            let entry = state
                .dynamic
                .remove(socket_index)
                .expect("speculative socket verified above");
            if state
                .affinity
                .get(&entry.peer_id)
                .is_some_and(|pin| pin.socket_index == *socket_index)
            {
                state.affinity.remove(&entry.peer_id);
            }
            return Some(entry);
        }
        let installed = outcome.installed?;
        {
            let entry = state.dynamic.get(socket_index)?;
            if entry.phase == DynamicSocketPhase::Finalized {
                return None;
            }
        }
        let peer_id = state.dynamic.get(socket_index)?.peer_id.clone();
        // Post-commit authenticated evidence is the socket's OWN record:
        // whenever the counter moved past the commit snapshot the mapping
        // demonstrably carried the peer's traffic, so the socket is promoted
        // to the durable phase instead of being rolled back — even when the
        // affinity still equals the installed pin (the evidence re-verified
        // the very socket the commit pinned).
        let has_post_commit_evidence = state
            .dynamic
            .get(socket_index)
            .is_some_and(|entry| entry.authenticated_evidence > outcome.evidence_at_commit);
        if has_post_commit_evidence {
            state
                .dynamic
                .get_mut(socket_index)
                .expect("committed socket verified above")
                .phase = DynamicSocketPhase::Finalized;
            debug!(
                "rollback promoted socket index={socket_index} peer={peer_id} to Finalized: authenticated evidence arrived after the commit (counter {} -> {})",
                outcome.evidence_at_commit,
                state
                    .dynamic
                    .get(socket_index)
                    .map(|entry| entry.authenticated_evidence)
                    .unwrap_or(0)
            );
            return None;
        }
        let affinity = state.affinity.get(&peer_id).copied();
        if affinity == Some(installed) {
            // Full rollback: restore the predecessor pin and detach this
            // generation's socket.
            let entry = state
                .dynamic
                .remove(socket_index)
                .expect("committed socket verified above");
            let predecessor = outcome.predecessor;
            let valid = predecessor.is_some_and(|pin| {
                pin.socket_index < self.socket_count()
                    || (pin.socket_index >= DYNAMIC_SOCKET_INDEX_BASE
                        && state.dynamic.contains_key(&pin.socket_index))
            });
            if valid {
                let epoch = state.next_epoch();
                if let Some(predecessor) = predecessor {
                    state.affinity.insert(
                        peer_id,
                        PeerSocketPin {
                            socket_index: predecessor.socket_index,
                            epoch,
                        },
                    );
                }
            } else {
                state.affinity.remove(&peer_id);
            }
            Some(entry)
        } else if affinity.is_some_and(|pin| pin.socket_index == *socket_index) {
            // The socket was re-pinned by fresh inbound evidence since the
            // commit (its evidence counter would normally have moved too; the
            // epoch-only match is the belt-and-braces path for pool pins).
            // It demonstrably carries the peer's traffic and must not be
            // deleted.  Promote it to the durable phase; the predecessor is
            // NOT restored (this socket owns the affinity now).
            state
                .dynamic
                .get_mut(socket_index)
                .expect("committed socket verified above")
                .phase = DynamicSocketPhase::Finalized;
            debug!(
                "rollback promoted socket index={socket_index} peer={peer_id} to Finalized: the socket was re-pinned by fresh evidence and stays as the working data path"
            );
            None
        } else {
            // A newer commit or fresh evidence owns the affinity: this socket
            // is superseded.  Detach it WITHOUT restoring the predecessor.
            debug!(
                "rollback detached socket index={socket_index} peer={peer_id} without restoring the predecessor (a newer owner holds the affinity)"
            );
            let entry = state
                .dynamic
                .remove(socket_index)
                .expect("committed socket verified above");
            Some(entry)
        }
    }
}

impl Drop for ProvisionalSocketGuard {
    fn drop(&mut self) {
        self.stop_tx.send_replace(true);
    }
}

#[cfg(test)]
mod birthday_tests {
    use super::{
        hard_hard_birthday_candidates, hard_hard_birthday_capacity_plan,
        hard_hard_birthday_packets_planned, hard_hard_birthday_socket_plan,
        hard_hard_birthday_wave_assignments, hard_hard_birthday_wave_count,
        record_birthday_worker_result, BirthdaySweepFailureKind, HardHardSocketSnapshot,
        ProbeSendFailureKind, PunchSendReport,
    };
    use crate::error::DaemonError;
    use p2pnet_nat::mapping::AllocationModelKind;
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn birthday_levels_are_exact_and_never_scan_the_full_port_ring() {
        let public_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        for (level, token) in [(64, "android"), (128, "android-2"), (256, "desktop")] {
            let candidates = hard_hard_birthday_candidates(
                public_ip,
                &[40_000, 40_001, 40_002, 40_003],
                level,
                token,
            );
            assert_eq!(candidates.len(), level);
            assert!(candidates
                .iter()
                .all(|candidate| { candidate.ip() == public_ip && candidate.port() != 0 }));
            let unique = candidates
                .iter()
                .map(SocketAddr::port)
                .collect::<HashSet<_>>();
            assert_eq!(unique.len(), level);
            assert!(level < usize::from(u16::MAX));
        }
    }

    #[test]
    fn birthday_diagnostics_keep_unknown_distinct_from_high_entropy() {
        assert_eq!(AllocationModelKind::Unknown.label(), "unknown");
        assert_eq!(AllocationModelKind::HighEntropy.label(), "high_entropy");
        assert_ne!(
            AllocationModelKind::Unknown.label(),
            AllocationModelKind::HighEntropy.label()
        );
    }

    #[test]
    fn probe_failure_kinds_keep_precise_terminal_stop_reasons() {
        let cases = [
            (ProbeSendFailureKind::PhysicalSend, "send_error"),
            (
                ProbeSendFailureKind::NetworkGenerationChanged,
                "network_generation_changed",
            ),
            (
                ProbeSendFailureKind::CandidateEpochChanged,
                "candidate_epoch_changed",
            ),
            (
                ProbeSendFailureKind::LocalProfileGenerationChanged,
                "profile_generation_changed",
            ),
            (
                ProbeSendFailureKind::RemoteProfileGenerationChanged,
                "profile_generation_changed",
            ),
            (
                ProbeSendFailureKind::PeerSessionChanged,
                "peer_session_changed",
            ),
            (ProbeSendFailureKind::SessionRetired, "session_retired"),
            (ProbeSendFailureKind::SocketUnavailable, "socket_unavailable"),
            (ProbeSendFailureKind::SocketRevoked, "socket_revoked"),
            (
                ProbeSendFailureKind::ProbeRegistrationFailed,
                "probe_registration_failed",
            ),
            (
                ProbeSendFailureKind::ProbeEncodingFailed,
                "probe_encoding_failed",
            ),
        ];
        for (probe_failure, stop_reason) in cases {
            let failure = BirthdaySweepFailureKind::from_probe_failure(probe_failure);
            assert_eq!(failure.stop_reason(), stop_reason);
            assert_eq!(
                BirthdaySweepFailureKind::from_stop_reason(stop_reason),
                Some(failure)
            );
        }
    }

    #[test]
    fn birthday_two_waves_rotate_targets_without_socket_cartesian_product() {
        for (socket_count, level) in [(2, 64), (4, 128), (8, 256)] {
            let targets = (1..=level)
                .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port as u16))
                .collect::<Vec<_>>();
            assert_eq!(hard_hard_birthday_wave_count(socket_count), 2);
            let first = hard_hard_birthday_wave_assignments(socket_count, targets.clone(), 0);
            let second = hard_hard_birthday_wave_assignments(socket_count, targets.clone(), 1);
            assert_eq!(first.len(), socket_count);
            assert_eq!(second.len(), socket_count);
            for assignments in [&first, &second] {
                let flattened = assignments.iter().flatten().copied().collect::<Vec<_>>();
                assert_eq!(flattened.len(), level);
                assert_eq!(flattened.iter().collect::<HashSet<_>>().len(), level);
                assert!(flattened.iter().all(|target| targets.contains(target)));
            }
            let first_socket = first
                .iter()
                .enumerate()
                .flat_map(|(socket, assigned)| assigned.iter().map(move |target| (*target, socket)))
                .collect::<HashMap<_, _>>();
            let second_socket = second
                .iter()
                .enumerate()
                .flat_map(|(socket, assigned)| assigned.iter().map(move |target| (*target, socket)))
                .collect::<HashMap<_, _>>();
            assert!(targets
                .iter()
                .all(|target| first_socket[target] != second_socket[target]));
        }
        assert_eq!(hard_hard_birthday_wave_count(1), 1);
        assert_eq!(hard_hard_birthday_wave_count(0), 0);
        assert_eq!(hard_hard_birthday_packets_planned(2, 64), 128);
        assert_eq!(hard_hard_birthday_packets_planned(4, 96), 192);
        assert_eq!(hard_hard_birthday_packets_planned(1, 96), 96);
    }

    #[test]
    fn birthday_capacity_plan_preserves_cap_and_exposes_downgrade() {
        assert_eq!(hard_hard_birthday_capacity_plan(64, 2), Some((64, 2)));
        assert_eq!(hard_hard_birthday_capacity_plan(128, 3), Some((64, 2)));
        assert_eq!(hard_hard_birthday_capacity_plan(256, 7), Some((128, 4)));
        assert_eq!(hard_hard_birthday_capacity_plan(256, 8), Some((256, 8)));
        assert_eq!(hard_hard_birthday_capacity_plan(256, 1), None);
    }

    #[test]
    fn birthday_socket_plan_is_exact_and_fails_closed() {
        let partial = hard_hard_birthday_socket_plan(
            64,
            vec![
                HardHardSocketSnapshot {
                    socket_index: 41,
                    attached: true,
                    usable: true,
                },
                HardHardSocketSnapshot {
                    socket_index: 42,
                    attached: true,
                    usable: false,
                },
            ],
        );
        assert_eq!(partial.requested_socket_count, 2);
        assert_eq!(partial.attached_socket_count, 2);
        assert_eq!(partial.usable_socket_count, 1);
        assert_eq!(partial.unavailable_socket_count, 1);
        assert_eq!(partial.usable_socket_indices, vec![41]);
        assert_eq!(
            hard_hard_birthday_wave_count(partial.usable_socket_count),
            1
        );

        let detached = hard_hard_birthday_socket_plan(
            64,
            vec![
                HardHardSocketSnapshot {
                    socket_index: 41,
                    attached: false,
                    usable: false,
                },
                HardHardSocketSnapshot {
                    socket_index: 42,
                    attached: false,
                    usable: false,
                },
            ],
        );
        assert_eq!(detached.attached_socket_count, 0);
        assert_eq!(detached.usable_socket_count, 0);
        assert_eq!(detached.unavailable_socket_count, 2);
        assert!(detached.usable_socket_indices.is_empty());
        assert_eq!(
            hard_hard_birthday_wave_count(detached.usable_socket_count),
            0
        );

        let full = hard_hard_birthday_socket_plan(
            128,
            (0..4)
                .map(|offset| HardHardSocketSnapshot {
                    socket_index: 100 + offset,
                    attached: true,
                    usable: true,
                })
                .collect(),
        );
        assert_eq!(full.requested_socket_count, 4);
        assert_eq!(full.attached_socket_count, 4);
        assert_eq!(full.usable_socket_count, 4);
        assert_eq!(full.unavailable_socket_count, 0);
        assert_eq!(hard_hard_birthday_wave_count(full.usable_socket_count), 2);

        let capped = hard_hard_birthday_socket_plan(
            256,
            (0..4)
                .map(|offset| HardHardSocketSnapshot {
                    socket_index: 200 + offset,
                    attached: true,
                    usable: true,
                })
                .collect(),
        );
        assert_eq!(capped.requested_socket_count, 8);
        assert_eq!(capped.usable_socket_count, 4);
        assert_eq!(capped.unavailable_socket_count, 4);
        assert_eq!(capped.usable_socket_indices, vec![200, 201, 202, 203]);
    }

    #[tokio::test]
    async fn birthday_worker_collection_preserves_partial_stats_and_join_errors() {
        let mut wave_report = PunchSendReport::default();
        let mut wave_fully_completed = true;
        let mut failure_kind = None;
        record_birthday_worker_result(
            &mut wave_report,
            &mut wave_fully_completed,
            &mut failure_kind,
            Ok((
                2,
                Ok(PunchSendReport {
                    packets_sent: 1,
                    per_socket_sent: vec![(41, 2)],
                    targets_assigned: 2,
                    targets_attempted: 2,
                    target_processing_completed: true,
                    ..PunchSendReport::default()
                }),
            )),
        );
        assert_eq!(wave_report.packets_sent, 1);
        assert_eq!(wave_report.per_socket_sent, vec![(41, 2)]);
        assert!(wave_fully_completed);
        assert_eq!(failure_kind, None);

        record_birthday_worker_result(
            &mut wave_report,
            &mut wave_fully_completed,
            &mut failure_kind,
            Ok((
                3,
                Err(DaemonError::Network("injected worker error".to_string())),
            )),
        );
        assert_eq!(wave_report.packets_sent, 1);
        assert_eq!(wave_report.per_socket_sent, vec![(41, 2)]);
        assert_eq!(wave_report.targets_cancelled, 3);
        assert_eq!(wave_report.probe_path_errors, 1);
        assert!(!wave_fully_completed);
        assert_eq!(
            failure_kind,
            Some(BirthdaySweepFailureKind::ProbeRegistrationFailed)
        );

        let handle = tokio::spawn(async { std::future::pending::<()>().await });
        handle.abort();
        let join_error = handle
            .await
            .expect_err("aborted worker must yield JoinError");
        record_birthday_worker_result(
            &mut wave_report,
            &mut wave_fully_completed,
            &mut failure_kind,
            Err(join_error),
        );
        assert!(!wave_fully_completed);
        assert_eq!(failure_kind, Some(BirthdaySweepFailureKind::WorkerJoin));
        assert_eq!(wave_report.packets_sent, 1);
        assert_eq!(wave_report.per_socket_sent, vec![(41, 2)]);
    }
}
