use super::*;
use crate::dataplane::{NetworkOutboundResourceSnapshot, PendingQueueResidence};
use crate::dataplane_resources::{QueueAggregateLease, QueueStage, QueueTotals, ResourceCapture};

mod actor;
use actor::*;

/// Loss metadata travels with the existing FIFO owner, never with retained
/// ciphertext or a second report task. At saturation, reason totals remain
/// exact while generation detail is explicitly omitted.
const MAX_DEFERRED_LOSS_RECORDS: usize = 16;

struct DeferredLoss {
    generation: Option<u64>,
    reason: QueueLossReason,
    packets: usize,
    bytes: usize,
    counter_complete: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueLossReason {
    QueueFull,
    GenerationChanged,
    WorkerStopped,
    DirectOnly,
    StartupExpired,
    Offline,
    DeliveryExpired,
    BackpressureExpired,
}

impl QueueLossReason {
    fn code(self) -> &'static str {
        match self {
            Self::QueueFull => REASON_OUTBOUND_QUEUE_FULL,
            Self::GenerationChanged => REASON_OUTBOUND_GENERATION_CHANGED,
            Self::WorkerStopped => REASON_OUTBOUND_WORKER_STOPPED,
            Self::DirectOnly => REASON_DIRECT_ONLY_NO_RELAY,
            Self::StartupExpired => REASON_RELAY_STARTUP_WAIT_EXPIRED,
            Self::Offline => REASON_OUTBOUND_PEER_OFFLINE,
            Self::DeliveryExpired => REASON_OUTBOUND_DELIVERY_DEADLINE,
            Self::BackpressureExpired => REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE,
        }
    }
}

/// One queued per-peer packet. The queue intentionally contains plaintext
/// only. An encrypted packet and its emit guard exist only in one lexical send
/// operation; a retry releases the guard and allocates a fresh counter.
pub(super) enum PendingPacket {
    Plain {
        packet: OutboundPacket,
        direct_budget_reroutes: u8,
        local_backpressure_retries: u32,
        pending_residence: Option<PendingQueueResidence>,
    },
}

impl PendingPacket {
    fn plain(packet: OutboundPacket) -> Self {
        let pending_residence =
            PendingQueueResidence::start(packet.trace.as_ref().is_some_and(|trace| trace.sampled));
        Self::Plain {
            packet,
            direct_budget_reroutes: 0,
            local_backpressure_retries: 0,
            pending_residence,
        }
    }

    fn stored_bytes(&self) -> usize {
        match self {
            Self::Plain { packet, .. } => packet.packet.len(),
        }
    }

    fn stored_capacity(&self) -> usize {
        match self {
            Self::Plain { packet, .. } => packet.packet.capacity(),
        }
    }

    fn raw_packet(&self) -> &[u8] {
        match self {
            Self::Plain { packet, .. } => &packet.packet,
        }
    }

    fn experienced_local_backpressure(&self) -> bool {
        match self {
            Self::Plain {
                local_backpressure_retries,
                ..
            } => *local_backpressure_retries > 0,
        }
    }

    fn take_pending_residence(&mut self) -> Option<PendingQueueResidence> {
        match self {
            Self::Plain {
                pending_residence, ..
            } => pending_residence.take(),
        }
    }
}

fn record_pending_residence(residence: Option<PendingQueueResidence>, stage: &'static str) {
    if let Some(residence) = residence {
        global_dataplane_profiler().record(true, stage, residence.finish());
    }
}

fn resource_snapshot(
    channel_packets: usize,
    pending: &HashMap<String, PeerPendingQueue>,
    active_flush_tasks: usize,
) -> NetworkOutboundResourceSnapshot {
    // This actor cannot inspect task-owned queues or an mpsc channel's byte
    // contents. Do not reinterpret a peer/task count as packets or fabricate
    // a whole-pipeline byte total from this partial ownership boundary.
    let (actor_pending_packets, actor_pending_bytes) =
        pending
            .values()
            .fold((0usize, 0usize), |(packets, bytes), queue| {
                (
                    packets.saturating_add(queue.queue.len()),
                    bytes.saturating_add(queue.bytes),
                )
            });
    NetworkOutboundResourceSnapshot {
        channel_packets,
        actor_pending_packets,
        actor_pending_bytes,
        active_flush_tasks,
    }
}

/// Bounded, event-driven first-packet wait policy.
///
/// `Some(timeout)` means a relay transport may still become available (relay
/// candidates are configured) and the first packet of a peer waits up to
/// `timeout` — SHARED across every queued packet of the same peer + generation
/// — for RelayPeerConfirmed or DirectConfirmed before being dropped with a
/// stable reason. Transport expectation is a separate fact: Direct-first can
/// wait for a Direct-only topology without inventing a configured Relay.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RelayStartupWait {
    pub(crate) relay_expected: bool,
    pub(crate) timeout: Option<Duration>,
}

/// One per-peer pending queue.  Packets are sent strictly in arrival order
/// (FIFO), so a drop or retry never reorders a peer's stream.
pub(super) struct PeerPendingQueue {
    queue: VecDeque<PendingPacket>,
    bytes: usize,
    resource_capture: Option<PendingQueueCapture>,
    /// When the peer's FIRST packet started waiting (None = not waiting).
    wait_started: Option<Instant>,
    /// Shared startup deadline for this peer + generation.
    wait_deadline: Option<Instant>,
    /// Network generation the current wait belongs to.
    wait_generation: Option<u64>,
    /// Next time a paced retry of this peer is allowed (after a transient
    /// send failure), so the maintenance ticker does not hot-loop a failed
    /// relay.
    retry_after: Option<Instant>,
    /// Terminal deadline after a path became usable or a send retry began.
    delivery_deadline: Option<Instant>,
    /// Prevent the maintenance tick from flooding diagnostics while the same
    /// queue remains behind one missing Direct business budget.
    budget_pending_reported: bool,
    deferred_losses: VecDeque<DeferredLoss>,
    loss_report_deadline: Option<tokio::time::Instant>,
}

/// Diagnostics move with the actual FIFO owner. A failed local capacity sum
/// stays unknown; it never changes enqueue, retry, overflow or drop decisions.
struct PendingQueueCapture {
    lease: QueueAggregateLease,
    vec_capacity: Option<usize>,
}

impl PeerPendingQueue {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            bytes: 0,
            resource_capture: None,
            wait_started: None,
            wait_deadline: None,
            wait_generation: None,
            retry_after: None,
            delivery_deadline: None,
            budget_pending_reported: false,
            deferred_losses: VecDeque::new(),
            loss_report_deadline: None,
        }
    }

    fn attach_resource_capture(&mut self, capture: Option<&Arc<ResourceCapture>>) {
        if self.resource_capture.is_some() {
            return;
        }
        let Some(lease) = capture
            .and_then(|capture| QueueAggregateLease::new(capture.clone(), QueueStage::ActorFifo))
        else {
            return;
        };
        // Usually the first ingress attaches to an empty new FIFO or timing
        // shell. An existing bounded FIFO is adopted once, never scanned on
        // each packet; every later mutation adjusts capacity in constant work.
        let vec_capacity = self.queue.iter().try_fold(0usize, |capacity, packet| {
            capacity.checked_add(packet.stored_capacity())
        });
        self.resource_capture = Some(PendingQueueCapture {
            lease,
            vec_capacity,
        });
        self.observe_resource_totals();
    }

    fn relocate_resources(&mut self, stage: QueueStage) {
        if let Some(capture) = self.resource_capture.as_mut() {
            let _ = capture.lease.relocate(stage);
        }
    }

    fn change_resource_capacity(&mut self, capacity: usize, increase: bool) {
        let Some(capture) = self.resource_capture.as_mut() else {
            return;
        };
        capture.vec_capacity = capture.vec_capacity.and_then(|previous| {
            if increase {
                previous.checked_add(capacity)
            } else {
                previous.checked_sub(capacity)
            }
        });
        self.observe_resource_totals();
    }

    fn observe_resource_totals(&mut self) {
        let Some(capture) = self.resource_capture.as_mut() else {
            return;
        };
        let totals = if let Some(vec_capacity) = capture.vec_capacity {
            QueueTotals {
                packets: self.queue.len(),
                plaintext_len: self.bytes,
                vec_capacity,
            }
        } else {
            // Typed invalid observation, without inventing a saturated sum.
            QueueTotals {
                packets: 0,
                plaintext_len: 1,
                vec_capacity: 0,
            }
        };
        let _ = capture.lease.set_totals(totals);
    }

    /// Park a packet in the bounded queue, dropping the OLDEST entries first
    /// when the packet/byte bound is exceeded.  Returns (dropped packets,
    /// dropped bytes) for the overflow so the caller can count them into
    /// `/status.stats.outbound_drops` — the loss is never silently ignored.
    fn enqueue(&mut self, packet: PendingPacket) -> (Vec<PendingPacket>, usize) {
        let packet_len = packet.stored_bytes();
        if packet_len > MAX_PENDING_BYTES_PER_PEER {
            return (vec![packet], packet_len);
        }
        let mut dropped_packets = Vec::new();
        let mut dropped_bytes = 0usize;
        while !self.queue.is_empty()
            && (self.queue.len() >= MAX_PENDING_PACKETS_PER_PEER
                || self.bytes.saturating_add(packet_len) > MAX_PENDING_BYTES_PER_PEER)
        {
            if let Some(old) = self.pop_front() {
                let old_len = old.stored_bytes();
                dropped_bytes = dropped_bytes.saturating_add(old_len);
                dropped_packets.push(old);
            }
        }
        let packet_capacity = packet.stored_capacity();
        self.bytes = self.bytes.saturating_add(packet_len);
        self.queue.push_back(packet);
        self.change_resource_capacity(packet_capacity, true);
        (dropped_packets, dropped_bytes)
    }

    fn pop_front(&mut self) -> Option<PendingPacket> {
        let packet = self.queue.pop_front()?;
        self.bytes = self.bytes.saturating_sub(packet.stored_bytes());
        self.change_resource_capacity(packet.stored_capacity(), false);
        Some(packet)
    }

    fn push_front(&mut self, packet: PendingPacket) {
        let packet_capacity = packet.stored_capacity();
        self.bytes = self.bytes.saturating_add(packet.stored_bytes());
        self.queue.push_front(packet);
        self.change_resource_capacity(packet_capacity, true);
    }

    fn delivery_deadline_reason(&self) -> &'static str {
        if self
            .queue
            .front()
            .is_some_and(PendingPacket::experienced_local_backpressure)
        {
            REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE
        } else {
            REASON_OUTBOUND_DELIVERY_DEADLINE
        }
    }

    fn has_work(&self) -> bool {
        !self.queue.is_empty() || !self.deferred_losses.is_empty()
    }

    /// The actor keeps only this workflow timing shell while the old packet
    /// batch is task-owned. New arrivals share its original deadlines.
    fn timing_shell(&self) -> Self {
        let mut shell = Self::new();
        shell.wait_started = self.wait_started;
        shell.wait_deadline = self.wait_deadline;
        shell.wait_generation = self.wait_generation;
        shell.delivery_deadline = self.delivery_deadline;
        shell.budget_pending_reported = self.budget_pending_reported;
        shell.loss_report_deadline = self.loss_report_deadline;
        shell
    }
}

/// Bump the relay probe kick so the forced-relay probe loop fires immediately
/// for any peer whose first business packet is now waiting.
pub(super) fn bump_probe_kick(kick: &mut u64, relay_probe_kick_tx: &watch::Sender<u64>) {
    *kick = kick.wrapping_add(1);
    let _ = relay_probe_kick_tx.send(*kick);
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_network_outbound(
    mut outbound_rx: mpsc::Receiver<OutboundPacket>,
    transport: WireGuardTransport,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_available_rx: watch::Receiver<bool>,
    relay_startup_wait: RelayStartupWait,
    relay_probe_kick_tx: watch::Sender<u64>,
    timeline: Arc<ConnectionTimeline>,
) {
    let mut pending: HashMap<String, PeerPendingQueue> = HashMap::new();
    let direct_notify = peers.direct_commit_notify();
    let relay_notify = peers.relay_confirm_notify();
    let mut path_changes = peers.subscribe_committed_business_path_changes();
    let mut budget_changes = peers.subscribe_direct_business_budget_changes();
    let mut relay_available_rx = relay_available_rx;
    let mut ticker = interval(OUTBOUND_MAINTENANCE_INTERVAL);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    #[cfg(test)]
    if let Some(initial_pending) = admission_test_hooks::take_initial_pending() {
        ticker.tick().await;
        pending = initial_pending;
        admission_test_hooks::worker_ready();
    }
    let ctx = PeerWorkContext {
        transport,
        peers,
        prefer_direct,
        udp_transport,
        relay_transport,
        startup_wait: relay_startup_wait,
        timeline,
        stopping: Arc::new(AtomicBool::new(false)),
    };
    let mut probe_kick = 0u64;
    let _ = relay_probe_kick_tx.send(probe_kick);
    let mut flush_tasks = JoinSet::new();
    let mut flushing_peers = HashMap::new();
    let mut fast_paths = HashMap::new();
    let mut fast_path_ineligible = HashMap::new();
    loop {
        tokio::select! {
            packet = outbound_rx.recv() => {
                let Some(mut packet) = packet else { break; };
                let now = Instant::now();
                if let Some(trace) = packet.trace.as_mut() {
                    trace.network_queue_dequeued = Some(now);
                    if trace.sampled {
                        global_dataplane_profiler().record_network_outbound_resources(true,
                            resource_snapshot(outbound_rx.len(), &pending, flush_tasks.len()));
                    }
                    if let Some(enqueued) = trace.transport_queue_send_started {
                        global_dataplane_profiler().record(trace.sampled,
                            "tx_network_outbound_queue_wait_us", now.duration_since(enqueued));
                    }
                }
                let peer_id = packet.peer_id.clone();
                let can_try_fast = ctx.prefer_direct && ctx.peers.is_direct_sync(&peer_id)
                    && !pending.contains_key(&peer_id) && !flushing_peers.contains_key(&peer_id);
                let packet = if can_try_fast {
                    match try_lan_direct_fast_path(packet, &ctx.transport, &ctx.peers,
                        ctx.prefer_direct, &ctx.udp_transport, &mut fast_paths, &mut fast_path_ineligible) {
                        FastPathAttempt::Sent => continue,
                        FastPathAttempt::Fallback(packet) => packet,
                        FastPathAttempt::Terminal { packet, generation, reason_code, reason } => {
                            let active_peer = peer_id.clone();
                            let ctx = ctx.clone();
                            let task = flush_tasks.spawn(async move {
                                report_fast_path_terminal(&ctx.transport, &ctx.peers, &peer_id,
                                    generation, packet.packet.len(), reason_code, reason, &ctx.timeline, None).await;
                                (peer_id, PeerPendingQueue::new())
                            });
                            flushing_peers.insert(active_peer, task.id());
                            continue;
                        }
                        FastPathAttempt::TerminalBytes { peer_id, path, local_endpoint, bytes, reason_code, reason } => {
                            let active_peer = peer_id.clone();
                            let ctx = ctx.clone();
                            let task = flush_tasks.spawn(async move {
                                report_fast_path_terminal(&ctx.transport, &ctx.peers, &peer_id,
                                    path.generation, bytes, reason_code, reason, &ctx.timeline,
                                    Some((path, local_endpoint))).await;
                                (peer_id, PeerPendingQueue::new())
                            });
                            flushing_peers.insert(active_peer, task.id());
                            continue;
                        }
                    }
                } else { packet };
                append_ingress(packet, &mut pending, &ctx, &mut probe_kick, &relay_probe_kick_tx);
                schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
            }
            _ = direct_notify.notified() => {
                #[cfg(test)]
                admission_test_hooks::before_scan(admission_test_hooks::Scan::DirectNotify).await;
                schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
            }
            _ = relay_notify.notified() => {
                schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
            }
            changed = path_changes.changed() => {
                if changed.is_err() { break; }
                schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
            }
            changed = budget_changes.changed() => {
                if changed.is_err() { break; }
                schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
            }
            changed = relay_available_rx.changed() => {
                if changed.is_err() { break; }
                bump_probe_kick(&mut probe_kick, &relay_probe_kick_tx);
                schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
            }
            _ = ticker.tick() => {
                #[cfg(test)]
                admission_test_hooks::before_scan(admission_test_hooks::Scan::Ticker).await;
                schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
            }
            result = flush_tasks.join_next(), if !flush_tasks.is_empty() => {
                match result {
                    Some(Ok((peer_id, queue))) => {
                        flushing_peers.remove(&peer_id);
                        merge_peer_work(&mut pending, peer_id, queue, &ctx);
                        #[cfg(test)]
                        admission_test_hooks::peer_completed(&pending, flushing_peers.len());
                        schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
                    }
                    Some(Err(err)) => {
                        let failed_peer = flushing_peers.iter()
                            .find(|(_, task)| **task == err.id()).map(|(peer, _)| peer.clone());
                        if let Some(peer) = failed_peer.as_ref() { flushing_peers.remove(peer); }
                        ctx.timeline.emit("outbound_peer_task_failed", None, None,
                            Some(format!("peer={failed_peer:?} accounting_complete=false old_task_fifo_unknown=true owner_released=true")));
                        warn!(event="outbound_peer_task_failed", peer_id=?failed_peer, error=%err,
                            "failed owner released; old task FIFO accounting remains unconfirmed");
                        schedule_peer_work(&mut pending, &mut flush_tasks, &mut flushing_peers, &ctx);
                    }
                    None => {}
                }
            }
        }
    }
    // Closing first also bounds the final channel drain under live producers.
    // Do not cancel already-started physical work with a replayable timeout.
    outbound_rx.close();
    ctx.stopping.store(true, Ordering::Release);
    while let Ok(packet) = outbound_rx.try_recv() {
        append_ingress(
            packet,
            &mut pending,
            &ctx,
            &mut probe_kick,
            &relay_probe_kick_tx,
        );
    }
    while let Some(result) = flush_tasks.join_next().await {
        match result {
            Ok((peer_id, queue)) => merge_peer_work(&mut pending, peer_id, queue, &ctx),
            Err(err) => warn!(event="outbound_peer_task_failed", error=%err,
                "task failed during shutdown; accounting remains unconfirmed"),
        }
    }
    // Reuse the same task owner for final discard/reporting. Every report has
    // an overall two-second deadline; incomplete phases stay explicit.
    for (peer_id, mut queue) in pending.drain() {
        queue.attach_resource_capture(ctx.transport.resource_capture());
        queue.relocate_resources(QueueStage::TaskOrUnjoinedFifo);
        flush_tasks.spawn(process_peer_queue(peer_id, queue, ctx.clone()));
    }
    while let Some(result) = flush_tasks.join_next().await {
        if let Ok((peer_id, queue)) = result {
            report_shutdown_unknown(&queue, &peer_id, &ctx);
        }
    }
    ctx.timeline.emit(
        "outbound_worker_stopped",
        None,
        Some(REASON_OUTBOUND_WORKER_STOPPED),
        Some("all packet owners stopped; incomplete accounting is reported explicitly".to_string()),
    );
}

/// Deterministic actor scheduling only for the admission contention tests.
/// The seed is transferred once into the existing actor-owned FIFO; it is
/// never a second live queue and is absent from production builds.
#[cfg(test)]
pub(super) mod admission_test_hooks {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;
    use tokio::sync::Semaphore;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(in crate::network_outbound) enum Scan {
        Ticker,
        DirectNotify,
    }

    pub(in crate::network_outbound) struct WorkerHook {
        initial_pending: Mutex<Option<HashMap<String, PeerPendingQueue>>>,
        events: mpsc::UnboundedSender<Option<Scan>>,
        pause_scan: Option<Scan>,
        armed: AtomicBool,
        release: Semaphore,
        completions: mpsc::UnboundedSender<Completion>,
        completion_receiver: Mutex<Option<mpsc::UnboundedReceiver<Completion>>>,
    }

    #[derive(Debug)]
    pub(in crate::network_outbound) struct Completion {
        pub(in crate::network_outbound) actor_packets: usize,
        pub(in crate::network_outbound) loss_records: usize,
        pub(in crate::network_outbound) active_tasks: usize,
    }

    tokio::task_local! {
        pub(in crate::network_outbound) static WORKER: Arc<WorkerHook>;
    }

    impl WorkerHook {
        pub(in crate::network_outbound) fn new(
            initial_pending: HashMap<String, PeerPendingQueue>,
            pause_scan: Option<Scan>,
        ) -> (Arc<Self>, mpsc::UnboundedReceiver<Option<Scan>>) {
            let (events, receiver) = mpsc::unbounded_channel();
            let (completions, completion_receiver) = mpsc::unbounded_channel();
            (
                Arc::new(Self {
                    initial_pending: Mutex::new(Some(initial_pending)),
                    events,
                    pause_scan,
                    armed: AtomicBool::new(true),
                    release: Semaphore::new(0),
                    completions,
                    completion_receiver: Mutex::new(Some(completion_receiver)),
                }),
                receiver,
            )
        }

        pub(in crate::network_outbound) fn release_scan(&self) {
            self.release.add_permits(1);
        }

        pub(in crate::network_outbound) fn completion_receiver(
            &self,
        ) -> mpsc::UnboundedReceiver<Completion> {
            self.completion_receiver.lock().unwrap().take().unwrap()
        }
    }

    pub(in crate::network_outbound) fn confirmed_direct_queue(
        generation: u64,
        packet: OutboundPacket,
    ) -> HashMap<String, PeerPendingQueue> {
        let peer_id = packet.peer_id.clone();
        let mut queue = PeerPendingQueue::new();
        queue.wait_generation = Some(generation);
        queue.delivery_deadline = Some(Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
        assert!(queue.enqueue(PendingPacket::plain(packet)).0.is_empty());
        HashMap::from([(peer_id, queue)])
    }

    pub(in crate::network_outbound) fn set_delivery_deadline(
        queue: &mut PeerPendingQueue,
        deadline: Instant,
    ) {
        queue.delivery_deadline = Some(deadline);
    }

    pub(in crate::network_outbound) fn queue_view(
        queue: &PeerPendingQueue,
    ) -> (Option<Instant>, Vec<Vec<u8>>) {
        (
            queue.delivery_deadline,
            queue
                .queue
                .iter()
                .map(|packet| packet.raw_packet().to_vec())
                .collect(),
        )
    }

    pub(super) fn take_initial_pending() -> Option<HashMap<String, PeerPendingQueue>> {
        WORKER
            .try_with(|hook| hook.initial_pending.lock().unwrap().take())
            .ok()
            .flatten()
    }

    pub(super) fn worker_ready() {
        let _ = WORKER.try_with(|hook| {
            let _ = hook.events.send(None);
        });
    }

    pub(super) fn peer_completed(pending: &HashMap<String, PeerPendingQueue>, active_tasks: usize) {
        let _ = WORKER.try_with(|hook| {
            let _ = hook.completions.send(Completion {
                actor_packets: pending.values().map(|queue| queue.queue.len()).sum(),
                loss_records: pending
                    .values()
                    .map(|queue| queue.deferred_losses.len())
                    .sum(),
                active_tasks,
            });
        });
    }

    pub(super) async fn before_scan(scan: Scan) {
        let hook = WORKER
            .try_with(|hook| {
                (hook.pause_scan == Some(scan) && hook.armed.swap(false, Ordering::SeqCst))
                    .then(|| hook.clone())
            })
            .ok()
            .flatten();
        if let Some(hook) = hook {
            let _ = hook.events.send(Some(scan));
            hook.release.acquire().await.unwrap().forget();
        }
    }
}

fn record_outbound_flush_batch(
    timeline: &ConnectionTimeline,
    peers: &PeerManager,
    peer_id: &str,
    flushed: usize,
    remaining: usize,
) {
    timeline.record_outbound_flush_batch();
    let relay_confirm_seq = peers.relay_confirm_seq_sync(peer_id);
    let direct_commit_seq = peers.direct_commit_seq_sync(peer_id);
    timeline.emit_first_scoped(
        &format!("peer:{peer_id}"),
        "outbound_first_packet_flushed",
        None,
        None,
        Some(format!(
            "peer={peer_id} flushed={flushed} remaining={remaining} relay_confirm_seq={relay_confirm_seq:?} direct_commit_seq={direct_commit_seq:?}"
        )),
    );
    debug!(peer_id, flushed, remaining, "Flushed a queued packet batch");
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn flush_one_peer(
    peer_id: String,
    queue: PeerPendingQueue,
    transport: WireGuardTransport,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: Arc<ConnectionTimeline>,
) -> (String, PeerPendingQueue) {
    let ctx = PeerWorkContext {
        transport: transport.clone(),
        peers: peers.clone(),
        prefer_direct,
        udp_transport: udp_transport.clone(),
        relay_transport: relay_transport.clone(),
        startup_wait: RelayStartupWait {
            relay_expected,
            timeout: None,
        },
        timeline: timeline.clone(),
        stopping: Arc::new(AtomicBool::new(false)),
    };
    let (peer_id, mut remaining) = flush_one_peer_until_stopped(
        peer_id,
        queue,
        transport,
        peers,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
        timeline,
        ctx.stopping.clone(),
    )
    .await;
    report_deferred_losses(&mut remaining, &peer_id, &ctx).await;
    (peer_id, remaining)
}

/// Flush one peer's queue. This is the sole owner of that peer's queue while
/// it is in flight. A terminal/uncertain handoff stops the batch immediately:
/// that counter is consumed, while later plaintext packets remain available
/// for a replacement path and receive fresh counters.
#[allow(clippy::too_many_arguments)]
pub(super) async fn flush_one_peer_until_stopped(
    peer_id: String,
    mut queue: PeerPendingQueue,
    transport: WireGuardTransport,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: Arc<ConnectionTimeline>,
    stopping: Arc<AtomicBool>,
) -> (String, PeerPendingQueue) {
    let ctx = PeerWorkContext {
        transport: transport.clone(),
        peers: peers.clone(),
        prefer_direct,
        udp_transport: udp_transport.clone(),
        relay_transport: relay_transport.clone(),
        startup_wait: RelayStartupWait {
            relay_expected,
            timeout: None,
        },
        timeline: timeline.clone(),
        stopping,
    };
    let mut flushed = 0usize;
    while flushed < MAX_FLUSH_PER_PEER_PER_TICK && !queue.queue.is_empty() {
        let generation = peers.current_network_generation_sync();
        let expired = queue
            .delivery_deadline
            .is_some_and(|deadline| Instant::now() >= deadline);
        let reason = if ctx.stopping.load(Ordering::Acquire) {
            Some(QueueLossReason::WorkerStopped)
        } else if queue.wait_generation.is_some_and(|old| old != generation) {
            Some(QueueLossReason::GenerationChanged)
        } else if expired {
            Some(
                if queue.delivery_deadline_reason() == REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE {
                    QueueLossReason::BackpressureExpired
                } else {
                    QueueLossReason::DeliveryExpired
                },
            )
        } else {
            None
        };
        if let Some(reason) = reason {
            discard_packets(&mut queue, &peer_id, reason, &ctx);
            break;
        }
        // Only untouched plaintext remains in the FIFO during this bounded
        // authority wait. No ciphertext or send future is cancelled here.
        let admitted = timeout(admission_bound(&queue), async {
            let relay_available = relay_transport.read().await.is_some();
            peers
                .is_data_path_admitted_for_generation(
                    &peer_id,
                    generation,
                    relay_available || relay_expected,
                )
                .await
        })
        .await;
        if !matches!(admitted, Ok(true)) {
            queue.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
            break;
        }
        if ctx.stopping.load(Ordering::Acquire) {
            discard_packets(&mut queue, &peer_id, QueueLossReason::WorkerStopped, &ctx);
            break;
        }
        let Some(front) = queue.pop_front() else {
            break;
        };

        let PendingPacket::Plain {
            packet,
            direct_budget_reroutes,
            local_backpressure_retries,
            mut pending_residence,
        } = front;
        // Removing a queue from the actor, merging queues, or checking a
        // temporarily unusable path is still pending residence. Pause only
        // immediately before an actual encryption/send attempt.
        if let Some(residence) = pending_residence.as_mut() {
            residence.pause();
        }
        match encrypt_then_send_with_deadline(
            packet,
            &transport,
            &peers,
            generation,
            prefer_direct,
            &udp_transport,
            &relay_transport,
            relay_expected,
            queue.delivery_deadline,
            Some(&ctx.stopping),
        )
        .await
        {
            EncryptSendOutcome::Sent => {
                record_pending_residence(pending_residence, "tx_pending_residence_sent_us");
                flushed = flushed.saturating_add(1);
            }
            EncryptSendOutcome::BudgetPending { packet, reason } => {
                if let Some(residence) = pending_residence.as_mut() {
                    residence.resume();
                }
                queue.push_front(PendingPacket::Plain {
                    packet,
                    direct_budget_reroutes,
                    local_backpressure_retries,
                    pending_residence,
                });
                queue
                    .delivery_deadline
                    .get_or_insert_with(|| Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
                timeline.emit(
                    "direct_business_budget_pending",
                    Some("direct"),
                    Some(REASON_DIRECT_BUDGET_PENDING),
                    Some(format!(
                        "peer={peer_id} queued={} queued_bytes={} detail={reason}",
                        queue.queue.len(),
                        queue.bytes
                    )),
                );
                break;
            }
            EncryptSendOutcome::Retryable {
                packet,
                reason_code,
                reason,
            } => {
                if reason_code == REASON_DIRECT_BUDGET_STALE && direct_budget_reroutes >= 1 {
                    record_pending_residence(pending_residence, "tx_pending_residence_dropped_us");
                    record_terminal_drop(
                        &transport,
                        &peers,
                        &peer_id,
                        generation,
                        packet,
                        REASON_DIRECT_BUDGET_REROUTE_EXHAUSTED,
                        format!(
                            "Direct token became stale again after one plaintext reroute: {reason}"
                        ),
                        &timeline,
                    )
                    .await;
                    if !queue.queue.is_empty() {
                        queue.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
                    }
                    break;
                }
                record_retry_and_repark(
                    &transport,
                    &peers,
                    &peer_id,
                    &mut queue,
                    packet,
                    if reason_code == REASON_DIRECT_BUDGET_STALE {
                        direct_budget_reroutes.saturating_add(1)
                    } else {
                        direct_budget_reroutes
                    },
                    local_backpressure_retries,
                    pending_residence,
                    reason_code,
                    reason,
                    &timeline,
                )
                .await;
                break;
            }
            EncryptSendOutcome::RetryableLocalBackpressure { packet, reason } => {
                let next_backpressure_retries = local_backpressure_retries.saturating_add(1);
                record_retry_and_repark(
                    &transport,
                    &peers,
                    &peer_id,
                    &mut queue,
                    packet,
                    direct_budget_reroutes,
                    next_backpressure_retries,
                    pending_residence,
                    REASON_DIRECT_LOCAL_BACKPRESSURE,
                    reason,
                    &timeline,
                )
                .await;
                timeline.emit(
                    "direct_business_local_backpressure",
                    Some("direct"),
                    Some(REASON_DIRECT_LOCAL_BACKPRESSURE),
                    Some(format!(
                        "peer={peer_id} direct_budget_reroutes={direct_budget_reroutes} local_backpressure_retries={next_backpressure_retries} retry_after_ms={}",
                        OUTBOUND_RETRY_DELAY.as_millis(),
                    )),
                );
                break;
            }
            EncryptSendOutcome::Terminal {
                packet,
                reason_code,
                reason,
            } => {
                record_pending_residence(pending_residence, "tx_pending_residence_dropped_us");
                record_terminal_drop(
                    &transport,
                    &peers,
                    &peer_id,
                    generation,
                    packet,
                    reason_code,
                    reason,
                    &timeline,
                )
                .await;
                // The failed packet's counter is terminal, but later entries
                // are still plaintext and have no counter yet. Keep them in
                // FIFO order so a newly confirmed path can encrypt them with
                // fresh counters. Never replay the uncertain ciphertext and
                // never silently erase later business packets.
                if !queue.queue.is_empty() {
                    queue.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
                    timeline.emit(
                        "outbound_fifo_reparked_after_terminal",
                        None,
                        Some(reason_code),
                        Some(format!(
                            "peer={peer_id} remaining_packets={} remaining_bytes={} prior_counter_terminal=true",
                            queue.queue.len(),
                            queue.bytes
                        )),
                    );
                }
                break;
            }
        }
    }

    if flushed > 0 {
        record_outbound_flush_batch(&timeline, &peers, &peer_id, flushed, queue.queue.len());
    }
    (peer_id, queue)
}

#[cfg(test)]
pub(super) async fn merge_completed_flush(
    pending: &mut HashMap<String, PeerPendingQueue>,
    peer_id: String,
    completed: PeerPendingQueue,
    peers: &Arc<PeerManager>,
    timeline: &Arc<ConnectionTimeline>,
) {
    let ctx = queue_test_context(peers.clone(), timeline.clone(), true);
    merge_peer_work(pending, peer_id.clone(), completed, &ctx);
    if let Some(queue) = pending.get_mut(&peer_id) {
        report_deferred_losses(queue, &peer_id, &ctx).await;
    }
    pending.retain(|_, queue| queue.has_work());
}

/// Record a pre-handoff failure and re-park plaintext at the FRONT of the
/// queue. The old encrypted counter has already been abandoned and is never
/// retried.
#[allow(clippy::too_many_arguments)]
pub(super) async fn record_retry_and_repark(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    peer_id: &str,
    entry: &mut PeerPendingQueue,
    packet: OutboundPacket,
    direct_budget_reroutes: u8,
    local_backpressure_retries: u32,
    mut pending_residence: Option<PendingQueueResidence>,
    reason_code: &'static str,
    reason: String,
    timeline: &ConnectionTimeline,
) {
    let bytes = packet.packet.len();
    let generation = entry
        .wait_generation
        .unwrap_or_else(|| peers.current_network_generation_sync());
    if let Some(residence) = pending_residence.as_mut() {
        residence.resume();
    }
    entry.push_front(PendingPacket::Plain {
        packet,
        direct_budget_reroutes,
        local_backpressure_retries,
        pending_residence,
    });
    entry.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
    entry
        .delivery_deadline
        .get_or_insert_with(|| Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
    let mut counter_complete = false;
    let report = async {
        transport
            .record_outbound_send_failure(reason_code, 1, bytes)
            .await;
        counter_complete = true;
        record_loss_event(
            peers,
            "send_failure",
            peer_id,
            generation,
            reason_code,
            1,
            bytes,
            timeline,
        )
        .await;
    };
    if timeout(OUTBOUND_SEND_TIMEOUT, report).await.is_err() {
        timeline.emit("outbound_retry_report_timeout", None, Some(reason_code),
            Some(format!("peer={peer_id} generation={generation} bytes={bytes} counter_complete={counter_complete} accounting_complete=false plaintext_retained=true")));
        warn!(
            event = "outbound_retry_report_timeout",
            peer_id,
            generation,
            bytes,
            reason_code,
            counter_complete,
            "retry accounting incomplete; original plaintext remains in FIFO"
        );
    }
    debug!(
        event = "outbound_plaintext_reparked",
        peer_id = %peer_id,
        generation,
        reason_code,
        reason = %reason,
        queue_depth = entry.queue.len(),
        queue_bytes = entry.bytes,
        retry_after_ms = OUTBOUND_RETRY_DELAY.as_millis() as u64,
        direct_budget_reroutes,
        local_backpressure_retries,
        "send failed before transport handoff; packet returned to the FIFO as plaintext with a fresh-counter retry"
    );
    timeline.emit(
        "outbound_send_failure",
        None,
        Some(reason_code),
        Some(format!(
            "peer={peer_id} generation={} detail={reason}",
            entry.wait_generation.unwrap_or(0)
        )),
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_terminal_drop(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    peer_id: &str,
    packet_generation: u64,
    packet: OutboundPacket,
    reason_code: &'static str,
    reason: String,
    timeline: &ConnectionTimeline,
) {
    report_fast_path_terminal(
        transport,
        peers,
        peer_id,
        packet_generation,
        packet.packet.len(),
        reason_code,
        reason,
        timeline,
        None,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn report_fast_path_terminal(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    peer_id: &str,
    generation: u64,
    bytes: usize,
    reason_code: &'static str,
    reason: String,
    timeline: &ConnectionTimeline,
    health_failure: Option<(ActivePathSnapshot, Option<SocketAddr>)>,
) {
    let mut accounting_complete = false;
    let report = async {
        // Loss belongs to the original packet even if its path was replaced.
        // Complete accounting before attempting optional path-health cleanup.
        record_terminal_drop_bytes(
            transport,
            peers,
            peer_id,
            generation,
            bytes,
            reason_code,
            reason.clone(),
            timeline,
        )
        .await;
        accounting_complete = true;
        if let Some((path, local_endpoint)) = health_failure {
            peers
                .record_direct_failure_for_active_path_snapshot(
                    peer_id,
                    path,
                    REASON_DIRECT_SEND_FAILED,
                    reason,
                    local_endpoint,
                )
                .await;
        }
    };
    if timeout(OUTBOUND_SEND_TIMEOUT, report).await.is_err() {
        let phase = if accounting_complete {
            "path_health"
        } else {
            "loss_accounting"
        };
        timeline.emit(
            "outbound_terminal_report_timeout", Some("direct"), Some(reason_code),
            Some(format!("peer={peer_id} generation={generation} bytes={bytes} accounting_complete={accounting_complete} phase={phase}; incomplete accounting may be partial")),
        );
        warn!(
            event = "outbound_terminal_report_timeout",
            peer_id,
            generation,
            bytes,
            reason_code,
            accounting_complete,
            phase,
            "bounded terminal report stopped; only completed accounting is confirmed"
        );
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn record_terminal_drop_bytes(
    transport: &WireGuardTransport,
    peers: &PeerManager,
    peer_id: &str,
    packet_generation: u64,
    bytes: usize,
    reason_code: &'static str,
    reason: String,
    timeline: &ConnectionTimeline,
) {
    transport.record_outbound_drop(reason_code, 1, bytes).await;
    record_loss_event(
        peers,
        "drop",
        peer_id,
        packet_generation,
        reason_code,
        1,
        bytes,
        timeline,
    )
    .await;
    timeline.emit(
        "outbound_packet_dropped",
        None,
        Some(reason_code),
        Some(format!(
            "peer={peer_id} generation={packet_generation} dropped=1 bytes={bytes} detail={reason}"
        )),
    );
    warn!(
        event = "outbound_terminal_drop",
        peer_id = %peer_id,
        generation = packet_generation,
        reason_code,
        packets = 1u64,
        bytes,
        detail = %reason,
        "plaintext business packet reached a terminal loss boundary"
    );
}

#[cfg(test)]
fn queue_test_context(
    peers: Arc<PeerManager>,
    timeline: Arc<ConnectionTimeline>,
    relay_expected: bool,
) -> PeerWorkContext {
    let (transport, _) = WireGuardTransport::new();
    PeerWorkContext {
        transport,
        peers,
        prefer_direct: true,
        udp_transport: Arc::new(RwLock::new(None)),
        relay_transport: Arc::new(RwLock::new(None)),
        startup_wait: RelayStartupWait {
            relay_expected,
            timeout: None,
        },
        timeline,
        stopping: Arc::new(AtomicBool::new(false)),
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn maintenance(
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: &Arc<ConnectionTimeline>,
    _flush_tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    _flushing_peers: &mut HashSet<String>,
) {
    let ctx = PeerWorkContext {
        transport: transport.clone(),
        peers: peers.clone(),
        prefer_direct,
        udp_transport: udp_transport.clone(),
        relay_transport: relay_transport.clone(),
        startup_wait: RelayStartupWait {
            relay_expected,
            timeout: None,
        },
        timeline: timeline.clone(),
        stopping: Arc::new(AtomicBool::new(false)),
    };
    let ready: Vec<_> = pending.drain().collect();
    for (peer_id, queue) in ready {
        let (peer_id, remaining) = process_peer_queue(peer_id, queue, ctx.clone()).await;
        if remaining.has_work() {
            pending.insert(peer_id, remaining);
        }
    }
}

#[cfg(test)]
#[path = "tests/queue.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/profiling.rs"]
mod profiling_tests;
