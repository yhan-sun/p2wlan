use super::*;

#[derive(Clone)]
pub(super) struct PeerWorkContext {
    pub(super) transport: WireGuardTransport,
    pub(super) peers: Arc<PeerManager>,
    pub(super) prefer_direct: bool,
    pub(super) udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    pub(super) relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    pub(super) startup_wait: RelayStartupWait,
    pub(super) timeline: Arc<ConnectionTimeline>,
    pub(super) stopping: Arc<AtomicBool>,
}

/// Append before any authority/slot/accounting await. The synchronous
/// generation mirror binds the FIFO; it never authorizes physical delivery.
pub(super) fn append_ingress(
    packet: OutboundPacket,
    pending: &mut HashMap<String, PeerPendingQueue>,
    ctx: &PeerWorkContext,
    probe_kick: &mut u64,
    probe_kick_tx: &watch::Sender<u64>,
) {
    let peer_id = packet.peer_id.clone();
    let generation = ctx.peers.current_network_generation_sync();
    let entry = pending
        .entry(peer_id.clone())
        .or_insert_with(PeerPendingQueue::new);
    if entry.wait_generation.is_some_and(|old| old != generation) {
        discard_packets(entry, &peer_id, QueueLossReason::GenerationChanged, ctx);
        let losses = std::mem::take(&mut entry.deferred_losses);
        let loss_deadline = entry.loss_report_deadline;
        *entry = PeerPendingQueue::new();
        entry.deferred_losses = losses;
        entry.loss_report_deadline = loss_deadline;
    }
    entry.attach_resource_capture(ctx.transport.resource_capture());
    if entry.wait_generation.is_none() {
        let now = Instant::now();
        entry.wait_generation = Some(generation);
        // This snapshot chooses a workflow deadline only. The per-peer task
        // must still obtain the authoritative admission/selection fences.
        let known_path = ctx
            .peers
            .committed_business_path_snapshot_sync(&peer_id)
            .is_some_and(|path| {
                path.is_online_in_generation(generation)
                    && !matches!(path.active, ActiveBusinessPath::Unavailable)
            });
        if known_path {
            entry.delivery_deadline = Some(now + OUTBOUND_DELIVERY_DEADLINE);
        } else {
            entry.wait_started = Some(now);
            entry.wait_deadline = ctx.startup_wait.timeout.map(|wait| now + wait);
            bump_probe_kick(probe_kick, probe_kick_tx);
            ctx.timeline.emit(
                "outbound_first_packet_wait_started",
                None,
                None,
                Some(format!(
                    "peer={peer_id} generation={generation} wait_timeout_ms={:?}",
                    ctx.startup_wait.timeout.map(|wait| wait.as_millis())
                )),
            );
        }
    }
    let (dropped, bytes) = entry.enqueue(PendingPacket::plain(packet));
    let count = dropped.len();
    for mut dropped in dropped {
        finish_discard(&mut dropped, &peer_id, ctx);
    }
    defer_loss(
        entry,
        &peer_id,
        Some(generation),
        QueueLossReason::QueueFull,
        count,
        bytes,
        ctx,
    );
    debug!(
        event = "outbound_fifo_state",
        peer_id,
        generation,
        queue_depth = entry.queue.len(),
        queue_bytes = entry.bytes,
        queue_head = entry
            .queue
            .front()
            .map(|packet| raw_packet_summary(packet.raw_packet())),
        "plaintext appended synchronously to its bounded generation-owned FIFO"
    );
}

/// Scheduling inspects actor-owned workflow metadata only. There is one task
/// per peer; that task owns admission, maintenance, reports and the old FIFO.
pub(super) fn schedule_peer_work(
    pending: &mut HashMap<String, PeerPendingQueue>,
    tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    active: &mut HashMap<String, tokio::task::Id>,
    ctx: &PeerWorkContext,
) {
    let now = Instant::now();
    let generation = ctx.peers.current_network_generation_sync();
    let ready: Vec<String> = pending
        .iter()
        .filter(|(peer, queue)| {
            queue.has_work()
                && !active.contains_key(*peer)
                && (queue.wait_generation.is_some_and(|old| old != generation)
                    || queue.delivery_deadline.is_some_and(|at| at <= now)
                    || queue.wait_deadline.is_some_and(|at| at <= now)
                    || queue.retry_after.is_none_or(|at| at <= now))
        })
        .map(|(peer, _)| peer.clone())
        .collect();
    for peer_id in ready {
        let Some(mut queue) = pending.remove(&peer_id) else {
            continue;
        };
        queue.attach_resource_capture(ctx.transport.resource_capture());
        let mut shell = queue.timing_shell();
        shell.attach_resource_capture(ctx.transport.resource_capture());
        pending.insert(peer_id.clone(), shell);
        queue.relocate_resources(QueueStage::TaskOrUnjoinedFifo);
        let ctx = ctx.clone();
        let active_peer = peer_id.clone();
        #[cfg(test)]
        let observer = ctx.transport.clone();
        let task = tasks.spawn(process_peer_queue(peer_id, queue, ctx));
        #[cfg(test)]
        observer.observe_resource_queue_task_for_test(task.clone());
        active.insert(active_peer, task.id());
    }
}

pub(super) fn merge_peer_work(
    pending: &mut HashMap<String, PeerPendingQueue>,
    peer_id: String,
    mut completed: PeerPendingQueue,
    ctx: &PeerWorkContext,
) {
    completed.attach_resource_capture(ctx.transport.resource_capture());
    completed.relocate_resources(QueueStage::ActorFifo);
    let generation = ctx.peers.current_network_generation_sync();
    if completed
        .wait_generation
        .is_some_and(|old| old != generation)
    {
        discard_packets(
            &mut completed,
            &peer_id,
            QueueLossReason::GenerationChanged,
            ctx,
        );
        completed.wait_generation = None;
        completed.wait_started = None;
        completed.wait_deadline = None;
        completed.delivery_deadline = None;
        completed.retry_after = None;
    }
    let mut newer = pending
        .remove(&peer_id)
        .unwrap_or_else(PeerPendingQueue::new);
    if newer.wait_generation.is_some_and(|old| old != generation) {
        discard_packets(
            &mut newer,
            &peer_id,
            QueueLossReason::GenerationChanged,
            ctx,
        );
        newer.wait_generation = None;
        newer.wait_started = None;
        newer.wait_deadline = None;
        newer.delivery_deadline = None;
        newer.retry_after = None;
    }
    if completed.wait_generation.is_none() {
        completed.wait_generation = newer.wait_generation;
    }
    // A task may have emptied its old batch while live arrivals accumulated.
    // Its timing still bounds those same-generation arrivals until the whole
    // FIFO becomes empty. Never restart a deadline at completion.
    completed.wait_started = earliest(completed.wait_started, newer.wait_started);
    completed.wait_deadline = earliest(completed.wait_deadline, newer.wait_deadline);
    completed.delivery_deadline = earliest(completed.delivery_deadline, newer.delivery_deadline);
    completed.budget_pending_reported |= newer.budget_pending_reported;
    completed.loss_report_deadline =
        match (completed.loss_report_deadline, newer.loss_report_deadline) {
            (Some(old), Some(new)) => Some(old.min(new)),
            (old, new) => old.or(new),
        };
    let (mut count, mut bytes) = (0usize, 0usize);
    while let Some(packet) = newer.pop_front() {
        let (dropped, dropped_bytes) = completed.enqueue(packet);
        count = count.saturating_add(dropped.len());
        bytes = bytes.saturating_add(dropped_bytes);
        for mut packet in dropped {
            finish_discard(&mut packet, &peer_id, ctx);
        }
    }
    for loss in newer.deferred_losses {
        merge_loss(&mut completed, &peer_id, loss, ctx);
    }
    let queued_generation = completed.wait_generation;
    defer_loss(
        &mut completed,
        &peer_id,
        queued_generation,
        QueueLossReason::QueueFull,
        count,
        bytes,
        ctx,
    );
    if completed.deferred_losses.is_empty() {
        completed.loss_report_deadline = None;
    }
    if completed.has_work() {
        pending.insert(peer_id, completed);
    }
}

fn earliest(left: Option<Instant>, right: Option<Instant>) -> Option<Instant> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

fn finish_discard(packet: &mut PendingPacket, peer_id: &str, ctx: &PeerWorkContext) {
    let _ = ctx.peers.emit_local_mtu_feedback(
        peer_id,
        packet.raw_packet(),
        crate::business_mtu::LocalMtuFeedbackKind::Unreachable,
    );
    record_pending_residence(
        packet.take_pending_residence(),
        "tx_pending_residence_dropped_us",
    );
}

pub(super) fn discard_packets(
    queue: &mut PeerPendingQueue,
    peer_id: &str,
    reason: QueueLossReason,
    ctx: &PeerWorkContext,
) {
    let count = queue.queue.len();
    let bytes = queue.bytes;
    let generation = queue.wait_generation;
    if count > 0 {
        // Preserve the established queue-expiry/degradation event contract.
        // Emitting the decision is synchronous; aggregate accounting below
        // still belongs to the bounded per-peer owner.
        ctx.timeline.emit(
            "relay_unavailable_or_first_packet_expired",
            None,
            Some(reason.code()),
            Some(format!(
                "peer={peer_id} generation={generation:?} dropped={count} bytes={bytes} waited_ms={}",
                queue.wait_started.map_or(0, |started| started.elapsed().as_millis())
            )),
        );
    }
    while let Some(mut packet) = queue.pop_front() {
        finish_discard(&mut packet, peer_id, ctx);
    }
    defer_loss(queue, peer_id, generation, reason, count, bytes, ctx);
}

fn defer_loss(
    queue: &mut PeerPendingQueue,
    peer_id: &str,
    generation: Option<u64>,
    reason: QueueLossReason,
    packets: usize,
    bytes: usize,
    ctx: &PeerWorkContext,
) {
    if packets == 0 {
        return;
    }
    queue
        .loss_report_deadline
        .get_or_insert_with(|| tokio::time::Instant::now() + OUTBOUND_SEND_TIMEOUT);
    merge_loss(
        queue,
        peer_id,
        DeferredLoss {
            generation,
            reason,
            packets,
            bytes,
            counter_complete: false,
        },
        ctx,
    );
    ctx.timeline.emit("outbound_packet_dropped", None, Some(reason.code()),
        Some(format!("peer={peer_id} generation={generation:?} dropped={packets} bytes={bytes} accounting_complete=false reporting=peer_task")));
}

fn merge_loss(
    queue: &mut PeerPendingQueue,
    peer_id: &str,
    loss: DeferredLoss,
    ctx: &PeerWorkContext,
) {
    if let Some(existing) = queue.deferred_losses.iter_mut().find(|entry| {
        entry.reason == loss.reason
            && entry.counter_complete == loss.counter_complete
            && (entry.generation == loss.generation || entry.generation.is_none())
    }) {
        existing.packets = existing.packets.saturating_add(loss.packets);
        existing.bytes = existing.bytes.saturating_add(loss.bytes);
        return;
    }
    if queue.deferred_losses.len() >= MAX_DEFERRED_LOSS_RECORDS {
        // Eight typed reasons x two accounting phases fit in 16 slots. Fold
        // generation detail only; counted and not-yet-counted totals never
        // mix, so a resumed report cannot count a previous partial commit twice.
        let old = std::mem::take(&mut queue.deferred_losses);
        for mut entry in old {
            entry.generation = None;
            merge_loss(queue, peer_id, entry, ctx);
        }
        ctx.timeline.emit("outbound_loss_attribution_compacted", None, None,
            Some(format!("peer={peer_id} reason_totals_exact=true generation_attribution_omitted=true slots={}", queue.deferred_losses.len())));
        warn!(event="outbound_loss_attribution_compacted", peer_id,
            "bounded loss metadata retained exact reason totals; detailed generation attribution omitted");
        let mut loss = loss;
        loss.generation = None;
        merge_loss(queue, peer_id, loss, ctx);
        return;
    }
    queue.deferred_losses.push_back(loss);
}

/// Counters and event phases are retained separately across a timeout. Only
/// unfinished phases are retried; no partial aggregate commit is replayed.
pub(super) async fn report_deferred_losses(
    queue: &mut PeerPendingQueue,
    peer_id: &str,
    ctx: &PeerWorkContext,
) {
    if queue.deferred_losses.is_empty() {
        queue.loss_report_deadline = None;
        return;
    }
    // This deadline belongs to the original report owner. New losses and
    // repeated scheduling never renew it, including while that owner is
    // waiting to finish an older send batch.
    let remaining = queue
        .loss_report_deadline
        .get_or_insert_with(|| tokio::time::Instant::now() + OUTBOUND_SEND_TIMEOUT)
        .saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        report_shutdown_unknown(queue, peer_id, ctx);
        queue.deferred_losses.clear();
        queue.loss_report_deadline = None;
        return;
    }
    let report = async {
        while let Some(loss) = queue.deferred_losses.front_mut() {
            if !loss.counter_complete {
                ctx.peers
                    .record_outbound_drop(loss.reason.code(), loss.packets, loss.bytes)
                    .await;
                loss.counter_complete = true;
            }
            if let Some(generation) = loss.generation {
                record_loss_event(
                    &ctx.peers,
                    "drop",
                    peer_id,
                    generation,
                    loss.reason.code(),
                    loss.packets,
                    loss.bytes,
                    &ctx.timeline,
                )
                .await;
            } else {
                ctx.timeline.emit("outbound_loss_attribution_omitted", None, Some(loss.reason.code()),
                    Some(format!("peer={peer_id} packets={} bytes={} aggregate_accounting_complete=true generation_attribution_omitted=true", loss.packets, loss.bytes)));
            }
            queue.deferred_losses.pop_front();
        }
    };
    if timeout(remaining, report).await.is_err() {
        let counter_complete = queue
            .deferred_losses
            .front()
            .is_some_and(|loss| loss.counter_complete);
        ctx.timeline.emit("outbound_queue_report_timeout", None, None,
            Some(format!("peer={peer_id} pending_records={} front_counter_complete={counter_complete} accounting_complete=false report_owner_released=true", queue.deferred_losses.len())));
        warn!(
            event = "outbound_queue_report_timeout",
            peer_id,
            counter_complete,
            pending_records = queue.deferred_losses.len(),
            "overall report deadline reached; only committed counter phases are confirmed"
        );
        report_shutdown_unknown(queue, peer_id, ctx);
        queue.deferred_losses.clear();
    }
    queue.loss_report_deadline = None;
}

enum Admission {
    Offline,
    Unusable,
    Usable { budget_ready: bool },
}

pub(super) fn admission_bound(queue: &PeerPendingQueue) -> Duration {
    queue
        .delivery_deadline
        .or(queue.wait_deadline)
        .map_or(OUTBOUND_SEND_TIMEOUT, |deadline| {
            deadline
                .saturating_duration_since(Instant::now())
                .min(OUTBOUND_SEND_TIMEOUT)
        })
}

async fn check_admission(peer_id: &str, generation: u64, ctx: &PeerWorkContext) -> Admission {
    if !ctx.peers.peer_online(peer_id).await {
        return Admission::Offline;
    }
    let relay_available = ctx.relay_transport.read().await.is_some();
    if !ctx
        .peers
        .is_data_path_admitted_for_generation(
            peer_id,
            generation,
            relay_available || ctx.startup_wait.relay_expected,
        )
        .await
    {
        return Admission::Unusable;
    }
    Admission::Usable {
        budget_ready: direct_business_budget_ready_for_active_path(
            &ctx.peers,
            peer_id,
            &ctx.udp_transport,
            generation,
            relay_available,
        )
        .await,
    }
}

fn expired_reason(queue: &PeerPendingQueue) -> Option<QueueLossReason> {
    let now = Instant::now();
    if queue
        .delivery_deadline
        .is_some_and(|deadline| deadline <= now)
    {
        return Some(
            if queue.delivery_deadline_reason() == REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE {
                QueueLossReason::BackpressureExpired
            } else {
                QueueLossReason::DeliveryExpired
            },
        );
    }
    if queue.delivery_deadline.is_none()
        && queue.wait_deadline.is_some_and(|deadline| deadline <= now)
    {
        return Some(QueueLossReason::StartupExpired);
    }
    None
}

pub(super) async fn process_peer_queue(
    peer_id: String,
    mut queue: PeerPendingQueue,
    ctx: PeerWorkContext,
) -> (String, PeerPendingQueue) {
    #[cfg(test)]
    ctx.transport.pause_resource_queue_for_test().await;
    if ctx.stopping.load(Ordering::Acquire) {
        discard_packets(&mut queue, &peer_id, QueueLossReason::WorkerStopped, &ctx);
    } else if !queue.queue.is_empty() {
        let generation = queue
            .wait_generation
            .unwrap_or_else(|| ctx.peers.current_network_generation_sync());
        if generation != ctx.peers.current_network_generation_sync() {
            discard_packets(
                &mut queue,
                &peer_id,
                QueueLossReason::GenerationChanged,
                &ctx,
            );
        } else if queue.delivery_deadline.is_some() && expired_reason(&queue).is_some() {
            let reason = expired_reason(&queue).unwrap_or(QueueLossReason::DeliveryExpired);
            discard_packets(&mut queue, &peer_id, reason, &ctx);
        } else {
            let admitted = timeout(
                admission_bound(&queue),
                check_admission(&peer_id, generation, &ctx),
            )
            .await;
            if ctx.stopping.load(Ordering::Acquire) {
                discard_packets(&mut queue, &peer_id, QueueLossReason::WorkerStopped, &ctx);
            } else if generation != ctx.peers.current_network_generation_sync() {
                discard_packets(
                    &mut queue,
                    &peer_id,
                    QueueLossReason::GenerationChanged,
                    &ctx,
                );
            } else {
                match admitted {
                    Ok(Admission::Offline) => {
                        discard_packets(&mut queue, &peer_id, QueueLossReason::Offline, &ctx)
                    }
                    Ok(Admission::Usable { budget_ready }) => {
                        queue
                            .delivery_deadline
                            .get_or_insert_with(|| Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
                        if budget_ready {
                            let (_, remaining) = flush_one_peer_until_stopped(
                                peer_id.clone(),
                                queue,
                                ctx.transport.clone(),
                                ctx.peers.clone(),
                                ctx.prefer_direct,
                                ctx.udp_transport.clone(),
                                ctx.relay_transport.clone(),
                                ctx.startup_wait.relay_expected,
                                ctx.timeline.clone(),
                                ctx.stopping.clone(),
                            )
                            .await;
                            queue = remaining;
                        } else if !queue.budget_pending_reported {
                            queue.budget_pending_reported = true;
                            ctx.timeline.emit("direct_business_budget_pending", Some("direct"), Some(REASON_DIRECT_BUDGET_PENDING),
                                Some(format!("peer={peer_id} generation={generation} queued={} queued_bytes={}", queue.queue.len(), queue.bytes)));
                        }
                    }
                    Ok(Admission::Unusable)
                        if ctx.startup_wait.timeout.is_none()
                            && queue.delivery_deadline.is_none() =>
                    {
                        discard_packets(&mut queue, &peer_id, QueueLossReason::DirectOnly, &ctx);
                    }
                    Ok(Admission::Unusable) | Err(_) => {
                        if let Some(reason) = expired_reason(&queue) {
                            discard_packets(&mut queue, &peer_id, reason, &ctx);
                        }
                    }
                }
            }
        }
    }
    if ctx.stopping.load(Ordering::Acquire) {
        discard_packets(&mut queue, &peer_id, QueueLossReason::WorkerStopped, &ctx);
    }
    report_deferred_losses(&mut queue, &peer_id, &ctx).await;
    if queue.has_work() {
        queue
            .retry_after
            .get_or_insert_with(|| Instant::now() + OUTBOUND_RETRY_DELAY);
    }
    (peer_id, queue)
}

#[cfg(test)]
#[path = "../tests/admission_owner.rs"]
mod tests;

#[cfg(test)]
#[path = "../tests/resource_capture_queue.rs"]
mod resource_capture_tests;

pub(super) fn report_shutdown_unknown(
    queue: &PeerPendingQueue,
    peer_id: &str,
    ctx: &PeerWorkContext,
) {
    for loss in &queue.deferred_losses {
        ctx.timeline.emit("outbound_accounting_incomplete", None, Some(loss.reason.code()),
            Some(format!("peer={peer_id} generation={:?} packets={} bytes={} counter_complete={} detailed_event_complete=false", loss.generation, loss.packets, loss.bytes, loss.counter_complete)));
        warn!(event="outbound_accounting_incomplete", peer_id, reason_code=loss.reason.code(), generation=?loss.generation,
            packets=loss.packets, bytes=loss.bytes, counter_complete=loss.counter_complete,
            "report owner deadline reached; unfinished accounting remains unconfirmed");
    }
}
