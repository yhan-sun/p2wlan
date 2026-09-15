use super::{
    bump_probe_kick, debug, direct_business_budget_ready_for_active_path, encrypt_then_send,
    overlay_packet_identity, raw_packet_summary, record_loss_event, record_overflow_drop,
    record_terminal_drop, watch, Arc, ConnectionTimeline, EncryptSendOutcome, HashMap, HashSet,
    Instant, JoinSet, OutboundPacket, PeerManager, PeerPendingQueue, PendingPacket,
    RelayStartupWait, RelayTransport, RwLock, UdpTransport, WireGuardTransport,
    MAX_FLUSH_PER_PEER_PER_TICK, OUTBOUND_DELIVERY_DEADLINE, OUTBOUND_RETRY_DELAY,
    REASON_DIRECT_BUDGET_PENDING, REASON_DIRECT_BUDGET_REROUTE_EXHAUSTED,
    REASON_DIRECT_BUDGET_STALE, REASON_DIRECT_LOCAL_BACKPRESSURE,
    REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE, REASON_DIRECT_ONLY_NO_RELAY,
    REASON_OUTBOUND_DELIVERY_DEADLINE, REASON_OUTBOUND_GENERATION_CHANGED,
    REASON_OUTBOUND_PEER_OFFLINE, REASON_RELAY_STARTUP_WAIT_EXPIRED,
};

/// Route one RAW packet: encrypt + send immediately when its peer already has
/// a usable path AND a WireGuard session; otherwise park it (PLAINTEXT — no
/// counter, no emit lock) in the peer's bounded queue and start the peer's
/// SHARED startup deadline (first packet of a peer + generation only).
#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_ingress(
    packet: OutboundPacket,
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
    relay_startup_wait: RelayStartupWait,
    relay_expected: bool,
    probe_kick: &mut u64,
    relay_probe_kick_tx: &watch::Sender<u64>,
    timeline: &Arc<ConnectionTimeline>,
    flush_tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    flushing_peers: &mut HashSet<String>,
) {
    let peer_id = packet.peer_id.clone();
    let generation = peers.current_network_generation().await;
    if let Some((nonce, sequence, direction)) = overlay_packet_identity(&packet.packet) {
        debug!(
            event = "outbound_overlay_queued",
            peer_id = %peer_id,
            nonce = format_args!("{nonce:#x}"),
            sequence,
            direction,
            generation,
            "raw overlay packet entered the per-peer FIFO"
        );
    }
    // A waiting queue whose generation advanced mid-wait is dropped first
    // (old NAT mappings are invalid); the packet below starts a fresh wait.
    if pending.get(&peer_id).is_some_and(|entry| {
        entry.wait_generation.is_some() && entry.wait_generation != Some(generation)
    }) {
        drop_pending_queue(
            peers,
            pending.remove(&peer_id),
            REASON_OUTBOUND_GENERATION_CHANGED,
            timeline,
        )
        .await;
    }

    let relay_available = relay_transport.read().await.is_some();
    let usable = peers
        .is_data_path_admitted_for_generation(
            &peer_id,
            generation,
            relay_available || relay_expected,
        )
        .await;
    // Every business packet, including a packet arriving after confirmation,
    // enters the same per-peer FIFO. This is the critical distinction from the
    // old relay-first implementation, which could send a new live packet
    // around an older retry/session flush.
    let entry = pending
        .entry(peer_id.clone())
        .or_insert_with(PeerPendingQueue::new);
    let (dropped_entries, dropped_bytes) = entry.enqueue(PendingPacket::plain(packet));
    let dropped_packets = dropped_entries.len();
    debug!(
        event = "outbound_fifo_state",
        peer_id = %peer_id,
        generation,
        queue_depth = entry.queue.len(),
        queue_bytes = entry.bytes,
        wait_started = entry.wait_started.is_some(),
        wait_generation = ?entry.wait_generation,
        dropped_packets,
        dropped_bytes,
        "raw business packet appended to the per-peer FIFO"
    );
    if dropped_packets > 0 {
        for dropped in &dropped_entries {
            let _ = peers.emit_local_mtu_feedback(
                &peer_id,
                dropped.raw_packet(),
                crate::business_mtu::LocalMtuFeedbackKind::Unreachable,
            );
        }
        record_overflow_drop(
            peers,
            &peer_id,
            dropped_packets,
            dropped_bytes,
            entry,
            timeline,
        )
        .await;
    }

    let should_start_wait = entry.wait_started.is_none() && !usable;
    if should_start_wait {
        match relay_startup_wait.timeout {
            None => {
                // Direct-only configuration: never wait for a relay that is
                // not configured/expected.  Drop every parked packet with a
                // stable reason code.
                drop_pending_queue(
                    peers,
                    pending.remove(&peer_id),
                    REASON_DIRECT_ONLY_NO_RELAY,
                    timeline,
                )
                .await;
                debug!(
                    "Outbound packet for peer {} dropped: direct-only config has no relay and direct is not confirmed",
                    peer_id
                );
            }
            Some(timeout) => {
                entry.wait_started = Some(Instant::now());
                entry.wait_deadline = Some(Instant::now() + timeout);
                entry.wait_generation = Some(generation);
                // Kick the forced-relay probe loop: the peer's first business
                // packet is waiting and the relay path is not confirmed yet.
                bump_probe_kick(probe_kick, relay_probe_kick_tx);
                let queue_head = entry
                    .queue
                    .front()
                    .map(|packet| raw_packet_summary(packet.raw_packet()))
                    .unwrap_or_else(|| "empty".to_string());
                timeline.emit(
                    "outbound_first_packet_wait_started",
                    None,
                    None,
                    Some(format!(
                        "peer={peer_id} generation={generation} wait_timeout_ms={} queued={} queue_head={queue_head}",
                        timeout.as_millis(),
                        entry.queue.len()
                    )),
                );
            }
        }
    }

    if usable {
        if let Some(entry) = pending.get_mut(&peer_id) {
            // Even a queue created after a confirmed path belongs to this
            // generation.  Recording it here lets generation advance cancel
            // a retry that was parked after a path/transport change instead
            // of leaving it behind an apparently healthy peer.
            entry.wait_generation = Some(generation);
            entry
                .delivery_deadline
                .get_or_insert_with(|| Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
        }
        start_ready_peer_flushes(
            transport,
            peers,
            pending,
            prefer_direct,
            udp_transport,
            relay_transport,
            relay_expected,
            timeline,
            flush_tasks,
            flushing_peers,
        )
        .await;
    }
}

/// Start one independent flush task for every peer that became usable
/// (DirectConfirmed or RelayPeerConfirmed). Only plaintext is retained
/// between attempts; encrypted packets never live in the retry queue.
///
/// The previous implementation awaited all peer flushes in this actor. That
/// made the actor stop receiving new TUN packets while one relay writer was
/// stalled. The task set below preserves one FIFO owner per peer while the
/// actor remains fair to other peers.
#[allow(clippy::too_many_arguments)]
pub(super) async fn start_ready_peer_flushes(
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
    pending: &mut HashMap<String, PeerPendingQueue>,
    prefer_direct: bool,
    udp_transport: &Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: &Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: &Arc<ConnectionTimeline>,
    flush_tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    flushing_peers: &mut HashSet<String>,
) {
    let now = Instant::now();
    let delivery_expired: Vec<(String, &'static str)> = pending
        .iter()
        .filter(|(_, entry)| {
            !entry.queue.is_empty()
                && entry
                    .delivery_deadline
                    .is_some_and(|deadline| now >= deadline)
        })
        .map(|(peer_id, entry)| (peer_id.clone(), entry.delivery_deadline_reason()))
        .collect();
    for (peer_id, reason_code) in delivery_expired {
        drop_pending_queue(peers, pending.remove(&peer_id), reason_code, timeline).await;
    }

    let (ready_ids, budget_pending_ids): (Vec<String>, Vec<String>) = {
        let mut ready = Vec::new();
        let mut budget_pending = Vec::new();
        for (peer_id, entry) in pending.iter() {
            if entry.queue.is_empty() {
                continue;
            }
            if flushing_peers.contains(peer_id) {
                continue;
            }
            if entry.retry_after.is_some_and(|at| at > Instant::now()) {
                continue;
            }
            let generation = peers.current_network_generation().await;
            let relay_available = relay_transport.read().await.is_some();
            if peers
                .is_data_path_admitted_for_generation(
                    peer_id,
                    generation,
                    relay_available || relay_expected,
                )
                .await
            {
                if direct_business_budget_ready_for_active_path(
                    peers,
                    peer_id,
                    udp_transport,
                    generation,
                    relay_available,
                )
                .await
                {
                    ready.push(peer_id.clone());
                } else {
                    budget_pending.push(peer_id.clone());
                }
            }
        }
        (ready, budget_pending)
    };
    // A queue can be created while relay confirmation is still pending, so
    // `handle_ingress` cannot start its delivery deadline at that time.  Once
    // the same-generation path becomes usable, bind one deadline to the whole
    // queued batch before handing ownership to a flush task.  Without this
    // boundary a slow writer can make a 256-packet backlog drain for tens of
    // seconds even though the startup wait itself was bounded.
    let delivery_deadline = now + OUTBOUND_DELIVERY_DEADLINE;
    for peer_id in ready_ids.iter().chain(budget_pending_ids.iter()) {
        if let Some(entry) = pending.get_mut(peer_id) {
            entry.delivery_deadline.get_or_insert(delivery_deadline);
            if !entry.budget_pending_reported && budget_pending_ids.contains(peer_id) {
                timeline.emit(
                    "direct_business_budget_pending",
                    Some("direct"),
                    Some(REASON_DIRECT_BUDGET_PENDING),
                    Some(format!(
                        "peer={peer_id} queued={} queued_bytes={} ttl_ms={}",
                        entry.queue.len(),
                        entry.bytes,
                        OUTBOUND_DELIVERY_DEADLINE.as_millis(),
                    )),
                );
                entry.budget_pending_reported = true;
            }
        }
    }
    // Remove each ready queue before starting its task. Each queue remains
    // single-owner, preserving FIFO and retry-at-front invariants, while a
    // stalled relay writer for one peer cannot hold up another peer's ingress.
    let ready_queues: Vec<(String, PeerPendingQueue)> = ready_ids
        .into_iter()
        .filter_map(|peer_id| pending.remove(&peer_id).map(|queue| (peer_id, queue)))
        .collect();
    for (peer_id, queue) in ready_queues {
        flushing_peers.insert(peer_id.clone());
        let task_transport = transport.clone();
        let task_peers = peers.clone();
        let task_udp_transport = udp_transport.clone();
        let task_relay_transport = relay_transport.clone();
        let task_timeline = timeline.clone();
        flush_tasks.spawn(async move {
            flush_one_peer(
                peer_id,
                queue,
                task_transport,
                task_peers,
                prefer_direct,
                task_udp_transport,
                task_relay_transport,
                relay_expected,
                task_timeline,
            )
            .await
        });
    }
}

/// Flush one peer's queue. This is the sole owner of that peer's queue while
/// it is in flight. A terminal/uncertain handoff stops the batch immediately:
/// that counter is consumed, while later plaintext packets remain available
/// for a replacement path and receive fresh counters.
#[allow(clippy::too_many_arguments)]
pub(super) async fn flush_one_peer(
    peer_id: String,
    mut queue: PeerPendingQueue,
    transport: WireGuardTransport,
    peers: Arc<PeerManager>,
    prefer_direct: bool,
    udp_transport: Arc<RwLock<Option<UdpTransport>>>,
    relay_transport: Arc<RwLock<Option<RelayTransport>>>,
    relay_expected: bool,
    timeline: Arc<ConnectionTimeline>,
) -> (String, PeerPendingQueue) {
    let mut flushed = 0usize;
    while flushed < MAX_FLUSH_PER_PEER_PER_TICK {
        if !queue.queue.is_empty()
            && queue
                .delivery_deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
        {
            let reason_code = queue.delivery_deadline_reason();
            if flushed > 0 {
                let remaining = queue.queue.len();
                let relay_confirm_seq = peers.relay_confirm_seq_sync(&peer_id);
                let direct_commit_seq = peers.direct_commit_seq_sync(&peer_id);
                timeline.emit(
                    "outbound_first_packet_flushed",
                    None,
                    None,
                    Some(format!(
                        "peer={peer_id} flushed={flushed} remaining={remaining} relay_confirm_seq={relay_confirm_seq:?} direct_commit_seq={direct_commit_seq:?}"
                    )),
                );
            }
            drop_pending_queue(&peers, Some(queue), reason_code, &timeline).await;
            return (peer_id, PeerPendingQueue::new());
        }
        let Some(front) = queue.pop_front() else {
            break;
        };

        let generation = peers.current_network_generation().await;
        if queue
            .wait_generation
            .is_some_and(|queued_generation| queued_generation != generation)
        {
            queue.push_front(front);
            drop_pending_queue(
                &peers,
                Some(queue),
                REASON_OUTBOUND_GENERATION_CHANGED,
                &timeline,
            )
            .await;
            return (peer_id, PeerPendingQueue::new());
        }

        let relay_available = relay_transport.read().await.is_some();
        let usable = peers
            .is_data_path_admitted_for_generation(
                &peer_id,
                generation,
                relay_available || relay_expected,
            )
            .await;
        if !usable {
            queue.push_front(front);
            break;
        }

        let PendingPacket::Plain {
            packet,
            direct_budget_reroutes,
            local_backpressure_retries,
        } = front;
        match encrypt_then_send(
            packet,
            &transport,
            &peers,
            generation,
            prefer_direct,
            &udp_transport,
            &relay_transport,
            relay_expected,
        )
        .await
        {
            EncryptSendOutcome::Sent => flushed = flushed.saturating_add(1),
            EncryptSendOutcome::BudgetPending { packet, reason } => {
                queue.push_front(PendingPacket::Plain {
                    packet,
                    direct_budget_reroutes,
                    local_backpressure_retries,
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
        let remaining = queue.queue.len();
        let relay_confirm_seq = peers.relay_confirm_seq_sync(&peer_id);
        let direct_commit_seq = peers.direct_commit_seq_sync(&peer_id);
        timeline.emit(
            "outbound_first_packet_flushed",
            None,
            None,
            Some(format!(
                "peer={peer_id} flushed={flushed} remaining={remaining} relay_confirm_seq={relay_confirm_seq:?} direct_commit_seq={direct_commit_seq:?}"
            )),
        );
        debug!("Flushed {flushed} queued packets for peer {peer_id}");
    }
    (peer_id, queue)
}

/// Merge a completed peer task ahead of packets that arrived while it was
/// running. The completed queue is always older, so appending the newer queue
/// preserves strict per-peer FIFO.
pub(super) fn merge_completed_flush(
    pending: &mut HashMap<String, PeerPendingQueue>,
    peer_id: String,
    mut completed: PeerPendingQueue,
) {
    let Some(mut newer) = pending.remove(&peer_id) else {
        if !completed.queue.is_empty() {
            pending.insert(peer_id, completed);
        }
        return;
    };

    if completed.queue.is_empty() {
        pending.insert(peer_id, newer);
        return;
    }

    completed.queue.append(&mut newer.queue);
    completed.bytes = completed.bytes.saturating_add(newer.bytes);
    if completed.wait_started.is_none() {
        completed.wait_started = newer.wait_started;
    }
    if completed.wait_deadline.is_none() {
        completed.wait_deadline = newer.wait_deadline;
    }
    if completed.wait_generation.is_none() {
        completed.wait_generation = newer.wait_generation;
    }
    if completed.retry_after.is_none() {
        completed.retry_after = newer.retry_after;
    }
    if completed.delivery_deadline.is_none() {
        completed.delivery_deadline = newer.delivery_deadline;
    }
    pending.insert(peer_id, completed);
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
    reason_code: &'static str,
    reason: String,
    timeline: &ConnectionTimeline,
) {
    transport
        .record_outbound_send_failure(reason_code, 1, packet.packet.len())
        .await;
    let generation = entry
        .wait_generation
        .unwrap_or_else(|| peers.current_network_generation_sync());
    record_loss_event(
        peers,
        "send_failure",
        peer_id,
        generation,
        reason_code,
        1,
        packet.packet.len(),
        timeline,
    )
    .await;
    entry.push_front(PendingPacket::Plain {
        packet,
        direct_budget_reroutes,
        local_backpressure_retries,
    });
    entry.retry_after = Some(Instant::now() + OUTBOUND_RETRY_DELAY);
    entry
        .delivery_deadline
        .get_or_insert_with(|| Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
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

/// Periodic maintenance: expire startup deadlines, cancel waits on peer
/// offline / generation change, and flush what became usable.
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
    flush_tasks: &mut JoinSet<(String, PeerPendingQueue)>,
    flushing_peers: &mut HashSet<String>,
) {
    let now = Instant::now();
    let generation = peers.current_network_generation().await;

    // 1. Startup-deadline expiry: every queued packet of a peer whose shared
    //    deadline passed is dropped with the stable reason code.  A peer that
    //    JUST became usable (RelayPeerConfirmed or DirectConfirmed) in the same
    //    tick is NOT dropped here: the confirmation races the deadline, and
    //    flush_ready_peers below must deliver its queued packets instead of the
    //    expiry dropping them as if the path never came up.
    let expired: Vec<String> = {
        let mut expired = Vec::new();
        for (peer_id, entry) in pending.iter() {
            if entry.wait_deadline.is_none_or(|deadline| now < deadline) {
                continue;
            }
            let relay_available = relay_transport.read().await.is_some();
            let usable = peers
                .is_data_path_admitted_for_generation(
                    peer_id,
                    generation,
                    relay_available || relay_expected,
                )
                .await;
            if !usable {
                expired.push(peer_id.clone());
            }
        }
        expired
    };
    for peer_id in expired {
        drop_pending_queue(
            peers,
            pending.remove(&peer_id),
            REASON_RELAY_STARTUP_WAIT_EXPIRED,
            timeline,
        )
        .await;
    }

    // 2. Cancellation: peer offline or generation change invalidates the wait.
    let cancellations: Vec<(String, &'static str)> = pending
        .iter()
        .filter(|(_, entry)| !entry.queue.is_empty())
        .filter_map(|(peer_id, entry)| {
            if entry.wait_generation != Some(generation) {
                return Some((peer_id.clone(), REASON_OUTBOUND_GENERATION_CHANGED));
            }
            None
        })
        .collect();
    for (peer_id, reason) in cancellations {
        drop_pending_queue(peers, pending.remove(&peer_id), reason, timeline).await;
    }
    let offline: Vec<String> = {
        let mut offline = Vec::new();
        for (peer_id, entry) in pending.iter() {
            if !entry.queue.is_empty() && !peers.peer_online(peer_id).await {
                offline.push(peer_id.clone());
            }
        }
        offline
    };
    for peer_id in offline {
        drop_pending_queue(
            peers,
            pending.remove(&peer_id),
            REASON_OUTBOUND_PEER_OFFLINE,
            timeline,
        )
        .await;
    }

    // 3. Flush what became usable (paced by each peer's retry_after).
    start_ready_peer_flushes(
        transport,
        peers,
        pending,
        prefer_direct,
        udp_transport,
        relay_transport,
        relay_expected,
        timeline,
        flush_tasks,
        flushing_peers,
    )
    .await;
}

/// Drop a pending queue, emitting a stable reason event with the peer detail
/// and recording the loss in the peer manager's structural drop counters.
pub(super) async fn drop_pending_queue(
    peers: &PeerManager,
    queue: Option<PeerPendingQueue>,
    reason_code: &'static str,
    timeline: &ConnectionTimeline,
) {
    let Some(queue) = queue else { return };
    let dropped = queue.queue.len();
    if dropped == 0 {
        return;
    }
    let peer_id = queue
        .queue
        .front()
        .map(|packet| packet.peer_id().to_string())
        .unwrap_or_default();
    let generation = queue.wait_generation.unwrap_or(0);
    if matches!(
        reason_code,
        REASON_OUTBOUND_DELIVERY_DEADLINE
            | REASON_DIRECT_LOCAL_BACKPRESSURE_DEADLINE
            | REASON_RELAY_STARTUP_WAIT_EXPIRED
            | REASON_DIRECT_ONLY_NO_RELAY
    ) {
        for packet in &queue.queue {
            let _ = peers.emit_local_mtu_feedback(
                &peer_id,
                packet.raw_packet(),
                crate::business_mtu::LocalMtuFeedbackKind::Unreachable,
            );
        }
    }
    timeline.emit(
        "relay_unavailable_or_first_packet_expired",
        None,
        Some(reason_code),
        Some(format!(
            "peer={peer_id} generation={generation} dropped={dropped} bytes={} waited_ms={}",
            queue.bytes,
            queue
                .wait_started
                .map(|started| started.elapsed().as_millis())
                .unwrap_or(0)
        )),
    );
    peers
        .record_outbound_drop(reason_code, dropped, queue.bytes)
        .await;
    record_loss_event(
        peers,
        "drop",
        &peer_id,
        generation,
        reason_code,
        dropped,
        queue.bytes,
        timeline,
    )
    .await;
    debug!(
        "Dropped {dropped} queued packets for peer {peer_id}: {reason_code} (bytes={})",
        queue.bytes
    );
}

pub(super) async fn drop_all_pending_queues(
    peers: &PeerManager,
    pending: &mut HashMap<String, PeerPendingQueue>,
    reason_code: &'static str,
    timeline: &ConnectionTimeline,
) {
    let peer_ids: Vec<String> = pending.keys().cloned().collect();
    for peer_id in peer_ids {
        drop_pending_queue(peers, pending.remove(&peer_id), reason_code, timeline).await;
    }
}
