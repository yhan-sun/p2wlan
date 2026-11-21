// C06 static candidate: actual original FIFO/actor/repark methods, no replica.
use super::*;
use crate::overlay_requests::CanonicalOverlayRequest;
use crate::request_carriage::test_support::{mint_routed_request, RoutedRequestFixture};
use crate::request_carriage::{RawRequestDelivery, RequestBindingState, RequestInputEligibility};

fn b14_network_legacy(template: &RawRequestDelivery, marker: u8, bytes: usize) -> OutboundPacket {
    OutboundPacket {
        room_authorization: None,
        trace: None,
        peer_id: template.peer_id.clone(),
        dst_ip: template.dst_ip.clone(),
        packet: vec![marker; bytes],
    }
}

fn b14_network_same_a(packet: &PendingPacket, record: &Arc<CanonicalOverlayRequest>) {
    let PendingPacket::Plain { packet, .. } = packet;
    let binding = packet.binding().expect("real read remains tracked");
    assert_eq!(binding.state(), RequestBindingState::RoutedExact);
    let original = binding
        .token()
        .request()
        .expect("explicit original view is alive");
    assert!(Arc::ptr_eq(record, &original));
    assert_eq!(packet.packet, record.original_packet());
    assert_eq!(original.generation, record.generation);
}

fn b14_network_context(
    peers: Arc<PeerManager>,
) -> (PeerWorkContext, mpsc::Receiver<RawRequestDelivery>) {
    let (transport, raw_rx) = WireGuardTransport::new_with_request_carriage();
    let timeline = ConnectionTimeline::new("b14-network-queue", 14);
    transport.set_outbound_loss_context(&peers, timeline.clone());
    (
        PeerWorkContext {
            transport,
            peers,
            prefer_direct: false,
            udp_transport: Arc::new(RwLock::new(None)),
            relay_transport: Arc::new(RwLock::new(None)),
            startup_wait: RelayStartupWait {
                relay_expected: true,
                timeout: Some(Duration::from_secs(8)),
            },
            timeline,
            stopping: Arc::new(AtomicBool::new(false)),
        },
        raw_rx,
    )
}

#[tokio::test]
async fn b14_c06_original_fifo_512_and_2mib_are_per_owner_and_keep_same_weak() {
    let RoutedRequestFixture {
        record, delivery, ..
    } = mint_routed_request().await;
    let weak = Arc::downgrade(&record);
    let len = delivery.packet.len();
    assert_eq!(MAX_PENDING_PACKETS_PER_PEER, 512);
    assert_eq!(MAX_PENDING_BYTES_PER_PEER, 2 * 1024 * 1024);
    let mut actor_owned = PeerPendingQueue::new();
    let mut task_owned = PeerPendingQueue::new();
    for _ in 0..512 {
        let (drop_a, bytes_a) = actor_owned.enqueue(PendingPacket::plain(delivery.clone()));
        let (drop_b, bytes_b) = task_owned.enqueue(PendingPacket::plain(delivery.clone()));
        assert!(drop_a.is_empty() && drop_b.is_empty());
        assert_eq!((bytes_a, bytes_b), (0, 0));
    }
    assert_eq!(
        (actor_owned.queue.len(), task_owned.queue.len()),
        (512, 512)
    );
    assert_eq!(
        (actor_owned.bytes, task_owned.bytes),
        (512 * len, 512 * len)
    );
    let (evicted, evicted_bytes) = actor_owned.enqueue(PendingPacket::plain(delivery.clone()));
    assert_eq!((evicted.len(), evicted_bytes), (1, len));
    b14_network_same_a(&evicted[0], &record);
    assert_eq!(
        (actor_owned.queue.len(), task_owned.queue.len()),
        (512, 512)
    );
    for packet in actor_owned.queue.iter().chain(task_owned.queue.iter()) {
        b14_network_same_a(packet, &record);
    }
    // Same original queue type; byte fillers remain explicitly legacy/untracked.
    let mut byte_owner = PeerPendingQueue::new();
    assert!(byte_owner
        .enqueue(PendingPacket::plain(delivery.clone()))
        .0
        .is_empty());
    assert!(byte_owner
        .enqueue(PendingPacket::plain(b14_network_legacy(
            &delivery,
            9,
            MAX_PENDING_BYTES_PER_PEER - len,
        )))
        .0
        .is_empty());
    assert_eq!(byte_owner.bytes, MAX_PENDING_BYTES_PER_PEER);
    let (evicted, bytes) =
        byte_owner.enqueue(PendingPacket::plain(b14_network_legacy(&delivery, 10, 1)));
    assert_eq!((evicted.len(), bytes), (1, len));
    b14_network_same_a(&evicted[0], &record);
    assert_eq!(byte_owner.bytes, MAX_PENDING_BYTES_PER_PEER - len + 1);
    let before = (byte_owner.queue.len(), byte_owner.bytes);
    let (oversize, bytes) = byte_owner.enqueue(PendingPacket::plain(b14_network_legacy(
        &delivery,
        11,
        MAX_PENDING_BYTES_PER_PEER + 1,
    )));
    assert_eq!((oversize.len(), bytes), (1, MAX_PENDING_BYTES_PER_PEER + 1));
    assert_eq!((byte_owner.queue.len(), byte_owner.bytes), before);
    drop(record);
    assert!(
        weak.upgrade().is_none(),
        "1024 original queued clones must not keep the request alive"
    );
    for packet in actor_owned.queue.iter().chain(task_owned.queue.iter()) {
        let PendingPacket::Plain { packet, .. } = packet;
        assert_eq!(
            packet.binding().unwrap().eligibility_at(Instant::now()),
            RequestInputEligibility::Retired
        );
    }
}

#[tokio::test]
async fn b14_c06_original_merge_repark_keep_fifo_earliest_deadlines_residence_and_a_generation() {
    let RoutedRequestFixture {
        peers,
        record,
        delivery,
        ..
    } = mint_routed_request().await;
    let original_generation = record.generation;
    let peer = delivery.peer_id.clone();
    let len = delivery.packet.len();
    let (ctx, _raw_rx) = b14_network_context(peers);
    let start = Instant::now();
    let wait_deadline = start + Duration::from_secs(8);
    let delivery_deadline = start + OUTBOUND_DELIVERY_DEADLINE;
    let mut completed = PeerPendingQueue::new();
    completed.wait_generation = Some(ctx.peers.current_network_generation_sync());
    completed.wait_started = Some(start);
    completed.wait_deadline = Some(wait_deadline);
    completed.delivery_deadline = Some(delivery_deadline);
    let mut first = PendingPacket::plain(delivery.clone());
    let PendingPacket::Plain {
        pending_residence, ..
    } = &mut first;
    // Setup only: opt-in sampled interval; no token, accepted or canonical clock write.
    *pending_residence = Some(PendingQueueResidence::start_at(start));
    assert!(completed.enqueue(first).0.is_empty());
    assert!(completed
        .enqueue(PendingPacket::plain(b14_network_legacy(&delivery, 1, 1)))
        .0
        .is_empty());
    let mut newer = completed.timing_shell();
    assert_eq!(
        (
            newer.wait_started,
            newer.wait_deadline,
            newer.delivery_deadline
        ),
        (Some(start), Some(wait_deadline), Some(delivery_deadline))
    );
    newer.wait_started = Some(start + Duration::from_millis(1));
    newer.wait_deadline = Some(wait_deadline + Duration::from_millis(1));
    newer.delivery_deadline = Some(delivery_deadline + Duration::from_millis(1));
    assert!(newer
        .enqueue(PendingPacket::plain(b14_network_legacy(&delivery, 2, 1)))
        .0
        .is_empty());
    assert!(newer
        .enqueue(PendingPacket::plain(delivery.clone()))
        .0
        .is_empty());
    let mut pending = HashMap::from([(peer.clone(), newer)]);
    merge_peer_work(&mut pending, peer.clone(), completed, &ctx);
    let mut merged = pending.remove(&peer).unwrap();
    assert_eq!(
        (
            merged.wait_started,
            merged.wait_deadline,
            merged.delivery_deadline
        ),
        (Some(start), Some(wait_deadline), Some(delivery_deadline))
    );
    assert_eq!(merged.bytes, 2 * len + 2);
    assert_eq!(merged.wait_generation, Some(original_generation));
    let mut first = merged.pop_front().unwrap();
    b14_network_same_a(&first, &record);
    let mut residence = first.take_pending_residence().unwrap();
    residence.pause_at(start + Duration::from_micros(7));
    let PendingPacket::Plain { packet, .. } = first;
    record_retry_and_repark(
        &ctx.transport,
        &ctx.peers,
        &peer,
        &mut merged,
        packet,
        1,
        3,
        Some(residence),
        REASON_DIRECT_LOCAL_BACKPRESSURE,
        "original local capacity retry".to_string(),
        &ctx.timeline,
    )
    .await;
    assert_eq!(
        (
            merged.wait_started,
            merged.wait_deadline,
            merged.delivery_deadline
        ),
        (Some(start), Some(wait_deadline), Some(delivery_deadline))
    );
    assert_eq!(merged.bytes, 2 * len + 2);
    assert_eq!(record.generation, original_generation);
    let mut retried = merged.pop_front().unwrap();
    b14_network_same_a(&retried, &record);
    let PendingPacket::Plain {
        direct_budget_reroutes,
        local_backpressure_retries,
        ..
    } = &retried;
    assert_eq!(
        (*direct_budget_reroutes, *local_backpressure_retries),
        (1, 3)
    );
    let mut residence = retried.take_pending_residence().unwrap();
    // Before its new resume: isolate already accumulated old residence, as the old profiler control does.
    residence.pause_at(start);
    assert_eq!(residence.finish(), Duration::from_micros(7));
    assert_eq!(merged.pop_front().unwrap().raw_packet(), &[1]);
    assert_eq!(merged.pop_front().unwrap().raw_packet(), &[2]);
    b14_network_same_a(&merged.pop_front().unwrap(), &record);
    assert_eq!(merged.bytes, 0);
    assert!(merged.queue.is_empty());
}

#[tokio::test]
async fn b14_c06_original_actor_generation_discard_does_not_relabel_a_then_shutdown_accounts() {
    let RoutedRequestFixture {
        peers,
        record,
        delivery,
        ..
    } = mint_routed_request().await;
    let weak = Arc::downgrade(&record);
    let original_generation = record.generation;
    let peer = delivery.peer_id.clone();
    let len = delivery.packet.len();
    let (ctx, mut raw_rx) = b14_network_context(peers);
    let (kick_tx, _kick_rx) = watch::channel(0);
    let mut kick = 0;
    let mut pending = HashMap::new();
    append_ingress(delivery.clone(), &mut pending, &ctx, &mut kick, &kick_tx);
    b14_network_same_a(pending.get(&peer).unwrap().queue.front().unwrap(), &record);
    let current = ctx
        .peers
        .advance_network_generation("b14 real generation boundary")
        .await;
    assert_ne!(current, original_generation);
    append_ingress(delivery.clone(), &mut pending, &ctx, &mut kick, &kick_tx);
    let queue = pending.get(&peer).unwrap();
    assert_eq!(queue.queue.len(), 1);
    assert_eq!(queue.wait_generation, Some(current));
    b14_network_same_a(queue.queue.front().unwrap(), &record);
    assert_eq!(
        record.generation, original_generation,
        "actor mirror cannot rewrite historical A.G"
    );
    assert_eq!(queue.deferred_losses.len(), 1);
    assert_eq!(
        (
            queue.deferred_losses[0].packets,
            queue.deferred_losses[0].bytes
        ),
        (1, len)
    );
    assert_eq!(
        queue.deferred_losses[0].reason,
        QueueLossReason::GenerationChanged
    );
    drop(record);
    assert!(
        weak.upgrade().is_none(),
        "new-generation parking retains the same expired Weak only"
    );
    ctx.stopping.store(true, Ordering::Release);
    let (_, remaining) =
        process_peer_queue(peer.clone(), pending.remove(&peer).unwrap(), ctx.clone()).await;
    assert!(remaining.queue.is_empty() && remaining.deferred_losses.is_empty());
    assert_eq!(remaining.bytes, 0);
    assert!(raw_rx.try_recv().is_err());
    let loss = ctx.peers.outbound_loss_stats().await;
    for reason in [
        REASON_OUTBOUND_GENERATION_CHANGED,
        REASON_OUTBOUND_WORKER_STOPPED,
    ] {
        let counter = loss.drops.get(reason).unwrap();
        assert_eq!((counter.packets, counter.bytes), (1, len as u64));
    }
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn b14_c06_original_stopping_owner_discards_real_tracked_fifo_without_keeper_or_send() {
    let RoutedRequestFixture {
        peers,
        record,
        delivery,
        ..
    } = mint_routed_request().await;
    let weak = Arc::downgrade(&record);
    let peer = delivery.peer_id.clone();
    let len = delivery.packet.len();
    let (ctx, mut raw_rx) = b14_network_context(peers);
    let (kick_tx, _kick_rx) = watch::channel(0);
    let mut kick = 0;
    let mut pending = HashMap::new();
    append_ingress(delivery.clone(), &mut pending, &ctx, &mut kick, &kick_tx);
    append_ingress(delivery.clone(), &mut pending, &ctx, &mut kick, &kick_tx);
    assert_eq!(pending.get(&peer).unwrap().queue.len(), 2);
    for packet in &pending.get(&peer).unwrap().queue {
        b14_network_same_a(packet, &record);
    }
    drop(record);
    assert!(weak.upgrade().is_none());
    ctx.stopping.store(true, Ordering::Release);
    let (_, remaining) = process_peer_queue(
        peer,
        pending.remove(&delivery.peer_id).unwrap(),
        ctx.clone(),
    )
    .await;
    assert!(remaining.queue.is_empty() && remaining.deferred_losses.is_empty());
    assert_eq!(remaining.bytes, 0);
    assert!(raw_rx.try_recv().is_err());
    let loss = ctx.peers.outbound_loss_stats().await;
    let counter = loss.drops.get(REASON_OUTBOUND_WORKER_STOPPED).unwrap();
    assert_eq!((counter.packets, counter.bytes), (2, (2 * len) as u64));
    assert!(weak.upgrade().is_none());
}
