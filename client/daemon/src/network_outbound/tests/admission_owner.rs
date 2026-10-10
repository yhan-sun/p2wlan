use super::super::super::test_support::test_peer;
use super::*;
use crate::config::Config;

async fn context() -> PeerWorkContext {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    peers
        .add_peer(&test_peer("peer-a", "127.0.0.1:41000".parse().unwrap()))
        .await;
    let (transport, _) = WireGuardTransport::new();
    PeerWorkContext {
        transport,
        peers,
        prefer_direct: true,
        udp_transport: Arc::new(RwLock::new(None)),
        relay_transport: Arc::new(RwLock::new(None)),
        startup_wait: RelayStartupWait {
            relay_expected: false,
            timeout: Some(Duration::from_secs(5)),
        },
        timeline: ConnectionTimeline::new("admission-owner", 0),
        stopping: Arc::new(AtomicBool::new(false)),
    }
}

fn packet(sequence: u8) -> OutboundPacket {
    OutboundPacket {
        peer_id: "peer-a".into(),
        room_authorization: None,
        dst_ip: "10.20.0.2".into(),
        packet: vec![sequence; 4],
        trace: None,
    }
}

#[tokio::test]
async fn canonical_connection_writers_complete_after_contention_release() {
    let ctx = context().await;
    let held = ctx.peers.hold_connections_writer_for_test().await;
    let mut first = Box::pin(async {
        let (_epoch, _connections) = ctx.peers.lock_epoch_and_connections_write().await;
    });
    let mut second = Box::pin(async {
        let (_epoch, _connections) = ctx.peers.lock_epoch_and_connections_write().await;
    });
    // Both real owner helpers must reach the fair connection-lock queue
    // before releasing the writer. A sleep would not establish that order.
    assert!(matches!(
        futures_util::poll!(first.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(matches!(
        futures_util::poll!(second.as_mut()),
        std::task::Poll::Pending
    ));
    drop(held);
    timeout(Duration::from_millis(100), async {
        tokio::join!(first, second);
    })
    .await
    .expect(
        "queued writers must retain an acquired connection permit long enough to make progress",
    );
}

#[tokio::test]
async fn canonical_connection_reader_and_writer_complete_after_contention_release() {
    let ctx = context().await;
    let held = ctx.peers.hold_connections_writer_for_test().await;
    let mut reader = Box::pin(async {
        let (_epoch, _connections) = ctx.peers.lock_epoch_and_connections_read().await;
    });
    let mut writer = Box::pin(async {
        let (_epoch, _connections) = ctx.peers.lock_epoch_and_connections_write().await;
    });
    assert!(matches!(
        futures_util::poll!(reader.as_mut()),
        std::task::Poll::Pending
    ));
    assert!(matches!(
        futures_util::poll!(writer.as_mut()),
        std::task::Poll::Pending
    ));
    drop(held);
    timeout(Duration::from_millis(100), async {
        tokio::join!(reader, writer);
    })
    .await
    .expect("queued reader/writer must not repeatedly surrender their granted connection permits");
}

#[tokio::test]
async fn live_ingress_and_empty_task_completion_keep_the_original_earliest_deadline() {
    let ctx = context().await;
    let generation = ctx.peers.current_network_generation_sync();
    let original = Instant::now() + Duration::from_millis(500);
    let started = Instant::now();
    let mut old = PeerPendingQueue::new();
    old.wait_generation = Some(generation);
    old.wait_started = Some(started);
    old.wait_deadline = Some(original);
    old.delivery_deadline = Some(original);
    let mut pending = HashMap::from([("peer-a".to_string(), old.timing_shell())]);
    let (probe_tx, _) = watch::channel(0);
    append_ingress(packet(2), &mut pending, &ctx, &mut 0, &probe_tx);
    assert_eq!(pending["peer-a"].delivery_deadline, Some(original));
    // Even an emptied task must carry timing until all arrivals queued behind
    // it have completed. A later local timestamp cannot renew that batch.
    pending.get_mut("peer-a").unwrap().delivery_deadline = Some(original + Duration::from_secs(1));
    merge_peer_work(&mut pending, "peer-a".into(), old, &ctx);
    let merged = &pending["peer-a"];
    assert_eq!(merged.delivery_deadline, Some(original));
    assert_eq!(merged.wait_deadline, Some(original));
    assert_eq!(merged.wait_started, Some(started));
    assert_eq!(merged.queue.front().unwrap().raw_packet(), packet(2).packet);
}

#[tokio::test]
async fn stale_task_completion_cannot_inherit_new_generation_or_its_deadline() {
    let ctx = context().await;
    let old_generation = ctx.peers.current_network_generation_sync();
    let mut completed = PeerPendingQueue::new();
    completed.wait_generation = Some(old_generation);
    completed.delivery_deadline = Some(Instant::now() - Duration::from_secs(1));
    completed.enqueue(PendingPacket::plain(packet(1)));
    let generation = ctx
        .peers
        .advance_network_generation("admission-owner-test")
        .await;
    let mut pending = HashMap::new();
    let (probe_tx, _) = watch::channel(0);
    append_ingress(packet(2), &mut pending, &ctx, &mut 0, &probe_tx);
    let deadline = pending["peer-a"].wait_deadline;
    merge_peer_work(&mut pending, "peer-a".into(), completed, &ctx);
    let merged = pending.get_mut("peer-a").unwrap();
    assert_eq!(merged.wait_generation, Some(generation));
    assert_eq!(merged.wait_deadline, deadline);
    assert!(merged.delivery_deadline.is_none());
    assert_eq!(merged.queue.len(), 1);
    assert_eq!(merged.queue[0].raw_packet(), packet(2).packet);
    report_deferred_losses(merged, "peer-a", &ctx).await;
    assert_eq!(
        ctx.peers.outbound_loss_stats().await.drops[REASON_OUTBOUND_GENERATION_CHANGED].packets,
        1
    );
}

#[tokio::test]
async fn admission_contention_cannot_renew_an_expired_startup_window() {
    let ctx = context().await;
    let mut queue = PeerPendingQueue::new();
    queue.wait_generation = Some(ctx.peers.current_network_generation_sync());
    queue.wait_started = Some(Instant::now() - Duration::from_secs(6));
    queue.wait_deadline = Some(Instant::now() - Duration::from_secs(1));
    queue.enqueue(PendingPacket::plain(packet(1)));
    let held = ctx.peers.hold_connections_writer_for_test().await;
    let (_, remaining) = process_peer_queue("peer-a".into(), queue, ctx.clone()).await;
    assert!(!remaining.has_work());
    assert_eq!(
        ctx.peers.outbound_loss_stats().await.drops[REASON_RELAY_STARTUP_WAIT_EXPIRED].packets,
        1
    );
    drop(held);
}

#[tokio::test]
async fn saturated_loss_metadata_keeps_exact_reason_totals_and_never_recounts_a_committed_phase() {
    let ctx = context().await;
    let mut queue = PeerPendingQueue::new();
    // One aggregate was committed before its detailed event became blocked.
    ctx.peers
        .record_outbound_drop(REASON_OUTBOUND_QUEUE_FULL, 3, 21)
        .await;
    queue.deferred_losses.push_back(DeferredLoss {
        generation: Some(100),
        reason: QueueLossReason::QueueFull,
        packets: 3,
        bytes: 21,
        counter_complete: true,
    });
    for generation in 0..64 {
        defer_loss(
            &mut queue,
            "peer-a",
            Some(generation),
            QueueLossReason::QueueFull,
            1,
            7,
            &ctx,
        );
        assert!(queue.deferred_losses.len() <= MAX_DEFERRED_LOSS_RECORDS);
    }
    assert_eq!(
        queue
            .deferred_losses
            .iter()
            .map(|loss| loss.packets)
            .sum::<usize>(),
        67
    );
    assert!(ctx
        .timeline
        .snapshot()
        .events
        .iter()
        .any(|event| event.event == "outbound_loss_attribution_compacted"));
    report_deferred_losses(&mut queue, "peer-a", &ctx).await;
    assert!(queue.deferred_losses.is_empty());
    let stats = ctx.peers.outbound_loss_stats().await;
    let total = &stats.drops[REASON_OUTBOUND_QUEUE_FULL];
    assert_eq!((total.packets, total.bytes), (67, 469));
    assert!(ctx
        .timeline
        .snapshot()
        .events
        .iter()
        .any(|event| event.event == "outbound_loss_attribution_omitted"));
}

#[tokio::test(start_paused = true)]
async fn permanent_accounting_contention_releases_the_real_actor_report_owner() {
    let ctx = context().await;
    let sink = Arc::new(tokio::sync::Mutex::new(
        crate::peer::OutboundLossCounters::default(),
    ));
    ctx.peers.set_outbound_loss_sink(sink.clone());
    ctx.transport.set_outbound_loss_sink(Some(sink.clone()));
    let held = sink.lock().await;
    let (tx, rx) = mpsc::channel(2);
    let (relay_tx, relay_rx) = watch::channel(false);
    let (probe_tx, _) = watch::channel(0);
    let (hook, mut events) = admission_test_hooks::WorkerHook::new(HashMap::new(), None);
    let mut completions = hook.completion_receiver();
    let worker = tokio::spawn(admission_test_hooks::WORKER.scope(
        hook,
        run_network_outbound(
            rx,
            ctx.transport.clone(),
            ctx.peers.clone(),
            false,
            ctx.udp_transport.clone(),
            ctx.relay_transport.clone(),
            relay_rx,
            ctx.startup_wait,
            probe_tx,
            ctx.timeline.clone(),
        ),
    ));
    assert_eq!(events.recv().await, Some(None));
    for sequence in 1..=2 {
        let mut oversized = packet(sequence);
        oversized
            .packet
            .resize(MAX_PENDING_BYTES_PER_PEER + 1, sequence);
        tx.send(oversized).await.unwrap();
        let permits = timeout(Duration::from_secs(1), tx.reserve_many(2))
            .await
            .unwrap()
            .unwrap();
        drop(permits);
    }
    tokio::time::advance(OUTBOUND_SEND_TIMEOUT).await;
    timeout(Duration::from_millis(100), async {
        loop {
            let completion = completions.recv().await.unwrap();
            if completion.actor_packets == 0
                && completion.loss_records == 0
                && completion.active_tasks == 0
            {
                break;
            }
        }
    })
    .await
    .expect("fixed report deadline must release the owner despite the permanently held sink");
    assert!(
        held.drops.is_empty(),
        "blocked accounting must never be advertised as committed"
    );
    assert!(ctx
        .timeline
        .snapshot()
        .events
        .iter()
        .any(|event| event.event == "outbound_accounting_incomplete"));
    drop(tx);
    timeout(Duration::from_millis(100), worker)
        .await
        .unwrap()
        .unwrap();
    drop(relay_tx);
    drop(held);
}
