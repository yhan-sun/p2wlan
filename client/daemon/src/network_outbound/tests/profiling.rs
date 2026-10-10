use super::*;
use crate::config::Config;
use crate::dataplane::DataplaneTxTrace;

fn packet(sequence: u8, bytes: usize, sampled: Option<bool>) -> OutboundPacket {
    let now = Instant::now();
    OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: vec![sequence; bytes],
        trace: sampled.map(|sampled| DataplaneTxTrace {
            sampled,
            tun_read_started: now,
            tun_read_completed: now,
            route_ready: None,
            dataplane_queue_send_started: None,
            transport_queue_dequeued: None,
            transport_queue_send_started: None,
            network_queue_dequeued: None,
        }),
    }
}

fn pending_packet(sequence: u8, queued_at: Instant) -> PendingPacket {
    PendingPacket::Plain {
        packet: packet(sequence, 4, None),
        direct_budget_reroutes: 0,
        local_backpressure_retries: 0,
        pending_residence: Some(PendingQueueResidence::start_at(queued_at)),
    }
}

fn context() -> (PeerManager, Arc<ConnectionTimeline>) {
    (
        PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap()),
        ConnectionTimeline::new("pending-profile", 0),
    )
}

#[test]
fn b03_pending_context_is_present_only_for_sampled_packets_and_taken_once() {
    for sampled in [None, Some(false)] {
        let mut pending = PendingPacket::plain(packet(1, 4, sampled));
        assert!(pending.take_pending_residence().is_none());
    }
    let mut pending = PendingPacket::plain(packet(1, 4, Some(true)));
    assert!(pending.take_pending_residence().is_some());
    assert!(pending.take_pending_residence().is_none());
}

#[tokio::test]
async fn b03_completed_merge_preserves_each_pending_interval_and_fifo() {
    let start = Instant::now();
    let later = start + Duration::from_micros(10);
    let mut completed = PeerPendingQueue::new();
    completed.enqueue(pending_packet(1, start));
    let mut newer = PeerPendingQueue::new();
    newer.enqueue(pending_packet(2, later));
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    let (peers, timeline) = context();

    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;

    let mut merged = pending.remove("peer-a").unwrap();
    for (sequence, queued_at) in [(1, start), (2, later)] {
        let mut packet = merged.pop_front().unwrap();
        assert_eq!(packet.raw_packet(), &[sequence; 4]);
        assert_eq!(
            packet.take_pending_residence(),
            Some(PendingQueueResidence::start_at(queued_at))
        );
    }
    assert_eq!(merged.bytes, 0);
}

#[tokio::test]
async fn b03_retry_repark_preserves_prior_wait_and_stays_at_fifo_front() {
    let start = Instant::now();
    let mut residence = PendingQueueResidence::start_at(start);
    residence.pause_at(start + Duration::from_micros(7));
    let mut queue = PeerPendingQueue::new();
    queue.enqueue(pending_packet(2, start));
    let (peers, timeline) = context();
    let (transport, _) = WireGuardTransport::new();

    record_retry_and_repark(
        &transport,
        &peers,
        "peer-a",
        &mut queue,
        packet(1, 4, None),
        1,
        3,
        Some(residence),
        REASON_DIRECT_LOCAL_BACKPRESSURE,
        "local socket busy".to_string(),
        &timeline,
    )
    .await;

    let mut front = queue.pop_front().unwrap();
    assert_eq!(front.raw_packet(), &[1; 4]);
    let PendingPacket::Plain {
        direct_budget_reroutes,
        local_backpressure_retries,
        ..
    } = &front;
    assert_eq!(
        (*direct_budget_reroutes, *local_backpressure_retries),
        (1, 3)
    );
    let mut residence = front
        .take_pending_residence()
        .expect("retry context retained");
    // Earlier than resume: isolate the previously accumulated interval.
    residence.pause_at(start);
    assert_eq!(residence.finish(), Duration::from_micros(7));
    assert_eq!(queue.pop_front().unwrap().raw_packet(), &[2; 4]);
    assert_eq!(queue.bytes, 0);
}

#[tokio::test]
async fn b03_unusable_flush_path_keeps_pending_interval_running() {
    let start = Instant::now();
    let mut queue = PeerPendingQueue::new();
    queue.enqueue(pending_packet(1, start));
    let (peers, timeline) = context();
    let (transport, _) = WireGuardTransport::new();

    let (_, mut remaining) = flush_one_peer(
        "peer-a".to_string(),
        queue,
        transport,
        Arc::new(peers),
        true,
        Arc::new(RwLock::new(None)),
        Arc::new(RwLock::new(None)),
        true,
        timeline,
    )
    .await;

    let mut packet = remaining.pop_front().unwrap();
    assert_eq!(
        packet.take_pending_residence(),
        Some(PendingQueueResidence::start_at(start))
    );
    assert_eq!(remaining.bytes, 0);
}

#[test]
fn b03_overflow_preserves_survivor_context_and_detaches_dropped_sample_once() {
    let start = Instant::now();
    let mut queue = PeerPendingQueue::new();
    for _ in 0..MAX_PENDING_PACKETS_PER_PEER {
        queue.enqueue(pending_packet(1, start));
    }
    let (mut dropped, bytes) = queue.enqueue(pending_packet(2, start));
    assert_eq!(bytes, 4);
    assert_eq!(dropped.len(), 1);
    assert_eq!(
        dropped[0].take_pending_residence(),
        Some(PendingQueueResidence::start_at(start))
    );
    assert!(dropped[0].take_pending_residence().is_none());
    assert_eq!(
        queue.pop_front().unwrap().take_pending_residence(),
        Some(PendingQueueResidence::start_at(start))
    );
}

#[tokio::test]
async fn b03_resource_snapshot_excludes_task_owned_queues_and_channel_bytes() {
    let start = Instant::now();
    let mut actor_queue = PeerPendingQueue::new();
    actor_queue.enqueue(pending_packet(1, start));
    actor_queue.enqueue(pending_packet(2, start));
    let mut task_owned = PeerPendingQueue::new();
    for _ in 0..5 {
        task_owned.enqueue(pending_packet(3, start));
    }
    let mut pending = HashMap::from([
        ("actor-peer".to_string(), actor_queue),
        ("task-peer".to_string(), task_owned),
    ]);
    let _task_owned = pending.remove("task-peer").unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    tx.send(packet(4, 1500, None)).await.unwrap();
    tx.send(packet(5, 900, None)).await.unwrap();
    let _active_packet = rx.recv().await.unwrap();

    let snapshot = resource_snapshot(rx.len(), &pending, 3);
    assert_eq!(
        snapshot,
        NetworkOutboundResourceSnapshot {
            channel_packets: 1,
            actor_pending_packets: 2,
            actor_pending_bytes: 8,
            active_flush_tasks: 3,
        }
    );
}
