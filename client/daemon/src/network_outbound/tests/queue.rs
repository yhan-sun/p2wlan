use super::super::test_support::*;
use super::*;
use crate::config::Config;

#[tokio::test(start_paused = true)]
async fn expired_managed_pending_delivery_deadline_drops_remaining_flush_batch() {
    let manager = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    manager
        .add_peer(&test_peer("peer-a", "127.0.0.1:41000".parse().unwrap()))
        .await;
    let peer_session_generation = manager
        .peer_session_generation_sync("peer-a")
        .expect("managed pending peer session");
    manager.mark_dplpmtud_capable_sync("peer-a", peer_session_generation);
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let timeline = ConnectionTimeline::new("node-a", 0);
    let mut queue = PeerPendingQueue::new();
    queue.wait_generation = Some(0);
    queue.delivery_deadline = Some(Instant::now() - Duration::from_millis(1));
    queue.enqueue(PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: vec![0x45, 0, 0, 20],
        trace: None,
    }));

    let (_peer_id, remaining) = flush_one_peer(
        "peer-a".to_string(),
        queue,
        transport,
        manager.clone(),
        true,
        Arc::new(RwLock::new(None)),
        Arc::new(RwLock::new(None)),
        true,
        timeline,
    )
    .await;

    assert!(remaining.queue.is_empty());
    let stats = manager.outbound_loss_stats().await;
    assert_eq!(
        stats
            .drops
            .get(REASON_OUTBOUND_DELIVERY_DEADLINE)
            .map(|counter| counter.packets),
        Some(1)
    );
}

#[tokio::test(start_paused = true)]
async fn peer_left_clears_managed_pending_fifo_without_flush_task_leak() {
    let manager = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    manager
        .add_peer(&test_peer("peer-a", "127.0.0.1:41001".parse().unwrap()))
        .await;
    let peer_session_generation = manager
        .peer_session_generation_sync("peer-a")
        .expect("managed pending peer session");
    manager.mark_dplpmtud_capable_sync("peer-a", peer_session_generation);

    let generation = manager.current_network_generation_sync();
    let mut queue = PeerPendingQueue::new();
    queue.wait_generation = Some(generation);
    queue.delivery_deadline = Some(Instant::now() + OUTBOUND_DELIVERY_DEADLINE);
    queue.enqueue(PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: Ipv4Packet::build_icmp_echo_request(
            "10.20.0.1".parse().unwrap(),
            "10.20.0.2".parse().unwrap(),
            1,
            1,
            b"managed-pending",
        ),
        trace: None,
    }));
    let mut pending = HashMap::from([("peer-a".to_string(), queue)]);
    let (transport, _outbound_rx) = WireGuardTransport::new();
    let udp_transport = Arc::new(RwLock::new(None));
    let relay_transport = Arc::new(RwLock::new(None));
    let timeline = ConnectionTimeline::new("node-a", 0);
    let mut flush_tasks = JoinSet::new();
    let mut flushing_peers = HashSet::new();

    manager.remove_peer("peer-a").await;
    maintenance(
        &transport,
        &manager,
        &mut pending,
        true,
        &udp_transport,
        &relay_transport,
        true,
        &timeline,
        &mut flush_tasks,
        &mut flushing_peers,
    )
    .await;

    assert!(pending.is_empty());
    assert!(flush_tasks.is_empty());
    assert!(flushing_peers.is_empty());
    let stats = manager.outbound_loss_stats().await;
    assert_eq!(
        stats
            .drops
            .get(REASON_OUTBOUND_PEER_OFFLINE)
            .map(|counter| counter.packets),
        Some(1)
    );
}

#[test]
fn managed_pending_fifo_obeys_packet_and_byte_caps() {
    let mut queue = PeerPendingQueue::new();
    let mut dropped = 0usize;
    for sequence in 0..300u16 {
        let (evicted, _) = queue.enqueue(PendingPacket::plain(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![sequence as u8; 65_535],
            trace: None,
        }));
        dropped = dropped.saturating_add(evicted.len());
    }
    assert!(dropped > 0);
    assert!(queue.queue.len() <= MAX_PENDING_PACKETS_PER_PEER);
    assert!(queue.bytes <= MAX_PENDING_BYTES_PER_PEER);
    let retained: Vec<u8> = queue
        .queue
        .iter()
        .map(|entry| entry.raw_packet()[0])
        .collect();
    assert!(retained
        .windows(2)
        .all(|window| { window[1] == window[0].wrapping_add(1) }));
}

#[tokio::test]
async fn completed_peer_flush_stays_ahead_of_live_fifo_arrivals() {
    fn packet(sequence: u8) -> OutboundPacket {
        OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![sequence],
            trace: None,
        }
    }

    let mut completed = PeerPendingQueue::new();
    completed.enqueue(PendingPacket::plain(packet(0)));
    completed.enqueue(PendingPacket::plain(packet(1)));

    let mut pending = HashMap::new();
    let mut live = PeerPendingQueue::new();
    live.enqueue(PendingPacket::plain(packet(2)));
    live.enqueue(PendingPacket::plain(packet(3)));
    pending.insert("peer-a".to_string(), live);

    let (peers, timeline) = merge_context();
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;

    let merged = pending.remove("peer-a").expect("merged queue");
    let sequences: Vec<u8> = merged
        .queue
        .into_iter()
        .map(|entry| match entry {
            PendingPacket::Plain { packet, .. } => packet.packet[0],
        })
        .collect();
    assert_eq!(sequences, vec![0, 1, 2, 3]);
}

#[test]
fn oversized_packet_cannot_exceed_the_queue_byte_bound_or_evict_valid_packets() {
    let mut queue = PeerPendingQueue::new();
    let normal = PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        dst_ip: "10.20.0.2".to_string(),
        peer_id: "peer".to_string(),
        packet: vec![1; 128],
        trace: None,
    });
    assert_eq!(queue.enqueue(normal).1, 0);
    let oversized_len = MAX_PENDING_BYTES_PER_PEER + 1;
    let oversized = PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        dst_ip: "10.20.0.2".to_string(),
        peer_id: "peer".to_string(),
        packet: vec![2; oversized_len],
        trace: None,
    });
    let (dropped, dropped_bytes) = queue.enqueue(oversized);
    assert_eq!(dropped.len(), 1);
    assert_eq!(dropped_bytes, oversized_len);
    assert_eq!(queue.bytes, 128);
    assert_eq!(queue.queue.len(), 1);
    assert_eq!(queue.pop_front().unwrap().raw_packet(), &[1; 128]);
    assert_eq!(queue.bytes, 0);
}
#[test]
fn empty_queue_rejects_a_single_oversized_packet() {
    let mut queue = PeerPendingQueue::new();
    let len = MAX_PENDING_BYTES_PER_PEER + 1;
    let (dropped, bytes) = queue.enqueue(PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        dst_ip: "10.20.0.2".to_string(),
        peer_id: "peer".to_string(),
        packet: vec![0; len],
        trace: None,
    }));
    assert_eq!(bytes, len);
    assert_eq!(dropped.len(), 1);
    assert!(queue.queue.is_empty());
    assert_eq!(queue.bytes, 0);
}

fn merge_context() -> (PeerManager, Arc<ConnectionTimeline>) {
    (
        PeerManager::new(Config::generate_default("https://ctrl.test", "net1").unwrap()),
        ConnectionTimeline::new("queue-merge", 0),
    )
}

fn merge_packet(sequence: u8, bytes: usize) -> PendingPacket {
    PendingPacket::plain(OutboundPacket {
        room_authorization: None,
        peer_id: "peer-a".to_string(),
        dst_ip: "10.20.0.2".to_string(),
        packet: vec![sequence; bytes],
        trace: None,
    })
}

fn merge_queue(generation: u64, sequence: u8, bytes: usize) -> PeerPendingQueue {
    let mut queue = PeerPendingQueue::new();
    queue.wait_generation = Some(generation);
    queue.enqueue(merge_packet(sequence, bytes));
    queue
}

#[tokio::test]
async fn completed_flush_merge_obeys_packet_limit() {
    let (peers, timeline) = merge_context();
    let mut completed = PeerPendingQueue::new();
    let mut newer = PeerPendingQueue::new();
    for _ in 0..MAX_PENDING_PACKETS_PER_PEER {
        completed.enqueue(merge_packet(1, 1));
        newer.enqueue(merge_packet(2, 1));
    }
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;
    let merged = &pending["peer-a"];
    assert_eq!(merged.queue.len(), MAX_PENDING_PACKETS_PER_PEER);
    assert_eq!(merged.bytes, MAX_PENDING_PACKETS_PER_PEER);
    assert!(merged.queue.iter().all(|packet| packet.raw_packet() == [2]));
    let losses = peers.outbound_loss_stats().await;
    let overflow = &losses.drops[REASON_OUTBOUND_QUEUE_FULL];
    assert_eq!(overflow.packets, MAX_PENDING_PACKETS_PER_PEER as u64);
    assert_eq!(overflow.bytes, MAX_PENDING_PACKETS_PER_PEER as u64);
}

#[tokio::test(start_paused = true)]
async fn completed_flush_merge_obeys_byte_limit_without_extending_deadlines() {
    let (peers, timeline) = merge_context();
    let len = MAX_PENDING_BYTES_PER_PEER / 2;
    let mut completed = merge_queue(0, 1, len);
    completed.enqueue(merge_packet(2, len));
    let deadline = Instant::now() + Duration::from_secs(1);
    completed.delivery_deadline = Some(deadline);
    completed.wait_deadline = Some(deadline);
    let mut newer = merge_queue(0, 3, len);
    newer.delivery_deadline = Some(deadline + Duration::from_secs(10));
    newer.wait_deadline = newer.delivery_deadline;
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;
    let merged = &pending["peer-a"];
    assert_eq!(merged.bytes, MAX_PENDING_BYTES_PER_PEER);
    assert_eq!(merged.queue.len(), 2);
    assert_eq!(merged.queue[0].raw_packet()[0], 2);
    assert_eq!(merged.queue[1].raw_packet()[0], 3);
    assert_eq!(merged.delivery_deadline, Some(deadline));
    assert_eq!(merged.wait_deadline, Some(deadline));
    let losses = peers.outbound_loss_stats().await;
    let overflow = &losses.drops[REASON_OUTBOUND_QUEUE_FULL];
    assert_eq!((overflow.packets, overflow.bytes), (1, len as u64));
}

#[tokio::test]
async fn stale_completed_flush_cannot_poison_current_generation_queue() {
    let (peers, timeline) = merge_context();
    let current = peers.current_network_generation_sync();
    let completed = merge_queue(current + 1, 1, 7);
    let newer = merge_queue(current, 2, 11);
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;
    let merged = &pending["peer-a"];
    assert_eq!(merged.wait_generation, Some(current));
    assert_eq!(merged.queue.len(), 1);
    assert_eq!(merged.bytes, 11);
    assert_eq!(merged.queue[0].raw_packet(), [2; 11]);
    let losses = peers.outbound_loss_stats().await;
    let stale = &losses.drops[REASON_OUTBOUND_GENERATION_CHANGED];
    assert_eq!((stale.packets, stale.bytes), (1, 7));
    assert!(!losses.drops.contains_key(REASON_OUTBOUND_QUEUE_FULL));
}

#[tokio::test]
async fn stale_pending_queue_cannot_contaminate_current_completed_flush() {
    let (peers, timeline) = merge_context();
    let current = peers.current_network_generation_sync();
    let completed = merge_queue(current, 1, 7);
    let newer = merge_queue(current + 1, 2, 11);
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;
    let merged = &pending["peer-a"];
    assert_eq!(merged.wait_generation, Some(current));
    assert_eq!(merged.bytes, 7);
    assert_eq!(merged.queue.len(), 1);
    assert_eq!(merged.queue[0].raw_packet(), [1; 7]);
    let losses = peers.outbound_loss_stats().await;
    let stale = &losses.drops[REASON_OUTBOUND_GENERATION_CHANGED];
    assert_eq!((stale.packets, stale.bytes), (1, 11));
}

#[tokio::test]
async fn stale_flush_without_live_arrivals_is_counted_and_not_reparked() {
    let (peers, timeline) = merge_context();
    let completed = merge_queue(peers.current_network_generation_sync() + 1, 1, 7);
    let mut pending = HashMap::new();
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;
    assert!(pending.is_empty());
    let losses = peers.outbound_loss_stats().await;
    let stale = &losses.drops[REASON_OUTBOUND_GENERATION_CHANGED];
    assert_eq!((stale.packets, stale.bytes), (1, 7));
}

#[tokio::test]
async fn empty_completed_flush_preserves_current_ingress_metadata() {
    let (peers, timeline) = merge_context();
    let mut newer = merge_queue(peers.current_network_generation_sync(), 2, 11);
    let deadline = Instant::now() + Duration::from_secs(3);
    newer.delivery_deadline = Some(deadline);
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        PeerPendingQueue::new(),
        &peers,
        &timeline,
    )
    .await;
    assert_eq!(pending["peer-a"].bytes, 11);
    assert_eq!(pending["peer-a"].delivery_deadline, Some(deadline));
    assert!(peers.outbound_loss_stats().await.drops.is_empty());
}

#[tokio::test]
async fn repeated_completed_flushes_stay_bounded_and_count_each_eviction_once() {
    let (peers, timeline) = merge_context();
    let mut completed = PeerPendingQueue::new();
    for _ in 0..MAX_PENDING_PACKETS_PER_PEER {
        completed.enqueue(merge_packet(0, 1));
    }
    let mut pending = HashMap::new();
    for sequence in 1..=8 {
        let mut newer = PeerPendingQueue::new();
        for _ in 0..MAX_PENDING_PACKETS_PER_PEER {
            newer.enqueue(merge_packet(sequence, 1));
        }
        pending.insert("peer-a".to_string(), newer);
        merge_completed_flush(
            &mut pending,
            "peer-a".to_string(),
            completed,
            &peers,
            &timeline,
        )
        .await;
        completed = pending.remove("peer-a").unwrap();
        assert_eq!(completed.queue.len(), MAX_PENDING_PACKETS_PER_PEER);
        assert_eq!(completed.bytes, MAX_PENDING_PACKETS_PER_PEER);
        assert!(completed
            .queue
            .iter()
            .all(|packet| packet.raw_packet() == [sequence]));
    }
    let losses = peers.outbound_loss_stats().await;
    let overflow = &losses.drops[REASON_OUTBOUND_QUEUE_FULL];
    assert_eq!(overflow.packets, 8 * MAX_PENDING_PACKETS_PER_PEER as u64);
    assert_eq!(overflow.bytes, 8 * MAX_PENDING_PACKETS_PER_PEER as u64);
}

#[tokio::test]
async fn generation_advance_during_flush_preserves_new_network_ingress() {
    let (peers, timeline) = merge_context();
    let old_generation = peers.current_network_generation_sync();
    let completed = merge_queue(old_generation, 1, 7);
    let generation = peers.advance_network_generation("queue-merge-test").await;
    assert!(generation > old_generation);
    let newer = merge_queue(generation, 2, 11);
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;
    assert_eq!(pending["peer-a"].wait_generation, Some(generation));
    assert_eq!(pending["peer-a"].bytes, 11);
    assert_eq!(pending["peer-a"].queue.len(), 1);
    assert_eq!(pending["peer-a"].queue[0].raw_packet(), [2; 11]);
    let losses = peers.outbound_loss_stats().await;
    let stale = &losses.drops[REASON_OUTBOUND_GENERATION_CHANGED];
    assert_eq!((stale.packets, stale.bytes), (1, 7));
}

#[tokio::test]
async fn both_stale_queues_are_discarded_and_counted_once() {
    let (peers, timeline) = merge_context();
    let generation = peers.current_network_generation_sync();
    let completed = merge_queue(generation, 1, 7);
    let newer = merge_queue(generation, 2, 11);
    peers.advance_network_generation("queue-merge-test").await;
    let mut pending = HashMap::from([("peer-a".to_string(), newer)]);
    merge_completed_flush(
        &mut pending,
        "peer-a".to_string(),
        completed,
        &peers,
        &timeline,
    )
    .await;
    assert!(pending.is_empty());
    let losses = peers.outbound_loss_stats().await;
    let stale = &losses.drops[REASON_OUTBOUND_GENERATION_CHANGED];
    assert_eq!((stale.packets, stale.bytes), (2, 18));
    assert!(!losses.drops.contains_key(REASON_OUTBOUND_QUEUE_FULL));
}
