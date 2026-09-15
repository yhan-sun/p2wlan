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

#[test]
fn completed_peer_flush_stays_ahead_of_live_fifo_arrivals() {
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

    merge_completed_flush(&mut pending, "peer-a".to_string(), completed);

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
