// C05 static candidate only. Every A comes from the real original minter/read.
// Legacy byte fillers exercise capacity/FIFO; none is a token/source factory.
use std::future::Future;
use std::pin::Pin;
use std::task::Poll;

use crate::overlay_requests::CanonicalOverlayRequest;
use crate::request_carriage::test_support::{mint_routed_request, RoutedRequestFixture};
use crate::request_carriage::{RawRequestDelivery, RequestBindingState, RequestInputEligibility};

fn b14_startup_legacy(
    template: &RawRequestDelivery,
    sequence: u16,
    bytes: usize,
) -> OutboundPacket {
    let mut packet = vec![0u8; bytes.max(2)];
    packet[..2].copy_from_slice(&sequence.to_be_bytes());
    OutboundPacket {
        room_authorization: None,
        trace: None,
        peer_id: template.peer_id.clone(),
        dst_ip: template.dst_ip.clone(),
        packet,
    }
}

fn b14_startup_same_a(packet: &RawRequestDelivery, record: &Arc<CanonicalOverlayRequest>) {
    let binding = packet.binding().expect("real read must stay tracked");
    assert_eq!(binding.state(), RequestBindingState::RoutedExact);
    let original = binding
        .token()
        .request()
        .expect("explicit original view is alive");
    assert!(Arc::ptr_eq(record, &original));
    assert_eq!(packet.packet, record.original_packet());
}

fn b14_startup_loss_sink(
    transport: &WireGuardTransport,
    peers: &Arc<PeerManager>,
) -> Arc<tokio::sync::Mutex<crate::peer::OutboundLossCounters>> {
    let sink = Arc::new(tokio::sync::Mutex::new(
        crate::peer::OutboundLossCounters::default(),
    ));
    transport.set_outbound_loss_sink(Some(sink.clone()));
    transport.set_outbound_loss_context(
        peers,
        crate::connection_timeline::ConnectionTimeline::new("b14-startup", 14),
    );
    sink
}

async fn b14_startup_poll_pending<F: Future + ?Sized>(mut future: Pin<&mut F>) {
    std::future::poll_fn(|cx| {
        assert!(
            future.as_mut().poll(cx).is_pending(),
            "original blocked operation completed early"
        );
        Poll::Ready(())
    })
    .await;
}

#[tokio::test]
async fn b14_c05_startup_256_overflow_retires_old_tracked_packet_and_keeps_fifo() {
    let RoutedRequestFixture {
        peers,
        record,
        delivery,
        ..
    } = mint_routed_request().await;
    let weak = Arc::downgrade(&record);
    let bytes = delivery.packet.len();
    let peer = delivery.peer_id.clone();
    let (transport, mut raw_rx) = WireGuardTransport::new_with_request_carriage();
    let sink = b14_startup_loss_sink(&transport, &peers);
    assert_eq!(MAX_PENDING_OUTBOUND_PER_PEER, 256);
    assert_eq!(PENDING_OUTBOUND_TTL, Duration::from_secs(8));
    transport
        .queue_pending_outbound(delivery.clone(), "b14 real startup")
        .await;
    for sequence in 1..256u16 {
        transport
            .queue_pending_outbound(b14_startup_legacy(&delivery, sequence, 2), "b14 capacity")
            .await;
    }
    {
        let pending = transport.pending_outbound.lock().await;
        let queue = pending.get(&peer).unwrap();
        assert_eq!(queue.len(), 256);
        b14_startup_same_a(&queue.front().unwrap().packet, &record);
    }
    transport
        .queue_pending_outbound(b14_startup_legacy(&delivery, 256, 2), "b14 overflow")
        .await;
    {
        let pending = transport.pending_outbound.lock().await;
        let queue = pending.get(&peer).unwrap();
        assert_eq!(queue.len(), 256);
        assert!(queue.iter().all(|entry| entry.packet.binding().is_none()));
        assert_eq!(queue.front().unwrap().packet.packet, 1u16.to_be_bytes());
        assert_eq!(queue.back().unwrap().packet.packet, 256u16.to_be_bytes());
    }
    let loss = sink.lock().await;
    let counter = loss.drops.get(REASON_SESSION_QUEUE_FULL).unwrap();
    assert_eq!((counter.packets, counter.bytes), (1, bytes as u64));
    drop(loss);
    tokio::time::timeout(
        Duration::from_secs(1),
        transport.flush_pending_outbound_for_peer(&peer),
    )
    .await
    .unwrap();
    for sequence in 1..=256u16 {
        let packet = raw_rx
            .try_recv()
            .expect("all old FIFO entries fit the original 1024 channel");
        assert_eq!(packet.packet, sequence.to_be_bytes());
        assert!(packet.binding().is_none());
    }
    assert!(raw_rx.try_recv().is_err());
    assert!(!transport.pending_outbound.lock().await.contains_key(&peer));
    drop(record);
    assert!(
        weak.upgrade().is_none(),
        "overflow/flush must not leave a canonical keeper"
    );
}

#[tokio::test]
async fn b14_c05_startup_original_8s_stale_enqueue_and_flush_drop_exact_a_bytes() {
    for expired_on_flush in [false, true] {
        let RoutedRequestFixture {
            peers,
            record,
            delivery,
            ..
        } = mint_routed_request().await;
        let weak = Arc::downgrade(&record);
        let peer = delivery.peer_id.clone();
        let bytes = delivery.packet.len();
        let (transport, mut raw_rx) = WireGuardTransport::new_with_request_carriage();
        let sink = b14_startup_loss_sink(&transport, &peers);
        transport
            .queue_pending_outbound(delivery.clone(), "b14 TTL")
            .await;
        {
            let mut pending = transport.pending_outbound.lock().await;
            let old = pending.get_mut(&peer).unwrap().front_mut().unwrap();
            b14_startup_same_a(&old.packet, &record);
            // Setup only: original queue timestamp, never canonical time/accepted.
            old.queued_at = Instant::now() - PENDING_OUTBOUND_TTL - Duration::from_millis(1);
        }
        drop(record);
        assert!(
            weak.upgrade().is_none(),
            "parked A must be Weak-only even before stale cleanup"
        );
        if expired_on_flush {
            tokio::time::timeout(
                Duration::from_secs(1),
                transport.flush_pending_outbound_for_peer(&peer),
            )
            .await
            .unwrap();
            assert!(raw_rx.try_recv().is_err());
        } else {
            transport
                .forward_raw_outbound(b14_startup_legacy(&delivery, 7, 3))
                .await
                .unwrap();
            let pending = transport.pending_outbound.lock().await;
            let queue = pending.get(&peer).unwrap();
            assert_eq!(queue.len(), 1);
            assert!(queue.front().unwrap().packet.binding().is_none());
            drop(pending);
            tokio::time::timeout(
                Duration::from_secs(1),
                transport.flush_pending_outbound_for_peer(&peer),
            )
            .await
            .unwrap();
            assert_eq!(raw_rx.try_recv().unwrap().packet, vec![0, 7, 0]);
        }
        assert!(!transport.pending_outbound.lock().await.contains_key(&peer));
        let loss = sink.lock().await;
        let counter = loss.drops.get(REASON_SESSION_QUEUE_STALE).unwrap();
        assert_eq!((counter.packets, counter.bytes), (1, bytes as u64));
    }
}

#[tokio::test]
async fn b14_c05_startup_removal_keeps_ingress_then_emit_and_never_retains_a() {
    let RoutedRequestFixture {
        peers,
        record,
        delivery,
        ..
    } = mint_routed_request().await;
    let weak = Arc::downgrade(&record);
    let bytes = delivery.packet.len();
    let peer = delivery.peer_id.clone();
    let (transport, mut raw_rx) = WireGuardTransport::new_with_request_carriage();
    let sink = b14_startup_loss_sink(&transport, &peers);
    transport
        .queue_pending_outbound(delivery.clone(), "b14 removal")
        .await;
    drop(record);
    assert!(weak.upgrade().is_none());
    {
        let pending = transport.pending_outbound.lock().await;
        let binding = pending
            .get(&peer)
            .unwrap()
            .front()
            .unwrap()
            .packet
            .binding()
            .unwrap();
        assert_eq!(
            binding.eligibility_at(Instant::now()),
            RequestInputEligibility::Retired
        );
    }
    let ingress = transport.outbound_ingress_lock(&peer).await;
    let emit = transport.outbound_emit_lock(&peer).await;
    let ingress_guard = ingress.lock().await;
    let emit_guard = emit.lock().await;
    let mut removal =
        Box::pin(transport.remove_session_with_reason(&peer, "b14 removal", "b14_c05"));
    b14_startup_poll_pending(removal.as_mut()).await;
    assert!(transport.pending_outbound.lock().await.contains_key(&peer));
    drop(ingress_guard);
    b14_startup_poll_pending(removal.as_mut()).await;
    assert!(
        ingress.try_lock().is_err(),
        "removal owns original ingress while waiting for emit"
    );
    assert!(transport.pending_outbound.lock().await.contains_key(&peer));
    drop(emit_guard);
    tokio::time::timeout(Duration::from_secs(1), removal)
        .await
        .unwrap();
    assert!(!transport.pending_outbound.lock().await.contains_key(&peer));
    assert!(raw_rx.try_recv().is_err());
    let loss = sink.lock().await;
    let counter = loss.drops.get(REASON_SESSION_QUEUE_REMOVED).unwrap();
    assert_eq!((counter.packets, counter.bytes), (1, bytes as u64));
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn b14_c05_startup_closed_original_channel_counts_failed_a_and_remaining_fifo() {
    let RoutedRequestFixture {
        peers,
        record,
        delivery,
        ..
    } = mint_routed_request().await;
    let weak = Arc::downgrade(&record);
    let bytes = delivery.packet.len();
    let peer = delivery.peer_id.clone();
    let (transport, raw_rx) = WireGuardTransport::new_with_request_carriage();
    let sink = b14_startup_loss_sink(&transport, &peers);
    transport
        .queue_pending_outbound(delivery.clone(), "b14 channel fail")
        .await;
    transport
        .queue_pending_outbound(b14_startup_legacy(&delivery, 1, 3), "b14 remaining")
        .await;
    transport
        .queue_pending_outbound(b14_startup_legacy(&delivery, 2, 9), "b14 remaining")
        .await;
    drop(record);
    assert!(weak.upgrade().is_none());
    drop(raw_rx);
    tokio::time::timeout(
        Duration::from_secs(1),
        transport.flush_pending_outbound_for_peer(&peer),
    )
    .await
    .unwrap();
    assert!(!transport.pending_outbound.lock().await.contains_key(&peer));
    let loss = sink.lock().await;
    let counter = loss.drops.get(REASON_SESSION_QUEUE_REMOVED).unwrap();
    assert_eq!((counter.packets, counter.bytes), (3, (bytes + 12) as u64));
    let event = loss.events.last().unwrap();
    assert_eq!(event.peer_id, peer);
    assert_eq!((event.packets, event.bytes), (3, (bytes + 12) as u64));
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn b14_c05_startup_1024_backpressure_flushes_same_a_before_live_raw() {
    let RoutedRequestFixture {
        peers,
        record,
        delivery,
        ..
    } = mint_routed_request().await;
    let peer = delivery.peer_id.clone();
    let (transport, mut raw_rx) = WireGuardTransport::new_with_request_carriage();
    let _sink = b14_startup_loss_sink(&transport, &peers);
    assert_eq!(transport.outbound_tx.max_capacity(), 1024);
    for _ in 0..1024 {
        transport
            .outbound_tx
            .send(b14_startup_legacy(&delivery, 0xffff, 2))
            .await
            .unwrap();
    }
    assert_eq!(raw_rx.len(), 1024);
    assert_eq!(transport.outbound_tx.capacity(), 0);
    let mut reserve = Box::pin(transport.outbound_tx.reserve());
    b14_startup_poll_pending(reserve.as_mut()).await;
    drop(reserve);
    transport
        .queue_pending_outbound(delivery.clone(), "b14 flush FIFO")
        .await;
    transport
        .queue_pending_outbound(b14_startup_legacy(&delivery, 2, 2), "b14 flush FIFO")
        .await;
    let mut flush = Box::pin(transport.flush_pending_outbound_for_peer(&peer));
    b14_startup_poll_pending(flush.as_mut()).await;
    assert!(!transport.pending_outbound.lock().await.contains_key(&peer));
    let ingress = transport.outbound_ingress_lock(&peer).await;
    assert!(
        ingress.try_lock().is_err(),
        "blocked flush keeps its original ingress turn"
    );
    let emit = transport.outbound_emit_lock(&peer).await;
    assert!(
        emit.try_lock().is_ok(),
        "raw handoff must not own an encryption counter lock"
    );
    let mut live = Box::pin(transport.forward_raw_outbound(b14_startup_legacy(&delivery, 3, 2)));
    b14_startup_poll_pending(live.as_mut()).await;
    for _ in 0..1024 {
        assert_eq!(raw_rx.try_recv().unwrap().packet, 0xffffu16.to_be_bytes());
    }
    tokio::time::timeout(Duration::from_secs(1), flush)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), live)
        .await
        .unwrap()
        .unwrap();
    let first = raw_rx.try_recv().unwrap();
    b14_startup_same_a(&first, &record);
    assert_eq!(raw_rx.try_recv().unwrap().packet, 2u16.to_be_bytes());
    assert_eq!(raw_rx.try_recv().unwrap().packet, 3u16.to_be_bytes());
    assert!(raw_rx.try_recv().is_err());
}
