// Canonical state controls composed with genuine minter, Noise/WG and UDP.
// Atomic phase fault injection below is synthetic; full facts are always real.
use super::*;
use crate::request_carriage::test_support::{mint_routed_request, RoutedRequestFixture, PEER};
use crate::request_carriage::EncryptedRequestDelivery;
use crate::transport::WireGuardTransport;
use crate::udp::{UdpSendCapture, UdpTransport};
use std::sync::Arc;
use std::time::Duration;

fn sessions() -> (
    p2pnet_wireguard::TransportSession,
    p2pnet_wireguard::TransportSession,
) {
    let a = p2pnet_crypto::NodeIdentity::generate();
    let b = p2pnet_crypto::NodeIdentity::generate();
    let mut initiator = p2pnet_wireguard::HandshakeInitiator::new(a, b.public_key(), None);
    let mut responder = p2pnet_wireguard::HandshakeResponder::new(b, None);
    let initiation = initiator.create_initiation().unwrap();
    let (response, bk) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let ak = initiator.consume_response(&response).unwrap();
    (
        p2pnet_wireguard::TransportSession::new(ak),
        p2pnet_wireguard::TransportSession::new(bk),
    )
}
async fn setup() -> (
    RoutedRequestFixture,
    WireGuardTransport,
    UdpTransport,
    tokio::net::UdpSocket,
) {
    let f = mint_routed_request().await;
    let (session, _remote) = sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    transport
        .replace_session_for_lifecycle(PEER, session, f.record.expected_target_lifecycle().unwrap())
        .await;
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), f.peers.clone())
        .await
        .unwrap();
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (f, transport, udp, receiver)
}
async fn encrypted(
    f: &RoutedRequestFixture,
    transport: &WireGuardTransport,
) -> (EncryptedRequestDelivery, PreparedPhysicalPublication) {
    let emit = transport.acquire_outbound_emit_guard(PEER).await;
    let gate = f.peers.network_epoch_gate();
    let epoch = gate.lock().await;
    let packet = transport
        .encrypt_request_with_emit_guard(f.delivery.clone())
        .await
        .unwrap()
        .unwrap();
    let prepared = packet
        .prepare_physical_publication(
            &f.peers,
            transport,
            f.peers.current_network_generation_sync(),
        )
        .unwrap();
    drop(epoch);
    drop(emit);
    (packet, prepared)
}
async fn actual_fact(
    udp: &UdpTransport,
    receiver: &tokio::net::UdpSocket,
    packet: &EncryptedRequestDelivery,
) -> UdpFullSendFact {
    let mut capture = UdpSendCapture::new();
    udp.send_packet_to_with_origin(packet, receiver.local_addr().unwrap(), Some(&mut capture))
        .await
        .unwrap();
    let mut bytes = [0u8; 2048];
    let (n, _) = receiver.recv_from(&mut bytes).await.unwrap();
    assert_eq!(&bytes[..n], packet.wire_bytes.as_slice());
    capture
        .take()
        .expect("only actual full poll_send_to can mint this fact")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b17_canonical_competing_producers_external_cancel_stale_id_and_new_attempt() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, transport, udp, receiver) = setup().await;
        let (packet, a) = encrypted(&f, &transport).await;
        let (other_packet, b) = encrypted(&f, &transport).await;
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let right_barrier = barrier.clone();
        let (left, right) = tokio::join!(
            tokio::spawn(async move {
                barrier.wait().await;
                (packet, a.open())
            }),
            tokio::spawn(async move {
                right_barrier.wait().await;
                (other_packet, b.open())
            }),
        );
        let (left, right) = (left.unwrap(), right.unwrap());
        let (packet, mut winner) = match (left, right) {
            (
                (packet, Ok(winner)),
                (_, Err(PublicationFailure::Occupied | PublicationFailure::Contended)),
            )
            | (
                (_, Err(PublicationFailure::Occupied | PublicationFailure::Contended)),
                (packet, Ok(winner)),
            ) => (packet, winner),
            _ => panic!("exactly one matching Open producer must win"),
        };
        let old_id = winner.id;
        assert_eq!(
            Arc::strong_count(&f.record),
            1,
            "attempt metadata is not a keeper"
        );
        assert!(f
            .record
            .physical_publication
            .terminal(old_id, PhysicalPublicationState::CancelledOrUncertain));
        // The physical UDP succeeds after a distinct canceller won. It cannot
        // promote the canonical state or overwrite the uncertain terminal.
        let fact = actual_fact(&udp, &receiver, &packet).await;
        assert!(matches!(
            winner.publish(fact),
            Err(PublicationFailure::Contended)
        ));
        assert!(f.record.physical_publication.record().is_none());
        let (fresh, prepared) = encrypted(&f, &transport).await;
        assert!(matches!(prepared.open(), Err(PublicationFailure::Occupied)));
        // Actual later UDP can complete, but uncertain canonical metadata is terminal.
        let _later = actual_fact(&udp, &receiver, &fresh).await;
        assert_eq!(
            f.record.physical_publication.state(),
            PhysicalPublicationState::CancelledOrUncertain
        );
        assert!(f.record.physical_publication.record().is_none());
        let (g, gt, gu, gr) = setup().await;
        let (_, first) = encrypted(&g, &gt).await;
        let mut known = first.open().unwrap();
        let old_id = known.id;
        known.finish(true);
        let (fresh, second) = encrypted(&g, &gt).await;
        let mut next = second.open().unwrap();
        assert!(next.id > old_id);
        assert!(!g
            .record
            .physical_publication
            .terminal(old_id, PhysicalPublicationState::DefinitelyNotHanded));
        next.publish(actual_fact(&gu, &gr, &fresh).await).unwrap();
        assert_eq!(
            g.record.physical_publication.state(),
            PhysicalPublicationState::Recorded
        );
        assert_eq!(
            g.record.physical_publication.record().unwrap().attempt_id(),
            next.id
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b17_canonical_exhaustion_and_once_lock_set_error_are_typed_terminal() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, transport, udp, receiver) = setup().await;
        let (packet, prepared) = encrypted(&f, &transport).await;
        let mut publisher = prepared.open().unwrap();
        publisher
            .publish(actual_fact(&udp, &receiver, &packet).await)
            .unwrap();
        // Synthetic state corruption only: the cell contains a prior REAL fact.
        f.record.physical_publication.phase.store(
            packed(1, PhysicalPublicationState::DefinitelyNotHanded),
            Ordering::Release,
        );
        let (fresh, prepared) = encrypted(&f, &transport).await;
        let mut faulted = prepared.open().unwrap();
        assert!(matches!(
            faulted.publish(actual_fact(&udp, &receiver, &fresh).await),
            Err(PublicationFailure::MetadataFailed)
        ));
        assert_eq!(
            f.record.physical_publication.state(),
            PhysicalPublicationState::MetadataFailed
        );
        assert!(f.record.physical_publication.record().is_none());
        assert!(matches!(
            encrypted(&f, &transport).await.1.open(),
            Err(PublicationFailure::Occupied)
        ));
        let (g, gt, _gu, _gr) = setup().await;
        g.record.physical_publication.phase.store(
            packed(ID_MAX, PhysicalPublicationState::DefinitelyNotHanded),
            Ordering::Release,
        );
        assert!(matches!(
            encrypted(&g, &gt).await.1.open(),
            Err(PublicationFailure::Exhausted)
        ));
        assert_eq!(
            g.record.physical_publication.state(),
            PhysicalPublicationState::Exhausted
        );
        assert_eq!(
            g.record.physical_publication.phase.load(Ordering::Acquire) >> 3,
            ID_MAX
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b17_canonical_record_is_single_get_dynamic_ttl_and_weak_retirement() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let (f, transport, udp, receiver) = setup().await;
        let (packet, prepared) = encrypted(&f, &transport).await;
        let mut publisher = prepared.open().unwrap();
        assert!(
            f.record.physical_publication.record().is_none(),
            "Open reader never waits"
        );
        publisher
            .publish(actual_fact(&udp, &receiver, &packet).await)
            .unwrap();
        let record = f.record.physical_publication.record().unwrap();
        assert_eq!(
            record.qualify(&f.record, Instant::now()),
            PhysicalInputQualification::UnknownUdpPublication
        );
        assert_eq!(
            record.qualify(
                &f.record,
                f.record.sent_at + crate::OVERLAY_NONCE_TTL + Duration::from_nanos(1)
            ),
            PhysicalInputQualification::Expired
        );
        assert_eq!(Arc::strong_count(&f.record), 1);
        drop(udp);
        assert_eq!(
            record.qualify(&f.record, Instant::now()),
            PhysicalInputQualification::Retired
        );
        assert!(std::ptr::eq(
            record,
            f.record.physical_publication.record().unwrap()
        ));
        let weak = Arc::downgrade(&f.record);
        drop(packet);
        drop(f);
        assert!(
            weak.upgrade().is_none(),
            "no publisher/fact keeps the canonical alive"
        );
    })
    .await
    .unwrap();
}
