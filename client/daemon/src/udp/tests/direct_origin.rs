//! Actual reader and original publication controls; no final ACK credit.
use super::*;
use crate::transport::InboundEvidenceFeed;
use crate::udp::DirectOriginFailure;
use tokio::sync::{watch, RwLock};

#[derive(Default)]
struct OriginalReaders(Vec<tokio::task::AbortHandle>);
impl Drop for OriginalReaders {
    fn drop(&mut self) {
        for reader in &self.0 {
            reader.abort();
        }
    }
}

async fn read_one(
    udp: &UdpTransport,
    index: usize,
    socket: Arc<UdpSocket>,
    wire: &[u8],
) -> ReceivedEncryptedPacket {
    let sender = UdpSocket::bind(if socket.local_addr().unwrap().is_ipv6() {
        "[::1]:0"
    } else {
        "127.0.0.1:0"
    })
    .await
    .unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    let read = udp.run_inbound_socket(index, socket.clone(), tx);
    tokio::pin!(read);
    let delivered = async {
        sender
            .send_to(wire, socket.local_addr().unwrap())
            .await
            .unwrap();
        rx.recv().await.unwrap()
    };
    tokio::select! { packet = delivered => packet, _ = &mut read => panic!("original reader ended") }
}

#[tokio::test]
async fn b26_actual_fixed_ipv6_reader_weak_origin_without_capture() {
    timeout(Duration::from_secs(2), async {
        let peers = peer_manager();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        udp.set_inbound_publication_owner(2601);
        assert!(udp.rx_business_capture.is_none());
        let weak_registry = Arc::downgrade(&udp.socket_state);
        let weak_socket = Arc::downgrade(&udp.socket);
        let (mut remote, _) = establish_sessions();
        let wire = remote.encrypt_to_bytes(&[0x45; 48]).unwrap();
        let mut origins = Vec::new();
        let mut sockets = vec![(0, udp.socket.clone())];
        // Bind explicitly: failure is a failed native IPv6 control, not a skip.
        let mut udp = udp;
        if udp.ipv6_socket.is_none() {
            udp.ipv6_socket = Some(Arc::new(UdpSocket::bind("[::1]:0").await.unwrap()));
        }
        sockets.push((IPV6_SOCKET_INDEX, udp.ipv6_socket.clone().unwrap()));
        for (index, socket) in sockets {
            let packet = read_one(&udp, index, socket.clone(), &wire).await;
            assert!(packet.physical_ingress.is_none());
            let original = packet.original_udp_read.as_ref().unwrap();
            assert!(original.belongs_to_socket(&socket));
            assert!(original.belongs_to_transport(&udp));
            assert_eq!(original.socket_index(), index);
            assert_eq!(original.publication_owner(), 2601);
            assert_eq!(
                original.network_generation(),
                peers.current_network_generation_sync()
            );
            assert_eq!(Some(original.received_at()), packet.udp_received);
            assert_eq!(
                Some(original.queue_send_started()),
                packet.transport_queue_send_started
            );
            let socket_count = Arc::strong_count(&socket);
            let registry_count = Arc::strong_count(&udp.socket_state);
            origins.push(original.clone());
            assert_eq!(Arc::strong_count(&socket), socket_count);
            assert_eq!(Arc::strong_count(&udp.socket_state), registry_count);
            assert!(udp
                .try_original_direct_publication_guard(
                    "origin-peer",
                    peers.current_network_generation_sync(),
                    Some(original),
                    None
                )
                .is_ok());
        }
        let replacement = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        replacement.set_inbound_publication_owner(2601);
        assert!(matches!(
            replacement.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&origins[0]),
                None
            ),
            Err(DirectOriginFailure::Stale)
        ));
        assert!(udp.clear_inbound_publication_owner_if_matches(2601));
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&origins[0]),
                None
            ),
            Err(DirectOriginFailure::Stale)
        ));
        drop(udp);
        assert!(
            weak_socket.upgrade().is_none(),
            "source must not keep original socket alive"
        );
        assert!(
            weak_registry.upgrade().is_none(),
            "source must not keep registry alive"
        );
        assert_eq!(
            origins[0].publication_owner(),
            2601,
            "history was not relabeled"
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b26_actual_reader_source_survives_noise_and_overlay_carriage() {
    timeout(Duration::from_secs(2), async {
        let peers = peer_manager();
        peers.add_peer(&peer("origin-peer", "10.20.0.2", None)).await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone()).await.unwrap();
        udp.set_inbound_publication_owner(2602);
        let (mut remote, local) = establish_sessions();
        let (wg, _outbound) = WireGuardTransport::new();
        wg.add_session("origin-peer", local).await;
        let payload = crate::build_overlay_payload(crate::OVERLAY_DIRECTION_REQUEST, 2602, 1);
        let plaintext = crate::build_udp_overlay_packet("10.20.0.2", "10.20.0.1", 32002, 32001, &payload).unwrap();
        let wire = remote.encrypt_to_bytes(&plaintext).unwrap();
        let original = read_one(&udp, 0, udp.socket.clone(), &wire).await;
        let captured = original.original_udp_read.as_ref().unwrap().clone();
        let (tx, rx) = mpsc::channel(4);
        tx.send(original).await.unwrap();
        let (inbound_tx, mut inbound_rx) = mpsc::channel(4);
        let (overlay_tx, mut overlay_rx) = mpsc::channel(128);
        let (_publication, updates) = watch::channel(Some(udp.clone()));
        let worker = wg.run_inbound_with_peers_live_udp_and_relay(rx, inbound_tx, Some(peers), updates, Some(InboundEvidenceFeed {
            relay_transport: Arc::new(RwLock::new(None)), timeline: None, overlay_ingress_tx: Some(overlay_tx),
        }));
        tokio::pin!(worker);
        let observe = async {
            assert_eq!(inbound_rx.recv().await.unwrap().packet, plaintext);
            let (event, source) = overlay_rx.recv().await.unwrap().into_parts();
            assert_eq!(event.packet, plaintext);
            let source = source.unwrap();
            assert!(source.session().belongs_to(&wg));
            let origin = source.original_udp_read().unwrap();
            assert!(origin.belongs_to_socket(&udp.socket));
            assert_eq!(origin.received_at(), captured.received_at());
            assert_eq!(origin.queue_send_started(), captured.queue_send_started());
            assert!(source.original_relay_read().is_none());
            let (_, legacy) = crate::transport::OverlayIngressDelivery::from(event).into_parts();
            assert!(legacy.is_none());
        };
        tokio::select! { () = observe => {}, _ = &mut worker => panic!("original decrypt worker ended") }
        // Both futures are dropped locally: no spawned task or socket keeper.
    }).await.unwrap();
}

#[tokio::test]
async fn b26_actual_dynamic_same_index_replacement_rejects_live_old_source() {
    timeout(Duration::from_secs(2), async {
        let peers = peer_manager();
        peers
            .add_peer(&peer("origin-peer", "10.20.0.2", None))
            .await;
        let (tx, mut rx) = mpsc::channel(4);
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_inbound_channel(tx);
        udp.set_inbound_publication_owner(2603);
        let generation = peers.current_network_generation_sync();
        let index = DYNAMIC_SOCKET_INDEX_BASE + 26;
        let (mut remote, _) = establish_sessions();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut readers = OriginalReaders::default();
        let mut origins = Vec::new();
        let mut old_sockets = Vec::new();
        for punch_generation in [1, 2] {
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let guard = udp
                .attach_dynamic_punch_socket(
                    "origin-peer",
                    index,
                    socket.clone(),
                    generation,
                    punch_generation,
                    None,
                )
                .await
                .unwrap();
            assert!(
                guard
                    .commit_and_pin_for_test(
                        &udp,
                        "origin-peer",
                        index,
                        generation,
                        punch_generation
                    )
                    .await
            );
            readers.0.push(
                udp.socket_state
                    .lock()
                    .await
                    .dynamic
                    .get(&index)
                    .unwrap()
                    .reader
                    .abort_handle(),
            );
            assert!(guard.finalize().await);
            let wire = remote.encrypt_to_bytes(&[0x45; 48]).unwrap();
            sender
                .send_to(&wire, socket.local_addr().unwrap())
                .await
                .unwrap();
            let packet = rx.recv().await.unwrap();
            let source = packet.original_udp_read.unwrap();
            assert!(source.belongs_to_socket(&socket));
            assert!(udp
                .try_original_direct_publication_guard(
                    "origin-peer",
                    generation,
                    Some(&source),
                    None
                )
                .is_ok());
            if let Some(old) = origins.first() {
                assert!(matches!(
                    udp.try_original_direct_publication_guard(
                        "origin-peer",
                        generation,
                        Some(old),
                        None
                    ),
                    Err(DirectOriginFailure::Stale)
                ));
            }
            let held = udp.socket_state.lock().await;
            assert!(matches!(
                udp.try_original_direct_publication_guard(
                    "origin-peer",
                    generation,
                    Some(&source),
                    None
                ),
                Err(DirectOriginFailure::ContendedSocket)
            ));
            drop(held);
            origins.push(source);
            old_sockets.push(socket);
            drop(packet.direct_socket);
            udp.detach_dynamic_socket_by_index(index, "origin_control")
                .await;
            assert!(matches!(
                udp.try_original_direct_publication_guard(
                    "origin-peer",
                    generation,
                    origins.last(),
                    None
                ),
                Err(DirectOriginFailure::Stale)
            ));
        }
        assert_eq!(
            old_sockets.len(),
            2,
            "old allocation deliberately stays alive"
        );
        assert!(udp.socket_state.lock().await.dynamic.is_empty());
        while readers.0.iter().any(|reader| !reader.is_finished()) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b26_original_publication_revoke_precedes_waiting_slot_writer() {
    timeout(Duration::from_secs(2), async {
        let peers = peer_manager();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let next = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let slot = Arc::new(RwLock::new(None));
        let publication = crate::UdpTransportPublication::new(slot.clone());
        let _lease = publication.publish(udp.clone()).await;
        let (mut remote, _) = establish_sessions();
        let wire = remote.encrypt_to_bytes(&[0x45; 48]).unwrap();
        let packet = read_one(&udp, 0, udp.socket.clone(), &wire).await;
        let old = packet.original_udp_read.unwrap();
        assert!(udp
            .try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&old),
                None
            )
            .is_ok());
        let original_slot = slot.read().await;
        let publish = publication.publish(next.clone());
        tokio::pin!(publish);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(publish.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        assert_eq!(udp.inbound_publication_owner(), 0);
        assert_eq!(
            original_slot.as_ref().unwrap().transport_instance_id(),
            udp.transport_instance_id()
        );
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&old),
                None
            ),
            Err(DirectOriginFailure::Stale)
        ));
        drop(original_slot);
        let _next_lease = publish.await;
        let packet = read_one(&next, 0, next.socket.clone(), &wire).await;
        let fresh = packet.original_udp_read.unwrap();
        assert!(next
            .try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&fresh),
                None
            )
            .is_ok());
        assert!(matches!(
            next.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&old),
                None
            ),
            Err(DirectOriginFailure::Stale)
        ));
        let runtime = next.dplpmtud_runtime();
        let gate = runtime.try_original_business_publication_guard().unwrap();
        assert!(matches!(
            next.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&fresh),
                None
            ),
            Err(DirectOriginFailure::ContendedPublication)
        ));
        drop(gate);
        assert!(next
            .try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                Some(&fresh),
                None
            )
            .is_ok());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn b26_actual_lan_full_fact_has_no_managed_token_and_legacy_stays_unknown() {
    timeout(Duration::from_secs(2), async {
        let peers = peer_manager();
        peers
            .add_peer(&peer("origin-peer", "10.20.0.2", None))
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        udp.set_inbound_publication_owner(2604);
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = receiver.local_addr().unwrap();
        let (mut local, mut remote) = establish_sessions();
        let plaintext = [0x45; 48];
        let packet = EncryptedPeerPacket {
            room_authorization: None,
            peer_id: "origin-peer".into(),
            dst_ip: "10.20.0.2".into(),
            wire_bytes: local.encrypt_to_bytes(&plaintext).unwrap(),
            is_business: true,
        };
        udp.socket.writable().await.unwrap();
        let mut capture = crate::udp::UdpSendCapture::new();
        assert_eq!(
            udp.try_send_lan_business_packet_on_socket_with_origin(
                &udp.socket,
                0,
                &packet,
                endpoint,
                2604,
                Some(&mut capture)
            )
            .unwrap(),
            packet.wire_bytes.len()
        );
        let mut bytes = [0u8; 256];
        let (len, _) = receiver.recv_from(&mut bytes).await.unwrap();
        assert_eq!(remote.decrypt_from_bytes(&bytes[..len]).unwrap(), plaintext);
        let fact = capture.take().unwrap();
        assert!(fact.original_managed_token().is_none());
        peers.with_peer_membership_held_for_test(|| {
            assert!(matches!(
                udp.try_original_direct_publication_guard(
                    "origin-peer",
                    peers.current_network_generation_sync(),
                    None,
                    Some(&fact)
                ),
                Err(DirectOriginFailure::ContendedMembership)
            ));
            assert!(
                udp.socket_state.try_lock().is_ok(),
                "membership contention leaves registry free"
            );
            assert!(
                udp.dplpmtud_runtime()
                    .try_original_business_publication_guard()
                    .is_some(),
                "membership contention leaves publication gate free"
            );
        });
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                "missing-peer",
                peers.current_network_generation_sync(),
                None,
                Some(&fact)
            ),
            Err(DirectOriginFailure::Unknown)
        ));

        assert!(udp
            .try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                None,
                Some(&fact)
            )
            .is_ok());
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                None,
                None
            ),
            Err(DirectOriginFailure::Unknown)
        ));
        let mut legacy = crate::udp::UdpSendCapture::new();
        udp.send_encrypted_packet_on_socket_until_with_origin(
            &udp.socket,
            0,
            &packet,
            endpoint,
            None,
            Some(&mut legacy),
        )
        .await
        .unwrap();
        let legacy = legacy.take().unwrap();
        assert!(legacy.original_managed_token().is_none());
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                None,
                Some(&legacy)
            ),
            Err(DirectOriginFailure::Unknown)
        ));
        let life = peers.peer_session_generation_sync("origin-peer").unwrap();
        peers.mark_dplpmtud_capable_sync("origin-peer", life);
        assert!(
            matches!(
                udp.try_original_direct_publication_guard(
                    "origin-peer",
                    peers.current_network_generation_sync(),
                    None,
                    Some(&fact)
                ),
                Err(DirectOriginFailure::Stale)
            ),
            "same owner negotiated support must not retain a legacy bypass"
        );
        assert!(udp.clear_inbound_publication_owner_if_matches(2604));
        assert!(matches!(
            udp.try_original_direct_publication_guard(
                "origin-peer",
                peers.current_network_generation_sync(),
                None,
                Some(&fact)
            ),
            Err(DirectOriginFailure::Stale)
        ));
    })
    .await
    .unwrap();
}
