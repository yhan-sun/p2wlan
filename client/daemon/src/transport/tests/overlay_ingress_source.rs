// S2 uses actual Noise/WireGuard decrypt and the original inbound actor.
// Relay connect_for_test allocates real local incarnations, without public TLS.
// These are carriage controls, not a synchronized final-owner/credit guard.
// The barrier receives InboundPacket from the actor output queue; it does not
// run DataPlane, MockTunDevice or recv_written, and proves no actual TUN write.

struct S2OverlayCarriageHarness {
    transport: WireGuardTransport,
    remote_session: TransportSession,
    peers: Arc<PeerManager>,
    peer_info: PeerInfo,
    original_life: PeerSessionGeneration,
    relay_slot: Arc<RwLock<Option<crate::relay::RelayTransport>>>,
    relay_endpoint: String,
    relay_connection_id: u64,
    encrypted_tx: mpsc::Sender<ReceivedEncryptedPacket>,
    inbound_rx: mpsc::Receiver<InboundPacket>,
    overlay_rx: mpsc::Receiver<OverlayIngressDelivery>,
    worker: tokio::task::JoinHandle<Result<()>>,
}

impl S2OverlayCarriageHarness {
    async fn new(authorized: bool) -> Self {
        let (peers, peer_info, original_life) = s1_peer_scope_owner().await;
        let peers = Arc::new(peers);
        let (remote_session, local_session) = establish_sessions();
        let (transport, _raw_outbound_rx) = WireGuardTransport::new();
        if authorized {
            s1_install_authorized(&transport, None, local_session, original_life).await;
        } else {
            transport.add_session("peer-a", local_session).await;
        }
        let relay_endpoint = "tls://relay.test:443".to_string();
        let relay = crate::relay::RelayTransport::connect_for_test(
            "s2-local",
            &relay_endpoint,
            peers.clone(),
        );
        let relay_connection_id = relay.connection_id();
        let relay_slot = Arc::new(RwLock::new(Some(relay)));
        let timeline = crate::connection_timeline::ConnectionTimeline::new("node-local", 1);
        peers.set_timeline(timeline.clone());
        // Same capacities as production overlay and existing native inbound fixture.
        // inbound_rx is the actor output queue, not a TUN-device write receipt.
        let (overlay_tx, overlay_rx) = mpsc::channel(128);
        assert_eq!(overlay_tx.max_capacity(), 128);
        let evidence = InboundEvidenceFeed {
            relay_transport: relay_slot.clone(),
            timeline: Some(timeline),
            overlay_ingress_tx: Some(overlay_tx),
        };
        let (encrypted_tx, encrypted_rx) = mpsc::channel(16);
        let (inbound_tx, inbound_rx) = mpsc::channel(16);
        let (_udp_tx, udp_updates) = watch::channel(None);
        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers_live_udp_and_relay(
                        encrypted_rx,
                        inbound_tx,
                        Some(peers),
                        udp_updates,
                        Some(evidence),
                    )
                    .await
            }
        });
        Self {
            transport,
            remote_session,
            peers,
            peer_info,
            original_life,
            relay_slot,
            relay_endpoint,
            relay_connection_id,
            encrypted_tx,
            inbound_rx,
            overlay_rx,
            worker,
        }
    }

    async fn send_and_wait_for_inbound_output(
        &mut self,
        packet: &[u8],
        generation: Option<u64>,
        registered_peer: Option<&str>,
        udp_owner: Option<u64>,
    ) -> (InboundPacket, Instant) {
        let wire_bytes = self.remote_session.encrypt_to_bytes(packet).unwrap();
        let queued_at = Instant::now();
        self.encrypted_tx
            .send(ReceivedEncryptedPacket {
                physical_ingress: None,
                original_relay_read: None,
                original_udp_read: None,
                source: None,
                local_endpoint: None,
                relay_endpoint: Some(self.relay_endpoint.clone()),
                relay_connection_id: Some(self.relay_connection_id),
                relay_peer_id: registered_peer.map(str::to_string),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: udp_owner,
                network_generation: generation,
                profile_sampled: false,
                udp_received: None,
                transport_queue_send_started: Some(queued_at),
                wire_bytes,
            })
            .await
            .unwrap();
        // The actor sends overlay before its InboundPacket output; this enqueue barrier
        // consumes only actor output, not the Delivery whose fields we will inspect.
        let inbound = timeout(Duration::from_secs(1), self.inbound_rx.recv())
            .await
            .expect(
                "actual inbound did not publish InboundPacket output within the original deadline",
            )
            .expect("actual inbound closed its InboundPacket output channel");
        assert_eq!(inbound.peer_id, "peer-a");
        assert_eq!(inbound.packet, packet);
        assert!(inbound.session_instance.is_some());
        assert!(!inbound.from_previous_session);
        assert!(
            !self.overlay_rx.is_empty(),
            "overlay send must precede InboundPacket output receipt"
        );
        (inbound, queued_at)
    }

    async fn recv_overlay(&mut self) -> OverlayIngressDelivery {
        timeout(Duration::from_secs(1), self.overlay_rx.recv())
            .await
            .expect("actual overlay channel failed within the original fixture deadline")
            .expect("actual overlay channel closed")
    }

    async fn replace_relay_incarnation(&mut self) -> u64 {
        let relay = crate::relay::RelayTransport::connect_for_test(
            "s2-local",
            &self.relay_endpoint,
            self.peers.clone(),
        );
        let replacement = relay.connection_id();
        assert_ne!(replacement, self.relay_connection_id);
        *self.relay_slot.write().await = Some(relay);
        self.relay_connection_id = replacement;
        replacement
    }

    async fn shutdown(self) {
        drop(self.encrypted_tx);
        timeout(Duration::from_secs(1), self.worker)
            .await
            .expect("actual inbound remained blocked beyond the original fixture deadline")
            .expect("actual inbound panicked")
            .expect("actual inbound failed");
    }
}

fn s2_overlay_packet(seq: u32) -> Vec<u8> {
    let payload = crate::build_overlay_payload(crate::OVERLAY_DIRECTION_REQUEST, 0x5202, seq);
    crate::build_udp_overlay_packet("10.20.0.2", "10.20.0.1", 32002, 32001, &payload)
        .expect("existing overlay builder must produce a real UDP candidate")
}

#[tokio::test]
async fn s2_delayed_relay_delivery_keeps_decrypt_and_envelope_origin() {
    let mut harness = S2OverlayCarriageHarness::new(true).await;
    let original_g = harness.peers.current_network_generation_sync();
    let original_r = harness.relay_connection_id;
    let original_life = harness.original_life;
    let old_packet = s2_overlay_packet(1); // Retain exactly this random-filled packet.
    let (old_inbound_output, old_enqueued) = harness
        .send_and_wait_for_inbound_output(&old_packet, Some(original_g), Some("peer-a"), None)
        .await;
    let after_old_inbound_output = Instant::now();
    assert_eq!(harness.overlay_rx.len(), 1);

    // Transition the actual owners only after the original Delivery is queued.
    let current_g = harness
        .peers
        .advance_network_generation("s2 delayed source")
        .await;
    assert_ne!(current_g, original_g);
    let current_r = harness.replace_relay_incarnation().await;
    let current_life = s1_readd_peer(&harness.peers, &harness.peer_info).await;
    let (current_remote, current_local) = establish_sessions();
    s1_install_authorized(&harness.transport, None, current_local, current_life).await;
    harness.remote_session = current_remote;
    let current_packet = s2_overlay_packet(2);
    let (current_inbound_output, current_enqueued) = harness
        .send_and_wait_for_inbound_output(&current_packet, Some(current_g), Some("peer-a"), None)
        .await;
    assert_ne!(
        old_inbound_output.session_instance,
        current_inbound_output.session_instance
    );

    let (old_event, old_origin) = harness.recv_overlay().await.into_parts();
    let old_origin = old_origin.expect("real decrypt must supply an original source");
    assert_eq!(old_event.packet, old_packet);
    assert_eq!(old_event.peer_id, "peer-a");
    assert_eq!(old_event.connection_generation, original_g);
    assert_eq!(
        old_event.ingress,
        OverlayIngress::Relay(harness.relay_endpoint.clone())
    );
    assert_eq!(old_origin.session().peer_id(), old_inbound_output.peer_id);
    assert_eq!(
        Some(old_origin.session().session_instance()),
        old_inbound_output.session_instance
    );
    assert_eq!(
        old_origin.session().authorized_peer_lifecycle(),
        Some(original_life)
    );
    assert_ne!(
        old_origin.session().authorized_peer_lifecycle(),
        Some(current_life)
    );
    assert!(!old_origin.session().is_previous_session());
    assert!(old_origin.session().authenticated_at() <= after_old_inbound_output);
    assert!(old_origin.session().belongs_to(&harness.transport.clone()));
    let (other_owner, _other_rx) = WireGuardTransport::new();
    assert!(!old_origin.session().belongs_to(&other_owner));
    assert_eq!(old_origin.network_generation(), Some(original_g));
    assert_ne!(old_origin.network_generation(), Some(current_g));
    assert_eq!(
        old_origin.relay_endpoint(),
        Some(harness.relay_endpoint.as_str())
    );
    assert_eq!(old_origin.relay_connection_id(), Some(original_r));
    assert_ne!(old_origin.relay_connection_id(), Some(current_r));
    assert_eq!(old_origin.relay_peer_id(), Some("peer-a"));
    assert_eq!(old_origin.udp_transport_owner(), None);
    assert_eq!(old_origin.source(), None);
    assert_eq!(old_origin.local_endpoint(), None);
    assert_eq!(old_origin.socket_index(), None);
    assert_eq!(old_origin.received_at(), None);
    assert_eq!(old_origin.queue_send_started(), Some(old_enqueued));

    // A second real ciphertext is the positive control for the replacement.
    let (current_event, current_origin) = harness.recv_overlay().await.into_parts();
    let current_origin = current_origin.expect("replacement decrypt must supply its actual source");
    assert_eq!(current_event.packet, current_packet);
    assert_eq!(current_event.connection_generation, current_g);
    assert_eq!(
        Some(current_origin.session().session_instance()),
        current_inbound_output.session_instance
    );
    assert_eq!(
        current_origin.session().authorized_peer_lifecycle(),
        Some(current_life)
    );
    assert_eq!(current_origin.network_generation(), Some(current_g));
    assert_eq!(current_origin.relay_connection_id(), Some(current_r));
    assert_eq!(current_origin.queue_send_started(), Some(current_enqueued));
    assert!(current_origin.session().belongs_to(&harness.transport));
    assert!(harness.overlay_rx.is_empty());
    harness.shutdown().await;
}

#[tokio::test]
async fn s2_native_missing_envelope_generation_is_not_backfilled() {
    let mut harness = S2OverlayCarriageHarness::new(true).await;
    let at_enqueue_g = harness
        .peers
        .advance_network_generation("s2 unknown envelope")
        .await;
    let packet = s2_overlay_packet(3);
    let (inbound_output, enqueued) = harness
        .send_and_wait_for_inbound_output(&packet, None, Some("peer-a"), None)
        .await;
    let current_g = harness
        .peers
        .advance_network_generation("s2 queued unknown envelope")
        .await;
    assert_ne!(at_enqueue_g, current_g);
    let (event, origin) = harness.recv_overlay().await.into_parts();
    let origin = origin.expect("native legacy envelope still has a successful decrypt source");
    assert_eq!(event.packet, packet);
    // Existing scalar fallback remains compatible, but is never original G.
    assert_eq!(event.connection_generation, at_enqueue_g);
    assert_eq!(origin.network_generation(), None);
    assert_eq!(
        Some(origin.session().session_instance()),
        inbound_output.session_instance
    );
    assert_eq!(
        origin.session().authorized_peer_lifecycle(),
        Some(harness.original_life)
    );
    assert_eq!(
        origin.relay_connection_id(),
        Some(harness.relay_connection_id)
    );
    assert_eq!(origin.relay_peer_id(), Some("peer-a"));
    assert_eq!(origin.queue_send_started(), Some(enqueued));
    assert!(origin.session().belongs_to(&harness.transport));
    assert!(harness.overlay_rx.is_empty());
    harness.shutdown().await;
}

#[tokio::test]
async fn s2_native_legacy_life_and_public_event_remain_unknown() {
    let mut harness = S2OverlayCarriageHarness::new(false).await;
    harness
        .peers
        .advance_network_generation("s2 legacy current observation")
        .await;
    let packet = s2_overlay_packet(4);
    // Zero UDP owner and absent registered peer are unknown legacy observations,
    // not proof of a live Direct reader or Relay ticket authentication.
    let (inbound_output, enqueued) = harness
        .send_and_wait_for_inbound_output(&packet, None, None, Some(0))
        .await;
    let (event, origin) = harness.recv_overlay().await.into_parts();
    let origin = origin.expect("legacy key actually decrypted; native provenance exists");
    assert_eq!(event.packet, packet);
    assert_eq!(origin.session().peer_id(), inbound_output.peer_id);
    assert_eq!(
        Some(origin.session().session_instance()),
        inbound_output.session_instance
    );
    assert_eq!(origin.session().authorized_peer_lifecycle(), None);
    assert!(harness
        .peers
        .peer_session_generation_sync("peer-a")
        .is_some());
    assert_eq!(origin.network_generation(), None);
    assert_eq!(origin.udp_transport_owner(), Some(0));
    assert_eq!(origin.relay_peer_id(), None);
    assert_eq!(
        origin.relay_connection_id(),
        Some(harness.relay_connection_id)
    );
    assert_eq!(origin.received_at(), None);
    assert_eq!(origin.queue_send_started(), Some(enqueued));
    assert!(origin.session().belongs_to(&harness.transport));
    let (legacy_event, fabricated_source) = OverlayIngressDelivery::from(event).into_parts();
    assert_eq!(legacy_event.packet, packet);
    assert!(
        fabricated_source.is_none(),
        "public Event cannot manufacture native provenance"
    );
    assert!(harness.overlay_rx.is_empty());
    harness.shutdown().await;
}
