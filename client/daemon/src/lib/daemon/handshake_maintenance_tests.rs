#[cfg(test)]
mod maintenance_integration_tests {
    use super::*;

    fn packet(peer_id: &str, sequence: u16) -> OutboundPacket {
        OutboundPacket {
            room_authorization: None,
            peer_id: peer_id.to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 1),
                Ipv4Addr::new(10, 20, 0, 2),
                42,
                sequence,
                b"maintenance-rekey-business",
            ),
            trace: None,
        }
    }

    async fn assert_business_decrypts(
        transport: &WireGuardTransport,
        peer_id: &str,
        receiver: &mut TransportSession,
        sequence: u16,
    ) {
        let packet = packet(peer_id, sequence);
        let expected = packet.packet.clone();
        let encrypted = transport
            .encrypt_outbound(packet)
            .await
            .unwrap()
            .expect("a usable session must remain installed throughout local rekey retries");
        assert_eq!(
            receiver.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
            expected
        );
    }

    #[tokio::test]
    async fn maintenance_rekey_loop_retries_binding_without_kick_and_preserves_business() {
        let mut local_private = [1; 32];
        let mut remote_private = [2; 32];
        if !local_is_designated_handshake_initiator(
            &NodeIdentity::from_private_key(local_private).public_key(),
            &NodeIdentity::from_private_key(remote_private).public_key(),
        ) {
            std::mem::swap(&mut local_private, &mut remote_private);
        }
        let local_public = NodeIdentity::from_private_key(local_private).public_key();
        let remote_public = NodeIdentity::from_private_key(remote_private).public_key();
        let mut config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
        config.node.private_key = hex::encode(local_private);
        config.node.public_key = hex::encode(local_public);
        let mut daemon = Daemon::new(config);
        let peer = control::PeerInfo {
            node_id: "maintenance-remote".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(remote_public),
            endpoint: "192.0.2.1:51820".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        };
        daemon.peers.add_peer(&peer).await;
        daemon.control = ControlClient::disabled_for_test();
        daemon.control.set_peer_for_test(peer.clone()).await;
        let mut offers = daemon.control.capture_critical_offers_for_test();

        let mut initial = HandshakeInitiator::new(
            NodeIdentity::from_private_key(local_private),
            remote_public,
            None,
        );
        let init = initial.create_initiation().unwrap();
        let mut responder =
            HandshakeResponder::new(NodeIdentity::from_private_key(remote_private), None);
        let (response, remote_keys) = responder.consume_initiation_and_respond(&init).unwrap();
        let local_keys = initial.consume_response(&response).unwrap();
        let mut old_remote_session = TransportSession::new(remote_keys);
        daemon
            .transport
            .add_session(
                peer.node_id.clone(),
                TransportSession::new(local_keys).with_thresholds(
                    u64::MAX,
                    Duration::ZERO,
                    u64::MAX,
                    Duration::from_secs(8),
                ),
            )
            .await;
        let old_status = daemon.transport.session_status(&peer.node_id).await;
        assert!(old_status.has_active && old_status.needs_rekey && !old_status.expired);
        assert!(daemon.candidate_snapshot.read().await.is_none());

        let reader = daemon.peers.hold_connections_reader_for_test().await;
        let ctx = HandshakeMaintenanceContext {
            peers: daemon.peers.clone(),
            transport: daemon.transport.clone(),
            pending: daemon.pending_handshakes.clone(),
            handshake_arbiter: daemon.handshake_arbiter.clone(),
            control: daemon.control.clone(),
            local_candidates: daemon.local_candidates.clone(),
            local_candidate_sources: daemon.local_candidate_sources.clone(),
            local_network_identity: daemon.local_network_identity.clone(),
            candidate_snapshot: daemon.candidate_snapshot.clone(),
            candidate_refresh_lock: daemon.candidate_refresh_lock.clone(),
            nat_profile: daemon.nat_profile.clone(),
            udp_transport: daemon.udp_transport.clone(),
            runtime_stun_servers: daemon.runtime_stun_servers.clone(),
            runtime_stun_timeout: daemon.runtime_stun_timeout.clone(),
            udp_advertise: None,
            node_private_key: daemon.config.node.private_key.clone(),
            kick_rx: daemon.path_setup_kick_tx.subscribe(),
            handshake_retry_kick_tx: daemon.handshake_retry_kick_tx.clone(),
            timeline: daemon.timeline.clone(),
        };
        let worker = tokio::spawn(run_handshake_maintenance(ctx));
        // Wait for three actual attempts, not an assumed scheduler sleep. The
        // old path either queues cleanup on this reader or waits ten seconds.
        timeout(Duration::from_secs(3), async {
            loop {
                if daemon.pending_handshakes.lock().next_start_id >= 3 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("local binding contention must have its own progress timer");
        assert!(offers.try_recv().is_err());
        assert_eq!(
            daemon
                .pending_handshakes
                .lock()
                .attempts
                .get(&peer.node_id)
                .copied()
                .unwrap_or(0),
            0
        );
        let another_reader = timeout(
            Duration::from_millis(200),
            daemon.peers.hold_connections_reader_for_test(),
        )
        .await
        .expect("failed binding preparation must not queue a cleanup writer");
        drop(another_reader);
        for sequence in 0..16 {
            assert_business_decrypts(
                &daemon.transport,
                &peer.node_id,
                &mut old_remote_session,
                sequence,
            )
            .await;
        }

        // No kick and no additional traffic is sent after releasing the lock.
        // Only the maintenance-owned retry timer can progress before the scan.
        drop(reader);
        let offer = timeout(Duration::from_secs(2), offers.recv())
            .await
            .expect("rekey must send without waiting for the ten-second scan")
            .expect("critical offer observer closed");
        assert_eq!(offer.to_node_id, peer.node_id);
        assert!(offer.candidates.is_empty());
        assert_eq!(
            daemon
                .pending_handshakes
                .lock()
                .attempts
                .get(&peer.node_id)
                .copied(),
            Some(1)
        );
        assert_business_decrypts(
            &daemon.transport,
            &peer.node_id,
            &mut old_remote_session,
            16,
        )
        .await;

        // Complete the real Noise response through the daemon answer handler,
        // then authenticate business ciphertext under the newly derived key.
        let initiation = MessageInitiation::from_bytes(&offer.handshake_init).unwrap();
        let mut responder =
            HandshakeResponder::new(NodeIdentity::from_private_key(remote_private), None);
        let (answer, remote_keys) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();
        let mut new_remote_session = TransportSession::new(remote_keys);
        let (_, response_probe_public) = new_probe_ephemeral_keypair();
        assert!(daemon
            .handle_peer_answer(
                &peer.node_id,
                &answer.to_bytes(),
                offer.session_id,
                Some(response_probe_public),
            )
            .await
            .unwrap());
        let new_status = daemon.transport.session_status(&peer.node_id).await;
        assert!(new_status.has_active && !new_status.expired && !new_status.needs_rekey);
        assert_ne!(
            new_status.active_session_instance,
            old_status.active_session_instance
        );
        assert_eq!(
            new_status.previous_session_instance,
            old_status.active_session_instance
        );
        for sequence in 17..33 {
            assert_business_decrypts(
                &daemon.transport,
                &peer.node_id,
                &mut new_remote_session,
                sequence,
            )
            .await;
        }
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
    }

    #[tokio::test]
    async fn maintenance_binding_classifies_epoch_contention_capacity_and_stale_lifecycle() {
        let config = Config::generate_default("http://127.0.0.1:1", "net1").unwrap();
        let daemon = Daemon::new(config);
        let peer = control::PeerInfo {
            node_id: "binding-peer".to_string(),
            device_name: String::new(),
            app_version: String::new(),
            public_key: hex::encode(NodeIdentity::generate().public_key()),
            endpoint: "192.0.2.2:51820".to_string(),
            nat_type: "Unknown".to_string(),
            virtual_ip: "10.20.0.2".to_string(),
            online: true,
            last_seen: 0,
            relay_rtt_ms: None,
        };
        daemon.peers.add_peer(&peer).await;
        let generation = daemon.peers.current_network_generation_sync();
        let peer_generation = daemon
            .peers
            .peer_session_generation_sync(&peer.node_id)
            .unwrap();
        let MaintenanceInitiatorReservationOutcome::Reserved { reservation, .. } =
            try_reserve_maintenance_initiator(
                &daemon.pending_handshakes,
                &daemon.handshake_arbiter,
                &peer.node_id,
                generation,
                peer_generation,
            )
        else {
            panic!("maintenance reservation must be available");
        };
        let epoch = daemon.peers.network_epoch_gate();
        let guard = epoch.lock().await;
        assert_eq!(
            try_stage_maintenance_probe_binding(
                &daemon.peers,
                &peer.node_id,
                &reservation,
                "attempt"
            ),
            MaintenanceBindingOutcome::Retry("network_epoch_contended")
        );
        drop(guard);
        let reader = daemon.peers.hold_connections_reader_for_test().await;
        assert_eq!(
            try_stage_maintenance_probe_binding(
                &daemon.peers,
                &peer.node_id,
                &reservation,
                "attempt"
            ),
            MaintenanceBindingOutcome::Retry("connections_contended")
        );
        drop(reader);
        let mut capacity_reached = false;
        for index in 0..64 {
            match daemon
                .peers
                .stage_probe_session_binding(
                    &peer.node_id,
                    format!("occupant-{index}"),
                    Some(format!("occupant-{index}")),
                    None,
                    false,
                )
                .await
            {
                ProbeBindingStage::Staged => {}
                ProbeBindingStage::Busy => {
                    capacity_reached = true;
                    break;
                }
                other => panic!("unexpected staging result: {other:?}"),
            }
        }
        assert!(capacity_reached);
        assert_eq!(
            try_stage_maintenance_probe_binding(
                &daemon.peers,
                &peer.node_id,
                &reservation,
                "attempt"
            ),
            MaintenanceBindingOutcome::Retry("binding_capacity")
        );
        assert!(daemon
            .peers
            .try_discard_pending_probe_session_binding(&peer.node_id, "occupant-0")
            .unwrap());
        assert_eq!(
            try_stage_maintenance_probe_binding(
                &daemon.peers,
                &peer.node_id,
                &reservation,
                "attempt"
            ),
            MaintenanceBindingOutcome::Staged
        );
        assert_eq!(
            try_stage_maintenance_probe_binding(
                &daemon.peers,
                &peer.node_id,
                &reservation,
                "attempt"
            ),
            MaintenanceBindingOutcome::Cancel("binding_duplicate")
        );
        daemon.peers.remove_peer(&peer.node_id).await;
        daemon.peers.add_peer(&peer).await;
        assert_eq!(
            try_stage_maintenance_probe_binding(
                &daemon.peers,
                &peer.node_id,
                &reservation,
                "attempt"
            ),
            MaintenanceBindingOutcome::Cancel("stale_lifecycle")
        );
    }

    #[test]
    fn maintenance_retry_ledger_is_bounded() {
        let now = Instant::now();
        let identity = MaintenanceRetryIdentity {
            network_generation: 1,
            peer_session_generation: PeerSessionGeneration::for_test(1),
            active_session_instance: Some(1),
        };
        let mut retries = MaintenancePreparationRetries::default();
        for index in 0..MAX_MAINTENANCE_RETRIES + 10 {
            retries.schedule(
                &format!("peer-{index}"),
                identity,
                None,
                "connections_contended",
                now,
            );
        }
        assert_eq!(retries.entries.len(), MAX_MAINTENANCE_RETRIES);
        for _ in 0..100 {
            retries.schedule("peer-0", identity, None, "connections_contended", now);
        }
        assert_eq!(retries.entries.len(), MAX_MAINTENANCE_RETRIES);
        assert!(retries.next_deadline().unwrap() > now);
    }
}
