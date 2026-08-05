#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::Ipv4Packet;
    use p2pnet_wireguard::{
        HandshakeInitiator, HandshakeResponder, MessageTransport, TransportSession, TYPE_TRANSPORT,
    };
    use tokio::sync::{mpsc, oneshot, Notify};

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::{ConnectionState, NetworkPath, ProbeBindingStage, ProbeKeyRole};

    fn establish_sessions() -> (TransportSession, TransportSession) {
        let node_a = NodeIdentity::generate();
        let node_b = NodeIdentity::generate();

        let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
        let mut responder = HandshakeResponder::new(node_b, None);

        let init = initiator.create_initiation().unwrap();
        let (response, node_b_keys) = responder.consume_initiation_and_respond(&init).unwrap();
        let node_a_keys = initiator.consume_response(&response).unwrap();

        (
            TransportSession::new(node_a_keys),
            TransportSession::new(node_b_keys),
        )
    }

    #[tokio::test]
    async fn encrypts_outbound_packet_with_peer_session() {
        let (node_a_session, mut node_b_session) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-b", node_a_session).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );

        let (outbound_tx, outbound_rx) = mpsc::channel(4);
        let worker = {
            let transport = transport.clone();
            tokio::spawn(async move { transport.run_outbound(outbound_rx).await })
        };

        outbound_tx
            .send(OutboundPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: packet.clone(),
            })
            .await
            .unwrap();

        let encrypted = encrypted_rx.recv().await.unwrap();
        assert_eq!(encrypted.peer_id, "peer-b");
        assert_eq!(encrypted.dst_ip, "10.20.0.2");
        assert_eq!(encrypted.wire_bytes[0], TYPE_TRANSPORT);

        let decrypted = node_b_session
            .decrypt_from_bytes(&encrypted.wire_bytes)
            .unwrap();
        assert_eq!(decrypted, packet);

        worker.abort();
    }

    #[tokio::test]
    async fn drops_outbound_packet_without_session() {
        let (transport, mut encrypted_rx) = WireGuardTransport::new();

        let dropped = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "missing-peer".to_string(),
                dst_ip: "10.20.0.9".to_string(),
                packet: vec![0x45, 0x00, 0x00, 0x14],
            })
            .await
            .unwrap();

        assert!(dropped.is_none());
        assert!(encrypted_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn session_install_cannot_miss_packet_queued_in_the_handoff_window() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        let pending_guard = transport.pending_outbound.lock().await;
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x1111,
            1,
            b"handoff-race",
        );

        let queue_task = tokio::spawn({
            let transport = transport.clone();
            let packet = packet.clone();
            async move {
                transport
                    .encrypt_or_queue_outbound(OutboundPacket {
                        peer_id: "peer-a".to_string(),
                        dst_ip: "10.20.0.1".to_string(),
                        packet,
                    })
                    .await
            }
        });
        tokio::task::yield_now().await;
        let install_task = tokio::spawn({
            let transport = transport.clone();
            async move { transport.add_session("peer-a", local_session).await }
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !transport.session_status("peer-a").await.has_active {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(pending_guard);

        let encrypted = tokio::time::timeout(Duration::from_secs(1), encrypted_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            remote_session
                .decrypt_from_bytes(&encrypted.wire_bytes)
                .unwrap(),
            packet
        );
        drop(encrypted);
        assert!(queue_task.await.unwrap().unwrap().is_none());
        install_task.await.unwrap();
    }

    #[tokio::test]
    async fn pending_flush_and_live_outbound_emit_monotonic_counters() {
        let (_remote_session, local_session) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        for sequence in 0..96u16 {
            assert!(transport
                .encrypt_or_queue_outbound(OutboundPacket {
                    peer_id: "peer-a".to_string(),
                    dst_ip: "10.20.0.1".to_string(),
                    packet: Ipv4Packet::build_icmp_echo_request(
                        Ipv4Addr::new(10, 20, 0, 2),
                        Ipv4Addr::new(10, 20, 0, 1),
                        0x1212,
                        sequence,
                        b"queued",
                    ),
                })
                .await
                .unwrap()
                .is_none());
        }

        let (outbound_tx, outbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            async move { transport.run_outbound(outbound_rx).await }
        });
        let install = tokio::spawn({
            let transport = transport.clone();
            async move { transport.add_session("peer-a", local_session).await }
        });
        outbound_tx
            .send(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: Ipv4Packet::build_icmp_echo_request(
                    Ipv4Addr::new(10, 20, 0, 2),
                    Ipv4Addr::new(10, 20, 0, 1),
                    0x1212,
                    96,
                    b"live",
                ),
            })
            .await
            .unwrap();
        install.await.unwrap();

        let mut counters = Vec::new();
        for _ in 0..97 {
            let encrypted = tokio::time::timeout(Duration::from_secs(1), encrypted_rx.recv())
                .await
                .unwrap()
                .unwrap();
            counters.push(
                MessageTransport::from_bytes(&encrypted.wire_bytes)
                    .unwrap()
                    .counter,
            );
        }
        assert_eq!(counters, (0..97u64).collect::<Vec<_>>());

        drop(outbound_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn drops_expired_outbound_session_without_stopping_transport() {
        let (_remote, local) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        transport
            .add_session(
                "peer-a",
                local.with_thresholds(u64::MAX, Duration::MAX, 0, Duration::MAX),
            )
            .await;

        let dropped = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: vec![0x45, 0x00, 0x00, 0x14],
            })
            .await
            .unwrap();

        assert!(dropped.is_none());
        let status = transport.session_status("peer-a").await;
        assert!(status.has_active);
        assert!(status.expired);
        assert_eq!(status.expires_in, Some(Duration::ZERO));
        assert!(encrypted_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn transactional_session_replacement_can_restore_previous_session() {
        let (mut old_remote, old_local) = establish_sessions();
        let (_new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        let previous = transport.replace_session("peer-a", new_local).await;
        assert!(previous.is_some());
        transport.restore_session("peer-a", previous).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"old-session",
        );
        let wire_bytes = old_remote.encrypt_to_bytes(&packet).unwrap();
        let inbound = transport
            .decrypt_inbound(&wire_bytes)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(inbound.peer_id, "peer-a");
        assert_eq!(inbound.packet, packet);
    }

    #[tokio::test]
    async fn rekey_accepts_previous_inbound_for_the_overlap_window() {
        let (mut old_remote, old_local) = establish_sessions();
        let (mut new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        assert!(!transport.add_session("peer-a", old_local).await);
        assert!(transport.add_session("peer-a", new_local).await);

        let old_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"old-in-flight",
        );
        let old_wire = old_remote.encrypt_to_bytes(&old_packet).unwrap();
        let inbound = transport
            .decrypt_inbound(&old_wire)
            .await
            .unwrap()
            .expect("old receive key should remain valid during rekey overlap");
        assert_eq!(inbound.packet, old_packet);

        let new_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            2,
            b"new-session",
        );
        let new_wire = new_remote.encrypt_to_bytes(&new_packet).unwrap();
        let inbound = transport
            .decrypt_inbound(&new_wire)
            .await
            .unwrap()
            .expect("new receive key should decrypt");
        assert_eq!(inbound.packet, new_packet);

        let late_old_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            3,
            b"late-old",
        );
        let late_old_wire = old_remote.encrypt_to_bytes(&late_old_packet).unwrap();
        let inbound = transport
            .decrypt_inbound(&late_old_wire)
            .await
            .unwrap()
            .expect("old receive key should remain valid for the overlap window");
        assert_eq!(inbound.packet, late_old_packet);
    }

    #[tokio::test]
    async fn responder_rekey_keeps_old_outbound_until_new_key_is_confirmed() {
        let (mut old_remote, old_local) = establish_sessions();
        let (mut new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        assert_eq!(
            transport
                .stage_responder_session("peer-a", "rekey-1".to_string(), new_local)
                .await,
            ResponderSessionStage::Staged { had_active: true }
        );
        assert_eq!(
            transport
                .commit_responder_session("peer-a", "rekey-1")
                .await,
            ResponderSessionCommit::PendingConfirmation
        );

        let old_outbound = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x2222,
            1,
            b"old-outbound-before-confirmation",
        );
        let encrypted = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: old_outbound.clone(),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            old_remote
                .decrypt_from_bytes(&encrypted.wire_bytes)
                .unwrap(),
            old_outbound
        );

        let confirmation = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x2222,
            2,
            b"new-key-confirmation",
        );
        let confirmation_wire = new_remote.encrypt_to_bytes(&confirmation).unwrap();
        assert_eq!(
            transport
                .decrypt_inbound(&confirmation_wire)
                .await
                .unwrap()
                .unwrap()
                .packet,
            confirmation
        );
        assert!(
            !transport
                .session_status("peer-a")
                .await
                .has_pending_responder
        );

        let new_outbound = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x2222,
            3,
            b"new-outbound-after-confirmation",
        );
        let encrypted = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: new_outbound.clone(),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            new_remote
                .decrypt_from_bytes(&encrypted.wire_bytes)
                .unwrap(),
            new_outbound
        );
    }

    #[tokio::test]
    async fn expired_active_does_not_auto_promote_committed_responder_session() {
        let (_old_remote, old_local) = establish_sessions();
        let (mut new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport
            .add_session(
                "peer-a",
                old_local.with_thresholds(u64::MAX, Duration::MAX, 0, Duration::MAX),
            )
            .await;
        transport
            .stage_responder_session("peer-a", "rekey-expired".to_string(), new_local)
            .await;
        assert_eq!(
            transport
                .commit_responder_session("peer-a", "rekey-expired")
                .await,
            ResponderSessionCommit::PendingConfirmation
        );

        let status = transport.session_status("peer-a").await;
        assert!(status.has_active);
        assert!(status.expired);
        assert!(status.has_pending_responder);
        assert!(transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: vec![0x45, 0x00, 0x00, 0x14],
            })
            .await
            .unwrap()
            .is_none());

        let confirmation = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x3333,
            1,
            b"confirm-expired-rekey",
        );
        let wire = new_remote.encrypt_to_bytes(&confirmation).unwrap();
        assert!(transport.decrypt_inbound(&wire).await.unwrap().is_some());
        let status = transport.session_status("peer-a").await;
        assert!(status.has_active);
        assert!(!status.expired);
        assert!(!status.has_pending_responder);
    }

    #[tokio::test]
    async fn duplicate_responder_token_cannot_replace_staged_keys() {
        let (_first_remote, first_local) = establish_sessions();
        let (_second_remote, second_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();

        assert_eq!(
            transport
                .stage_responder_session("peer-a", "same-token".to_string(), first_local)
                .await,
            ResponderSessionStage::Staged { had_active: false }
        );
        assert_eq!(
            transport
                .stage_responder_session("peer-a", "same-token".to_string(), second_local)
                .await,
            ResponderSessionStage::ReplayableDuplicate { had_active: false }
        );
    }

    #[tokio::test]
    async fn expired_committed_responder_token_cannot_replay_a_discarded_key() {
        let (_old_remote, old_local) = establish_sessions();
        let (_new_remote, new_local) = establish_sessions();
        let (_replacement_remote, replacement_local) = establish_sessions();
        let (mut restaged_remote, restaged_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        assert_eq!(
            transport
                .stage_responder_session("peer-a", "expired-token".to_string(), new_local)
                .await,
            ResponderSessionStage::Staged { had_active: true }
        );
        assert_eq!(
            transport
                .commit_responder_session("peer-a", "expired-token")
                .await,
            ResponderSessionCommit::PendingConfirmation
        );
        {
            let mut sessions = transport.sessions.lock().await;
            sessions
                .get_mut("peer-a")
                .unwrap()
                .pending
                .get_mut("expired-token")
                .unwrap()
                .expires_at = Instant::now();
        }

        assert_eq!(
            transport
                .stage_responder_session("peer-a", "expired-token".to_string(), replacement_local,)
                .await,
            ResponderSessionStage::StaleDuplicate
        );
        assert_eq!(
            transport
                .restage_cached_responder_session(
                    "peer-a",
                    "expired-token".to_string(),
                    restaged_local,
                )
                .await,
            ResponderSessionStage::Staged { had_active: true }
        );
        assert_eq!(
            transport
                .commit_responder_session("peer-a", "expired-token")
                .await,
            ResponderSessionCommit::PendingConfirmation
        );
        let confirmation = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x4545,
            1,
            b"restaged-cached-answer",
        );
        let wire = restaged_remote.encrypt_to_bytes(&confirmation).unwrap();
        assert_eq!(
            transport
                .decrypt_inbound(&wire)
                .await
                .unwrap()
                .unwrap()
                .packet,
            confirmation
        );
        let status = transport.session_status("peer-a").await;
        assert!(status.has_active);
        assert!(!status.has_pending_responder);
    }

    #[tokio::test]
    async fn superseded_responder_token_cannot_be_restaged_from_cache() {
        let (_old_remote, old_local) = establish_sessions();
        let (_first_remote, first_local) = establish_sessions();
        let (_second_remote, second_local) = establish_sessions();
        let (_replay_remote, replay_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        for (token, session) in [("token-a", first_local), ("token-b", second_local)] {
            assert_eq!(
                transport
                    .stage_responder_session("peer-a", token.to_string(), session)
                    .await,
                ResponderSessionStage::Staged { had_active: true }
            );
            assert_eq!(
                transport.commit_responder_session("peer-a", token).await,
                ResponderSessionCommit::PendingConfirmation
            );
        }

        assert_eq!(
            transport
                .confirm_responder_session("peer-a", "token-b")
                .await,
            ResponderSessionConfirmation::Promoted
        );
        assert_eq!(
            transport
                .restage_cached_responder_session("peer-a", "token-a".to_string(), replay_local,)
                .await,
            ResponderSessionStage::StaleDuplicate
        );
    }

    #[tokio::test]
    async fn expired_responder_token_cannot_restage_after_initiator_answer_supersedes_it() {
        let (_old_remote, old_local) = establish_sessions();
        let (_pending_remote, pending_local) = establish_sessions();
        let (_initiator_remote, initiator_local) = establish_sessions();
        let (_replay_remote, replay_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        assert_eq!(
            transport
                .stage_responder_session(
                    "peer-a",
                    "expired-before-initiator".to_string(),
                    pending_local,
                )
                .await,
            ResponderSessionStage::Staged { had_active: true }
        );
        assert_eq!(
            transport
                .commit_responder_session("peer-a", "expired-before-initiator")
                .await,
            ResponderSessionCommit::PendingConfirmation
        );
        {
            let mut sessions = transport.sessions.lock().await;
            sessions
                .get_mut("peer-a")
                .unwrap()
                .pending
                .get_mut("expired-before-initiator")
                .unwrap()
                .expires_at = Instant::now();
        }
        assert!(!transport
            .session_status("peer-a")
            .await
            .has_pending_responder);

        transport
            .install_active_session(
                "peer-a",
                Some("new-initiator-answer".to_string()),
                initiator_local,
            )
            .await;
        assert_eq!(
            transport
                .restage_cached_responder_session(
                    "peer-a",
                    "expired-before-initiator".to_string(),
                    replay_local,
                )
                .await,
            ResponderSessionStage::StaleDuplicate
        );
    }

    #[tokio::test]
    async fn promoted_previous_token_stays_terminal_after_overlap_expires() {
        let (_old_remote, old_local) = establish_sessions();
        let (_first_remote, first_local) = establish_sessions();
        let (_second_remote, second_local) = establish_sessions();
        let (_replay_remote, replay_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        for (token, session) in [("token-a", first_local), ("token-b", second_local)] {
            assert_eq!(
                transport
                    .stage_responder_session("peer-a", token.to_string(), session)
                    .await,
                ResponderSessionStage::Staged { had_active: true }
            );
            assert_eq!(
                transport.commit_responder_session("peer-a", token).await,
                ResponderSessionCommit::PendingConfirmation
            );
            assert_eq!(
                transport.confirm_responder_session("peer-a", token).await,
                ResponderSessionConfirmation::Promoted
            );
        }
        {
            let mut sessions = transport.sessions.lock().await;
            sessions
                .get_mut("peer-a")
                .unwrap()
                .previous
                .as_mut()
                .unwrap()
                .expires_at = Instant::now();
        }

        assert_eq!(
            transport
                .restage_cached_responder_session("peer-a", "token-a".to_string(), replay_local,)
                .await,
            ResponderSessionStage::StaleDuplicate
        );
    }

    #[tokio::test]
    async fn rolled_back_responder_token_stays_terminal() {
        let (_old_remote, old_local) = establish_sessions();
        let (_staged_remote, staged_local) = establish_sessions();
        let (_replay_remote, replay_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        assert_eq!(
            transport
                .stage_responder_session("peer-a", "rolled-back".to_string(), staged_local)
                .await,
            ResponderSessionStage::Staged { had_active: true }
        );
        assert!(
            transport
                .discard_responder_session("peer-a", "rolled-back")
                .await
        );
        assert_eq!(
            transport
                .restage_cached_responder_session(
                    "peer-a",
                    "rolled-back".to_string(),
                    replay_local,
                )
                .await,
            ResponderSessionStage::StaleDuplicate
        );
    }

    #[tokio::test]
    async fn expired_pending_wireguard_session_cannot_be_probe_confirmed() {
        let (mut old_remote, old_local) = establish_sessions();
        let (_expired_remote, expired_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;
        assert_eq!(
            transport
                .stage_responder_session(
                    "peer-a",
                    "expired-pending".to_string(),
                    expired_local.with_thresholds(
                        u64::MAX,
                        Duration::MAX,
                        u64::MAX,
                        Duration::from_millis(1),
                    ),
                )
                .await,
            ResponderSessionStage::Staged { had_active: true }
        );
        assert_eq!(
            transport
                .commit_responder_session("peer-a", "expired-pending")
                .await,
            ResponderSessionCommit::PendingConfirmation
        );
        tokio::time::sleep(Duration::from_millis(5)).await;

        assert_eq!(
            transport
                .confirm_responder_session("peer-a", "expired-pending")
                .await,
            ResponderSessionConfirmation::Expired
        );
        assert!(transport
            .promoted_responder_tokens
            .lock()
            .await
            .get("peer-a")
            .is_none());

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x4646,
            1,
            b"old-session-remains-active",
        );
        let encrypted = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: packet.clone(),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            old_remote
                .decrypt_from_bytes(&encrypted.wire_bytes)
                .unwrap(),
            packet
        );
    }

    #[tokio::test]
    async fn multiple_responder_tokens_do_not_overwrite_and_exact_receiver_index_wins() {
        let (_old_remote, old_local) = establish_sessions();
        let (_first_remote, first_local) = establish_sessions();
        let (mut second_remote, second_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        for (token, session) in [
            ("token-1".to_string(), first_local),
            ("token-2".to_string(), second_local),
        ] {
            assert_eq!(
                transport
                    .stage_responder_session("peer-a", token.clone(), session)
                    .await,
                ResponderSessionStage::Staged { had_active: true }
            );
            assert_eq!(
                transport.commit_responder_session("peer-a", &token).await,
                ResponderSessionCommit::PendingConfirmation
            );
        }

        let confirmation = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x5656,
            2,
            b"second-token-wins",
        );
        let wire = second_remote.encrypt_to_bytes(&confirmation).unwrap();
        assert_eq!(
            transport
                .decrypt_inbound(&wire)
                .await
                .unwrap()
                .unwrap()
                .packet,
            confirmation
        );
        assert!(
            !transport
                .session_status("peer-a")
                .await
                .has_pending_responder
        );

        let outbound = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x5656,
            3,
            b"selected-token-outbound",
        );
        let encrypted = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: outbound.clone(),
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            second_remote
                .decrypt_from_bytes(&encrypted.wire_bytes)
                .unwrap(),
            outbound
        );
    }

    #[tokio::test]
    async fn queued_packet_holds_counter_lock_until_network_send_finishes() {
        let (mut remote, local) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local).await;

        let first = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x6666,
            0,
            b"queued-before-immediate",
        );
        assert!(transport
            .enqueue_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: first.clone(),
            })
            .await
            .unwrap());

        let second = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x6666,
            1,
            b"queued-before-immediate",
        );
        let (emitted_tx, mut emitted_rx) = mpsc::channel(1);
        let immediate = tokio::spawn({
            let transport = transport.clone();
            let second = second.clone();
            async move {
                transport
                    .encrypt_and_emit_outbound(
                        OutboundPacket {
                            peer_id: "peer-a".to_string(),
                            dst_ip: "10.20.0.1".to_string(),
                            packet: second,
                        },
                        move |encrypted| async move {
                            emitted_tx.send(encrypted).await.map_err(|_| {
                                DaemonError::Network("test emit channel closed".to_string())
                            })
                        },
                    )
                    .await
            }
        });

        assert!(tokio::time::timeout(Duration::from_millis(20), emitted_rx.recv())
            .await
            .is_err());

        let queued = encrypted_rx.recv().await.unwrap();
        assert_eq!(remote.decrypt_from_bytes(&queued.wire_bytes).unwrap(), first);
        // The real network worker releases the guard only after its send and
        // retry loop has completed. Dropping the test wrapper models that point.
        drop(queued);

        let emitted = tokio::time::timeout(Duration::from_secs(1), emitted_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            remote.decrypt_from_bytes(&emitted.wire_bytes).unwrap(),
            second
        );
        assert!(immediate.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn dead_peer_egress_lock_is_pruned_during_later_peer_churn() {
        let (_remote, local) = establish_sessions();
        let (transport, mut encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local).await;
        assert!(transport
            .enqueue_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: Ipv4Packet::build_icmp_echo_request(
                    Ipv4Addr::new(10, 20, 0, 2),
                    Ipv4Addr::new(10, 20, 0, 1),
                    0x6565,
                    0,
                    b"peer-churn-lock-cleanup",
                ),
            })
            .await
            .unwrap());

        transport.remove_session("peer-a").await;
        assert!(transport
            .outbound_emit_locks
            .lock()
            .await
            .contains_key("peer-a"));

        let queued = encrypted_rx.recv().await.unwrap();
        drop(queued);
        let later_peer_lock = transport.outbound_emit_lock("peer-b").await;
        drop(later_peer_lock);

        assert!(!transport
            .outbound_emit_locks
            .lock()
            .await
            .contains_key("peer-a"));
    }

    #[tokio::test]
    async fn immediate_emit_lock_prevents_low_counter_from_falling_behind_sixty_five_packets() {
        let (mut remote, local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local).await;
        let (emitted_tx, mut emitted_rx) = mpsc::channel(128);
        let (started_tx, started_rx) = oneshot::channel();
        let release = Arc::new(Notify::new());

        let first_worker = tokio::spawn({
            let transport = transport.clone();
            let emitted_tx = emitted_tx.clone();
            let release = release.clone();
            async move {
                transport
                    .encrypt_and_emit_outbound(
                        OutboundPacket {
                            peer_id: "peer-a".to_string(),
                            dst_ip: "10.20.0.1".to_string(),
                            packet: Ipv4Packet::build_icmp_echo_request(
                                Ipv4Addr::new(10, 20, 0, 2),
                                Ipv4Addr::new(10, 20, 0, 1),
                                0x6767,
                                0,
                                b"ordered-emit",
                            ),
                        },
                        move |encrypted| async move {
                            let _ = started_tx.send(());
                            release.notified().await;
                            emitted_tx.send(encrypted).await.map_err(|_| {
                                DaemonError::Network("test emit channel closed".to_string())
                            })
                        },
                    )
                    .await
            }
        });
        started_rx.await.unwrap();

        let later_worker = tokio::spawn({
            let transport = transport.clone();
            let emitted_tx = emitted_tx.clone();
            async move {
                for sequence in 1..=65u16 {
                    let emitted_tx = emitted_tx.clone();
                    transport
                        .encrypt_and_emit_outbound(
                            OutboundPacket {
                                peer_id: "peer-a".to_string(),
                                dst_ip: "10.20.0.1".to_string(),
                                packet: Ipv4Packet::build_icmp_echo_request(
                                    Ipv4Addr::new(10, 20, 0, 2),
                                    Ipv4Addr::new(10, 20, 0, 1),
                                    0x6767,
                                    sequence,
                                    b"ordered-emit",
                                ),
                            },
                            move |encrypted| async move {
                                emitted_tx.send(encrypted).await.map_err(|_| {
                                    DaemonError::Network("test emit channel closed".to_string())
                                })
                            },
                        )
                        .await?;
                }
                Result::<()>::Ok(())
            }
        });

        assert!(
            tokio::time::timeout(Duration::from_millis(20), emitted_rx.recv())
                .await
                .is_err()
        );
        release.notify_one();
        assert!(first_worker.await.unwrap().unwrap());
        later_worker.await.unwrap().unwrap();
        drop(emitted_tx);

        for sequence in 0..=65u16 {
            let encrypted = emitted_rx.recv().await.unwrap();
            let expected = Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 2),
                Ipv4Addr::new(10, 20, 0, 1),
                0x6767,
                sequence,
                b"ordered-emit",
            );
            assert_eq!(
                remote.decrypt_from_bytes(&encrypted.wire_bytes).unwrap(),
                expected
            );
        }
    }

    #[tokio::test]
    async fn initial_wireguard_confirmation_promotes_matching_probe_binding() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        assert_eq!(
            transport
                .stage_responder_session("peer-a", "initial-token".to_string(), local_session,)
                .await,
            ResponderSessionStage::Staged { had_active: false }
        );
        assert_eq!(
            transport
                .commit_responder_session("peer-a", "initial-token")
                .await,
            ResponderSessionCommit::ActivatedInitial
        );

        let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
        let peers = Arc::new(PeerManager::new(config));
        let probe_identity = NodeIdentity::generate();
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                public_key: hex::encode(probe_identity.public_key()),
                virtual_ip: "10.20.0.1".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        assert_eq!(
            peers
                .stage_probe_session_binding(
                    "peer-a",
                    "initial-token".to_string(),
                    Some("initial-session".to_string()),
                    Some([9u8; 32]),
                    true,
                )
                .await,
            ProbeBindingStage::Staged
        );
        let expected_probe_key = peers
            .probe_key_candidates_for_peer("peer-a")
            .await
            .into_iter()
            .find_map(|candidate| {
                matches!(candidate.role, ProbeKeyRole::Pending { .. }).then_some(candidate.key)
            })
            .unwrap();

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x4444,
            1,
            crate::REKEY_CONFIRMATION_PAYLOAD,
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers))
                    .await
            }
        });
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_peer_id: Some("peer-a".to_string()),
                wire_bytes,
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), inbound_rx.recv())
                .await
                .is_err()
        );
        assert_eq!(
            peers.probe_key_for_peer("peer-a").await,
            Some(expected_probe_key)
        );
        let connection = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(connection.state, ConnectionState::Idle);
        assert_eq!(connection.relay_server, None);

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rekey_uses_new_session_for_outbound_packets() {
        let (_old_remote, old_local) = establish_sessions();
        let (mut new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;
        transport.add_session("peer-a", new_local).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            4,
            b"new-outbound",
        );
        let encrypted = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: packet.clone(),
            })
            .await
            .unwrap()
            .expect("active rekey session should encrypt outbound traffic");
        assert_eq!(
            new_remote
                .decrypt_from_bytes(&encrypted.wire_bytes)
                .unwrap(),
            packet
        );
    }

    #[tokio::test]
    async fn decrypts_inbound_packet_with_matching_receiver_index() {
        let (mut node_a_session, node_b_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", node_b_session).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&packet).unwrap();

        let inbound = transport
            .decrypt_inbound(&wire_bytes)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(inbound.peer_id, "peer-a");
        assert_eq!(inbound.packet, packet);
    }

    #[tokio::test]
    async fn confirms_relay_only_after_wireguard_decryption() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.1".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers))
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_peer_id: Some("peer-a".to_string()),
                wire_bytes,
            })
            .await
            .unwrap();
        let inbound = inbound_rx.recv().await.unwrap();
        assert_eq!(inbound.peer_id, "peer-a");

        let conn = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Relay);
        assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
        assert_eq!(conn.relay_server.as_deref(), Some("tls://relay.test:443"));

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relay_validation_echo_reply_records_peer_rtt() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.1".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let payload = build_relay_validation_payload(unix_time_millis().saturating_sub(42));
        let mut packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            &payload,
        );
        packet[20] = 0;
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers))
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_peer_id: Some("peer-a".to_string()),
                wire_bytes,
            })
            .await
            .unwrap();
        assert_eq!(inbound_rx.recv().await.unwrap().peer_id, "peer-a");

        let conn = peers.get_connection("peer-a").await.unwrap();
        let latency = conn.relay_health.latency_ms.unwrap();
        assert!(latency >= 42);
        assert!(latency < 1_000);
        assert_eq!(conn.relay_health.rtt_ewma_ms, Some(latency));

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_relay_source_that_does_not_match_decrypted_peer() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("http://ctrl.test", "default").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.1".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers))
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_peer_id: Some("different-peer".to_string()),
                wire_bytes,
            })
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), inbound_rx.recv())
                .await
                .is_err()
        );

        let conn = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(conn.state, ConnectionState::Idle);
        assert_eq!(conn.relay_server, None);

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn drops_inbound_packet_without_matching_session() {
        let (mut node_a_session, _node_b_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );
        let wire_bytes = node_a_session.encrypt_to_bytes(&packet).unwrap();

        let inbound = transport.decrypt_inbound(&wire_bytes).await.unwrap();
        assert!(inbound.is_none());
    }
}
