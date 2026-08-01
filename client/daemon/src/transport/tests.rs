#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::Ipv4Packet;
    use p2pnet_wireguard::{
        HandshakeInitiator, HandshakeResponder, TransportSession, TYPE_TRANSPORT,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::{ConnectionState, NetworkPath};

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
        assert!(!transport.has_session("peer-a").await);
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
