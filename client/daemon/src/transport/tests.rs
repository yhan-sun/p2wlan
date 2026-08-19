#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use p2pnet_crypto::NodeIdentity;
    use p2pnet_tun::Ipv4Packet;
    use p2pnet_wireguard::{
        HandshakeInitiator, HandshakeResponder, MessageTransport, TransportSession,
    };
    use tokio::sync::{mpsc, oneshot, watch, Notify, RwLock};

    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::peer::{ConnectionState, NetworkPath, ProbeBindingStage, ProbeKeyRole};
    use crate::udp::UdpTransport;
    use tokio::time::{sleep, timeout};

    #[test]
    fn first_usable_evidence_requires_a_decrypted_overlay_ip_packet() {
        assert!(!is_real_overlay_business_packet(&[]));
        assert!(!is_real_overlay_business_packet(&[0u8; 32]));

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            7,
            1,
            b"real-tun-business",
        );
        assert!(is_real_overlay_business_packet(&packet));
    }

    #[test]
    fn relay_validation_echo_is_not_first_usable_business_evidence() {
        let payload = build_relay_validation_payload(unix_time_millis().saturating_sub(42));
        let request = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            &payload,
        );
        let mut reply = request.clone();
        // The ICMP type byte follows the 20-byte IPv4 header.
        reply[20] = 0;

        assert!(!is_real_overlay_business_packet(&request));
        assert!(!is_real_overlay_business_packet(&reply));
        assert!(relay_validation_rtt(&reply).is_some());
        assert!(relay_validation_rtt(&request).is_none());
    }

    #[test]
    fn daemon_internal_validation_and_relay_probe_are_not_business_evidence() {
        for kind in [DirectValidationKind::Request, DirectValidationKind::Ack] {
            let packet = Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 1),
                Ipv4Addr::new(10, 20, 0, 2),
                0x1234,
                1,
                &build_direct_validation_payload(kind, 7, 0x1234, 1, 9),
            );
            assert!(parse_direct_validation_token(&packet).is_some());
            assert!(!is_real_overlay_business_packet(&packet));
        }

        let relay_probe = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x4321,
            1,
            &crate::relay_probe::build_relay_probe_payload(
                crate::relay_probe::RelayProbeKind::Request,
                7,
                0x4321,
                9,
            ),
        );
        assert!(crate::relay_probe::parse_relay_probe_token(&relay_probe).is_some());
        assert!(!is_real_overlay_business_packet(&relay_probe));
    }

    #[test]
    fn wire_counter_extracts_only_wireguard_transport_headers() {
        let message = MessageTransport {
            receiver_index: 0x1122_3344,
            counter: 0x8877_6655_4433_2211,
            encrypted_payload: vec![0xaa; 16],
        };
        let bytes = message.to_bytes();
        assert_eq!(wire_counter(&bytes), Some(message.counter));
        assert_eq!(wire_counter(&bytes[..15]), None);
        assert_eq!(wire_counter(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]), None);
    }

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
    async fn run_outbound_forwards_raw_packet_without_encrypting() {
        // The transport no longer encrypts on the dataplane path: run_outbound
        // forwards the RAW packet to the network outbound worker, which is the
        // only place that encrypts business packets (and only once the peer's
        // path is usable).
        let (_node_a_session, _node_b_session) = establish_sessions();
        let (transport, mut outbound_rx) = WireGuardTransport::new();

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"ping",
        );

        let (outbound_tx, dataplane_rx) = mpsc::channel(4);
        let worker = {
            let transport = transport.clone();
            tokio::spawn(async move { transport.run_outbound(dataplane_rx).await })
        };

        outbound_tx
            .send(OutboundPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: packet.clone(),
            })
            .await
            .unwrap();

        let raw = tokio::time::timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .expect("the worker receiver must get the forwarded RAW packet")
            .expect("channel open");
        assert_eq!(raw.peer_id, "peer-b");
        assert_eq!(raw.dst_ip, "10.20.0.2");
        assert_eq!(raw.packet, packet);
        assert!(
            outbound_rx.try_recv().is_err(),
            "no encrypted packet may appear on the worker channel"
        );

        drop(outbound_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn worker_encrypt_does_not_wait_for_ingress_when_session_is_missing() {
        // remove_session owns ingress before it waits for emit.  The
        // production network worker must therefore never try to enter the
        // legacy session queue while it owns emit, otherwise the two paths
        // form an ingress -> emit / emit -> ingress deadlock.
        let (transport, _outbound_rx) = WireGuardTransport::new();
        let ingress_lock = transport.outbound_ingress_lock("peer-missing").await;
        let _ingress_guard = ingress_lock.lock().await;
        let packet = OutboundPacket {
            peer_id: "peer-missing".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 1),
                Ipv4Addr::new(10, 20, 0, 2),
                0x1234,
                1,
                b"missing-session",
            ),
        };
        let result = timeout(
            Duration::from_millis(100),
            transport.encrypt_outbound_with_guard(packet),
        )
        .await
        .expect("missing-session handling must not wait on the ingress lock")
        .expect("missing-session handling is not an encryption error");
        assert!(result.is_none());
        assert!(!transport
            .pending_outbound
            .lock()
            .await
            .contains_key("peer-missing"));
    }

    #[tokio::test]
    async fn session_queue_loss_event_has_generation_and_timeline_context() {
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let timeline = crate::connection_timeline::ConnectionTimeline::new("node-a", 0x42);
        let sink = Arc::new(tokio::sync::Mutex::new(
            crate::peer::OutboundLossCounters::default(),
        ));
        transport.set_outbound_loss_sink(Some(sink.clone()));
        transport.set_outbound_loss_context(&peers, timeline.clone());
        let generation = peers.advance_network_generation("session_queue_test").await;

        let packet = OutboundPacket {
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: vec![1, 2, 3, 4],
        };
        assert!(transport
            .encrypt_or_queue_outbound(packet)
            .await
            .unwrap()
            .is_none());
        transport.remove_session("peer-a").await;

        let loss = sink.lock().await;
        let event = loss.events.last().expect("session queue loss is audited");
        assert_eq!(event.peer_id, "peer-a");
        assert_eq!(event.generation, generation);
        assert_eq!(event.reason_code, REASON_SESSION_QUEUE_REMOVED);
        assert_eq!(event.correlation_id, timeline.correlation_id());
        assert!(event.at_ms <= timeline.uptime_ms());
        assert_eq!(event.packets, 1);
        assert_eq!(event.bytes, 4);
    }

    #[tokio::test]
    async fn drops_outbound_packet_without_session() {
        let (transport, mut outbound_rx) = WireGuardTransport::new();

        let dropped = transport
            .encrypt_outbound(OutboundPacket {
                peer_id: "missing-peer".to_string(),
                dst_ip: "10.20.0.9".to_string(),
                packet: vec![0x45, 0x00, 0x00, 0x14],
            })
            .await
            .unwrap();

        assert!(dropped.is_none());
        assert!(outbound_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn session_install_cannot_miss_packet_queued_in_the_handoff_window() {
        let (_remote_session, local_session) = establish_sessions();
        let (transport, mut outbound_rx) = WireGuardTransport::new();
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

        // The session commit must forward the RAW queued packet to the
        // network outbound worker (never lose it in the handoff window, and
        // never encrypt it before the worker decides the path is usable).
        let raw = tokio::time::timeout(Duration::from_secs(1), outbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw.peer_id, "peer-a");
        assert_eq!(raw.packet, packet);
        assert!(queue_task.await.unwrap().unwrap().is_none());
        install_task.await.unwrap();
    }

    #[tokio::test]
    async fn pending_flush_forwards_raw_packets_in_fifo_order_and_encrypts_monotonic() {
        let (_remote_session, local_session) = establish_sessions();
        let (transport, mut outbound_rx) = WireGuardTransport::new();
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

        let (outbound_tx, dataplane_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = transport.clone();
            async move { transport.run_outbound(dataplane_rx).await }
        });
        let live_packet = OutboundPacket {
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.1".to_string(),
            packet: Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 2),
                Ipv4Addr::new(10, 20, 0, 1),
                0x1212,
                96,
                b"live",
            ),
        };
        // Install first so the session flush (queued 0..95, forwarded in FIFO)
        // deterministically precedes the live dataplane packet on the worker
        // channel — exactly the order a single worker must preserve.
        transport.add_session("peer-a", local_session).await;
        outbound_tx.send(live_packet.clone()).await.unwrap();

        // The session flush and the live dataplane packets arrive at the
        // worker as RAW packets in FIFO order (session queue first, live
        // packet last) — the worker's order is preserved end to end.
        let mut received = Vec::new();
        for _ in 0..97 {
            let raw = tokio::time::timeout(Duration::from_secs(1), outbound_rx.recv())
                .await
                .expect("the worker channel must deliver the forwarded packet")
                .expect("channel open");
            let parsed = Ipv4Packet::new(&raw.packet).unwrap();
            let icmp = parsed.payload();
            // ICMP echo header: type(1) code(1) checksum(2) id(2) seq(2)
            let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
            received.push(sequence);
        }
        assert_eq!(received, (0..97u16).collect::<Vec<_>>());

        // Encrypting the forwarded packets in worker order allocates strictly
        // increasing counters: WireGuard order on the wire matches the FIFO.
        let mut counters = Vec::new();
        for raw in received {
            let packet = OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: Ipv4Packet::build_icmp_echo_request(
                    Ipv4Addr::new(10, 20, 0, 2),
                    Ipv4Addr::new(10, 20, 0, 1),
                    0x1212,
                    raw,
                    b"queued",
                ),
            };
            let (encrypted, _guard) = transport
                .encrypt_outbound_with_guard(packet)
                .await
                .expect("session must be ready")
                .expect("session must be ready");
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
    async fn session_flush_and_live_tun_share_one_per_peer_ingress_fifo() {
        // A session-ready flush and the live TUN bridge are two independent
        // producers of the transport's raw outbound channel.  Fill that
        // channel first so the flush is forced to wait while a live packet is
        // submitted concurrently; the per-peer ingress arbiter must keep the
        // live packet behind the older session backlog.
        let (_remote_session, local_session) = establish_sessions();
        let (transport, mut outbound_rx) = WireGuardTransport::new();
        for sequence in 0..96u16 {
            assert!(transport
                .encrypt_or_queue_outbound(OutboundPacket {
                    peer_id: "peer-a".to_string(),
                    dst_ip: "10.20.0.1".to_string(),
                    packet: Ipv4Packet::build_icmp_echo_request(
                        Ipv4Addr::new(10, 20, 0, 2),
                        Ipv4Addr::new(10, 20, 0, 1),
                        0x3131,
                        sequence,
                        b"session-backlog",
                    ),
                })
                .await
                .unwrap()
                .is_none());
        }

        let filler = OutboundPacket {
            peer_id: "filler".to_string(),
            dst_ip: "10.20.0.254".to_string(),
            packet: Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 1),
                Ipv4Addr::new(10, 20, 0, 254),
                0x3132,
                0,
                b"filler",
            ),
        };
        for _ in 0..1024 {
            transport
                .outbound_tx
                .try_send(filler.clone())
                .expect("the raw outbound channel capacity must be known to this regression");
        }

        let (live_tx, live_rx) = mpsc::channel(1);
        let forwarder = tokio::spawn({
            let transport = transport.clone();
            async move { transport.run_outbound(live_rx).await }
        });
        let install = tokio::spawn({
            let transport = transport.clone();
            async move { transport.add_session("peer-a", local_session).await }
        });

        // Wait until the session is installed and the flush has removed the
        // backlog from its map.  At this point its first raw send is blocked
        // by the full central channel, so the live producer is truly
        // concurrent with the flush rather than merely following it.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let active = transport.session_status("peer-a").await.has_active;
            let pending = transport
                .pending_outbound
                .lock()
                .await
                .contains_key("peer-a");
            if active && !pending {
                break;
            }
            assert!(std::time::Instant::now() < deadline);
            tokio::task::yield_now().await;
        }

        let live_packet = OutboundPacket {
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.1".to_string(),
            packet: Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 2),
                Ipv4Addr::new(10, 20, 0, 1),
                0x3131,
                96,
                b"live-tun",
            ),
        };
        live_tx.send(live_packet).await.unwrap();

        let mut peer_sequences = Vec::new();
        // Drain the 1024 filler frames plus the 96 queued frames and one live
        // frame.  Only the peer-a sequence is relevant; the order in which
        // the filler is drained is intentionally part of the backpressure.
        for _ in 0..(1024 + 96 + 1) {
            let packet = tokio::time::timeout(Duration::from_secs(3), outbound_rx.recv())
                .await
                .expect("raw outbound channel must drain")
                .expect("raw outbound channel must stay open");
            if packet.peer_id == "peer-a" {
                let ip = Ipv4Packet::new(&packet.packet).unwrap();
                let icmp = ip.payload();
                peer_sequences.push(u16::from_be_bytes([icmp[6], icmp[7]]));
            }
        }
        assert_eq!(peer_sequences, (0..97u16).collect::<Vec<_>>());

        install.await.unwrap();
        drop(live_tx);
        forwarder.abort();
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
    async fn active_session_replacement_waits_for_inflight_emit_guard() {
        let (_old_remote, old_local) = establish_sessions();
        let (mut new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        let (encrypted, emit_guard) = transport
            .encrypt_outbound_with_guard(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: Ipv4Packet::build_icmp_echo_request(
                    Ipv4Addr::new(10, 20, 0, 2),
                    Ipv4Addr::new(10, 20, 0, 1),
                    0x7a7a,
                    1,
                    b"inflight-before-rekey",
                ),
            })
            .await
            .expect("old session must encrypt")
            .expect("old session must be active");

        let mut replacement = tokio::spawn({
            let transport = transport.clone();
            async move { transport.install_active_session("peer-a", None, new_local).await }
        });
        assert!(
            timeout(Duration::from_millis(30), &mut replacement)
                .await
                .is_err(),
            "session replacement must not publish a new key while an old-key packet still owns the emit lock"
        );
        assert!(transport.has_session("peer-a").await);

        drop(encrypted);
        drop(emit_guard);
        assert!(
            timeout(Duration::from_secs(1), &mut replacement)
                .await
                .expect("replacement must complete after the in-flight send releases")
                .expect("replacement task must not panic")
        );

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x7a7a,
            2,
            b"after-rekey",
        );
        let wire_bytes = new_remote.encrypt_to_bytes(&packet).unwrap();
        let inbound = transport
            .decrypt_inbound(&wire_bytes)
            .await
            .expect("new active session must decrypt")
            .expect("new active session must be present");
        assert_eq!(inbound.packet, packet);
        assert!(!inbound.from_previous_session);
    }

    #[tokio::test]
    async fn evidence_commit_fence_rejects_replaced_session() {
        let (mut old_remote, old_local) = establish_sessions();
        let (_new_remote, new_local) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", old_local).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x7b7b,
            1,
            b"evidence-before-rekey",
        );
        let wire_bytes = old_remote.encrypt_to_bytes(&packet).unwrap();
        let inbound = transport
            .decrypt_inbound(&wire_bytes)
            .await
            .expect("old session must decrypt")
            .expect("inbound packet must be present");
        let session_instance = inbound.session_instance.expect("session instance");

        // This is the exact boundary used by inbound path/evidence commits:
        // a rekey cannot publish a new active key until the old packet has
        // finished its state mutation.
        let evidence_guard = transport
            .acquire_current_session_evidence_guard("peer-a", Some(session_instance))
            .await
            .expect("the active session must be eligible before replacement");
        let mut replacement = tokio::spawn({
            let transport = transport.clone();
            async move { transport.install_active_session("peer-a", None, new_local).await }
        });
        assert!(
            timeout(Duration::from_millis(30), &mut replacement)
                .await
                .is_err(),
            "session replacement must wait for the evidence commit fence"
        );
        drop(evidence_guard);
        assert!(
            timeout(Duration::from_secs(1), &mut replacement)
                .await
                .expect("replacement must complete after evidence commit")
                .expect("replacement task must not panic")
        );
        assert!(
            !transport
                .session_instance_is_current("peer-a", Some(session_instance))
                .await,
            "the old session must not remain eligible after replacement"
        );
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
        assert!(inbound.from_previous_session);
        let old_instance = inbound.session_instance.expect("session instance");

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
        assert!(!inbound.from_previous_session);
        assert!(inbound.session_instance.is_some());
        assert_eq!(
            transport.session_instance_state("peer-a", old_instance).await,
            (true, false),
            "the old overlap key remains receive-only and cannot be current evidence"
        );

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
        assert!(inbound.from_previous_session);

        transport.remove_session("peer-a").await;
        assert_eq!(
            transport.session_instance_state("peer-a", old_instance).await,
            (false, false),
            "removing a peer must retire every old session instance"
        );
    }

    #[tokio::test]
    async fn queued_packet_from_old_network_generation_is_dropped_before_delivery() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let old_generation = peers.current_network_generation_sync();
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x4A11,
            1,
            b"queued-before-network-handover",
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);

        // Stamp the packet at the encrypted-ingress boundary, then advance the
        // manager before the worker is allowed to consume it. This is the
        // exact queue race that previously let an old datagram be attributed
        // to the new generation after decryption.
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_connection_id: None,
                relay_peer_id: Some("peer-a".to_string()),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: Some(old_generation),
                wire_bytes,
            })
            .await
            .unwrap();
        let new_generation = peers.advance_network_generation("queued_packet_handover").await;
        assert_eq!(new_generation, old_generation + 1);

        let worker = tokio::spawn({
            let transport = transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), None)
                    .await
            }
        });
        drop(encrypted_tx);
        timeout(Duration::from_secs(2), worker)
            .await
            .expect("stale-generation worker must finish")
            .unwrap()
            .unwrap();

        assert!(
            inbound_rx.try_recv().is_err(),
            "a packet stamped by the old generation must not reach the TUN"
        );
        let connection = peers.get_connection("peer-a").await.unwrap();
        assert!(connection.first_usable_at.is_none());
        assert!(connection.first_usable_path.is_none());
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
        assert!(
            !encrypted.is_business,
            "generic/control encryption must not advance relay-first business admission"
        );
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
        assert!(
            !transport
                .session_status("peer-a")
                .await
                .has_pending_responder
        );

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
                        Duration::from_millis(100),
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
        tokio::time::sleep(Duration::from_millis(150)).await;

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
        let (transport, _outbound_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local).await;

        let first = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x6666,
            0,
            b"queued-before-immediate",
        );
        let (encrypted_first, guard) = transport
            .encrypt_outbound_with_guard(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: first.clone(),
            })
            .await
            .expect("session ready")
            .expect("session ready");
        assert!(
            encrypted_first.is_business,
            "the guarded production TUN path must carry the business marker"
        );

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

        assert!(
            tokio::time::timeout(Duration::from_millis(20), emitted_rx.recv())
                .await
                .is_err(),
            "a later control packet must not be encrypted while a queued business packet's guard is held"
        );

        // The queued packet's guard is released only after its network send
        // completes (here: when the worker's send is done).  Only then can the
        // control packet be encrypted — its counter is strictly higher, so the
        // wire order always matches the counter order.
        assert_eq!(
            remote
                .decrypt_from_bytes(&encrypted_first.wire_bytes)
                .unwrap(),
            first
        );
        drop(encrypted_first);
        drop(guard);

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
    async fn direct_validation_lock_contention_is_bounded_below_slow_rtt_floor() {
        let (transport, _outbound_rx) = WireGuardTransport::new();
        let emit_lock = transport.outbound_emit_lock("peer-a").await;
        let _guard = emit_lock.lock().await;
        let started = std::time::Instant::now();

        let emitted = transport
            .encrypt_and_emit_outbound_with_lock_timeout(
                OutboundPacket {
                    peer_id: "peer-a".to_string(),
                    dst_ip: "10.20.0.1".to_string(),
                    packet: vec![0],
                },
                DIRECT_VALIDATION_EMIT_LOCK_TIMEOUT,
                |_encrypted| async { Ok(()) },
            )
            .await
            .expect("lock contention must be a terminal skipped attempt, not an error");

        assert_eq!(
            emitted,
            BoundedEmitOutcome::LockTimeout,
            "a validation packet cannot bypass a held counter lock"
        );
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "Direct validation lock contention must not be measured as a 500ms path RTT"
        );
    }

    #[tokio::test]
    async fn dead_peer_egress_lock_is_pruned_during_later_peer_churn() {
        let (_remote, local) = establish_sessions();
        let (transport, _outbound_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local).await;
        let (encrypted, guard) = transport
            .encrypt_outbound_with_guard(OutboundPacket {
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
            .expect("session ready")
            .expect("session ready");

        let removal = tokio::spawn({
            let transport = transport.clone();
            async move { transport.remove_session("peer-a").await }
        });
        let mut removal = removal;
        assert!(
            timeout(Duration::from_millis(30), &mut removal)
                .await
                .is_err(),
            "session removal must wait for the in-flight emit guard"
        );
        assert!(transport.has_session("peer-a").await);
        assert!(transport
            .outbound_emit_locks
            .lock()
            .await
            .contains_key("peer-a"));

        drop(encrypted);
        drop(guard);
        timeout(Duration::from_secs(1), &mut removal)
            .await
            .expect("session removal must complete after the emit guard is released")
            .expect("session removal task must not panic");
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
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), None)
                    .await
            }
        });
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_connection_id: None,
                relay_peer_id: Some("peer-a".to_string()),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
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
    async fn confirms_relay_after_decrypted_business_ingress() {
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
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), None)
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_connection_id: None,
                relay_peer_id: Some("peer-a".to_string()),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
                wire_bytes,
            })
            .await
            .unwrap();
        let inbound = inbound_rx.recv().await.unwrap();
        assert_eq!(inbound.peer_id, "peer-a");

        let conn = peers.get_connection("peer-a").await.unwrap();
        // This is a real encrypted overlay packet received through the
        // current relay envelope, so it is an end-to-end business echo.  It
        // may confirm relay before the separate forced-relay probe ACK; a
        // local TCP write or queue counter would not be sufficient here.
        assert_eq!(conn.state, ConnectionState::Relay);
        assert_eq!(conn.active_path(), Some(NetworkPath::Relay));
        assert_eq!(conn.relay_confirmed_generation, Some(0));
        assert!(conn.relay_confirmed_at.is_some());
        assert_eq!(conn.relay_server.as_deref(), Some("tls://relay.test:443"));

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn relay_business_ingress_records_first_usable_even_before_probe_ack() {
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

        let relay = crate::relay::RelayTransport::connect_for_test(
            "test",
            "tls://relay.test:443",
            peers.clone(),
        );
        let relay_connection_id = relay.connection_id();
        let timeline = crate::connection_timeline::ConnectionTimeline::new("node-a", 1);
        // The production daemon installs the same timeline on PeerManager and
        // on the inbound evidence feed.  Keep the test wired the same way so
        // the manager's first_usable_path milestone and the transport's
        // first_real_business_ingress event are asserted against one audit
        // stream.
        peers.set_timeline(timeline.clone());
        let evidence = InboundEvidenceFeed {
            relay_transport: Arc::new(RwLock::new(Some(relay))),
            timeline: Some(timeline.clone()),
            overlay_ingress_tx: None,
        };

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x4321,
            7,
            b"business-before-relay-probe-ack",
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
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

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_connection_id: Some(relay_connection_id),
                relay_peer_id: Some("peer-a".to_string()),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: Some(0),
                wire_bytes,
            })
            .await
            .unwrap();

        let inbound = inbound_rx.recv().await.unwrap();
        assert_eq!(inbound.peer_id, "peer-a");
        let connection = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(connection.relay_confirmed_generation, Some(0));
        assert_eq!(
            connection.relay_confirmed_connection_id,
            Some(relay_connection_id)
        );
        assert_eq!(connection.relay_first.business_received_generation, Some(0));
        assert_eq!(connection.first_usable_generation, Some(0));
        assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));

        let events = timeline.snapshot().events;
        assert!(events.iter().any(|event| {
            event.event == "business_ingress_observed"
                && event.path.as_deref() == Some("relay")
                && event.reason_code.as_deref() == Some("first_usable_recorded")
                && event.connection_generation == Some(0)
                && event.relay_id.as_deref() == Some("tls://relay.test:443")
        }));
        assert!(events.iter().any(|event| {
            event.event == "first_real_business_ingress" && event.path.as_deref() == Some("relay")
        }));
        assert!(events
            .iter()
            .any(|event| event.event == "first_usable_path" && event.path.as_deref() == Some("relay")));

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn direct_first_gate_rejection_does_not_hide_later_relay_ingress() {
        let (mut remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.1".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let relay_endpoint = "tls://relay.test:443";
        let relay = crate::relay::RelayTransport::connect_for_test(
            "test",
            relay_endpoint,
            peers.clone(),
        );
        let relay_connection_id = relay.connection_id();
        peers
            .mark_relay_transport_ready("peer-a", relay_endpoint, 0)
            .await;
        assert!(peers
            .confirm_relay_peer_with_transport(
                "peer-a",
                relay_endpoint,
                0,
                Some(relay_connection_id),
            )
            .await);

        let timeline = crate::connection_timeline::ConnectionTimeline::new("node-a", 1);
        peers.set_timeline(timeline.clone());
        let evidence = InboundEvidenceFeed {
            relay_transport: Arc::new(RwLock::new(Some(relay))),
            timeline: Some(timeline.clone()),
            overlay_ingress_tx: None,
        };

        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        udp.set_inbound_publication_owner(1);
        let local_endpoint = udp.local_addr().unwrap();
        let (_udp_updates_tx, udp_updates) = watch::channel(Some(udp));
        let (encrypted_tx, encrypted_rx) = mpsc::channel(2);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(2);
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

        let direct_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x6101,
            1,
            b"direct-first-gated",
        );
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some("198.51.100.10:51820".parse().unwrap()),
                local_endpoint: Some(local_endpoint),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: Some(1),
                network_generation: Some(0),
                wire_bytes: remote_session.encrypt_to_bytes(&direct_packet).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(inbound_rx.recv().await.unwrap().peer_id, "peer-a");
        assert_eq!(
            peers
                .get_connection("peer-a")
                .await
                .unwrap()
                .first_usable_path,
            None,
            "Direct business ingress before the relay-business gate is not first usable"
        );

        let relay_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x6102,
            1,
            b"relay-later-usable",
        );
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some(relay_endpoint.to_string()),
                relay_connection_id: Some(relay_connection_id),
                relay_peer_id: Some("peer-a".to_string()),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: Some(0),
                wire_bytes: remote_session.encrypt_to_bytes(&relay_packet).unwrap(),
            })
            .await
            .unwrap();
        assert_eq!(inbound_rx.recv().await.unwrap().peer_id, "peer-a");

        let connection = peers.get_connection("peer-a").await.unwrap();
        assert_eq!(connection.first_usable_generation, Some(0));
        assert_eq!(connection.first_usable_path, Some(NetworkPath::Relay));

        let events = timeline.snapshot().events;
        assert!(events.iter().any(|event| {
            event.event == "business_ingress_observed"
                && event.path.as_deref() == Some("direct")
                && event.reason_code.as_deref() == Some("first_usable_not_recorded")
        }));
        assert!(events.iter().any(|event| {
            event.event == "business_ingress_observed"
                && event.path.as_deref() == Some("relay")
                && event.reason_code.as_deref() == Some("first_usable_recorded")
                && event.relay_id.as_deref() == Some(relay_endpoint)
        }));
        assert!(events.iter().any(|event| {
            event.event == "first_usable_path" && event.path.as_deref() == Some("relay")
        }));

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
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), None)
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_connection_id: None,
                relay_peer_id: Some("peer-a".to_string()),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
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
        // Relay validation is daemon-internal health evidence only.  It must
        // never become the production first-usable business milestone; that
        // milestone requires a normal decrypted overlay packet.
        assert!(conn.first_usable_at.is_none());
        assert!(conn.first_usable_path.is_none());

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
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), None)
                    .await
            }
        });

        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: None,
                local_endpoint: None,
                relay_endpoint: Some("tls://relay.test:443".to_string()),
                relay_connection_id: None,
                relay_peer_id: Some("different-peer".to_string()),
                socket_index: None,
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
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

    #[tokio::test]
    async fn adopts_affinity_socket_only_after_wireguard_decryption() {
        // Raw encrypted UDP is never fresh affinity evidence: only a packet
        // that decrypts successfully may pin its receiving socket for the
        // peer.  Garbage (undecryptable) UDP must leave the affinity empty.
        let (mut remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: "peer-a-pubkey".to_string(),
                endpoint: "127.0.0.1:51820".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;

        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let (udp_inbound_tx, _udp_inbound_rx) = mpsc::channel(4);
        let udp = udp.with_inbound_channel(udp_inbound_tx);

        let (encrypted_tx, encrypted_rx) = mpsc::channel(2);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(2);
        let worker = tokio::spawn({
            let transport = wg_transport.clone();
            let peers = peers.clone();
            let udp = udp.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), Some(udp))
                    .await
            }
        });

        // 1. Undecryptable datagram claiming the socket: no affinity pin.
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some("198.51.100.7:51820".parse().unwrap()),
                local_endpoint: udp.local_addr().ok(),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
                wire_bytes: vec![0xAB; 64],
            })
            .await
            .unwrap();
        // Give the worker a deterministic window to process the garbage.
        sleep(Duration::from_millis(100)).await;
        {
            let pin = udp.affinity_pin_for_test("peer-a").await;
            assert!(
                pin.is_none(),
                "undecryptable raw UDP must never pin affinity evidence"
            );
        }

        // 2. A genuinely encrypted packet from the peer: after decryption the
        // receiving socket becomes the peer's fresh affinity pin.
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x5151,
            1,
            b"affinity",
        );
        let wire_bytes = remote_session.encrypt_to_bytes(&packet).unwrap();
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some("198.51.100.7:51820".parse().unwrap()),
                local_endpoint: udp.local_addr().ok(),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
                wire_bytes,
            })
            .await
            .unwrap();
        let inbound = tokio::time::timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .expect("decrypted packet must be emitted")
            .expect("channel closed");
        assert_eq!(inbound.peer_id, "peer-a");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let pin = udp.affinity_pin_for_test("peer-a").await;
                if pin.is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("decryption success must adopt the receiving socket");
        let pin = udp.affinity_pin_for_test("peer-a").await.unwrap();
        assert_eq!(
            pin.socket_index, 0,
            "the affinity must point at the socket that carried the decrypted packet"
        );

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn live_udp_inbound_uses_transport_published_after_worker_start() {
        let (mut remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: "peer-a-pubkey".to_string(),
                endpoint: "127.0.0.1:51820".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;

        let (udp_updates_tx, udp_updates_rx) = watch::channel(None);
        let (encrypted_tx, encrypted_rx) = mpsc::channel(2);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(2);
        let worker = tokio::spawn({
            let transport = wg_transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers_live_udp(
                        encrypted_rx,
                        inbound_tx,
                        Some(peers),
                        udp_updates_rx,
                    )
                    .await
            }
        });

        // The WireGuard worker is already alive with no UDP transport.  A
        // later publish must be observed for this packet, not discarded as a
        // startup-time `None` snapshot.
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        udp.set_inbound_publication_owner(1);
        let local_endpoint = udp.local_addr().unwrap();
        udp_updates_tx.send_replace(Some(udp.clone()));

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x5152,
            1,
            b"delayed-udp-publication",
        );
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some("198.51.100.8:51820".parse().unwrap()),
                local_endpoint: Some(local_endpoint),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: Some(1),
                network_generation: None,
                wire_bytes: remote_session.encrypt_to_bytes(&packet).unwrap(),
            })
            .await
            .unwrap();

        assert_eq!(
            timeout(Duration::from_secs(2), inbound_rx.recv())
                .await
                .unwrap()
                .unwrap()
                .peer_id,
            "peer-a"
        );
        assert!(
            udp.affinity_pin_for_test("peer-a").await.is_some(),
            "the delayed publication must supply affinity ownership"
        );

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn live_udp_inbound_reacquires_replacement_transport() {
        let (mut remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                device_name: String::new(),
                app_version: String::new(),
                public_key: "peer-a-pubkey".to_string(),
                endpoint: "127.0.0.1:51820".to_string(),
                nat_type: "Unknown".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                last_seen: 0,
                relay_rtt_ms: None,
            })
            .await;

        let stale_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let replacement_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        stale_udp.set_inbound_publication_owner(1);
        replacement_udp.set_inbound_publication_owner(2);
        let replacement_endpoint = replacement_udp.local_addr().unwrap();
        let (udp_updates_tx, udp_updates_rx) = watch::channel(Some(stale_udp.clone()));
        let (encrypted_tx, encrypted_rx) = mpsc::channel(2);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(2);
        let worker = tokio::spawn({
            let transport = wg_transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers_live_udp(
                        encrypted_rx,
                        inbound_tx,
                        Some(peers),
                        udp_updates_rx,
                    )
                    .await
            }
        });

        // Replace before the decrypted packet reaches the worker.  A static
        // snapshot would write the old transport's affinity; the live source
        // must use the new socket state.
        udp_updates_tx.send_replace(Some(replacement_udp.clone()));
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x5153,
            1,
            b"udp-replacement",
        );
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some("198.51.100.9:51820".parse().unwrap()),
                local_endpoint: Some(replacement_endpoint),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: Some(2),
                network_generation: None,
                wire_bytes: remote_session.encrypt_to_bytes(&packet).unwrap(),
            })
            .await
            .unwrap();

        let _ = timeout(Duration::from_secs(2), inbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(replacement_udp
            .affinity_pin_for_test("peer-a")
            .await
            .is_some());
        assert!(
            stale_udp.affinity_pin_for_test("peer-a").await.is_none(),
            "the retired UDP transport must not receive post-replacement affinity"
        );

        drop(encrypted_tx);
        worker.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn live_udp_inbound_rejects_queued_retired_owner_validation_ack() {
        // An old UDP reader can enqueue a packet just before its transport is
        // withdrawn. Hold the WireGuard session lock so the packet cannot
        // finish decrypting until after publication has moved to a replacement.
        // Its token intentionally matches the replacement's live expectation:
        // only the envelope's publication owner can distinguish this stale
        // reader from a packet actually received by the replacement socket.
        let (mut remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let source: std::net::SocketAddr = "198.51.100.73:51820".parse().unwrap();
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                endpoint: "198.51.100.72:51820".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;

        let stale_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        stale_udp.set_inbound_publication_owner(1);
        // Binding this transport registers the replacement validation registry.
        let replacement_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        replacement_udp.set_inbound_publication_owner(2);
        let generation = peers.current_network_generation().await;
        let owner_token = match replacement_udp
            .begin_or_merge_direct_validation("peer-a", source, generation)
            .await
        {
            crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
            _ => panic!("replacement transport must own the validation lease"),
        };
        let request_id = 0x7A21;
        assert!(
            replacement_udp
                .expect_direct_validation_ack_owned(
                    "peer-a",
                    request_id,
                    generation,
                    owner_token,
                    source,
                )
                .await
        );

        let stale_local_endpoint = stale_udp.local_addr().unwrap();
        let (udp_updates_tx, udp_updates_rx) = watch::channel(Some(stale_udp.clone()));
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = wg_transport.clone();
            let peers = peers.clone();
            async move {
                transport
                    .run_inbound_with_peers_live_udp(
                        encrypted_rx,
                        inbound_tx,
                        Some(peers),
                        udp_updates_rx,
                    )
                    .await
            }
        });

        let decrypt_gate = wg_transport.sessions.lock().await;
        let ack_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            request_id,
            0,
            &build_direct_validation_payload(
                DirectValidationKind::Ack,
                generation,
                request_id,
                0,
                owner_token,
            ),
        );
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some(source),
                local_endpoint: Some(stale_local_endpoint),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: Some(1),
                network_generation: None,
                wire_bytes: remote_session.encrypt_to_bytes(&ack_packet).unwrap(),
            })
            .await
            .unwrap();

        // This mirrors UdpTransportPublication::publish: revoke the old
        // reader's owner before exposing the replacement to live inbound.
        assert!(stale_udp.clear_inbound_publication_owner_if_matches(1));
        udp_updates_tx.send_replace(Some(replacement_udp.clone()));
        drop(decrypt_gate);
        drop(encrypted_tx);
        timeout(Duration::from_secs(2), worker)
            .await
            .expect("inbound worker must drain the retired reader packet")
            .unwrap()
            .unwrap();

        assert!(
            inbound_rx.recv().await.is_none(),
            "internal validation ACKs must stay off the TUN path"
        );
        let connection = peers.get_connection("peer-a").await.unwrap();
        assert_ne!(connection.state, ConnectionState::Direct);
        assert_eq!(connection.direct_health.success_count, 0);
        assert_ne!(connection.endpoint, Some(source));
        assert!(
            replacement_udp
                .has_direct_validation_expectation("peer-a")
                .await,
            "a queued packet from a retired reader must not consume the replacement expectation"
        );
        assert!(
            replacement_udp
                .affinity_pin_for_test("peer-a")
                .await
                .is_none(),
            "a retired reader packet must not establish replacement affinity"
        );
        assert!(
            stale_udp.affinity_pin_for_test("peer-a").await.is_none(),
            "a retired reader packet must not retain old transport affinity"
        );
    }

    #[tokio::test]
    async fn inbound_validation_request_is_ingress_only_until_local_ack() {
        let (_remote_session, local_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-a", local_session).await;
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        let trigger_count = Arc::new(AtomicUsize::new(0));
        let trigger_count_clone = trigger_count.clone();
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_validation_trigger(Arc::new(move |_| {
                trigger_count_clone.fetch_add(1, Ordering::SeqCst);
            }));
        let source: std::net::SocketAddr = "198.51.100.73:51820".parse().unwrap();
        let token = crate::transport::DirectValidationToken {
            kind: crate::transport::DirectValidationKind::Request,
            generation: 0,
            request_id: 0x4102,
            sequence: 0,
            owner_token: 9,
        };
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            token.request_id,
            0,
            &crate::transport::build_direct_validation_payload(
                crate::transport::DirectValidationKind::Request,
                token.generation,
                token.request_id,
                token.sequence,
                token.owner_token,
            ),
        );

        transport
            .handle_direct_validation_packet(
                &peers,
                Some(&udp),
                "peer-a",
                &packet,
                Some(source),
                udp.local_addr().ok(),
                Some(0),
                None,
                token,
            )
            .await;

        let connection = peers.get_connection("peer-a").await.unwrap();
        assert_ne!(connection.state, ConnectionState::Direct);
        assert_eq!(connection.direct_health.success_count, 0);
        assert_eq!(trigger_count.load(Ordering::SeqCst), 1);
        assert!(connection
            .direct_events
            .iter()
            .any(|event| event.stage == "direct_validation_request_received"));
        assert!(!connection
            .direct_events
            .iter()
            .any(|event| event.stage == "direct_validation_promoted"));

        let request_event = connection
            .direct_events
            .iter()
            .find(|event| event.stage == "direct_validation_request_received")
            .expect("the request event must be present");
        assert_eq!(
            request_event.validation_session_id, None,
            "a remote request owner must never be reported as this daemon's local validation session"
        );
        assert_eq!(
            request_event.remote_validation_owner,
            Some(token.owner_token),
            "remote validation ownership needs an explicit structured field"
        );
        assert_eq!(
            request_event.request_id,
            Some(token.request_id),
            "request_id must remain structured rather than only appearing in detail text"
        );
    }

    #[tokio::test]
    async fn validation_ack_leaves_through_the_receiving_socket_not_new_affinity() {
        let (_remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_socket_pool(2)
            .await
            .unwrap();
        let (_, receiving_socket) = udp
            .socket_for_peer(None)
            .await
            .expect("the primary UDP socket must exist");
        let receiving_endpoint = receiving_socket.local_addr().unwrap();
        let sink = tokio::net::UdpSocket::bind(
            "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
        )
            .await
            .unwrap();

        // Simulate a concurrent peer-reflexive observation that moved the
        // normal affinity to pool socket 1.  The request below was received
        // on socket 0, so its ACK must still leave socket 0; resolving by
        // peer affinity would incorrectly use socket 1.
        udp.remember_peer_socket("peer-a", 1, crate::udp::SocketEvidence::Fresh)
            .await;

        let source = sink.local_addr().unwrap();
        let token = crate::transport::DirectValidationToken {
            kind: crate::transport::DirectValidationKind::Request,
            generation: 0,
            request_id: 0x4A21,
            sequence: 0,
            owner_token: 9,
        };
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            token.request_id,
            0,
            &crate::transport::build_direct_validation_payload(
                crate::transport::DirectValidationKind::Request,
                token.generation,
                token.request_id,
                token.sequence,
                token.owner_token,
            ),
        );

        wg_transport
            .handle_direct_validation_packet(
                &peers,
                Some(&udp),
                "peer-a",
                &packet,
                Some(source),
                Some(receiving_endpoint),
                Some(0),
                None,
                token,
            )
            .await;

        let mut encrypted_ack = [0u8; 2048];
        let (_, observed_source) = timeout(
            Duration::from_secs(1),
            sink.recv_from(&mut encrypted_ack),
        )
        .await
        .expect("the validation ACK must reach the local UDP sink")
        .unwrap();
        assert_eq!(
            observed_source, receiving_endpoint,
            "a validation ACK must preserve the NAT mapping of the receiving socket"
        );
    }

    #[tokio::test]
    async fn validation_ack_uses_queued_dynamic_socket_after_entry_detached() {
        // A dynamic entry can be removed after its reader queued an
        // authenticated request but before the WireGuard worker handles it.
        // The envelope's exact socket Arc must still be usable; resolving the
        // numeric index from the current map would incorrectly return None.
        let (_remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                endpoint: "198.51.100.72:51820".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let (socket_index, dynamic_socket) = udp.bind_fresh_punch_socket().await.unwrap();
        let dynamic_endpoint = dynamic_socket.local_addr().unwrap();
        let sink = tokio::net::UdpSocket::bind(
            "127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap(),
        )
        .await
        .unwrap();
        let source = sink.local_addr().unwrap();
        let token = crate::transport::DirectValidationToken {
            kind: crate::transport::DirectValidationKind::Request,
            generation: 0,
            request_id: 0x4A22,
            sequence: 0,
            owner_token: 10,
        };
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            token.request_id,
            0,
            &crate::transport::build_direct_validation_payload(
                crate::transport::DirectValidationKind::Request,
                token.generation,
                token.request_id,
                token.sequence,
                token.owner_token,
            ),
        );

        // Do not attach the fresh socket: this is the post-detach state. The
        // packet still owns the exact socket handle captured by the reader.
        wg_transport
            .handle_direct_validation_packet(
                &peers,
                Some(&udp),
                "peer-a",
                &packet,
                Some(source),
                Some(dynamic_endpoint),
                Some(socket_index),
                Some(dynamic_socket.clone()),
                token,
            )
            .await;

        let mut encrypted_ack = [0u8; 2048];
        let (_, observed_source) = timeout(
            Duration::from_secs(1),
            sink.recv_from(&mut encrypted_ack),
        )
        .await
        .expect("the ACK must use the queued dynamic socket handle")
        .unwrap();
        assert_eq!(
            observed_source,
            dynamic_endpoint,
            "a detached dynamic validation request must retain its original source mapping"
        );
    }

    #[tokio::test]
    async fn old_generation_validation_ack_cannot_promote_or_adopt_affinity() {
        // Exercise the real decrypt -> inbound ACK handler path.  This is not
        // a unit test of the expectation map: a token that was valid before a
        // network generation advance must be rejected before it can mutate
        // either Direct state or the receiving UDP socket affinity.
        let (mut remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let source: std::net::SocketAddr = "198.51.100.44:51820".parse().unwrap();
        let old_generation = peers.current_network_generation().await;
        let owner_token = match udp
            .begin_or_merge_direct_validation("peer-a", source, old_generation)
            .await
        {
            crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
            crate::udp::DirectValidationSessionStart::Merged => {
                panic!("first validation observation must receive an owner lease")
            }
            crate::udp::DirectValidationSessionStart::IgnoredStaleGeneration => {
                panic!("the current generation must accept the initial owner lease")
            }
            crate::udp::DirectValidationSessionStart::IgnoredInactive => {
                panic!("an active non-Direct peer must accept the initial owner lease")
            }
        };
        assert!(
            udp.expect_direct_validation_ack_owned(
                "peer-a",
                0x7A11,
                old_generation,
                owner_token,
                source,
            )
            .await
        );

        assert_eq!(
            peers
                .advance_network_generation("test old validation ACK")
                .await,
            old_generation + 1
        );
        assert!(
            !udp.has_direct_validation_expectation("peer-a").await,
            "generation advance must atomically clear old validation expectations"
        );

        let ack_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            0x7A11,
            0,
            &build_direct_validation_payload(
                DirectValidationKind::Ack,
                old_generation,
                0x7A11,
                0,
                owner_token,
            ),
        );
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = wg_transport.clone();
            let peers = peers.clone();
            let udp = udp.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), Some(udp))
                    .await
            }
        });
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some(source),
                local_endpoint: udp.local_addr().ok(),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
                wire_bytes: remote_session.encrypt_to_bytes(&ack_packet).unwrap(),
            })
            .await
            .unwrap();
        drop(encrypted_tx);
        timeout(Duration::from_secs(2), worker)
            .await
            .expect("inbound worker must drain stale ACK")
            .unwrap()
            .unwrap();

        assert!(
            inbound_rx.recv().await.is_none(),
            "internal validation packets must not reach the TUN"
        );
        let connection = peers.get_connection("peer-a").await.unwrap();
        assert_ne!(connection.state, ConnectionState::Direct);
        assert_eq!(
            connection.direct_health.success_count, 0,
            "the old token must not record Direct success in the new generation"
        );
        assert!(
            !connection
                .direct_events
                .iter()
                .any(|event| event.stage == "direct_validation_ack_received"),
            "a rejected old ACK must not be recorded as a Direct confirmation"
        );
        assert!(
            udp.affinity_pin_for_test("peer-a").await.is_none(),
            "the old ACK must not establish a socket affinity"
        );
    }

    #[tokio::test]
    async fn old_validation_owner_ack_cannot_promote_rebound_same_generation_session() {
        // Exercise the real decrypt -> inbound ACK handler with an intentional
        // request-id collision. The second UDP registry uses the SAME network
        // generation and request id as the retired one, so only the wire owner
        // token can distinguish a delayed old ACK from the live expectation.
        let (mut remote_session, local_session) = establish_sessions();
        let (wg_transport, _encrypted_rx) = WireGuardTransport::new();
        wg_transport.add_session("peer-a", local_session).await;

        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: "peer-a".to_string(),
                virtual_ip: "10.20.0.2".to_string(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        let source: std::net::SocketAddr = "198.51.100.55:51820".parse().unwrap();
        let generation = peers.current_network_generation().await;
        let request_id = 0x5A17;

        let retired_udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let retired_owner = match retired_udp
            .begin_or_merge_direct_validation("peer-a", source, generation)
            .await
        {
            crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
            _ => panic!("retired transport must obtain the first lease"),
        };
        assert!(
            retired_udp
                .expect_direct_validation_ack_owned(
                    "peer-a",
                    request_id,
                    generation,
                    retired_owner,
                    source,
                )
                .await
        );

        // Binding a replacement changes the active registry without advancing
        // the network generation. Its globally allocated owner must differ.
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let current_owner = match udp
            .begin_or_merge_direct_validation("peer-a", source, generation)
            .await
        {
            crate::udp::DirectValidationSessionStart::Spawn(lease) => lease.owner_token,
            _ => panic!("replacement transport must obtain a fresh lease"),
        };
        assert_ne!(retired_owner, current_owner);
        assert!(
            udp.expect_direct_validation_ack_owned(
                "peer-a",
                request_id,
                generation,
                current_owner,
                source,
            )
            .await
        );

        let old_ack_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            request_id,
            0,
            &build_direct_validation_payload(
                DirectValidationKind::Ack,
                generation,
                request_id,
                0,
                retired_owner,
            ),
        );
        let (encrypted_tx, encrypted_rx) = mpsc::channel(1);
        let (inbound_tx, mut inbound_rx) = mpsc::channel(1);
        let worker = tokio::spawn({
            let transport = wg_transport.clone();
            let peers = peers.clone();
            let udp = udp.clone();
            async move {
                transport
                    .run_inbound_with_peers(encrypted_rx, inbound_tx, Some(peers), Some(udp))
                    .await
            }
        });
        encrypted_tx
            .send(ReceivedEncryptedPacket {
                source: Some(source),
                local_endpoint: udp.local_addr().ok(),
                relay_endpoint: None,
                relay_connection_id: None,
                relay_peer_id: None,
                socket_index: Some(0),
                direct_socket: None,
                udp_transport_owner: None,
                network_generation: None,
                wire_bytes: remote_session.encrypt_to_bytes(&old_ack_packet).unwrap(),
            })
            .await
            .unwrap();
        drop(encrypted_tx);
        timeout(Duration::from_secs(2), worker)
            .await
            .expect("inbound worker must drain delayed ACK")
            .unwrap()
            .unwrap();

        assert!(
            inbound_rx.recv().await.is_none(),
            "internal validation ACKs must remain off the TUN path"
        );
        let connection = peers.get_connection("peer-a").await.unwrap();
        assert_ne!(connection.state, ConnectionState::Direct);
        assert_eq!(
            connection.direct_health.success_count, 0,
            "a colliding old owner token must not record Direct success"
        );
        assert!(
            udp.has_direct_validation_expectation("peer-a").await,
            "the live owner's expectation must survive a mismatched old ACK"
        );
        assert_eq!(
            udp.direct_validation_target("peer-a")
                .await
                .expect("the live owner must remain registered")
                .owner_token,
            current_owner
        );
        assert!(
            udp.affinity_pin_for_test("peer-a").await.is_none(),
            "a colliding old ACK must not establish affinity"
        );
    }
    #[tokio::test]
    async fn hedge_duplicate_replay_is_safe_and_observable() {
        // The same WireGuard ciphertext is legitimately delivered twice during
        // the Direct trial window (once per Direct path, once per relay
        // hedge).  The second copy must be dropped by WireGuard replay
        // protection, attributed as a hedge duplicate, and must not change
        // any path state.
        let (node_a_session, mut node_b_session) = establish_sessions();
        let (transport, _encrypted_rx) = WireGuardTransport::new();
        transport.add_session("peer-b", node_a_session).await;

        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x4321,
            1,
            b"hedge",
        );
        let wire = node_b_session.encrypt_to_bytes(&packet).unwrap();

        // First delivery decrypts normally.
        let first = transport
            .decrypt_inbound(&wire)
            .await
            .expect("first delivery must decrypt")
            .expect("must be decrypted for the peer session");
        assert_eq!(first.peer_id, "peer-b");
        assert_eq!(transport.hedge_replay_count("peer-b"), 0);

        // Second delivery of the identical ciphertext is replay-classified:
        // observable (counted) and safe (an error, no state mutation).
        let second = transport.decrypt_inbound(&wire).await;
        assert!(
            second.is_err(),
            "the duplicate ciphertext must be rejected by WireGuard replay protection"
        );
        assert!(
            second.unwrap_err().to_string().contains("replay detected"),
            "the rejection must be classified as replay detected"
        );
        assert_eq!(
            transport.hedge_replay_count("peer-b"),
            1,
            "the hedge duplicate must be attributed and counted per peer"
        );

        // A third duplicate increments the counter; the classification stays
        // safe and does not consume any future counter.
        let third = transport.decrypt_inbound(&wire).await;
        assert!(third.is_err());
        assert_eq!(transport.hedge_replay_count("peer-b"), 2);

        // The session is untouched: a NEW packet with the next counter still
        // decrypts, and the transport never learned any path state from the
        // duplicates.
        let next_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x4322,
            1,
            b"next",
        );
        let next_wire = node_b_session.encrypt_to_bytes(&next_packet).unwrap();
        let next = transport
            .decrypt_inbound(&next_wire)
            .await
            .expect("a fresh packet must still decrypt after hedge duplicates")
            .expect("fresh packet decrypts");
        assert_eq!(next.peer_id, "peer-b");
    }
}
