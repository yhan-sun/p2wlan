use super::*;
use p2pnet_nat::{decode_authenticated_punch_packet, PunchPacketKind};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

/// One diagnostic observation from this fixture's original validation worker.
/// It never changes admission, the request deadline, or an assertion result.
#[derive(Clone, Default)]
struct PreflightOutcomeCapture(Arc<std::sync::Mutex<Option<String>>>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PreflightOutcomeCapture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _context: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() != "p2pnet_daemon::direct_validation" {
            return;
        }
        struct EventName(bool);
        impl tracing::field::Visit for EventName {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    self.0 = value == "direct_validation_preflight_completed";
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut name = EventName(false);
        event.record(&mut name);
        if !name.0 {
            return;
        }
        struct Outcome(Option<String>);
        impl tracing::field::Visit for Outcome {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "outcome" {
                    // This producer records only the fixed preflight enum and
                    // its static reason; retain one bounded diagnostic value.
                    self.0 = Some(format!("{value:?}").chars().take(256).collect());
                }
            }
        }
        let mut outcome = Outcome(None);
        event.record(&mut outcome);
        let mut first = self.0.lock().unwrap();
        if first.is_none() {
            *first = outcome.0;
        }
    }
}

fn mapping_config(identity: &NodeIdentity, node_id: &str, virtual_ip: &str) -> Config {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.node.node_id = node_id.to_string();
    config.node.public_key = hex::encode(identity.public_key());
    config.node.private_key = hex::encode(identity.private_key());
    config.network.virtual_ip = virtual_ip.to_string();
    config
}

fn mapping_peer(node_id: &str, public_key: String, virtual_ip: &str) -> control::PeerInfo {
    control::PeerInfo {
        capabilities: control::PeerCapabilities::default(),
        registration_seq: 0,
        node_id: node_id.to_string(),
        device_name: String::new(),
        app_version: "0.1.25".to_string(),
        public_key,
        endpoint: String::new(),
        nat_type: "Unknown".to_string(),
        virtual_ip: virtual_ip.to_string(),
        online: true,
        last_seen: 0,
        relay_rtt_ms: None,
    }
}

/// The advertised destination P and the authenticated return mapping R are
/// distinct. A Probe-v2 ACK must authenticate R before the FIRST encrypted
/// Request, while that Request still uses P and the exact original A socket.
/// Learning R by accepting the encrypted ACK itself would erase the security
/// boundary; retrying toward R would conceal the APDM port-chasing regression.
#[tokio::test]
async fn ordinary_validation_preflight_authenticates_return_mapping_without_chasing_it() {
    let a_identity = NodeIdentity::generate();
    let b_identity = NodeIdentity::generate();
    let peers_a = Arc::new(PeerManager::new(mapping_config(
        &a_identity,
        "node-a",
        "10.20.0.1",
    )));
    let peers_b = Arc::new(PeerManager::new(mapping_config(
        &b_identity,
        "node-b",
        "10.20.0.2",
    )));
    peers_a
        .add_peer(&mapping_peer(
            "node-b",
            hex::encode(b_identity.public_key()),
            "10.20.0.2",
        ))
        .await;
    peers_b
        .add_peer(&mapping_peer(
            "node-a",
            hex::encode(a_identity.public_key()),
            "10.20.0.1",
        ))
        .await;
    let probe_key = peers_a.probe_key_for_peer("node-b").await.unwrap();
    assert_eq!(peers_b.probe_key_for_peer("node-a").await, Some(probe_key));

    let mut initiator = HandshakeInitiator::new(a_identity, b_identity.public_key(), None);
    let initiation = initiator.create_initiation().unwrap();
    let mut responder = HandshakeResponder::new(b_identity, None);
    let (response, b_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let a_keys = initiator.consume_response(&response).unwrap();
    // Independent decoders inspect the real ciphertext without touching the
    // production receivers' counters or replacing their authenticated ACKs.
    let mut request_decoder = TransportSession::new(b_keys.clone());
    let mut ack_decoder = TransportSession::new(a_keys.clone());
    let (wg_a, _outbound_a) = WireGuardTransport::new();
    let (wg_b, _outbound_b) = WireGuardTransport::new();
    wg_a.add_session("node-b", TransportSession::new(a_keys))
        .await;
    wg_b.add_session("node-a", TransportSession::new(b_keys))
        .await;

    let (udp_tx_a, udp_rx_a) = mpsc::channel(64);
    let (udp_tx_b, udp_rx_b) = mpsc::channel(64);
    let udp_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .unwrap()
        .with_local_node_id("node-a")
        .with_wireguard_transport(wg_a.clone())
        .with_inbound_channel(udp_tx_a.clone());
    let udp_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .unwrap()
        .with_local_node_id("node-b")
        .with_wireguard_transport(wg_b.clone())
        .with_inbound_channel(udp_tx_b.clone());
    let a_addr = udp_a.local_addr().unwrap();
    let b_addr = udp_b.local_addr().unwrap();
    let original = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let returning = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let original_addr = original.local_addr().unwrap();
    let returning_addr = returning.local_addr().unwrap();
    assert_ne!(original_addr, returning_addr);
    let generation = peers_a.current_network_generation_sync();
    assert!(
        !peers_a
            .is_authenticated_direct_endpoint("node-b", returning_addr, generation)
            .await
    );

    // JoinSet owns every fixture task, including assertion/panic paths.
    // Neither node installs an automatic validation trigger: only A's one
    // explicit owner runs, so B cannot accidentally supply a second path.
    let mut tasks = JoinSet::new();
    let a_reader = udp_a.clone();
    tasks.spawn(async move {
        let _ = a_reader.run_inbound(udp_tx_a).await;
    });
    let b_reader = udp_b.clone();
    tasks.spawn(async move {
        let _ = b_reader.run_inbound(udp_tx_b).await;
    });
    let (ip_tx_a, _ip_rx_a) = mpsc::channel(64);
    let (ip_tx_b, _ip_rx_b) = mpsc::channel(64);
    let a_inbound = (wg_a.clone(), peers_a.clone(), udp_a.clone());
    tasks.spawn(async move {
        let _ = a_inbound
            .0
            .run_inbound_with_peers(udp_rx_a, ip_tx_a, Some(a_inbound.1), Some(a_inbound.2))
            .await;
    });
    let b_inbound = (wg_b, peers_b, udp_b);
    tasks.spawn(async move {
        let _ = b_inbound
            .0
            .run_inbound_with_peers(udp_rx_b, ip_tx_b, Some(b_inbound.1), Some(b_inbound.2))
            .await;
    });

    let (request_tx, request_rx) = oneshot::channel();
    let (release_ack_tx, release_ack_rx) = oneshot::channel();
    let (forwarded_tx, forwarded_rx) = oneshot::channel();
    tasks.spawn(async move {
        let mut packet = vec![0u8; 2048];
        let (len, source) = original.recv_from(&mut packet).await.unwrap();
        assert_eq!(source, a_addr, "preflight must use A's actual socket");
        let preflight = decode_authenticated_punch_packet(&packet[..len], &probe_key)
            .expect("the first packet must be an authenticated Probe-v2 preflight");
        assert_eq!(preflight.kind, PunchPacketKind::Punch);
        assert!(
            !preflight.use_candidate,
            "ordinary preflight cannot nominate"
        );
        assert_eq!(preflight.source_node_id.as_deref(), Some("node-a"));
        assert_eq!(preflight.target_node_id.as_deref(), Some("node-b"));
        assert_eq!(preflight.generation, Some(generation));
        returning.send_to(&packet[..len], b_addr).await.unwrap();

        let (len, source) = returning.recv_from(&mut packet).await.unwrap();
        assert_eq!(source, b_addr);
        let probe_ack = decode_authenticated_punch_packet(&packet[..len], &probe_key)
            .expect("the responder must return an authenticated Probe ACK");
        assert_eq!(probe_ack.kind, PunchPacketKind::Ack);
        assert_eq!(probe_ack.nonce, preflight.nonce);
        returning.send_to(&packet[..len], a_addr).await.unwrap();

        // Receiving this packet at P proves that learning R did not retarget
        // the already prepared request. No unrelated punch loop is running.
        let (len, source) = original.recv_from(&mut packet).await.unwrap();
        assert_eq!(
            source, a_addr,
            "encrypted Request must reuse the probe socket"
        );
        let request_plaintext = request_decoder.decrypt_from_bytes(&packet[..len]).unwrap();
        let request = parse_direct_validation_token(&request_plaintext).unwrap();
        assert_eq!(request.kind, DirectValidationKind::Request);
        assert_eq!(request.sequence, 0, "the first Request must already work");
        assert_eq!(request.generation, generation);
        assert_ne!(request.owner_token, 0);
        returning.send_to(&packet[..len], b_addr).await.unwrap();

        // Consume the responder's bounded duplicate ACK / triggered-check
        // traffic without forwarding it. Only the correlated preflight ACK
        // above may supply A's independent return-mapping evidence.
        let mut encrypted_ack = None;
        for _ in 0..8 {
            let (len, source) = returning.recv_from(&mut packet).await.unwrap();
            assert_eq!(source, b_addr);
            if let Some(ack) = decode_authenticated_punch_packet(&packet[..len], &probe_key) {
                assert_eq!(ack.source_node_id.as_deref(), Some("node-b"));
                assert_eq!(ack.target_node_id.as_deref(), Some("node-a"));
                if ack.kind == PunchPacketKind::Ack {
                    assert_eq!(ack.nonce, preflight.nonce);
                }
                continue;
            }
            let ack_plaintext = ack_decoder.decrypt_from_bytes(&packet[..len]).unwrap();
            let ack = parse_direct_validation_token(&ack_plaintext).unwrap();
            assert_eq!(ack.kind, DirectValidationKind::Ack);
            assert_eq!(ack.request_id, request.request_id);
            assert_eq!(ack.owner_token, request.owner_token);
            assert_eq!(ack.generation, request.generation);
            assert_eq!(ack.sequence, request.sequence);
            encrypted_ack = Some(packet[..len].to_vec());
            break;
        }
        let encrypted_ack = encrypted_ack.expect("the first Request must receive a real WG ACK");
        request_tx.send(request).unwrap();
        release_ack_rx.await.unwrap();
        returning.send_to(&encrypted_ack, a_addr).await.unwrap();
        forwarded_tx.send(()).unwrap();
    });

    let worker_udp = udp_a.clone();
    let worker_peers = peers_a.clone();
    let (completed_tx, completed_rx) = oneshot::channel();
    let preflight = PreflightOutcomeCapture::default();
    let subscriber = tracing_subscriber::registry().with(preflight.clone());
    tasks.spawn(
        async move {
            run_direct_encrypted_validation(
                PeerReflexiveObservation {
                    peer_id: "node-b".to_string(),
                    observed_endpoint: original_addr,
                },
                worker_udp,
                worker_peers,
                wg_a,
                "10.20.0.1",
            )
            .await;
            let _ = completed_tx.send(());
        }
        .with_subscriber(subscriber),
    );

    timeout(Duration::from_secs(3), async {
        let request = request_rx
            .await
            .expect("proxy must observe the first request/ACK");
        // Evaluate the original predicate once, at its original protocol
        // boundary. Diagnostics must never wait for it to become true.
        let independent_authentication = peers_a
            .is_authenticated_direct_endpoint("node-b", returning_addr, generation)
            .await;
        eprintln!(
            "mapping_preflight outcome={:?} independent_authenticated={independent_authentication}",
            preflight.0.lock().unwrap().as_ref(),
        );
        if !independent_authentication {
            let counters = timeout(Duration::from_millis(20), udp_a.probe_rx_snapshot()).await;
            eprintln!("mapping_preflight original_failure_rx={counters:?}");
        }
        assert!(
            independent_authentication,
            "independent Probe authentication must precede encrypted ACK acceptance"
        );
        assert!(
            !peers_a.is_direct_sync("node-b"),
            "Probe alone cannot promote Direct"
        );
        let current = udp_a.direct_validation_target("node-b").await.unwrap();
        assert_eq!(current.owner_token, request.owner_token);
        assert_eq!(current.endpoint, original_addr);
        assert_eq!(current.generation, generation);
        release_ack_tx.send(()).unwrap();
        forwarded_rx.await.unwrap();
        completed_rx.await.unwrap();
        assert!(peers_a.is_direct_sync("node-b"));
        assert_eq!(
            peers_a.selected_direct_endpoint_for_consent("node-b").await,
            Some(returning_addr)
        );
        let pair = peers_a.direct_commit_pair_snapshot_sync("node-b").unwrap();
        assert_eq!(pair.local_endpoint, Some(a_addr));
        assert_eq!(pair.remote_endpoint, returning_addr);
        assert_eq!(pair.generation, generation);

        // Direct's atomic state is published before its diagnostic event;
        // wait for the same handler's evidence without using a timing sleep.
        let diagnostics = loop {
            let diagnostics = peers_a.diagnostics().await;
            if diagnostics[0].direct_events.iter().any(|event| {
                event.stage == "direct_validation_ack_received"
                    && event.request_id == Some(request.request_id)
            }) {
                break diagnostics;
            }
            tokio::task::yield_now().await;
        };
        let events = &diagnostics[0].direct_events;
        let ack = events
            .iter()
            .find(|event| event.stage == "direct_validation_ack_received")
            .expect("the real encrypted ACK must be consumed");
        assert_eq!(ack.validation_session_id, Some(request.owner_token));
        assert_eq!(ack.request_id, Some(request.request_id));
        assert_eq!(ack.expected_endpoint, Some(original_addr.to_string()));
        assert_eq!(ack.observed_ack_endpoint, Some(returning_addr.to_string()));
        assert_eq!(ack.ack_endpoint_authenticated, Some(true));
        assert_eq!(ack.socket_index, Some(0));
        assert_eq!(
            events
                .iter()
                .filter(|event| event.stage == "direct_validation_request_sent")
                .count(),
            1,
            "success must not depend on a second request or chasing R"
        );
    })
    .await
    .expect("the first owned request/ACK must establish Direct through the return mapping");
}
