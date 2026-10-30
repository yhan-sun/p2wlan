// Real WireGuard and loopback Relay controls, with actual emit reentry.
// No KernelRead, native/current-owner/once fact or remote-NIC claim.
use tracing::instrument::WithSubscriber;

const PEER: &str = "relay-post-b";
struct Fixture {
    server: p2pnet_relay::RelayServer,
    relay: crate::relay::RelayTransport,
    remote_relay: crate::relay::RelayTransport,
    remote_rx: mpsc::Receiver<p2pnet_relay::RelayMessage>,
    _local_rx: mpsc::Receiver<p2pnet_relay::RelayMessage>,
    peers: Arc<crate::peer::PeerManager>,
    transport: WireGuardTransport,
    remote: TransportSession,
    endpoint: String,
}
impl Fixture {
    async fn start() -> Self {
        let server = p2pnet_relay::RelayServer::start_random().await.unwrap();
        let endpoint = server.addr.to_string();
        let peers = Arc::new(crate::peer::PeerManager::new(
            Config::generate_default("https://control.test", "test").unwrap(),
        ));
        peers
            .add_peer(&PeerInfo {
                node_id: PEER.into(),
                public_key: hex::encode(NodeIdentity::generate().public_key()),
                virtual_ip: "10.20.0.2".into(),
                online: true,
                ..PeerInfo::default()
            })
            .await;
        let (relay, local_rx) =
            crate::relay::RelayTransport::connect(&endpoint, "relay-post-a", peers.clone())
                .await
                .unwrap();
        let (remote_relay, remote_rx) =
            crate::relay::RelayTransport::connect(&endpoint, PEER, peers.clone())
                .await
                .unwrap();
        let (local, remote) = establish_sessions();
        let (transport, _raw) = WireGuardTransport::new();
        transport.add_session(PEER, local).await;
        Self {
            server,
            relay,
            remote_relay,
            remote_rx,
            _local_rx: local_rx,
            peers,
            transport,
            remote,
            endpoint,
        }
    }
    fn packet() -> OutboundPacket {
        OutboundPacket {
            room_authorization: None,
            trace: None,
            peer_id: PEER.into(),
            dst_ip: "10.20.0.2".into(),
            packet: Ipv4Packet::build_icmp_echo_request(
                Ipv4Addr::new(10, 20, 0, 1),
                Ipv4Addr::new(10, 20, 0, 2),
                3,
                1,
                b"relay-control-post-write",
            ),
        }
    }
    async fn finish(self) {
        self.relay.abort_writer();
        self.remote_relay.abort_writer();
        self.server.shutdown().await;
    }
}
struct Probe {
    transport: WireGuardTransport,
    events: Arc<std::sync::Mutex<Vec<String>>>,
    released: Arc<AtomicUsize>,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Probe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        #[derive(Default)]
        struct Name(String);
        impl tracing::field::Visit for Name {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" {
                    self.0 = value.into();
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut name = Name::default();
        event.record(&mut name);
        if !name.0.starts_with("relay_outbound_write_") {
            return;
        }
        self.events.lock().unwrap().push(name.0);
        if self
            .transport
            .try_acquire_outbound_emit_guard(PEER)
            .is_some()
        {
            self.released.fetch_add(1, Ordering::SeqCst);
        }
    }
}
fn observe(
    fixture: &Fixture,
) -> (
    tracing::Dispatch,
    Arc<std::sync::Mutex<Vec<String>>>,
    Arc<AtomicUsize>,
) {
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let released = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(Probe {
        transport: fixture.transport.clone(),
        events: events.clone(),
        released: released.clone(),
    });
    (tracing::Dispatch::new(subscriber), events, released)
}

#[tokio::test]
async fn real_relay_full_keeps_counter_fence_then_drains_diagnostics_after_unlock() {
    let mut fixture = Fixture::start().await;
    let (subscriber, events, released) = observe(&fixture);
    let packet = Fixture::packet();
    let expected = packet.packet.clone();
    let transport = fixture.transport.clone();
    let boundary_transport = transport.clone();
    let relay = fixture.relay.clone();
    let boundaries = Arc::new(AtomicUsize::new(0));
    let seen = boundaries.clone();
    let result = async {
        let mut log = relay.prepare_deferred_send(PEER);
        let log_ref = &mut log;
        let result = transport
            .encrypt_and_emit_outbound(packet, move |encrypted| async move {
                relay
                    .send_packet_deferred(
                        &encrypted,
                        Some(Box::new(move |_| {
                            assert!(boundary_transport
                                .try_acquire_outbound_emit_guard(PEER)
                                .is_none());
                            seen.fetch_add(1, Ordering::SeqCst);
                            true
                        })),
                        log_ref,
                    )
                    .await
            })
            .await;
        log.finish().await;
        result
    }
    .with_subscriber(subscriber)
    .await
    .unwrap();
    assert!(result);
    assert_eq!(boundaries.load(Ordering::SeqCst), 1);
    let wire = timeout(Duration::from_secs(2), async {
        loop {
            let message = fixture
                .remote_rx
                .recv()
                .await
                .expect("real Relay stream closed");
            if let p2pnet_relay::RelayMessage::Data { data, .. } = message {
                break data;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.remote.decrypt_from_bytes(&wire).unwrap(), expected);
    assert_eq!(
        *events.lock().unwrap(),
        [
            "relay_outbound_write_submitted",
            "relay_outbound_write_completed"
        ]
    );
    assert_eq!(released.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .peers
            .get_connection(PEER)
            .await
            .unwrap()
            .relay_server,
        Some(fixture.endpoint.clone())
    );
    fixture.finish().await;
}

#[tokio::test]
async fn real_relay_boundary_rejection_keeps_typed_failure_without_success_diagnostic() {
    let fixture = Fixture::start().await;
    let (subscriber, events, released) = observe(&fixture);
    let transport = fixture.transport.clone();
    let relay = fixture.relay.clone();
    let result = async {
        let mut log = relay.prepare_deferred_send(PEER);
        let log_ref = &mut log;
        let result = transport
            .encrypt_and_emit_outbound(Fixture::packet(), move |encrypted| async move {
                relay
                    .send_packet_deferred(&encrypted, Some(Box::new(|_| false)), log_ref)
                    .await
            })
            .await;
        log.finish().await;
        result
    }
    .with_subscriber(subscriber)
    .await;
    assert!(matches!(
        result,
        Err(DaemonError::RelaySend {
            error: p2pnet_relay::RelayError::WriteBoundaryRejected,
            ..
        })
    ));
    assert_eq!(
        *events.lock().unwrap(),
        [
            "relay_outbound_write_submitted",
            "relay_outbound_write_failed"
        ]
    );
    assert_eq!(released.load(Ordering::SeqCst), 2);
    assert!(fixture
        .peers
        .get_connection(PEER)
        .await
        .unwrap()
        .relay_server
        .is_none());
    fixture.finish().await;
}

#[tokio::test(flavor = "current_thread")]
async fn real_queued_relay_cancel_drops_actual_emit_before_submission_diagnostic() {
    let fixture = Fixture::start().await;
    let (subscriber, events, released) = observe(&fixture);
    let transport = fixture.transport.clone();
    let relay = fixture.relay.clone();
    let mut attempt = Box::pin(
        async {
            let mut log = relay.prepare_deferred_send(PEER);
            let log_ref = &mut log;
            let result = transport
                .encrypt_and_emit_outbound(Fixture::packet(), move |encrypted| async move {
                    relay.send_packet_deferred(&encrypted, None, log_ref).await
                })
                .await;
            log.finish().await;
            result
        }
        .with_subscriber(subscriber.clone()),
    );
    // A single-thread runtime cannot poll its real writer between this
    // explicit Pending observation and cancellation; queued delivery is unknown.
    assert!(futures_util::poll!(attempt.as_mut()).is_pending());
    assert!(fixture
        .transport
        .try_acquire_outbound_emit_guard(PEER)
        .is_none());
    tracing::dispatcher::with_default(&subscriber, || drop(attempt));
    assert!(fixture
        .transport
        .try_acquire_outbound_emit_guard(PEER)
        .is_some());
    assert_eq!(*events.lock().unwrap(), ["relay_outbound_write_submitted"]);
    assert_eq!(released.load(Ordering::SeqCst), 1);
    assert!(fixture
        .peers
        .get_connection(PEER)
        .await
        .unwrap()
        .relay_server
        .is_none());
    fixture.finish().await;
}
