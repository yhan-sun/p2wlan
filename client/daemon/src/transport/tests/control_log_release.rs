// Actual encryption/UDP handoff and subscriber reentry into the same fence.
// This control grants no kernel, Full, current-owner or remote NIC fact.
use tracing::instrument::WithSubscriber;
use tracing_subscriber::prelude::*;

struct CompletionProbe {
    transport: WireGuardTransport,
    observed: Arc<AtomicUsize>,
    released: Arc<AtomicUsize>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CompletionProbe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct EventName(bool);
        impl tracing::field::Visit for EventName {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "event" && value == "control_transport_handoff_completed" {
                    self.0 = true;
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut name = EventName(false);
        event.record(&mut name);
        if name.0 {
            self.observed.fetch_add(1, Ordering::SeqCst);
            if self
                .transport
                .try_acquire_outbound_emit_guard("peer-a")
                .is_some()
            {
                self.released.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

#[tokio::test]
async fn control_emit_completion_logger_runs_after_actual_handoff_and_emit_unlock() {
    let (mut remote, local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    let observed = Arc::new(AtomicUsize::new(0));
    let released = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(CompletionProbe {
        transport: transport.clone(),
        observed: observed.clone(),
        released: released.clone(),
    });
    let plaintext = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        7,
        1,
        b"emit-log-release",
    );
    let expected = plaintext.clone();
    let control = OutboundPacket {
        room_authorization: None,
        trace: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.1".into(),
        packet: plaintext,
    };
    let sent = transport
        .encrypt_and_emit_outbound(control, |encrypted| async move {
            assert_eq!(
                socket
                    .send_to(&encrypted.wire_bytes, endpoint)
                    .await
                    .unwrap(),
                encrypted.wire_bytes.len()
            );
            Ok(())
        })
        .with_subscriber(subscriber)
        .await
        .unwrap();
    assert!(sent);
    let mut wire = [0u8; 2048];
    let (length, _) = timeout(Duration::from_secs(1), receiver.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        remote.decrypt_from_bytes(&wire[..length]).unwrap(),
        expected
    );
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "logger must reenter the original mutex after the real send"
    );
}

struct AllControlLogProbe {
    transport: WireGuardTransport,
    counts: Arc<[AtomicUsize; 4]>,
    released: Arc<AtomicUsize>,
    handoff: Arc<std::sync::atomic::AtomicBool>,
}
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AllControlLogProbe {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Name(Option<usize>);
        impl tracing::field::Visit for Name {
            fn record_str(&mut self, f: &tracing::field::Field, v: &str) {
                if f.name() == "event" {
                    self.0 = [
                        "control_emit_lock_acquired",
                        "wireguard_outbound_counter_allocated",
                        "control_transport_handoff_started",
                        "control_transport_handoff_completed",
                    ]
                    .iter()
                    .position(|s| *s == v);
                }
            }
            fn record_debug(&mut self, _: &tracing::field::Field, _: &dyn std::fmt::Debug) {}
        }
        let mut name = Name(None);
        event.record(&mut name);
        if let Some(i) = name.0 {
            assert!(
                self.handoff.load(Ordering::SeqCst),
                "callbacks must follow the original actual handoff return"
            );
            self.counts[i].fetch_add(1, Ordering::SeqCst);
            if self
                .transport
                .try_acquire_outbound_emit_guard("peer-a")
                .is_some()
            {
                self.released.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}
async fn control_all_log_fixture(fail: bool) {
    let (mut remote, local) = establish_sessions();
    let (transport, _rx) = WireGuardTransport::new();
    transport.add_session("peer-a", local).await;
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint = receiver.local_addr().unwrap();
    let counts = Arc::new(std::array::from_fn(|_| AtomicUsize::new(0)));
    let released = Arc::new(AtomicUsize::new(0));
    let handoff = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let subscriber = tracing_subscriber::registry().with(AllControlLogProbe {
        transport: transport.clone(),
        counts: counts.clone(),
        released: released.clone(),
        handoff: handoff.clone(),
    });
    let plain = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        7,
        1,
        b"all-control-logs",
    );
    let expected = plain.clone();
    let packet = OutboundPacket {
        room_authorization: None,
        trace: None,
        peer_id: "peer-a".into(),
        dst_ip: "10.20.0.1".into(),
        packet: plain,
    };
    let result = transport
        .encrypt_and_emit_outbound(packet, |encrypted| async move {
            if fail {
                handoff.store(true, Ordering::SeqCst);
                return Err(DaemonError::Relay("original fixture handoff error".into()));
            }
            let n = socket
                .send_to(&encrypted.wire_bytes, endpoint)
                .await
                .unwrap();
            assert_eq!(n, encrypted.wire_bytes.len());
            handoff.store(true, Ordering::SeqCst);
            Ok(())
        })
        .with_subscriber(subscriber)
        .await;
    assert_eq!(result.is_err(), fail);
    if !fail {
        assert!(result.unwrap());
        let mut wire = [0u8; 2048];
        let (n, _) = timeout(Duration::from_secs(1), receiver.recv_from(&mut wire))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remote.decrypt_from_bytes(&wire[..n]).unwrap(), expected);
    }
    assert_eq!(
        counts
            .iter()
            .map(|c| c.load(Ordering::SeqCst))
            .collect::<Vec<_>>(),
        if fail {
            vec![1, 1, 1, 0]
        } else {
            vec![1, 1, 1, 1]
        }
    );
    assert_eq!(released.load(Ordering::SeqCst), if fail { 3 } else { 4 });
}
#[tokio::test]
async fn control_emit_all_log_callbacks_after_successful_handoff_and_unlock() {
    control_all_log_fixture(false).await;
}
#[tokio::test]
async fn control_emit_all_log_callbacks_after_failed_handoff_and_unlock() {
    control_all_log_fixture(true).await;
}
