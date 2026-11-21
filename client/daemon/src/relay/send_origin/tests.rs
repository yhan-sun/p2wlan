// Kernel TCP positives use both original library writers and the original
// RelayTransport send/JoinSet caller. Closed shells, barriers/panic and ledger
// faults are labelled synthetic negatives; no canonical/emit/partial/ACK proof.
use super::*;
use crate::relay::{RelayMessage, RelayTransport};
use crate::request_carriage::test_support::{mint_routed_request, RoutedRequestFixture, PEER};
use crate::transport::WireGuardTransport;
use p2pnet_relay::protocol::{read_frame, Frame, MSG_FORWARD, MSG_PING, MSG_REGISTER};
use p2pnet_relay::{RelayClientConfig, RelayError};
use std::future::{poll_fn, Future};
use std::task::Poll;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Clone, Copy)]
enum WriterPath {
    General,
    LegacyAddress,
}
#[derive(Clone, Copy)]
struct Budget {
    end: tokio::time::Instant,
}
impl Budget {
    fn new() -> Self {
        Self {
            end: tokio::time::Instant::now() + Duration::from_secs(2),
        }
    }
    async fn step<T>(&self, future: impl Future<Output = T>) -> T {
        let end = self
            .end
            .min(tokio::time::Instant::now() + Duration::from_secs(1));
        tokio::time::timeout_at(end, future)
            .await
            .expect("B18a original caller prerequisite timeout")
    }
}
struct Fixture {
    transport: Option<RelayTransport>,
    _inbound: mpsc::Receiver<RelayMessage>,
    frames: mpsc::Receiver<Frame>,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(transport) = self.transport.take() {
            transport.abort_writer();
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
impl Fixture {
    async fn start(path: WriterPath, peers: Arc<crate::peer::PeerManager>, budget: Budget) -> Self {
        let listener = budget.step(TcpListener::bind("127.0.0.1:0")).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let endpoint = format!("tcp://{addr}");
        let (tx, frames) = mpsc::channel(4);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = stopped => {},
                _ = async {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let registration = read_frame(&mut stream).await.unwrap();
                    assert_eq!(registration.msg_type, MSG_REGISTER);
                    let node = std::str::from_utf8(&registration.payload).unwrap();
                    stream.write_all(&Frame::registered(node).encode()).await.unwrap();
                    while let Ok(frame) = read_frame(&mut stream).await {
                        match frame.msg_type {
                            MSG_FORWARD => { if tx.send(frame).await.is_err() { break; } },
                            MSG_PING => {
                                if stream.write_all(&Frame::new(p2pnet_relay::protocol::MSG_PONG, frame.payload).encode()).await.is_err() { break; }
                            },
                            other => panic!("unexpected original frame {other}"),
                        }
                    }
                } => {},
            }
        });
        let (transport, inbound) = match path {
            WriterPath::General => budget
                .step(RelayTransport::connect(&endpoint, "b18a-general", peers))
                .await
                .unwrap(),
            WriterPath::LegacyAddress => {
                let config = RelayClientConfig {
                    register_timeout: Duration::from_secs(1),
                    allow_insecure_plaintext: true,
                    ..Default::default()
                };
                let (client, inbound) = budget
                    .step(RelayClient::connect_with_config(
                        &addr.to_string(),
                        "b18a-legacy",
                        config,
                    ))
                    .await
                    .unwrap();
                // Test-only shell for a genuinely connected legacy client. The
                // public daemon connector uses general; no production bridge.
                let transport = RelayTransport {
                    relay_connection_id: super::super::NEXT_RELAY_CONNECTION_ID
                        .fetch_add(1, Ordering::Relaxed),
                    relay_region: "b18a-legacy-fixture".to_string(),
                    relay_endpoint: endpoint,
                    connect_latency_ms: 0,
                    route_signature: Vec::new(),
                    client: Arc::new(client),
                    rendezvous: None,
                    write_boundaries_live: Arc::new(std::sync::Mutex::new(true)),
                    peers,
                    ticket_audience: None,
                    ticket_region: None,
                    ticket_expires_at_unix: None,
                };
                (transport, inbound)
            }
        };
        Self {
            transport: Some(transport),
            _inbound: inbound,
            frames,
            stop: Some(stop),
            task: Some(task),
        }
    }
    fn transport(&self) -> &RelayTransport {
        self.transport.as_ref().unwrap()
    }
    async fn frame(&mut self, packet: &EncryptedPeerPacket, budget: Budget) -> Frame {
        let frame = budget.step(self.frames.recv()).await.unwrap();
        assert_eq!(
            frame,
            Frame::forward(&packet.peer_id, &packet.wire_bytes).unwrap()
        );
        frame
    }
    async fn finish(mut self, budget: Budget) {
        if let Some(transport) = self.transport.take() {
            transport.abort_writer();
        }
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            budget.step(task).await.unwrap();
        }
    }
}
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
async fn ciphertext(
    budget: Budget,
) -> (
    RoutedRequestFixture,
    WireGuardTransport,
    EncryptedPeerPacket,
    p2pnet_wireguard::TransportSession,
) {
    let f = budget.step(mint_routed_request()).await;
    let (session, remote) = sessions();
    let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
    budget
        .step(transport.replace_session_for_lifecycle(
            PEER,
            session,
            f.record.expected_target_lifecycle().unwrap(),
        ))
        .await;
    let emit = budget
        .step(transport.acquire_outbound_emit_guard(PEER))
        .await;
    let encrypted = budget
        .step(transport.encrypt_request_with_emit_guard(f.delivery.clone()))
        .await
        .unwrap()
        .unwrap();
    let packet = (*encrypted).clone();
    drop(emit);
    // Never prepare/open canonical physical publication in this neutral batch.
    (f, transport, packet, remote)
}
fn synthetic_packet() -> EncryptedPeerPacket {
    EncryptedPeerPacket {
        room_authorization: None,
        peer_id: PEER.to_string(),
        dst_ip: "10.20.0.2".to_string(),
        wire_bytes: vec![4, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        is_business: false,
    }
}
fn pool(
    peers: Arc<crate::peer::PeerManager>,
    clients: Vec<(&str, Arc<RelayClient>)>,
) -> Arc<super::super::RelayRendezvous> {
    Arc::new(super::super::RelayRendezvous {
        plan: Arc::new(super::super::RelayRendezvousPlan {
            candidates: Vec::new(),
            node_id: "b18a-negative".to_string(),
            peers,
            ticket_cache: None,
            static_relay_ticket: None,
            allow_insecure_plaintext: true,
            ca_cert_path: None,
            connect_timeout: Duration::from_secs(1),
        }),
        routes: std::sync::Mutex::new(super::super::RendezvousRoutes {
            clients: clients
                .into_iter()
                .map(|(endpoint, client)| (endpoint.to_string(), client))
                .collect(),
            peers: std::collections::HashMap::new(),
        }),
        tasks: std::sync::Mutex::new(Vec::new()),
        stopped: AtomicBool::new(false),
        stop_attempted: AtomicBool::new(false),
    })
}
fn relay_error(result: crate::error::Result<()>) -> RelayError {
    match result {
        Err(crate::error::DaemonError::RelaySend { error, .. }) => error,
        other => panic!("typed original error expected: {other:?}"),
    }
}
async fn full_and_none(path: WriterPath) {
    let budget = Budget::new();
    let (f, _crypto, packet, mut remote) = ciphertext(budget).await;
    let mut fixture = Fixture::start(path, f.peers.clone(), budget).await;
    budget
        .step(fixture.transport().send_packet(&packet))
        .await
        .unwrap();
    fixture.frame(&packet, budget).await;
    let capture = RelaySendCapture::new(&packet).unwrap();
    let before = Arc::strong_count(&fixture.transport().client);
    budget
        .step(
            fixture
                .transport()
                .send_packet_with_origin(&packet, capture.clone()),
        )
        .await
        .unwrap();
    let frame = fixture.frame(&packet, budget).await;
    let (dst, bytes) = frame.parse_forward_payload().unwrap();
    assert_eq!(dst, PEER);
    assert_eq!(
        remote.decrypt_from_bytes(bytes).unwrap(),
        f.record.original_packet()
    );
    let full = match capture.finish() {
        RelayCaptureOutcome::Full(full) => full,
        _ => panic!("actual full must be captured"),
    };
    let fact = full.original().unwrap();
    assert!(fact.belongs_to_writer(&fixture.transport().client));
    assert_eq!(fact.destination(), PEER);
    assert_eq!(fact.data_len(), packet.wire_bytes.len());
    assert_eq!(
        fact.encoded_frame_len(),
        Frame::forward(PEER, &packet.wire_bytes)
            .unwrap()
            .encode()
            .len()
    );
    assert!(fact.write_started_at() <= fact.completed_at());
    assert_eq!(full.endpoint(), fixture.transport().endpoint());
    assert_eq!(full.connection_id(), fixture.transport().connection_id());
    assert_eq!(full.wire(), wire(&packet));
    assert!(full.source_is_live());
    assert_eq!(
        Arc::strong_count(&fixture.transport().client),
        before,
        "no source keeper"
    );
    assert_eq!(Arc::strong_count(&f.record), 1, "no A keeper");
    let weak = Arc::downgrade(&fixture.transport().client);
    fixture.finish(budget).await;
    assert!(weak.upgrade().is_none());
    assert!(!full.source_is_live());
}
async fn cancel_before_full(path: WriterPath) {
    let budget = Budget::new();
    let (f, _crypto, packet, _remote) = ciphertext(budget).await;
    let mut fixture = Fixture::start(path, f.peers.clone(), budget).await;
    let capture = RelaySendCapture::new(&packet).unwrap();
    let live = fixture.transport().write_boundaries_live.clone();
    {
        let _guard = live.lock().unwrap();
        let mut send = Box::pin(
            fixture
                .transport()
                .send_packet_with_origin(&packet, capture.clone()),
        );
        // No await precedes the original single queue try_send/oneshot wait.
        // Poll synchronously once; the lexical guard scope contains no await.
        // The original gate barrier is an explicit synthetic prewrite stall.
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        assert!(matches!(send.as_mut().poll(&mut context), Poll::Pending));
        assert_eq!(capture.branches().unwrap().len(), 1);
        assert_eq!(
            capture.branches().unwrap()[0].disposition(),
            RelayBranchDisposition::Unresolved
        );
        drop(send);
        assert!(matches!(capture.finish(), RelayCaptureOutcome::Uncertain));
        assert!(capture.branches().unwrap()[0].original().is_none());
    }
    fixture.frame(&packet, budget).await;
    assert!(matches!(capture.finish(), RelayCaptureOutcome::Uncertain));
    fixture.finish(budget).await;
}
async fn full_then_loss(path: WriterPath, panic_worker: bool) {
    let budget = Budget::new();
    let (f, _crypto, packet, _remote) = ciphertext(budget).await;
    let mut fixture = Fixture::start(path, f.peers.clone(), budget).await;
    let capture = RelaySendCapture::new(&packet).unwrap();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    capture.after_full_for_test(move || {
        let _ = entered_tx.send(());
        release_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("explicit fault release");
        if panic_worker {
            panic!("test-only observer panic AFTER genuine capture");
        }
    });
    let mut send = Box::pin(
        fixture
            .transport()
            .send_packet_with_origin(&packet, capture.clone()),
    );
    assert!(
        budget
            .step(poll_fn(|cx| Poll::Ready(matches!(
                send.as_mut().poll(cx),
                Poll::Pending
            ))))
            .await
    );
    budget.step(entered_rx).await.unwrap();
    assert!(capture.branches().unwrap()[0].original().is_some());
    if panic_worker {
        release_tx.send(()).unwrap();
        assert!(matches!(
            relay_error(budget.step(send).await),
            RelayError::WriterStoppedBeforeWrite
        ));
    } else {
        drop(send);
        release_tx.send(()).unwrap();
    }
    let full = match capture.finish() {
        RelayCaptureOutcome::Full(full) => full,
        _ => panic!("full survives completion loss"),
    };
    assert!(full
        .original()
        .unwrap()
        .belongs_to_writer(&fixture.transport().client));
    assert_eq!(full.disposition(), RelayBranchDisposition::FullWrite);
    fixture.frame(&packet, budget).await;
    fixture.finish(budget).await;
}
async fn prewrite_and_queue(path: WriterPath) {
    let budget = Budget::new();
    let (f, _crypto, packet, _remote) = ciphertext(budget).await;
    let mut fixture = Fixture::start(path, f.peers.clone(), budget).await;
    *fixture.transport().write_boundaries_live.lock().unwrap() = false;
    let refused = RelaySendCapture::new(&packet).unwrap();
    assert!(matches!(
        relay_error(
            budget
                .step(
                    fixture
                        .transport()
                        .send_packet_with_origin(&packet, refused.clone())
                )
                .await
        ),
        RelayError::WriteBoundaryRejected
    ));
    assert!(matches!(
        refused.finish(),
        RelayCaptureOutcome::DefinitelyNotHanded
    ));
    assert!(refused.branches().unwrap()[0].original().is_none());
    assert!(matches!(
        fixture.frames.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
    *fixture.transport().write_boundaries_live.lock().unwrap() = true;
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let blocked_transport = fixture.transport().clone();
    let blocked_packet = packet.clone();
    let blocked = tokio::spawn(async move {
        blocked_transport
            .send_packet_with_write_boundary(&blocked_packet, move |_| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("original prewrite fault release");
                false
            })
            .await
    });
    budget.step(entered_rx).await.unwrap();
    for _ in 0..128 {
        budget
            .step(fixture.transport().client.ping())
            .await
            .unwrap();
    }
    let full_queue = RelaySendCapture::new(&packet).unwrap();
    assert!(matches!(
        relay_error(
            budget
                .step(
                    fixture
                        .transport()
                        .send_packet_with_origin(&packet, full_queue.clone())
                )
                .await
        ),
        RelayError::CommandQueueFull
    ));
    assert!(matches!(
        full_queue.finish(),
        RelayCaptureOutcome::DefinitelyNotHanded
    ));
    assert!(full_queue.branches().unwrap()[0].original().is_none());
    fixture.transport().client.abort();
    release_tx.send(()).unwrap();
    assert!(matches!(
        relay_error(budget.step(blocked).await.unwrap()),
        RelayError::WriteBoundaryRejected
    ));
    fixture.finish(budget).await;
}
#[tokio::test]
async fn b18a_general_original_daemon_full_tcp_decrypt_and_none() {
    full_and_none(WriterPath::General).await;
}
#[tokio::test]
async fn b18a_legacy_real_connected_bridge_full_tcp_decrypt_and_none() {
    full_and_none(WriterPath::LegacyAddress).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_general_accepted_pending_cancel_late_full_closed() {
    cancel_before_full(WriterPath::General).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_legacy_accepted_pending_cancel_late_full_closed() {
    cancel_before_full(WriterPath::LegacyAddress).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_general_full_before_real_completion_receiver_drop() {
    full_then_loss(WriterPath::General, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_legacy_full_before_real_completion_receiver_drop() {
    full_then_loss(WriterPath::LegacyAddress, false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_general_full_then_synthetic_observer_panic() {
    full_then_loss(WriterPath::General, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_legacy_full_then_synthetic_observer_panic() {
    full_then_loss(WriterPath::LegacyAddress, true).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_general_original_typed_prewrite_and_queue128_full() {
    prewrite_and_queue(WriterPath::General).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b18a_legacy_original_typed_prewrite_and_queue128_full() {
    prewrite_and_queue(WriterPath::LegacyAddress).await;
}
#[tokio::test]
async fn b18a_original_fanout_two_real_writers_first_slot_and_weak_sources() {
    let budget = Budget::new();
    let (f, _crypto, packet, mut remote) = ciphertext(budget).await;
    let mut first = Fixture::start(WriterPath::General, f.peers.clone(), budget).await;
    let mut second = Fixture::start(WriterPath::LegacyAddress, f.peers.clone(), budget).await;
    let endpoints = (
        first.transport().endpoint().to_string(),
        second.transport().endpoint().to_string(),
    );
    let clients = (
        first.transport().client.clone(),
        second.transport().client.clone(),
    );
    first.transport.as_mut().unwrap().rendezvous = Some(pool(
        f.peers.clone(),
        vec![
            (&endpoints.0, clients.0.clone()),
            (&endpoints.1, clients.1.clone()),
        ],
    ));
    let capture = RelaySendCapture::new(&packet).unwrap();
    budget
        .step(
            first
                .transport()
                .send_packet_with_origin(&packet, capture.clone()),
        )
        .await
        .unwrap();
    let a = first.frame(&packet, budget).await;
    let b = second.frame(&packet, budget).await;
    assert_eq!(a, b);
    assert_eq!(
        remote
            .decrypt_from_bytes(a.parse_forward_payload().unwrap().1)
            .unwrap(),
        f.record.original_packet()
    );
    let branches = capture.branches().unwrap();
    assert_eq!(branches.len(), 2);
    for cell in branches {
        assert_eq!(cell.disposition(), RelayBranchDisposition::FullWrite);
        let expected = if cell.endpoint() == endpoints.0 {
            &clients.0
        } else {
            &clients.1
        };
        assert!(cell.original().unwrap().belongs_to_writer(expected));
        assert!(cell.source_is_live());
    }
    assert!(matches!(capture.finish(), RelayCaptureOutcome::Full(_)));
    drop(clients);
    first.finish(budget).await;
    second.finish(budget).await;
}
#[tokio::test]
async fn b18a_original_fanout_all_closed_prewrite_and_zero_selection() {
    let budget = Budget::new();
    let f = budget.step(mint_routed_request()).await;
    let packet = synthetic_packet();
    let mut transport =
        RelayTransport::connect_for_test("b18a-negative", "closed-main", f.peers.clone());
    transport.rendezvous = Some(pool(
        f.peers.clone(),
        vec![
            ("closed-one", Arc::new(RelayClient::new_for_test())),
            ("closed-two", Arc::new(RelayClient::new_for_test())),
        ],
    ));
    // Actual original JoinSet/try_send caller with explicitly NO KERNEL sockets.
    let capture = RelaySendCapture::new(&packet).unwrap();
    assert!(matches!(
        relay_error(
            budget
                .step(transport.send_packet_with_origin(&packet, capture.clone()))
                .await
        ),
        RelayError::WriterStoppedBeforeAccept
    ));
    assert_eq!(capture.branches().unwrap().len(), 2);
    assert!(capture.branches().unwrap().iter().all(|b| b.disposition()
        == RelayBranchDisposition::DefinitelyNotHanded
        && b.original().is_none()));
    assert!(matches!(
        capture.finish(),
        RelayCaptureOutcome::DefinitelyNotHanded
    ));
    transport.rendezvous = Some(pool(f.peers.clone(), Vec::new()));
    let zero = RelaySendCapture::new(&packet).unwrap();
    assert!(matches!(
        relay_error(
            budget
                .step(transport.send_packet_with_origin(&packet, zero.clone()))
                .await
        ),
        RelayError::WriterStoppedBeforeAccept
    ));
    assert!(zero.branches().unwrap().is_empty());
    assert!(matches!(
        zero.finish(),
        RelayCaptureOutcome::DefinitelyNotHanded
    ));
}
#[tokio::test]
async fn b18a_same_original_selection_endpoint_weak_pairs_and_known_route() {
    let budget = Budget::new();
    let f = budget.step(mint_routed_request()).await;
    let one = Arc::new(RelayClient::new_for_test());
    let two = Arc::new(RelayClient::new_for_test());
    let pool = pool(
        f.peers.clone(),
        vec![("first", one.clone()), ("second", two.clone())],
    );
    let before = (Arc::strong_count(&one), Arc::strong_count(&two));
    let (clients, selected) = pool.send_clients_with_origins(PEER);
    let selected = selected.unwrap();
    assert_eq!(clients.len(), 2);
    for (client, origin) in clients.iter().zip(&selected) {
        assert!(Weak::ptr_eq(&origin.writer, &Arc::downgrade(client)));
        assert!(Arc::ptr_eq(
            client,
            if origin.endpoint == "first" {
                &one
            } else {
                &two
            }
        ));
    }
    drop(clients);
    assert_eq!((Arc::strong_count(&one), Arc::strong_count(&two)), before);
    pool.routes
        .lock()
        .unwrap()
        .peers
        .insert(PEER.to_string(), "second".to_string());
    let (clients, selected) = pool.send_clients_with_origins(PEER);
    assert_eq!(clients.len(), 1);
    assert!(Arc::ptr_eq(&clients[0], &two));
    assert_eq!(selected.unwrap()[0].endpoint, "second");
}
#[tokio::test]
async fn b18a_synthetic_unknown_last_prewrite_missing_worker_and_metadata_failure() {
    let packet = synthetic_packet();
    let one = Arc::new(RelayClient::new_for_test());
    let two = Arc::new(RelayClient::new_for_test());
    let live = Arc::new(std::sync::Mutex::new(true));
    let make = || {
        let capture = RelaySendCapture::new(&packet).unwrap();
        capture.configure(
            &packet,
            Some(vec![
                SelectedRelayWriter::capture("one", &one).unwrap(),
                SelectedRelayWriter::capture("two", &two).unwrap(),
            ]),
            7,
            Arc::downgrade(&live),
        );
        capture
    };
    let unknown = make();
    unknown
        .branch(0)
        .unwrap()
        .note_result(&Err(RelayError::WriterStoppedBeforeWrite));
    unknown
        .branch(1)
        .unwrap()
        .note_result(&Err(RelayError::WriterStoppedBeforeAccept));
    assert!(
        matches!(unknown.finish(), RelayCaptureOutcome::Uncertain),
        "last prewrite never erases unknown"
    );
    let missing = make();
    missing
        .branch(1)
        .unwrap()
        .note_result(&Err(RelayError::WriteBoundaryRejected));
    assert!(
        matches!(missing.finish(), RelayCaptureOutcome::Uncertain),
        "missing/JoinError remains unresolved"
    );
    let handed = make();
    handed.branch(0).unwrap().note_handed();
    handed
        .branch(0)
        .unwrap()
        .note_result(&Err(RelayError::WriteBoundaryRejected));
    handed
        .branch(1)
        .unwrap()
        .note_result(&Err(RelayError::CommandQueueFull));
    assert!(
        matches!(handed.finish(), RelayCaptureOutcome::Uncertain),
        "accepted/partial/error cannot become prewrite"
    );
    let failed = RelaySendCapture::new(&packet).unwrap();
    failed.configure(&packet, None, 7, Arc::downgrade(&live));
    assert!(matches!(
        failed.finish(),
        RelayCaptureOutcome::MetadataFailed
    ));
    let reused = make();
    reused.configure(&packet, Some(Vec::new()), 7, Arc::downgrade(&live));
    assert!(reused.branch(0).is_none());
    assert!(matches!(
        reused.finish(),
        RelayCaptureOutcome::MetadataFailed
    ));
    // Synthetic mid-set phase fault, with NO manufactured fact/partial TCP.
    let in_flight = make();
    in_flight.first.phase.store(CAPTURING, Ordering::Release);
    assert!(matches!(in_flight.finish(), RelayCaptureOutcome::Uncertain));
    assert!(in_flight
        .first
        .phase
        .compare_exchange(CAPTURING, FULL, Ordering::Release, Ordering::Acquire)
        .is_err());
}

async fn full_before_reuse_is_failed(path: WriterPath) {
    let budget = Budget::new();
    let (f, _crypto, packet, mut remote) = ciphertext(budget).await;
    let mut fixture = Fixture::start(path, f.peers.clone(), budget).await;
    let capture = RelaySendCapture::new(&packet).unwrap();
    budget
        .step(
            fixture
                .transport()
                .send_packet_with_origin(&packet, capture.clone()),
        )
        .await
        .unwrap();
    let frame = fixture.frame(&packet, budget).await;
    assert_eq!(
        remote
            .decrypt_from_bytes(frame.parse_forward_payload().unwrap().1)
            .unwrap(),
        f.record.original_packet()
    );
    assert_eq!(capture.first.phase.load(Ordering::Acquire), FULL);
    let cell = capture.branches().unwrap()[0].clone();
    let original = cell.original().unwrap() as *const OriginalRelayWriteFact;
    assert!(cell
        .original()
        .unwrap()
        .belongs_to_writer(&fixture.transport().client));
    // A second original business send with the same capture still has its
    // original Result/selected vector. Its rejected metadata reuse must not
    // return the first send's historical full fact as this capture's outcome.
    budget
        .step(
            fixture
                .transport()
                .send_packet_with_origin(&packet, capture.clone()),
        )
        .await
        .unwrap();
    fixture.frame(&packet, budget).await;
    assert!(capture.metadata_failed.load(Ordering::Acquire));
    assert!(matches!(
        capture.finish(),
        RelayCaptureOutcome::MetadataFailed
    ));
    assert_eq!(
        cell.original().unwrap() as *const OriginalRelayWriteFact,
        original
    );
    assert!(
        cell.source_is_live(),
        "failure preserves historical Weak-source cell"
    );
    fixture.finish(budget).await;
}

#[tokio::test]
async fn b18a_general_actual_full_before_reuse_is_metadata_failed() {
    full_before_reuse_is_failed(WriterPath::General).await;
}
#[tokio::test]
async fn b18a_legacy_actual_full_before_reuse_is_metadata_failed() {
    full_before_reuse_is_failed(WriterPath::LegacyAddress).await;
}
