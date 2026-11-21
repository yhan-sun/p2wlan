// Real loopback TCP controls exercise the two original writer algorithms.
// These facts are local full application writes, not NIC/remote ACK authority.
// Private factory/time setters are never invoked by these fixtures.

use crate::client::{OriginalRelayWriteFact, RelayClient, RelayMessage};
use crate::protocol::{read_frame, Frame, MSG_FORWARD, MSG_PING, MSG_REGISTER};
use crate::RelayClientConfig;
use std::future::{poll_fn, Future};
use std::sync::Arc;
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

#[derive(Clone, Copy)]
enum WriterPath {
    Address,
    Endpoint,
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
        let until = self
            .end
            .min(tokio::time::Instant::now() + Duration::from_secs(1));
        tokio::time::timeout_at(until, future)
            .await
            .expect("original-write fixture prerequisite timed out")
    }
}

struct Peer {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    frames: mpsc::Receiver<Frame>,
}

impl Drop for Peer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct Fixture {
    client: Option<Arc<RelayClient>>,
    _inbound: mpsc::Receiver<RelayMessage>,
    peer: Peer,
}

impl Fixture {
    async fn start(path: WriterPath, node: &str, budget: Budget) -> Self {
        let listener = budget.step(TcpListener::bind("127.0.0.1:0")).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (frames_tx, frames) = mpsc::channel(4);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = stopped => {},
                _ = async {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let registered = read_frame(&mut stream).await.unwrap();
                    assert_eq!(registered.msg_type, MSG_REGISTER);
                    let node = std::str::from_utf8(&registered.payload).unwrap();
                    stream.write_all(&Frame::registered(node).encode()).await.unwrap();
                    while let Ok(frame) = read_frame(&mut stream).await {
                        match frame.msg_type {
                            MSG_FORWARD => {
                                if frames_tx.send(frame).await.is_err() {
                                    break;
                                }
                            }
                            MSG_PING => {
                                if stream.write_all(&Frame::new(
                                    crate::protocol::MSG_PONG,
                                    frame.payload,
                                ).encode()).await.is_err() {
                                    break;
                                }
                            }
                            other => panic!("unexpected original writer frame {other}"),
                        }
                    }
                } => {},
            }
        });
        let peer = Peer {
            stop: Some(stop),
            task: Some(task),
            frames,
        };
        let config = RelayClientConfig {
            register_timeout: Duration::from_secs(1),
            allow_insecure_plaintext: true,
            ..Default::default()
        };
        let (client, inbound) = match path {
            WriterPath::Address => {
                budget
                    .step(RelayClient::connect_with_config(
                        &addr.to_string(),
                        node,
                        config,
                    ))
                    .await
            }
            WriterPath::Endpoint => {
                budget
                    .step(RelayClient::connect_with_endpoint(
                        &format!("tcp://{addr}"),
                        node,
                        config,
                    ))
                    .await
            }
        }
        .unwrap();
        Self {
            client: Some(Arc::new(client)),
            _inbound: inbound,
            peer,
        }
    }

    fn client(&self) -> Arc<RelayClient> {
        self.client.as_ref().unwrap().clone()
    }

    async fn wire(&mut self, dst: &str, bytes: &[u8], budget: Budget) {
        let frame = budget.step(self.peer.frames.recv()).await.unwrap();
        assert_eq!(frame, Frame::forward(dst, bytes).unwrap());
    }

    async fn finish(mut self, budget: Budget) {
        if let Some(client) = self.client.take() {
            client.abort();
            drop(client);
        }
        if let Some(stop) = self.peer.stop.take() {
            let _ = stop.send(());
        }
        if let Some(mut task) = self.peer.task.take() {
            let until = budget
                .end
                .min(tokio::time::Instant::now() + Duration::from_secs(1));
            let joined = tokio::time::timeout_at(until, &mut task).await;
            if joined.is_err() {
                task.abort();
            }
            joined.expect("owned TCP peer cleanup timed out").unwrap();
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(client) = &self.client {
            client.abort();
        }
    }
}

async fn full_and_legacy(path: WriterPath) {
    let budget = Budget::new();
    let mut fixture = Fixture::start(path, "write-full", budget).await;
    let client = fixture.client();
    let (pre_tx, pre_rx) = oneshot::channel();
    let (fact_tx, fact_rx) = oneshot::channel();
    let data = b"original exact full Forward bytes";
    budget
        .step(client.send_data_with_write_boundary_and_observer(
            "peer-full",
            data,
            move |started| {
                let _ = pre_tx.send(started);
                true
            },
            move |fact| {
                let _ = fact_tx.send(fact);
            },
        ))
        .await
        .unwrap();
    let pre = budget.step(pre_rx).await.unwrap();
    let fact = budget.step(fact_rx).await.unwrap();
    assert_eq!(fact.destination(), "peer-full");
    assert_eq!(fact.data_len(), data.len());
    assert_eq!(
        fact.encoded_frame_len(),
        Frame::forward("peer-full", data).unwrap().encode().len()
    );
    assert_eq!(fact.write_started_at(), pre);
    assert!(fact.completed_at() >= pre);
    assert!(fact.belongs_to_writer(&client));
    fixture.wire("peer-full", data, budget).await;

    // Existing public APIs still send exact bytes on the same original writer.
    // Their observer=None and absent extra completion clock are static properties.
    budget
        .step(client.send_data("peer-old", b"legacy no observer"))
        .await
        .unwrap();
    fixture
        .wire("peer-old", b"legacy no observer", budget)
        .await;
    budget
        .step(client.send_data_with_write_boundary("peer-old-hook", b"old hook", |_| true))
        .await
        .unwrap();
    fixture.wire("peer-old-hook", b"old hook", budget).await;
    drop(client);
    fixture.finish(budget).await;
}

async fn queue_delay(path: WriterPath) {
    let budget = Budget::new();
    let mut fixture = Fixture::start(path, "write-queue", budget).await;
    let client = fixture.client();
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client
            .send_data_with_write_boundary("peer", b"rejected-first", move |_| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("queue gate release");
                false
            })
            .await
    });
    budget.step(entered_rx).await.unwrap();

    let (pre_tx, pre_rx) = oneshot::channel();
    let (fact_tx, fact_rx) = oneshot::channel();
    let mut queued = Box::pin(client.send_data_with_write_boundary_and_observer(
        "peer-queued",
        b"queued exact bytes",
        move |started| {
            let _ = pre_tx.send(started);
            true
        },
        move |fact| {
            let _ = fact_tx.send(fact);
        },
    ));
    // Poll the actual API once while the original writer is blocked in its hook.
    // This accepts the real command but cannot complete it or mint a full fact.
    let pending = budget
        .step(poll_fn(|cx| {
            Poll::Ready(matches!(queued.as_mut().poll(cx), Poll::Pending))
        }))
        .await;
    assert!(pending);
    assert_eq!(client.cmd_tx.capacity(), client.cmd_tx.max_capacity() - 1);
    let released_at = Instant::now();
    release_tx.send(()).unwrap();
    assert!(matches!(
        budget.step(first).await.unwrap(),
        Err(crate::RelayError::WriteBoundaryRejected)
    ));
    budget.step(queued.as_mut()).await.unwrap();
    drop(queued);
    let pre = budget.step(pre_rx).await.unwrap();
    let fact = budget.step(fact_rx).await.unwrap();
    assert!(
        pre >= released_at,
        "prehook time must exclude original command wait"
    );
    assert_eq!(fact.write_started_at(), pre);
    assert!(fact.completed_at() >= pre);
    fixture
        .wire("peer-queued", b"queued exact bytes", budget)
        .await;
    drop(client);
    fixture.finish(budget).await;
}

async fn prewrite_and_full_queue(path: WriterPath) {
    let budget = Budget::new();
    let fixture = Fixture::start(path, "write-refusal", budget).await;
    let client = fixture.client();
    let (fact_tx, fact_rx) = oneshot::channel::<OriginalRelayWriteFact>();
    let rejected = budget
        .step(client.send_data_with_write_boundary_and_observer(
            "peer",
            b"refused",
            |_| false,
            move |fact| {
                let _ = fact_tx.send(fact);
            },
        ))
        .await;
    assert!(matches!(
        rejected,
        Err(crate::RelayError::WriteBoundaryRejected)
    ));
    assert!(budget.step(fact_rx).await.is_err());

    let (fact_tx, fact_rx) = oneshot::channel::<OriginalRelayWriteFact>();
    let large = vec![1; 65_535];
    let oversized = budget
        .step(client.send_data_with_write_boundary_and_observer(
            "peer",
            &large,
            |_| true,
            move |fact| {
                let _ = fact_tx.send(fact);
            },
        ))
        .await;
    assert!(matches!(
        oversized,
        Err(crate::RelayError::FrameTooLarge(_, _))
    ));
    assert!(budget.step(fact_rx).await.is_err());
    budget.step(client.cmd_tx.closed()).await;
    let (fact_tx, fact_rx) = oneshot::channel::<OriginalRelayWriteFact>();
    let closed = budget
        .step(client.send_data_with_write_boundary_and_observer(
            "peer",
            b"already stopped",
            |_| true,
            move |fact| {
                let _ = fact_tx.send(fact);
            },
        ))
        .await;
    assert!(matches!(
        closed,
        Err(crate::RelayError::WriterStoppedBeforeAccept)
    ));
    assert!(budget.step(fact_rx).await.is_err());
    // FrameTooLarge follows the unchanged original writer failure/close policy.
    drop(client);
    fixture.finish(budget).await;

    let fixture = Fixture::start(path, "write-full-queue", budget).await;
    let client = fixture.client();
    assert_eq!(client.cmd_tx.max_capacity(), 128);
    let (entered_tx, entered_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let first_client = client.clone();
    let first = tokio::spawn(async move {
        first_client
            .send_data_with_write_boundary("peer", b"hold", move |_| {
                let _ = entered_tx.send(());
                release_rx
                    .recv_timeout(Duration::from_secs(1))
                    .expect("full queue gate release");
                false
            })
            .await
    });
    budget.step(entered_rx).await.unwrap();
    for _ in 0..128 {
        budget.step(client.ping()).await.unwrap();
    }
    assert_eq!(client.cmd_tx.capacity(), 0);
    let (fact_tx, fact_rx) = oneshot::channel::<OriginalRelayWriteFact>();
    let full = budget
        .step(client.send_data_with_write_boundary_and_observer(
            "peer",
            b"not accepted",
            |_| true,
            move |fact| {
                let _ = fact_tx.send(fact);
            },
        ))
        .await;
    assert!(matches!(full, Err(crate::RelayError::CommandQueueFull)));
    assert!(budget.step(fact_rx).await.is_err());
    client.abort();
    release_tx.send(()).unwrap();
    assert!(matches!(
        budget.step(first).await.unwrap(),
        Err(crate::RelayError::WriteBoundaryRejected)
    ));
    drop(client);
    fixture.finish(budget).await;
}

async fn identity_retirement(path: WriterPath) {
    let budget = Budget::new();
    let mut first = Fixture::start(path, "write-identity-one", budget).await;
    let second = Fixture::start(path, "write-identity-two", budget).await;
    let first_client = first.client();
    let second_client = second.client();
    let (fact_tx, fact_rx) = oneshot::channel();
    budget
        .step(first_client.send_data_with_write_boundary_and_observer(
            "peer-id",
            b"identity",
            |_| true,
            move |fact| {
                let _ = fact_tx.send(fact);
            },
        ))
        .await
        .unwrap();
    let fact = budget.step(fact_rx).await.unwrap();
    first.wire("peer-id", b"identity", budget).await;
    assert!(fact.belongs_to_writer(&first_client));
    assert!(!fact.belongs_to_writer(&second_client));
    assert!(!fact.writer_channel_retired());
    first_client.abort();
    // Closing does not change original channel identity: it is not eligibility.
    assert!(fact.belongs_to_writer(&first_client));
    drop(first_client);
    drop(first.client.take());
    assert!(
        fact.writer_channel_retired(),
        "neutral fact must not keep a strong Sender"
    );
    assert!(!fact.belongs_to_writer(&second_client));
    drop(second_client);
    first.finish(budget).await;
    second.finish(budget).await;
}

async fn dropped_completion_after_full(path: WriterPath) {
    let budget = Budget::new();
    let mut fixture = Fixture::start(path, "write-drop-completion", budget).await;
    let client = fixture.client();
    let (fact_tx, fact_rx) = oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let mut send = Box::pin(client.send_data_with_write_boundary_and_observer(
        "peer-drop",
        b"full before caller drop",
        |_| true,
        move |fact| {
            let _ = fact_tx.send(fact);
            release_rx
                .recv_timeout(Duration::from_secs(1))
                .expect("observer release");
        },
    ));
    assert!(
        budget
            .step(poll_fn(|cx| {
                Poll::Ready(matches!(send.as_mut().poll(cx), Poll::Pending))
            }))
            .await
    );
    let fact = budget.step(fact_rx).await.unwrap();
    assert!(fact.belongs_to_writer(&client));
    // Callback already has the actual full-write fact, completion is not sent.
    drop(send);
    release_tx.send(()).unwrap();
    fixture
        .wire("peer-drop", b"full before caller drop", budget)
        .await;
    budget
        .step(client.send_data("peer-after", b"writer stays usable"))
        .await
        .unwrap();
    fixture
        .wire("peer-after", b"writer stays usable", budget)
        .await;
    drop(client);
    fixture.finish(budget).await;
}

async fn observer_panic_is_uncertain(path: WriterPath) {
    let budget = Budget::new();
    let mut fixture = Fixture::start(path, "write-observer-panic", budget).await;
    let client = fixture.client();
    let (fact_tx, fact_rx) = oneshot::channel();
    let result = budget
        .step(client.send_data_with_write_boundary_and_observer(
            "peer-panic",
            b"full before opt-in panic",
            |_| true,
            move |fact| {
                let _ = fact_tx.send(fact);
                panic!("explicit opt-in observer panic after full application write");
            },
        ))
        .await;
    assert!(matches!(
        result,
        Err(crate::RelayError::WriterStoppedBeforeWrite)
    ));
    let fact = budget.step(fact_rx).await.unwrap();
    assert!(fact.belongs_to_writer(&client));
    fixture
        .wire("peer-panic", b"full before opt-in panic", budget)
        .await;
    // The old error denotes accepted-but-no-completion, never proven prewrite.
    drop(client);
    fixture.finish(budget).await;
}

#[tokio::test]
async fn b2_lib_address_real_full_and_legacy_none_compatibility() {
    full_and_legacy(WriterPath::Address).await;
}

#[tokio::test]
async fn b2_lib_endpoint_real_full_and_legacy_none_compatibility() {
    full_and_legacy(WriterPath::Endpoint).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_lib_address_real_queue_delay_excluded_from_write_time() {
    queue_delay(WriterPath::Address).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_lib_endpoint_real_queue_delay_excluded_from_write_time() {
    queue_delay(WriterPath::Endpoint).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_lib_address_real_prewrite_refusals_and_full_original_queue_no_fact() {
    prewrite_and_full_queue(WriterPath::Address).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_lib_endpoint_real_prewrite_refusals_and_full_original_queue_no_fact() {
    prewrite_and_full_queue(WriterPath::Endpoint).await;
}

#[tokio::test]
async fn b2_lib_address_real_command_identity_and_weak_retirement() {
    identity_retirement(WriterPath::Address).await;
}

#[tokio::test]
async fn b2_lib_endpoint_real_command_identity_and_weak_retirement() {
    identity_retirement(WriterPath::Endpoint).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_lib_address_real_caller_drop_after_full_write_keeps_fact() {
    dropped_completion_after_full(WriterPath::Address).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn b2_lib_endpoint_real_caller_drop_after_full_write_keeps_fact() {
    dropped_completion_after_full(WriterPath::Endpoint).await;
}

#[tokio::test]
async fn b2_lib_address_real_opt_in_panic_completion_loss_is_uncertain() {
    observer_panic_is_uncertain(WriterPath::Address).await;
}

#[tokio::test]
async fn b2_lib_endpoint_real_opt_in_panic_completion_loss_is_uncertain() {
    observer_panic_is_uncertain(WriterPath::Endpoint).await;
}
