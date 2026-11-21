//! Real TCP inputs exercise the two original library readers. These controls
//! observe full application-frame reads, not NIC arrival or business ACK credit.
//! No test can construct a Some read fact or change the witness's private time.

use crate::client::{OriginalRelayDelivery, OriginalRelayReadWitness};
use crate::protocol::{Frame, ERR_IDLE_TIMEOUT, FRAME_HEADER_SIZE, MSG_RECEIVED, MSG_REGISTER};
use crate::{RelayClient, RelayClientConfig, RelayCloseReason, RelayMessage};
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

type Check = std::result::Result<(), String>;

#[derive(Clone, Copy)]
enum ReaderPath {
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
    async fn step<T>(
        &self,
        label: &str,
        future: impl Future<Output = T>,
    ) -> std::result::Result<T, String> {
        // One fixed two-second test end; individual observations may only tighten it.
        let until = self
            .end
            .min(tokio::time::Instant::now() + Duration::from_secs(1));
        tokio::time::timeout_at(until, future)
            .await
            .map_err(|_| format!("fixture prerequisite timeout: {label}"))
    }
}

fn require(condition: bool, message: &str) -> Check {
    if condition {
        Ok(())
    } else {
        Err(message.to_string())
    }
}

fn combine(body: Check, cleanup: Check) -> Check {
    match (body, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}

fn empty<T>(rx: &mut mpsc::Receiver<T>) -> Check {
    match rx.try_recv() {
        Err(mpsc::error::TryRecvError::Empty) => Ok(()),
        Err(mpsc::error::TryRecvError::Disconnected) => Err("receiver unexpectedly closed".into()),
        Ok(_) => Err("unexpected output before complete valid Data".into()),
    }
}

struct WireGate {
    reached: Notify,
    release: Notify,
}
impl WireGate {
    fn new() -> Self {
        Self {
            reached: Notify::new(),
            release: Notify::new(),
        }
    }
    async fn wait(&self) {
        self.reached.notified().await;
    }
    fn release(&self) {
        self.release.notify_one();
    }
}

enum WireStep {
    Write(Vec<u8>),
    Pause(Arc<WireGate>),
    HalfClose,
}

struct OwnedPeer {
    addr: SocketAddr,
    stop: Arc<Notify>,
    task: Option<JoinHandle<Check>>,
}

impl OwnedPeer {
    async fn start(steps: Vec<WireStep>, budget: Budget) -> std::result::Result<Self, String> {
        let listener = budget
            .step("bind real loopback TCP", TcpListener::bind("127.0.0.1:0"))
            .await?
            .map_err(|error| error.to_string())?;
        let addr = listener.local_addr().map_err(|error| error.to_string())?;
        let stop = Arc::new(Notify::new());
        let stopped = stop.clone();
        // The fixture creates exactly one owned handler. The two client tasks are
        // the original reader/writer, stopped by their original close watch.
        let task = tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = stopped.notified() => Ok(()),
                result = serve(listener, steps, budget) => result,
            }
        });
        Ok(Self {
            addr,
            stop,
            task: Some(task),
        })
    }

    async fn stop_and_join(&mut self, budget: Budget) -> Check {
        self.stop.notify_one();
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let result = tokio::time::timeout_at(budget.end, &mut *task).await;
        match result {
            Ok(joined) => {
                let _ = self.task.take();
                joined.map_err(|error| format!("owned TCP handler join failed: {error}"))?
            }
            Err(_) => {
                task.abort();
                // An exhausted fixed end is a fixture failure, never a success
                // receipt. Drop keeps the abort fallback; no extra grace is added.
                Err("owned TCP handler not joined within fixed test end".into())
            }
        }
    }
}

impl Drop for OwnedPeer {
    fn drop(&mut self) {
        self.stop.notify_one();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve(listener: TcpListener, steps: Vec<WireStep>, budget: Budget) -> Check {
    let (mut stream, _) = budget
        .step("accept actual TCP", listener.accept())
        .await?
        .map_err(|error| error.to_string())?;
    stream
        .set_nodelay(true)
        .map_err(|error| error.to_string())?;
    let mut header = [0u8; FRAME_HEADER_SIZE];
    budget
        .step(
            "read actual Register header",
            stream.read_exact(&mut header),
        )
        .await?
        .map_err(|error| error.to_string())?;
    let length = u16::from_be_bytes([header[6], header[7]]) as usize;
    // This is only the external peer's fixture input check, not a product cap.
    require(
        length == 1,
        "fixture expected the actual one-byte node Register",
    )?;
    let mut registered_input = header.to_vec();
    registered_input.push(0);
    budget
        .step(
            "read actual Register payload",
            stream.read_exact(&mut registered_input[FRAME_HEADER_SIZE..]),
        )
        .await?
        .map_err(|error| error.to_string())?;
    let (register, consumed) =
        Frame::decode(&registered_input).map_err(|error| error.to_string())?;
    require(
        register.msg_type == MSG_REGISTER
            && register.payload.as_slice() == b"n"
            && consumed == registered_input.len(),
        "actual client registration was not the expected frame",
    )?;
    budget
        .step(
            "write actual Registered frame",
            stream.write_all(&Frame::registered("n").encode()),
        )
        .await?
        .map_err(|error| error.to_string())?;
    for step in steps {
        match step {
            WireStep::Write(bytes) => {
                budget
                    .step("write scripted TCP bytes", stream.write_all(&bytes))
                    .await?
                    .map_err(|error| error.to_string())?;
            }
            WireStep::Pause(gate) => {
                gate.reached.notify_one();
                // External byte-production barrier only, not proof that the
                // client consumed a partial prefix. The real witness is separate.
                budget
                    .step("release scripted TCP byte barrier", gate.release.notified())
                    .await?;
            }
            WireStep::HalfClose => {
                budget
                    .step("peer write-half FIN", stream.shutdown())
                    .await?
                    .map_err(|error| error.to_string())?;
            }
        }
    }
    // Drain client keepalives without replying, so timeout controls exercise the
    // original reader deadline rather than an induced writer socket failure.
    let mut drained = [0u8; 256];
    loop {
        match tokio::time::timeout_at(budget.end, stream.read(&mut drained)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => {}
            Ok(Err(error)) => return Err(format!("fixture TCP drain failed: {error}")),
            Err(_) => return Err("fixture handler exceeded fixed test end".into()),
        }
    }
}

fn config() -> RelayClientConfig {
    RelayClientConfig {
        connect_timeout: Duration::from_secs(1),
        register_timeout: Duration::from_secs(1),
        allow_insecure_plaintext: true,
        ..Default::default()
    }
}

struct SourcedPeer {
    owner: OwnedPeer,
    client: RelayClient,
    rx: mpsc::Receiver<OriginalRelayDelivery>,
    witness: Arc<OriginalRelayReadWitness>,
    budget: Budget,
}

impl SourcedPeer {
    async fn connect(
        path: ReaderPath,
        config: RelayClientConfig,
        steps: Vec<WireStep>,
        budget: Budget,
    ) -> std::result::Result<Self, String> {
        let mut owner = OwnedPeer::start(steps, budget).await?;
        let witness = Arc::new(OriginalRelayReadWitness::new());
        let connected = budget
            .step("actual sourced registration", async {
                match path {
                    ReaderPath::Address => {
                        RelayClient::connect_with_config_and_read_origin_witness(
                            &owner.addr.to_string(),
                            "n",
                            config,
                            witness.clone(),
                        )
                        .await
                    }
                    ReaderPath::Endpoint => {
                        RelayClient::connect_with_endpoint_and_read_origin_witness(
                            &format!("tcp://{}", owner.addr),
                            "n",
                            config,
                            witness.clone(),
                        )
                        .await
                    }
                }
            })
            .await
            .and_then(|result| result.map_err(|error| error.to_string()));
        match connected {
            Ok((client, rx)) => Ok(Self {
                owner,
                client,
                rx,
                witness,
                budget,
            }),
            Err(error) => {
                witness.release();
                let cleanup = owner.stop_and_join(budget).await;
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(format!("{error}; cleanup: {cleanup}")),
                }
            }
        }
    }

    async fn next(&mut self) -> std::result::Result<OriginalRelayDelivery, String> {
        self.budget
            .step("receive actual original-channel delivery", self.rx.recv())
            .await?
            .ok_or_else(|| "actual inbound channel closed before expected item".into())
    }

    async fn captured(&self) -> std::result::Result<Instant, String> {
        self.budget
            .step(
                "first valid actual Data read witness",
                self.witness.wait_captured(),
            )
            .await?;
        self.witness
            .completed_at()
            .ok_or_else(|| "real witness notified without a captured read".into())
    }

    async fn finish(&mut self, body: Check) -> Check {
        self.client.abort();
        self.witness.release();
        let joined = self.owner.stop_and_join(self.budget).await;
        // Drain the original receiver to observe release of the reader's actual
        // sender. No public JoinHandle exists for the original writer; do not
        // claim a writer native wait based on this receiver closure.
        let receiver_closed = self
            .budget
            .step("original reader sender closure", async {
                while self.rx.recv().await.is_some() {}
            })
            .await;
        combine(body, combine(joined, receiver_closed))
    }
}

impl Drop for SourcedPeer {
    fn drop(&mut self) {
        self.client.abort();
        self.witness.release();
    }
}

fn data_time(
    delivery: OriginalRelayDelivery,
    source: &str,
    bytes: &[u8],
) -> std::result::Result<Instant, String> {
    let (message, read) = delivery.into_parts();
    require(
        message
            == RelayMessage::Data {
                from_node: source.to_string(),
                data: bytes.to_vec(),
            },
        "actual Data source or complete bytes changed",
    )?;
    let at = read
        .ok_or_else(|| "actual complete valid TCP Data had Unknown read origin".to_string())?
        .completed_at();
    require(
        at <= Instant::now(),
        "original full read cannot follow consumption",
    )?;
    Ok(at)
}

fn control(delivery: OriginalRelayDelivery, expected: RelayMessage) -> Check {
    let (message, read) = delivery.into_parts();
    require(
        message == expected,
        "original control or terminal classification changed",
    )?;
    require(
        read.is_none(),
        "control/terminal message must retain Unknown read origin",
    )
}

fn received(source: &str, bytes: &[u8]) -> std::result::Result<Vec<u8>, String> {
    Frame::received(source, bytes)
        .map(|frame| frame.encode())
        .map_err(|error| error.to_string())
}

async fn fresh_complete(path: ReaderPath, budget: Budget) -> Check {
    let wire = received("p", b"fresh positive")?;
    let mut peer =
        SourcedPeer::connect(path, config(), vec![WireStep::Write(wire)], budget).await?;
    let body = async {
        let captured = peer.captured().await?;
        empty(&mut peer.rx)?;
        peer.witness.release();
        let actual = data_time(peer.next().await?, "p", b"fresh positive")?;
        require(
            actual == captured,
            "fresh actual Data did not retain captured origin",
        )
    }
    .await;
    peer.finish(body).await
}

async fn fragmented(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let header_prefix = Arc::new(WireGate::new());
    let payload_prefix = Arc::new(WireGate::new());
    let wire = received("peer-original", b"actual full split payload")?;
    let steps = vec![
        WireStep::Write(wire[..FRAME_HEADER_SIZE - 1].to_vec()),
        WireStep::Pause(header_prefix.clone()),
        WireStep::Write(wire[FRAME_HEADER_SIZE - 1..wire.len() - 1].to_vec()),
        WireStep::Pause(payload_prefix.clone()),
        WireStep::Write(wire[wire.len() - 1..].to_vec()),
    ];
    let mut peer = SourcedPeer::connect(path, config(), steps, budget).await?;
    let body = async {
        budget
            .step("peer wrote partial header", header_prefix.wait())
            .await?;
        require(
            peer.witness.completed_at().is_none(),
            "partial header fabricated complete Data origin",
        )?;
        empty(&mut peer.rx)?;
        header_prefix.release();
        budget
            .step("peer wrote partial payload", payload_prefix.wait())
            .await?;
        require(
            peer.witness.completed_at().is_none(),
            "partial payload fabricated complete Data origin",
        )?;
        empty(&mut peer.rx)?;
        let before_last_byte = Instant::now();
        payload_prefix.release();
        let original = peer.captured().await?;
        require(
            original >= before_last_byte,
            "origin preceded release of missing final TCP payload byte",
        )?;
        empty(&mut peer.rx)?;
        peer.witness.release();
        let actual = data_time(
            peer.next().await?,
            "peer-original",
            b"actual full split payload",
        )?;
        require(
            actual == original,
            "Data queue item resampled or lost original full read time",
        )
    }
    .await;
    peer.finish(body).await
}

async fn malformed_payloads(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let invalid = [vec![], vec![9, b'p'], vec![1, 0xff]];
    let mut steps: Vec<_> = invalid
        .into_iter()
        .map(|payload| WireStep::Write(Frame::new(MSG_RECEIVED, payload).encode()))
        .collect();
    steps.push(WireStep::Write(received("p", b"valid after malformed")?));
    let mut peer = SourcedPeer::connect(path, config(), steps, budget).await?;
    let body = async {
        let original = peer.captured().await?;
        // All three preceding frames crossed the actual parser before this first
        // valid-frame witness. They must not appear as Data or close the reader.
        empty(&mut peer.rx)?;
        peer.witness.release();
        let actual = data_time(peer.next().await?, "p", b"valid after malformed")?;
        require(
            actual == original,
            "invalid parser inputs displaced first valid origin",
        )
    }
    .await;
    peer.finish(body).await
}

async fn invalid_headers(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let valid = received("p", b"v")?;
    let mut bad_magic = valid[..FRAME_HEADER_SIZE].to_vec();
    bad_magic[0] = b'X';
    let mut bad_version = valid[..FRAME_HEADER_SIZE].to_vec();
    bad_version[4] = 2;
    let mut too_large = valid[..FRAME_HEADER_SIZE].to_vec();
    too_large[6..8].copy_from_slice(&17u16.to_be_bytes());
    for header in [bad_magic, bad_version, too_large] {
        let mut limits = config();
        limits.max_frame_payload = 16;
        let mut peer =
            SourcedPeer::connect(path, limits, vec![WireStep::Write(header)], budget).await?;
        let body = async {
            control(
                peer.next().await?,
                RelayMessage::Closed {
                    reason: RelayCloseReason::LocalShutdown,
                },
            )?;
            require(
                peer.witness.completed_at().is_none(),
                "rejected header fabricated Data read origin",
            )
        }
        .await;
        peer.finish(body).await?;
    }
    fresh_complete(path, budget).await
}

async fn eof_parts(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let full = received("p", b"eof payload")?;
    for (prefix, reason) in [
        (
            full[..FRAME_HEADER_SIZE - 1].to_vec(),
            RelayCloseReason::ServerEof,
        ),
        (full[..full.len() - 1].to_vec(), RelayCloseReason::IoError),
    ] {
        let mut peer = SourcedPeer::connect(
            path,
            config(),
            vec![WireStep::Write(prefix), WireStep::HalfClose],
            budget,
        )
        .await?;
        let body = async {
            control(peer.next().await?, RelayMessage::Closed { reason })?;
            require(
                peer.witness.completed_at().is_none(),
                "truncated header/payload fabricated complete origin",
            )
        }
        .await;
        peer.finish(body).await?;
    }
    fresh_complete(path, budget).await
}

async fn idle_parts(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let full = received("p", b"timeout payload")?;
    for (prefix, message) in [
        (full[..FRAME_HEADER_SIZE - 1].to_vec(), "idle timeout"),
        (
            full[..full.len() - 1].to_vec(),
            "idle timeout during payload",
        ),
    ] {
        let limits = RelayClientConfig {
            idle_timeout: Duration::from_millis(100),
            keepalive_interval: Duration::from_millis(50),
            ..config()
        };
        // Original effective idle formula is 100 + 3*50 = 250ms. The peer
        // drains writer PING bytes but sends no response; there is no sleep.
        let mut peer =
            SourcedPeer::connect(path, limits, vec![WireStep::Write(prefix)], budget).await?;
        let body = async {
            control(
                peer.next().await?,
                RelayMessage::Error {
                    code: ERR_IDLE_TIMEOUT,
                    message: message.into(),
                },
            )?;
            control(
                peer.next().await?,
                RelayMessage::Closed {
                    reason: RelayCloseReason::IdleTimeout,
                },
            )?;
            require(
                peer.witness.completed_at().is_none(),
                "timeout fabricated complete Data read origin",
            )
        }
        .await;
        peer.finish(body).await?;
    }
    fresh_complete(path, budget).await
}

async fn inbound_backpressure(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let tokens = [u64::MAX - 7, u64::MAX - 8];
    let steps = vec![
        WireStep::Write(Frame::pong(tokens[0]).encode()),
        WireStep::Write(Frame::pong(tokens[1]).encode()),
        WireStep::Write(received("p", b"original behind full queue")?),
        WireStep::Write(received("p", b"fresh second actual frame")?),
    ];
    let limits = RelayClientConfig {
        inbound_queue_capacity: 2,
        ..config()
    };
    let mut peer = SourcedPeer::connect(path, limits, steps, budget).await?;
    let body = async {
        let original = peer.captured().await?;
        require(
            peer.rx.len() == 2,
            "two actual parsed Pong controls did not fill original inbound2",
        )?;
        peer.witness.release();
        tokio::task::yield_now().await;
        require(
            peer.rx.len() == 2,
            "valid Data bypassed the original bounded full queue",
        )?;
        for token in tokens {
            control(
                peer.next().await?,
                RelayMessage::Pong {
                    timestamp: token,
                    round_trip_time: None,
                },
            )?;
        }
        let actual = data_time(peer.next().await?, "p", b"original behind full queue")?;
        require(
            actual == original,
            "queue-pressure Data resampled its original read completion",
        )?;
        let second = data_time(peer.next().await?, "p", b"fresh second actual frame")?;
        require(
            second >= original,
            "second real frame carried an older read time",
        )?;
        require(
            peer.witness.completed_at() == Some(original),
            "second actual Data overwrote first-frame witness",
        )
    }
    .await;
    peer.finish(body).await
}

async fn legacy_api(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let token = u64::MAX - 9;
    let steps = vec![
        WireStep::Write(received("p", b"legacy real TCP bytes")?),
        WireStep::Write(Frame::pong(token).encode()),
        WireStep::Write(Frame::error(404, "old control").encode()),
        WireStep::Write(Frame::close(0).encode()),
    ];
    let mut owner = OwnedPeer::start(steps, budget).await?;
    // The annotation verifies the original public receiver shape; no bridge or
    // second queue converts production messages. From conversion is at consumption.
    let connected = budget
        .step("original public legacy registration", async {
            match path {
                ReaderPath::Address => {
                    RelayClient::connect_verified_with_config(
                        &owner.addr.to_string(),
                        "n",
                        config(),
                    )
                    .await
                }
                ReaderPath::Endpoint => {
                    RelayClient::connect_with_endpoint(
                        &format!("tcp://{}", owner.addr),
                        "n",
                        config(),
                    )
                    .await
                }
            }
        })
        .await
        .and_then(|result| result.map_err(|error| error.to_string()));
    let (client, mut rx): (RelayClient, mpsc::Receiver<RelayMessage>) = match connected {
        Ok(pair) => pair,
        Err(error) => {
            let cleanup = owner.stop_and_join(budget).await;
            return combine(Err(error), cleanup);
        }
    };
    let body = async {
        for expected in [
            RelayMessage::Data {
                from_node: "p".into(),
                data: b"legacy real TCP bytes".to_vec(),
            },
            RelayMessage::Pong {
                timestamp: token,
                round_trip_time: None,
            },
            RelayMessage::Error {
                code: 404,
                message: "old control".into(),
            },
            RelayMessage::Closed {
                reason: RelayCloseReason::ServerCloseFrame,
            },
        ] {
            let message = budget
                .step("receive original public legacy item", rx.recv())
                .await?
                .ok_or_else(|| "legacy channel ended before actual expected frame".to_string())?;
            require(
                message == expected,
                "original public legacy bytes/controls changed",
            )?;
            let (_, read) = OriginalRelayDelivery::from(message).into_parts();
            require(
                read.is_none(),
                "legacy public conversion fabricated a full-read origin",
            )?;
        }
        Ok(())
    }
    .await;
    client.abort();
    let joined = owner.stop_and_join(budget).await;
    let receiver_closed = budget
        .step("legacy original reader closure", async {
            while rx.recv().await.is_some() {}
        })
        .await;
    combine(body, combine(joined, receiver_closed))
}

#[tokio::test]
async fn b3_r02_address_actual_split_header_payload_original_read() -> Check {
    fragmented(ReaderPath::Address).await
}
#[tokio::test]
async fn b3_r01_endpoint_actual_split_header_payload_original_read() -> Check {
    fragmented(ReaderPath::Endpoint).await
}
#[tokio::test]
async fn b3_r02_address_actual_invalid_payload_then_fresh_valid() -> Check {
    malformed_payloads(ReaderPath::Address).await
}
#[tokio::test]
async fn b3_r01_endpoint_actual_invalid_payload_then_fresh_valid() -> Check {
    malformed_payloads(ReaderPath::Endpoint).await
}
#[tokio::test]
async fn b3_r02_address_actual_invalid_headers_have_no_origin() -> Check {
    invalid_headers(ReaderPath::Address).await
}
#[tokio::test]
async fn b3_r01_endpoint_actual_invalid_headers_have_no_origin() -> Check {
    invalid_headers(ReaderPath::Endpoint).await
}
#[tokio::test]
async fn b3_r02_address_actual_partial_eof_has_no_origin() -> Check {
    eof_parts(ReaderPath::Address).await
}
#[tokio::test]
async fn b3_r01_endpoint_actual_partial_eof_has_no_origin() -> Check {
    eof_parts(ReaderPath::Endpoint).await
}
#[tokio::test]
async fn b3_r02_address_actual_header_payload_idle_has_no_origin() -> Check {
    idle_parts(ReaderPath::Address).await
}
#[tokio::test]
async fn b3_r01_endpoint_actual_header_payload_idle_has_no_origin() -> Check {
    idle_parts(ReaderPath::Endpoint).await
}
#[tokio::test]
async fn b3_r03_address_actual_inbound2_retains_original_read() -> Check {
    inbound_backpressure(ReaderPath::Address).await
}
#[tokio::test]
async fn b3_r03_endpoint_actual_inbound2_retains_original_read() -> Check {
    inbound_backpressure(ReaderPath::Endpoint).await
}
#[tokio::test]
async fn b3_r09_address_original_public_api_real_frames_unknown() -> Check {
    legacy_api(ReaderPath::Address).await
}
#[tokio::test]
async fn b3_r09_endpoint_original_public_api_real_frames_unknown() -> Check {
    legacy_api(ReaderPath::Endpoint).await
}

async fn original_client_identity(path: ReaderPath) -> Check {
    let budget = Budget::new();
    let wire = received("p", b"original reader identity")?;
    let mut peer =
        SourcedPeer::connect(path, config(), vec![WireStep::Write(wire)], budget).await?;
    let mut other = match SourcedPeer::connect(path, config(), Vec::new(), budget).await {
        Ok(other) => other,
        Err(error) => return peer.finish(Err(error)).await,
    };
    let mut retained = None;
    let body = async {
        let captured_at = peer.captured().await?;
        peer.witness.release();
        let (message, fact) = peer.next().await?.into_parts();
        require(
            message
                == RelayMessage::Data {
                    from_node: "p".into(),
                    data: b"original reader identity".to_vec(),
                },
            "identity carrier changed the real Data payload",
        )?;
        let fact = fact.ok_or_else(|| "actual reader identity missing".to_string())?;
        let before = peer.client.cmd_tx.strong_count();
        require(
            fact.completed_at() == captured_at,
            "identity resampled read time",
        )?;
        require(
            fact.belongs_to_client(&peer.client),
            "same original client rejected",
        )?;
        require(
            !fact.belongs_to_client(&other.client),
            "different actual client accepted",
        )?;
        require(
            peer.client.cmd_tx.strong_count() == before,
            "identity comparison retained the original command sender",
        )?;
        // Close is deliberately independent of historical identity. This API
        // cannot serve as the later synchronized current-owner qualification.
        peer.client.abort();
        require(
            fact.belongs_to_client(&peer.client),
            "close rewrote historical identity",
        )?;
        let copy = fact.clone();
        require(
            copy.completed_at() == captured_at && copy.belongs_to_client(&peer.client),
            "immutable source clone changed its original time or client",
        )?;
        require(
            peer.client.cmd_tx.strong_count() == before,
            "immutable source clone retained the original command sender",
        )?;
        retained = Some(copy);
        Ok(())
    }
    .await;
    let result = peer.finish(body).await;
    let result = combine(result, other.finish(Ok(())).await);
    drop(peer);
    drop(other);
    combine(
        result,
        require(
            retained
                .as_ref()
                .is_some_and(|fact| fact.reader_channel_retired()),
            "retained read fact kept the old client command sender alive",
        ),
    )
}

#[tokio::test]
async fn original_read_address_client_identity_is_weak_and_exact() -> Check {
    original_client_identity(ReaderPath::Address).await
}

#[tokio::test]
async fn original_read_endpoint_client_identity_is_weak_and_exact() -> Check {
    original_client_identity(ReaderPath::Endpoint).await
}

#[test]
fn b3_r09_caller_built_data_cannot_create_read_origin() -> Check {
    let message = RelayMessage::Data {
        from_node: "caller".into(),
        data: b"legacy input".to_vec(),
    };
    let (same, read) = OriginalRelayDelivery::from(message.clone()).into_parts();
    require(
        same == message && read.is_none(),
        "public caller-built Data conversion must stay Unknown",
    )
}

mod close_lifecycle;
