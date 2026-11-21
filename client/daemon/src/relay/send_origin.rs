//! Neutral metadata on the original RelayTransport selected writer branches.
//! This is not canonical A/B/G, current-owner qualification, final credit or ACK.
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock, Weak};

use super::{EncryptedPeerPacket, RelayClient};
use p2pnet_relay::OriginalRelayWriteFact;

const EMPTY: u8 = 0;
const CAPTURING: u8 = 1;
const FULL: u8 = 2;
const CLOSED: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RelayBranchDisposition {
    Unresolved = 0,
    HandedUnknown = 1,
    DefinitelyNotHanded = 2,
    Unknown = 3,
    FullWrite = 4,
}

pub(super) struct SelectedRelayWriter {
    endpoint: String,
    writer: Weak<RelayClient>,
}
impl SelectedRelayWriter {
    pub(super) fn capture(endpoint: &str, client: &Arc<RelayClient>) -> Option<Self> {
        let mut copy = String::new();
        copy.try_reserve_exact(endpoint.len()).ok()?;
        copy.push_str(endpoint);
        Some(Self {
            endpoint: copy,
            writer: Arc::downgrade(client),
        })
    }
    pub(super) fn single(endpoint: &str, client: &Arc<RelayClient>) -> Option<Vec<Self>> {
        let mut selected = Vec::new();
        selected.try_reserve_exact(1).ok()?;
        selected.push(Self::capture(endpoint, client)?);
        Some(selected)
    }
}

// Each cell has exactly the original FnOnce observer as its only fact setter.
// It holds Weak source identities and has no reference back to the capture/slot.
pub(crate) struct RelayFullSendFact {
    endpoint: String,
    writer: Weak<RelayClient>,
    live: Weak<std::sync::Mutex<bool>>,
    connection_id: u64,
    wire: (usize, Option<u64>, u64),
    disposition: AtomicU8,
    original: OnceLock<OriginalRelayWriteFact>,
    #[cfg(test)]
    after_original: OnceLock<TestAfterFull>,
}
impl RelayFullSendFact {
    #[cfg(test)]
    pub(crate) fn after_original_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        let _ = self
            .after_original
            .set(std::sync::Mutex::new(Some(Box::new(hook))));
    }
    pub(crate) fn matches_wire(&self, wire: (usize, Option<u64>, u64), peer: &str) -> bool {
        self.wire == wire
            && self
                .original()
                .is_some_and(|fact| fact.data_len() == wire.0 && fact.destination() == peer)
    }
    #[allow(dead_code)] // Immutable historical reader; no current-owner credit.
    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }
    #[allow(dead_code)] // Immutable historical reader; no current-owner credit.
    pub(crate) fn connection_id(&self) -> u64 {
        self.connection_id
    }
    #[allow(dead_code)] // Immutable historical reader; no current-owner credit.
    pub(crate) fn wire(&self) -> (usize, Option<u64>, u64) {
        self.wire
    }
    pub(crate) fn original(&self) -> Option<&OriginalRelayWriteFact> {
        self.original.get()
    }
    pub(crate) fn source_is_live(&self) -> bool {
        // Allocation identity/liveness only. Never inspect this gate's bool or
        // infer revocation, current writer, peer authorization or receipt.
        self.live.upgrade().is_some()
            && self.writer.upgrade().is_some_and(|writer| {
                self.original
                    .get()
                    .is_some_and(|fact| fact.belongs_to_writer(&writer))
            })
    }
    pub(super) fn matches_publication(
        &self,
        connection_id: u64,
        live: &Arc<std::sync::Mutex<bool>>,
    ) -> bool {
        self.connection_id == connection_id && self.live.ptr_eq(&Arc::downgrade(live))
    }
    pub(super) fn matches_client(&self, client: &Arc<RelayClient>) -> bool {
        self.writer.ptr_eq(&Arc::downgrade(client))
            && self
                .original()
                .is_some_and(|fact| fact.belongs_to_writer(client))
    }
    pub(crate) fn disposition(&self) -> RelayBranchDisposition {
        match self.disposition.load(Ordering::Acquire) {
            0 => RelayBranchDisposition::Unresolved,
            1 => RelayBranchDisposition::HandedUnknown,
            2 => RelayBranchDisposition::DefinitelyNotHanded,
            4 => RelayBranchDisposition::FullWrite,
            _ => RelayBranchDisposition::Unknown,
        }
    }
}

struct FirstRelayWrite {
    phase: AtomicU8,
    full: OnceLock<Arc<RelayFullSendFact>>,
    #[cfg(test)]
    after_full: OnceLock<TestAfterFull>,
}

// Only metadata Arcs are captured by the queue callbacks. FirstRelayWrite may
// own its winning cell; the cell never owns FirstRelayWrite, so no cycle exists.
pub(crate) struct RelaySendCapture {
    destination: String,
    wire: (usize, Option<u64>, u64),
    branches: OnceLock<Vec<Arc<RelayFullSendFact>>>,
    metadata_failed: AtomicBool,
    configured: AtomicBool,
    first: Arc<FirstRelayWrite>,
}
pub(crate) enum RelayCaptureOutcome {
    Full(Arc<RelayFullSendFact>),
    DefinitelyNotHanded,
    Uncertain,
    MetadataFailed,
}
impl RelaySendCapture {
    pub(crate) fn new(packet: &EncryptedPeerPacket) -> Option<Arc<Self>> {
        let mut destination = String::new();
        destination.try_reserve_exact(packet.peer_id.len()).ok()?;
        destination.push_str(&packet.peer_id);
        Some(Arc::new(Self {
            destination,
            wire: wire(packet),
            branches: OnceLock::new(),
            metadata_failed: AtomicBool::new(false),
            configured: AtomicBool::new(false),
            first: Arc::new(FirstRelayWrite {
                phase: AtomicU8::new(EMPTY),
                full: OnceLock::new(),
                #[cfg(test)]
                after_full: OnceLock::new(),
            }),
        }))
    }
    pub(super) fn configure(
        &self,
        packet: &EncryptedPeerPacket,
        selected: Option<Vec<SelectedRelayWriter>>,
        connection_id: u64,
        live: Weak<std::sync::Mutex<bool>>,
    ) {
        // One configure winner rejects reuse before obtaining any observers.
        // Neither a second vector setter nor a second cell setter is admitted.
        if self
            .configured
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        }
        // Prepare every original branch before the first queue call. No
        // endpoint is reconstructed after this original selection snapshot.
        if self.destination != packet.peer_id || self.wire != wire(packet) {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        }
        let Some(selected) = selected else {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        };
        let mut branches = Vec::new();
        if branches.try_reserve_exact(selected.len()).is_err() {
            self.metadata_failed.store(true, Ordering::Release);
            return;
        }
        for selected in selected {
            branches.push(Arc::new(RelayFullSendFact {
                endpoint: selected.endpoint,
                writer: selected.writer,
                live: live.clone(),
                connection_id,
                wire: self.wire,
                disposition: AtomicU8::new(RelayBranchDisposition::Unresolved as u8),
                original: OnceLock::new(),
                #[cfg(test)]
                after_original: OnceLock::new(),
            }));
        }
        // The original configure caller is the sole setter. Reusing a capture
        // is rejected as metadata failure; it cannot create a new attempt.
        if self.branches.set(branches).is_err() {
            self.metadata_failed.store(true, Ordering::Release);
        }
    }
    pub(super) fn branch(&self, index: usize) -> Option<RelayWriteObserver> {
        if self.metadata_failed.load(Ordering::Acquire) {
            return None;
        }
        Some(RelayWriteObserver {
            cell: self.branches.get()?.get(index)?.clone(),
            first: self.first.clone(),
        })
    }
    #[allow(dead_code)] // Staged finite reader; no drain, retry or spinning.
    pub(crate) fn branches(&self) -> Option<&[Arc<RelayFullSendFact>]> {
        self.branches.get().map(Vec::as_slice)
    }
    pub(crate) fn finish(&self) -> RelayCaptureOutcome {
        // One RMW seals capture. A callback still in Capturing is uncertain;
        // this reader never waits on a setter or retries its load/CAS.
        let previous = self.first.phase.swap(CLOSED, Ordering::AcqRel);
        // Failure/reuse is sticky and takes precedence over any earlier full
        // cell. Historical facts remain readable, but cannot be returned as
        // this invalid capture's result or a different send's success.
        if self.metadata_failed.load(Ordering::Acquire) {
            return RelayCaptureOutcome::MetadataFailed;
        }
        if previous == FULL {
            if let Some(full) = self.first.full.get() {
                return RelayCaptureOutcome::Full(full.clone());
            }
            return RelayCaptureOutcome::MetadataFailed;
        }
        if previous == CLOSED || previous == CAPTURING {
            return RelayCaptureOutcome::Uncertain;
        }
        // Includes explicitly configured zero selection. Missing/JoinError/
        // accepted-pending branches never equal DefinitelyNotHanded.
        if self.branches.get().is_some_and(|branches| {
            branches
                .iter()
                .all(|branch| branch.disposition() == RelayBranchDisposition::DefinitelyNotHanded)
        }) {
            RelayCaptureOutcome::DefinitelyNotHanded
        } else {
            RelayCaptureOutcome::Uncertain
        }
    }
    #[cfg(test)]
    pub(crate) fn after_full_for_test(&self, hook: impl FnOnce() + Send + 'static) {
        // Explicit test-only completion-loss/barrier fault outside the finite
        // production callback. This is not evidence of a partial TCP write.
        let _ = self
            .first
            .after_full
            .set(std::sync::Mutex::new(Some(Box::new(hook))));
    }
}
impl Drop for RelaySendCapture {
    fn drop(&mut self) {
        // Queued observers may outlive the caller, but cannot reopen capture.
        self.first.phase.swap(CLOSED, Ordering::AcqRel);
    }
}

#[derive(Clone)]
pub(super) struct RelayWriteObserver {
    cell: Arc<RelayFullSendFact>,
    first: Arc<FirstRelayWrite>,
}
impl RelayWriteObserver {
    pub(super) fn note_handed(&self) {
        let _ = self.cell.disposition.compare_exchange(
            RelayBranchDisposition::Unresolved as u8,
            RelayBranchDisposition::HandedUnknown as u8,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    pub(super) fn note_unknown(&self) {
        let previous = self.cell.disposition.load(Ordering::Acquire);
        if previous != RelayBranchDisposition::FullWrite as u8 {
            let _ = self.cell.disposition.compare_exchange(
                previous,
                RelayBranchDisposition::Unknown as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        }
    }
    pub(super) fn note_result(&self, result: &std::result::Result<(), p2pnet_relay::RelayError>) {
        use p2pnet_relay::RelayError;
        if matches!(
            result,
            Err(RelayError::CommandQueueFull
                | RelayError::WriterStoppedBeforeAccept
                | RelayError::WriteBoundaryRejected)
        ) {
            if self
                .cell
                .disposition
                .compare_exchange(
                    RelayBranchDisposition::Unresolved as u8,
                    RelayBranchDisposition::DefinitelyNotHanded as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                self.note_unknown();
            }
        } else if self.cell.disposition() != RelayBranchDisposition::FullWrite {
            self.note_unknown();
        }
    }
    pub(super) fn observe(self, fact: OriginalRelayWriteFact) {
        // This FnOnce has no clocks, locks, allocation, I/O, logging, panic,
        // await, spin or retry in production. Both facts/setters are genuine:
        // the private B16 factory runs only after its original full writer Ok.
        if self.cell.original.set(fact).is_err() {
            self.note_unknown();
            return;
        }
        self.cell
            .disposition
            .store(RelayBranchDisposition::FullWrite as u8, Ordering::Release);
        #[cfg(test)]
        if let Some(hook) = self.cell.after_original.get() {
            if let Some(hook) = hook.lock().unwrap_or_else(|p| p.into_inner()).take() {
                hook();
            }
        }
        if self
            .first
            .phase
            .compare_exchange(EMPTY, CAPTURING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        // Only the CAS winner can call set; competing observers never enter
        // OnceLock::set and therefore cannot wait for this writer callback.
        if self.first.full.set(self.cell.clone()).is_err() {
            let _ = self.first.phase.compare_exchange(
                CAPTURING,
                CLOSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return;
        }
        // Matching CAS is essential: finish may already have sealed Capturing.
        // A late full fact is historical cell evidence, never capture reopening.
        let published = self
            .first
            .phase
            .compare_exchange(CAPTURING, FULL, Ordering::Release, Ordering::Acquire)
            .is_ok();
        #[cfg(test)]
        if published {
            if let Some(hook) = self.first.after_full.get() {
                if let Some(hook) = hook.lock().unwrap_or_else(|p| p.into_inner()).take() {
                    hook();
                }
            }
        }
        #[cfg(not(test))]
        let _ = published;
    }
}

fn wire(packet: &EncryptedPeerPacket) -> (usize, Option<u64>, u64) {
    (
        packet.wire_bytes.len(),
        crate::transport::wire_counter(&packet.wire_bytes),
        crate::transport::wire_fingerprint(&packet.wire_bytes),
    )
}

#[cfg(test)]
type TestAfterFull = std::sync::Mutex<Option<Box<dyn FnOnce() + Send + 'static>>>;
#[cfg(test)]
#[path = "send_origin/tests.rs"]
mod tests;

// Shared cfg(test)-only real writer fixtures and labelled phase/ledger faults.
// They are not a production legacy connector, partial TCP or global emit fence.
#[cfg(test)]
pub(crate) mod publication_test_support {
    use super::*;
    use crate::relay::{RelayMessage, RelayTransport};
    use crate::request_carriage::test_support::{mint_routed_request, RoutedRequestFixture, PEER};
    use crate::transport::WireGuardTransport;
    use p2pnet_relay::protocol::{read_frame, Frame, MSG_FORWARD, MSG_PING, MSG_REGISTER};
    use p2pnet_relay::RelayClientConfig;
    use std::future::Future;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;
    use tokio::sync::{mpsc, oneshot};
    use tokio::task::JoinHandle;
    #[derive(Clone, Copy)]
    pub(crate) enum WriterPath {
        General,
        LegacyAddress,
    }
    #[derive(Clone, Copy)]
    pub(crate) struct Budget {
        end: tokio::time::Instant,
    }
    impl Budget {
        pub(crate) fn new() -> Self {
            Self {
                end: tokio::time::Instant::now() + Duration::from_secs(2),
            }
        }
        pub(crate) fn original_end(self) -> tokio::time::Instant {
            self.end
        }
        pub(crate) async fn step<T>(&self, future: impl Future<Output = T>) -> T {
            let end = self
                .end
                .min(tokio::time::Instant::now() + Duration::from_secs(1));
            tokio::time::timeout_at(end, future)
                .await
                .expect("B19 bounded original caller prerequisite timeout")
        }
    }
    pub(crate) async fn ping_original_writer(
        transport: &RelayTransport,
    ) -> p2pnet_relay::RelayResult<()> {
        transport.client.ping().await
    }
    pub(crate) struct Fixture {
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
        pub(crate) async fn start(
            path: WriterPath,
            peers: Arc<crate::peer::PeerManager>,
            budget: Budget,
        ) -> Self {
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
                    .step(RelayTransport::connect(&endpoint, "b19-general", peers))
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
                            "b19-legacy",
                            config,
                        ))
                        .await
                        .unwrap();
                    // Test-only shell for a genuinely connected legacy client. The
                    // public daemon connector uses general; no production bridge.
                    let transport = RelayTransport {
                        relay_connection_id: super::super::NEXT_RELAY_CONNECTION_ID
                            .fetch_add(1, Ordering::Relaxed),
                        relay_region: "b19-legacy-fixture".to_string(),
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
        pub(crate) fn transport(&self) -> &RelayTransport {
            self.transport.as_ref().unwrap()
        }
        pub(crate) async fn frame(
            &mut self,
            packet: &EncryptedPeerPacket,
            budget: Budget,
        ) -> Frame {
            let frame = budget.step(self.frames.recv()).await.unwrap();
            assert_eq!(
                frame,
                Frame::forward(&packet.peer_id, &packet.wire_bytes).unwrap()
            );
            frame
        }
        pub(crate) async fn finish(mut self, budget: Budget) {
            self.finish_joined(budget).await;
        }
        pub(crate) async fn finish_joined(&mut self, budget: Budget) {
            if let Some(transport) = self.transport.take() {
                transport.abort_writer();
            }
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(task) = self.task.as_mut() {
                let result = budget.step(task).await;
                drop(self.task.take());
                result.unwrap();
            }
        }
        pub(crate) async fn abort_and_join_server(
            &mut self,
            end: tokio::time::Instant,
        ) -> std::result::Result<(), String> {
            if let Some(transport) = self.transport.take() {
                transport.abort_writer();
            }
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            let Some(task) = self.task.as_mut() else {
                return Ok(());
            };
            task.abort();
            let result = tokio::time::timeout_at(end, task)
                .await
                .map_err(|_| "original fixture server cleanup deadline exceeded".to_string())?;
            drop(self.task.take());
            match result {
                Ok(()) => Ok(()),
                Err(error) if error.is_cancelled() => Ok(()),
                Err(error) => Err(format!("original fixture server panicked: {error}")),
            }
        }
    }
    pub(crate) fn sessions() -> (
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

    impl Fixture {
        pub(crate) async fn next_frame(&mut self, budget: Budget) -> Frame {
            budget.step(self.frames.recv()).await.unwrap()
        }
        pub(crate) fn client_count(&self) -> usize {
            Arc::strong_count(&self.transport().client)
        }
        pub(crate) fn weak_client(&self) -> Weak<RelayClient> {
            Arc::downgrade(&self.transport().client)
        }
        pub(crate) fn gate(&self) -> Arc<std::sync::Mutex<bool>> {
            self.transport().write_boundaries_live.clone()
        }
        pub(crate) fn set_live(&self, live: bool) {
            *self.transport().write_boundaries_live.lock().unwrap() = live;
        }
        pub(crate) fn fanout_with(&mut self, other: &Self) {
            let pool = pool(
                self.transport().peers.clone(),
                vec![
                    (self.transport().endpoint(), self.transport().client.clone()),
                    (
                        other.transport().endpoint(),
                        other.transport().client.clone(),
                    ),
                ],
            );
            self.transport.as_mut().unwrap().rendezvous = Some(pool);
        }
        pub(crate) fn stall_writer(
            &self,
            packet: EncryptedPeerPacket,
        ) -> (
            oneshot::Receiver<()>,
            std::sync::mpsc::SyncSender<()>,
            JoinHandle<crate::error::Result<()>>,
        ) {
            let (entered_tx, entered_rx) = oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
            let relay = self.transport().clone();
            let task = tokio::spawn(async move {
                relay
                    .send_packet_with_write_boundary(&packet, move |_| {
                        // This cfg(test) callback retains the production write locks.
                        // Hand off the runtime worker before notifying the test.
                        tokio::task::block_in_place(|| {
                            let _ = entered_tx.send(());
                            release_rx
                                .recv_timeout(Duration::from_secs(1))
                                .expect("explicit synthetic prewrite release");
                            false
                        })
                    })
                    .await
            });
            (entered_rx, release_tx, task)
        }
    }
    fn pool(
        peers: Arc<crate::peer::PeerManager>,
        clients: Vec<(&str, Arc<RelayClient>)>,
    ) -> Arc<super::super::RelayRendezvous> {
        Arc::new(super::super::RelayRendezvous {
            plan: Arc::new(super::super::RelayRendezvousPlan {
                candidates: Vec::new(),
                node_id: "b19-synthetic-selection".to_string(),
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
    pub(crate) fn closed_rendezvous(
        peers: Arc<crate::peer::PeerManager>,
        count: usize,
    ) -> RelayTransport {
        let mut relay =
            RelayTransport::connect_for_test("b19-synthetic", "closed-main", peers.clone());
        let endpoints: Vec<String> = (0..count).map(|i| format!("closed-{i}")).collect();
        let clients = endpoints
            .iter()
            .map(|endpoint| (endpoint.as_str(), Arc::new(RelayClient::new_for_test())))
            .collect();
        relay.rendezvous = Some(pool(peers, clients));
        relay
    }
    #[derive(Clone, Copy)]
    pub(crate) enum SyntheticBranch {
        Missing,
        TypedPrewrite,
        Accepted,
        Unknown,
    }
    pub(crate) fn synthetic_capture(
        packet: &EncryptedPeerPacket,
        states: &[SyntheticBranch],
    ) -> Arc<RelaySendCapture> {
        // Explicit synthetic ledger controls: no kernel socket and no full fact.
        let capture = RelaySendCapture::new(packet).unwrap();
        let live = Arc::new(std::sync::Mutex::new(true));
        let client = Arc::new(RelayClient::new_for_test());
        capture.configure(
            packet,
            Some(
                states
                    .iter()
                    .map(|_| SelectedRelayWriter::capture("synthetic", &client).unwrap())
                    .collect(),
            ),
            19,
            Arc::downgrade(&live),
        );
        for (index, state) in states.iter().enumerate() {
            let observer = capture.branch(index).unwrap();
            match state {
                SyntheticBranch::Missing => {}
                SyntheticBranch::TypedPrewrite => {
                    observer.note_result(&Err(p2pnet_relay::RelayError::WriterStoppedBeforeAccept))
                }
                SyntheticBranch::Accepted => {
                    observer.note_handed();
                    observer.note_result(&Err(p2pnet_relay::RelayError::WriteBoundaryRejected));
                }
                SyntheticBranch::Unknown => {
                    observer.note_result(&Err(p2pnet_relay::RelayError::WriterStoppedBeforeWrite))
                }
            }
        }
        capture
    }
    pub(crate) async fn cryptographic_fixture(
        budget: Budget,
        authorized: bool,
    ) -> (
        RoutedRequestFixture,
        WireGuardTransport,
        p2pnet_wireguard::TransportSession,
    ) {
        let f = budget.step(mint_routed_request()).await;
        let (session, remote) = sessions();
        let (transport, _rx) = WireGuardTransport::new_with_request_carriage();
        if authorized {
            budget
                .step(transport.replace_session_for_lifecycle(
                    PEER,
                    session,
                    f.record.expected_target_lifecycle().unwrap(),
                ))
                .await;
        } else {
            budget.step(transport.add_session(PEER, session)).await;
        }
        (f, transport, remote)
    }
    pub(crate) async fn encrypt_existing(
        f: &RoutedRequestFixture,
        transport: &WireGuardTransport,
        budget: Budget,
    ) -> (
        crate::request_carriage::EncryptedRequestDelivery,
        crate::overlay_requests::PreparedPhysicalPublication,
    ) {
        let emit = budget
            .step(transport.acquire_outbound_emit_guard(PEER))
            .await;
        let gate = f.peers.network_epoch_gate();
        let epoch = budget.step(gate.lock()).await;
        let packet = budget
            .step(transport.encrypt_request_with_emit_guard(f.delivery.clone()))
            .await
            .unwrap()
            .unwrap();
        let prepared = packet
            .prepare_physical_publication(
                &f.peers,
                transport,
                f.peers.current_network_generation_sync(),
            )
            .unwrap();
        drop(epoch);
        drop(emit);
        (packet, prepared)
    }
    pub(crate) async fn genuine_full(
        fixture: &mut Fixture,
        packet: &EncryptedPeerPacket,
        budget: Budget,
    ) -> Arc<RelayFullSendFact> {
        let capture = RelaySendCapture::new(packet).unwrap();
        budget
            .step(
                fixture
                    .transport()
                    .send_packet_with_origin(packet, capture.clone()),
            )
            .await
            .unwrap();
        fixture.frame(packet, budget).await;
        match capture.finish() {
            RelayCaptureOutcome::Full(fact) => fact,
            _ => panic!("genuine original full writer required"),
        }
    }
}
