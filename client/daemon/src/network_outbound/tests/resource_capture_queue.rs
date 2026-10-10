//! Execute the real scheduler, task result retention, cancellation and merge.

use super::super::super::test_support::test_peer;
use super::*;
use crate::config::Config;
use crate::dataplane_resources::{FifoSnapshot, QueueStage, ResourceCapture};
use crate::transport::ResourceQueueTestGate;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::time::{timeout_at, Instant as TokioInstant};

struct Children(JoinSet<(String, PeerPendingQueue)>);

impl Children {
    async fn abort_join(&mut self, deadline: TokioInstant) {
        self.0.abort_all();
        let mut panic = None;
        while let Some(result) = timeout_at(deadline, self.0.join_next())
            .await
            .expect("fixed cleanup deadline must join every real FIFO task")
        {
            if let Err(error) = result {
                if error.is_panic() {
                    if panic.is_none() {
                        panic = Some(error.into_panic());
                    }
                } else {
                    assert!(error.is_cancelled());
                }
            }
        }
        if let Some(panic) = panic {
            std::panic::resume_unwind(panic);
        }
    }
}

impl Drop for Children {
    fn drop(&mut self) {
        self.0.abort_all();
    }
}

struct ReleaseOnDrop(Arc<ResourceQueueTestGate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

#[derive(Clone, Copy)]
struct Position {
    actor: FifoSnapshot,
    task: FifoSnapshot,
    actor_scope: bool,
    task_scope: bool,
    valid: bool,
}

fn position(resources: &ResourceCapture) -> Position {
    let snapshot = resources.snapshot();
    Position {
        actor: snapshot.fifo(QueueStage::ActorFifo),
        task: snapshot.fifo(QueueStage::TaskOrUnjoinedFifo),
        actor_scope: snapshot.fifo_scope_observed(QueueStage::ActorFifo),
        task_scope: snapshot.fifo_scope_observed(QueueStage::TaskOrUnjoinedFifo),
        valid: snapshot.valid,
    }
}

struct Observations {
    old_capacity: u64,
    new_capacity: u64,
    held: Position,
    unjoined: Option<Position>,
    returned: Position,
    dropped: Position,
}

fn packet(sequence: u8, capacity: usize) -> OutboundPacket {
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(&[sequence; 4]);
    OutboundPacket {
        peer_id: "peer-a".into(),
        room_authorization: None,
        dst_ip: "10.20.0.2".into(),
        packet: bytes,
        trace: None,
    }
}

async fn workflow(
    abort: bool,
    deadline: TokioInstant,
    cleanup_deadline: TokioInstant,
) -> Observations {
    let resources = ResourceCapture::new([if abort { 0xa2 } else { 0xa1 }; 16]);
    let gate = Arc::new(ResourceQueueTestGate::new(deadline));
    let release = ReleaseOnDrop(gate.clone());
    let mut children = Children(JoinSet::new());
    let result = timeout_at(
        deadline,
        AssertUnwindSafe(async {
            let peers = Arc::new(PeerManager::new(
                Config::generate_default("https://ctrl.test", "net1").unwrap(),
            ));
            peers
                .add_peer(&test_peer("peer-a", "127.0.0.1:41000".parse().unwrap()))
                .await;
            let (transport, mut encrypted_outbound) = WireGuardTransport::new();
            let transport = transport
                .with_resource_capture(resources.clone())
                .unwrap()
                .with_resource_queue_gate_for_test(gate.clone());
            let ctx = PeerWorkContext {
                transport,
                peers,
                prefer_direct: true,
                udp_transport: Arc::new(RwLock::new(None)),
                relay_transport: Arc::new(RwLock::new(None)),
                startup_wait: RelayStartupWait {
                    relay_expected: false,
                    timeout: Some(Duration::from_secs(5)),
                },
                timeline: ConnectionTimeline::new("resource-fifo", 0),
                stopping: Arc::new(AtomicBool::new(false)),
            };
            let generation = ctx.peers.current_network_generation_sync();
            let mut pending = HashMap::new();
            let mut active = HashMap::new();
            let (probe_tx, _) = watch::channel(0);
            let mut probe_kick = 0;
            let old = packet(1, 128);
            let old_capacity = old.packet.capacity() as u64;
            append_ingress(old, &mut pending, &ctx, &mut probe_kick, &probe_tx);
            let original_deadline = pending["peer-a"].wait_deadline;
            assert!(original_deadline.is_some());
            assert_eq!(pending["peer-a"].wait_generation, Some(generation));
            assert_eq!(pending["peer-a"].bytes, 4);
            assert_eq!(pending["peer-a"].queue.len(), 1);
            assert!(pending["peer-a"].queue[0].raw_packet() == [1; 4]);
            schedule_peer_work(&mut pending, &mut children.0, &mut active, &ctx);
            gate.wait_entered().await;
            let task = gate.task();
            assert_eq!(active.get("peer-a"), Some(&task.id()));
            assert_eq!(children.0.len(), 1);
            assert!(!task.is_finished());
            assert!(pending["peer-a"].queue.is_empty());
            assert_eq!(pending["peer-a"].bytes, 0);
            assert_eq!(pending["peer-a"].wait_deadline, original_deadline);
            let newer = packet(2, 256);
            let new_capacity = newer.packet.capacity() as u64;
            append_ingress(newer, &mut pending, &ctx, &mut probe_kick, &probe_tx);
            assert_eq!(pending["peer-a"].queue.len(), 1);
            assert_eq!(pending["peer-a"].bytes, 4);
            assert!(pending["peer-a"].queue[0].raw_packet() == [2; 4]);
            assert_eq!(pending["peer-a"].wait_deadline, original_deadline);
            let held = position(&resources);
            let unjoined;
            if abort {
                children.0.abort_all();
                let error = timeout_at(
                    deadline.min(TokioInstant::now() + Duration::from_secs(1)),
                    children.0.join_next(),
                )
                .await
                .expect("cancelled FIFO task must be joined within one second")
                .expect("the real scheduled task must remain in its JoinSet")
                .err()
                .expect("held task must be cancelled before the release");
                assert!(error.is_cancelled());
                assert_eq!(error.id(), task.id());
                assert!(task.is_finished());
                active.remove("peer-a");
                unjoined = None;
                assert_eq!(pending["peer-a"].queue.len(), 1);
                assert!(pending["peer-a"].queue[0].raw_packet() == [2; 4]);
                assert_eq!(pending["peer-a"].wait_deadline, original_deadline);
            } else {
                gate.release();
                timeout_at(
                    deadline.min(TokioInstant::now() + Duration::from_secs(1)),
                    async {
                        while !task.is_finished() {
                            tokio::task::yield_now().await;
                        }
                    },
                )
                .await
                .expect("real task must finish without joining its result");
                assert_eq!(children.0.len(), 1);
                assert_eq!(active.get("peer-a"), Some(&task.id()));
                unjoined = Some(position(&resources));
                let (peer_id, completed) = timeout_at(
                    deadline.min(TokioInstant::now() + Duration::from_secs(1)),
                    children.0.join_next(),
                )
                .await
                .expect("finished task must be joined within one second")
                .expect("actual task result must exist")
                .expect("actual FIFO task must not panic");
                assert_eq!(peer_id, "peer-a");
                assert_eq!(completed.queue.len(), 1);
                assert_eq!(completed.bytes, 4);
                assert!(completed.queue[0].raw_packet() == [1; 4]);
                assert_eq!(completed.wait_deadline, original_deadline);
                assert_eq!(completed.wait_generation, Some(generation));
                active.remove(&peer_id);
                merge_peer_work(&mut pending, peer_id, completed, &ctx);
                let merged = &pending["peer-a"];
                assert_eq!(merged.queue.len(), 2);
                assert_eq!(merged.bytes, 8);
                assert!(merged.queue[0].raw_packet() == [1; 4]);
                assert!(merged.queue[1].raw_packet() == [2; 4]);
                assert_eq!(merged.wait_deadline, original_deadline);
                assert_eq!(merged.wait_generation, Some(generation));
            }
            assert!(children.0.is_empty());
            assert!(active.is_empty());
            assert!(matches!(
                encrypted_outbound.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
            assert!(ctx.peers.outbound_loss_stats().await.drops.is_empty());
            let returned = position(&resources);
            resources.finish();
            drop(pending);
            let dropped = position(&resources);
            Observations {
                old_capacity,
                new_capacity,
                held,
                unjoined,
                returned,
                dropped,
            }
        })
        .catch_unwind(),
    )
    .await;
    drop(release);
    children.abort_join(cleanup_deadline).await;
    match result {
        Ok(Ok(observed)) => observed,
        Ok(Err(panic)) => std::panic::resume_unwind(panic),
        Err(_) => panic!("fixed four-second FIFO workflow deadline"),
    }
}

fn assert_position(observed: Position, actor: FifoSnapshot, task: FifoSnapshot) {
    assert!(observed.valid);
    // The first RED targets actual task-owned bytes, including an unjoined
    // result. Zero with no observed lease remains missing coverage.
    assert_eq!(
        observed.task, task,
        "actual task/unjoined FIFO observations missing"
    );
    assert_eq!(
        observed.actor, actor,
        "actual actor FIFO observations missing"
    );
    assert!(observed.actor_scope);
    assert!(observed.task_scope);
}

#[tokio::test]
async fn actual_joinset_fifo_ownership_completion_merge_and_abort_require_live_gauges() {
    // Reserve the final second for release, cancellation and joining even if
    // a workflow fails; both actual workflows share this absolute bound.
    let whole_deadline = TokioInstant::now() + Duration::from_secs(5);
    let work_deadline = whole_deadline - Duration::from_secs(1);
    let complete = workflow(false, work_deadline, whole_deadline).await;
    let aborted = workflow(true, work_deadline, whole_deadline).await;
    for (observed, abort) in [(complete, false), (aborted, true)] {
        let newer = FifoSnapshot {
            live_packets: 1,
            plaintext_len: 4,
            vec_capacity: observed.new_capacity,
        };
        let older = FifoSnapshot {
            live_packets: 1,
            plaintext_len: 4,
            vec_capacity: observed.old_capacity,
        };
        assert_position(observed.held, newer, older);
        if let Some(unjoined) = observed.unjoined {
            assert_position(unjoined, newer, older);
        }
        let returned = if abort {
            newer
        } else {
            FifoSnapshot {
                live_packets: 2,
                plaintext_len: 8,
                vec_capacity: observed.old_capacity + observed.new_capacity,
            }
        };
        assert_position(observed.returned, returned, FifoSnapshot::default());
        assert_position(
            observed.dropped,
            FifoSnapshot::default(),
            FifoSnapshot::default(),
        );
    }
}
