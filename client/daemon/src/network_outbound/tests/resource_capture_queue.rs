//! Execute the real scheduler, task result retention, cancellation and merge.

use super::super::super::test_support::test_peer;
use super::*;
use crate::config::Config;
use crate::dataplane_resources::{
    FifoSnapshot, QueueStage, ResidencySnapshot, ResidencyStage, ResourceCapture,
};
use crate::transport::ResourceQueueTestGate;
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use tokio::time::{timeout_at, Instant as TokioInstant};

#[test]
fn resource_capture_late_actual_fifo_adoption_overflow_and_discard_keep_real_owner_totals() {
    let capture = ResourceCapture::new([0xe8; 16]);
    let mut queue = PeerPendingQueue::new();
    let first = packet(1, 128);
    let first_ptr = first.packet.as_ptr();
    let first_capacity = first.packet.capacity() as u64;
    let second = packet(2, 256);
    let mut capacity = first_capacity + second.packet.capacity() as u64;
    assert!(queue.enqueue(PendingPacket::plain(first)).0.is_empty());
    assert!(queue.enqueue(PendingPacket::plain(second)).0.is_empty());
    queue.attach_resource_capture(Some(&capture));
    let adopted = capture.residency_snapshot();
    assert!(adopted.coherent && adopted.valid);
    assert_eq!(adopted.unknown_bits, 1); // Earlier channel/history remains unknown.
    assert_eq!(adopted.total.unwrap().live_buffers, 2);
    assert_eq!(adopted.total.unwrap().capacity_bytes, capacity);
    assert_eq!(
        queue.queue.front().unwrap().raw_packet().as_ptr(),
        first_ptr
    );
    assert_eq!(adopted.total, adopted.stage(ResidencyStage::PendingFifo));
    for _ in 2..MAX_PENDING_PACKETS_PER_PEER {
        let filler = packet(3, 16);
        capacity += filler.packet.capacity() as u64;
        assert!(queue.enqueue(PendingPacket::plain(filler)).0.is_empty());
    }
    let next = packet(4, 512);
    capacity += next.packet.capacity() as u64;
    let (discarded, dropped_bytes) = queue.enqueue(PendingPacket::plain(next));
    assert_eq!(dropped_bytes, 4);
    assert_eq!(discarded.len(), 1);
    assert_eq!(discarded[0].raw_packet().as_ptr(), first_ptr);
    let overflow = capture.residency_snapshot();
    assert!(overflow.coherent && overflow.valid);
    assert_eq!(
        overflow.total.unwrap().live_buffers,
        (MAX_PENDING_PACKETS_PER_PEER + 1) as u64
    );
    assert_eq!(overflow.total.unwrap().capacity_bytes, capacity);
    assert_eq!(
        overflow
            .stage(ResidencyStage::DiscardBatch)
            .unwrap()
            .live_buffers,
        1
    );
    assert_eq!(
        overflow
            .stage(ResidencyStage::DiscardBatch)
            .unwrap()
            .capacity_bytes,
        first_capacity
    );
    drop(discarded);
    capacity -= first_capacity;
    let oversized = OutboundPacket {
        packet: vec![9; MAX_PENDING_BYTES_PER_PEER + 1],
        ..packet(9, 4)
    };
    let oversized_capacity = oversized.packet.capacity() as u64;
    let (discarded, dropped_bytes) = queue.enqueue(PendingPacket::plain(oversized));
    assert_eq!(dropped_bytes, MAX_PENDING_BYTES_PER_PEER + 1);
    let rejected = capture.residency_snapshot();
    assert!(rejected.coherent && rejected.valid);
    assert_eq!(
        rejected.total.unwrap().capacity_bytes,
        capacity + oversized_capacity
    );
    assert_eq!(
        rejected
            .stage(ResidencyStage::PendingFifo)
            .unwrap()
            .live_buffers,
        MAX_PENDING_PACKETS_PER_PEER as u64
    );
    assert_eq!(
        rejected
            .stage(ResidencyStage::DiscardBatch)
            .unwrap()
            .capacity_bytes,
        oversized_capacity
    );
    drop(discarded);
    let before_move = capture.residency_snapshot();
    let front = queue.pop_front().unwrap();
    assert_eq!(front.raw_packet(), [2; 4]);
    let detached = capture.residency_snapshot();
    assert_eq!(detached.total, before_move.total);
    assert_eq!(
        detached
            .stage(ResidencyStage::DetachedRaw)
            .unwrap()
            .live_buffers,
        1
    );
    queue.push_front(front);
    let returned = capture.residency_snapshot();
    assert_eq!(returned.total, before_move.total);
    assert_eq!(
        returned.capacity_high_water_bytes,
        before_move.capacity_high_water_bytes
    );
    assert_eq!(returned.clone_ops, Some(0));
    capture.finish();
    drop(queue);
    let drained = capture.residency_snapshot();
    assert!(drained.coherent && drained.valid);
    assert_eq!(drained.total.unwrap().live_buffers, 0);
    assert_eq!(drained.unknown_bits, 1);
    assert!(!drained.whole_pipeline_bytes_measured);
}

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
    residency: ResidencySnapshot,
}

fn position(resources: &ResourceCapture) -> Position {
    let snapshot = resources.snapshot();
    Position {
        actor: snapshot.fifo(QueueStage::ActorFifo),
        task: snapshot.fifo(QueueStage::TaskOrUnjoinedFifo),
        actor_scope: snapshot.fifo_scope_observed(QueueStage::ActorFifo),
        task_scope: snapshot.fifo_scope_observed(QueueStage::TaskOrUnjoinedFifo),
        valid: snapshot.valid,
        residency: resources.residency_snapshot(),
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
            assert!(pending["peer-a"].queue.front().unwrap().raw_packet() == [1; 4]);
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
            assert!(pending["peer-a"].queue.front().unwrap().raw_packet() == [2; 4]);
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
                assert!(pending["peer-a"].queue.front().unwrap().raw_packet() == [2; 4]);
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
                assert!(completed.queue.front().unwrap().raw_packet() == [1; 4]);
                assert_eq!(completed.wait_deadline, original_deadline);
                assert_eq!(completed.wait_generation, Some(generation));
                active.remove(&peer_id);
                merge_peer_work(&mut pending, peer_id, completed, &ctx);
                let merged = &pending["peer-a"];
                assert_eq!(merged.queue.len(), 2);
                assert_eq!(merged.bytes, 8);
                assert!(merged.queue.front().unwrap().raw_packet() == [1; 4]);
                assert!(merged.queue.iter().nth(1).unwrap().raw_packet() == [2; 4]);
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
    assert!(observed.residency.coherent && observed.residency.valid);
    let pending = observed
        .residency
        .stage(ResidencyStage::PendingFifo)
        .unwrap();
    assert_eq!(pending.live_buffers, actor.live_packets + task.live_packets);
    assert_eq!(pending.len_bytes, actor.plaintext_len + task.plaintext_len);
    assert_eq!(
        pending.capacity_bytes,
        actor.vec_capacity + task.vec_capacity
    );
    assert_eq!(observed.residency.total, Some(pending));
    assert_eq!(observed.residency.unknown_bits, 1); // Original fixture starts at FIFO ingress.
    assert_eq!(observed.residency.clone_ops, Some(0));
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
