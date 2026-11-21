//! Instance-local, test-only synchronization at the actual FIFO task owner.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::task::AbortHandle;
use tokio::time::{timeout_at, Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerLossPoint {
    BeforePhysicalHandoff,
    AfterRecordedSent,
}

/// Saved from the original actor only after its real JoinSet returned Err.
pub(crate) struct WorkerLossObservation {
    pub(crate) task_id: tokio::task::Id,
    pub(crate) cancelled: bool,
    pub(crate) active_removed: bool,
    pub(crate) actor_packets: usize,
    pub(crate) front_token: Option<crate::overlay_requests::RequestSendToken>,
    pub(crate) front_len: usize,
    pub(crate) front_capacity: usize,
    pub(crate) generation: Option<u64>,
    pub(crate) delivery_deadline: Option<std::time::Instant>,
    pub(crate) wait_deadline: Option<std::time::Instant>,
}

pub(crate) struct ResourceQueueTestGate {
    armed: AtomicBool,
    released: AtomicBool,
    entered: Semaphore,
    release: Semaphore,
    task: Mutex<Option<AbortHandle>>,
    workflow_deadline: Instant,
    loss_point: Option<WorkerLossPoint>,
    task_registered: Semaphore,
    original_delivery_deadline: Mutex<Option<std::time::Instant>>,
    loss: Mutex<Option<WorkerLossObservation>>,
    loss_entered: Semaphore,
    loss_release: Semaphore,
    loss_released: AtomicBool,
    abort_children: AtomicBool,
    selected_joined: AtomicBool,
}

impl ResourceQueueTestGate {
    pub(crate) fn new(workflow_deadline: Instant) -> Self {
        Self {
            armed: AtomicBool::new(true),
            released: AtomicBool::new(false),
            entered: Semaphore::new(0),
            release: Semaphore::new(0),
            task: Mutex::new(None),
            workflow_deadline,
            loss_point: None,
            task_registered: Semaphore::new(0),
            original_delivery_deadline: Mutex::new(None),
            loss: Mutex::new(None),
            loss_entered: Semaphore::new(0),
            loss_release: Semaphore::new(0),
            loss_released: AtomicBool::new(false),
            abort_children: AtomicBool::new(false),
            selected_joined: AtomicBool::new(false),
        }
    }

    pub(crate) fn for_worker_loss(deadline: Instant, point: WorkerLossPoint) -> Self {
        let mut gate = Self::new(deadline);
        gate.loss_point = Some(point);
        gate
    }

    pub(crate) async fn pause_once(&self) {
        if self.loss_point.is_some() {
            return;
        }
        if !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        self.entered.add_permits(1);
        let bound = self
            .workflow_deadline
            .min(Instant::now() + std::time::Duration::from_secs(2));
        timeout_at(bound, self.release.acquire())
            .await
            .expect("test-only FIFO release deadline")
            .expect("test-only FIFO release semaphore")
            .forget();
    }

    pub(crate) async fn wait_entered(&self) {
        let bound = self
            .workflow_deadline
            .min(Instant::now() + std::time::Duration::from_secs(1));
        timeout_at(bound, self.entered.acquire())
            .await
            .expect("actual FIFO task must reach bounded owner gate")
            .expect("test-only FIFO arrival semaphore")
            .forget();
    }

    pub(crate) fn release(&self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.release.add_permits(1);
        }
    }

    pub(crate) fn observe_task(&self, task: AbortHandle) {
        if self.loss_point.is_some() && self.abort_children.load(Ordering::Acquire) {
            task.abort();
        }
        let mut slot = self.task.lock().unwrap_or_else(|error| error.into_inner());
        if self.loss_point.is_some() && slot.is_some() {
            // Recovery tasks use the same real scheduler; never replace the
            // selected first owner or mistake a later task for the fault.
            return;
        }
        // One task per gate; the fixture uses a fresh gate for each workflow.
        assert!(slot.is_none(), "test observer must not retain another task");
        *slot = Some(task);
        drop(slot);
        self.task_registered.add_permits(1);
    }

    pub(crate) fn task(&self) -> AbortHandle {
        self.task
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .expect("actual scheduler must register the task")
            .clone()
    }

    pub(crate) async fn pause_worker_loss(
        &self,
        point: WorkerLossPoint,
        delivery_deadline: Option<std::time::Instant>,
    ) {
        if self.loss_point != Some(point) {
            return;
        }
        let bound = self
            .workflow_deadline
            .min(Instant::now() + std::time::Duration::from_secs(1));
        let registered = self
            .task
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_some();
        if !registered {
            timeout_at(bound, self.task_registered.acquire())
                .await
                .expect("original scheduler registration deadline")
                .expect("original scheduler registration semaphore")
                .forget();
        }
        if tokio::task::try_id() != Some(self.task().id())
            || !self.armed.swap(false, Ordering::AcqRel)
        {
            return;
        }
        *self
            .original_delivery_deadline
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = delivery_deadline;
        self.entered.add_permits(1);
        let bound = delivery_deadline
            .map(Instant::from_std)
            .map_or(bound, |end| end.min(bound));
        timeout_at(bound, self.release.acquire())
            .await
            .expect("actual selected child pause deadline")
            .expect("actual selected child release semaphore")
            .forget();
    }

    pub(crate) fn original_delivery_deadline(&self) -> Option<std::time::Instant> {
        *self
            .original_delivery_deadline
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) async fn observe_loss(&self, observed: WorkerLossObservation) {
        if self.loss_point.is_none() || observed.task_id != self.task().id() {
            return;
        }
        self.note_joined(observed.task_id);
        {
            let mut slot = self.loss.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                slot.is_none(),
                "one selected original child can only be joined once"
            );
            *slot = Some(observed);
        }
        self.loss_entered.add_permits(1);
        let bound = self
            .workflow_deadline
            .min(Instant::now() + std::time::Duration::from_secs(1));
        timeout_at(bound, self.loss_release.acquire())
            .await
            .expect("real JoinSet loss observation deadline")
            .expect("real JoinSet loss release semaphore")
            .forget();
    }

    pub(crate) async fn take_loss(&self) -> WorkerLossObservation {
        let bound = self
            .workflow_deadline
            .min(Instant::now() + std::time::Duration::from_secs(1));
        timeout_at(bound, self.loss_entered.acquire())
            .await
            .expect("real cancelled child must be joined")
            .expect("real cancelled child observation semaphore")
            .forget();
        self.loss
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
            .expect("original JoinError observation exists")
    }

    pub(crate) fn release_loss(&self) {
        if !self.loss_released.swap(true, Ordering::AcqRel) {
            self.loss_release.add_permits(1);
        }
    }

    pub(crate) fn request_children_abort(&self) {
        self.abort_children.store(true, Ordering::Release);
    }

    pub(crate) fn children_abort_requested(&self) -> bool {
        self.loss_point.is_some() && self.abort_children.load(Ordering::Acquire)
    }

    pub(crate) fn note_joined(&self, id: tokio::task::Id) {
        let selected = self.task.lock().unwrap_or_else(|p| p.into_inner());
        if self.loss_point.is_some() && selected.as_ref().is_some_and(|task| task.id() == id) {
            self.selected_joined.store(true, Ordering::Release);
        }
    }

    pub(crate) fn selected_joined(&self) -> bool {
        self.selected_joined.load(Ordering::Acquire)
    }
}
