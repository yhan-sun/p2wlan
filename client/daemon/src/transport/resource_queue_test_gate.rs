//! Instance-local, test-only synchronization at the actual FIFO task owner.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::task::AbortHandle;
use tokio::time::{timeout_at, Instant};

pub(crate) struct ResourceQueueTestGate {
    armed: AtomicBool,
    released: AtomicBool,
    entered: Semaphore,
    release: Semaphore,
    task: Mutex<Option<AbortHandle>>,
    workflow_deadline: Instant,
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
        }
    }

    pub(crate) async fn pause_once(&self) {
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
        let mut slot = self.task.lock().unwrap_or_else(|error| error.into_inner());
        // One task per gate; the fixture uses a fresh gate for each workflow.
        assert!(slot.is_none(), "test observer must not retain another task");
        *slot = Some(task);
    }

    pub(crate) fn task(&self) -> AbortHandle {
        self.task
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .as_ref()
            .expect("actual scheduler must register the task")
            .clone()
    }
}
