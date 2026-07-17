//! Critical task supervision for the daemon.
//!
//! Tracks JoinHandles for control, data-plane, UDP, relay, diagnostics, and
//! rekey loops. A crash of any critical task marks the daemon unhealthy and can
//! drive a controlled shutdown.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// Health status reported by diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    ShuttingDown,
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "healthy"),
            Self::Degraded => write!(f, "degraded"),
            Self::Unhealthy => write!(f, "unhealthy"),
            Self::ShuttingDown => write!(f, "shutting_down"),
        }
    }
}

/// Snapshot of daemon health for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub status: HealthStatus,
    pub reason: Option<String>,
    pub critical_tasks: Vec<TaskStatus>,
    pub control_connected: bool,
    pub last_control_success_secs_ago: Option<u64>,
    pub reauth_required: bool,
}

/// Status of one supervised task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskStatus {
    pub name: String,
    pub critical: bool,
    pub running: bool,
    pub finished: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
struct TrackedTask {
    name: String,
    critical: bool,
    handle: JoinHandle<()>,
    finished: bool,
    error: Option<String>,
}

/// Shared health state used by diagnostics and the main loop.
#[derive(Debug)]
pub struct HealthState {
    status: Mutex<HealthStatus>,
    reason: Mutex<Option<String>>,
    control_connected: AtomicBool,
    reauth_required: AtomicBool,
    last_control_success: Mutex<Option<Instant>>,
}

impl HealthState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(HealthStatus::Healthy),
            reason: Mutex::new(None),
            control_connected: AtomicBool::new(false),
            reauth_required: AtomicBool::new(false),
            last_control_success: Mutex::new(None),
        })
    }

    pub async fn set_status(&self, status: HealthStatus, reason: Option<String>) {
        *self.status.lock().await = status;
        *self.reason.lock().await = reason;
    }

    pub fn set_control_connected(&self, connected: bool) {
        self.control_connected.store(connected, Ordering::SeqCst);
    }

    pub fn set_reauth_required(&self, required: bool) {
        self.reauth_required.store(required, Ordering::SeqCst);
        if required {
            self.control_connected.store(false, Ordering::SeqCst);
        }
    }

    pub async fn mark_control_success(&self) {
        *self.last_control_success.lock().await = Some(Instant::now());
        self.control_connected.store(true, Ordering::SeqCst);
        self.reauth_required.store(false, Ordering::SeqCst);
    }

    pub async fn snapshot(&self, tasks: &[TaskStatus]) -> HealthSnapshot {
        let status = *self.status.lock().await;
        let reason = self.reason.lock().await.clone();
        let last = self
            .last_control_success
            .lock()
            .await
            .map(|t| t.elapsed().as_secs());
        HealthSnapshot {
            status,
            reason,
            critical_tasks: tasks.to_vec(),
            control_connected: self.control_connected.load(Ordering::SeqCst),
            last_control_success_secs_ago: last,
            reauth_required: self.reauth_required.load(Ordering::SeqCst),
        }
    }
}

/// Manages critical background tasks and propagates failures.
pub struct TaskManager {
    tasks: Mutex<HashMap<String, TrackedTask>>,
    health: Arc<HealthState>,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl TaskManager {
    pub fn new(health: Arc<HealthState>) -> Arc<Self> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Arc::new(Self {
            tasks: Mutex::new(HashMap::new()),
            health,
            shutdown_tx,
            shutdown_rx,
        })
    }

    pub fn health(&self) -> Arc<HealthState> {
        self.health.clone()
    }

    pub fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn is_shutdown(&self) -> bool {
        *self.shutdown_rx.borrow()
    }

    /// Spawn a named task. Critical tasks mark the daemon unhealthy on exit/crash.
    pub async fn spawn<F>(self: &Arc<Self>, name: impl Into<String>, critical: bool, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let name = name.into();
        let manager = Arc::clone(self);
        let task_name = name.clone();
        let handle = tokio::spawn(async move {
            fut.await;
            manager.on_task_finished(&task_name, None).await;
        });
        self.tasks.lock().await.insert(
            name.clone(),
            TrackedTask {
                name,
                critical,
                handle,
                finished: false,
                error: None,
            },
        );
    }

    /// Spawn a task that returns Result; failures are recorded.
    pub async fn spawn_result<F, E>(
        self: &Arc<Self>,
        name: impl Into<String>,
        critical: bool,
        fut: F,
    ) where
        F: std::future::Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Display + Send + 'static,
    {
        let name = name.into();
        let manager = Arc::clone(self);
        let task_name = name.clone();
        let handle = tokio::spawn(async move {
            match fut.await {
                Ok(()) => manager.on_task_finished(&task_name, None).await,
                Err(err) => {
                    manager
                        .on_task_finished(&task_name, Some(err.to_string()))
                        .await;
                }
            }
        });
        self.tasks.lock().await.insert(
            name.clone(),
            TrackedTask {
                name,
                critical,
                handle,
                finished: false,
                error: None,
            },
        );
    }

    async fn on_task_finished(&self, name: &str, error: Option<String>) {
        let mut tasks = self.tasks.lock().await;
        let Some(task) = tasks.get_mut(name) else {
            return;
        };
        task.finished = true;
        task.error = error.clone();
        let critical = task.critical;
        drop(tasks);

        if self.is_shutdown() {
            info!("Task {name} stopped during shutdown");
            return;
        }

        if let Some(ref err) = error {
            error!("Task {name} failed: {err}");
        } else {
            warn!("Task {name} exited unexpectedly");
        }

        if critical {
            let reason = error.unwrap_or_else(|| format!("critical task {name} exited"));
            self.health
                .set_status(HealthStatus::Unhealthy, Some(reason.clone()))
                .await;
            // Drive shutdown so main does not pretend to stay healthy forever.
            self.request_shutdown();
        } else {
            self.health
                .set_status(
                    HealthStatus::Degraded,
                    Some(error.unwrap_or_else(|| format!("task {name} exited"))),
                )
                .await;
        }
    }

    pub async fn task_statuses(&self) -> Vec<TaskStatus> {
        let mut out = Vec::new();
        for task in self.tasks.lock().await.values() {
            out.push(TaskStatus {
                name: task.name.clone(),
                critical: task.critical,
                running: !task.finished && !task.handle.is_finished(),
                finished: task.finished || task.handle.is_finished(),
                error: task.error.clone(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }

    /// Abort all tasks and wait up to `timeout` for them to finish.
    pub async fn shutdown_all(&self, timeout: Duration) {
        self.request_shutdown();
        self.health
            .set_status(
                HealthStatus::ShuttingDown,
                Some("shutdown requested".into()),
            )
            .await;

        let handles: Vec<(String, JoinHandle<()>)> = {
            let mut tasks = self.tasks.lock().await;
            tasks.drain().map(|(name, t)| (name, t.handle)).collect()
        };

        for (name, handle) in &handles {
            if !handle.is_finished() {
                info!("Aborting task {name}");
                handle.abort();
            }
        }

        let wait = async {
            for (name, handle) in handles {
                match handle.await {
                    Ok(()) => debug_finished(&name),
                    Err(err) if err.is_cancelled() => debug_finished(&name),
                    Err(err) => warn!("Task {name} join error: {err}"),
                }
            }
        };

        if tokio::time::timeout(timeout, wait).await.is_err() {
            warn!(
                "Timed out waiting for tasks to stop after {} ms",
                timeout.as_millis()
            );
        }
    }
}

fn debug_finished(name: &str) {
    info!("Task {name} stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn critical_task_exit_marks_unhealthy_and_requests_shutdown() {
        let health = HealthState::new();
        let manager = TaskManager::new(health.clone());
        let notify = Arc::new(Notify::new());
        let n2 = notify.clone();

        manager
            .spawn("critical-worker", true, async move {
                n2.notified().await;
            })
            .await;

        notify.notify_one();
        tokio::time::sleep(Duration::from_millis(50)).await;

        let snap = health.snapshot(&manager.task_statuses().await).await;
        assert_eq!(snap.status, HealthStatus::Unhealthy);
        assert!(manager.is_shutdown());
    }

    #[tokio::test]
    async fn non_critical_task_exit_is_degraded() {
        let health = HealthState::new();
        let manager = TaskManager::new(health.clone());
        let counter = Arc::new(AtomicUsize::new(0));
        let c2 = counter.clone();

        manager
            .spawn("background", false, async move {
                c2.fetch_add(1, Ordering::SeqCst);
            })
            .await;

        tokio::time::sleep(Duration::from_millis(50)).await;
        let snap = health.snapshot(&manager.task_statuses().await).await;
        assert_eq!(snap.status, HealthStatus::Degraded);
        assert!(!manager.is_shutdown());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn shutdown_all_aborts_running_tasks() {
        let health = HealthState::new();
        let manager = TaskManager::new(health);
        manager
            .spawn("long", true, async {
                tokio::time::sleep(Duration::from_secs(60)).await;
            })
            .await;
        manager.shutdown_all(Duration::from_millis(200)).await;
        assert!(manager.is_shutdown());
    }
}
