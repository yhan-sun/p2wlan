//! Critical task supervision for the daemon.
//!
//! Tracks JoinHandles for control, data-plane, UDP, relay, diagnostics, and
//! rekey loops. A crash of any critical task marks the daemon unhealthy and can
//! drive a controlled shutdown.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

const CONTROL_HEALTH_STALE_AFTER: Duration = Duration::from_secs(30);
/// The control server expires a device after 90 seconds without a successful
/// endpoint/lease refresh. Keep the local diagnostic fence aligned with that
/// server-side contract instead of allowing unrelated successful GETs to keep
/// the device lease looking healthy forever.
const DEVICE_LEASE_STALE_AFTER: Duration = Duration::from_secs(90);

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
    /// Whether a non-heartbeat control API request most recently succeeded.
    /// This is deliberately separate from the device's server-side online
    /// lease: roster/signal GET success cannot refresh that lease.
    #[serde(default)]
    pub control_api_reachable: bool,
    /// Whether the most recent device-authenticated lease refresh succeeded
    /// and has not exceeded the server's lease TTL.
    #[serde(default)]
    pub device_lease_healthy: bool,
    #[serde(default)]
    pub last_device_lease_success_secs_ago: Option<u64>,
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
    presentation: Mutex<HealthPresentation>,
    /// API reachability, device lease ownership, auth state, and their clocks
    /// form one logical snapshot. Keeping them under one short std mutex avoids
    /// impossible combinations when GET and PATCH completions race `/status`.
    control: StdMutex<ControlHealthState>,
}

#[derive(Debug)]
struct HealthPresentation {
    status: HealthStatus,
    reason: Option<String>,
}

#[derive(Debug, Default)]
struct ControlHealthState {
    control_api_reachable: bool,
    device_lease_healthy: bool,
    reauth_required: bool,
    last_control_success: Option<Instant>,
    last_device_lease_success: Option<Instant>,
}

impl HealthState {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            presentation: Mutex::new(HealthPresentation {
                status: HealthStatus::Healthy,
                reason: None,
            }),
            control: StdMutex::new(ControlHealthState::default()),
        })
    }

    pub async fn set_status(&self, status: HealthStatus, reason: Option<String>) {
        *self.presentation.lock().await = HealthPresentation { status, reason };
    }

    pub fn set_control_connected(&self, connected: bool) {
        // Compatibility entry point used by generic ControlEvent consumers.
        // It only describes API reachability. Device lease ownership is changed
        // exclusively by the registration/heartbeat lane below.
        self.set_control_api_reachable(connected);
    }

    pub fn set_control_api_reachable(&self, reachable: bool) {
        self.control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .control_api_reachable = reachable;
    }

    pub fn set_device_lease_healthy(&self, healthy: bool) {
        self.control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .device_lease_healthy = healthy;
    }

    pub fn set_reauth_required(&self, required: bool) {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.reauth_required = required;
        if required {
            control.control_api_reachable = false;
            control.device_lease_healthy = false;
        }
    }

    /// Record a successful control API operation. This intentionally does NOT
    /// refresh the server-side device lease.
    pub async fn mark_control_success(&self) {
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.last_control_success = Some(Instant::now());
        control.control_api_reachable = true;
        control.reauth_required = false;
    }

    /// Record a successful registration or endpoint PATCH: the only operations
    /// that refresh the device's server-side online lease.
    pub async fn mark_device_lease_success(&self) {
        let now = Instant::now();
        let mut control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        control.last_control_success = Some(now);
        control.last_device_lease_success = Some(now);
        control.control_api_reachable = true;
        control.device_lease_healthy = true;
        control.reauth_required = false;
    }

    pub async fn snapshot(&self, tasks: &[TaskStatus]) -> HealthSnapshot {
        let presentation = self.presentation.lock().await;
        let mut status = presentation.status;
        let mut reason = presentation.reason.clone();
        drop(presentation);
        let control = self
            .control
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let last = control
            .last_control_success
            .map(|instant| instant.elapsed().as_secs());
        let last_device_lease = control
            .last_device_lease_success
            .map(|instant| instant.elapsed().as_secs());
        let raw_api_reachable = control.control_api_reachable;
        let raw_device_lease_healthy = control.device_lease_healthy;
        let reauth_required = control.reauth_required;
        drop(control);
        let control_stale =
            raw_api_reachable && last.is_some_and(|age| age > CONTROL_HEALTH_STALE_AFTER.as_secs());
        let device_lease_stale = raw_device_lease_healthy
            && last_device_lease.is_some_and(|age| age > DEVICE_LEASE_STALE_AFTER.as_secs());
        let control_api_reachable = raw_api_reachable && !control_stale;
        let device_lease_healthy = raw_device_lease_healthy && !device_lease_stale;
        let control_connected = control_api_reachable && device_lease_healthy;
        let previously_connected = last.is_some() || last_device_lease.is_some();
        if previously_connected && !control_connected && status == HealthStatus::Healthy {
            status = HealthStatus::Degraded;
            if reason.is_none() {
                reason = Some(if !device_lease_healthy {
                    if device_lease_stale {
                        format!(
                            "device lease last refreshed {}s ago and may have expired on the control server",
                            last_device_lease.unwrap_or_default()
                        )
                    } else {
                        "device lease refresh failed; successful control API reads do not keep this node online"
                            .to_string()
                    }
                } else if control_stale {
                    format!(
                        "control plane last successful API request was {}s ago; peer and candidate state may be stale",
                        last.unwrap_or_default()
                    )
                } else {
                    "control API is unreachable while the last device lease may still be active"
                        .to_string()
                });
            }
        }
        HealthSnapshot {
            status,
            reason,
            critical_tasks: tasks.to_vec(),
            control_connected,
            last_control_success_secs_ago: last,
            control_api_reachable,
            device_lease_healthy,
            last_device_lease_success_secs_ago: last_device_lease,
            reauth_required,
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

    #[tokio::test]
    async fn stale_control_success_reports_disconnected() {
        let health = HealthState::new();
        health.mark_device_lease_success().await;
        {
            let mut control = health
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            control.last_control_success =
                Some(Instant::now() - CONTROL_HEALTH_STALE_AFTER - Duration::from_secs(1));
        }

        let snap = health.snapshot(&[]).await;

        assert!(!snap.control_connected);
        assert_eq!(snap.status, HealthStatus::Degraded);
        assert!(snap.reason.as_deref().unwrap().contains("control plane"));
        assert!(snap.last_control_success_secs_ago.unwrap() > CONTROL_HEALTH_STALE_AFTER.as_secs());
    }

    #[tokio::test]
    async fn explicit_control_disconnect_overrides_recent_success() {
        let health = HealthState::new();
        health.mark_device_lease_success().await;
        health.set_control_connected(false);

        let snap = health.snapshot(&[]).await;

        assert!(!snap.control_connected);
        assert!(!snap.control_api_reachable);
        assert!(snap.device_lease_healthy);
        assert_eq!(snap.status, HealthStatus::Degraded);
        assert_eq!(snap.last_control_success_secs_ago, Some(0));
    }

    #[tokio::test]
    async fn successful_get_cannot_override_failed_device_lease_refresh() {
        let health = HealthState::new();
        health.mark_device_lease_success().await;
        health.set_device_lease_healthy(false);

        // A later roster/signal GET proves API reachability only.
        health.mark_control_success().await;
        let snap = health.snapshot(&[]).await;

        assert!(snap.control_api_reachable);
        assert!(!snap.device_lease_healthy);
        assert!(!snap.control_connected);
        assert_eq!(snap.status, HealthStatus::Degraded);
        assert!(snap
            .reason
            .as_deref()
            .unwrap()
            .contains("device lease refresh failed"));
    }

    #[tokio::test]
    async fn recent_get_cannot_hide_an_expired_device_lease() {
        let health = HealthState::new();
        health.mark_device_lease_success().await;
        {
            let mut control = health
                .control
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            control.last_device_lease_success =
                Some(Instant::now() - DEVICE_LEASE_STALE_AFTER - Duration::from_secs(1));
        }
        health.mark_control_success().await;

        let snap = health.snapshot(&[]).await;

        assert!(snap.control_api_reachable);
        assert!(!snap.device_lease_healthy);
        assert!(!snap.control_connected);
        assert!(snap.reason.as_deref().unwrap().contains("may have expired"));
    }
}
