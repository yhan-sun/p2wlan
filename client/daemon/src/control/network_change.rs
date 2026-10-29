//! Capacity-one wakeup for authorized Android and confirmed route edges.
//! This projects existing network observers, without owning network state.

use super::*;
use crate::AndroidNetworkChangeHint;

pub(super) enum ControlNetworkEdge {
    Android(AndroidNetworkChangeHint),
    ConfirmedRoute,
}

impl ControlNetworkEdge {
    pub(super) fn requires_http_rebuild(&self) -> bool {
        matches!(self, Self::Android(_))
    }
}

type NetworkEdgeSnapshot = Option<Arc<ControlNetworkEdge>>;

pub(super) struct ControlRouteChangeNotifier {
    changes: Arc<ControlNetworkChanges>,
    commands: mpsc::UnboundedSender<ControlCommand>,
}

impl ControlRouteChangeNotifier {
    pub(super) fn new(
        changes: Arc<ControlNetworkChanges>,
        commands: mpsc::UnboundedSender<ControlCommand>,
    ) -> Self {
        Self { changes, commands }
    }

    pub(super) fn notify(&self) {
        if self
            .changes
            .observe_edge(ControlNetworkEdge::ConfirmedRoute)
        {
            let _ = self
                .commands
                .send(ControlCommand::NetworkChanged(self.changes.clone()));
        }
    }
}

#[derive(Default)]
struct NetworkEdgeState {
    latest: NetworkEdgeSnapshot,
    consumed: NetworkEdgeSnapshot,
    wake_queued: bool,
}

#[derive(Default)]
pub(super) struct ControlNetworkChanges {
    state: std::sync::Mutex<NetworkEdgeState>,
    changed: tokio::sync::Notify,
}

fn same_network_edge(left: &NetworkEdgeSnapshot, right: &NetworkEdgeSnapshot) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

impl ControlNetworkChanges {
    /// Returns true only when the caller must enqueue the one wakeup. Arc
    /// identity follows accepted order even when a new service resets gen to 1.
    pub(super) fn observe(&self, hint: AndroidNetworkChangeHint) -> bool {
        self.observe_edge(ControlNetworkEdge::Android(hint))
    }

    fn observe_edge(&self, edge: ControlNetworkEdge) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.latest = Some(Arc::new(edge));
        let enqueue = !state.wake_queued;
        state.wake_queued = true;
        drop(state);
        self.changed.notify_waiters();
        enqueue
    }

    pub(super) fn take_pending(&self, consuming_wakeup: bool) -> NetworkEdgeSnapshot {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if consuming_wakeup {
            state.wake_queued = false;
        }
        if same_network_edge(&state.latest, &state.consumed) {
            return None;
        }
        state.consumed = state.latest.clone();
        state.latest.clone()
    }

    pub(super) fn snapshot(&self) -> NetworkEdgeSnapshot {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .latest
            .clone()
    }

    pub(super) fn begin_registration(&self) -> (NetworkEdgeSnapshot, bool) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let changed = !same_network_edge(&state.latest, &state.consumed);
        state.consumed = state.latest.clone();
        (state.latest.clone(), changed)
    }

    pub(super) fn commit_if_current(
        &self,
        expected: &NetworkEdgeSnapshot,
        commit: impl FnOnce(),
    ) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if !same_network_edge(&state.latest, expected) {
            return false;
        }
        // Synchronous publication only: no I/O or await under this guard.
        commit();
        true
    }

    pub(super) async fn changed_since(&self, expected: &NetworkEdgeSnapshot) {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if !same_network_edge(&self.snapshot(), expected) {
                return;
            }
            notified.await;
        }
    }

    pub(super) fn commit_registration_if_current(
        &self,
        expected: &NetworkEdgeSnapshot,
        auth: &watch::Sender<Option<CriticalControlAuth>>,
        clock: &ServerClockEstimate,
        commit: impl FnOnce(),
    ) -> bool {
        if self.commit_if_current(expected, commit) {
            return true;
        }
        auth.send_replace(None);
        clock.invalidate_registration();
        false
    }

    pub(super) async fn during_registration<F: std::future::Future>(
        &self,
        expected: &NetworkEdgeSnapshot,
        auth: &watch::Sender<Option<CriticalControlAuth>>,
        clock: &ServerClockEstimate,
        work: F,
    ) -> Option<F::Output> {
        tokio::select! {
            biased;
            _ = self.changed_since(expected) => {
                auth.send_replace(None);
                clock.invalidate_registration();
                None
            }
            result = work => self.commit_registration_if_current(expected, auth, clock, || {}).then_some(result),
        }
    }

    /// Credential issuance is a server-side write. Revoke use of the old
    /// registration immediately, but retain its bounded response so a
    /// successfully issued credential can be persisted before retrying.
    pub(super) async fn finish_registration_side_effect<F: std::future::Future>(
        &self,
        expected: &NetworkEdgeSnapshot,
        auth: &watch::Sender<Option<CriticalControlAuth>>,
        clock: &ServerClockEstimate,
        work: F,
    ) -> F::Output {
        tokio::pin!(work);
        tokio::select! {
            biased;
            _ = self.changed_since(expected) => {
                auth.send_replace(None);
                clock.invalidate_registration();
                work.await
            }
            result = &mut work => result,
        }
    }
}

#[cfg(test)]
#[path = "tests/network_change.rs"]
mod tests;
