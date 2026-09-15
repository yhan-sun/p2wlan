use super::state_machine::DplpmtudBudgetRevisionState;
use super::{
    DplpmtudEvent, DplpmtudPathIdentity, DplpmtudProbeIdentity, DplpmtudProbeSendFailure,
    DplpmtudSnapshot, DplpmtudSocketIdentity, DplpmtudState, DplpmtudStateMachine,
    DplpmtudTransitionDecision, DplpmtudWireToken, OuterIpPacketSize, OverlayPayloadBudget,
    UdpDatagramSize, DPLPMTUD_ACK_RATE_LIMIT_PER_PEER, DPLPMTUD_ACK_RATE_WINDOW,
    DPLPMTUD_PROBE_TIMEOUT, MAX_TRACKED_DPLPMTUD_PEERS,
};
use rand::RngCore;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex, RwLock as StdRwLock,
};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Notify};
use tokio::time::Instant;

/// Process-wide allocator so replacing the entire UDP runtime cannot reuse a
/// business budget revision from an older socket publication.
pub(super) static NEXT_DPLPMTUD_BUDGET_REVISION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub(crate) struct DplpmtudProbePlan {
    pub(crate) peer_id: String,
    pub(crate) worker_owner_token: u64,
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) probe_identity: DplpmtudProbeIdentity,
    pub(crate) wire_token: DplpmtudWireToken,
    pub(crate) deadline: Instant,
}

#[derive(Debug)]
pub(crate) struct DplpmtudWorkerLease {
    pub(crate) peer_id: String,
    pub(crate) worker_owner_token: u64,
    pub(crate) identity: DplpmtudPathIdentity,
    pub(crate) cancel_rx: watch::Receiver<bool>,
    pub(crate) notify: Arc<Notify>,
}

#[derive(Debug)]
pub(crate) struct DplpmtudWorkerStart {
    pub(crate) lease: DplpmtudWorkerLease,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) local_virtual_ip: Ipv4Addr,
    pub(crate) peer_virtual_ip: Ipv4Addr,
}

#[derive(Clone, Default)]
pub(crate) struct DplpmtudWorkerIngress {
    pub(super) state: Arc<StdMutex<VecDeque<DplpmtudWorkerStart>>>,
    pub(super) notify: Arc<Notify>,
}

impl DplpmtudWorkerIngress {
    pub(crate) fn submit(&self, start: DplpmtudWorkerStart) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.len() >= MAX_TRACKED_DPLPMTUD_PEERS {
            return false;
        }
        state.push_back(start);
        drop(state);
        self.notify.notify_one();
        true
    }

    pub(crate) async fn next(&self) -> DplpmtudWorkerStart {
        loop {
            let notified = self.notify.notified();
            if let Some(start) = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
            {
                return start;
            }
            notified.await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DplpmtudInstallDecision {
    Spawned,
    Unchanged,
    Unsupported,
    Closed,
    CapacityExceeded,
    OwnerTokenExhausted,
}

#[derive(Debug)]
pub(crate) struct DplpmtudInstallResult {
    pub(crate) decision: DplpmtudInstallDecision,
    pub(crate) worker: Option<DplpmtudWorkerLease>,
}

/// Read-only budget returned for one exact committed path.  The lookup is
/// keyed by peer in the runtime registry and then fenced by the complete path
/// identity; it never clones the all-peer diagnostics table.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudConfirmedBudget {
    pub(crate) budget_revision: u64,
    pub(crate) udp_datagram_size: UdpDatagramSize,
    pub(crate) outer_ip_packet_size: OuterIpPacketSize,
    pub(crate) overlay_payload_budget: OverlayPayloadBudget,
}

/// Immutable confirmed budget consumed by normal Direct business traffic.
/// The full path identity deliberately travels with the value rather than
/// living only in the map key, closing endpoint/socket/publication ABA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessBudgetPublication {
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) budget_revision: u64,
    pub(crate) udp_datagram_size: UdpDatagramSize,
    pub(crate) overlay_payload_budget: OverlayPayloadBudget,
}

/// Every business-visible revision is published, including `Some -> None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessBudgetUpdate {
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) budget_revision: u64,
    pub(crate) budget: Option<DirectBusinessBudgetPublication>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessBudgetMirrorEntry {
    /// False only when this exact platform/path is intentionally legacy-
    /// compatible (capability absent or no-fragment unavailable).
    pub(crate) enforced: bool,
    pub(crate) update: DirectBusinessBudgetUpdate,
}

/// Token captured before WireGuard encryption and revalidated at the exact
/// UDP syscall boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessSendToken {
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) budget_revision: u64,
    pub(crate) max_udp_datagram_size: UdpDatagramSize,
    pub(crate) max_overlay_payload_size: OverlayPayloadBudget,
    pub(crate) udp_publication_owner: u64,
}

pub(super) struct RuntimeEntry {
    pub(super) machine: DplpmtudStateMachine,
    pub(super) budget_revision: Option<u64>,
    pub(super) budget_revision_state: DplpmtudBudgetRevisionState,
    pub(super) path_cookie: [u8; 16],
    pub(super) worker_owner_token: Option<u64>,
    pub(super) cancel_tx: Option<watch::Sender<bool>>,
    pub(super) notify: Arc<Notify>,
    pub(super) worker_running: bool,
    pub(super) send_in_progress: bool,
    pub(super) business_enforced: bool,
}

#[derive(Default)]
pub(super) struct RuntimeRegistry {
    pub(super) entries: HashMap<String, RuntimeEntry>,
    pub(super) supported_sessions: HashMap<String, u64>,
    pub(super) ack_response_times: HashMap<String, VecDeque<Instant>>,
    pub(super) closed: bool,
}

/// Bounded, cloneable registry shared by one UDP publication, its scheduler,
/// receive path and diagnostics. No network I/O occurs while the mutex is held.
#[derive(Clone)]
pub(crate) struct DplpmtudRuntime {
    pub(super) registry: Arc<StdMutex<RuntimeRegistry>>,
    pub(super) snapshots: Arc<StdRwLock<HashMap<String, DplpmtudSnapshot>>>,
    pub(super) next_worker_owner_token: Arc<AtomicU64>,
    /// Latest immutable per-peer business publication. Readers clone one Arc
    /// through Tokio watch and never touch `registry`.
    pub(super) business_publications:
        watch::Sender<Arc<HashMap<String, DirectBusinessBudgetMirrorEntry>>>,
    /// Serializes budget/owner revocation against the final nonblocking UDP
    /// syscall. It is intentionally independent from the DPLPMTUD registry.
    pub(super) business_publication_gate: Arc<StdMutex<()>>,
    pub(super) business_change_notifier: Option<watch::Sender<u64>>,
}

impl Default for DplpmtudRuntime {
    fn default() -> Self {
        let (business_publications, _) = watch::channel(Arc::new(HashMap::new()));
        Self {
            registry: Arc::new(StdMutex::new(RuntimeRegistry::default())),
            snapshots: Arc::new(StdRwLock::new(HashMap::new())),
            next_worker_owner_token: Arc::new(AtomicU64::new(1)),
            business_publications,
            business_publication_gate: Arc::new(StdMutex::new(())),
            business_change_notifier: None,
        }
    }
}

impl DplpmtudRuntime {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn new_with_business_change_notifier(notifier: watch::Sender<u64>) -> Self {
        Self {
            business_change_notifier: Some(notifier),
            ..Self::default()
        }
    }

    pub(super) fn allocate_worker_owner_token(&self) -> Option<u64> {
        self.next_worker_owner_token
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .filter(|token| *token != 0)
    }

    pub(super) fn allocate_budget_revision(&self) -> Option<u64> {
        NEXT_DPLPMTUD_BUDGET_REVISION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .filter(|revision| *revision != 0)
    }

    pub(super) fn refresh_budget_revision(&self, entry: &mut RuntimeEntry) {
        let next_state = entry.machine.budget_revision_state();
        if next_state != entry.budget_revision_state {
            entry.budget_revision = self.allocate_budget_revision();
            entry.budget_revision_state = next_state;
        }
    }

    pub(crate) fn admit_probe_response(&self, peer_id: &str, now: Instant) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        registry.ack_response_times.retain(|_, sent| {
            while sent.front().is_some_and(|sent_at| {
                now.saturating_duration_since(*sent_at) >= DPLPMTUD_ACK_RATE_WINDOW
            }) {
                sent.pop_front();
            }
            !sent.is_empty()
        });
        if !registry.ack_response_times.contains_key(peer_id)
            && registry.ack_response_times.len() >= MAX_TRACKED_DPLPMTUD_PEERS
        {
            return false;
        }
        let sent = registry
            .ack_response_times
            .entry(peer_id.to_string())
            .or_default();
        if sent.len() >= DPLPMTUD_ACK_RATE_LIMIT_PER_PEER {
            return false;
        }
        sent.push_back(now);
        true
    }

    pub(crate) fn mark_supported(&self, peer_id: &str, peer_session_generation: u64) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        if !registry.supported_sessions.contains_key(peer_id)
            && registry.supported_sessions.len() >= MAX_TRACKED_DPLPMTUD_PEERS
        {
            return false;
        }
        registry
            .supported_sessions
            .insert(peer_id.to_string(), peer_session_generation)
            != Some(peer_session_generation)
    }

    #[cfg(test)]
    pub(crate) fn is_supported(&self, peer_id: &str, peer_session_generation: u64) -> bool {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .supported_sessions
            .get(peer_id)
            .is_some_and(|generation| *generation == peer_session_generation)
    }

    #[allow(dead_code)]
    pub(crate) fn install_path(
        &self,
        identity: DplpmtudPathIdentity,
        supported: bool,
        now: Instant,
    ) -> DplpmtudInstallResult {
        self.install_path_with_reason(
            identity,
            supported,
            if supported {
                "direct_committed"
            } else {
                "dplpmtud_capability_not_negotiated"
            },
            now,
        )
    }

    pub(crate) fn install_path_with_reason(
        &self,
        identity: DplpmtudPathIdentity,
        supported: bool,
        unsupported_reason: &str,
        now: Instant,
    ) -> DplpmtudInstallResult {
        let peer_id = identity.peer_id.clone();
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::Closed,
                worker: None,
            };
        }
        if !registry.entries.contains_key(&peer_id)
            && registry.entries.len() >= MAX_TRACKED_DPLPMTUD_PEERS
        {
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::CapacityExceeded,
                worker: None,
            };
        }

        if let Some(existing) = registry.entries.get_mut(&peer_id) {
            if existing.machine.identity() == Some(&identity) {
                existing.business_enforced = supported;
                if supported
                    && existing.worker_running
                    && existing.worker_owner_token.is_some()
                    && !matches!(
                        existing.machine.state(),
                        DplpmtudState::Disabled | DplpmtudState::Unsupported
                    )
                {
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Unchanged,
                        worker: None,
                    };
                }
                if supported {
                    let Some(worker_owner_token) = self.allocate_worker_owner_token() else {
                        return DplpmtudInstallResult {
                            decision: DplpmtudInstallDecision::OwnerTokenExhausted,
                            worker: None,
                        };
                    };
                    if matches!(
                        existing.machine.state(),
                        DplpmtudState::Disabled | DplpmtudState::Unsupported
                    ) {
                        rand::thread_rng().fill_bytes(&mut existing.path_cookie);
                        existing.machine = DplpmtudStateMachine::for_path_with_reason(
                            identity.clone(),
                            true,
                            "direct_committed",
                        );
                    }
                    let (cancel_tx, cancel_rx) = watch::channel(false);
                    existing.worker_owner_token = Some(worker_owner_token);
                    existing.cancel_tx = Some(cancel_tx);
                    existing.worker_running = true;
                    existing.send_in_progress = false;
                    let notify = existing.notify.clone();
                    self.publish_snapshot_locked(&peer_id, existing, now);
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Spawned,
                        worker: Some(DplpmtudWorkerLease {
                            peer_id,
                            worker_owner_token,
                            identity,
                            cancel_rx,
                            notify,
                        }),
                    };
                }
                if existing.machine.state() == DplpmtudState::Unsupported
                    && !existing.worker_running
                    && existing.worker_owner_token.is_none()
                    && existing.cancel_tx.is_none()
                {
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Unsupported,
                        worker: None,
                    };
                }
                if let Some(cancel_tx) = existing.cancel_tx.take() {
                    let _ = cancel_tx.send(true);
                }
                existing.worker_owner_token = None;
                existing.worker_running = false;
                existing.send_in_progress = false;
                existing.machine =
                    DplpmtudStateMachine::for_path_with_reason(identity, false, unsupported_reason);
                self.publish_snapshot_locked(&peer_id, existing, now);
                return DplpmtudInstallResult {
                    decision: DplpmtudInstallDecision::Unsupported,
                    worker: None,
                };
            }
            if let Some(cancel_tx) = existing.cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
            existing.worker_owner_token = None;
            existing.worker_running = false;
            existing.send_in_progress = false;
        }

        let mut path_cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut path_cookie);
        let notify = Arc::new(Notify::new());
        if !supported {
            let machine =
                DplpmtudStateMachine::for_path_with_reason(identity, false, unsupported_reason);
            let entry = RuntimeEntry {
                budget_revision: self.allocate_budget_revision(),
                budget_revision_state: machine.budget_revision_state(),
                machine,
                path_cookie,
                worker_owner_token: None,
                cancel_tx: None,
                notify,
                worker_running: false,
                send_in_progress: false,
                business_enforced: false,
            };
            registry.entries.insert(peer_id.clone(), entry);
            let entry = registry
                .entries
                .get_mut(&peer_id)
                .expect("entry inserted above");
            self.publish_snapshot_locked(&peer_id, entry, now);
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::Unsupported,
                worker: None,
            };
        }

        let Some(worker_owner_token) = self.allocate_worker_owner_token() else {
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::OwnerTokenExhausted,
                worker: None,
            };
        };
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let machine = DplpmtudStateMachine::for_path(identity.clone(), true, now);
        let entry = RuntimeEntry {
            budget_revision: self.allocate_budget_revision(),
            budget_revision_state: machine.budget_revision_state(),
            machine,
            path_cookie,
            worker_owner_token: Some(worker_owner_token),
            cancel_tx: Some(cancel_tx),
            notify: notify.clone(),
            worker_running: true,
            send_in_progress: false,
            business_enforced: true,
        };
        registry.entries.insert(peer_id.clone(), entry);
        let entry = registry
            .entries
            .get_mut(&peer_id)
            .expect("entry inserted above");
        self.publish_snapshot_locked(&peer_id, entry, now);
        DplpmtudInstallResult {
            decision: DplpmtudInstallDecision::Spawned,
            worker: Some(DplpmtudWorkerLease {
                peer_id,
                worker_owner_token,
                identity,
                cancel_rx,
                notify,
            }),
        }
    }

    pub(crate) fn retain_known_peers(&self, peers: &HashSet<String>, now: Instant) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = registry
            .entries
            .keys()
            .filter(|peer_id| !peers.contains(*peer_id))
            .cloned()
            .collect::<Vec<_>>();
        for peer_id in removed {
            if let Some(mut entry) = registry.entries.remove(&peer_id) {
                if let Some(cancel_tx) = entry.cancel_tx.take() {
                    let _ = cancel_tx.send(true);
                }
                let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
                    reason: "peer_left".to_string(),
                    now,
                });
                self.refresh_budget_revision(&mut entry);
                self.publish_direct_business_budget_locked(&peer_id, &entry);
            }
            registry.supported_sessions.remove(&peer_id);
            registry.ack_response_times.remove(&peer_id);
            self.snapshots
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&peer_id);
        }
    }

    pub(crate) fn cancel_before_network_generation(
        &self,
        generation: u64,
        reason: &str,
        now: Instant,
    ) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let peer_ids = registry
            .entries
            .iter()
            .filter_map(|(peer_id, entry)| {
                entry
                    .machine
                    .identity()
                    .filter(|identity| identity.epoch.network_generation != generation)
                    .map(|_| peer_id.clone())
            })
            .collect::<Vec<_>>();
        for peer_id in peer_ids {
            let Some(entry) = registry.entries.get_mut(&peer_id) else {
                continue;
            };
            if let Some(cancel_tx) = entry.cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
            entry.worker_owner_token = None;
            entry.worker_running = false;
            entry.send_in_progress = false;
            let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
                reason: reason.to_string(),
                now,
            });
            entry.notify.notify_waiters();
            self.publish_snapshot_locked(&peer_id, entry, now);
        }
    }

    pub(crate) fn cancel_peer(&self, peer_id: &str, reason: &str, now: Instant) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(peer_id) else {
            return;
        };
        if let Some(cancel_tx) = entry.cancel_tx.take() {
            let _ = cancel_tx.send(true);
        }
        entry.worker_owner_token = None;
        entry.worker_running = false;
        entry.send_in_progress = false;
        let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
            reason: reason.to_string(),
            now,
        });
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(peer_id, entry, now);
    }

    pub(crate) fn close(&self, reason: &str, now: Instant) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.closed = true;
        for (peer_id, entry) in &mut registry.entries {
            if let Some(cancel_tx) = entry.cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
            entry.worker_owner_token = None;
            entry.worker_running = false;
            entry.send_in_progress = false;
            let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
                reason: reason.to_string(),
                now,
            });
            entry.notify.notify_waiters();
            self.publish_snapshot_locked(peer_id, entry, now);
        }
        registry.supported_sessions.clear();
        registry.ack_response_times.clear();
    }

    pub(crate) fn schedule_probe(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
        worker_owner_token: u64,
        now: Instant,
    ) -> Option<DplpmtudProbePlan> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return None;
        }
        let entry = registry.entries.get_mut(peer_id)?;
        if !entry.worker_running
            || entry.worker_owner_token != Some(worker_owner_token)
            || entry.machine.identity() != Some(identity)
        {
            return None;
        }
        if entry.machine.state() == DplpmtudState::Base {
            let _ = entry.machine.apply(DplpmtudEvent::StartSearch { now });
        }
        if entry.machine.state() == DplpmtudState::SearchComplete {
            let _ = entry
                .machine
                .apply(DplpmtudEvent::CurrentPlpmtuConfirmationTimerExpired { now });
        }
        if matches!(
            entry.machine.state(),
            DplpmtudState::SearchComplete | DplpmtudState::Error
        ) && entry
            .machine
            .next_wakeup()
            .is_some_and(|deadline| now >= deadline)
        {
            let _ = entry
                .machine
                .apply(DplpmtudEvent::RaiseTimerExpired { now });
        }
        let (sequence, candidate, retry) = entry.machine.next_probe_components()?;
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let probe_identity = DplpmtudProbeIdentity {
            sequence,
            nonce,
            path_cookie: entry.path_cookie,
            candidate_udp_datagram_size: candidate,
        };
        let deadline = now + DPLPMTUD_PROBE_TIMEOUT;
        if entry.machine.apply(DplpmtudEvent::ProbeScheduled {
            probe: probe_identity,
            retry,
            now,
            deadline,
        }) != DplpmtudTransitionDecision::Applied
        {
            return None;
        }
        let wire_token = DplpmtudWireToken {
            sequence,
            nonce,
            path_cookie: entry.path_cookie,
            network_generation: identity.epoch.network_generation,
            peer_session_generation: identity.epoch.peer_session_generation.value(),
            remote_candidate_epoch: identity.epoch.remote_candidate_epoch,
            direct_validation_owner_token: identity.direct_validation_owner_token,
            direct_validation_request_id: identity.direct_validation_request_id,
            candidate_udp_datagram_size: candidate,
            outer_ip_family: identity.outer_ip_family,
        };
        self.publish_snapshot_locked(peer_id, entry, now);
        Some(DplpmtudProbePlan {
            peer_id: peer_id.to_string(),
            worker_owner_token,
            path_identity: identity.clone(),
            probe_identity,
            wire_token,
            deadline,
        })
    }

    /// Linearization point immediately before a worker attempts the kernel
    /// send. Marking the probe sent here, before socket I/O, prevents a fast
    /// authenticated ACK from racing ahead of the send bookkeeping.
    pub(crate) fn begin_probe_send(&self, plan: &DplpmtudProbePlan, now: Instant) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        let Some(entry) = registry.entries.get_mut(&plan.peer_id) else {
            return false;
        };
        if !entry.worker_running
            || entry.worker_owner_token != Some(plan.worker_owner_token)
            || entry.machine.identity() != Some(&plan.path_identity)
            || entry.machine.outstanding_identity() != Some(plan.probe_identity)
            || entry.send_in_progress
            || now >= plan.deadline
        {
            return false;
        }
        if entry.machine.apply(DplpmtudEvent::ProbeSent {
            probe: plan.probe_identity,
            now,
        }) != DplpmtudTransitionDecision::Applied
        {
            return false;
        }
        entry.send_in_progress = true;
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&plan.peer_id, entry, now);
        true
    }

    pub(crate) fn finish_probe_send(
        &self,
        plan: &DplpmtudProbePlan,
        result: Result<(), DplpmtudProbeSendFailure>,
        now: Instant,
    ) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(&plan.peer_id) else {
            return;
        };
        if entry.worker_owner_token != Some(plan.worker_owner_token)
            || entry.machine.identity() != Some(&plan.path_identity)
        {
            return;
        }
        entry.send_in_progress = false;
        match result {
            Ok(()) => {}
            Err(failure) => {
                let _ = entry.machine.apply(DplpmtudEvent::ProbeSendFailed {
                    probe: plan.probe_identity,
                    failure,
                    now,
                });
            }
        }
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&plan.peer_id, entry, now);
    }

    pub(crate) fn timeout_probe(
        &self,
        plan: &DplpmtudProbePlan,
        now: Instant,
    ) -> DplpmtudTransitionDecision {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(&plan.peer_id) else {
            return DplpmtudTransitionDecision::Noop;
        };
        if entry.worker_owner_token != Some(plan.worker_owner_token)
            || entry.machine.identity() != Some(&plan.path_identity)
        {
            return DplpmtudTransitionDecision::Noop;
        }
        let decision = entry.machine.apply(DplpmtudEvent::ProbeTimedOut {
            probe: plan.probe_identity,
            now,
        });
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&plan.peer_id, entry, now);
        decision
    }

    /// Consume an ACK while the caller holds the upper lifecycle/epoch fence.
    /// Contention fails closed instead of awaiting a lower registry lock.
    ///
    /// The ACK is WireGuard-authenticated and its token echoes the exact
    /// outstanding probe (nonce and path cookie), so the reply's UDP source
    /// is not required to equal the validation-time
    /// `authenticated_remote_endpoint`: behind an address/port-dependent NAT
    /// the peer's reply leaves through a different mapping than the one the
    /// encrypted validation commit observed, and pinning it here rejected
    /// every legitimate ACK. The local endpoint and socket identity stay
    /// pinned so the measurement remains bound to the probed local path.
    pub(crate) fn try_accept_ack(
        &self,
        peer_id: &str,
        current_path: &DplpmtudPathIdentity,
        token: DplpmtudWireToken,
        ingress: DplpmtudAckIngress,
        now: Instant,
    ) -> DplpmtudTransitionDecision {
        let Ok(mut registry) = self.registry.try_lock() else {
            return DplpmtudTransitionDecision::Busy;
        };
        if registry.closed {
            return DplpmtudTransitionDecision::Stale;
        }
        let Some(entry) = registry.entries.get_mut(peer_id) else {
            return DplpmtudTransitionDecision::Stale;
        };
        let exact_wire_identity = token.network_generation == current_path.epoch.network_generation
            && token.peer_session_generation == current_path.epoch.peer_session_generation.value()
            && token.remote_candidate_epoch == current_path.epoch.remote_candidate_epoch
            && token.direct_validation_owner_token == current_path.direct_validation_owner_token
            && token.direct_validation_request_id == current_path.direct_validation_request_id
            && token.outer_ip_family == current_path.outer_ip_family;
        let exact_ingress = ingress.local_endpoint == current_path.local_endpoint
            && ingress.socket == current_path.socket;
        let worker_is_current = entry.worker_running && entry.worker_owner_token.is_some();
        let decision = if !worker_is_current
            || entry.machine.identity() != Some(current_path)
            || !exact_wire_identity
            || !exact_ingress
        {
            entry.machine.apply(DplpmtudEvent::StaleAck { now })
        } else {
            entry.machine.apply(DplpmtudEvent::ProbeAcked {
                probe: token.probe_identity(),
                now,
            })
        };
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(peer_id, entry, now);
        decision
    }

    pub(crate) fn outstanding_is_current(&self, plan: &DplpmtudProbePlan) -> bool {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(&plan.peer_id)
            .is_some_and(|entry| {
                entry.worker_running
                    && entry.worker_owner_token == Some(plan.worker_owner_token)
                    && entry.machine.identity() == Some(&plan.path_identity)
                    && entry.machine.outstanding_identity() == Some(plan.probe_identity)
            })
    }

    pub(crate) fn worker_state(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
        worker_owner_token: u64,
    ) -> Option<(
        DplpmtudState,
        Option<Instant>,
        Option<DplpmtudProbeIdentity>,
    )> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(peer_id)
            .filter(|entry| {
                entry.worker_owner_token == Some(worker_owner_token)
                    && entry.machine.identity() == Some(identity)
            })
            .map(|entry| {
                (
                    entry.machine.state(),
                    entry.machine.next_wakeup(),
                    entry.machine.outstanding_identity(),
                )
            })
    }

    pub(crate) fn finish_worker(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
        worker_owner_token: u64,
    ) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(peer_id) else {
            return;
        };
        if entry.worker_owner_token == Some(worker_owner_token)
            && entry.machine.identity() == Some(identity)
        {
            entry.worker_owner_token = None;
            entry.worker_running = false;
            entry.send_in_progress = false;
            entry.cancel_tx = None;
            self.publish_snapshot_locked(peer_id, entry, Instant::now());
        }
    }

    pub(crate) fn path_identity(&self, peer_id: &str) -> Option<DplpmtudPathIdentity> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(peer_id)
            .and_then(|entry| entry.machine.identity().cloned())
    }

    pub(crate) fn snapshots(&self) -> HashMap<String, DplpmtudSnapshot> {
        self.snapshots
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Read one peer's diagnostics without cloning the all-peer table.
    pub(crate) fn snapshot_for_peer(&self, peer_id: &str) -> Option<DplpmtudSnapshot> {
        self.snapshots
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer_id)
            .cloned()
    }

    /// Read one exact path's diagnostics without cloning the all-peer table.
    /// This is for control/timeline reporting; business packetization uses
    /// the immutable publication mirror instead.
    pub(crate) fn snapshot_for_path(
        &self,
        identity: &DplpmtudPathIdentity,
    ) -> Option<DplpmtudSnapshot> {
        let expected = identity.summary();
        let snapshot = self.snapshot_for_peer(&identity.peer_id)?;
        (snapshot.path_identity.as_ref() == Some(&expected)).then_some(snapshot)
    }

    /// O(1) per-peer confirmed-budget read for the business consumer.  The
    /// exact identity check prevents a budget from a replaced endpoint,
    /// generation, candidate epoch, or socket publication from being reused.
    /// Business hot paths must use this accessor rather than `snapshots()`.
    #[allow(dead_code)]
    pub(crate) fn confirmed_budget_for_path(
        &self,
        identity: &DplpmtudPathIdentity,
    ) -> Option<DplpmtudConfirmedBudget> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return None;
        }
        let entry = registry.entries.get(&identity.peer_id)?;
        if entry.machine.identity() != Some(identity)
            || !entry.machine.supported
            || matches!(
                entry.machine.state(),
                DplpmtudState::Disabled | DplpmtudState::Unsupported
            )
            || !entry.machine.base_confirmed
        {
            return None;
        }
        let udp_datagram_size = entry.machine.business_confirmed_udp_datagram_size()?;
        let budget_revision = entry.budget_revision?;
        let outer_ip_packet_size = udp_datagram_size.outer_ip_packet_size(identity.outer_ip_family);
        let overlay_payload_budget = udp_datagram_size.overlay_payload_budget()?;
        Some(DplpmtudConfirmedBudget {
            budget_revision,
            udp_datagram_size,
            outer_ip_packet_size,
            overlay_payload_budget,
        })
    }

    /// Registry-free read used by the business data plane. Tokio watch owns
    /// one immutable, bounded map; cloning this entry never acquires the
    /// mutable DPLPMTUD registry mutex.
    pub(crate) fn direct_business_budget_entry(
        &self,
        peer_id: &str,
    ) -> Option<DirectBusinessBudgetMirrorEntry> {
        self.business_publications.borrow().get(peer_id).cloned()
    }

    /// Test seam for proving that the production post-encryption check uses
    /// the real WireGuard datagram length rather than the plaintext estimate.
    /// It intentionally makes one immutable publication conservative while
    /// leaving the reducer state untouched.
    #[cfg(test)]
    pub(crate) fn force_business_udp_budget_for_test(
        &self,
        peer_id: &str,
        udp_datagram_size: UdpDatagramSize,
    ) -> bool {
        self.with_business_publication_gate(|| {
            let current = self.business_publications.borrow().clone();
            let mut next = (*current).clone();
            let Some(entry) = next.get_mut(peer_id) else {
                return false;
            };
            let Some(publication) = entry.update.budget.as_mut() else {
                return false;
            };
            publication.udp_datagram_size = udp_datagram_size;
            self.business_publications.send_replace(Arc::new(next));
            if let Some(notifier) = self.business_change_notifier.as_ref() {
                notifier.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
            }
            true
        })
    }

    /// Test seam for publishing one internally consistent confirmed business
    /// budget without driving the upward-probe timer. Unlike the conservative
    /// ciphertext-defense seam above, this updates both UDP and overlay sizes.
    #[cfg(test)]
    pub(crate) fn force_coherent_business_budget_for_test(
        &self,
        peer_id: &str,
        udp_datagram_size: UdpDatagramSize,
    ) -> bool {
        let Some(overlay_payload_budget) = udp_datagram_size.overlay_payload_budget() else {
            return false;
        };
        self.with_business_publication_gate(|| {
            let current = self.business_publications.borrow().clone();
            let mut next = (*current).clone();
            let Some(entry) = next.get_mut(peer_id) else {
                return false;
            };
            let Some(publication) = entry.update.budget.as_mut() else {
                return false;
            };
            publication.udp_datagram_size = udp_datagram_size;
            publication.overlay_payload_budget = overlay_payload_budget;
            self.business_publications.send_replace(Arc::new(next));
            if let Some(notifier) = self.business_change_notifier.as_ref() {
                notifier.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
            }
            true
        })
    }

    /// Serialize UDP publication-owner stores with the final business send.
    /// This gate is deliberately independent from `registry`; holding the
    /// registry in a test or worker cannot delay a confirmed business send.
    pub(crate) fn with_business_publication_gate<R>(&self, operation: impl FnOnce() -> R) -> R {
        let _guard = self
            .business_publication_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        operation()
    }

    /// Final budget linearization point. If this returns `Some`, the token was
    /// current for the entire synchronous operation (normally one
    /// `UdpSocket::try_send_to` syscall). A revocation that wins the gate makes
    /// this return `None`; a send that wins is ordered before the revocation.
    pub(crate) fn with_current_direct_business_token<R>(
        &self,
        token: &DirectBusinessSendToken,
        operation: impl FnOnce() -> R,
    ) -> Option<R> {
        self.with_business_publication_gate(|| {
            let publications = self.business_publications.borrow();
            let entry = publications.get(&token.path_identity.peer_id)?;
            if !entry.enforced
                || entry.update.path_identity != token.path_identity
                || entry.update.budget_revision != token.budget_revision
            {
                return None;
            }
            let publication = entry.update.budget.as_ref()?;
            if publication.path_identity != token.path_identity
                || publication.budget_revision != token.budget_revision
                || publication.udp_datagram_size != token.max_udp_datagram_size
                || publication.overlay_payload_budget != token.max_overlay_payload_size
            {
                return None;
            }
            Some(operation())
        })
    }

    /// Fail closed after a business EMSGSIZE (or an impossible actual-
    /// ciphertext overrun). Exact identity + revision make duplicate reports
    /// idempotent. No path-health or Relay state is touched here.
    pub(crate) fn invalidate_direct_business_budget(
        &self,
        token: &DirectBusinessSendToken,
        now: Instant,
    ) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        let Some(entry) = registry.entries.get_mut(&token.path_identity.peer_id) else {
            return false;
        };
        if entry.machine.identity() != Some(&token.path_identity)
            || entry.budget_revision != Some(token.budget_revision)
            || entry
                .machine
                .business_confirmed_udp_datagram_size()
                .is_none()
        {
            return false;
        }
        if entry
            .machine
            .apply(DplpmtudEvent::BusinessPacketTooLarge { now })
            != DplpmtudTransitionDecision::Applied
        {
            return false;
        }
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&token.path_identity.peer_id, entry, now);
        true
    }

    #[cfg(test)]
    pub(super) fn current_probe_token(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
    ) -> Option<DplpmtudWireToken> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = registry.entries.get(peer_id)?;
        if entry.machine.identity() != Some(identity) {
            return None;
        }
        let probe = entry.machine.outstanding.as_ref()?.identity;
        Some(DplpmtudWireToken {
            sequence: probe.sequence,
            nonce: probe.nonce,
            path_cookie: probe.path_cookie,
            network_generation: identity.epoch.network_generation,
            peer_session_generation: identity.epoch.peer_session_generation.value(),
            remote_candidate_epoch: identity.epoch.remote_candidate_epoch,
            direct_validation_owner_token: identity.direct_validation_owner_token,
            direct_validation_request_id: identity.direct_validation_request_id,
            candidate_udp_datagram_size: probe.candidate_udp_datagram_size,
            outer_ip_family: identity.outer_ip_family,
        })
    }

    #[cfg(test)]
    pub(crate) fn tracked_peer_count(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .len()
    }

    #[cfg(test)]
    pub(crate) fn active_worker_count(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .values()
            .filter(|entry| entry.worker_running && entry.worker_owner_token.is_some())
            .count()
    }

    pub(super) fn publish_snapshot_locked(
        &self,
        peer_id: &str,
        entry: &mut RuntimeEntry,
        now: Instant,
    ) {
        self.refresh_budget_revision(entry);
        self.publish_direct_business_budget_locked(peer_id, entry);
        let mut snapshot = entry.machine.snapshot(now, entry.worker_running);
        snapshot.budget_revision = entry.budget_revision;
        self.snapshots
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_id.to_string(), snapshot);
    }

    pub(super) fn publish_direct_business_budget_locked(
        &self,
        peer_id: &str,
        entry: &RuntimeEntry,
    ) {
        let identity = entry.machine.identity().cloned();
        let revision = entry.budget_revision;
        self.with_business_publication_gate(|| {
            let current = self.business_publications.borrow().clone();
            let mut next = (*current).clone();
            let next_entry = identity
                .zip(revision)
                .map(|(path_identity, budget_revision)| {
                    let budget = entry
                        .machine
                        .business_confirmed_udp_datagram_size()
                        .and_then(|udp_datagram_size| {
                            udp_datagram_size.overlay_payload_budget().map(
                                |overlay_payload_budget| DirectBusinessBudgetPublication {
                                    path_identity: path_identity.clone(),
                                    budget_revision,
                                    udp_datagram_size,
                                    overlay_payload_budget,
                                },
                            )
                        });
                    DirectBusinessBudgetMirrorEntry {
                        enforced: entry.business_enforced,
                        update: DirectBusinessBudgetUpdate {
                            path_identity,
                            budget_revision,
                            budget,
                        },
                    }
                });

            let changed = match next_entry {
                Some(next_entry) => {
                    if !next.contains_key(peer_id) && next.len() >= MAX_TRACKED_DPLPMTUD_PEERS {
                        if let Some(tombstone) = next.iter().find_map(|(candidate, entry)| {
                            entry.update.budget.is_none().then(|| candidate.clone())
                        }) {
                            next.remove(&tombstone);
                        }
                    }
                    if (next.len() >= MAX_TRACKED_DPLPMTUD_PEERS && !next.contains_key(peer_id))
                        || next.get(peer_id) == Some(&next_entry)
                    {
                        false
                    } else {
                        next.insert(peer_id.to_string(), next_entry);
                        true
                    }
                }
                None => next.remove(peer_id).is_some(),
            };
            if changed {
                self.business_publications.send_replace(Arc::new(next));
                if let Some(notifier) = self.business_change_notifier.as_ref() {
                    notifier.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
                }
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudAckIngress {
    pub(crate) remote_endpoint: SocketAddr,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) socket: DplpmtudSocketIdentity,
}
