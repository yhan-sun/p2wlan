//! Fixed diagnostics owned by one original ordinary invocation. Never admission.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use super::{PeerSessionGeneration, ProbeSendFailure, ProbeSendFailureKind, ProbeSendResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OrdinaryProbeIdentity {
    pub(crate) transport_instance: u64,
    pub(crate) session_id: u64,
    pub(crate) network_generation: u64,
    pub(crate) peer_session_generation: PeerSessionGeneration,
    pub(crate) recovery_epoch: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OrdinaryProbeSocket {
    pub(crate) index: usize,
    pub(crate) socket_ptr: usize,
    pub(crate) local_endpoint: Option<SocketAddr>,
    pub(crate) target: SocketAddr,
    pub(crate) network_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OrdinaryProbeKind {
    Primary,
    Compatibility,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum OrdinaryProducerSettlement {
    #[default]
    NotStarted,
    Active,
    Joined,
    CancelledJoined,
    FailedJoined,
    OriginalProducerNotJoined,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct OrdinaryProbeBucket {
    pub(crate) entered_operations: u64,
    pub(crate) active_operations: u64,
    pub(crate) accepted_datagrams: u64,
    pub(crate) accepted_bytes: u64,
    pub(crate) returned_errors: u64,
    pub(crate) error_requested_bytes: u64,
    pub(crate) missing_completions: u64,
    pub(crate) missing_completion_requested_bytes: u64,
    pub(crate) first_result_at_ms: Option<u64>,
    pub(crate) last_result_at_ms: Option<u64>,
    pub(crate) first_socket: Option<OrdinaryProbeSocket>,
    pub(crate) multiple_socket_contexts: bool,
}

/// A lower bound for instrumented primary/compatibility operations only.
/// Bursts, ACKs and STUN are excluded; never add the returned-call view to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OrdinaryProbeCostSnapshot {
    pub(crate) identity: OrdinaryProbeIdentity,
    pub(crate) first_punch_generation: Option<(u64, u64)>,
    pub(crate) multiple_punch_generations: bool,
    pub(crate) producer_settlement: OrdinaryProducerSettlement,
    pub(crate) producer_active: bool,
    pub(crate) calls_started: u64,
    pub(crate) active_calls: u64,
    pub(crate) returned_calls: u64,
    pub(crate) dropped_calls: u64,
    pub(crate) excluded_hh2_calls: u64,
    pub(crate) proven_pre_handoff_rejections: u64,
    pub(crate) first_pre_handoff_rejection: Option<ProbeSendFailureKind>,
    pub(crate) primary: OrdinaryProbeBucket,
    pub(crate) compatibility: OrdinaryProbeBucket,
    pub(crate) counters_saturated: bool,
}

struct OrdinaryProbeCostState {
    snapshot: Mutex<OrdinaryProbeCostSnapshot>,
    #[cfg(test)]
    gate: Mutex<Option<(OrdinaryProbeTestStage, Arc<OrdinaryProbeTestGate>)>>,
    #[cfg(test)]
    compatibility_target: Mutex<Option<SocketAddr>>,
}

#[derive(Clone)]
pub(crate) struct OrdinaryProbeCost(Arc<OrdinaryProbeCostState>);

fn add(counter: &mut u64, amount: u64, saturated: &mut bool) {
    match counter.checked_add(amount) {
        Some(value) => *counter = value,
        None => {
            *counter = u64::MAX;
            *saturated = true;
        }
    }
}

impl OrdinaryProbeCost {
    pub(crate) fn new(identity: OrdinaryProbeIdentity) -> Self {
        Self(Arc::new(OrdinaryProbeCostState {
            snapshot: Mutex::new(OrdinaryProbeCostSnapshot {
                identity,
                first_punch_generation: None,
                multiple_punch_generations: false,
                producer_settlement: OrdinaryProducerSettlement::NotStarted,
                producer_active: false,
                calls_started: 0,
                active_calls: 0,
                returned_calls: 0,
                dropped_calls: 0,
                excluded_hh2_calls: 0,
                proven_pre_handoff_rejections: 0,
                first_pre_handoff_rejection: None,
                primary: OrdinaryProbeBucket::default(),
                compatibility: OrdinaryProbeBucket::default(),
                counters_saturated: false,
            }),
            #[cfg(test)]
            gate: Mutex::new(None),
            #[cfg(test)]
            compatibility_target: Mutex::new(None),
        }))
    }

    fn update(&self, apply: impl FnOnce(&mut OrdinaryProbeCostSnapshot)) {
        let mut state = self.0.snapshot.lock().unwrap_or_else(|p| p.into_inner());
        apply(&mut state);
    }

    pub(crate) fn snapshot(&self) -> OrdinaryProbeCostSnapshot {
        *self.0.snapshot.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(super) fn observe_generation(&self, network: u64, punch: u64) {
        self.update(|s| {
            let actual = (network, punch);
            if let Some(first) = s.first_punch_generation {
                s.multiple_punch_generations |= first != actual;
            } else {
                s.first_punch_generation = Some(actual);
            }
        });
    }

    pub(super) fn start_producer(&self) -> OrdinaryProbeProducer {
        self.update(|s| {
            s.producer_settlement = OrdinaryProducerSettlement::Active;
            s.producer_active = true;
        });
        OrdinaryProbeProducer(self.clone())
    }

    pub(super) fn settle_producer(&self, settlement: OrdinaryProducerSettlement) {
        self.update(|s| s.producer_settlement = settlement);
    }

    pub(super) fn begin_call(&self) -> OrdinaryProbeCall {
        self.update(|s| {
            add(&mut s.calls_started, 1, &mut s.counters_saturated);
            add(&mut s.active_calls, 1, &mut s.counters_saturated);
        });
        OrdinaryProbeCall {
            owner: self.clone(),
            ordinary: false,
            physical_started: false,
            returned: false,
        }
    }

    #[cfg(test)]
    pub(super) fn install_gate(&self, stage: OrdinaryProbeTestStage) -> Arc<OrdinaryProbeTestGate> {
        let gate = Arc::new(OrdinaryProbeTestGate::default());
        *self.0.gate.lock().unwrap_or_else(|p| p.into_inner()) = Some((stage, gate.clone()));
        gate
    }

    #[cfg(test)]
    pub(super) async fn wait_at_gate(&self, stage: OrdinaryProbeTestStage) {
        let gate = self
            .0
            .gate
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .filter(|(selected, _)| *selected == stage)
            .map(|(_, gate)| gate.clone());
        if let Some(gate) = gate {
            gate.reached.notify_one();
            gate.release.notified().await;
        }
    }

    #[cfg(test)]
    pub(super) fn set_compatibility_target(&self, target: SocketAddr) {
        *self
            .0
            .compatibility_target
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(target);
    }

    #[cfg(test)]
    pub(super) fn compatibility_target(&self, original: SocketAddr) -> SocketAddr {
        self.0
            .compatibility_target
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .unwrap_or(original)
    }
}

pub(super) struct OrdinaryProbeProducer(OrdinaryProbeCost);

impl Drop for OrdinaryProbeProducer {
    fn drop(&mut self) {
        self.0.update(|s| s.producer_active = false);
    }
}

pub(super) struct OrdinaryProbeCall {
    pub(super) owner: OrdinaryProbeCost,
    ordinary: bool,
    physical_started: bool,
    returned: bool,
}

impl OrdinaryProbeCall {
    pub(super) fn classify_domain(&mut self, ordinary: bool) {
        self.ordinary = ordinary;
        if !ordinary {
            self.owner
                .update(|s| add(&mut s.excluded_hh2_calls, 1, &mut s.counters_saturated));
        }
    }

    pub(super) fn begin_operation(
        &mut self,
        kind: OrdinaryProbeKind,
        requested: usize,
        socket: OrdinaryProbeSocket,
    ) -> OrdinaryProbeOperation {
        self.physical_started = true;
        self.owner.update(|s| {
            let (b, saturated) = bucket(s, kind);
            add(&mut b.entered_operations, 1, saturated);
            add(&mut b.active_operations, 1, saturated);
            if let Some(first) = b.first_socket {
                b.multiple_socket_contexts |= first != socket;
            } else {
                b.first_socket = Some(socket);
            }
        });
        OrdinaryProbeOperation {
            owner: self.owner.clone(),
            kind,
            requested,
            completed: false,
        }
    }

    pub(super) fn returned(
        &mut self,
        result: &std::result::Result<ProbeSendResult, ProbeSendFailure>,
    ) {
        self.returned = true;
        self.owner.update(|s| {
            add(&mut s.returned_calls, 1, &mut s.counters_saturated);
            if self.ordinary && !self.physical_started {
                if let Err(failure) = result {
                    if failure.kind != ProbeSendFailureKind::PhysicalSend {
                        add(
                            &mut s.proven_pre_handoff_rejections,
                            1,
                            &mut s.counters_saturated,
                        );
                        s.first_pre_handoff_rejection.get_or_insert(failure.kind);
                    }
                }
            }
        });
    }
}

impl Drop for OrdinaryProbeCall {
    fn drop(&mut self) {
        self.owner.update(|s| {
            s.active_calls = s.active_calls.saturating_sub(1);
            if !self.returned {
                add(&mut s.dropped_calls, 1, &mut s.counters_saturated);
            }
        });
    }
}

fn bucket(
    s: &mut OrdinaryProbeCostSnapshot,
    kind: OrdinaryProbeKind,
) -> (&mut OrdinaryProbeBucket, &mut bool) {
    match kind {
        OrdinaryProbeKind::Primary => (&mut s.primary, &mut s.counters_saturated),
        OrdinaryProbeKind::Compatibility => (&mut s.compatibility, &mut s.counters_saturated),
    }
}

pub(super) struct OrdinaryProbeOperation {
    owner: OrdinaryProbeCost,
    kind: OrdinaryProbeKind,
    requested: usize,
    completed: bool,
}

impl OrdinaryProbeOperation {
    pub(super) fn complete(&mut self, accepted: Option<usize>, at_ms: u64) {
        if self.completed {
            return;
        }
        self.completed = true;
        self.owner.update(|s| {
            let (b, saturated) = bucket(s, self.kind);
            if let Some(bytes) = accepted {
                add(&mut b.accepted_datagrams, 1, saturated);
                add(&mut b.accepted_bytes, bytes as u64, saturated);
            } else {
                add(&mut b.returned_errors, 1, saturated);
                add(
                    &mut b.error_requested_bytes,
                    self.requested as u64,
                    saturated,
                );
            }
            b.first_result_at_ms = Some(b.first_result_at_ms.map_or(at_ms, |old| old.min(at_ms)));
            b.last_result_at_ms = Some(b.last_result_at_ms.map_or(at_ms, |old| old.max(at_ms)));
        });
    }
}

impl Drop for OrdinaryProbeOperation {
    fn drop(&mut self) {
        self.owner.update(|s| {
            let (b, saturated) = bucket(s, self.kind);
            b.active_operations = b.active_operations.saturating_sub(1);
            if !self.completed {
                add(&mut b.missing_completions, 1, saturated);
                add(
                    &mut b.missing_completion_requested_bytes,
                    self.requested as u64,
                    saturated,
                );
            }
        });
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OrdinaryProbeTestStage {
    PrimaryAwait,
    PrimaryResult,
    CompatibilityResult,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct OrdinaryProbeTestGate {
    pub(super) reached: tokio::sync::Notify,
    pub(super) release: tokio::sync::Notify,
}

#[cfg(test)]
#[path = "tests/ordinary_probe_reducer.rs"]
mod tests;
