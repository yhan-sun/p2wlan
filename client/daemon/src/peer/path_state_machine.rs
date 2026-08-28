use crate::dplpmtud::{MtuState, MTU_FLOOR};

/// One coherent, generation-bound view of a peer's selected path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathStateMachineSnapshot {
    pub state: ConnectionState,
    pub active_path: Option<NetworkPath>,
    pub previous_path: Option<NetworkPath>,
    pub network_generation: u64,
    pub candidate_generation: u64,
    pub revision: u64,
    pub transition_reason: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathMtuSnapshot {
    pub direct_generation: u64,
    pub direct_effective_mtu: u32,
    pub direct_next_probe: Option<u32>,
    pub relay_generation: u64,
    pub relay_effective_mtu: u32,
    pub relay_next_probe: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathTransitionRejection {
    StaleNetworkGeneration,
    StaleCandidateGeneration,
    IllegalTransition,
    SupersededRevision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreparedPathTransition {
    expected: PathStateMachineSnapshot,
    next: PathStateMachineSnapshot,
}

impl PreparedPathTransition {
    pub(crate) fn next_snapshot(self) -> PathStateMachineSnapshot {
        self.next
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathTransitionOutcome {
    pub previous: PathStateMachineSnapshot,
    pub current: PathStateMachineSnapshot,
    pub changed: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct PathStateMachine {
    snapshot: PathStateMachineSnapshot,
    direct_mtu_generation: u64,
    direct_mtu: MtuState,
    relay_mtu_generation: u64,
    relay_mtu: MtuState,
}

impl PathStateMachine {
    pub(crate) fn new(initial_state: ConnectionState) -> Self {
        Self {
            snapshot: PathStateMachineSnapshot {
                state: initial_state,
                active_path: Self::active_path(initial_state),
                previous_path: None,
                network_generation: 0,
                candidate_generation: 0,
                revision: 0,
                transition_reason: "initial",
            },
            direct_mtu_generation: 0,
            direct_mtu: MtuState::new(),
            relay_mtu_generation: 0,
            relay_mtu: MtuState::new(),
        }
    }

    pub(crate) fn snapshot(&self) -> PathStateMachineSnapshot {
        self.snapshot
    }

    pub(crate) fn mtu_snapshot(&self) -> PathMtuSnapshot {
        PathMtuSnapshot {
            direct_generation: self.direct_mtu_generation,
            direct_effective_mtu: self.direct_mtu.effective_mtu(),
            direct_next_probe: self.direct_mtu.next_probe(),
            relay_generation: self.relay_mtu_generation,
            relay_effective_mtu: self.relay_mtu.effective_mtu(),
            relay_next_probe: self.relay_mtu.next_probe(),
        }
    }

    /// Reset is reserved for an authenticated peer lifecycle replacement.
    pub(crate) fn reset(&mut self, state: ConnectionState) {
        let revision = self.snapshot.revision.wrapping_add(1);
        self.snapshot = PathStateMachineSnapshot {
            state,
            active_path: Self::active_path(state),
            previous_path: self.snapshot.active_path,
            network_generation: 0,
            candidate_generation: 0,
            revision,
            transition_reason: "peer_session_reset",
        };
        self.direct_mtu_generation = 0;
        self.direct_mtu = MtuState::new();
        self.relay_mtu_generation = 0;
        self.relay_mtu = MtuState::new();
    }

    /// Validate a transition without mutating either the machine or any peer
    /// business fields. The returned token is committed under the same peer
    /// write lock after endpoint, health and cache updates have been prepared.
    pub(crate) fn prepare(
        &self,
        requested_state: ConnectionState,
        network_generation: u64,
        candidate_generation: u64,
        reason: &'static str,
    ) -> Result<PreparedPathTransition, PathTransitionRejection> {
        let current = self.snapshot;
        if network_generation < current.network_generation {
            return Err(PathTransitionRejection::StaleNetworkGeneration);
        }
        if requested_state == ConnectionState::Direct
            && network_generation == current.network_generation
            && candidate_generation < current.candidate_generation
        {
            return Err(PathTransitionRejection::StaleCandidateGeneration);
        }
        if !Self::is_legal(current.state, requested_state) {
            return Err(PathTransitionRejection::IllegalTransition);
        }

        let generation_changed = network_generation > current.network_generation;
        let candidate_changed = if generation_changed {
            candidate_generation != current.candidate_generation
        } else {
            candidate_generation > current.candidate_generation
        };
        let state_changed = requested_state != current.state;
        let changed = generation_changed || candidate_changed || state_changed;
        let next_active_path = Self::active_path(requested_state);
        let next = PathStateMachineSnapshot {
            state: requested_state,
            active_path: next_active_path,
            previous_path: if next_active_path != current.active_path {
                current.active_path
            } else {
                current.previous_path
            },
            network_generation: network_generation.max(current.network_generation),
            candidate_generation: if generation_changed {
                candidate_generation
            } else {
                candidate_generation.max(current.candidate_generation)
            },
            revision: if changed {
                current.revision.wrapping_add(1)
            } else {
                current.revision
            },
            transition_reason: if changed { reason } else { current.transition_reason },
        };
        Ok(PreparedPathTransition {
            expected: current,
            next,
        })
    }

    /// Commit a previously prepared transition. A superseded token is rejected
    /// without changing the state-machine snapshot or MTU state.
    pub(crate) fn commit(
        &mut self,
        prepared: PreparedPathTransition,
    ) -> Result<PathTransitionOutcome, PathTransitionRejection> {
        if self.snapshot != prepared.expected {
            return Err(PathTransitionRejection::SupersededRevision);
        }
        let previous = self.snapshot;
        self.snapshot = prepared.next;
        if previous.active_path != self.snapshot.active_path
            || previous.network_generation != self.snapshot.network_generation
        {
            match self.snapshot.active_path {
                Some(NetworkPath::Direct) => {
                    self.direct_mtu_generation = self.snapshot.network_generation;
                    self.direct_mtu = MtuState::new();
                }
                Some(NetworkPath::Relay) => {
                    self.relay_mtu_generation = self.snapshot.network_generation;
                    self.relay_mtu = MtuState::new();
                }
                None => {}
            }
        }
        Ok(PathTransitionOutcome {
            previous,
            current: self.snapshot,
            changed: previous != self.snapshot,
        })
    }

    pub(crate) fn next_mtu_probe(&self, path: NetworkPath, generation: u64) -> Option<u32> {
        match path {
            NetworkPath::Direct if generation == self.direct_mtu_generation => {
                self.direct_mtu.next_probe()
            }
            NetworkPath::Relay if generation == self.relay_mtu_generation => {
                self.relay_mtu.next_probe()
            }
            _ => None,
        }
    }

    /// Fold an authenticated live-path probe result. Stale generations are
    /// ignored without mutating the current path's MTU state.
    pub(crate) fn record_mtu_probe(
        &mut self,
        path: NetworkPath,
        generation: u64,
        size: u32,
        succeeded: bool,
    ) -> bool {
        match path {
            NetworkPath::Direct if generation == self.direct_mtu_generation => {
                self.direct_mtu.record(size, succeeded);
                true
            }
            NetworkPath::Relay if generation == self.relay_mtu_generation => {
                self.relay_mtu.record(size, succeeded);
                true
            }
            _ => false,
        }
    }

    pub(crate) fn effective_mtu(&self, path: NetworkPath, generation: u64) -> u32 {
        match path {
            NetworkPath::Direct if generation == self.direct_mtu_generation => {
                self.direct_mtu.effective_mtu()
            }
            NetworkPath::Relay if generation == self.relay_mtu_generation => {
                self.relay_mtu.effective_mtu()
            }
            _ => MTU_FLOOR,
        }
    }

    fn active_path(state: ConnectionState) -> Option<NetworkPath> {
        match state {
            ConnectionState::Direct => Some(NetworkPath::Direct),
            ConnectionState::Relay => Some(NetworkPath::Relay),
            _ => None,
        }
    }

    fn is_legal(from: ConnectionState, to: ConnectionState) -> bool {
        if from == to || to == ConnectionState::Closed {
            return true;
        }
        match from {
            ConnectionState::Closed => false,
            ConnectionState::Idle => matches!(
                to,
                ConnectionState::Connecting
                    | ConnectionState::HolePunching
                    | ConnectionState::Direct
                    | ConnectionState::FallbackToRelay
                    | ConnectionState::Relay
                    | ConnectionState::Failed
            ),
            ConnectionState::Connecting => matches!(
                to,
                ConnectionState::Idle
                    | ConnectionState::HolePunching
                    | ConnectionState::Direct
                    | ConnectionState::FallbackToRelay
                    | ConnectionState::Relay
                    | ConnectionState::Failed
            ),
            ConnectionState::HolePunching => matches!(
                to,
                ConnectionState::Idle
                    | ConnectionState::Connecting
                    | ConnectionState::Direct
                    | ConnectionState::FallbackToRelay
                    | ConnectionState::Relay
                    | ConnectionState::Failed
            ),
            ConnectionState::Direct => matches!(
                to,
                ConnectionState::Idle
                    | ConnectionState::Connecting
                    | ConnectionState::HolePunching
                    | ConnectionState::FallbackToRelay
                    | ConnectionState::Relay
                    | ConnectionState::Failed
            ),
            ConnectionState::FallbackToRelay => matches!(
                to,
                ConnectionState::Idle
                    | ConnectionState::Connecting
                    | ConnectionState::HolePunching
                    | ConnectionState::Direct
                    | ConnectionState::Relay
                    | ConnectionState::Failed
            ),
            ConnectionState::Relay => matches!(
                to,
                ConnectionState::Idle
                    | ConnectionState::Connecting
                    | ConnectionState::HolePunching
                    | ConnectionState::Direct
                    | ConnectionState::FallbackToRelay
                    | ConnectionState::Failed
            ),
            ConnectionState::Failed => matches!(
                to,
                ConnectionState::Idle
                    | ConnectionState::Connecting
                    | ConnectionState::HolePunching
                    | ConnectionState::Direct
                    | ConnectionState::FallbackToRelay
                    | ConnectionState::Relay
            ),
        }
    }
}

#[cfg(test)]
mod path_state_machine_tests {
    use super::*;

    #[test]
    fn prepare_is_non_mutating_and_commit_is_atomic() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        let before = machine.snapshot();
        let prepared = machine
            .prepare(ConnectionState::Relay, 7, 11, "relay_confirmed")
            .expect("transition should prepare");
        assert_eq!(machine.snapshot(), before);
        let committed = machine.commit(prepared).expect("commit should succeed");
        assert!(committed.changed);
        assert_eq!(committed.current.active_path, Some(NetworkPath::Relay));
        assert_eq!(committed.current.revision, 1);
    }

    #[test]
    fn stale_and_illegal_prepare_leave_snapshot_unchanged() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        let prepared = machine
            .prepare(ConnectionState::Relay, 8, 10, "relay_confirmed")
            .unwrap();
        machine.commit(prepared).unwrap();
        let before = machine.snapshot();
        assert_eq!(
            machine.prepare(ConnectionState::Direct, 7, 99, "stale"),
            Err(PathTransitionRejection::StaleNetworkGeneration)
        );
        assert_eq!(machine.snapshot(), before);
        let close = machine
            .prepare(ConnectionState::Closed, 8, 10, "closed")
            .unwrap();
        machine.commit(close).unwrap();
        let closed = machine.snapshot();
        assert_eq!(
            machine.prepare(ConnectionState::Direct, 9, 11, "resurrect"),
            Err(PathTransitionRejection::IllegalTransition)
        );
        assert_eq!(machine.snapshot(), closed);
    }

    #[test]
    fn superseded_token_does_not_mutate_snapshot() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        let relay = machine
            .prepare(ConnectionState::Relay, 3, 1, "relay")
            .unwrap();
        let direct = machine
            .prepare(ConnectionState::Direct, 3, 2, "direct")
            .unwrap();
        machine.commit(relay).unwrap();
        let before = machine.snapshot();
        assert_eq!(
            machine.commit(direct),
            Err(PathTransitionRejection::SupersededRevision)
        );
        assert_eq!(machine.snapshot(), before);
    }

    #[test]
    fn mtu_is_keyed_by_path_and_generation() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        let direct = machine
            .prepare(ConnectionState::Direct, 5, 2, "direct")
            .unwrap();
        machine.commit(direct).unwrap();
        assert_eq!(machine.next_mtu_probe(NetworkPath::Direct, 5), Some(1280));
        assert!(machine.record_mtu_probe(NetworkPath::Direct, 5, 1280, true));
        assert_eq!(machine.effective_mtu(NetworkPath::Direct, 5), 1280);
        assert!(!machine.record_mtu_probe(NetworkPath::Direct, 4, 1360, true));
        assert_eq!(machine.effective_mtu(NetworkPath::Direct, 5), 1280);

        let relay = machine
            .prepare(ConnectionState::Relay, 5, 2, "relay")
            .unwrap();
        machine.commit(relay).unwrap();
        assert_eq!(machine.effective_mtu(NetworkPath::Relay, 5), MTU_FLOOR);
        assert_eq!(machine.effective_mtu(NetworkPath::Direct, 5), 1280);
    }
}
