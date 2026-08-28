/// One coherent, generation-bound view of a peer's connection and active path.
///
/// `PeerConnection::state` remains the compatibility mirror consumed by the
/// existing selector and diagnostics code. All live mutations now pass through
/// this machine first, so the mirror cannot resurrect a terminal peer or apply
/// stale generation/candidate evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathStateMachineSnapshot {
    pub state: ConnectionState,
    pub active_path: Option<NetworkPath>,
    pub network_generation: u64,
    pub candidate_generation: u64,
    pub revision: u64,
    pub rejected_transitions: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathTransitionDecision {
    Applied,
    Noop,
    RejectedStaleNetworkGeneration,
    RejectedStaleCandidateGeneration,
    RejectedIllegalTransition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathTransitionOutcome {
    pub decision: PathTransitionDecision,
    pub previous_state: ConnectionState,
    pub requested_state: ConnectionState,
    pub snapshot: PathStateMachineSnapshot,
}

impl PathTransitionOutcome {
    pub(crate) fn accepted(self) -> bool {
        matches!(
            self.decision,
            PathTransitionDecision::Applied | PathTransitionDecision::Noop
        )
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PathStateMachine {
    snapshot: PathStateMachineSnapshot,
}

impl PathStateMachine {
    pub(crate) fn new(initial_state: ConnectionState) -> Self {
        Self {
            snapshot: PathStateMachineSnapshot {
                state: initial_state,
                active_path: Self::active_path(initial_state),
                network_generation: 0,
                candidate_generation: 0,
                revision: 0,
                rejected_transitions: 0,
            },
        }
    }

    pub(crate) fn snapshot(&self) -> PathStateMachineSnapshot {
        self.snapshot
    }

    /// Reset is reserved for an authenticated peer lifecycle replacement. It
    /// is intentionally distinct from a normal state transition because a
    /// terminal `Closed` state must otherwise never be resurrected.
    pub(crate) fn reset(&mut self, state: ConnectionState) {
        let rejected_transitions = self.snapshot.rejected_transitions;
        let revision = self.snapshot.revision.wrapping_add(1);
        self.snapshot = PathStateMachineSnapshot {
            state,
            active_path: Self::active_path(state),
            network_generation: 0,
            candidate_generation: 0,
            revision,
            rejected_transitions,
        };
    }

    pub(crate) fn apply(
        &mut self,
        requested_state: ConnectionState,
        network_generation: u64,
        candidate_generation: u64,
    ) -> PathTransitionOutcome {
        let previous_state = self.snapshot.state;
        if network_generation < self.snapshot.network_generation {
            return self.reject(
                PathTransitionDecision::RejectedStaleNetworkGeneration,
                previous_state,
                requested_state,
            );
        }

        if requested_state == ConnectionState::Direct
            && network_generation == self.snapshot.network_generation
            && candidate_generation < self.snapshot.candidate_generation
        {
            return self.reject(
                PathTransitionDecision::RejectedStaleCandidateGeneration,
                previous_state,
                requested_state,
            );
        }

        if !Self::is_legal(previous_state, requested_state) {
            return self.reject(
                PathTransitionDecision::RejectedIllegalTransition,
                previous_state,
                requested_state,
            );
        }

        let generation_changed = network_generation > self.snapshot.network_generation;
        let candidate_changed = candidate_generation > self.snapshot.candidate_generation;
        let state_changed = previous_state != requested_state;

        if generation_changed {
            self.snapshot.network_generation = network_generation;
            // Candidate generations belong to a network epoch. A newer epoch
            // starts a fresh floor rather than inheriting the old one.
            self.snapshot.candidate_generation = candidate_generation;
        } else if candidate_changed {
            self.snapshot.candidate_generation = candidate_generation;
        }

        if state_changed {
            self.snapshot.state = requested_state;
            self.snapshot.active_path = Self::active_path(requested_state);
        }

        let decision = if generation_changed || candidate_changed || state_changed {
            self.snapshot.revision = self.snapshot.revision.wrapping_add(1);
            PathTransitionDecision::Applied
        } else {
            PathTransitionDecision::Noop
        };

        PathTransitionOutcome {
            decision,
            previous_state,
            requested_state,
            snapshot: self.snapshot,
        }
    }

    fn reject(
        &mut self,
        decision: PathTransitionDecision,
        previous_state: ConnectionState,
        requested_state: ConnectionState,
    ) -> PathTransitionOutcome {
        self.snapshot.rejected_transitions =
            self.snapshot.rejected_transitions.wrapping_add(1);
        PathTransitionOutcome {
            decision,
            previous_state,
            requested_state,
            snapshot: self.snapshot,
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
    fn relay_can_promote_to_direct_in_same_generation() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        assert!(machine
            .apply(ConnectionState::Relay, 7, 11)
            .accepted());
        let promoted = machine.apply(ConnectionState::Direct, 7, 12);
        assert_eq!(promoted.decision, PathTransitionDecision::Applied);
        assert_eq!(promoted.snapshot.active_path, Some(NetworkPath::Direct));
        assert_eq!(promoted.snapshot.revision, 2);
    }

    #[test]
    fn direct_can_fall_back_to_relay_without_losing_generation() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        assert!(machine
            .apply(ConnectionState::Direct, 4, 9)
            .accepted());
        assert!(machine
            .apply(ConnectionState::FallbackToRelay, 4, 9)
            .accepted());
        let relay = machine.apply(ConnectionState::Relay, 4, 9);
        assert_eq!(relay.snapshot.network_generation, 4);
        assert_eq!(relay.snapshot.active_path, Some(NetworkPath::Relay));
    }

    #[test]
    fn stale_network_generation_is_rejected() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        assert!(machine
            .apply(ConnectionState::Relay, 8, 2)
            .accepted());
        let stale = machine.apply(ConnectionState::Direct, 7, 99);
        assert_eq!(
            stale.decision,
            PathTransitionDecision::RejectedStaleNetworkGeneration
        );
        assert_eq!(stale.snapshot.state, ConnectionState::Relay);
        assert_eq!(stale.snapshot.rejected_transitions, 1);
    }

    #[test]
    fn stale_candidate_generation_cannot_promote_direct() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        assert!(machine
            .apply(ConnectionState::Relay, 3, 10)
            .accepted());
        let stale = machine.apply(ConnectionState::Direct, 3, 9);
        assert_eq!(
            stale.decision,
            PathTransitionDecision::RejectedStaleCandidateGeneration
        );
        assert_eq!(stale.snapshot.active_path, Some(NetworkPath::Relay));
    }

    #[test]
    fn closed_is_terminal_until_authenticated_reset() {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        assert!(machine
            .apply(ConnectionState::Closed, 2, 1)
            .accepted());
        let rejected = machine.apply(ConnectionState::Connecting, 3, 0);
        assert_eq!(
            rejected.decision,
            PathTransitionDecision::RejectedIllegalTransition
        );
        machine.reset(ConnectionState::Idle);
        assert!(machine
            .apply(ConnectionState::Connecting, 3, 0)
            .accepted());
    }
}
