//! Generation-safe path-state reducer.
//!
//! The legacy `ConnectionState` remains a compatibility projection for the
//! public status API.  This module is the authority for the active business
//! path and for Direct/Relay progress.  It deliberately models those domains
//! with enums instead of another collection of independently mutable flags.

use super::{ConnectionState, NetworkPath, PeerSessionGeneration};
use std::net::SocketAddr;

/// The three independent generations that fence every path event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PathEpoch {
    pub(crate) network_generation: u64,
    pub(crate) peer_session_generation: PeerSessionGeneration,
    pub(crate) remote_candidate_epoch: u64,
}

impl PathEpoch {
    pub(crate) const fn new(
        network_generation: u64,
        peer_session_generation: PeerSessionGeneration,
        remote_candidate_epoch: u64,
    ) -> Self {
        Self {
            network_generation,
            peer_session_generation,
            remote_candidate_epoch,
        }
    }

    pub(crate) const fn unbound(network_generation: u64, remote_candidate_epoch: u64) -> Self {
        Self::new(
            network_generation,
            PeerSessionGeneration::UNBOUND,
            remote_candidate_epoch,
        )
    }
}

/// Process-local identity of an encrypted Direct validation transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectValidationIdentity {
    pub(crate) epoch: PathEpoch,
    pub(crate) owner_token: Option<u64>,
    pub(crate) request_id: Option<u16>,
    pub(crate) endpoint: Option<SocketAddr>,
}

impl DirectValidationIdentity {
    pub(crate) const fn owned(
        epoch: PathEpoch,
        owner_token: u64,
        request_id: Option<u16>,
        endpoint: Option<SocketAddr>,
    ) -> Self {
        Self {
            epoch,
            owner_token: Some(owner_token),
            request_id,
            endpoint,
        }
    }

    pub(crate) const fn compatibility(epoch: PathEpoch, endpoint: Option<SocketAddr>) -> Self {
        Self {
            epoch,
            owner_token: None,
            request_id: None,
            endpoint,
        }
    }

    fn with_epoch(self, epoch: PathEpoch) -> Self {
        Self { epoch, ..self }
    }

    fn same_owner(self, other: Self) -> bool {
        match (self.owner_token, other.owner_token) {
            (Some(current), Some(incoming)) => current == incoming,
            // Compatibility confirmations have no daemon-owned worker.  They
            // remain available to old internal callers but can never match an
            // owned validation lease by accident.
            (None, None) => true,
            _ => false,
        }
    }
}

/// A Relay connection can be unknown only for compatibility callers.  Real
/// relay runtime traffic always carries a process-local incarnation ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelayConnectionIncarnation {
    Known(u64),
    CompatibilityUnknown,
}

impl From<Option<u64>> for RelayConnectionIncarnation {
    fn from(value: Option<u64>) -> Self {
        value.map_or(Self::CompatibilityUnknown, Self::Known)
    }
}

/// Exact identity of one local Relay transport publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelayConnectionIdentity {
    pub(crate) epoch: PathEpoch,
    pub(crate) endpoint: String,
    pub(crate) incarnation: RelayConnectionIncarnation,
}

impl RelayConnectionIdentity {
    pub(crate) fn new(
        epoch: PathEpoch,
        endpoint: impl Into<String>,
        connection_id: Option<u64>,
    ) -> Self {
        Self {
            epoch,
            endpoint: endpoint.into(),
            incarnation: connection_id.into(),
        }
    }

    fn with_epoch(&self, epoch: PathEpoch) -> Self {
        Self {
            epoch,
            endpoint: self.endpoint.clone(),
            incarnation: self.incarnation,
        }
    }

    fn same_transport(&self, other: &Self) -> bool {
        self.endpoint == other.endpoint && self.incarnation == other.incarnation
    }

    fn rejects_ready_replacement(&self, incoming: &Self) -> bool {
        match (self.incarnation, incoming.incarnation) {
            (
                RelayConnectionIncarnation::Known(current),
                RelayConnectionIncarnation::Known(replacement),
            ) => {
                replacement < current
                    || (replacement == current && self.endpoint != incoming.endpoint)
            }
            (
                RelayConnectionIncarnation::Known(_),
                RelayConnectionIncarnation::CompatibilityUnknown,
            ) => true,
            (
                RelayConnectionIncarnation::CompatibilityUnknown,
                RelayConnectionIncarnation::Known(_)
                | RelayConnectionIncarnation::CompatibilityUnknown,
            ) => false,
        }
    }
}

/// Monotonic retry identity.  Reusing an attempt number is harmless because
/// duplicate events reduce to a no-op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DirectAttemptNumber(pub(crate) u64);

/// Which already-proven paths survive a local generation advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathRetention {
    None,
    Direct,
    Relay,
    DirectAndRelay,
}

impl PathRetention {
    fn keeps_direct(self) -> bool {
        matches!(self, Self::Direct | Self::DirectAndRelay)
    }

    fn keeps_relay(self) -> bool {
        matches!(self, Self::Relay | Self::DirectAndRelay)
    }
}

/// Whether a remote candidate refresh preserves the exact encrypted Direct
/// transport or represents a real handover.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectCandidateContinuity {
    RetainCommitted,
    Invalidate,
}

/// Typed input to the reducer.  Every asynchronous path result carries all
/// three epoch domains; Direct and Relay results additionally carry their
/// concrete validation/transport identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathEvent {
    PeerOnline {
        epoch: PathEpoch,
    },
    PeerLeft {
        epoch: PathEpoch,
    },
    IdentityReset,
    NetworkGenerationAdvanced {
        epoch: PathEpoch,
        retained: PathRetention,
    },
    RemoteCandidateEpochAdvanced {
        epoch: PathEpoch,
        direct: DirectCandidateContinuity,
    },
    RelayTransportReady {
        relay: RelayConnectionIdentity,
    },
    RelayPeerConfirmed {
        relay: RelayConnectionIdentity,
    },
    RelayBusinessUsable {
        relay: RelayConnectionIdentity,
    },
    RelayTransportLost {
        relay: RelayConnectionIdentity,
    },
    RelayPathFailed {
        relay: RelayConnectionIdentity,
    },
    DirectProbeStarted {
        epoch: PathEpoch,
        attempt: DirectAttemptNumber,
    },
    DirectValidationStarted {
        validation: DirectValidationIdentity,
    },
    DirectCommitted {
        validation: DirectValidationIdentity,
    },
    DirectProbeFailed {
        epoch: PathEpoch,
    },
    DirectPathFailed {
        epoch: PathEpoch,
    },
    DirectAttemptCancelled {
        epoch: PathEpoch,
        owner_token: Option<u64>,
    },
    DirectRetryScheduled {
        epoch: PathEpoch,
        attempt: DirectAttemptNumber,
    },
    /// Compatibility seam for existing synchronous state callers.  New path
    /// decisions use the specific events above.
    CompatibilityStateRequested {
        epoch: PathEpoch,
        state: ConnectionState,
        direct_endpoint: Option<SocketAddr>,
        relay_endpoint: Option<String>,
        relay_connection_id: Option<u64>,
    },
}

impl PathEvent {
    pub(crate) fn epoch(&self) -> Option<PathEpoch> {
        match self {
            Self::PeerOnline { epoch }
            | Self::PeerLeft { epoch }
            | Self::NetworkGenerationAdvanced { epoch, .. }
            | Self::RemoteCandidateEpochAdvanced { epoch, .. }
            | Self::DirectProbeStarted { epoch, .. }
            | Self::DirectProbeFailed { epoch }
            | Self::DirectPathFailed { epoch }
            | Self::DirectAttemptCancelled { epoch, .. }
            | Self::DirectRetryScheduled { epoch, .. }
            | Self::CompatibilityStateRequested { epoch, .. } => Some(*epoch),
            Self::RelayTransportReady { relay }
            | Self::RelayPeerConfirmed { relay }
            | Self::RelayBusinessUsable { relay }
            | Self::RelayTransportLost { relay }
            | Self::RelayPathFailed { relay } => Some(relay.epoch),
            Self::DirectValidationStarted { validation } | Self::DirectCommitted { validation } => {
                Some(validation.epoch)
            }
            Self::IdentityReset => None,
        }
    }
}

/// There is exactly one active business path.  `Unavailable` is a real state,
/// not the accidental combination of several false flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ActiveBusinessPath {
    Unavailable,
    Relay(RelayConnectionIdentity),
    Direct(DirectValidationIdentity),
}

impl ActiveBusinessPath {
    pub(crate) fn network_path(&self) -> Option<NetworkPath> {
        match self {
            Self::Unavailable => None,
            Self::Relay(_) => Some(NetworkPath::Relay),
            Self::Direct(_) => Some(NetworkPath::Direct),
        }
    }
}

/// Relay's delivery proof is stronger at every successive variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayPathState {
    Unavailable,
    Ready(RelayConnectionIdentity),
    Confirmed(RelayConnectionIdentity),
    Usable(RelayConnectionIdentity),
}

impl RelayPathState {
    fn identity(&self) -> Option<&RelayConnectionIdentity> {
        match self {
            Self::Unavailable => None,
            Self::Ready(identity) | Self::Confirmed(identity) | Self::Usable(identity) => {
                Some(identity)
            }
        }
    }

    fn confirmed_identity(&self) -> Option<&RelayConnectionIdentity> {
        match self {
            Self::Confirmed(identity) | Self::Usable(identity) => Some(identity),
            Self::Unavailable | Self::Ready(_) => None,
        }
    }

    fn with_epoch(&self, epoch: PathEpoch) -> Self {
        match self {
            Self::Unavailable => Self::Unavailable,
            Self::Ready(identity) => Self::Ready(identity.with_epoch(epoch)),
            Self::Confirmed(identity) => Self::Confirmed(identity.with_epoch(epoch)),
            Self::Usable(identity) => Self::Usable(identity.with_epoch(epoch)),
        }
    }
}

/// Direct discovery and validation are explicit even while Relay remains the
/// active business path in the background.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DirectPathState {
    Idle,
    Probing {
        epoch: PathEpoch,
        attempt: DirectAttemptNumber,
    },
    Validating(DirectValidationIdentity),
    Committed(DirectValidationIdentity),
}

impl DirectPathState {
    fn with_epoch_if_committed(&self, epoch: PathEpoch) -> Self {
        match self {
            Self::Committed(identity) => Self::Committed(identity.with_epoch(epoch)),
            Self::Idle | Self::Probing { .. } | Self::Validating(_) => Self::Idle,
        }
    }
}

/// Degradation and recovery are first-class state, not log-only side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathRecoveryState {
    Stable,
    Degraded {
        epoch: PathEpoch,
        from: NetworkPath,
        fallback: Option<NetworkPath>,
    },
    Recovering {
        epoch: PathEpoch,
        target: NetworkPath,
        attempt: DirectAttemptNumber,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerPathLifecycle {
    Unbound,
    Online,
    Offline,
}

/// Complete typed state.  `compatibility_state` is a projection maintained in
/// the same commit as the authoritative fields; it is never reduced on its
/// own by production path decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathState {
    pub(crate) lifecycle: PeerPathLifecycle,
    pub(crate) epoch: Option<PathEpoch>,
    pub(crate) active: ActiveBusinessPath,
    pub(crate) relay: RelayPathState,
    pub(crate) direct: DirectPathState,
    pub(crate) recovery: PathRecoveryState,
    pub(crate) compatibility_state: ConnectionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathTransitionDecision {
    Applied,
    Noop,
    RejectedNetworkGeneration,
    RejectedPeerSessionGeneration,
    RejectedRemoteCandidateEpoch,
    RejectedPeerOffline,
    RejectedDirectValidationIdentity,
    RejectedRelayConnectionIdentity,
    RejectedRevision,
    RejectedIllegalTransition,
}

impl PathTransitionDecision {
    pub(crate) fn accepted(self) -> bool {
        matches!(self, Self::Applied | Self::Noop)
    }
}

/// Minimal typed side-effect interface reserved for observability and future
/// DPLPMTUD consumers.  It does not change any wire format.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PathAction {
    ActivePath {
        previous: Option<NetworkPath>,
        current: Option<NetworkPath>,
    },
    CompatibilityState {
        previous: ConnectionState,
        current: ConnectionState,
    },
    RelayState,
    DirectState,
    RecoveryState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathTransition {
    base_revision: u64,
    decision: PathTransitionDecision,
    next: PathState,
    actions: Vec<PathAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathStateMachineSnapshot {
    pub(crate) state: PathState,
    pub(crate) revision: u64,
    pub(crate) rejected_transitions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathTransitionOutcome {
    pub(crate) decision: PathTransitionDecision,
    pub(crate) previous: PathState,
    pub(crate) snapshot: PathStateMachineSnapshot,
    pub(crate) actions: Vec<PathAction>,
}

impl PathTransitionOutcome {
    pub(crate) fn accepted(&self) -> bool {
        self.decision.accepted()
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PathStateMachine {
    state: PathState,
    revision: u64,
    rejected_transitions: u64,
}

impl PathStateMachine {
    pub(crate) fn new(initial_state: ConnectionState) -> Self {
        Self {
            state: PathState {
                lifecycle: PeerPathLifecycle::Unbound,
                epoch: None,
                active: ActiveBusinessPath::Unavailable,
                relay: RelayPathState::Unavailable,
                direct: DirectPathState::Idle,
                recovery: PathRecoveryState::Stable,
                compatibility_state: initial_state,
            },
            revision: 0,
            rejected_transitions: 0,
        }
    }

    pub(crate) fn snapshot(&self) -> PathStateMachineSnapshot {
        PathStateMachineSnapshot {
            state: self.state.clone(),
            revision: self.revision,
            rejected_transitions: self.rejected_transitions,
        }
    }

    pub(crate) fn current_epoch(&self) -> Option<PathEpoch> {
        self.state.epoch
    }

    pub(crate) fn active_path(&self) -> Option<NetworkPath> {
        self.state.active.network_path()
    }

    /// Pure reducer: no compatibility mirror or transport side effect is
    /// touched until `PeerConnection::commit_path_transition` accepts it.
    pub(crate) fn reduce(&self, event: PathEvent) -> PathTransition {
        let previous = &self.state;
        let mut next = previous.clone();

        let result: Result<(), PathTransitionDecision> = (|| match event {
            PathEvent::IdentityReset => {
                next = Self::unbound_state();
                Ok(())
            }
            PathEvent::PeerOnline { epoch } => self.reduce_peer_online(&mut next, epoch),
            PathEvent::PeerLeft { epoch } => {
                if self.state.lifecycle == PeerPathLifecycle::Unbound {
                    next.epoch = Some(epoch);
                } else if self.state.lifecycle == PeerPathLifecycle::Offline {
                    if self.state.epoch != Some(epoch) {
                        return Err(PathTransitionDecision::RejectedPeerSessionGeneration);
                    }
                } else {
                    let current = self.online_epoch()?;
                    if epoch.peer_session_generation < current.peer_session_generation {
                        return Err(PathTransitionDecision::RejectedPeerSessionGeneration);
                    }
                    if epoch.peer_session_generation == current.peer_session_generation {
                        self.validate_epoch_values(current, epoch)?;
                    } else {
                        next.epoch = Some(epoch);
                    }
                }
                next.lifecycle = PeerPathLifecycle::Offline;
                next.active = ActiveBusinessPath::Unavailable;
                next.relay = RelayPathState::Unavailable;
                next.direct = DirectPathState::Idle;
                next.recovery = PathRecoveryState::Stable;
                next.compatibility_state = ConnectionState::Closed;
                Ok(())
            }
            PathEvent::NetworkGenerationAdvanced { epoch, retained } => {
                self.reduce_network_advance(&mut next, epoch, retained)
            }
            PathEvent::RemoteCandidateEpochAdvanced { epoch, direct } => {
                self.reduce_remote_candidate_advance(&mut next, epoch, direct)
            }
            PathEvent::RelayTransportReady { relay } => {
                self.validate_exact_epoch(relay.epoch)?;
                self.reduce_relay_ready(&mut next, relay)
            }
            PathEvent::RelayPeerConfirmed { relay } => {
                self.validate_exact_epoch(relay.epoch)?;
                self.reduce_relay_confirmed(&mut next, relay)
            }
            PathEvent::RelayBusinessUsable { relay } => {
                self.validate_exact_epoch(relay.epoch)?;
                self.reduce_relay_usable(&mut next, relay)
            }
            PathEvent::RelayTransportLost { relay } => {
                self.validate_bound_epoch(relay.epoch)?;
                self.reduce_relay_lost(&mut next, relay)
            }
            PathEvent::RelayPathFailed { relay } => {
                self.validate_exact_epoch(relay.epoch)?;
                self.reduce_relay_path_failed(&mut next, relay)
            }
            PathEvent::DirectProbeStarted { epoch, attempt }
            | PathEvent::DirectRetryScheduled { epoch, attempt } => {
                self.validate_exact_epoch(epoch)?;
                self.reduce_direct_probe_started(&mut next, epoch, attempt);
                Ok(())
            }
            PathEvent::DirectValidationStarted { validation } => {
                self.validate_exact_epoch(validation.epoch)?;
                self.reduce_direct_validation_started(&mut next, validation)
            }
            PathEvent::DirectCommitted { validation } => {
                self.validate_exact_epoch(validation.epoch)?;
                self.reduce_direct_committed(&mut next, validation)
            }
            PathEvent::DirectProbeFailed { epoch } => {
                self.validate_exact_epoch(epoch)?;
                self.reduce_direct_probe_failed(&mut next, epoch);
                Ok(())
            }
            PathEvent::DirectPathFailed { epoch } => {
                self.validate_exact_epoch(epoch)?;
                self.reduce_direct_path_failed(&mut next, epoch);
                Ok(())
            }
            PathEvent::DirectAttemptCancelled { epoch, owner_token } => {
                self.validate_exact_epoch(epoch)?;
                self.reduce_direct_cancelled(&mut next, epoch, owner_token)
            }
            PathEvent::CompatibilityStateRequested {
                epoch,
                state,
                direct_endpoint,
                relay_endpoint,
                relay_connection_id,
            } => self.reduce_compatibility_state(
                &mut next,
                epoch,
                state,
                direct_endpoint,
                relay_endpoint,
                relay_connection_id,
            ),
        })();

        if let Err(decision) = result {
            return PathTransition {
                base_revision: self.revision,
                decision,
                next: previous.clone(),
                actions: Vec::new(),
            };
        }
        if !Self::state_is_valid(&next) {
            return PathTransition {
                base_revision: self.revision,
                decision: PathTransitionDecision::RejectedIllegalTransition,
                next: previous.clone(),
                actions: Vec::new(),
            };
        }

        let actions = Self::actions(previous, &next);
        PathTransition {
            base_revision: self.revision,
            decision: if next == *previous {
                PathTransitionDecision::Noop
            } else {
                PathTransitionDecision::Applied
            },
            next,
            actions,
        }
    }

    pub(crate) fn commit(&mut self, transition: PathTransition) -> PathTransitionOutcome {
        let previous = self.state.clone();
        let decision =
            if transition.decision.accepted() && transition.base_revision != self.revision {
                PathTransitionDecision::RejectedRevision
            } else {
                transition.decision
            };
        let actions = if decision.accepted() {
            transition.actions.clone()
        } else {
            Vec::new()
        };
        if decision.accepted() {
            if decision == PathTransitionDecision::Applied {
                self.state = transition.next;
                self.revision = self.revision.wrapping_add(1);
            }
        } else {
            self.rejected_transitions = self.rejected_transitions.wrapping_add(1);
        }
        PathTransitionOutcome {
            decision,
            previous,
            snapshot: self.snapshot(),
            actions,
        }
    }

    fn unbound_state() -> PathState {
        PathState {
            lifecycle: PeerPathLifecycle::Unbound,
            epoch: None,
            active: ActiveBusinessPath::Unavailable,
            relay: RelayPathState::Unavailable,
            direct: DirectPathState::Idle,
            recovery: PathRecoveryState::Stable,
            compatibility_state: ConnectionState::Idle,
        }
    }

    fn reduce_peer_online(
        &self,
        next: &mut PathState,
        epoch: PathEpoch,
    ) -> Result<(), PathTransitionDecision> {
        if let Some(current) = self.state.epoch {
            if epoch.peer_session_generation < current.peer_session_generation {
                return Err(PathTransitionDecision::RejectedPeerSessionGeneration);
            }
            if epoch.peer_session_generation == current.peer_session_generation {
                if self.state.lifecycle == PeerPathLifecycle::Offline {
                    return Err(PathTransitionDecision::RejectedPeerOffline);
                }
                if epoch.network_generation != current.network_generation {
                    return Err(PathTransitionDecision::RejectedNetworkGeneration);
                }
                if epoch.remote_candidate_epoch != current.remote_candidate_epoch {
                    return Err(PathTransitionDecision::RejectedRemoteCandidateEpoch);
                }
                return Ok(());
            }
        }
        *next = PathState {
            lifecycle: PeerPathLifecycle::Online,
            epoch: Some(epoch),
            active: ActiveBusinessPath::Unavailable,
            relay: RelayPathState::Unavailable,
            direct: DirectPathState::Idle,
            recovery: PathRecoveryState::Stable,
            compatibility_state: ConnectionState::Idle,
        };
        Ok(())
    }

    fn reduce_network_advance(
        &self,
        next: &mut PathState,
        epoch: PathEpoch,
        retained: PathRetention,
    ) -> Result<(), PathTransitionDecision> {
        let current = self.online_epoch()?;
        if epoch.peer_session_generation != current.peer_session_generation {
            return Err(PathTransitionDecision::RejectedPeerSessionGeneration);
        }
        if epoch.network_generation < current.network_generation {
            return Err(PathTransitionDecision::RejectedNetworkGeneration);
        }
        if epoch.remote_candidate_epoch != current.remote_candidate_epoch {
            return Err(PathTransitionDecision::RejectedRemoteCandidateEpoch);
        }
        if epoch.network_generation == current.network_generation {
            return Ok(());
        }

        let previous_active = self.state.active.network_path();
        next.epoch = Some(epoch);
        next.relay = if retained.keeps_relay() {
            self.state.relay.with_epoch(epoch)
        } else {
            RelayPathState::Unavailable
        };
        next.direct = if retained.keeps_direct() {
            self.state.direct.with_epoch_if_committed(epoch)
        } else {
            DirectPathState::Idle
        };
        next.active = match (&self.state.active, &next.direct, &next.relay) {
            (ActiveBusinessPath::Direct(_), DirectPathState::Committed(identity), _) => {
                ActiveBusinessPath::Direct(*identity)
            }
            (ActiveBusinessPath::Relay(_), _, relay) => relay
                .confirmed_identity()
                .cloned()
                .map_or(ActiveBusinessPath::Unavailable, ActiveBusinessPath::Relay),
            _ => ActiveBusinessPath::Unavailable,
        };
        Self::set_projection_after_epoch_change(next, previous_active, epoch);
        Ok(())
    }

    fn reduce_remote_candidate_advance(
        &self,
        next: &mut PathState,
        epoch: PathEpoch,
        continuity: DirectCandidateContinuity,
    ) -> Result<(), PathTransitionDecision> {
        let current = self.online_epoch()?;
        if epoch.peer_session_generation != current.peer_session_generation {
            return Err(PathTransitionDecision::RejectedPeerSessionGeneration);
        }
        if epoch.network_generation != current.network_generation {
            return Err(PathTransitionDecision::RejectedNetworkGeneration);
        }
        if epoch.remote_candidate_epoch < current.remote_candidate_epoch {
            return Err(PathTransitionDecision::RejectedRemoteCandidateEpoch);
        }
        if epoch.remote_candidate_epoch == current.remote_candidate_epoch {
            return Ok(());
        }

        let previous_active = self.state.active.network_path();
        next.epoch = Some(epoch);
        // Relay delivery is not invalidated by a candidate refresh, but its
        // state stamp is rebased so future old-candidate events fail closed.
        next.relay = self.state.relay.with_epoch(epoch);
        next.direct = match continuity {
            DirectCandidateContinuity::RetainCommitted => {
                self.state.direct.with_epoch_if_committed(epoch)
            }
            DirectCandidateContinuity::Invalidate => DirectPathState::Idle,
        };
        next.active = match (&self.state.active, &next.direct) {
            (ActiveBusinessPath::Direct(_), DirectPathState::Committed(identity)) => {
                ActiveBusinessPath::Direct(*identity)
            }
            (ActiveBusinessPath::Direct(_), _) => next
                .relay
                .confirmed_identity()
                .cloned()
                .map_or(ActiveBusinessPath::Unavailable, ActiveBusinessPath::Relay),
            (ActiveBusinessPath::Relay(_), _) => next
                .relay
                .confirmed_identity()
                .cloned()
                .map_or(ActiveBusinessPath::Unavailable, ActiveBusinessPath::Relay),
            (ActiveBusinessPath::Unavailable, _) => ActiveBusinessPath::Unavailable,
        };
        Self::set_projection_after_epoch_change(next, previous_active, epoch);
        Ok(())
    }

    fn reduce_relay_ready(
        &self,
        next: &mut PathState,
        relay: RelayConnectionIdentity,
    ) -> Result<(), PathTransitionDecision> {
        if let Some(current) = self.state.relay.identity() {
            if current.rejects_ready_replacement(&relay) {
                return Err(PathTransitionDecision::RejectedRelayConnectionIdentity);
            }
            if current.same_transport(&relay)
                && matches!(
                    self.state.relay,
                    RelayPathState::Confirmed(_) | RelayPathState::Usable(_)
                )
            {
                return Ok(());
            }
        }
        let replaced_active_relay = matches!(
            &self.state.active,
            ActiveBusinessPath::Relay(active) if !active.same_transport(&relay)
        );
        next.relay = RelayPathState::Ready(relay);
        if replaced_active_relay {
            next.active = ActiveBusinessPath::Unavailable;
            let epoch = next
                .epoch
                .expect("validated online events always have an epoch");
            next.recovery = PathRecoveryState::Degraded {
                epoch,
                from: NetworkPath::Relay,
                fallback: None,
            };
            next.compatibility_state = ConnectionState::FallbackToRelay;
        }
        Ok(())
    }

    fn reduce_relay_confirmed(
        &self,
        next: &mut PathState,
        relay: RelayConnectionIdentity,
    ) -> Result<(), PathTransitionDecision> {
        if let Some(current) = self.state.relay.identity() {
            if !current.same_transport(&relay) {
                return Err(PathTransitionDecision::RejectedRelayConnectionIdentity);
            }
        }
        next.relay = match &self.state.relay {
            RelayPathState::Usable(current) if current.same_transport(&relay) => {
                RelayPathState::Usable(relay.clone())
            }
            _ => RelayPathState::Confirmed(relay.clone()),
        };
        if !matches!(next.active, ActiveBusinessPath::Direct(_)) {
            next.active = ActiveBusinessPath::Relay(relay);
            next.compatibility_state = ConnectionState::Relay;
            if !matches!(
                next.direct,
                DirectPathState::Probing { .. } | DirectPathState::Validating(_)
            ) {
                next.recovery = PathRecoveryState::Stable;
            }
        }
        Ok(())
    }

    fn reduce_relay_usable(
        &self,
        next: &mut PathState,
        relay: RelayConnectionIdentity,
    ) -> Result<(), PathTransitionDecision> {
        let Some(current) = self.state.relay.confirmed_identity() else {
            return Err(PathTransitionDecision::RejectedIllegalTransition);
        };
        if !current.same_transport(&relay) {
            return Err(PathTransitionDecision::RejectedRelayConnectionIdentity);
        }
        next.relay = RelayPathState::Usable(relay.clone());
        if !matches!(next.active, ActiveBusinessPath::Direct(_)) {
            next.active = ActiveBusinessPath::Relay(relay);
            next.compatibility_state = ConnectionState::Relay;
        }
        Ok(())
    }

    fn reduce_relay_lost(
        &self,
        next: &mut PathState,
        relay: RelayConnectionIdentity,
    ) -> Result<(), PathTransitionDecision> {
        let Some(current) = self.state.relay.identity() else {
            return Ok(());
        };
        if !current.same_transport(&relay) {
            return Err(PathTransitionDecision::RejectedRelayConnectionIdentity);
        }
        next.relay = RelayPathState::Unavailable;
        if matches!(
            &self.state.active,
            ActiveBusinessPath::Relay(active) if active.same_transport(&relay)
        ) {
            next.active = ActiveBusinessPath::Unavailable;
            next.recovery = PathRecoveryState::Degraded {
                epoch: relay.epoch,
                from: NetworkPath::Relay,
                fallback: None,
            };
            next.compatibility_state = ConnectionState::FallbackToRelay;
        }
        Ok(())
    }

    fn reduce_relay_path_failed(
        &self,
        next: &mut PathState,
        relay: RelayConnectionIdentity,
    ) -> Result<(), PathTransitionDecision> {
        let Some(current) = self.state.relay.confirmed_identity() else {
            return Ok(());
        };
        if !current.same_transport(&relay) {
            return Err(PathTransitionDecision::RejectedRelayConnectionIdentity);
        }
        if matches!(
            &self.state.active,
            ActiveBusinessPath::Relay(active) if active.same_transport(&relay)
        ) {
            next.active = ActiveBusinessPath::Unavailable;
            next.recovery = PathRecoveryState::Degraded {
                epoch: relay.epoch,
                from: NetworkPath::Relay,
                fallback: None,
            };
            next.compatibility_state = ConnectionState::FallbackToRelay;
        }
        Ok(())
    }

    fn reduce_direct_probe_started(
        &self,
        next: &mut PathState,
        epoch: PathEpoch,
        attempt: DirectAttemptNumber,
    ) {
        if matches!(
            self.state.direct,
            DirectPathState::Validating(_) | DirectPathState::Committed(_)
        ) {
            return;
        }
        next.direct = DirectPathState::Probing { epoch, attempt };
        next.recovery = PathRecoveryState::Recovering {
            epoch,
            target: NetworkPath::Direct,
            attempt,
        };
        if matches!(next.active, ActiveBusinessPath::Unavailable) {
            next.compatibility_state = ConnectionState::HolePunching;
        }
    }

    fn reduce_direct_validation_started(
        &self,
        next: &mut PathState,
        validation: DirectValidationIdentity,
    ) -> Result<(), PathTransitionDecision> {
        if let DirectPathState::Committed(current) = self.state.direct {
            return if current == validation {
                Ok(())
            } else {
                Err(PathTransitionDecision::RejectedDirectValidationIdentity)
            };
        }
        if let DirectPathState::Validating(current) = self.state.direct {
            if !current.same_owner(validation) {
                return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
            }
        }
        next.direct = DirectPathState::Validating(validation);
        next.recovery = PathRecoveryState::Recovering {
            epoch: validation.epoch,
            target: NetworkPath::Direct,
            attempt: DirectAttemptNumber(validation.owner_token.unwrap_or_default()),
        };
        if matches!(next.active, ActiveBusinessPath::Unavailable) {
            next.compatibility_state = ConnectionState::HolePunching;
        }
        Ok(())
    }

    fn reduce_direct_committed(
        &self,
        next: &mut PathState,
        validation: DirectValidationIdentity,
    ) -> Result<(), PathTransitionDecision> {
        match self.state.direct {
            DirectPathState::Validating(current) => {
                if current != validation {
                    return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
                }
            }
            DirectPathState::Committed(current) => {
                let compatibility_replacement =
                    current.owner_token.is_none() && validation.owner_token.is_none();
                if current != validation && !compatibility_replacement {
                    return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
                }
                // A second ACK from the same validation owner is duplicate
                // evidence. Preserve the first atomic commit and its endpoint.
                if current == validation {
                    return Ok(());
                }
            }
            DirectPathState::Idle | DirectPathState::Probing { .. }
                if validation.owner_token.is_some() =>
            {
                return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
            }
            DirectPathState::Idle | DirectPathState::Probing { .. } => {}
        }
        next.direct = DirectPathState::Committed(validation);
        next.active = ActiveBusinessPath::Direct(validation);
        next.recovery = PathRecoveryState::Stable;
        next.compatibility_state = ConnectionState::Direct;
        Ok(())
    }

    fn reduce_direct_probe_failed(&self, next: &mut PathState, epoch: PathEpoch) {
        if matches!(self.state.direct, DirectPathState::Committed(_)) {
            return;
        }
        next.direct = DirectPathState::Idle;
        if matches!(next.active, ActiveBusinessPath::Relay(_)) {
            // Relay stays active while the failed background upgrade is
            // retried.  In particular, this never marks the peer Offline.
            next.recovery = PathRecoveryState::Recovering {
                epoch,
                target: NetworkPath::Direct,
                attempt: DirectAttemptNumber(0),
            };
            next.compatibility_state = ConnectionState::Relay;
        } else {
            next.recovery = PathRecoveryState::Degraded {
                epoch,
                from: NetworkPath::Direct,
                fallback: None,
            };
            next.compatibility_state = ConnectionState::FallbackToRelay;
        }
    }

    fn reduce_direct_path_failed(&self, next: &mut PathState, epoch: PathEpoch) {
        let direct_was_active = matches!(self.state.active, ActiveBusinessPath::Direct(_));
        next.direct = DirectPathState::Idle;
        if direct_was_active {
            let relay = next.relay.confirmed_identity().cloned();
            next.active = relay
                .clone()
                .map_or(ActiveBusinessPath::Unavailable, ActiveBusinessPath::Relay);
            next.recovery = PathRecoveryState::Degraded {
                epoch,
                from: NetworkPath::Direct,
                fallback: relay.as_ref().map(|_| NetworkPath::Relay),
            };
            next.compatibility_state = if relay.is_some() {
                ConnectionState::Relay
            } else {
                ConnectionState::FallbackToRelay
            };
        } else if matches!(next.active, ActiveBusinessPath::Relay(_)) {
            next.recovery = PathRecoveryState::Recovering {
                epoch,
                target: NetworkPath::Direct,
                attempt: DirectAttemptNumber(0),
            };
            next.compatibility_state = ConnectionState::Relay;
        } else {
            next.recovery = PathRecoveryState::Degraded {
                epoch,
                from: NetworkPath::Direct,
                fallback: None,
            };
            next.compatibility_state = ConnectionState::FallbackToRelay;
        }
    }

    fn reduce_direct_cancelled(
        &self,
        next: &mut PathState,
        _epoch: PathEpoch,
        owner_token: Option<u64>,
    ) -> Result<(), PathTransitionDecision> {
        match self.state.direct {
            DirectPathState::Validating(current) if current.owner_token != owner_token => {
                return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
            }
            DirectPathState::Committed(_) | DirectPathState::Idle => return Ok(()),
            DirectPathState::Probing { .. } | DirectPathState::Validating(_) => {}
        }
        next.direct = DirectPathState::Idle;
        next.recovery = PathRecoveryState::Stable;
        if matches!(next.active, ActiveBusinessPath::Unavailable) {
            next.compatibility_state = ConnectionState::Idle;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn reduce_compatibility_state(
        &self,
        next: &mut PathState,
        epoch: PathEpoch,
        state: ConnectionState,
        direct_endpoint: Option<SocketAddr>,
        relay_endpoint: Option<String>,
        relay_connection_id: Option<u64>,
    ) -> Result<(), PathTransitionDecision> {
        if self.state.lifecycle == PeerPathLifecycle::Unbound {
            next.lifecycle = PeerPathLifecycle::Online;
            next.epoch = Some(epoch);
        } else {
            self.validate_exact_epoch(epoch)?;
        }
        match state {
            ConnectionState::Direct => {
                let validation = DirectValidationIdentity::compatibility(epoch, direct_endpoint);
                next.direct = DirectPathState::Committed(validation);
                next.active = ActiveBusinessPath::Direct(validation);
                next.recovery = PathRecoveryState::Stable;
            }
            ConnectionState::Relay => {
                let relay = RelayConnectionIdentity::new(
                    epoch,
                    relay_endpoint.unwrap_or_else(|| "compatibility-relay".to_string()),
                    relay_connection_id,
                );
                next.relay = RelayPathState::Confirmed(relay.clone());
                next.direct = DirectPathState::Idle;
                next.active = ActiveBusinessPath::Relay(relay);
                next.recovery = PathRecoveryState::Stable;
            }
            ConnectionState::HolePunching => {
                next.active = ActiveBusinessPath::Unavailable;
                next.direct = DirectPathState::Probing {
                    epoch,
                    attempt: DirectAttemptNumber(0),
                };
                next.recovery = PathRecoveryState::Recovering {
                    epoch,
                    target: NetworkPath::Direct,
                    attempt: DirectAttemptNumber(0),
                };
            }
            ConnectionState::FallbackToRelay => {
                let from = next.active.network_path().unwrap_or(NetworkPath::Direct);
                next.active = ActiveBusinessPath::Unavailable;
                next.direct = DirectPathState::Idle;
                next.recovery = PathRecoveryState::Degraded {
                    epoch,
                    from,
                    fallback: None,
                };
            }
            ConnectionState::Closed => {
                next.lifecycle = PeerPathLifecycle::Offline;
                next.active = ActiveBusinessPath::Unavailable;
                next.relay = RelayPathState::Unavailable;
                next.direct = DirectPathState::Idle;
                next.recovery = PathRecoveryState::Stable;
            }
            ConnectionState::Idle | ConnectionState::Connecting | ConnectionState::Failed => {
                next.active = ActiveBusinessPath::Unavailable;
                next.direct = DirectPathState::Idle;
                next.recovery = PathRecoveryState::Stable;
            }
        }
        next.compatibility_state = state;
        Ok(())
    }

    fn validate_exact_epoch(&self, incoming: PathEpoch) -> Result<(), PathTransitionDecision> {
        let current = self.online_epoch()?;
        self.validate_epoch_values(current, incoming)
    }

    fn validate_bound_epoch(&self, incoming: PathEpoch) -> Result<(), PathTransitionDecision> {
        let current = self
            .state
            .epoch
            .ok_or(PathTransitionDecision::RejectedIllegalTransition)?;
        self.validate_epoch_values(current, incoming)
    }

    fn validate_epoch_values(
        &self,
        current: PathEpoch,
        incoming: PathEpoch,
    ) -> Result<(), PathTransitionDecision> {
        if incoming.peer_session_generation != current.peer_session_generation {
            return Err(PathTransitionDecision::RejectedPeerSessionGeneration);
        }
        if incoming.network_generation != current.network_generation {
            return Err(PathTransitionDecision::RejectedNetworkGeneration);
        }
        if incoming.remote_candidate_epoch != current.remote_candidate_epoch {
            return Err(PathTransitionDecision::RejectedRemoteCandidateEpoch);
        }
        Ok(())
    }

    fn online_epoch(&self) -> Result<PathEpoch, PathTransitionDecision> {
        if self.state.lifecycle != PeerPathLifecycle::Online {
            return Err(PathTransitionDecision::RejectedPeerOffline);
        }
        self.state
            .epoch
            .ok_or(PathTransitionDecision::RejectedIllegalTransition)
    }

    fn set_projection_after_epoch_change(
        next: &mut PathState,
        previous_active: Option<NetworkPath>,
        epoch: PathEpoch,
    ) {
        next.compatibility_state = match next.active.network_path() {
            Some(NetworkPath::Direct) => ConnectionState::Direct,
            Some(NetworkPath::Relay) => ConnectionState::Relay,
            None => {
                if let Some(from) = previous_active {
                    next.recovery = PathRecoveryState::Degraded {
                        epoch,
                        from,
                        fallback: None,
                    };
                    ConnectionState::FallbackToRelay
                } else {
                    // Generation publication alone never changed the legacy
                    // user-visible state. Preserve Idle/Connecting/
                    // HolePunching here; explicit probe events own recovery.
                    next.recovery = PathRecoveryState::Stable;
                    next.compatibility_state
                }
            }
        };
    }

    fn state_is_valid(state: &PathState) -> bool {
        if state.lifecycle == PeerPathLifecycle::Unbound {
            return state.epoch.is_none()
                && matches!(state.active, ActiveBusinessPath::Unavailable)
                && matches!(state.relay, RelayPathState::Unavailable)
                && matches!(state.direct, DirectPathState::Idle);
        }
        if state.lifecycle == PeerPathLifecycle::Offline {
            return matches!(state.active, ActiveBusinessPath::Unavailable)
                && matches!(state.relay, RelayPathState::Unavailable)
                && matches!(state.direct, DirectPathState::Idle)
                && matches!(state.recovery, PathRecoveryState::Stable)
                && state.compatibility_state == ConnectionState::Closed;
        }
        let Some(epoch) = state.epoch else {
            return false;
        };
        if state
            .relay
            .identity()
            .is_some_and(|identity| identity.epoch != epoch)
        {
            return false;
        }
        let direct_epoch = match state.direct {
            DirectPathState::Idle => None,
            DirectPathState::Probing { epoch, .. } => Some(epoch),
            DirectPathState::Validating(identity) | DirectPathState::Committed(identity) => {
                Some(identity.epoch)
            }
        };
        if direct_epoch.is_some_and(|direct_epoch| direct_epoch != epoch) {
            return false;
        }
        let recovery_epoch = match state.recovery {
            PathRecoveryState::Stable => None,
            PathRecoveryState::Degraded { epoch, .. }
            | PathRecoveryState::Recovering { epoch, .. } => Some(epoch),
        };
        if recovery_epoch.is_some_and(|recovery_epoch| recovery_epoch != epoch) {
            return false;
        }
        match &state.active {
            ActiveBusinessPath::Unavailable => !matches!(
                state.compatibility_state,
                ConnectionState::Direct | ConnectionState::Relay
            ),
            ActiveBusinessPath::Direct(active) => {
                state.compatibility_state == ConnectionState::Direct
                    && matches!(
                        state.direct,
                        DirectPathState::Committed(identity) if identity == *active
                    )
            }
            ActiveBusinessPath::Relay(active) => {
                state.compatibility_state == ConnectionState::Relay
                    && state
                        .relay
                        .confirmed_identity()
                        .is_some_and(|identity| identity == active)
            }
        }
    }

    fn actions(previous: &PathState, next: &PathState) -> Vec<PathAction> {
        let mut actions = Vec::new();
        let previous_active = previous.active.network_path();
        let next_active = next.active.network_path();
        if previous_active != next_active {
            actions.push(PathAction::ActivePath {
                previous: previous_active,
                current: next_active,
            });
        }
        if previous.compatibility_state != next.compatibility_state {
            actions.push(PathAction::CompatibilityState {
                previous: previous.compatibility_state,
                current: next.compatibility_state,
            });
        }
        if previous.relay != next.relay {
            actions.push(PathAction::RelayState);
        }
        if previous.direct != next.direct {
            actions.push(PathAction::DirectState);
        }
        if previous.recovery != next.recovery {
            actions.push(PathAction::RecoveryState);
        }
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(network: u64, session: u64, candidate: u64) -> PathEpoch {
        PathEpoch::new(network, PeerSessionGeneration::for_test(session), candidate)
    }

    fn commit(machine: &mut PathStateMachine, event: PathEvent) -> PathTransitionOutcome {
        let transition = machine.reduce(event);
        machine.commit(transition)
    }

    fn online_machine(epoch: PathEpoch) -> PathStateMachine {
        let mut machine = PathStateMachine::new(ConnectionState::Idle);
        assert!(commit(&mut machine, PathEvent::PeerOnline { epoch }).accepted());
        machine
    }

    fn relay(epoch: PathEpoch, endpoint: &str, id: u64) -> RelayConnectionIdentity {
        RelayConnectionIdentity::new(epoch, endpoint, Some(id))
    }

    fn validation(epoch: PathEpoch, owner: u64, request: u16) -> DirectValidationIdentity {
        DirectValidationIdentity::owned(
            epoch,
            owner,
            Some(request),
            Some("198.51.100.7:4000".parse().unwrap()),
        )
    }

    fn commit_direct(
        machine: &mut PathStateMachine,
        validation: DirectValidationIdentity,
    ) -> PathTransitionOutcome {
        assert!(commit(machine, PathEvent::DirectValidationStarted { validation },).accepted());
        commit(machine, PathEvent::DirectCommitted { validation })
    }

    #[test]
    fn stale_direct_ack_late_is_rejected_by_each_generation_domain_table() {
        let current = epoch(7, 11, 13);
        let cases = [
            (
                epoch(6, 11, 13),
                PathTransitionDecision::RejectedNetworkGeneration,
            ),
            (
                epoch(7, 10, 13),
                PathTransitionDecision::RejectedPeerSessionGeneration,
            ),
            (
                epoch(7, 11, 12),
                PathTransitionDecision::RejectedRemoteCandidateEpoch,
            ),
        ];
        for (stale, expected) in cases {
            let mut machine = online_machine(current);
            let confirmed_relay = relay(current, "relay.test:443", 41);
            commit(
                &mut machine,
                PathEvent::RelayPeerConfirmed {
                    relay: confirmed_relay,
                },
            );
            let outcome = commit(
                &mut machine,
                PathEvent::DirectCommitted {
                    validation: validation(stale, 1, 2),
                },
            );
            assert_eq!(outcome.decision, expected);
            assert_eq!(
                outcome.snapshot.state.active.network_path(),
                Some(NetworkPath::Relay)
            );
        }

        let mut machine = online_machine(current);
        let current_validation = validation(current, 22, 3);
        commit(
            &mut machine,
            PathEvent::DirectValidationStarted {
                validation: current_validation,
            },
        );
        let stale_owner = commit(
            &mut machine,
            PathEvent::DirectCommitted {
                validation: validation(current, 21, 2),
            },
        );
        assert_eq!(
            stale_owner.decision,
            PathTransitionDecision::RejectedDirectValidationIdentity
        );
        let stale_request = commit(
            &mut machine,
            PathEvent::DirectCommitted {
                validation: validation(current, 22, 2),
            },
        );
        assert_eq!(
            stale_request.decision,
            PathTransitionDecision::RejectedDirectValidationIdentity
        );
        assert!(commit(
            &mut machine,
            PathEvent::DirectCommitted {
                validation: current_validation,
            },
        )
        .accepted());
        assert_eq!(
            commit(
                &mut machine,
                PathEvent::DirectCommitted {
                    validation: validation(current, 21, 2),
                },
            )
            .decision,
            PathTransitionDecision::RejectedDirectValidationIdentity
        );
        assert_eq!(
            commit(
                &mut machine,
                PathEvent::DirectValidationStarted {
                    validation: validation(current, 23, 4),
                },
            )
            .decision,
            PathTransitionDecision::RejectedDirectValidationIdentity
        );
    }

    #[test]
    fn stale_relay_ack_late_cannot_replace_current_relay() {
        let current = epoch(3, 5, 8);
        let mut machine = online_machine(current);
        let live = relay(current, "relay.test:443", 102);
        commit(
            &mut machine,
            PathEvent::RelayTransportReady {
                relay: live.clone(),
            },
        );
        let stale = relay(epoch(3, 4, 8), "relay.test:443", 101);
        let outcome = commit(&mut machine, PathEvent::RelayPeerConfirmed { relay: stale });
        assert_eq!(
            outcome.decision,
            PathTransitionDecision::RejectedPeerSessionGeneration
        );
        assert!(matches!(
            outcome.snapshot.state.relay,
            RelayPathState::Ready(_)
        ));
    }

    #[test]
    fn network_generation_switch_rejects_old_completion() {
        let first = epoch(1, 1, 2);
        let second = epoch(2, 1, 2);
        let mut machine = online_machine(first);
        let mixed_epoch = commit(
            &mut machine,
            PathEvent::NetworkGenerationAdvanced {
                epoch: epoch(2, 1, 1),
                retained: PathRetention::None,
            },
        );
        assert_eq!(
            mixed_epoch.decision,
            PathTransitionDecision::RejectedRemoteCandidateEpoch
        );
        commit(
            &mut machine,
            PathEvent::NetworkGenerationAdvanced {
                epoch: second,
                retained: PathRetention::None,
            },
        );
        let outcome = commit(
            &mut machine,
            PathEvent::DirectCommitted {
                validation: validation(first, 9, 1),
            },
        );
        assert_eq!(
            outcome.decision,
            PathTransitionDecision::RejectedNetworkGeneration
        );
    }

    #[test]
    fn candidate_refresh_wins_over_concurrent_old_direct_commit() {
        let old = epoch(4, 2, 10);
        let refreshed = epoch(4, 2, 11);
        let mut machine = online_machine(old);
        let in_flight = validation(old, 7, 3);
        assert!(commit(
            &mut machine,
            PathEvent::DirectValidationStarted {
                validation: in_flight,
            },
        )
        .accepted());
        commit(
            &mut machine,
            PathEvent::RemoteCandidateEpochAdvanced {
                epoch: refreshed,
                direct: DirectCandidateContinuity::Invalidate,
            },
        );
        let outcome = commit(
            &mut machine,
            PathEvent::DirectCommitted {
                validation: in_flight,
            },
        );
        assert_eq!(
            outcome.decision,
            PathTransitionDecision::RejectedRemoteCandidateEpoch
        );
        assert_eq!(outcome.snapshot.state.active.network_path(), None);
    }

    #[test]
    fn candidate_refresh_retains_an_established_encrypted_direct_path_when_proven() {
        let before = epoch(4, 2, 10);
        let after = epoch(5, 2, 10);
        let mut machine = online_machine(before);
        commit_direct(&mut machine, validation(before, 8, 4));

        let retained = commit(
            &mut machine,
            PathEvent::NetworkGenerationAdvanced {
                epoch: after,
                retained: PathRetention::Direct,
            },
        );
        assert_eq!(
            retained.snapshot.state.active.network_path(),
            Some(NetworkPath::Direct)
        );
        assert!(matches!(
            retained.snapshot.state.direct,
            DirectPathState::Committed(identity) if identity.epoch == after
        ));
    }

    #[test]
    fn compatibility_direct_confirmation_can_replace_endpoint_without_weakening_owned_identity() {
        let current = epoch(4, 2, 10);
        let mut machine = online_machine(current);
        let first = DirectValidationIdentity::compatibility(
            current,
            Some("198.51.100.7:4000".parse().unwrap()),
        );
        let replacement = DirectValidationIdentity::compatibility(
            current,
            Some("192.168.31.20:51820".parse().unwrap()),
        );
        assert!(commit(
            &mut machine,
            PathEvent::DirectCommitted { validation: first },
        )
        .accepted());
        let replaced = commit(
            &mut machine,
            PathEvent::DirectCommitted {
                validation: replacement,
            },
        );
        assert!(replaced.accepted());
        assert!(matches!(
            replaced.snapshot.state.active,
            ActiveBusinessPath::Direct(identity) if identity == replacement
        ));
    }

    #[test]
    fn direct_and_relay_simultaneous_success_always_leave_one_direct_active_path() {
        let current = epoch(9, 3, 4);
        for direct_first in [false, true] {
            let mut machine = online_machine(current);
            let relay = relay(current, "relay.test:443", 71);
            let direct = validation(current, 88, 5);
            let events = if direct_first {
                vec![
                    PathEvent::DirectValidationStarted { validation: direct },
                    PathEvent::DirectCommitted { validation: direct },
                    PathEvent::RelayPeerConfirmed { relay },
                ]
            } else {
                vec![
                    PathEvent::RelayPeerConfirmed { relay },
                    PathEvent::DirectValidationStarted { validation: direct },
                    PathEvent::DirectCommitted { validation: direct },
                ]
            };
            for event in events {
                assert!(commit(&mut machine, event).accepted());
            }
            assert_eq!(machine.active_path(), Some(NetworkPath::Direct));
        }
    }

    #[test]
    fn relay_available_direct_probe_failure_keeps_peer_online_and_relay_active() {
        let current = epoch(2, 4, 6);
        let mut machine = online_machine(current);
        let relay = relay(current, "relay.test:443", 1);
        commit(&mut machine, PathEvent::RelayPeerConfirmed { relay });
        commit(
            &mut machine,
            PathEvent::DirectProbeStarted {
                epoch: current,
                attempt: DirectAttemptNumber(1),
            },
        );
        let outcome = commit(
            &mut machine,
            PathEvent::DirectProbeFailed { epoch: current },
        );
        assert_eq!(outcome.snapshot.state.lifecycle, PeerPathLifecycle::Online);
        assert_eq!(
            outcome.snapshot.state.active.network_path(),
            Some(NetworkPath::Relay)
        );
        assert_eq!(
            outcome.snapshot.state.compatibility_state,
            ConnectionState::Relay
        );
    }

    #[test]
    fn relay_reconnect_same_endpoint_invalidates_old_id_and_old_ack() {
        let current = epoch(5, 5, 5);
        let mut machine = online_machine(current);
        let old = relay(current, "relay.test:443", 200);
        commit(
            &mut machine,
            PathEvent::RelayTransportReady { relay: old.clone() },
        );
        commit(
            &mut machine,
            PathEvent::RelayPeerConfirmed { relay: old.clone() },
        );
        let replacement = relay(current, "relay.test:443", 201);
        let replaced = commit(
            &mut machine,
            PathEvent::RelayTransportReady {
                relay: replacement.clone(),
            },
        );
        assert_eq!(replaced.snapshot.state.active.network_path(), None);
        let stale_ready = commit(
            &mut machine,
            PathEvent::RelayTransportReady { relay: old.clone() },
        );
        assert_eq!(
            stale_ready.decision,
            PathTransitionDecision::RejectedRelayConnectionIdentity
        );
        let stale = commit(&mut machine, PathEvent::RelayPeerConfirmed { relay: old });
        assert_eq!(
            stale.decision,
            PathTransitionDecision::RejectedRelayConnectionIdentity
        );
        let confirmed = commit(
            &mut machine,
            PathEvent::RelayPeerConfirmed { relay: replacement },
        );
        assert_eq!(
            confirmed.snapshot.state.active.network_path(),
            Some(NetworkPath::Relay)
        );
    }

    #[test]
    fn peer_left_blocks_old_probe_validation_and_timer_completion() {
        let old = epoch(1, 1, 1);
        let replacement = epoch(1, 2, 1);
        let mut machine = online_machine(old);
        commit(&mut machine, PathEvent::PeerLeft { epoch: old });
        for event in [
            PathEvent::DirectProbeStarted {
                epoch: old,
                attempt: DirectAttemptNumber(1),
            },
            PathEvent::DirectCommitted {
                validation: validation(old, 1, 1),
            },
            PathEvent::DirectRetryScheduled {
                epoch: old,
                attempt: DirectAttemptNumber(2),
            },
        ] {
            assert_eq!(
                commit(&mut machine, event).decision,
                PathTransitionDecision::RejectedPeerOffline
            );
        }
        assert!(commit(&mut machine, PathEvent::PeerOnline { epoch: replacement }).accepted());
        assert_eq!(
            commit(
                &mut machine,
                PathEvent::DirectCommitted {
                    validation: validation(old, 1, 1),
                },
            )
            .decision,
            PathTransitionDecision::RejectedPeerSessionGeneration
        );
    }

    #[test]
    fn duplicate_events_are_idempotent_and_do_not_advance_revision() {
        let current = epoch(1, 1, 1);
        let mut machine = online_machine(current);
        let relay = relay(current, "relay.test:443", 4);
        let first = commit(
            &mut machine,
            PathEvent::RelayPeerConfirmed {
                relay: relay.clone(),
            },
        );
        let duplicate = commit(&mut machine, PathEvent::RelayPeerConfirmed { relay });
        assert_eq!(duplicate.decision, PathTransitionDecision::Noop);
        assert_eq!(duplicate.snapshot.revision, first.snapshot.revision);
    }

    #[test]
    fn direct_to_relay_to_direct_recovery_is_explicit() {
        let current = epoch(6, 7, 8);
        let mut machine = online_machine(current);
        let relay = relay(current, "relay.test:443", 90);
        commit(
            &mut machine,
            PathEvent::RelayPeerConfirmed {
                relay: relay.clone(),
            },
        );
        commit_direct(&mut machine, validation(current, 1, 1));
        let degraded = commit(&mut machine, PathEvent::DirectPathFailed { epoch: current });
        assert_eq!(
            degraded.snapshot.state.active.network_path(),
            Some(NetworkPath::Relay)
        );
        assert!(matches!(
            degraded.snapshot.state.recovery,
            PathRecoveryState::Degraded {
                fallback: Some(NetworkPath::Relay),
                ..
            }
        ));
        let recovered = commit_direct(&mut machine, validation(current, 2, 2));
        assert_eq!(
            recovered.snapshot.state.active.network_path(),
            Some(NetworkPath::Direct)
        );
        assert!(matches!(
            recovered.snapshot.state.recovery,
            PathRecoveryState::Stable
        ));
    }

    #[test]
    fn cancel_and_retry_require_the_current_validation_owner() {
        let current = epoch(2, 2, 2);
        let mut machine = online_machine(current);
        let identity = validation(current, 55, 9);
        commit(
            &mut machine,
            PathEvent::DirectValidationStarted {
                validation: identity,
            },
        );
        let stale_cancel = commit(
            &mut machine,
            PathEvent::DirectAttemptCancelled {
                epoch: current,
                owner_token: Some(54),
            },
        );
        assert_eq!(
            stale_cancel.decision,
            PathTransitionDecision::RejectedDirectValidationIdentity
        );
        assert_eq!(
            commit(
                &mut machine,
                PathEvent::DirectAttemptCancelled {
                    epoch: current,
                    owner_token: None,
                },
            )
            .decision,
            PathTransitionDecision::RejectedDirectValidationIdentity
        );
        assert!(commit(
            &mut machine,
            PathEvent::DirectAttemptCancelled {
                epoch: current,
                owner_token: Some(55),
            },
        )
        .accepted());
        let retried = commit(
            &mut machine,
            PathEvent::DirectRetryScheduled {
                epoch: current,
                attempt: DirectAttemptNumber(3),
            },
        );
        assert!(matches!(
            retried.snapshot.state.direct,
            DirectPathState::Probing {
                attempt: DirectAttemptNumber(3),
                ..
            }
        ));
    }

    #[test]
    fn relay_background_direct_upgrade_never_destroys_healthy_relay() {
        let current = epoch(8, 8, 8);
        let mut machine = online_machine(current);
        let relay = relay(current, "relay.test:443", 8);
        commit(
            &mut machine,
            PathEvent::RelayPeerConfirmed {
                relay: relay.clone(),
            },
        );
        commit(
            &mut machine,
            PathEvent::DirectProbeStarted {
                epoch: current,
                attempt: DirectAttemptNumber(1),
            },
        );
        let validating = commit(
            &mut machine,
            PathEvent::DirectValidationStarted {
                validation: validation(current, 8, 1),
            },
        );
        assert_eq!(
            validating.snapshot.state.active.network_path(),
            Some(NetworkPath::Relay)
        );
        assert!(matches!(
            validating.snapshot.state.relay,
            RelayPathState::Confirmed(_)
        ));
    }

    #[test]
    fn rejected_connection_commit_executes_no_partial_side_effects() {
        let current = epoch(5, 7, 9);
        let stale = epoch(4, 7, 9);
        let mut connection = crate::peer::PeerConnection::new("peer-atomic", "10.20.0.9");
        assert!(connection
            .commit_path_transition(PathEvent::PeerOnline { epoch: current }, |_| {})
            .accepted());
        connection.bytes_sent = 7;

        let rejected = connection
            .commit_path_transition(PathEvent::DirectPathFailed { epoch: stale }, |conn| {
                conn.bytes_sent = 99
            });

        assert_eq!(
            rejected.decision,
            PathTransitionDecision::RejectedNetworkGeneration
        );
        assert_eq!(connection.bytes_sent, 7);
        assert_eq!(connection.state, ConnectionState::Idle);
        assert_eq!(connection.active_path(), None);
        assert_eq!(connection.path_state_snapshot().rejected_transitions, 1);
    }

    #[test]
    fn stale_reducer_transition_cannot_overwrite_a_newer_commit() {
        let current = epoch(9, 9, 9);
        let mut machine = online_machine(current);
        let delayed = machine.reduce(PathEvent::DirectProbeStarted {
            epoch: current,
            attempt: DirectAttemptNumber(1),
        });
        let relay = relay(current, "relay.test:443", 9);
        assert!(commit(
            &mut machine,
            PathEvent::RelayPeerConfirmed {
                relay: relay.clone(),
            },
        )
        .accepted());

        let stale_commit = machine.commit(delayed);
        assert_eq!(
            stale_commit.decision,
            PathTransitionDecision::RejectedRevision
        );
        assert_eq!(
            stale_commit.snapshot.state.active,
            ActiveBusinessPath::Relay(relay)
        );
        assert!(stale_commit.actions.is_empty());
    }
}
