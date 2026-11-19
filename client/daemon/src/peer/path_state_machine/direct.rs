//! Direct path transitions, including bounded validation of an alternate
//! while the committed path continues to own business traffic.
use super::*;

impl PathStateMachine {
    pub(super) fn start_alternate_validation(
        &self,
        next: &mut PathState,
        current: DirectValidationIdentity,
        validation: DirectValidationIdentity,
    ) -> Result<(), PathTransitionDecision> {
        if next.direct != DirectPathState::Committed(current)
            || next.active != ActiveBusinessPath::Direct(current)
            || current.epoch != validation.epoch
            || !validation.can_start_validation()
            || current.owner_token.is_none()
            || current.request_id.is_none()
            || current.owner_token == validation.owner_token
            || validation.owner_token.is_none()
            || current.commit_endpoint() == validation.request_endpoint()
            || next
                .alternate
                .is_some_and(|(_, pending)| !pending.same_owner(validation))
        {
            return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
        }
        next.alternate = Some((current, validation));
        Ok(())
    }

    pub(super) fn reduce_direct_probe_started(
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

    pub(super) fn reduce_direct_validation_started(
        &self,
        next: &mut PathState,
        validation: DirectValidationIdentity,
    ) -> Result<(), PathTransitionDecision> {
        if !validation.can_start_validation() {
            return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
        }
        if let DirectPathState::Committed(current) = self.state.direct {
            return if current.same_validation_request(validation) {
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

    pub(super) fn reduce_direct_committed(
        &self,
        next: &mut PathState,
        validation: DirectValidationIdentity,
    ) -> Result<(), PathTransitionDecision> {
        if !validation.can_commit() {
            return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
        }
        match self.state.direct {
            DirectPathState::Validating(current) => {
                if !current.same_validation_request(validation) {
                    return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
                }
            }
            DirectPathState::Committed(current) => {
                let compatibility_replacement =
                    current.owner_token.is_none() && validation.owner_token.is_none();
                if current != validation
                    && !current.same_validation_request(validation)
                    && !compatibility_replacement
                    && !self.state.alternate.is_some_and(|(original, pending)| {
                        original == current
                            && pending.same_validation_request(validation)
                            && validation.alternate_return_matches()
                    })
                {
                    return Err(PathTransitionDecision::RejectedDirectValidationIdentity);
                }
                // A second ACK from the same validation owner is duplicate
                // evidence. Preserve the first atomic commit and its endpoint.
                if current == validation || current.same_validation_request(validation) {
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

    pub(super) fn reduce_direct_probe_failed(&self, next: &mut PathState, epoch: PathEpoch) {
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

    pub(super) fn reduce_direct_path_failed(&self, next: &mut PathState, epoch: PathEpoch) {
        let direct_was_active = matches!(self.state.active, ActiveBusinessPath::Direct(_));
        next.direct = DirectPathState::Idle;
        if direct_was_active {
            // A business-ready Direct path has already satisfied startup and
            // falls back immediately. An ACK-only path whose MTU budget
            // never became usable must not turn a probe failure into an
            // early release of the connection's first Direct window.
            let relay = if self.direct_first_pending() {
                None
            } else {
                next.relay.confirmed_identity().cloned()
            };
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

    pub(super) fn reduce_direct_cancelled(
        &self,
        next: &mut PathState,
        _epoch: PathEpoch,
        owner_token: Option<u64>,
    ) -> Result<(), PathTransitionDecision> {
        if next
            .alternate
            .is_some_and(|(_, pending)| pending.owner_token == owner_token)
        {
            next.alternate = None;
            return Ok(());
        }
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
}
