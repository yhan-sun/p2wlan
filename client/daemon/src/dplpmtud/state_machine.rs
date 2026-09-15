use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::Instant;

use super::identity::{DplpmtudPathIdentity, DplpmtudPathIdentitySnapshot};
use super::sizes::{UdpDatagramSize, DPLPMTUD_BASE_UDP_DATAGRAM_SIZE};

pub(crate) const DPLPMTUD_SEARCH_GRANULARITY: u32 = 8;

pub(crate) const DPLPMTUD_MAX_RETRIES: u8 = 2;

pub(crate) const DPLPMTUD_PROBE_TIMEOUT: Duration = Duration::from_secs(1);

pub(crate) const DPLPMTUD_RAISE_INTERVAL: Duration = Duration::from_secs(10 * 60);

pub(crate) const DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) const DPLPMTUD_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(5);

const MAX_CONSUMED_PROBE_RECEIPTS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DplpmtudState {
    Disabled,
    Unsupported,
    Base,
    Searching,
    SearchComplete,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct DplpmtudProbeIdentity {
    pub(crate) sequence: u64,
    pub(crate) nonce: [u8; 16],
    pub(crate) path_cookie: [u8; 16],
    pub(crate) candidate_udp_datagram_size: UdpDatagramSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OutstandingProbe {
    identity: DplpmtudProbeIdentity,
    scheduled_at: Instant,
    sent_at: Option<Instant>,
    deadline: Instant,
    retry: u8,
}

/// Business-budget state that controls the independent monotonic revision.
/// Reducer diagnostics use `DplpmtudStateMachine::revision`; this state tracks
/// only exact-path identity and business-visible confirmed-budget changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DplpmtudBudgetRevisionState {
    path_identity: Option<DplpmtudPathIdentity>,
    confirmed_udp_datagram_size: Option<UdpDatagramSize>,
}

/// Failure classification for the final DPLPMTUD emit boundary.
///
/// These values are deliberately separate from path health: a lock/session
/// miss is local scheduling pressure, a transient send error is an I/O retry,
/// and only `LocalPacketTooLarge` is evidence that can shrink the local
/// search ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DplpmtudProbeSendFailure {
    TransientSend,
    EmitLockUnavailable,
    SessionUnavailable,
    LocalPacketTooLarge,
}

impl From<crate::error::DaemonError> for DplpmtudProbeSendFailure {
    fn from(_error: crate::error::DaemonError) -> Self {
        Self::TransientSend
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DplpmtudEvent {
    StartSearch {
        now: Instant,
    },
    ProbeScheduled {
        probe: DplpmtudProbeIdentity,
        retry: u8,
        now: Instant,
        deadline: Instant,
    },
    ProbeSent {
        probe: DplpmtudProbeIdentity,
        now: Instant,
    },
    ProbeAcked {
        probe: DplpmtudProbeIdentity,
        now: Instant,
    },
    ProbeTimedOut {
        probe: DplpmtudProbeIdentity,
        now: Instant,
    },
    ProbeSendFailed {
        probe: DplpmtudProbeIdentity,
        failure: DplpmtudProbeSendFailure,
        now: Instant,
    },
    /// A normal business datagram was rejected locally with EMSGSIZE.  The
    /// runtime accepts this only for the exact current identity + revision.
    BusinessPacketTooLarge {
        now: Instant,
    },
    CurrentPlpmtuConfirmationTimerExpired {
        now: Instant,
    },
    RaiseTimerExpired {
        now: Instant,
    },
    StaleAck {
        now: Instant,
    },
    Cancelled {
        reason: String,
        now: Instant,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DplpmtudTransitionDecision {
    Applied,
    Duplicate,
    Stale,
    Noop,
    Rejected,
    Busy,
}

#[derive(Debug, Clone)]
pub(crate) struct DplpmtudTransition {
    decision: DplpmtudTransitionDecision,
    next: DplpmtudStateMachine,
}

/// Pure bounded reducer for one exact Direct path.
#[derive(Debug, Clone)]
pub(crate) struct DplpmtudStateMachine {
    identity: Option<DplpmtudPathIdentity>,
    state: DplpmtudState,
    supported: bool,
    /// Conservative starting point.  This is never a usable budget until a
    /// BASE probe is positively ACKed.
    base_udp_datagram_size: UdpDatagramSize,
    base_confirmed: bool,
    confirmed_udp_datagram_size: Option<UdpDatagramSize>,
    search_upper_udp_datagram_size: UdpDatagramSize,
    pending_candidate_udp_datagram_size: Option<UdpDatagramSize>,
    current_plpmtu_confirmation_pending: bool,
    current_plpmtu_confirmation_at: Option<Instant>,
    outstanding: Option<OutstandingProbe>,
    retry_count: u8,
    next_sequence: u64,
    revision: u64,
    probe_count: u64,
    success_count: u64,
    timeout_count: u64,
    send_failure_count: u64,
    transient_send_failure_count: u64,
    emit_lock_unavailable_count: u64,
    session_unavailable_count: u64,
    local_packet_too_large_count: u64,
    business_packet_too_large_count: u64,
    last_send_failure_kind: Option<DplpmtudProbeSendFailure>,
    stale_ack_count: u64,
    duplicate_ack_count: u64,
    last_success_at: Option<Instant>,
    last_timeout_at: Option<Instant>,
    last_failure_at: Option<Instant>,
    raise_at: Option<Instant>,
    last_reset_reason: Option<String>,
    reset_count: u64,
    consumed_receipts: VecDeque<DplpmtudProbeIdentity>,
}

impl DplpmtudStateMachine {
    pub(crate) fn for_path(identity: DplpmtudPathIdentity, supported: bool, _now: Instant) -> Self {
        Self::for_path_with_reason(
            identity,
            supported,
            if supported {
                "direct_committed"
            } else {
                "dplpmtud_capability_not_negotiated"
            },
        )
    }

    pub(super) fn for_path_with_reason(
        identity: DplpmtudPathIdentity,
        supported: bool,
        reset_reason: &str,
    ) -> Self {
        let base = UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE);
        let upper = identity.outer_ip_family.ceiling_udp_datagram_size();
        let pending = supported.then_some(base);
        Self {
            identity: Some(identity),
            state: if supported {
                DplpmtudState::Base
            } else {
                DplpmtudState::Unsupported
            },
            supported,
            base_udp_datagram_size: base,
            base_confirmed: false,
            confirmed_udp_datagram_size: None,
            search_upper_udp_datagram_size: upper,
            pending_candidate_udp_datagram_size: pending,
            current_plpmtu_confirmation_pending: false,
            current_plpmtu_confirmation_at: None,
            outstanding: None,
            retry_count: 0,
            next_sequence: 1,
            revision: 1,
            probe_count: 0,
            success_count: 0,
            timeout_count: 0,
            send_failure_count: 0,
            transient_send_failure_count: 0,
            emit_lock_unavailable_count: 0,
            session_unavailable_count: 0,
            local_packet_too_large_count: 0,
            business_packet_too_large_count: 0,
            last_send_failure_kind: None,
            stale_ack_count: 0,
            duplicate_ack_count: 0,
            last_success_at: None,
            last_timeout_at: None,
            last_failure_at: None,
            raise_at: None,
            last_reset_reason: Some(reset_reason.to_string()),
            reset_count: 1,
            consumed_receipts: VecDeque::new(),
        }
    }

    pub(crate) fn identity(&self) -> Option<&DplpmtudPathIdentity> {
        self.identity.as_ref()
    }

    pub(crate) const fn state(&self) -> DplpmtudState {
        self.state
    }

    pub(super) fn business_confirmed_udp_datagram_size(&self) -> Option<UdpDatagramSize> {
        if !self.supported
            || matches!(
                self.state,
                DplpmtudState::Disabled | DplpmtudState::Unsupported
            )
            || !self.base_confirmed
        {
            return None;
        }
        self.confirmed_udp_datagram_size
    }

    pub(super) fn budget_revision_state(&self) -> DplpmtudBudgetRevisionState {
        DplpmtudBudgetRevisionState {
            path_identity: self.identity.clone(),
            confirmed_udp_datagram_size: self.business_confirmed_udp_datagram_size(),
        }
    }

    pub(crate) fn outstanding_identity(&self) -> Option<DplpmtudProbeIdentity> {
        self.outstanding.map(|outstanding| outstanding.identity)
    }

    pub(crate) fn next_wakeup(&self) -> Option<Instant> {
        [
            self.outstanding.map(|outstanding| outstanding.deadline),
            self.current_plpmtu_confirmation_at,
            self.raise_at,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    pub(crate) fn next_probe_components(&self) -> Option<(u64, UdpDatagramSize, u8)> {
        if !self.supported
            || !matches!(self.state, DplpmtudState::Base | DplpmtudState::Searching)
            || self.outstanding.is_some()
        {
            return None;
        }
        self.pending_candidate_udp_datagram_size
            .map(|candidate| (self.next_sequence, candidate, self.retry_count))
    }

    pub(crate) fn reduce(&self, event: DplpmtudEvent) -> DplpmtudTransition {
        let mut next = self.clone();
        let decision = match event {
            DplpmtudEvent::StartSearch { now } => {
                if self.state != DplpmtudState::Base {
                    DplpmtudTransitionDecision::Noop
                } else if self.pending_candidate_udp_datagram_size.is_none() {
                    next.state = DplpmtudState::SearchComplete;
                    next.raise_at = Some(now + DPLPMTUD_RAISE_INTERVAL);
                    DplpmtudTransitionDecision::Applied
                } else {
                    next.state = DplpmtudState::Searching;
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::ProbeScheduled {
                probe,
                retry,
                now,
                deadline,
            } => {
                if !matches!(self.state, DplpmtudState::Base | DplpmtudState::Searching)
                    || self.outstanding.is_some()
                    || self.pending_candidate_udp_datagram_size
                        != Some(probe.candidate_udp_datagram_size)
                    || retry != self.retry_count
                    || probe.sequence != self.next_sequence
                    || deadline <= now
                {
                    DplpmtudTransitionDecision::Rejected
                } else {
                    next.state = DplpmtudState::Searching;
                    next.outstanding = Some(OutstandingProbe {
                        identity: probe,
                        scheduled_at: now,
                        sent_at: None,
                        deadline,
                        retry,
                    });
                    next.next_sequence = next.next_sequence.wrapping_add(1).max(1);
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::ProbeSent { probe, now } => {
                if let Some(outstanding) = next.outstanding.as_mut() {
                    if outstanding.identity == probe && outstanding.sent_at.is_none() {
                        outstanding.sent_at = Some(now);
                        next.probe_count = next.probe_count.saturating_add(1);
                        DplpmtudTransitionDecision::Applied
                    } else {
                        DplpmtudTransitionDecision::Noop
                    }
                } else {
                    DplpmtudTransitionDecision::Noop
                }
            }
            DplpmtudEvent::ProbeAcked { probe, now } => {
                if self.consumed_receipts.contains(&probe) {
                    DplpmtudTransitionDecision::Duplicate
                } else if let Some(outstanding) = self.outstanding {
                    if outstanding.identity != probe
                        || outstanding.sent_at.is_none()
                        || now > outstanding.deadline
                    {
                        next.stale_ack_count = next.stale_ack_count.saturating_add(1);
                        DplpmtudTransitionDecision::Stale
                    } else {
                        next.outstanding = None;
                        next.retry_count = 0;
                        let is_current_confirmation = self.current_plpmtu_confirmation_pending;
                        if is_current_confirmation {
                            if self.confirmed_udp_datagram_size
                                != Some(probe.candidate_udp_datagram_size)
                            {
                                next.stale_ack_count = next.stale_ack_count.saturating_add(1);
                                return DplpmtudTransition {
                                    decision: DplpmtudTransitionDecision::Stale,
                                    next,
                                };
                            }
                        } else if probe.candidate_udp_datagram_size == self.base_udp_datagram_size {
                            next.base_confirmed = true;
                            next.confirmed_udp_datagram_size = Some(self.base_udp_datagram_size);
                        } else if self
                            .confirmed_udp_datagram_size
                            .is_some_and(|confirmed| probe.candidate_udp_datagram_size >= confirmed)
                        {
                            next.confirmed_udp_datagram_size =
                                Some(probe.candidate_udp_datagram_size);
                        } else {
                            next.stale_ack_count = next.stale_ack_count.saturating_add(1);
                            return DplpmtudTransition {
                                decision: DplpmtudTransitionDecision::Stale,
                                next,
                            };
                        }
                        next.success_count = next.success_count.saturating_add(1);
                        next.last_success_at = Some(now);
                        push_consumed_receipt(&mut next.consumed_receipts, probe);
                        if is_current_confirmation {
                            next.current_plpmtu_confirmation_pending = false;
                            next.current_plpmtu_confirmation_at =
                                Some(now + DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL);
                            next.pending_candidate_udp_datagram_size = None;
                            next.state = DplpmtudState::SearchComplete;
                        } else {
                            let confirmed = next
                                .confirmed_udp_datagram_size
                                .expect("BASE must be positively confirmed before search");
                            next.pending_candidate_udp_datagram_size = next_search_candidate(
                                confirmed,
                                next.search_upper_udp_datagram_size,
                            );
                            if next.pending_candidate_udp_datagram_size.is_none() {
                                next.state = DplpmtudState::SearchComplete;
                                next.current_plpmtu_confirmation_at =
                                    Some(now + DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL);
                                next.raise_at = Some(now + DPLPMTUD_RAISE_INTERVAL);
                            } else {
                                next.state = DplpmtudState::Searching;
                                next.raise_at = None;
                            }
                        }
                        DplpmtudTransitionDecision::Applied
                    }
                } else {
                    next.stale_ack_count = next.stale_ack_count.saturating_add(1);
                    DplpmtudTransitionDecision::Stale
                }
            }
            DplpmtudEvent::ProbeTimedOut { probe, now } => {
                let Some(outstanding) = self.outstanding else {
                    return DplpmtudTransition {
                        decision: DplpmtudTransitionDecision::Noop,
                        next,
                    };
                };
                if outstanding.identity != probe
                    || outstanding.sent_at.is_none()
                    || now < outstanding.deadline
                {
                    DplpmtudTransitionDecision::Rejected
                } else {
                    next.outstanding = None;
                    next.timeout_count = next.timeout_count.saturating_add(1);
                    next.last_timeout_at = Some(now);
                    if outstanding.retry < DPLPMTUD_MAX_RETRIES {
                        next.retry_count = outstanding.retry.saturating_add(1);
                        next.pending_candidate_udp_datagram_size =
                            Some(probe.candidate_udp_datagram_size);
                        next.state = DplpmtudState::Searching;
                    } else {
                        next.retry_count = 0;
                        if self.current_plpmtu_confirmation_pending {
                            lower_after_current_confirmation_failure(&mut next, probe, now);
                        } else if probe.candidate_udp_datagram_size == self.base_udp_datagram_size
                            && !self.base_confirmed
                        {
                            enter_base_error(&mut next, now);
                        } else {
                            let Some(confirmed) = self.confirmed_udp_datagram_size else {
                                enter_base_error(&mut next, now);
                                return DplpmtudTransition {
                                    decision: DplpmtudTransitionDecision::Applied,
                                    next,
                                };
                            };
                            lower_after_failed_search_candidate(
                                &mut next,
                                confirmed,
                                probe.candidate_udp_datagram_size,
                                now,
                            );
                        }
                    }
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::ProbeSendFailed {
                probe,
                failure,
                now,
            } => {
                if self.outstanding.map(|value| value.identity) != Some(probe) {
                    DplpmtudTransitionDecision::Noop
                } else {
                    next.outstanding = None;
                    next.send_failure_count = next.send_failure_count.saturating_add(1);
                    next.last_failure_at = Some(now);
                    next.last_send_failure_kind = Some(failure);
                    match failure {
                        DplpmtudProbeSendFailure::LocalPacketTooLarge => {
                            next.local_packet_too_large_count =
                                next.local_packet_too_large_count.saturating_add(1);
                            if self.current_plpmtu_confirmation_pending {
                                lower_after_current_confirmation_failure(&mut next, probe, now);
                            } else if probe.candidate_udp_datagram_size
                                == self.base_udp_datagram_size
                                && !self.base_confirmed
                            {
                                enter_base_error(&mut next, now);
                            } else if let Some(confirmed) = self.confirmed_udp_datagram_size {
                                lower_after_failed_search_candidate(
                                    &mut next,
                                    confirmed,
                                    probe.candidate_udp_datagram_size,
                                    now,
                                );
                            } else {
                                enter_base_error(&mut next, now);
                            }
                        }
                        DplpmtudProbeSendFailure::TransientSend
                        | DplpmtudProbeSendFailure::EmitLockUnavailable
                        | DplpmtudProbeSendFailure::SessionUnavailable => {
                            match failure {
                                DplpmtudProbeSendFailure::TransientSend => {
                                    next.transient_send_failure_count =
                                        next.transient_send_failure_count.saturating_add(1);
                                }
                                DplpmtudProbeSendFailure::EmitLockUnavailable => {
                                    next.emit_lock_unavailable_count =
                                        next.emit_lock_unavailable_count.saturating_add(1);
                                }
                                DplpmtudProbeSendFailure::SessionUnavailable => {
                                    next.session_unavailable_count =
                                        next.session_unavailable_count.saturating_add(1);
                                }
                                DplpmtudProbeSendFailure::LocalPacketTooLarge => {}
                            }
                            if self.current_plpmtu_confirmation_pending
                                && self.retry_count >= DPLPMTUD_MAX_RETRIES
                            {
                                lower_after_current_confirmation_failure(&mut next, probe, now);
                            } else if self.retry_count < DPLPMTUD_MAX_RETRIES {
                                next.retry_count = self.retry_count.saturating_add(1);
                                next.pending_candidate_udp_datagram_size =
                                    Some(probe.candidate_udp_datagram_size);
                                next.state = DplpmtudState::Searching;
                            } else if probe.candidate_udp_datagram_size
                                == self.base_udp_datagram_size
                                && !self.base_confirmed
                            {
                                enter_base_error(&mut next, now);
                            } else {
                                next.state = DplpmtudState::Error;
                                next.pending_candidate_udp_datagram_size = None;
                                next.raise_at = Some(now + DPLPMTUD_ERROR_RETRY_INTERVAL);
                            }
                        }
                    }
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::BusinessPacketTooLarge { now } => {
                if self.business_confirmed_udp_datagram_size().is_none() {
                    DplpmtudTransitionDecision::Noop
                } else {
                    next.business_packet_too_large_count =
                        next.business_packet_too_large_count.saturating_add(1);
                    next.local_packet_too_large_count =
                        next.local_packet_too_large_count.saturating_add(1);
                    next.last_send_failure_kind =
                        Some(DplpmtudProbeSendFailure::LocalPacketTooLarge);
                    next.last_failure_at = Some(now);
                    next.base_confirmed = false;
                    next.confirmed_udp_datagram_size = None;
                    next.outstanding = None;
                    next.pending_candidate_udp_datagram_size = Some(next.base_udp_datagram_size);
                    next.current_plpmtu_confirmation_pending = false;
                    next.current_plpmtu_confirmation_at = None;
                    next.retry_count = 0;
                    next.raise_at = None;
                    next.state = DplpmtudState::Base;
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::CurrentPlpmtuConfirmationTimerExpired { now } => {
                if self.state != DplpmtudState::SearchComplete
                    || self
                        .current_plpmtu_confirmation_at
                        .is_none_or(|deadline| now < deadline)
                    || self.confirmed_udp_datagram_size.is_none()
                    || self.current_plpmtu_confirmation_pending
                {
                    DplpmtudTransitionDecision::Noop
                } else {
                    next.pending_candidate_udp_datagram_size = self.confirmed_udp_datagram_size;
                    next.current_plpmtu_confirmation_at = None;
                    next.current_plpmtu_confirmation_pending = true;
                    next.retry_count = 0;
                    next.state = DplpmtudState::Searching;
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::RaiseTimerExpired { now } => {
                if !matches!(
                    self.state,
                    DplpmtudState::SearchComplete | DplpmtudState::Error
                ) || self.raise_at.is_none_or(|deadline| now < deadline)
                {
                    DplpmtudTransitionDecision::Noop
                } else {
                    next.search_upper_udp_datagram_size = next
                        .identity
                        .as_ref()
                        .map(|identity| identity.outer_ip_family.ceiling_udp_datagram_size())
                        .unwrap_or(next.search_upper_udp_datagram_size);
                    next.current_plpmtu_confirmation_pending = false;
                    next.current_plpmtu_confirmation_at = None;
                    next.pending_candidate_udp_datagram_size = next
                        .confirmed_udp_datagram_size
                        .map(|confirmed| {
                            next_search_candidate(confirmed, next.search_upper_udp_datagram_size)
                        })
                        .unwrap_or(Some(next.base_udp_datagram_size));
                    next.retry_count = 0;
                    next.raise_at = None;
                    next.state = if next.confirmed_udp_datagram_size.is_none() {
                        DplpmtudState::Base
                    } else if next.pending_candidate_udp_datagram_size.is_some() {
                        DplpmtudState::Searching
                    } else {
                        next.current_plpmtu_confirmation_at =
                            Some(now + DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL);
                        next.raise_at = Some(now + DPLPMTUD_RAISE_INTERVAL);
                        DplpmtudState::SearchComplete
                    };
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::StaleAck { now: _ } => {
                next.stale_ack_count = next.stale_ack_count.saturating_add(1);
                DplpmtudTransitionDecision::Stale
            }
            DplpmtudEvent::Cancelled { reason, now: _ } => {
                if self.state == DplpmtudState::Disabled
                    && self.last_reset_reason.as_deref() == Some(reason.as_str())
                    && !self.base_confirmed
                    && self.confirmed_udp_datagram_size.is_none()
                    && self.outstanding.is_none()
                    && self.pending_candidate_udp_datagram_size.is_none()
                    && !self.current_plpmtu_confirmation_pending
                    && self.current_plpmtu_confirmation_at.is_none()
                    && self.raise_at.is_none()
                {
                    DplpmtudTransitionDecision::Noop
                } else {
                    next.state = DplpmtudState::Disabled;
                    next.supported = false;
                    next.base_confirmed = false;
                    next.confirmed_udp_datagram_size = None;
                    next.outstanding = None;
                    next.pending_candidate_udp_datagram_size = None;
                    next.current_plpmtu_confirmation_pending = false;
                    next.current_plpmtu_confirmation_at = None;
                    next.raise_at = None;
                    next.last_reset_reason = Some(reason);
                    next.reset_count = next.reset_count.saturating_add(1);
                    DplpmtudTransitionDecision::Applied
                }
            }
        };
        DplpmtudTransition { decision, next }
    }

    pub(crate) fn commit(&mut self, transition: DplpmtudTransition) -> DplpmtudTransitionDecision {
        match transition.decision {
            DplpmtudTransitionDecision::Applied | DplpmtudTransitionDecision::Stale => {
                *self = transition.next;
                self.revision = self.revision.saturating_add(1);
            }
            DplpmtudTransitionDecision::Duplicate => {
                // Duplicate ACKs do not alter revision, timestamps, bounds or
                // success accounting. Only the dedicated diagnostic counter changes.
                self.duplicate_ack_count = self.duplicate_ack_count.saturating_add(1);
            }
            DplpmtudTransitionDecision::Noop
            | DplpmtudTransitionDecision::Rejected
            | DplpmtudTransitionDecision::Busy => {}
        }
        transition.decision
    }

    pub(crate) fn apply(&mut self, event: DplpmtudEvent) -> DplpmtudTransitionDecision {
        let transition = self.reduce(event);
        self.commit(transition)
    }

    pub(crate) fn snapshot(&self, now: Instant, live_worker: bool) -> DplpmtudSnapshot {
        let outstanding_probe = self
            .outstanding
            .map(|outstanding| DplpmtudOutstandingSnapshot {
                sequence: outstanding.identity.sequence,
                candidate_udp_datagram_size: outstanding.identity.candidate_udp_datagram_size.0,
                retry: outstanding.retry,
                scheduled_age_ms: duration_ms(
                    now.saturating_duration_since(outstanding.scheduled_at),
                ),
                sent_age_ms: outstanding
                    .sent_at
                    .map(|sent_at| duration_ms(now.saturating_duration_since(sent_at))),
                deadline_remaining_ms: duration_ms(
                    outstanding.deadline.saturating_duration_since(now),
                ),
            });
        let family = self
            .identity
            .as_ref()
            .map(|identity| identity.outer_ip_family);
        DplpmtudSnapshot {
            state: self.state,
            supported: self.supported,
            path_identity: self.identity.as_ref().map(DplpmtudPathIdentity::summary),
            assumed_base_udp_datagram_size: self.base_udp_datagram_size.0,
            base_confirmed: self.base_confirmed,
            confirmed_udp_datagram_size: self.confirmed_udp_datagram_size.map(|value| value.0),
            search_upper_udp_datagram_size: self.search_upper_udp_datagram_size.0,
            confirmed_outer_ip_packet_size: self
                .confirmed_udp_datagram_size
                .and_then(|size| family.map(|family| size.outer_ip_packet_size(family).0)),
            overlay_payload_budget: self
                .confirmed_udp_datagram_size
                .and_then(UdpDatagramSize::overlay_payload_budget)
                .map(|value| value.0),
            current_plpmtu_confirmation_pending: self.current_plpmtu_confirmation_pending,
            current_plpmtu_confirmation_remaining_ms: self
                .current_plpmtu_confirmation_at
                .map(|at| duration_ms(at.saturating_duration_since(now))),
            outstanding_probe,
            last_success_age_ms: self
                .last_success_at
                .map(|at| duration_ms(now.saturating_duration_since(at))),
            last_timeout_age_ms: self
                .last_timeout_at
                .map(|at| duration_ms(now.saturating_duration_since(at))),
            last_failure_age_ms: self
                .last_failure_at
                .map(|at| duration_ms(now.saturating_duration_since(at))),
            reset_reason: self.last_reset_reason.clone(),
            reset_count: self.reset_count,
            revision: self.revision,
            budget_revision: None,
            probe_count: self.probe_count,
            success_count: self.success_count,
            timeout_count: self.timeout_count,
            send_failure_count: self.send_failure_count,
            transient_send_failure_count: self.transient_send_failure_count,
            emit_lock_unavailable_count: self.emit_lock_unavailable_count,
            session_unavailable_count: self.session_unavailable_count,
            local_packet_too_large_count: self.local_packet_too_large_count,
            business_packet_too_large_count: self.business_packet_too_large_count,
            last_send_failure_kind: self.last_send_failure_kind,
            stale_ack_count: self.stale_ack_count,
            duplicate_ack_count: self.duplicate_ack_count,
            live_worker,
        }
    }
}

fn enter_base_error(next: &mut DplpmtudStateMachine, now: Instant) {
    next.base_confirmed = false;
    next.confirmed_udp_datagram_size = None;
    next.pending_candidate_udp_datagram_size = None;
    next.current_plpmtu_confirmation_pending = false;
    next.current_plpmtu_confirmation_at = None;
    next.state = DplpmtudState::Error;
    next.raise_at = Some(now + DPLPMTUD_ERROR_RETRY_INTERVAL);
}

fn lower_after_failed_search_candidate(
    next: &mut DplpmtudStateMachine,
    confirmed: UdpDatagramSize,
    failed_candidate: UdpDatagramSize,
    now: Instant,
) {
    let failed_upper = failed_candidate
        .0
        .saturating_sub(DPLPMTUD_SEARCH_GRANULARITY)
        .max(confirmed.0);
    next.search_upper_udp_datagram_size =
        UdpDatagramSize(next.search_upper_udp_datagram_size.0.min(failed_upper));
    next.pending_candidate_udp_datagram_size =
        next_search_candidate(confirmed, next.search_upper_udp_datagram_size);
    next.current_plpmtu_confirmation_pending = false;
    next.current_plpmtu_confirmation_at = None;
    if next.pending_candidate_udp_datagram_size.is_none() {
        next.state = DplpmtudState::SearchComplete;
        next.current_plpmtu_confirmation_at =
            Some(now + DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL);
        next.raise_at = Some(now + DPLPMTUD_RAISE_INTERVAL);
    } else {
        next.state = DplpmtudState::Searching;
        next.raise_at = None;
    }
}

fn lower_after_current_confirmation_failure(
    next: &mut DplpmtudStateMachine,
    probe: DplpmtudProbeIdentity,
    _now: Instant,
) {
    let safe_base = next.base_udp_datagram_size;
    next.current_plpmtu_confirmation_pending = false;
    next.current_plpmtu_confirmation_at = None;
    next.search_upper_udp_datagram_size = UdpDatagramSize(
        next.search_upper_udp_datagram_size
            .0
            .min(
                probe
                    .candidate_udp_datagram_size
                    .0
                    .saturating_sub(DPLPMTUD_SEARCH_GRANULARITY),
            )
            .max(safe_base.0),
    );
    // A current-PLPMTU confirmation failure invalidates the historical
    // confirmed value.  BASE is only usable again after a fresh positive
    // BASE ACK; never expose the assumed BASE as a replacement confirmation.
    next.base_confirmed = false;
    next.confirmed_udp_datagram_size = None;
    next.outstanding = None;
    next.pending_candidate_udp_datagram_size = Some(safe_base);
    next.retry_count = 0;
    next.raise_at = None;
    next.state = DplpmtudState::Base;
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn push_consumed_receipt(
    receipts: &mut VecDeque<DplpmtudProbeIdentity>,
    receipt: DplpmtudProbeIdentity,
) {
    if receipts.contains(&receipt) {
        return;
    }
    while receipts.len() >= MAX_CONSUMED_PROBE_RECEIPTS {
        receipts.pop_front();
    }
    receipts.push_back(receipt);
}

fn next_search_candidate(
    confirmed: UdpDatagramSize,
    upper: UdpDatagramSize,
) -> Option<UdpDatagramSize> {
    if upper.0 <= confirmed.0 {
        return None;
    }
    let distance = upper.0 - confirmed.0;
    let midpoint = confirmed.0 + distance / 2;
    let aligned = confirmed.0
        + ((midpoint - confirmed.0) / DPLPMTUD_SEARCH_GRANULARITY) * DPLPMTUD_SEARCH_GRANULARITY;
    let candidate = aligned
        .max(confirmed.0.saturating_add(DPLPMTUD_SEARCH_GRANULARITY))
        .min(upper.0);
    (candidate > confirmed.0).then_some(UdpDatagramSize(candidate))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DplpmtudOutstandingSnapshot {
    pub(crate) sequence: u64,
    pub(crate) candidate_udp_datagram_size: u32,
    pub(crate) retry: u8,
    pub(crate) scheduled_age_ms: u64,
    pub(crate) sent_age_ms: Option<u64>,
    pub(crate) deadline_remaining_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DplpmtudSnapshot {
    pub(crate) state: DplpmtudState,
    pub(crate) supported: bool,
    pub(crate) path_identity: Option<DplpmtudPathIdentitySnapshot>,
    pub(crate) assumed_base_udp_datagram_size: u32,
    pub(crate) base_confirmed: bool,
    pub(crate) confirmed_udp_datagram_size: Option<u32>,
    pub(crate) search_upper_udp_datagram_size: u32,
    pub(crate) confirmed_outer_ip_packet_size: Option<u32>,
    pub(crate) overlay_payload_budget: Option<u32>,
    pub(crate) current_plpmtu_confirmation_pending: bool,
    pub(crate) current_plpmtu_confirmation_remaining_ms: Option<u64>,
    pub(crate) outstanding_probe: Option<DplpmtudOutstandingSnapshot>,
    pub(crate) last_success_age_ms: Option<u64>,
    pub(crate) last_timeout_age_ms: Option<u64>,
    pub(crate) last_failure_age_ms: Option<u64>,
    pub(crate) reset_reason: Option<String>,
    pub(crate) reset_count: u64,
    pub(crate) revision: u64,
    #[serde(default)]
    pub(crate) budget_revision: Option<u64>,
    pub(crate) probe_count: u64,
    pub(crate) success_count: u64,
    pub(crate) timeout_count: u64,
    pub(crate) send_failure_count: u64,
    pub(crate) transient_send_failure_count: u64,
    pub(crate) emit_lock_unavailable_count: u64,
    pub(crate) session_unavailable_count: u64,
    pub(crate) local_packet_too_large_count: u64,
    #[serde(default)]
    pub(crate) business_packet_too_large_count: u64,
    pub(crate) last_send_failure_kind: Option<DplpmtudProbeSendFailure>,
    pub(crate) stale_ack_count: u64,
    pub(crate) duplicate_ack_count: u64,
    pub(crate) live_worker: bool,
}

#[cfg(test)]
#[path = "tests/state_machine.rs"]
mod tests;
