/// Fixed counters for completed classified ordinary fresh-mapping calls.
/// These are not recovery budget debits or future retransmission costs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FreshMappingProbeFailureCounts {
    pub(crate) physical_send: u64,
    pub(crate) pre_handoff_timeout: u64,
    pub(crate) network_generation_changed: u64,
    pub(crate) candidate_epoch_changed: u64,
    pub(crate) local_profile_generation_changed: u64,
    pub(crate) remote_profile_generation_changed: u64,
    pub(crate) peer_session_changed: u64,
    pub(crate) session_retired: u64,
    pub(crate) socket_unavailable: u64,
    pub(crate) socket_revoked: u64,
    pub(crate) probe_registration_failed: u64,
    pub(crate) probe_encoding_failed: u64,
}

/// An outer loop stop is separate from a classified send returning `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FreshMappingProbeStopCause {
    Cancelled,
    DirectConfirmed,
    NetworkGenerationChanged,
}

impl FreshMappingProbeStopCause {
    const fn label(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::DirectConfirmed => "direct_confirmed",
            Self::NetworkGenerationChanged => "network_generation_changed",
        }
    }
}

/// Local, fixed-size completed-call summary. It creates no send authority.
/// Successful primary count has the same saturating-u32 semantics as `sent`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct FreshMappingProbeSummary {
    pub(crate) logical_calls_attempted: u64,
    pub(crate) successful_primary_sends: u32,
    pub(crate) first_failure: Option<ProbeSendFailureKind>,
    pub(crate) failures: FreshMappingProbeFailureCounts,
    pub(crate) physical_send_errors: u64,
    pub(crate) physical_send_error_bytes: u64,
    pub(crate) outer_stop: Option<FreshMappingProbeStopCause>,
    /// Saturated counters are lower bounds, not claimed exact totals.
    pub(crate) counters_saturated: bool,
}

fn add_fresh_mapping_probe_counter(counter: &mut u64, delta: u64, saturated: &mut bool) {
    match counter.checked_add(delta) {
        Some(value) => *counter = value,
        None => {
            *counter = u64::MAX;
            *saturated = true;
        }
    }
}

impl FreshMappingProbeSummary {
    fn record_call(&mut self) {
        add_fresh_mapping_probe_counter(
            &mut self.logical_calls_attempted,
            1,
            &mut self.counters_saturated,
        );
    }

    fn record_failure(&mut self, failure: &ProbeSendFailure) {
        self.first_failure.get_or_insert(failure.kind);
        let count = match failure.kind {
            ProbeSendFailureKind::PhysicalSend => &mut self.failures.physical_send,
            ProbeSendFailureKind::PreHandoffTimeout => &mut self.failures.pre_handoff_timeout,
            ProbeSendFailureKind::NetworkGenerationChanged => {
                &mut self.failures.network_generation_changed
            }
            ProbeSendFailureKind::CandidateEpochChanged => {
                &mut self.failures.candidate_epoch_changed
            }
            ProbeSendFailureKind::LocalProfileGenerationChanged => {
                &mut self.failures.local_profile_generation_changed
            }
            ProbeSendFailureKind::RemoteProfileGenerationChanged => {
                &mut self.failures.remote_profile_generation_changed
            }
            ProbeSendFailureKind::PeerSessionChanged => &mut self.failures.peer_session_changed,
            ProbeSendFailureKind::SessionRetired => &mut self.failures.session_retired,
            ProbeSendFailureKind::SocketUnavailable => &mut self.failures.socket_unavailable,
            ProbeSendFailureKind::SocketRevoked => &mut self.failures.socket_revoked,
            ProbeSendFailureKind::ProbeRegistrationFailed => {
                &mut self.failures.probe_registration_failed
            }
            ProbeSendFailureKind::ProbeEncodingFailed => &mut self.failures.probe_encoding_failed,
        };
        add_fresh_mapping_probe_counter(count, 1, &mut self.counters_saturated);
        self.record_physical_error_cost(
            failure.physical_send_errors,
            failure.physical_send_error_bytes,
        );
    }

    fn record_success(&mut self, result: &ProbeSendResult) {
        match self.successful_primary_sends.checked_add(1) {
            Some(value) => self.successful_primary_sends = value,
            None => self.counters_saturated = true,
        }
        // An accepted primary may coexist with a failed compatibility copy.
        // It remains one successful primary, regardless of datagrams_sent.
        self.record_physical_error_cost(
            result.physical_send_errors,
            result.physical_send_error_bytes,
        );
    }

    fn record_physical_error_cost(&mut self, errors: u8, bytes: u64) {
        add_fresh_mapping_probe_counter(
            &mut self.physical_send_errors,
            u64::from(errors),
            &mut self.counters_saturated,
        );
        add_fresh_mapping_probe_counter(
            &mut self.physical_send_error_bytes,
            bytes,
            &mut self.counters_saturated,
        );
    }

    fn record_outer_stop(&mut self, stop: FreshMappingProbeStopCause) {
        self.outer_stop.get_or_insert(stop);
    }

    fn diagnostic_fields(&self) -> String {
        format!(
            "first_failure={} logical_calls_attempted={} successful_primary_sends={} physical_send_errors={} physical_send_error_bytes={} outer_stop={} counters_saturated={}",
            self.first_failure.map_or("none", ProbeSendFailureKind::label),
            self.logical_calls_attempted,
            self.successful_primary_sends,
            self.physical_send_errors,
            self.physical_send_error_bytes,
            self.outer_stop.map_or("none", FreshMappingProbeStopCause::label),
            self.counters_saturated,
        )
    }
}
