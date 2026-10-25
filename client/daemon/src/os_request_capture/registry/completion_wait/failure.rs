//! First failed wait metadata, before the original actor retires its scope.
//! No retry, later reply, renewed deadline or native outcome is produced.
use super::super::{control_lock, full, CaptureFailure, CaptureSession, FullRetentionLossReason};
use super::TerminalMetadataReceipt;
use serde::Serialize;
use std::sync::atomic::Ordering;
use std::sync::{Arc, TryLockError};
use std::time::Instant;

const MAX_FAILURE_BYTES: usize = 16 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum Observation {
    Observed,
    RegistryContended,
    RegistryPoisoned,
    FlowUnavailable,
    InvalidFixedEight,
    AllocationUnavailable,
}

#[derive(Serialize)]
struct Row {
    sequence: u32,
    request_nonce: String,
    run_nonce: String,
    round_nonce: String,
    read_events: u64,
    first_read_ordinal: Option<u64>,
    terminal_outcome_recorded: bool,
    original_write_window_received: bool,
    kernel_frame_read_complete: bool,
    historical_frame_full_complete: bool,
    incoming_frame_system_write_complete: bool,
    flow_invalid: bool,
    incoming_flow_invalid: bool,
}

#[derive(Serialize)]
pub(in crate::os_request_capture::registry) struct FailureMetadata {
    scope: &'static str,
    owner: u64,
    capture_id: String,
    producer_scope: String,
    failure: String,
    original_deadline_ns: u64,
    observed_monotonic_ns: Option<u64>,
    observation: Observation,
    capture_active: bool,
    original_read_observation_complete: bool,
    original_full_retention_complete: bool,
    incoming_provenance_complete: bool,
    first_original_full_retention_loss: Option<FullRetentionLossReason>,
    first_original_inbound_loss: Option<super::super::inbound_loss::InboundLossSnapshot>,
    original_input_registry_refusal: Option<control_lock::InputRefusalSnapshot>,
    original_authenticated_input_registry_refusal:
        Option<control_lock::AuthenticatedRefusalSnapshot>,
    original_system_write_registry_refusal: Option<control_lock::SystemWriteRefusalSnapshot>,
    original_kernel_epoch_refusal: Option<crate::peer::EpochRefusalSnapshot>,
    original_read_peer_epoch_refusal: Option<crate::peer::EpochRefusalSnapshot>,
    original_kernel_emit_refusal: Option<crate::transport::EmitRefusalSnapshot>,
    observations_are_sequential_not_atomic: bool,
    requests: Vec<Row>,
    native_os_write_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
}

impl FailureMetadata {
    pub(in crate::os_request_capture::registry) fn encoded(&self) -> Option<Vec<u8>> {
        serde_json::to_vec(self)
            .ok()
            .filter(|raw| raw.len() <= MAX_FAILURE_BYTES)
    }
}

impl CaptureSession {
    pub(in crate::os_request_capture) async fn wait_original_outcomes_observed(
        self: &Arc<Self>,
        producer: [u8; 16],
        end: tokio::time::Instant,
        original_deadline_ns: u64,
    ) -> Result<TerminalMetadataReceipt, CaptureFailure> {
        let result = self.wait_original_outcomes(producer, end).await;
        if let Err(failure) = &result {
            // The original wait has ended. One try-only metadata observation
            // precedes the unchanged error/retirement. Serialization and the
            // existing logger run only after that guard has been released.
            let metadata = self.terminal_failure_metadata(producer, original_deadline_ns, failure);
            if let Some(raw) = metadata.encoded() {
                tracing::warn!(
                    original_terminal_failure = %String::from_utf8_lossy(&raw),
                    "original terminal wait failed; metadata only"
                );
            } else {
                tracing::warn!(
                    scope = "original_terminal_wait_failure_metadata_only",
                    reason = "encoding_or_capacity_unavailable",
                    native_os_write_verified = false,
                    physical_send_verified = false,
                    canonical_current_owner_verified = false,
                    "original terminal wait failed; metadata unavailable"
                );
            }
        }
        result
    }

    pub(in crate::os_request_capture::registry) fn terminal_failure_metadata(
        &self,
        producer: [u8; 16],
        original_deadline_ns: u64,
        failure: &CaptureFailure,
    ) -> FailureMetadata {
        let mut metadata = FailureMetadata {
            scope: "original_terminal_wait_failure_metadata_only",
            owner: self.owner,
            capture_id: hex::encode(self.capture_id),
            producer_scope: hex::encode(producer),
            failure: format!("{failure:?}"),
            original_deadline_ns,
            observed_monotonic_ns: crate::os_request_capture::original_kernel_monotonic_ns(),
            observation: Observation::FlowUnavailable,
            capture_active: self.is_live(Instant::now()),
            original_read_observation_complete: self.read_complete.load(Ordering::Acquire),
            original_full_retention_complete: self.full_complete.load(Ordering::Acquire),
            incoming_provenance_complete: self.inbound_complete.load(Ordering::Acquire),
            first_original_full_retention_loss: self.full_loss.snapshot(),
            first_original_inbound_loss: self.inbound_loss.snapshot(),
            original_input_registry_refusal: self.state.input_refusal_snapshot(),
            original_authenticated_input_registry_refusal: self
                .state
                .authenticated_refusal_snapshot(),
            original_system_write_registry_refusal: self
                .system_write_state
                .system_write_refusal_snapshot(),
            original_kernel_epoch_refusal: self.epoch_trace.snapshot(),
            original_read_peer_epoch_refusal: self.epoch_trace.read_peer_snapshot(),
            original_kernel_emit_refusal: self.emit_trace.snapshot(),
            observations_are_sequential_not_atomic: true,
            requests: Vec::new(),
            native_os_write_verified: false,
            physical_send_verified: false,
            canonical_current_owner_verified: false,
        };
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => {
                metadata.observation = Observation::RegistryContended;
                return metadata;
            }
            Err(TryLockError::Poisoned(_)) => {
                metadata.observation = Observation::RegistryPoisoned;
                return metadata;
            }
        };
        let mut matches = state
            .flows
            .iter()
            .enumerate()
            .filter(|(_, flow)| flow.producer_scope == producer);
        let Some((index, flow)) = matches.next() else {
            return metadata;
        };
        if matches.next().is_some() || flow.requests.len() != 8 || flow.plan.requests.len() != 8 {
            metadata.observation = Observation::InvalidFixedEight;
            return metadata;
        }
        if metadata.requests.try_reserve(8).is_err() {
            metadata.observation = Observation::AllocationUnavailable;
            return metadata;
        }
        for (slot, (key, row)) in flow.plan.requests.iter().zip(&flow.requests).enumerate() {
            metadata.requests.push(Row {
                sequence: key.sequence,
                request_nonce: hex::encode(key.request_nonce),
                run_nonce: hex::encode(key.run),
                round_nonce: hex::encode(key.round),
                read_events: row.read_events,
                first_read_ordinal: row.first_read.as_ref().map(|read| read.ordinal()),
                terminal_outcome_recorded: row.native_credit.is_some(),
                original_write_window_received: row.original_write_window.is_some(),
                kernel_frame_read_complete: !flow.invalid.load(Ordering::Acquire)
                    && (row.udp_complete || row.tcp.as_ref().is_some_and(|tcp| tcp.is_complete())),
                historical_frame_full_complete: !flow.invalid.load(Ordering::Acquire)
                    && self.full_complete.load(Ordering::Acquire)
                    && full::frame_complete(&state.read_history, index, slot, &flow.plan),
                incoming_frame_system_write_complete: !flow.inbound.invalid.load(Ordering::Acquire)
                    && state
                        .inbound_history
                        .frame_complete(index, slot, &flow.plan),
                flow_invalid: flow.invalid.load(Ordering::Acquire),
                incoming_flow_invalid: flow.inbound.invalid.load(Ordering::Acquire),
            });
        }
        metadata.observation = Observation::Observed;
        metadata
    }
}
