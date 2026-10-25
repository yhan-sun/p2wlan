//! Frozen diagnostic projection. The sole registry still owns all mutable
//! capture facts. This value contains copied fields and immutable plans only;
//! no scope, original owner, native permission or mutable history is retained.
use super::*;

mod buffers;
pub(super) use buffers::SnapshotBuffers;
#[cfg(all(unix, test))]
mod allocation_tests;

pub(super) struct SnapshotCoverage {
    rows: Vec<(usize, Vec<full::ReadFrameSpan>)>,
}

impl SnapshotCoverage {
    pub(super) fn from_rows(rows: Vec<(usize, Vec<full::ReadFrameSpan>)>) -> Self {
        // Membership and spans come from the existing capped 1024-packet
        // histories while the original registry is held. Never re-read a live
        // Full/write/once/owner after its release to fill a missing capture.
        Self { rows }
    }

    fn frame_complete(&self, flow: usize, slot: usize, plan: &RegisteredFlowPlan) -> bool {
        full::spans_complete(
            self.rows
                .iter()
                .filter(|(index, _)| *index == flow)
                .flat_map(|(_, spans)| spans),
            slot,
            plan,
        )
    }
}

pub(super) struct CapturedSnapshot {
    value: ReadSnapshot,
    plans: Vec<Arc<RegisteredFlowPlan>>,
    full: SnapshotCoverage,
    inbound: SnapshotCoverage,
}

impl CapturedSnapshot {
    pub(super) fn finish(mut self) -> ReadSnapshot {
        for request in &mut self.value.requests {
            let plan = &self.plans[request.flow];
            request.historical_frame_full_complete = self.value.original_full_retention_complete
                && !request.flow_invalid
                && self
                    .full
                    .frame_complete(request.flow, request.sequence as usize, plan);
            request.incoming_frame_system_write_complete = !request.incoming_flow_invalid
                && self
                    .inbound
                    .frame_complete(request.flow, request.sequence as usize, plan);
        }
        self.value
    }
}

impl CaptureSession {
    #[cfg(all(unix, test))]
    pub(super) fn capture_snapshot_in(
        &self,
        state: &RegistryState,
    ) -> Result<CapturedSnapshot, CaptureFailure> {
        self.capture_snapshot_with_buffers(state, SnapshotBuffers::prepare())
    }

    pub(super) fn capture_snapshot_with_buffers(
        &self,
        state: &RegistryState,
        buffers: SnapshotBuffers,
    ) -> Result<CapturedSnapshot, CaptureFailure> {
        let SnapshotBuffers {
            mut requests,
            mut plans,
            mut full_coverage,
            inbound_coverage,
            full_packets,
            system_writes,
        } = buffers;
        #[cfg(any(target_os = "linux", all(unix, test)))]
        let mut captured_native_verified = true;
        for (flow_index, flow) in state.flows.iter().enumerate() {
            let plan = &flow.plan;
            for (key, read) in plan.requests.iter().zip(&flow.requests) {
                #[cfg(any(target_os = "linux", all(unix, test)))]
                let native_credit = read.native_credit.as_ref();
                #[cfg(any(target_os = "linux", all(unix, test)))]
                {
                    captured_native_verified &=
                        native_credit.is_some_and(native::NativeFrameOutcome::verified);
                }
                requests.push(RequestSnapshot {
                    #[cfg(any(target_os = "linux", all(unix, test)))]
                    native_credit: native_credit.map(native::NativeFrameOutcome::snapshot),
                    flow: flow_index,
                    producer_scope: flow.producer_scope,
                    sequence: key.sequence,
                    run_nonce: key.run,
                    round_nonce: key.round,
                    request_nonce: key.request_nonce,
                    kind: match key.kind {
                        crate::business_evidence::RequestKind::Request => "request",
                        crate::business_evidence::RequestKind::Response => "response",
                    },
                    protocol: match plan.protocol {
                        Protocol::Udp => "udp",
                        Protocol::Tcp => "tcp",
                    },
                    read_events: read.read_events,
                    first_read_ordinal: read.first_read.as_ref().map(|read| read.ordinal()),
                    last_read_ordinal: read.last_read.as_ref().map(|read| read.ordinal()),
                    first_read_monotonic_ns: read
                        .first_read
                        .as_ref()
                        .map(|read| read.monotonic_ns()),
                    last_read_monotonic_ns: read.last_read.as_ref().map(|read| read.monotonic_ns()),
                    kernel_frame_read_complete: !flow.invalid.load(Ordering::Acquire)
                        && (read.udp_complete
                            || read.tcp.as_ref().is_some_and(|tcp| tcp.is_complete())),
                    flow_invalid: flow.invalid.load(Ordering::Acquire),
                    // Only frozen original history is interpreted after release.
                    historical_frame_full_complete: false,
                    incoming_frame_system_write_complete: false,
                    incoming_flow_invalid: flow.inbound.invalid.load(Ordering::Acquire),
                    original_peer: read.first_peer.as_ref().map(|peer| peer.snapshot()),
                    original_request_room: read
                        .first_request_room
                        .as_ref()
                        .map(|room| room.snapshot()),
                    original_response_input: read
                        .first_response
                        .as_ref()
                        .map(|input| input.snapshot()),
                    #[cfg(any(target_os = "linux", all(unix, test)))]
                    original_write_window: read.original_write_window.as_ref().cloned(),
                });
            }
        }
        #[cfg(any(target_os = "linux", all(unix, test)))]
        let native_verified = state.requests != 0
            && self.read_complete.load(Ordering::Acquire)
            && self.inbound_complete.load(Ordering::Acquire)
            && self.full_complete.load(Ordering::Acquire)
            && state.flows.iter().all(|flow| {
                !flow.invalid.load(Ordering::Acquire)
                    && !flow.inbound.invalid.load(Ordering::Acquire)
            })
            && captured_native_verified;
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        let native_verified = false;
        plans.extend(state.flows.iter().map(|flow| flow.plan.clone()));
        full_coverage.extend(
            state
                .read_history
                .iter()
                .filter(|read| read.full_observed_ns().is_some())
                .map(|read| (read.flow, read.spans.clone())),
        );
        // Freeze one immutable Full-write prefix after copying native rows.
        // A published entry already contains its original write; later
        // appends cannot change either coverage or the serialized history.
        let inbound_prefix = state.inbound_history.published_len();
        Ok(CapturedSnapshot {
            plans,
            full: SnapshotCoverage::from_rows(full_coverage),
            inbound: state
                .inbound_history
                .snapshot_coverage(inbound_prefix, inbound_coverage),
            value: ReadSnapshot {
                schema_version: 2,
                scope: "registered_native_frame_capture",
                owner: self.owner,
                capture_id: self.capture_id,
                producer_scope: self.producer_scope,
                clock_scope: self.clock_scope.clone(),
                observed_monotonic_ns: monotonic_ns(),
                registration_revision: state.revision,
                total_registered_requests: state.requests,
                registration_sets: state.producers.len(),
                active: self.is_live(Instant::now()),
                gaps: self.gaps.load(Ordering::Relaxed),
                requests,
                historical_full_packets: full::snapshot(&state.read_history, full_packets),
                system_tun_full_writes: state
                    .inbound_history
                    .snapshot(inbound_prefix, system_writes),
                // Registration alone leaves these false. Only the sole native
                // current-owner/once transaction can make every frame verified;
                // original application OS-write qualification stays separate.
                daemon_registration_verified: native_verified,
                physical_send_verified: native_verified,
                canonical_current_owner_verified: native_verified,
                incoming_provenance_complete: self.inbound_complete.load(Ordering::Acquire),
                original_read_observation_complete: self.read_complete.load(Ordering::Acquire),
                first_original_read_loss: self.read_loss.snapshot(),
                original_read_registry_refusal: self.state.original_read_refusal_snapshot(),
                original_full_retention_complete: self.full_complete.load(Ordering::Acquire),
                first_original_full_retention_loss: self.full_loss.snapshot(),
                first_original_inbound_loss: self.inbound_loss.snapshot(),
                retained_original_reads: state.read_history.len(),
                original_input_registry_refusal: self.state.input_refusal_snapshot(),
                original_authenticated_input_registry_refusal: self
                    .state
                    .authenticated_refusal_snapshot(),
                original_system_write_registry_refusal: self
                    .system_write_state
                    .system_write_refusal_snapshot(),
                #[cfg(any(target_os = "linux", all(unix, test)))]
                original_kernel_epoch_refusal: self.epoch_trace.snapshot(),
                #[cfg(any(target_os = "linux", all(unix, test)))]
                original_read_peer_epoch_refusal: self.epoch_trace.read_peer_snapshot(),
                #[cfg(any(target_os = "linux", all(unix, test)))]
                original_kernel_emit_refusal: self.emit_trace.snapshot(),
            },
        })
    }
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn snapshot_projection_frozen_registration_and_negative_never_refill() {
        let (setup, _parent) = super::super::snapshot_projection_tests::scope().await;
        setup
            .session
            .original_full_retention_lost(FullRetentionLossReason::InputRegistryContended);
        let state = setup.session.state.try_lock().unwrap();
        let captured = setup.session.capture_snapshot_in(&state).unwrap();
        drop(state);
        let document = json!({"schema_version":1,"capture_id":"11".repeat(16),
            "producer_scope":"89".repeat(16),"flows":[{
                "protocol":"udp","kind":"request","peer_id":"later-snapshot-peer",
                "run_nonce":"91".repeat(16),"round_nonce":"92".repeat(16),
                "bind_ip":"10.21.1.2","bind_port":32124,"target_ip":"10.21.1.4","target_port":43211,
                "payload_bytes":128,"request_nonces":["93".repeat(16)]}]});
        setup
            .session
            .register(RegistrationPlan::decode(&serde_json::to_vec(&document).unwrap()).unwrap())
            .unwrap();
        setup
            .session
            .original_full_retention_lost(FullRetentionLossReason::PeerEncryptionMismatch);
        let held = setup.session.state.try_lock().unwrap();
        // Finish and serialize with the actual registry held: no owner, live
        // membership, new failure or publication can be sampled at this point.
        let value = serde_json::to_value(captured.finish()).unwrap();
        assert_eq!(value["requests"].as_array().unwrap().len(), 1);
        assert_eq!(value["total_registered_requests"], 1);
        assert_eq!(value["registration_revision"], 1);
        assert_eq!(value["registration_sets"], 1);
        assert_eq!(value["gaps"], 1);
        assert_eq!(
            value["first_original_full_retention_loss"],
            "input_registry_contended"
        );
        assert_eq!(value["original_full_retention_complete"], false);
        assert_eq!(value["physical_send_verified"], false);
        assert_eq!(
            value["requests"][0]["native_credit"],
            serde_json::Value::Null
        );
        drop(held);
        let later = serde_json::to_value(setup.session.snapshot().unwrap()).unwrap();
        assert_eq!(later["total_registered_requests"], 2);
        assert_eq!(later["registration_revision"], 2);
        assert_eq!(later["gaps"], 2);
    }

    #[tokio::test]
    async fn snapshot_projection_frozen_bytes_do_not_keep_scope_or_descriptor_alive() {
        let (setup, parent) = super::super::snapshot_projection_tests::scope().await;
        let state = setup.session.state.try_lock().unwrap();
        let captured = setup.session.capture_snapshot_in(&state).unwrap();
        let weak = Arc::downgrade(&setup.session);
        drop(state);
        drop(setup);
        drop(parent);
        assert!(weak.upgrade().is_none());
        let value = serde_json::to_value(captured.finish()).unwrap();
        assert_eq!(value["requests"].as_array().unwrap().len(), 1);
        assert_eq!(value["historical_full_packets"], json!([]));
        assert_eq!(value["system_tun_full_writes"], json!([]));
        assert_eq!(value["physical_send_verified"], false);
        assert_eq!(value["canonical_current_owner_verified"], false);
    }
}
