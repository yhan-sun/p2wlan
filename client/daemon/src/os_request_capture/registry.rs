#[cfg(unix)]
use super::clock::{monotonic_ns, NativeClockScope};
use super::device::{DeviceLease, KernelRead};
use super::plan::{CaptureFailure, Protocol, RegisteredFlowPlan, MAX_BINDINGS_PER_PACKET};
#[cfg(any(target_os = "linux", all(unix, test)))]
use super::plan::{RegistrationPlan, CAPTURE_TTL_SECS, MAX_REQUESTS};
use crate::business_evidence::parse_os_udp;
use crate::business_evidence::tcp_frame::{
    parse_tcp_segment, TcpCoverageResult, TcpFrameCoverage, TcpFrameKey, TcpFramePlan,
};
use crate::dataplane::OutboundPacket;
use crate::peer::PeerManager;
#[cfg(unix)]
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Weak};
#[cfg(any(target_os = "linux", all(unix, test)))]
use std::time::Duration;
use std::time::Instant;

mod binding_rejection;
mod published;
use published::{First, Published};
#[cfg(unix)]
mod control_lock;
mod full;
#[cfg(any(target_os = "linux", all(unix, test)))]
mod full_completion;
mod full_loss;
mod inbound_loss;
#[cfg(any(target_os = "linux", all(unix, test)))]
mod registration;
#[cfg(all(unix, test))]
mod registration_tests;
#[cfg(unix)]
mod snapshot;
#[cfg(unix)]
mod snapshot_hex;
#[cfg(all(unix, test))]
mod snapshot_projection_tests;
#[cfg(unix)]
use control_lock::ControlState as RegistryMutex;
use full_loss::FullRetentionLoss;
pub(crate) use full_loss::FullRetentionLossReason;
#[cfg(not(unix))]
use std::sync::Mutex as RegistryMutex;
#[cfg(any(target_os = "linux", all(unix, test)))]
mod completion_wait;
#[cfg(any(target_os = "linux", all(unix, test)))]
mod native;
mod owners;
pub(crate) use full::OriginalFullObservation;
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) use native::{OriginalKernelExchange, OriginalKernelOnce};
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(crate) use owners::OriginalKernelCurrentOwners;
mod ingress;
#[cfg(unix)]
mod read_loss;
mod read_packet;
mod read_peer;
mod read_retention_input;
mod read_room;
#[cfg(any(target_os = "linux", all(unix, test)))]
pub(super) mod write_window;
pub(crate) use ingress::{KernelCaptureRuntime, KernelIngressBinding};

#[cfg(any(target_os = "linux", all(unix, test)))]
static NEXT_SCOPE: AtomicU64 = AtomicU64::new(1);

pub(crate) struct CaptureSession {
    #[cfg(unix)]
    owner: u64,
    active: Arc<AtomicBool>,
    inbound_complete: AtomicBool,
    read_complete: AtomicBool,
    #[cfg(unix)]
    read_loss: read_loss::ReadLoss,
    full_complete: AtomicBool,
    full_loss: FullRetentionLoss,
    inbound_loss: inbound_loss::InboundLoss,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pending_full: full_completion::CompletionSignal,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    native_completion: native::completion_gate::NativeCompletionGate,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    native_terminal_revision: AtomicU64,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    epoch_trace: crate::peer::EpochTraceLease,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    emit_trace: Arc<crate::transport::EmitTrace>,
    expires: Instant,
    peers: Weak<PeerManager>,
    #[cfg(unix)]
    capture_id: [u8; 16],
    #[cfg(unix)]
    producer_scope: [u8; 16],
    #[cfg(unix)]
    clock_scope: Option<NativeClockScope>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    sources: native::source_index::SourceIndex,
    state: RegistryMutex<RegistryState>,
    gaps: AtomicU64,
}

struct RegistryState {
    current_owners: First<Arc<owners::OriginalKernelOwners>>,
    original_room_owner: Option<Weak<crate::rooms::RoomAuthorization>>,
    flows: Vec<FlowState>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    native_flows: Published<Arc<native::source_index::FlowSources>>,
    original_device: Option<Arc<KernelRead>>,
    system_device: First<Weak<DeviceLease>>,
    // Actual original read order includes unresolved and failed publications.
    // A later duplicate Full cannot replace an earlier uncertain producer.
    read_history: Published<Arc<KernelReadBinding>>,
    inbound_history: ingress::InboundHistory,
    #[cfg(unix)]
    requests: usize,
    #[cfg(unix)]
    revision: u64,
    #[cfg(unix)]
    producers: std::collections::HashSet<[u8; 16]>,
}
struct FlowState {
    plan: Arc<RegisteredFlowPlan>,
    #[cfg(unix)]
    producer_scope: [u8; 16],
    tcp_open: Option<u32>,
    invalid: Arc<AtomicBool>,
    requests: Vec<RequestReadState>,
    inbound: ingress::InboundFlow,
}
struct RequestReadState {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    native_credit: native::completion::NativeFrameSlot,
    first_request_room: Option<Arc<ingress::OriginalIncomingRoom>>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    original_write_window: First<write_window::WriteWindow>,
    first_peer: First<Arc<read_peer::FirstReadPeer>>,
    first_response: First<Arc<ingress::ResponseCapture>>,
    read_events: u64,
    first_read: Option<Arc<KernelRead>>,
    last_read: Option<Arc<KernelRead>>,
    tcp: Option<TcpFrameCoverage>,
    udp_complete: bool,
}

/// Private fields and no deserializer: registration JSON and arbitrary Any
/// values cannot construct this type. Arc clones retain the same observation;
/// device and scope owners remain weak, including after queue/crypto handoff.
pub(crate) struct KernelReadBinding {
    scope: Weak<CaptureSession>,
    read: Arc<KernelRead>,
    flow: usize,
    slots: Vec<usize>,
    packet_len: usize,
    packet_sha256: [u8; 32],
    plan: Arc<RegisteredFlowPlan>,
    spans: Vec<full::ReadFrameSpan>,
    physical_publication: crate::overlay_requests::PhysicalSendPublication,
    full_retained_ns: AtomicU64,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    full_completion_pending: AtomicBool,
    original_publication_ns: OnceLock<u64>,
    original_peers: Vec<Arc<read_peer::FirstReadPeer>>,
    original_responses: Vec<Arc<ingress::ResponseCapture>>,
    original_request_rooms: Vec<Arc<ingress::OriginalIncomingRoom>>,
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct ReadSnapshot {
    pub(super) schema_version: u8,
    scope: &'static str,
    owner: u64,
    #[serde(serialize_with = "snapshot_hex::serialize")]
    capture_id: [u8; 16],
    #[serde(serialize_with = "snapshot_hex::serialize")]
    producer_scope: [u8; 16],
    clock_scope: Option<NativeClockScope>,
    observed_monotonic_ns: Option<u64>,
    registration_revision: u64,
    total_registered_requests: usize,
    registration_sets: usize,
    active: bool,
    gaps: u64,
    requests: Vec<RequestSnapshot>,
    historical_full_packets: Vec<full::FullPacketSnapshot>,
    system_tun_full_writes: Vec<ingress::WriteSnapshot>,
    daemon_registration_verified: bool,
    physical_send_verified: bool,
    canonical_current_owner_verified: bool,
    incoming_provenance_complete: bool,
    original_read_observation_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_original_read_loss: Option<read_loss::ReadLossSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_read_registry_refusal: Option<control_lock::OriginalReadRefusalSnapshot>,
    original_full_retention_complete: bool,
    first_original_full_retention_loss: Option<FullRetentionLossReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_original_inbound_loss: Option<inbound_loss::InboundLossSnapshot>,
    retained_original_reads: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_input_registry_refusal: Option<control_lock::InputRefusalSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_authenticated_input_registry_refusal:
        Option<control_lock::AuthenticatedRefusalSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_system_write_registry_refusal: Option<control_lock::SystemWriteRefusalSnapshot>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    original_kernel_epoch_refusal: Option<crate::peer::EpochRefusalSnapshot>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    original_read_peer_epoch_refusal: Option<crate::peer::EpochRefusalSnapshot>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    #[serde(skip_serializing_if = "Option::is_none")]
    original_kernel_emit_refusal: Option<crate::transport::EmitRefusalSnapshot>,
}
#[cfg(unix)]
#[derive(Serialize)]
struct RequestSnapshot {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    native_credit: Option<native::NativeFrameSnapshot>,
    flow: usize,
    #[serde(serialize_with = "snapshot_hex::serialize")]
    producer_scope: [u8; 16],
    sequence: u32,
    #[serde(serialize_with = "snapshot_hex::serialize")]
    run_nonce: [u8; 16],
    #[serde(serialize_with = "snapshot_hex::serialize")]
    round_nonce: [u8; 16],
    #[serde(serialize_with = "snapshot_hex::serialize")]
    request_nonce: [u8; 16],
    kind: &'static str,
    protocol: &'static str,
    read_events: u64,
    first_read_ordinal: Option<u64>,
    last_read_ordinal: Option<u64>,
    first_read_monotonic_ns: Option<u64>,
    last_read_monotonic_ns: Option<u64>,
    kernel_frame_read_complete: bool,
    flow_invalid: bool,
    historical_frame_full_complete: bool,
    incoming_frame_system_write_complete: bool,
    incoming_flow_invalid: bool,
    original_peer: Option<read_peer::ReadPeerSnapshot>,
    original_request_room: Option<read_room::ReadRoomSnapshot>,
    original_response_input: Option<ingress::ResponseSnapshot>,
    #[cfg(any(target_os = "linux", all(unix, test)))]
    original_write_window: Option<write_window::WriteWindow>,
}

#[cfg(any(target_os = "linux", all(unix, test)))]
#[derive(Serialize)]
pub(super) struct RegistrationReceipt {
    scope: &'static str,
    owner: u64,
    capture_id: String,
    producer_scope: String,
    registration_revision: u64,
    added_requests: usize,
    total_requests: usize,
}

impl CaptureSession {
    // Only the control module calls this after adopting its actual connected
    // descriptor. The plan itself remains labels, never a system read proof.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn from_control_descriptor(
        plan: RegistrationPlan,
        peers: &Arc<PeerManager>,
    ) -> Result<Arc<Self>, CaptureFailure> {
        let owner = NEXT_SCOPE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| CaptureFailure::CounterExhausted)?;
        let expires = Instant::now()
            .checked_add(Duration::from_secs(CAPTURE_TTL_SECS))
            .ok_or(CaptureFailure::Capacity)?;
        let current_owners = First::new();
        let system_device = First::new();
        let read_history = Published::new(full::MAX_FULL_PACKETS)?;
        let inbound_history = ingress::InboundHistory::new()?;
        let native_flows = Published::new(MAX_REQUESTS)?;
        let sources = native::source_index::SourceIndex::new(
            native_flows.clone(),
            read_history.clone(),
            inbound_history.writes.clone(),
            system_device.clone(),
            current_owners.clone(),
        );
        // All possible flow slots are reserved before this scope is exposed.
        let flows = registration::flow_storage()?;
        let session = Arc::new(Self {
            owner,
            active: Arc::new(AtomicBool::new(true)),
            inbound_complete: AtomicBool::new(true),
            read_complete: AtomicBool::new(true),
            #[cfg(unix)]
            read_loss: read_loss::ReadLoss::new(),
            full_complete: AtomicBool::new(true),
            full_loss: FullRetentionLoss::new(),
            inbound_loss: inbound_loss::InboundLoss::new(),
            pending_full: full_completion::CompletionSignal::new(),
            native_completion: native::completion_gate::NativeCompletionGate::new(),
            native_terminal_revision: AtomicU64::new(0),
            epoch_trace: peers.network_epoch_gate().capture_diagnostics(
                owner,
                plan.capture_id,
                expires,
            ),
            emit_trace: crate::transport::EmitTrace::new(owner, plan.capture_id, expires),
            expires,
            peers: Arc::downgrade(peers),
            capture_id: plan.capture_id,
            producer_scope: plan.producer_scope,
            clock_scope: NativeClockScope::capture(),
            sources,
            state: RegistryMutex::new(RegistryState {
                current_owners,
                original_room_owner: None,
                flows,
                native_flows,
                original_device: None,
                system_device,
                read_history,
                inbound_history,
                requests: 0,
                revision: 0,
                producers: registration::producer_membership()?,
            }),
            gaps: AtomicU64::new(0),
        });
        if !plan.flows.is_empty() {
            session.register(plan)?;
        }
        peers.register_original_kernel_read_observer(Arc::downgrade(&session.active), expires);
        Ok(session)
    }

    /// Prepare immutable labels before entering the sole registration writer.
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn register(
        &self,
        plan: RegistrationPlan,
    ) -> Result<RegistrationReceipt, CaptureFailure> {
        let mut prepared = registration::PreparedRegistration::new(plan, self);
        let mut state = self
            .state
            .try_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        let result = prepared.append(self, &mut state);
        drop(state);
        result
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) async fn register_control(
        &self,
        plan: RegistrationPlan,
        end: tokio::time::Instant,
    ) -> Result<RegistrationReceipt, CaptureFailure> {
        let mut prepared = registration::PreparedRegistration::new(plan, self);
        let mut state = self.state.lock_until(end).await?;
        let result = prepared.append(self, &mut state);
        drop(state);
        result
    }

    pub(crate) fn retire(&self) {
        self.active.store(false, Ordering::Release);
        #[cfg(any(target_os = "linux", all(unix, test)))]
        self.epoch_trace.deactivate();
        #[cfg(any(target_os = "linux", all(unix, test)))]
        self.emit_trace.deactivate();
    }

    pub(super) fn bind_system_device(&self, device: &Arc<DeviceLease>) -> bool {
        let Ok(mut state) = self.state.try_lock() else {
            self.gap();
            return false;
        };
        if state.system_device.is_some() || !self.is_live(Instant::now()) {
            self.gap();
            return false;
        }
        if state.system_device.set(Arc::downgrade(device)).is_err() {
            self.gap();
            return false;
        }
        true
    }
    #[cfg(unix)]
    pub(super) fn expires(&self) -> Instant {
        self.expires
    }
    fn is_live(&self, at: Instant) -> bool {
        self.active.load(Ordering::Acquire) && at < self.expires
    }
    fn gap(&self) {
        // No retry/lock: saturated diagnostic coverage never wraps or grants
        // evidence, and can never stop the original packet's forwarding.
        let _ = self
            .gaps
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1));
    }

    pub(super) fn observe_system_read(
        self: &Arc<Self>,
        original: KernelRead,
        packet: &[u8],
    ) -> Option<Arc<KernelReadBinding>> {
        if !original.is_current()
            || !self.is_live(original.at())
            || !self.read_complete.load(Ordering::Acquire)
        {
            return None;
        }
        #[cfg(unix)]
        let ordinal = original.ordinal();
        match self.capture_read(original, packet) {
            Ok(binding) => binding,
            Err(_error) => {
                #[cfg(unix)]
                self.read_loss.record(ordinal, _error);
                // A lost original read cannot be replaced by a later copy
                // sampled under a newer peer lifecycle or network generation.
                self.original_observation_lost(&self.read_complete);
                None
            }
        }
    }

    pub(super) fn original_observation_lost(&self, complete: &AtomicBool) {
        #[cfg(any(target_os = "linux", all(unix, test)))]
        let first_loss = complete.swap(false, Ordering::AcqRel);
        #[cfg(not(any(target_os = "linux", all(unix, test))))]
        complete.store(false, Ordering::Release);
        self.gap();
        #[cfg(any(target_os = "linux", all(unix, test)))]
        if first_loss {
            // Only the first irreversible transition of each sole provenance
            // flag wakes the existing actor. No Full marker/fact is invented.
            self.wake_original_terminal_loss();
        }
    }

    fn capture_read(
        self: &Arc<Self>,
        original: KernelRead,
        packet: &[u8],
    ) -> Result<Option<Arc<KernelReadBinding>>, CaptureFailure> {
        read_packet::capture(packet, |udp, tcp| {
            let packet_sha256: [u8; 32] = Sha256::digest(packet).into();
            #[cfg(unix)]
            let state = self.state.try_original_read_lock(original.ordinal());
            #[cfg(not(unix))]
            let state = self.state.try_lock();
            let mut state = state.map_err(|_| CaptureFailure::Contended)?;
            if state
                .system_device
                .as_ref()
                .is_none_or(|device| !original.belongs_to(device))
            {
                return Err(CaptureFailure::ForeignDevice);
            }
            let Some(index) = state
                .flows
                .iter()
                .position(|flow| match flow.plan.protocol {
                    Protocol::Udp => udp
                        .as_ref()
                        .is_some_and(|parsed| parsed.flow == flow.plan.flow),
                    Protocol::Tcp => tcp
                        .as_ref()
                        .is_some_and(|parsed| parsed.flow() == flow.plan.flow),
                })
            else {
                return Ok(None);
            };
            if state
                .original_device
                .as_ref()
                .is_some_and(|first| !first.same_device(&original))
            {
                return Err(CaptureFailure::ForeignDevice);
            }
            let original = Arc::new(original);
            if state.original_device.is_none() {
                state.original_device = Some(original.clone());
            }
            let room = state.original_room_owner.clone();
            let flow = &mut state.flows[index];
            let plan = flow.plan.clone();
            if flow.invalid.load(Ordering::Acquire) {
                return Err(CaptureFailure::FrameConflict);
            }
            let mut slots = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
            let mut spans = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
            if let Some(parsed) = udp {
                if plan.protocol != Protocol::Udp || parsed.payload_bytes != plan.payload_bytes {
                    return Ok(None);
                }
                if let Some(slot) = plan.requests.iter().position(|key| *key == parsed.key) {
                    slots.push(slot);
                    spans.push(full::ReadFrameSpan::new(slot, 0, 1));
                    flow.requests[slot].udp_complete = true;
                }
            } else if let Some(segment) = tcp {
                if plan.protocol != Protocol::Tcp {
                    return Ok(None);
                }
                if segment.is_syn() {
                    let opened = segment.sequence().wrapping_add(1);
                    if flow.tcp_open.is_some_and(|previous| previous != opened) {
                        flow.invalid.store(true, Ordering::Release);
                        return Err(CaptureFailure::FrameConflict);
                    }
                    flow.tcp_open = Some(opened);
                    // SYN/SYN-ACK are only sequence anchors, never application data.
                    return Ok(None);
                }
                if segment.is_control_only() {
                    return Ok(None);
                }
                let base = flow.tcp_open.ok_or(CaptureFailure::MissingTcpOpen)?;
                let wire_len = 4 + 63 + u32::from(plan.payload_bytes);
                // First find all overlaps. The batch bound is checked before any
                // coverage mutation, so overflow cannot leave partial acceptance.
                for slot in 0..plan.requests.len() {
                    let start = base.wrapping_add((slot as u32).wrapping_mul(wire_len));
                    if segment.overlaps_frame(start, wire_len as usize) {
                        if slots.len() == MAX_BINDINGS_PER_PACKET {
                            flow.invalid.store(true, Ordering::Release);
                            return Err(CaptureFailure::Capacity);
                        }
                        slots.push(slot);
                    }
                }
                for slot in &slots {
                    let key = plan.requests[*slot];
                    let read = &mut flow.requests[*slot];
                    if read.tcp.is_none() {
                        let frame = TcpFramePlan::new(
                            plan.flow,
                            TcpFrameKey {
                                run: key.run,
                                round: key.round,
                                sequence: key.sequence,
                                request_nonce: key.request_nonce,
                                kind: key.kind,
                            },
                            plan.payload_bytes,
                        )
                        .ok_or(CaptureFailure::InvalidPlan)?;
                        read.tcp = TcpFrameCoverage::new(
                            frame,
                            base.wrapping_add((*slot as u32).wrapping_mul(wire_len)),
                            original.at(),
                            self.expires,
                        );
                    }
                    let coverage = read.tcp.as_mut().ok_or(CaptureFailure::InvalidPlan)?;
                    if matches!(
                        coverage.observe(&segment, original.at()),
                        TcpCoverageResult::Conflict | TcpCoverageResult::Invalidated
                    ) {
                        flow.invalid.store(true, Ordering::Release);
                        return Err(CaptureFailure::FrameConflict);
                    }
                    let (start, end) = coverage
                        .matching_span(&segment)
                        .ok_or(CaptureFailure::FrameConflict)?;
                    spans.push(full::ReadFrameSpan::new(*slot, start, end));
                }
            }
            if slots.is_empty() {
                return Ok(None);
            }
            let original_peers = self.first_read_peers(
                flow,
                &slots,
                #[cfg(any(target_os = "linux", all(unix, test)))]
                Some(&original),
            );
            let original_request_rooms = self.first_read_request_rooms(flow, &slots, room.as_ref());
            for slot in &slots {
                let read = &mut flow.requests[*slot];
                read.read_events = read
                    .read_events
                    .checked_add(1)
                    .ok_or(CaptureFailure::CounterExhausted)?;
                if read.first_read.is_none() {
                    read.first_read = Some(original.clone());
                }
                read.last_read = Some(original.clone());
            }
            let original_responses =
                self.first_response_inputs(&mut state, index, &slots, &original);
            if state.read_history.len() >= full::MAX_FULL_PACKETS {
                return Err(CaptureFailure::Capacity);
            }
            state
                .read_history
                .try_reserve(1)
                .map_err(|_| CaptureFailure::Capacity)?;
            let binding = Arc::new(KernelReadBinding {
                scope: Arc::downgrade(self),
                read: original,
                flow: index,
                slots,
                packet_len: packet.len(),
                packet_sha256,
                plan,
                spans,
                physical_publication: crate::overlay_requests::PhysicalSendPublication::new(),
                full_retained_ns: AtomicU64::new(0),
                #[cfg(any(target_os = "linux", all(unix, test)))]
                full_completion_pending: AtomicBool::new(false),
                original_publication_ns: OnceLock::new(),
                original_peers,
                original_responses,
                original_request_rooms,
            });
            state.read_history.push(binding.clone())?;
            Ok(Some(binding))
        })
    }

    #[cfg(unix)]
    pub(super) fn snapshot(&self) -> Result<ReadSnapshot, CaptureFailure> {
        let buffers = snapshot::SnapshotBuffers::prepare();
        let state = self
            .state
            .try_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        let captured = self.capture_snapshot_with_buffers(&state, buffers)?;
        drop(state);
        Ok(captured.finish())
    }

    #[cfg(unix)]
    pub(super) async fn snapshot_control(
        &self,
        end: tokio::time::Instant,
    ) -> Result<ReadSnapshot, CaptureFailure> {
        let buffers = snapshot::SnapshotBuffers::prepare();
        let state = self.state.lock_until(end).await?;
        let captured = self.capture_snapshot_with_buffers(&state, buffers)?;
        drop(state);
        Ok(captured.finish())
    }
}

impl KernelReadBinding {
    pub(crate) fn is_current_at(&self, observed_at: Instant) -> bool {
        self.original_input_rejection(observed_at).is_none()
    }

    // The original checks, order and single try-lock are unchanged. Returning
    // a negative diagnostic does not lease an owner or authorize publication.
    pub(crate) fn original_input_rejection(
        &self,
        observed_at: Instant,
    ) -> Option<FullRetentionLossReason> {
        use FullRetentionLossReason as Reason;
        let Some(scope) = self.scope.upgrade() else {
            return Some(Reason::InputScopeUnavailable);
        };
        if !scope.is_live(observed_at) {
            return Some(Reason::InputScopeNotLive);
        }
        if !scope.read_complete.load(Ordering::Acquire) {
            return Some(Reason::InputReadObservationIncomplete);
        }
        if !self.read.is_current() {
            return Some(Reason::InputDeviceRetired);
        }
        if self.read.at() > observed_at {
            return Some(Reason::InputClockBeforeRead);
        }
        #[cfg(unix)]
        let input = scope.state.try_input_lock(self.read.ordinal());
        #[cfg(not(unix))]
        let input = scope.state.try_lock();
        let state = match input {
            Ok(state) => state,
            Err(std::sync::TryLockError::WouldBlock) => {
                return Some(Reason::InputRegistryContended)
            }
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Some(Reason::InputRegistryPoisoned)
            }
        };
        state.flows[self.flow]
            .invalid
            .load(Ordering::Acquire)
            .then_some(Reason::InputFlowInvalid)
    }
}
