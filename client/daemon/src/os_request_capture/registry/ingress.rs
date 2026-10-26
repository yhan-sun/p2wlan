//! Original authenticated input and concrete system Full-write history.
//! No current connection state or final once permission is maintained here.
use super::full::ReadFrameSpan;
use super::inbound_loss::InboundLossSite;
use super::*;
use crate::business_evidence::{OsUdpReqKey, RegisteredFlow, RequestKind};
use crate::dataplane::InboundPacket;
use crate::os_request_capture::device::KernelWrite;
use crate::rooms::{OriginalRoomSendFailure, RoomAuthorization, RoomSendPermit};
#[cfg(unix)]
use crate::transport::OriginalSessionRole;
use crate::transport::{OriginalOverlayIngressSource, WireGuardTransport};
use p2pnet_tun::PacketWriteContext;
use std::sync::OnceLock;

pub(super) const MAX_SYSTEM_WRITES: usize = 1024;
const MAX_ORIGINAL_ENDPOINT_BYTES: usize = 4096;

mod response;
#[cfg(all(unix, test))]
pub(super) use response::known_route_room;
pub(super) use response::merge_original_permits;
pub(super) use response::ResponseCapture;
#[cfg(unix)]
pub(super) use response::ResponseSnapshot;

pub(crate) struct KernelCaptureRuntime {
    scope: Weak<CaptureSession>,
    room: Weak<RoomAuthorization>,
}

pub(super) struct OriginalIncomingRoom {
    pub(super) owner: Weak<RoomAuthorization>,
    pub(super) permit: Result<Option<RoomSendPermit>, OriginalRoomSendFailure>,
}

pub(super) struct InboundFlow {
    tcp_open: Option<u32>,
    pub(super) invalid: Arc<AtomicBool>,
    coverage: Vec<Option<TcpFrameCoverage>>,
    original_room: Vec<Option<Arc<OriginalIncomingRoom>>>,
}

impl InboundFlow {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new(requests: usize) -> Self {
        Self {
            tcp_open: None,
            invalid: Arc::new(AtomicBool::new(false)),
            coverage: (0..requests).map(|_| None).collect(),
            original_room: (0..requests).map(|_| None).collect(),
        }
    }
}

pub(crate) struct KernelIngressBinding {
    scope: Weak<CaptureSession>,
    source: Arc<OriginalOverlayIngressSource>,
    flow: usize,
    spans: Vec<ReadFrameSpan>,
    original_rooms: Vec<Arc<OriginalIncomingRoom>>,
    // The same canonical invalidation cell owned by the original input flow.
    inbound_invalid: Arc<AtomicBool>,
    packet_len: usize,
    packet_sha256: [u8; 32],
    authenticated_observed_monotonic_ns: Option<u64>,
    write: OnceLock<KernelWrite>,
}

pub(super) struct InboundHistory {
    // Read projection of the sole SystemWriteState appender, never a second
    // history or another production append site.
    pub(super) writes: Published<Arc<KernelIngressBinding>>,
}

pub(super) struct SystemWriteState {
    pub(super) system_device: First<Weak<DeviceLease>>,
    pub(super) writes: Published<Arc<KernelIngressBinding>>,
}

#[cfg(unix)]
#[derive(Serialize)]
pub(super) struct WriteSnapshot {
    scope: &'static str,
    flow: usize,
    spans: Vec<ReadFrameSpan>,
    write_ordinal: u64,
    write_observed_monotonic_ns: u64,
    authenticated_observed_monotonic_ns: Option<u64>,
    packet_len: usize,
    #[serde(serialize_with = "super::snapshot_hex::serialize")]
    packet_sha256: [u8; 32],
    network_generation: Option<u64>,
    session_instance: u64,
    peer_lifecycle: Option<u64>,
    original_session_role: &'static str,
    original_room_captured: Vec<bool>,
    original_room_restricted: Vec<bool>,
    original_room_owner_live: Vec<bool>,
    canonical_current_owner_verified: bool,
}

fn reverse(flow: RegisteredFlow) -> RegisteredFlow {
    RegisteredFlow {
        src_v4: flow.dst_v4,
        dst_v4: flow.src_v4,
        src_port: flow.dst_port,
        dst_port: flow.src_port,
    }
}

fn opposite(key: OsUdpReqKey) -> OsUdpReqKey {
    OsUdpReqKey {
        kind: match key.kind {
            RequestKind::Request => RequestKind::Response,
            RequestKind::Response => RequestKind::Request,
        },
        ..key
    }
}

impl CaptureSession {
    pub(crate) fn inbound_runtime(
        self: &Arc<Self>,
        room: &Arc<RoomAuthorization>,
    ) -> KernelCaptureRuntime {
        let expected = Arc::downgrade(room);
        let bound = self.state.try_lock().is_ok_and(|mut state| {
            if let Some(original) = &state.original_room_owner {
                original.ptr_eq(&expected)
            } else {
                state.original_room_owner = Some(expected.clone());
                true
            }
        });
        if !bound {
            self.inbound_loss.record(InboundLossSite::RoomBinding, None);
            self.read_complete.store(false, Ordering::Release);
            self.original_observation_lost(&self.inbound_complete);
        }
        KernelCaptureRuntime {
            scope: Arc::downgrade(self),
            room: expected,
        }
    }

    pub(in crate::os_request_capture) fn observe_system_write(
        self: &Arc<Self>,
        original: KernelWrite,
        binding: Arc<KernelIngressBinding>,
        packet: &[u8],
    ) {
        let retain = || -> Result<(), CaptureFailure> {
            if !original.is_current()
                || !self.is_live(original.at())
                || !binding.scope.ptr_eq(&Arc::downgrade(self))
                || !binding.exact_input(self, packet, original.at())
                || binding
                    .authenticated_observed_monotonic_ns
                    .is_none_or(|at| at > original.monotonic_ns())
            {
                return Err(CaptureFailure::InvalidPlan);
            }
            #[cfg(any(target_os = "linux", all(unix, test)))]
            let (flow, count, mut slots) = (
                binding.flow,
                binding.spans.len(),
                [0; MAX_BINDINGS_PER_PACKET],
            );
            #[cfg(any(target_os = "linux", all(unix, test)))]
            for (slot, span) in slots.iter_mut().zip(&binding.spans) {
                *slot = span.slot();
            }
            #[cfg(unix)]
            let mut state = self
                .system_write_state
                .try_system_write_lock(original.ordinal())
                .map_err(|_| CaptureFailure::Contended)?;
            #[cfg(not(unix))]
            let mut state = self
                .system_write_state
                .try_lock()
                .map_err(|_| CaptureFailure::Contended)?;
            if state
                .system_device
                .as_ref()
                .is_none_or(|device| !original.belongs_to(device))
            {
                return Err(CaptureFailure::ForeignDevice);
            }
            if binding.inbound_invalid.load(Ordering::Acquire) {
                return Err(CaptureFailure::FrameConflict);
            }
            if state.writes.len() >= MAX_SYSTEM_WRITES {
                return Err(CaptureFailure::Capacity);
            }
            state
                .writes
                .try_reserve(1)
                .map_err(|_| CaptureFailure::Capacity)?;
            binding
                .write
                .set(original)
                .map_err(|_| CaptureFailure::DuplicateWrite)?;
            state.writes.push(binding)?;
            #[cfg(any(target_os = "linux", all(unix, test)))]
            {
                let mut completion = native::completion::NativeCompletionBatch::new();
                drop(state);
                self.prepare_original_frames(flow, &slots[..count], &mut completion);
                completion.finish(self);
            }
            Ok(())
        };
        if let Err(error) = retain() {
            self.inbound_loss
                .record(InboundLossSite::SystemWriteRetention, Some(error));
            // A lost Full-write observation cannot be repaired by a later
            // duplicate sampled after a lifecycle change or room renewal.
            self.original_observation_lost(&self.inbound_complete);
        }
    }
}

impl KernelCaptureRuntime {
    pub(crate) fn capture_authenticated(
        &self,
        transport: &WireGuardTransport,
        source: &OriginalOverlayIngressSource,
        packet: &InboundPacket,
    ) -> Option<Arc<KernelIngressBinding>> {
        let scope = self.scope.upgrade()?;
        let captured = self.capture_inner(&scope, transport, source, packet);
        match captured {
            Ok(binding) => binding,
            Err(error) => {
                scope
                    .inbound_loss
                    .record(InboundLossSite::AuthenticatedInput, Some(error));
                // A missing first input cannot be repaired by a later copy
                // borrowing a renewed room permit. This scope never rearms.
                scope.original_observation_lost(&scope.inbound_complete);
                None
            }
        }
    }

    fn capture_inner(
        &self,
        scope: &Arc<CaptureSession>,
        transport: &WireGuardTransport,
        source: &OriginalOverlayIngressSource,
        packet: &InboundPacket,
    ) -> Result<Option<Arc<KernelIngressBinding>>, CaptureFailure> {
        if !scope.inbound_complete.load(Ordering::Acquire) {
            return Ok(None);
        }
        let udp = parse_os_udp(&packet.packet).ok();
        let tcp = parse_tcp_segment(&packet.packet).ok();
        if udp.is_none() && tcp.is_none() {
            return Ok(None);
        }
        if tcp
            .as_ref()
            .is_some_and(|segment| segment.is_control_only() && !segment.is_syn())
        {
            return Ok(None);
        }
        #[cfg(unix)]
        let mut state = scope
            .state
            .try_authenticated_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        #[cfg(not(unix))]
        let mut state = scope
            .state
            .try_lock()
            .map_err(|_| CaptureFailure::Contended)?;
        let Some(index) = state.flows.iter().position(|flow| {
            flow.plan.peer == packet.peer_id
                && match flow.plan.protocol {
                    Protocol::Udp => udp
                        .as_ref()
                        .is_some_and(|parsed| parsed.flow == reverse(flow.plan.flow)),
                    Protocol::Tcp => tcp
                        .as_ref()
                        .is_some_and(|segment| segment.flow() == reverse(flow.plan.flow)),
                }
        }) else {
            return Ok(None);
        };
        if udp.as_ref().is_some_and(|parsed| {
            parsed.payload_bytes != state.flows[index].plan.payload_bytes
                || !state.flows[index]
                    .plan
                    .requests
                    .iter()
                    .any(|key| opposite(*key) == parsed.key)
        }) {
            return Ok(None);
        }
        let authenticated = source.session().authenticated_at();
        let read_at = match (source.original_udp_read(), source.original_relay_read()) {
            (Some(read), None) => read.received_at(),
            (None, Some(read)) => read.completed_at(),
            _ => return Err(CaptureFailure::OriginalIngressSource),
        };
        if !scope.is_live(authenticated)
            || read_at > authenticated
            || !source.session().belongs_to(transport)
            || source.session().peer_id() != packet.peer_id
            || packet.session_instance != Some(source.session().session_instance())
            || packet.from_previous_session != source.session().is_previous_session()
            || source.network_generation().is_none()
            || source
                .relay_endpoint()
                .is_some_and(|value| value.len() > MAX_ORIGINAL_ENDPOINT_BYTES)
            || source
                .relay_reader_endpoint()
                .is_some_and(|value| value.len() > MAX_ORIGINAL_ENDPOINT_BYTES)
            || (source.original_relay_read().is_some()
                && source.relay_peer_id() != Some(packet.peer_id.as_str()))
        {
            return Err(CaptureFailure::InvalidPlan);
        }
        let flow = &mut state.flows[index];
        if flow.inbound.invalid.load(Ordering::Acquire) {
            return Err(CaptureFailure::FrameConflict);
        }
        let mut spans = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
        if let Some(parsed) = udp {
            if parsed.payload_bytes != flow.plan.payload_bytes {
                return Ok(None);
            }
            let Some(slot) = flow
                .plan
                .requests
                .iter()
                .position(|key| opposite(*key) == parsed.key)
            else {
                return Ok(None);
            };
            spans.push(ReadFrameSpan::new(slot, 0, 1));
        } else if let Some(segment) = tcp {
            if segment.is_syn() {
                let base = segment.sequence().wrapping_add(1);
                if flow.inbound.tcp_open.is_some_and(|old| old != base) {
                    flow.inbound.invalid.store(true, Ordering::Release);
                    return Err(CaptureFailure::FrameConflict);
                }
                flow.inbound.tcp_open = Some(base);
                return Ok(None);
            }
            if segment.is_control_only() {
                return Ok(None);
            }
            let base = flow
                .inbound
                .tcp_open
                .ok_or(CaptureFailure::MissingTcpOpen)?;
            let length = 4 + 63 + u32::from(flow.plan.payload_bytes);
            let mut slots = Vec::with_capacity(MAX_BINDINGS_PER_PACKET);
            for slot in 0..flow.plan.requests.len() {
                if segment.overlaps_frame(base.wrapping_add(slot as u32 * length), length as usize)
                {
                    if slots.len() == MAX_BINDINGS_PER_PACKET {
                        flow.inbound.invalid.store(true, Ordering::Release);
                        return Err(CaptureFailure::Capacity);
                    }
                    slots.push(slot);
                }
            }
            for slot in slots {
                if flow.inbound.coverage[slot].is_none() {
                    let key = opposite(flow.plan.requests[slot]);
                    let frame = TcpFramePlan::new(
                        reverse(flow.plan.flow),
                        TcpFrameKey {
                            run: key.run,
                            round: key.round,
                            sequence: key.sequence,
                            request_nonce: key.request_nonce,
                            kind: key.kind,
                        },
                        flow.plan.payload_bytes,
                    )
                    .ok_or(CaptureFailure::InvalidPlan)?;
                    flow.inbound.coverage[slot] = TcpFrameCoverage::new(
                        frame,
                        base.wrapping_add(slot as u32 * length),
                        authenticated,
                        scope.expires,
                    );
                }
                let coverage = flow.inbound.coverage[slot]
                    .as_mut()
                    .ok_or(CaptureFailure::InvalidPlan)?;
                if matches!(
                    coverage.observe(&segment, authenticated),
                    TcpCoverageResult::Conflict | TcpCoverageResult::Invalidated
                ) {
                    flow.inbound.invalid.store(true, Ordering::Release);
                    return Err(CaptureFailure::FrameConflict);
                }
                let (start, end) = coverage
                    .matching_span(&segment)
                    .ok_or(CaptureFailure::FrameConflict)?;
                spans.push(ReadFrameSpan::new(slot, start, end));
            }
        }
        if spans.is_empty() {
            return Ok(None);
        }
        // Try-only, before any post-decrypt await. First input for a frame owns
        // its original permit result, including unknown/contended results.
        let room = self.room.upgrade();
        let permit = room
            .as_ref()
            .ok_or(OriginalRoomSendFailure::MissingOriginal)
            .and_then(|room| {
                room.try_capture_original_send_permit(
                    &packet.peer_id,
                    &flow.plan.flow.dst_v4.to_string(),
                    &flow.plan.flow.src_v4.to_string(),
                )
            });
        let new_room = Arc::new(OriginalIncomingRoom {
            owner: self.room.clone(),
            permit,
        });
        let mut original_rooms = Vec::with_capacity(spans.len());
        for span in &spans {
            let saved =
                flow.inbound.original_room[span.slot()].get_or_insert_with(|| new_room.clone());
            original_rooms.push(saved.clone());
        }
        let inbound_invalid = flow.inbound.invalid.clone();
        // The original flow updates and first room-permit selection are done.
        // Build the immutable binding without retaining the registry guard.
        drop(state);
        Ok(Some(Arc::new(KernelIngressBinding {
            scope: Arc::downgrade(scope),
            source: Arc::new(source.clone()),
            flow: index,
            spans,
            original_rooms,
            inbound_invalid,
            packet_len: packet.packet.len(),
            packet_sha256: Sha256::digest(&packet.packet).into(),
            authenticated_observed_monotonic_ns: super::super::clock::monotonic_ns(),
            write: OnceLock::new(),
        })))
    }
}

#[cfg(any(target_os = "linux", all(unix, test)))]
impl KernelIngressBinding {
    pub(crate) fn original_source(&self) -> &OriginalOverlayIngressSource {
        &self.source
    }
    pub(super) fn original_write(&self) -> Option<&KernelWrite> {
        self.write.get()
    }
    pub(super) fn frame_spans(&self) -> &[ReadFrameSpan] {
        &self.spans
    }
    pub(super) fn frame_flow(&self) -> usize {
        self.flow
    }
    pub(super) fn original_rooms(&self) -> &[Arc<OriginalIncomingRoom>] {
        &self.original_rooms
    }
    pub(super) fn original_scope(&self) -> &Weak<CaptureSession> {
        &self.scope
    }
    pub(super) fn authenticated_ns(&self) -> Option<u64> {
        self.authenticated_observed_monotonic_ns
    }
}

impl KernelIngressBinding {
    fn exact_input(&self, scope: &CaptureSession, packet: &[u8], at: Instant) -> bool {
        scope.is_live(at)
            && scope.inbound_complete.load(Ordering::Acquire)
            && self.source.session().authenticated_at() <= at
            && self.packet_len == packet.len()
            && self.packet_sha256 == <[u8; 32]>::from(Sha256::digest(packet))
            && !self.spans.is_empty()
            && self.spans.len() <= MAX_BINDINGS_PER_PACKET
    }

    pub(crate) fn write_context(
        self: &Arc<Self>,
        peers: &Arc<PeerManager>,
        packet: &[u8],
    ) -> Option<PacketWriteContext> {
        let scope = self.scope.upgrade()?;
        if !scope.peers.ptr_eq(&Arc::downgrade(peers))
            || !self.exact_input(&scope, packet, Instant::now())
            || self.original_rooms.len() != self.spans.len()
            || self
                .original_rooms
                .iter()
                .any(|room| room.permit.is_err() || room.owner.strong_count() == 0)
        {
            scope.gap();
            return None;
        }
        Some(Box::new(self.clone()))
    }
}

impl InboundHistory {
    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn new() -> Result<Self, CaptureFailure> {
        Ok(Self {
            writes: Published::new(MAX_SYSTEM_WRITES)?,
        })
    }

    #[cfg(unix)]
    pub(super) fn published_len(&self) -> usize {
        self.writes.len()
    }

    #[cfg(any(target_os = "linux", all(unix, test)))]
    pub(super) fn frame_complete(
        &self,
        flow: usize,
        slot: usize,
        plan: &RegisteredFlowPlan,
    ) -> bool {
        super::full::spans_complete(
            self.writes
                .iter()
                .filter(|binding| binding.flow == flow && binding.write.get().is_some())
                .flat_map(|binding| &binding.spans),
            slot,
            plan,
        )
    }

    #[cfg(unix)]
    pub(super) fn snapshot_coverage(
        &self,
        published_prefix: usize,
        mut rows: Vec<(usize, Vec<ReadFrameSpan>)>,
    ) -> super::snapshot::SnapshotCoverage {
        rows.extend(
            self.writes
                .iter()
                .take(published_prefix)
                .filter(|binding| binding.write.get().is_some())
                .map(|binding| (binding.flow, binding.spans.clone())),
        );
        super::snapshot::SnapshotCoverage::from_rows(rows)
    }

    #[cfg(unix)]
    pub(super) fn snapshot(
        &self,
        published_prefix: usize,
        mut output: Vec<WriteSnapshot>,
    ) -> Vec<WriteSnapshot> {
        output.extend(
            self.writes
                .iter()
                .take(published_prefix)
                .filter_map(|binding| {
                    let write = binding.write.get()?;
                    Some(WriteSnapshot {
                        scope: "original_authenticated_system_tun_full_history_only",
                        flow: binding.flow,
                        spans: binding.spans.clone(),
                        write_ordinal: write.ordinal(),
                        write_observed_monotonic_ns: write.monotonic_ns(),
                        authenticated_observed_monotonic_ns: binding
                            .authenticated_observed_monotonic_ns,
                        packet_len: binding.packet_len,
                        packet_sha256: binding.packet_sha256,
                        network_generation: binding.source.network_generation(),
                        session_instance: binding.source.session().session_instance(),
                        peer_lifecycle: binding
                            .source
                            .session()
                            .authorized_peer_lifecycle()
                            .map(|life| life.value()),
                        original_session_role: match binding.source.session().original_role() {
                            OriginalSessionRole::Active => "active",
                            OriginalSessionRole::Pending => "pending",
                            OriginalSessionRole::Previous => "previous",
                        },
                        original_room_captured: binding
                            .original_rooms
                            .iter()
                            .map(|room| room.permit.is_ok())
                            .collect(),
                        original_room_restricted: binding
                            .original_rooms
                            .iter()
                            .map(|room| matches!(room.permit, Ok(Some(_))))
                            .collect(),
                        original_room_owner_live: binding
                            .original_rooms
                            .iter()
                            .map(|room| room.owner.upgrade().is_some())
                            .collect(),
                        canonical_current_owner_verified: false,
                    })
                }),
        );
        output
    }
}

#[cfg(all(unix, test))]
mod tests;
