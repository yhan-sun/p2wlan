//! Private, default-disabled registered RX observations.
//!
//! These are historical observations, never routing or acceptance authority.
//! In-process Arc carriers are lifetime guards; their addresses are not identity.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

mod hooks;
mod parser;
mod recorder;
#[allow(unused_imports)]
pub(crate) use parser::{parse_os_udp, ParseErrorKind, ParsedOsUdp};
#[allow(unused_imports)]
pub(crate) use recorder::{
    ArmError, CaptureOwner, CoverageSnapshot, SlotSnapshot, SnapshotDisposition,
};

pub(crate) const MAX_REQUESTS: usize = 1000;
pub(crate) const MAX_SLOTS: usize = MAX_REQUESTS * 2;
pub(crate) const MAX_PEERS: usize = MAX_SLOTS;
pub(crate) const MAX_PEER_ID_BYTES: usize = 256;
pub(crate) const MAX_CONTEXT_BYTES: usize = 512;
pub(crate) const MAX_SLOT_BYTES: usize = 4096;
pub(crate) const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_TTL_SECS: u64 = 120;
pub(crate) const OS_UDP_HEADER_BYTES: usize = 63;
pub(crate) const MAX_OS_UDP_BYTES: usize = 1200;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum RequestKind {
    Request,
    Response,
}

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct OsUdpReqKey {
    pub(crate) run: [u8; 16],
    pub(crate) round: [u8; 16],
    pub(crate) sequence: u32,
    pub(crate) request_nonce: [u8; 16],
    pub(crate) kind: RequestKind,
}

impl fmt::Debug for OsUdpReqKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsUdpReqKey")
            .field("sequence", &self.sequence)
            .field("kind", &self.kind)
            .field("nonces", &"redacted")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegisteredFlow {
    pub(crate) src_v4: Ipv4Addr,
    pub(crate) dst_v4: Ipv4Addr,
    pub(crate) src_port: u16,
    pub(crate) dst_port: u16,
}

impl RegisteredFlow {
    pub(crate) fn reverse(self) -> Self {
        Self {
            src_v4: self.dst_v4,
            dst_v4: self.src_v4,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }

    fn valid(self) -> bool {
        self.src_port != 0
            && self.dst_port != 0
            && !self.src_v4.is_unspecified()
            && !self.dst_v4.is_unspecified()
            && !self.src_v4.is_multicast()
            && !self.dst_v4.is_multicast()
            && !self.src_v4.is_broadcast()
            && !self.dst_v4.is_broadcast()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Registration {
    pub(crate) key: OsUdpReqKey,
    pub(crate) flow: RegisteredFlow,
    pub(crate) expected_payload_bytes: u16,
    pub(crate) peer_slot: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CaptureScope {
    pub(crate) capture_id: [u8; 16],
    pub(crate) producer_scope: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotRef {
    scope: CaptureScope,
    index: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegisteredObservation {
    slot: SlotRef,
    registration: Registration,
}

impl RegisteredObservation {
    pub(crate) fn slot(self) -> SlotRef {
        self.slot
    }

    pub(crate) fn registration(self) -> Registration {
        self.registration
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecordDisposition {
    Stored,
    DuplicateSameIdentity,
    Conflict,
    Disabled,
    Unregistered,
    FlowMismatch,
    PeerMismatch,
    Malformed,
    Expired,
    Contended,
    IdentityMissing,
}

impl RecordDisposition {
    pub(crate) const COUNT: usize = 11;
    fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnableError {
    AlreadyEnabled,
}

/// Missing evidence never changes business admission or delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EvidenceGap {
    IdentityMissing,
    Malformed,
    FlowMismatch,
}

impl EvidenceGap {
    fn disposition(self) -> RecordDisposition {
        match self {
            Self::IdentityMissing => RecordDisposition::IdentityMissing,
            Self::Malformed => RecordDisposition::Malformed,
            Self::FlowMismatch => RecordDisposition::FlowMismatch,
        }
    }
}

static NEXT_WG_EVIDENCE_OWNER: AtomicU64 = AtomicU64::new(1);

/// Scoped further by CaptureScope/launch; never a wire or global process ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WgEvidenceOwnerId(u64);

impl WgEvidenceOwnerId {
    pub(crate) fn allocate() -> Self {
        Self::allocate_from(&NEXT_WG_EVIDENCE_OWNER)
    }

    fn allocate_from(counter: &AtomicU64) -> Self {
        // Constructor only. Exhaustion becomes missing evidence rather than
        // silently reusing a previously assigned owner.
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            let Some(next) = current.checked_add(1) else {
                return Self(0);
            };
            match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(previous) => return Self(previous),
                Err(observed) => current = observed,
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservedIngress {
    DirectUdpObserved,
    RelayObserved,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SocketOwner {
    FixedPool {
        index: u32,
    },
    DynamicAttach {
        peer_slot: u16,
        network_generation: u64,
        punch_generation: u64,
    },
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationObservation {
    EnqueueObserved { owner: Option<NonZeroU64> },
    Unknown,
}

/// Immutable original reader facts. No Arc, payload, pointer or mutable owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PhysicalIngressContext {
    ingress: ObservedIngress,
    network_generation: Option<u64>,
    runtime_instance: Option<NonZeroU64>,
    socket_index: Option<u32>,
    socket_owner: SocketOwner,
    publication: PublicationObservation,
    source: Option<SocketAddr>,
    local_endpoint: Option<SocketAddr>,
    received_at: Option<Instant>,
    enqueued_at: Option<Instant>,
    relay_connection_id: Option<NonZeroU64>,
    relay_endpoint_slot: Option<u16>,
}

impl PhysicalIngressContext {
    /// Values sampled once by the original reader at enqueue. Missing
    /// dimensions stay unknown; no mutable socket/path lookup fills them in.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_udp_reader(
        network_generation: u64,
        runtime_instance: Option<NonZeroU64>,
        socket_index: Option<u32>,
        socket_owner: SocketOwner,
        publication: PublicationObservation,
        source: SocketAddr,
        local_endpoint: Option<SocketAddr>,
        received_at: Instant,
        enqueued_at: Instant,
    ) -> Self {
        Self {
            ingress: ObservedIngress::DirectUdpObserved,
            network_generation: Some(network_generation),
            runtime_instance,
            socket_index,
            socket_owner,
            publication,
            source: Some(source),
            local_endpoint,
            received_at: Some(received_at),
            enqueued_at: Some(enqueued_at),
            relay_connection_id: None,
            relay_endpoint_slot: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn direct_udp(
        network_generation: Option<u64>,
        runtime_instance: NonZeroU64,
        socket_index: u32,
        socket_owner: SocketOwner,
        publication: PublicationObservation,
        source: SocketAddr,
        local_endpoint: SocketAddr,
        received_at: Instant,
        enqueued_at: Instant,
    ) -> Self {
        Self {
            ingress: ObservedIngress::DirectUdpObserved,
            network_generation,
            runtime_instance: Some(runtime_instance),
            socket_index: Some(socket_index),
            socket_owner,
            publication,
            source: Some(source),
            local_endpoint: Some(local_endpoint),
            received_at: Some(received_at),
            enqueued_at: Some(enqueued_at),
            relay_connection_id: None,
            relay_endpoint_slot: None,
        }
    }

    pub(crate) fn runtime_instance(self) -> Option<NonZeroU64> {
        self.runtime_instance
    }
    pub(crate) fn publication(self) -> PublicationObservation {
        self.publication
    }
    pub(crate) fn source(self) -> Option<SocketAddr> {
        self.source
    }
    pub(crate) fn local_endpoint(self) -> Option<SocketAddr> {
        self.local_endpoint
    }
    pub(crate) fn socket_index(self) -> Option<u32> {
        self.socket_index
    }
    pub(crate) fn ingress(self) -> ObservedIngress {
        self.ingress
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireTuple {
    pub(crate) receiver_index: u32,
    pub(crate) counter: u64,
    pub(crate) wire_len: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AuthenticatedIngressContext {
    registered: RegisteredObservation,
    physical: PhysicalIngressContext,
    wg_owner: WgEvidenceOwnerId,
    session_instance: NonZeroU64,
    auth_prev_session: bool,
    wire: WireTuple,
    authenticated_at: Instant,
}

impl AuthenticatedIngressContext {
    pub(crate) fn new(
        registered: RegisteredObservation,
        physical: PhysicalIngressContext,
        wg_owner: WgEvidenceOwnerId,
        session_instance: NonZeroU64,
        auth_prev_session: bool,
        wire: WireTuple,
        authenticated_at: Instant,
    ) -> Option<Self> {
        if wg_owner.0 == 0 || wire.wire_len < 16 {
            return None;
        }
        Some(Self {
            registered,
            physical,
            wg_owner,
            session_instance,
            auth_prev_session,
            wire,
            authenticated_at,
        })
    }

    pub(crate) fn registered(self) -> RegisteredObservation {
        self.registered
    }
    pub(crate) fn physical(self) -> PhysicalIngressContext {
        self.physical
    }
    pub(crate) fn session_instance(self) -> NonZeroU64 {
        self.session_instance
    }
    pub(crate) fn wg_owner(self) -> WgEvidenceOwnerId {
        self.wg_owner
    }
    pub(crate) fn auth_prev_session(self) -> bool {
        self.auth_prev_session
    }
    pub(crate) fn wire(self) -> WireTuple {
        self.wire
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunBackend {
    MockDelivered,
    SystemPlatformReportedFull,
    WintunRingSubmitted,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TunEvidenceIdentity {
    pub(crate) instance: NonZeroU64,
    pub(crate) backend: TunBackend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CurrentFence {
    Current,
    Stale,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TunFullReceipt {
    authenticated: AuthenticatedIngressContext,
    normalized_flow: RegisteredFlow,
    normalized_len: u32,
    written: u32,
    target: TunEvidenceIdentity,
    completed_at: Instant,
    current_fence: CurrentFence,
}

impl TunFullReceipt {
    pub(crate) fn new(
        authenticated: AuthenticatedIngressContext,
        normalized_flow: RegisteredFlow,
        normalized_len: u32,
        written: u32,
        target: TunEvidenceIdentity,
        completed_at: Instant,
        current_fence: CurrentFence,
    ) -> Option<Self> {
        if normalized_len == 0 || written != normalized_len {
            return None;
        }
        Some(Self {
            authenticated,
            normalized_flow,
            normalized_len,
            written,
            target,
            completed_at,
            current_fence,
        })
    }

    pub(crate) fn authenticated(self) -> AuthenticatedIngressContext {
        self.authenticated
    }
    pub(crate) fn normalized_flow(self) -> RegisteredFlow {
        self.normalized_flow
    }
    pub(crate) fn written(self) -> u32 {
        self.written
    }
    pub(crate) fn target(self) -> TunEvidenceIdentity {
        self.target
    }
    pub(crate) fn current_fence(self) -> CurrentFence {
        self.current_fence
    }

    fn same_identity(self, other: Self) -> bool {
        self.authenticated == other.authenticated
            && self.normalized_flow == other.normalized_flow
            && self.normalized_len == other.normalized_len
            && self.written == other.written
            && self.target == other.target
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StageReceipt {
    AuthenticatedReceive(AuthenticatedIngressContext),
    TunWriteFull(TunFullReceipt),
}

#[cfg(test)]
mod tests;
