//! UDP transport for encrypted peer packets.
//!
//! The WireGuard adapter produces serialized transport messages keyed by peer
//! ID. This module is the direct UDP sink: it resolves each peer endpoint from
//! `PeerManager` and sends the encrypted datagram to that socket address.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex as StdMutex,
};
use std::time::{Duration, Instant};

use p2pnet_nat::{
    build_authenticated_punch_ack, build_authenticated_punch_packet_with_nomination,
    build_punch_ack, build_punch_packet, build_punch_packet_with_nonce,
    candidate_report_from_observations, decode_authenticated_punch_packet, decode_punch_packet,
    gather_candidate_report, peek_authenticated_punch_identity, CandidateGatherReport,
    FilteringBehavior, IceConfig, MappingBehavior, PunchPacketKind, StunAttribute, StunClient,
    StunMessage, StunObservation, BINDING_RESPONSE, MAGIC_COOKIE,
};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::task::JoinSet;
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, info, trace, warn};

use crate::dataplane::global_dataplane_profiler;
use crate::error::{DaemonError, Result};
use crate::peer::{
    is_public_probe_endpoint, ActiveBusinessPath, DirectValidationIdentity, PeerManager,
    PeerPathLifecycle, PeerSessionGeneration, ProbeKeyRole, REASON_DIRECT_SEND_FAILED,
};
use crate::transport::{
    EncryptedPeerPacket, ReceivedEncryptedPacket, ResponderSessionConfirmation, WireGuardTransport,
};

mod probe_budget;
use probe_budget::{
    default_global_outbound_probe_budget, default_global_relay_backoff_heartbeat_budget,
    outbound_probe_admission_reason, retain_live_budget_entries, GlobalOutboundProbeBudget,
    GlobalRelayBackoffHeartbeatBudget, OutboundProbeAdmission, OutboundProbeBudgetKey,
    OutboundProbeBudgetState, OUTBOUND_PROBE_BUDGET_PER_NETWORK, OUTBOUND_PROBE_BUDGET_PER_PEER,
    OUTBOUND_PROBE_BUDGET_PER_PEER_REMOTE_IP, RELAY_BACKOFF_HEARTBEAT_FOREGROUND_RESERVE,
};
#[cfg(test)]
use probe_budget::{
    OUTBOUND_PROBE_PERSISTENT_PER_PEER, OUTBOUND_PROBE_PERSISTENT_PER_PEER_SOCKET,
    OUTBOUND_PROBE_PERSISTENT_WINDOW,
};
include!("udp/state.rs");

include!("udp/admission.rs");
include!("udp/gather.rs");
include!("udp/fast_gather.rs");

include!("udp/outbound.rs");
include!("udp/inbound.rs");
include!("udp/utils.rs");

#[cfg(test)]
#[path = "udp/tests.rs"]
mod tests;

/// The resolved socket for one owned encrypted direct-validation request.
///
/// Produced by `UdpTransport::prepare_direct_validation_send`: the index and
/// the socket are the exact ones recorded in the ACK expectation, so the send
/// uses this socket directly instead of re-resolving (which could observe a
/// detach or an affinity switch between the expectation registration and the
/// actual kernel send).
#[derive(Debug)]
pub(crate) struct PreparedDirectValidationSend {
    pub(crate) socket_index: usize,
    pub(crate) socket: Arc<UdpSocket>,
}

/// Why a validation send could not be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirectValidationSendError {
    /// The validation owner no longer owns the endpoint (revoked, replaced
    /// or the network generation advanced): nothing was registered and the
    /// resolved socket lease was released.
    OwnerRevoked,
    /// No UDP socket could be resolved for the peer.
    NoSocket,
}

/// Exact socket lease and immutable budget token captured before WireGuard
/// encryption for one normal Direct business packet.
#[derive(Debug)]
pub(crate) struct PreparedDirectBusinessSend {
    pub(crate) token: crate::dplpmtud::DirectBusinessSendToken,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) endpoint: SocketAddr,
    pub(crate) socket_index: usize,
    _lease: DynamicSocketSendLease,
}

#[derive(Debug)]
pub(crate) enum DirectBusinessBudgetGate {
    /// Capability was not negotiated, or this platform's exact socket cannot
    /// provide the no-fragment profile. Preserve pre-DPLPMTUD behavior.
    Unmanaged,
    /// Modern peer, but BASE/budget/exact identity is not currently usable.
    ManagedPending {
        reason: &'static str,
    },
    Ready(Box<PreparedDirectBusinessSend>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum DirectBusinessUdpSendError {
    #[error("Direct business send token is stale")]
    StaleToken,
    #[error("encrypted UDP datagram exceeds confirmed budget")]
    CiphertextTooLarge,
    #[error("local UDP path rejected the datagram as too large")]
    LocalPacketTooLarge,
    #[error("local UDP socket would block before handoff")]
    WouldBlock,
    #[error("UDP send failed before handoff: {0}")]
    Io(String),
    #[error("short UDP send: sent {sent} of {expected} bytes")]
    Short { sent: usize, expected: usize },
}

/// Exact reverse target learned from an authenticated Direct-validation
/// Request. A dependent NAT may need this target to reproduce the public
/// source mapping which the peer committed from our validation ACK.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DplpmtudAckReverseRoute {
    network_generation: u64,
    peer_session_generation: PeerSessionGeneration,
    remote_endpoint: SocketAddr,
    local_endpoint: SocketAddr,
    socket_index: usize,
}

#[cfg(test)]
type RemoteIncarnationCleanupGateSlot =
    Arc<std::sync::Mutex<Option<(String, Arc<RemoteIncarnationCleanupGate>)>>>;

static NEXT_UDP_TRANSPORT_INSTANCE: AtomicU64 = AtomicU64::new(1);

pub const IPV6_SOCKET_INDEX: usize = 2048;

/// Sends encrypted WireGuard packets over direct UDP endpoints.
#[derive(Clone)]
pub struct UdpTransport {
    /// Process-local identity of this concrete UDP publication. Clones keep
    /// the identity; a newly bound/replaced transport gets a new one, so a
    /// cached fast-path socket index can never silently carry across a
    /// publication replacement that reused the same index.
    transport_instance_id: u64,
    /// The primary socket is used for STUN and remains the single-socket
    /// fallback. Additional sockets, when explicitly enabled, are only used
    /// for bounded symmetric-NAT traversal experiments.
    socket: Arc<UdpSocket>,
    sockets: Arc<Vec<Arc<UdpSocket>>>,
    pub(crate) ipv6_socket: Option<Arc<UdpSocket>>,
    ipv6_socket_diagnostics: Arc<Mutex<Option<UdpSocketPoolMemberDiagnostics>>>,
    /// Physical interface used to bypass a foreign system TUN. `None` keeps
    /// ordinary multi-interface routing when no capture route is present.
    outbound_interface: Option<Arc<str>>,
    peers: Arc<PeerManager>,
    pending_probes: PendingProbes,
    /// Local-only binding from a Hard↔Hard probe nonce to its rendezvous
    /// token. It never changes the UDP wire packet; the authenticated Probe
    /// v2 nonce is simply refused if its bounded session has been removed or
    /// superseded before the ACK arrives.
    hard_hard_probe_bindings: HardHardProbeBindings,
    stun_waiters: StunWaiters,
    /// Merged socket ownership state: dynamic punch sockets, per-peer
    /// affinity pins and the affinity epoch counter live under one mutex so
    /// every ownership transition is atomic and no lock ordering exists.
    socket_state: Arc<Mutex<SocketState>>,
    /// Shared network-epoch gate (owned by the peer manager) serializing
    /// generation advances against every generation-sensitive socket-state
    /// mutation: commit, finalize, attach, affinity adoption and pending-probe
    /// registration.  Lock order everywhere: network-epoch gate -> adoption
    /// lock -> socket_state -> pending probes.
    network_epoch_gate: Arc<tokio::sync::Mutex<()>>,
    /// Per-peer adoption locks serializing every pending-probe ACK adoption
    /// against `clear_pending_probes_for_peer`.
    ///
    /// An ACK handler matches the pending entry, removes it and then performs
    /// a sequence of awaits (WireGuard promotion, endpoint learning, socket
    /// pin, Direct promotion).  Without a fence, a PeerLeft / offline /
    /// public-key cleanup can interleave between those awaits and the ACK
    /// would recreate affinity, candidate or endpoint state for a peer that
    /// was cleaned.  The per-peer adoption lock makes each ACK's
    /// match+adoption one atomic section: the cleanup either runs before the
    /// ACK (the cleanup-epoch fence then refuses the adoption) or after it
    /// (the cleanup removes whatever the ACK created).  Lock order everywhere
    /// is: adoption lock -> socket_state -> pending probes.
    peer_adoption_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    socket_pool_active: Arc<AtomicBool>,
    socket_pool_diagnostics: Arc<Mutex<Vec<UdpSocketPoolMemberDiagnostics>>>,
    dynamic_socket_counter: Arc<AtomicUsize>,
    dynamic_socket_diagnostics: Arc<Mutex<HashMap<usize, UdpSocketPoolMemberDiagnostics>>>,
    /// Authenticated probe receive counters keyed by `(peer_id, generation)`.
    /// Aggregate socket counters remain available for topology-free diagnostics,
    /// but they must never be used as evidence for a single peer's timeout.
    peer_probe_rx_diagnostics: PeerProbeRxDiagnostics,
    inbound_tx: Option<mpsc::Sender<ReceivedEncryptedPacket>>,
    /// Owner of the daemon publication currently allowed to turn an
    /// authenticated UDP envelope into Direct-path state. Socket readers
    /// stamp this on every envelope; WireGuard inbound compares it with the
    /// live watch value after decryption so a packet queued by a withdrawn
    /// transport cannot be attributed to a replacement socket.
    inbound_publication_owner: Arc<AtomicU64>,
    /// Bounded per-peer newest-wins ingress for authenticated endpoint
    /// observations.  The daemon-side consumer owns the only receive loop;
    /// UDP readers submit synchronously and never wait on a worker queue.
    peer_reflexive_ingress: Option<PeerReflexiveIngress>,
    /// Optional daemon-registered ingress for daemon-internal
    /// direct-validation observations.
    ///
    /// The UDP layer cannot call the validation task directly (module
    /// layering: `udp` is below `lib`), so the daemon registers a closure at
    /// setup.  Both matched ACK and peer-reflexive paths call this same
    /// ingress; it only queues/merges evidence and never spawns a worker.
    validation_trigger: Option<Arc<dyn Fn(PeerReflexiveObservation) + Send + Sync>>,
    triggered_checks: TriggeredCheckState,
    nat_maintainers: NatMaintainerState,
    /// Dedicated per-(peer, socket) budget for NAT-state binding maintainer
    /// probes, fully isolated from the recovery-epoch traversal credit and
    /// the shared outbound probe budgets.
    nat_maintainer_budget: NatMaintainerBudgetState,
    /// Dedicated per-peer budget for the relay-backed recovery heartbeat.
    relay_backoff_heartbeat_budget: RelayBackoffHeartbeatBudgetState,
    /// Send-capability registry for relay-backoff heartbeat tasks: at most
    /// one send-capable worker per peer, with a quit handshake before
    /// replacement.
    relay_backoff_heartbeats: RelayBackoffHeartbeatState,
    /// Test-only hook that parks a heartbeat worker immediately before a UDP
    /// send, letting a deterministic test cancel the owner and assert that
    /// the worker re-validates its ownership before the actual send.
    #[cfg(test)]
    heartbeat_send_gate: Arc<std::sync::Mutex<Option<Arc<HeartbeatSendGate>>>>,
    /// Test-only physical-send seam. It is absent from production builds and
    /// disabled by default; tests can fail selected send attempts at the
    /// shared UDP send abstraction without closing or replacing the socket.
    #[cfg(test)]
    probe_send_failure_hook: Arc<std::sync::Mutex<Option<ProbeSendFailureHook>>>,
    #[cfg(test)]
    probe_send_failure_hook_enabled: Arc<AtomicBool>,
    /// One-shot lifecycle linearization seam used only by the remote-restart
    /// race regression.
    #[cfg(test)]
    remote_incarnation_cleanup_gate: RemoteIncarnationCleanupGateSlot,
    /// One-shot deterministic seam between business encryption and the exact
    /// UDP handoff. Production builds contain no hook or additional branch.
    #[cfg(test)]
    direct_business_send_gate: Arc<std::sync::Mutex<Option<Arc<DirectBusinessSendGate>>>>,
    /// Inject one typed local EMSGSIZE at the exact business syscall boundary.
    #[cfg(test)]
    direct_business_emsgsize_once: Arc<AtomicBool>,
    /// Deterministic per-peer `WouldBlock` injection at the same exact syscall
    /// boundary. Production builds contain neither the map nor its branch.
    #[cfg(test)]
    direct_business_would_block: Arc<StdMutex<HashMap<String, DirectBusinessWouldBlockInjection>>>,
    authenticated_punch_replay: AuthPunchReplayState,
    authenticated_punch_rate: AuthPunchRateState,
    outbound_probe_budget: OutboundProbeBudgetState,
    global_outbound_probe_budget: Option<Arc<GlobalOutboundProbeBudget>>,
    local_node_id: Option<String>,
    wireguard_transport: Option<WireGuardTransport>,
    /// Outstanding daemon-internal direct-validation requests per peer: the
    /// ACK handler only promotes Direct when the ACK token matches an
    /// expectation registered by the validation task, so a stale request can
    /// never confirm a new session.
    /// Shared validation session/expectation registry.  `PeerManager` holds a
    /// clone so a network-generation transition cancels old ownership while
    /// it is still inside the shared epoch gate.
    direct_validation: DirectValidationRegistry,
    /// DPLPMTUD state, capability receipts and exact-path workers owned by
    /// this concrete UDP publication.
    dplpmtud: crate::dplpmtud::DplpmtudRuntime,
    /// One authenticated reverse response route per peer, bounded by the same
    /// 256-peer ceiling as DPLPMTUD. This belongs to the concrete UDP
    /// publication and is cleared by peer lifecycle cleanup.
    dplpmtud_ack_reverse_routes: Arc<StdMutex<HashMap<String, DplpmtudAckReverseRoute>>>,
    dplpmtud_worker_ingress: crate::dplpmtud::DplpmtudWorkerIngress,
    dplpmtud_local_virtual_ip: Option<Ipv4Addr>,
    /// Adaptive-prediction learner state for the current network generation.
    ///
    /// The fresh-mapping generator feeds each batch's observed ports into a
    /// shared [`StepLearner`] (cross-batch EWMA stride) and [`ReverseDetector`]
    /// (allocation direction) so the predictor can use a stride newer than
    /// this one batch's median and widen its window on reverse allocation.  All
    /// peers on one egress share the allocator, so the cache is keyed by
    /// public IP (not peer).  The whole cache resets when the network
    /// generation changes, since a new allocator invalidates every learned
    /// stride and direction.
    learning_cache: Arc<Mutex<LearningCache>>,
}

use p2pnet_nat::adaptive::{DirectionPattern, ReverseDetector, StepLearner};

use p2pnet_nat::mapping::{
    build_model_for_batch, infer_allocation_model, predict_ports_with_learning, MappingBatch,
    MappingObservation, ModelRejection, PortModel, PortModelKind,
};

use learning::LearningCache;

use learning::model_deltas;

use learning::fresh_mapping_target_eligible;

use dynamic_punch::monotonic_millis;

#[cfg(test)]
use birthday::hard_hard_birthday_candidates;

pub(crate) use birthday::hard_hard_birthday_socket_count;

#[cfg(test)]
use birthday::hard_hard_birthday_capacity_plan;

#[cfg(test)]
use birthday::hard_hard_birthday_socket_plan;

use punch_reports::record_birthday_worker_result;

use punch_reports::combine_birthday_failure_kind;

use punch_reports::merge_punch_send_reports;

pub(crate) use punch_reports::update_birthday_sweep_counters;

use punch_reports::update_live_birthday_counters;

pub(crate) use punch_reports::apply_live_birthday_counters;

use punch_reports::publish_birthday_sweep_progress;

pub(crate) use birthday::hard_hard_birthday_wave_count;

#[cfg(test)]
use birthday::hard_hard_birthday_packets_planned;

#[cfg(test)]
use birthday::hard_hard_birthday_wave_assignments;

pub(crate) use socket_lifecycle::ProvisionalSocketGuard;

#[cfg(test)]
#[path = "udp/birthday_tests.rs"]
mod birthday_tests;

mod core;

mod business_mtu;

mod socket_registry;

mod peer_cleanup;

mod direct_validation;

mod diagnostics;

mod dynamic_punch;

mod socket_lifecycle;

mod learning;

mod birthday;

mod punch_sender;

mod punch_reports;
