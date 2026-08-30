//! Authenticated Direct UDP Datagram Packetization Layer Path MTU Discovery.
//!
//! This phase deliberately keeps three layers distinct:
//! - [`OuterIpPacketSize`]: complete outer IP packet (IP + UDP + datagram);
//! - [`UdpDatagramSize`]: bytes passed to `UdpSocket::send_to`;
//! - [`OverlayPayloadBudget`]: decrypted WireGuard plaintext budget.
//!
//! The reducer below never selects an active path and never mutates Direct
//! health. A probe timeout only narrows one exact Direct path's size search.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex as StdMutex, RwLock as StdRwLock,
};
use std::time::Duration;

use p2pnet_tun::{Ipv4Packet, Protocol};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::{watch, Notify};
use tokio::time::Instant;

use crate::peer::{ActiveBusinessPath, DirectValidationIdentity, PathEpoch, PeerPathLifecycle};

/// WireGuard transport header (16 bytes) plus ChaCha20-Poly1305 tag (16 bytes).
pub(crate) const WIREGUARD_UDP_DATAGRAM_OVERHEAD: u32 = 32;
/// Outer IPv4 + UDP framing, excluded from [`UdpDatagramSize`].
pub(crate) const IPV4_OUTER_IP_UDP_OVERHEAD: u32 = 20 + 8;
/// Outer IPv6 + UDP framing, excluded from [`UdpDatagramSize`].
pub(crate) const IPV6_OUTER_IP_UDP_OVERHEAD: u32 = 40 + 8;
/// Conservative UDP datagram baseline for an authenticated Direct path.
pub(crate) const DPLPMTUD_BASE_UDP_DATAGRAM_SIZE: u32 = 1200;
/// Ethernet-sized IPv4 UDP datagram ceiling: 1500 - IPv4(20) - UDP(8).
pub(crate) const DPLPMTUD_IPV4_UDP_DATAGRAM_CEILING: u32 = 1472;
/// Ethernet-sized IPv6 UDP datagram ceiling: 1500 - IPv6(40) - UDP(8).
pub(crate) const DPLPMTUD_IPV6_UDP_DATAGRAM_CEILING: u32 = 1452;
pub(crate) const DPLPMTUD_SEARCH_GRANULARITY: u32 = 8;
pub(crate) const DPLPMTUD_MAX_RETRIES: u8 = 2;
pub(crate) const DPLPMTUD_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const DPLPMTUD_RAISE_INTERVAL: Duration = Duration::from_secs(10 * 60);
pub(crate) const DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL: Duration = Duration::from_secs(30);
pub(crate) const DPLPMTUD_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const DPLPMTUD_WORKER_MAX_LIFETIME: Duration = Duration::from_secs(60 * 60);
pub(crate) const MAX_TRACKED_DPLPMTUD_PEERS: usize = 256;
pub(crate) const DPLPMTUD_ACK_RATE_LIMIT_PER_PEER: usize = 8;
pub(crate) const DPLPMTUD_ACK_RATE_WINDOW: Duration = Duration::from_secs(1);
const MAX_CONSUMED_PROBE_RECEIPTS: usize = 32;

const DIRECT_VALIDATION_TOKEN_BYTES: usize = 8 + 2 + 1 + 8;
const DIRECT_VALIDATION_CAPABILITY_EXTENSION: [u8; 6] = [b'D', b'P', b'M', b'1', 1, 1];
const DPLPMTUD_PROBE_PREFIX: &[u8] = b"p2wlan-dplpmtud-probe-v1";
const DPLPMTUD_ACK_PREFIX: &[u8] = b"p2wlan-dplpmtud-ack-v1";
const DPLPMTUD_TOKEN_BYTES: usize = 8 + 16 + 16 + 8 + 8 + 8 + 8 + 2 + 4 + 1;
const INNER_IPV4_ICMP_OVERHEAD: usize = 20 + 8;
/// Process-wide allocator so replacing the entire UDP runtime cannot reuse a
/// business budget revision from an older socket publication.
static NEXT_DPLPMTUD_BUDGET_REVISION: AtomicU64 = AtomicU64::new(1);

/// Additive capability bytes inserted before the existing fixed Direct-
/// validation tail token. Old peers locate that token from the end and safely
/// ignore these bytes.
pub(crate) const fn direct_validation_capability_extension() -> [u8; 6] {
    DIRECT_VALIDATION_CAPABILITY_EXTENSION
}

/// Capability negotiation is fail-closed: legacy or malformed extensions are
/// treated as unsupported and therefore never receive a size Probe.
pub(crate) fn direct_validation_supports_dplpmtud(packet: &[u8]) -> bool {
    let Ok(ip) = Ipv4Packet::new(packet) else {
        return false;
    };
    if ip.protocol() != Protocol::Icmp {
        return false;
    }
    let Some(payload) = ip.payload().get(8..) else {
        return false;
    };
    let prefix_len = if payload.starts_with(crate::DIRECT_VALIDATION_REQUEST_PAYLOAD) {
        crate::DIRECT_VALIDATION_REQUEST_PAYLOAD.len()
    } else if payload.starts_with(crate::DIRECT_VALIDATION_ACK_PAYLOAD) {
        crate::DIRECT_VALIDATION_ACK_PAYLOAD.len()
    } else {
        return false;
    };
    let Some(token_start) = payload.len().checked_sub(DIRECT_VALIDATION_TOKEN_BYTES) else {
        return false;
    };
    token_start >= prefix_len
        && payload[prefix_len..token_start] == DIRECT_VALIDATION_CAPABILITY_EXTENSION
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct OuterIpPacketSize(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct UdpDatagramSize(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct OverlayPayloadBudget(pub(crate) u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OuterIpFamily {
    Ipv4,
    Ipv6,
}

impl OuterIpFamily {
    pub(crate) const fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::Ipv4,
            IpAddr::V6(_) => Self::Ipv6,
        }
    }

    pub(crate) const fn outer_ip_udp_overhead(self) -> u32 {
        match self {
            Self::Ipv4 => IPV4_OUTER_IP_UDP_OVERHEAD,
            Self::Ipv6 => IPV6_OUTER_IP_UDP_OVERHEAD,
        }
    }

    pub(crate) const fn ceiling_udp_datagram_size(self) -> UdpDatagramSize {
        match self {
            Self::Ipv4 => UdpDatagramSize(DPLPMTUD_IPV4_UDP_DATAGRAM_CEILING),
            Self::Ipv6 => UdpDatagramSize(DPLPMTUD_IPV6_UDP_DATAGRAM_CEILING),
        }
    }
}

impl UdpDatagramSize {
    pub(crate) const fn outer_ip_packet_size(self, family: OuterIpFamily) -> OuterIpPacketSize {
        OuterIpPacketSize(self.0 + family.outer_ip_udp_overhead())
    }

    pub(crate) const fn overlay_payload_budget(self) -> Option<OverlayPayloadBudget> {
        match self.0.checked_sub(WIREGUARD_UDP_DATAGRAM_OVERHEAD) {
            Some(value) => Some(OverlayPayloadBudget(value)),
            None => None,
        }
    }
}

/// Stable identity of the concrete local socket in one UDP publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct DplpmtudSocketIdentity {
    pub(crate) transport_instance_id: u64,
    pub(crate) socket_index: usize,
}

/// Exact local identity of one already-authenticated Direct UDP path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DplpmtudPathIdentity {
    pub(crate) peer_id: String,
    pub(crate) epoch: PathEpoch,
    pub(crate) direct_validation_owner_token: u64,
    pub(crate) direct_validation_request_id: u16,
    pub(crate) authenticated_remote_endpoint: SocketAddr,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) socket: DplpmtudSocketIdentity,
    pub(crate) outer_ip_family: OuterIpFamily,
}

impl DplpmtudPathIdentity {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_committed_validation(
        peer_id: impl Into<String>,
        validation: DirectValidationIdentity,
        authenticated_remote_endpoint: SocketAddr,
        local_endpoint: SocketAddr,
        transport_instance_id: u64,
        socket_index: usize,
    ) -> Option<Self> {
        if local_endpoint.is_ipv4() != authenticated_remote_endpoint.is_ipv4() {
            return None;
        }
        Some(Self {
            peer_id: peer_id.into(),
            epoch: validation.epoch,
            direct_validation_owner_token: validation.owner_token?,
            direct_validation_request_id: validation.request_id?,
            authenticated_remote_endpoint,
            local_endpoint,
            socket: DplpmtudSocketIdentity {
                transport_instance_id,
                socket_index,
            },
            outer_ip_family: OuterIpFamily::from_ip(authenticated_remote_endpoint.ip()),
        })
    }

    pub(crate) fn matches_committed_path(
        &self,
        lifecycle: PeerPathLifecycle,
        epoch: Option<PathEpoch>,
        active: &ActiveBusinessPath,
    ) -> bool {
        lifecycle == PeerPathLifecycle::Online
            && epoch == Some(self.epoch)
            && matches!(
                active,
                ActiveBusinessPath::Direct(validation)
                    if validation.epoch == self.epoch
                        && validation.owner_token == Some(self.direct_validation_owner_token)
                        && validation.request_id == Some(self.direct_validation_request_id)
                        && validation.commit_endpoint()
                            == Some(self.authenticated_remote_endpoint)
            )
    }

    pub(crate) fn summary(&self) -> DplpmtudPathIdentitySnapshot {
        DplpmtudPathIdentitySnapshot {
            peer_id: self.peer_id.clone(),
            network_generation: self.epoch.network_generation,
            peer_session_generation: self.epoch.peer_session_generation.value(),
            remote_candidate_epoch: self.epoch.remote_candidate_epoch,
            direct_validation_owner_token: self.direct_validation_owner_token,
            direct_validation_request_id: self.direct_validation_request_id,
            authenticated_remote_endpoint: self.authenticated_remote_endpoint.to_string(),
            local_endpoint: self.local_endpoint.to_string(),
            transport_instance_id: self.socket.transport_instance_id,
            socket_index: self.socket.socket_index,
            outer_ip_family: self.outer_ip_family,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DplpmtudPathIdentitySnapshot {
    pub(crate) peer_id: String,
    pub(crate) network_generation: u64,
    pub(crate) peer_session_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) direct_validation_owner_token: u64,
    pub(crate) direct_validation_request_id: u16,
    pub(crate) authenticated_remote_endpoint: String,
    pub(crate) local_endpoint: String,
    pub(crate) transport_instance_id: u64,
    pub(crate) socket_index: usize,
    pub(crate) outer_ip_family: OuterIpFamily,
}

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
struct DplpmtudBudgetRevisionState {
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

    fn for_path_with_reason(
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

    fn business_confirmed_udp_datagram_size(&self) -> Option<UdpDatagramSize> {
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

    fn budget_revision_state(&self) -> DplpmtudBudgetRevisionState {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudWireToken {
    pub(crate) sequence: u64,
    pub(crate) nonce: [u8; 16],
    pub(crate) path_cookie: [u8; 16],
    pub(crate) network_generation: u64,
    pub(crate) peer_session_generation: u64,
    pub(crate) remote_candidate_epoch: u64,
    pub(crate) direct_validation_owner_token: u64,
    pub(crate) direct_validation_request_id: u16,
    pub(crate) candidate_udp_datagram_size: UdpDatagramSize,
    pub(crate) outer_ip_family: OuterIpFamily,
}

impl DplpmtudWireToken {
    pub(crate) fn probe_identity(self) -> DplpmtudProbeIdentity {
        DplpmtudProbeIdentity {
            sequence: self.sequence,
            nonce: self.nonce,
            path_cookie: self.path_cookie,
            candidate_udp_datagram_size: self.candidate_udp_datagram_size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DplpmtudControlKind {
    Probe,
    Ack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudControlPacket {
    pub(crate) kind: DplpmtudControlKind,
    pub(crate) token: DplpmtudWireToken,
}

pub(crate) fn build_probe_inner_packet(
    local_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
    token: DplpmtudWireToken,
) -> Result<Vec<u8>, String> {
    let target_plaintext = usize::try_from(token.candidate_udp_datagram_size.0)
        .ok()
        .and_then(|target| target.checked_sub(WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize))
        .ok_or_else(|| "candidate UDP datagram is smaller than WireGuard overhead".to_string())?;
    let target_payload = target_plaintext
        .checked_sub(INNER_IPV4_ICMP_OVERHEAD)
        .ok_or_else(|| "candidate UDP datagram cannot carry IPv4/ICMP framing".to_string())?;
    let fixed_payload = DPLPMTUD_PROBE_PREFIX.len() + DPLPMTUD_TOKEN_BYTES;
    if target_payload < fixed_payload {
        return Err(format!(
            "candidate UDP datagram {} is smaller than DPLPMTUD fixed framing {}",
            token.candidate_udp_datagram_size.0,
            fixed_payload + INNER_IPV4_ICMP_OVERHEAD + WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize,
        ));
    }
    let mut payload = Vec::with_capacity(target_payload);
    payload.extend_from_slice(DPLPMTUD_PROBE_PREFIX);
    encode_wire_token(&mut payload, token);
    payload.resize(target_payload, 0);
    let packet = Ipv4Packet::build_icmp_echo_request(
        local_virtual_ip,
        peer_virtual_ip,
        (token.sequence as u16).max(1),
        (token.sequence as u16).wrapping_add(1),
        &payload,
    );
    if packet.len() != target_plaintext {
        return Err(format!(
            "DPLPMTUD plaintext size mismatch: built={} expected={target_plaintext}",
            packet.len(),
        ));
    }
    Ok(packet)
}

pub(crate) fn build_ack_inner_packet(
    local_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
    token: DplpmtudWireToken,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(DPLPMTUD_ACK_PREFIX.len() + DPLPMTUD_TOKEN_BYTES);
    payload.extend_from_slice(DPLPMTUD_ACK_PREFIX);
    encode_wire_token(&mut payload, token);
    Ipv4Packet::build_icmp_echo_request(
        local_virtual_ip,
        peer_virtual_ip,
        (token.sequence as u16).max(1),
        (token.sequence as u16).wrapping_add(1),
        &payload,
    )
}

pub(crate) fn parse_control_packet(packet: &[u8]) -> Option<DplpmtudControlPacket> {
    let ip = Ipv4Packet::new(packet).ok()?;
    if ip.protocol() != Protocol::Icmp {
        return None;
    }
    let icmp = ip.payload();
    if icmp.len() < 8 || icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    let payload = &icmp[8..];
    let (kind, token_bytes) = if let Some(bytes) = payload.strip_prefix(DPLPMTUD_PROBE_PREFIX) {
        (DplpmtudControlKind::Probe, bytes)
    } else {
        let bytes = payload.strip_prefix(DPLPMTUD_ACK_PREFIX)?;
        (DplpmtudControlKind::Ack, bytes)
    };
    let token = decode_wire_token(token_bytes)?;
    let ceiling = token.outer_ip_family.ceiling_udp_datagram_size().0;
    if token.candidate_udp_datagram_size.0 < DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
        || token.candidate_udp_datagram_size.0 > ceiling
    {
        return None;
    }
    Some(DplpmtudControlPacket { kind, token })
}

fn encode_wire_token(output: &mut Vec<u8>, token: DplpmtudWireToken) {
    output.extend_from_slice(&token.sequence.to_be_bytes());
    output.extend_from_slice(&token.nonce);
    output.extend_from_slice(&token.path_cookie);
    output.extend_from_slice(&token.network_generation.to_be_bytes());
    output.extend_from_slice(&token.peer_session_generation.to_be_bytes());
    output.extend_from_slice(&token.remote_candidate_epoch.to_be_bytes());
    output.extend_from_slice(&token.direct_validation_owner_token.to_be_bytes());
    output.extend_from_slice(&token.direct_validation_request_id.to_be_bytes());
    output.extend_from_slice(&token.candidate_udp_datagram_size.0.to_be_bytes());
    output.push(match token.outer_ip_family {
        OuterIpFamily::Ipv4 => 4,
        OuterIpFamily::Ipv6 => 6,
    });
}

fn decode_wire_token(bytes: &[u8]) -> Option<DplpmtudWireToken> {
    if bytes.len() < DPLPMTUD_TOKEN_BYTES {
        return None;
    }
    let mut cursor = 0usize;
    let sequence = take_u64(bytes, &mut cursor)?;
    let nonce = take_array::<16>(bytes, &mut cursor)?;
    let path_cookie = take_array::<16>(bytes, &mut cursor)?;
    let network_generation = take_u64(bytes, &mut cursor)?;
    let peer_session_generation = take_u64(bytes, &mut cursor)?;
    let remote_candidate_epoch = take_u64(bytes, &mut cursor)?;
    let direct_validation_owner_token = take_u64(bytes, &mut cursor)?;
    let direct_validation_request_id = take_u16(bytes, &mut cursor)?;
    let candidate_udp_datagram_size = UdpDatagramSize(take_u32(bytes, &mut cursor)?);
    let outer_ip_family = match *bytes.get(cursor)? {
        4 => OuterIpFamily::Ipv4,
        6 => OuterIpFamily::Ipv6,
        _ => return None,
    };
    Some(DplpmtudWireToken {
        sequence,
        nonce,
        path_cookie,
        network_generation,
        peer_session_generation,
        remote_candidate_epoch,
        direct_validation_owner_token,
        direct_validation_request_id,
        candidate_udp_datagram_size,
        outer_ip_family,
    })
}

fn take_array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Option<[u8; N]> {
    let end = cursor.checked_add(N)?;
    let value = bytes.get(*cursor..end)?.try_into().ok()?;
    *cursor = end;
    Some(value)
}

fn take_u64(bytes: &[u8], cursor: &mut usize) -> Option<u64> {
    Some(u64::from_be_bytes(take_array(bytes, cursor)?))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Option<u32> {
    Some(u32::from_be_bytes(take_array(bytes, cursor)?))
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Option<u16> {
    Some(u16::from_be_bytes(take_array(bytes, cursor)?))
}

/// Build a compatibility-shaped Direct-validation packet carrying a DPLPMTUD
/// Probe. The fixed Direct-validation tail remains at the end for old decoders.
pub(crate) fn build_encrypted_probe_plaintext(
    local_virtual_ip: Ipv4Addr,
    peer_virtual_ip: Ipv4Addr,
    identity: &DplpmtudPathIdentity,
    plan: &DplpmtudProbePlan,
) -> Result<Vec<u8>, String> {
    let dplpmtud = build_probe_inner_packet(local_virtual_ip, peer_virtual_ip, plan.wire_token)?;
    // The DPLPMTUD inner packet itself is the authenticated WireGuard
    // plaintext. It is parsed before ordinary Direct-validation handling.
    debug_assert_eq!(identity.peer_id, plan.peer_id);
    Ok(dplpmtud)
}

#[derive(Debug, Clone)]
pub(crate) struct DplpmtudProbePlan {
    pub(crate) peer_id: String,
    pub(crate) worker_owner_token: u64,
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) probe_identity: DplpmtudProbeIdentity,
    pub(crate) wire_token: DplpmtudWireToken,
    pub(crate) deadline: Instant,
}

#[derive(Debug)]
pub(crate) struct DplpmtudWorkerLease {
    pub(crate) peer_id: String,
    pub(crate) worker_owner_token: u64,
    pub(crate) identity: DplpmtudPathIdentity,
    pub(crate) cancel_rx: watch::Receiver<bool>,
    pub(crate) notify: Arc<Notify>,
}

#[derive(Debug)]
pub(crate) struct DplpmtudWorkerStart {
    pub(crate) lease: DplpmtudWorkerLease,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) local_virtual_ip: Ipv4Addr,
    pub(crate) peer_virtual_ip: Ipv4Addr,
}

#[derive(Clone, Default)]
pub(crate) struct DplpmtudWorkerIngress {
    state: Arc<StdMutex<VecDeque<DplpmtudWorkerStart>>>,
    notify: Arc<Notify>,
}

impl DplpmtudWorkerIngress {
    pub(crate) fn submit(&self, start: DplpmtudWorkerStart) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.len() >= MAX_TRACKED_DPLPMTUD_PEERS {
            return false;
        }
        state.push_back(start);
        drop(state);
        self.notify.notify_one();
        true
    }

    pub(crate) async fn next(&self) -> DplpmtudWorkerStart {
        loop {
            let notified = self.notify.notified();
            if let Some(start) = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
            {
                return start;
            }
            notified.await;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DplpmtudInstallDecision {
    Spawned,
    Unchanged,
    Unsupported,
    Closed,
    CapacityExceeded,
    OwnerTokenExhausted,
}

#[derive(Debug)]
pub(crate) struct DplpmtudInstallResult {
    pub(crate) decision: DplpmtudInstallDecision,
    pub(crate) worker: Option<DplpmtudWorkerLease>,
}

/// Read-only budget returned for one exact committed path.  The lookup is
/// keyed by peer in the runtime registry and then fenced by the complete path
/// identity; it never clones the all-peer diagnostics table.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudConfirmedBudget {
    pub(crate) budget_revision: u64,
    pub(crate) udp_datagram_size: UdpDatagramSize,
    pub(crate) outer_ip_packet_size: OuterIpPacketSize,
    pub(crate) overlay_payload_budget: OverlayPayloadBudget,
}

/// Immutable confirmed budget consumed by normal Direct business traffic.
/// The full path identity deliberately travels with the value rather than
/// living only in the map key, closing endpoint/socket/publication ABA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessBudgetPublication {
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) budget_revision: u64,
    pub(crate) udp_datagram_size: UdpDatagramSize,
    pub(crate) overlay_payload_budget: OverlayPayloadBudget,
}

/// Every business-visible revision is published, including `Some -> None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessBudgetUpdate {
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) budget_revision: u64,
    pub(crate) budget: Option<DirectBusinessBudgetPublication>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessBudgetMirrorEntry {
    /// False only when this exact platform/path is intentionally legacy-
    /// compatible (capability absent or no-fragment unavailable).
    pub(crate) enforced: bool,
    pub(crate) update: DirectBusinessBudgetUpdate,
}

/// Token captured before WireGuard encryption and revalidated at the exact
/// UDP syscall boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DirectBusinessSendToken {
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) budget_revision: u64,
    pub(crate) max_udp_datagram_size: UdpDatagramSize,
    pub(crate) max_overlay_payload_size: OverlayPayloadBudget,
    pub(crate) udp_publication_owner: u64,
}

struct RuntimeEntry {
    machine: DplpmtudStateMachine,
    budget_revision: Option<u64>,
    budget_revision_state: DplpmtudBudgetRevisionState,
    path_cookie: [u8; 16],
    worker_owner_token: Option<u64>,
    cancel_tx: Option<watch::Sender<bool>>,
    notify: Arc<Notify>,
    worker_running: bool,
    send_in_progress: bool,
    business_enforced: bool,
}

#[derive(Default)]
struct RuntimeRegistry {
    entries: HashMap<String, RuntimeEntry>,
    supported_sessions: HashMap<String, u64>,
    ack_response_times: HashMap<String, VecDeque<Instant>>,
    closed: bool,
}

/// Bounded, cloneable registry shared by one UDP publication, its scheduler,
/// receive path and diagnostics. No network I/O occurs while the mutex is held.
#[derive(Clone)]
pub(crate) struct DplpmtudRuntime {
    registry: Arc<StdMutex<RuntimeRegistry>>,
    snapshots: Arc<StdRwLock<HashMap<String, DplpmtudSnapshot>>>,
    next_worker_owner_token: Arc<AtomicU64>,
    /// Latest immutable per-peer business publication. Readers clone one Arc
    /// through Tokio watch and never touch `registry`.
    business_publications: watch::Sender<Arc<HashMap<String, DirectBusinessBudgetMirrorEntry>>>,
    /// Serializes budget/owner revocation against the final nonblocking UDP
    /// syscall. It is intentionally independent from the DPLPMTUD registry.
    business_publication_gate: Arc<StdMutex<()>>,
    business_change_notifier: Option<watch::Sender<u64>>,
}

impl Default for DplpmtudRuntime {
    fn default() -> Self {
        let (business_publications, _) = watch::channel(Arc::new(HashMap::new()));
        Self {
            registry: Arc::new(StdMutex::new(RuntimeRegistry::default())),
            snapshots: Arc::new(StdRwLock::new(HashMap::new())),
            next_worker_owner_token: Arc::new(AtomicU64::new(1)),
            business_publications,
            business_publication_gate: Arc::new(StdMutex::new(())),
            business_change_notifier: None,
        }
    }
}

impl DplpmtudRuntime {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn new_with_business_change_notifier(notifier: watch::Sender<u64>) -> Self {
        Self {
            business_change_notifier: Some(notifier),
            ..Self::default()
        }
    }

    fn allocate_worker_owner_token(&self) -> Option<u64> {
        self.next_worker_owner_token
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .filter(|token| *token != 0)
    }

    fn allocate_budget_revision(&self) -> Option<u64> {
        NEXT_DPLPMTUD_BUDGET_REVISION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .filter(|revision| *revision != 0)
    }

    fn refresh_budget_revision(&self, entry: &mut RuntimeEntry) {
        let next_state = entry.machine.budget_revision_state();
        if next_state != entry.budget_revision_state {
            entry.budget_revision = self.allocate_budget_revision();
            entry.budget_revision_state = next_state;
        }
    }

    pub(crate) fn admit_probe_response(&self, peer_id: &str, now: Instant) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        registry.ack_response_times.retain(|_, sent| {
            while sent.front().is_some_and(|sent_at| {
                now.saturating_duration_since(*sent_at) >= DPLPMTUD_ACK_RATE_WINDOW
            }) {
                sent.pop_front();
            }
            !sent.is_empty()
        });
        if !registry.ack_response_times.contains_key(peer_id)
            && registry.ack_response_times.len() >= MAX_TRACKED_DPLPMTUD_PEERS
        {
            return false;
        }
        let sent = registry
            .ack_response_times
            .entry(peer_id.to_string())
            .or_default();
        if sent.len() >= DPLPMTUD_ACK_RATE_LIMIT_PER_PEER {
            return false;
        }
        sent.push_back(now);
        true
    }

    pub(crate) fn mark_supported(&self, peer_id: &str, peer_session_generation: u64) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        if !registry.supported_sessions.contains_key(peer_id)
            && registry.supported_sessions.len() >= MAX_TRACKED_DPLPMTUD_PEERS
        {
            return false;
        }
        registry
            .supported_sessions
            .insert(peer_id.to_string(), peer_session_generation)
            != Some(peer_session_generation)
    }

    #[cfg(test)]
    pub(crate) fn is_supported(&self, peer_id: &str, peer_session_generation: u64) -> bool {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .supported_sessions
            .get(peer_id)
            .is_some_and(|generation| *generation == peer_session_generation)
    }

    #[allow(dead_code)]
    pub(crate) fn install_path(
        &self,
        identity: DplpmtudPathIdentity,
        supported: bool,
        now: Instant,
    ) -> DplpmtudInstallResult {
        self.install_path_with_reason(
            identity,
            supported,
            if supported {
                "direct_committed"
            } else {
                "dplpmtud_capability_not_negotiated"
            },
            now,
        )
    }

    pub(crate) fn install_path_with_reason(
        &self,
        identity: DplpmtudPathIdentity,
        supported: bool,
        unsupported_reason: &str,
        now: Instant,
    ) -> DplpmtudInstallResult {
        let peer_id = identity.peer_id.clone();
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::Closed,
                worker: None,
            };
        }
        if !registry.entries.contains_key(&peer_id)
            && registry.entries.len() >= MAX_TRACKED_DPLPMTUD_PEERS
        {
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::CapacityExceeded,
                worker: None,
            };
        }

        if let Some(existing) = registry.entries.get_mut(&peer_id) {
            if existing.machine.identity() == Some(&identity) {
                existing.business_enforced = supported;
                if supported
                    && existing.worker_running
                    && existing.worker_owner_token.is_some()
                    && !matches!(
                        existing.machine.state(),
                        DplpmtudState::Disabled | DplpmtudState::Unsupported
                    )
                {
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Unchanged,
                        worker: None,
                    };
                }
                if supported {
                    let Some(worker_owner_token) = self.allocate_worker_owner_token() else {
                        return DplpmtudInstallResult {
                            decision: DplpmtudInstallDecision::OwnerTokenExhausted,
                            worker: None,
                        };
                    };
                    if matches!(
                        existing.machine.state(),
                        DplpmtudState::Disabled | DplpmtudState::Unsupported
                    ) {
                        rand::thread_rng().fill_bytes(&mut existing.path_cookie);
                        existing.machine = DplpmtudStateMachine::for_path_with_reason(
                            identity.clone(),
                            true,
                            "direct_committed",
                        );
                    }
                    let (cancel_tx, cancel_rx) = watch::channel(false);
                    existing.worker_owner_token = Some(worker_owner_token);
                    existing.cancel_tx = Some(cancel_tx);
                    existing.worker_running = true;
                    existing.send_in_progress = false;
                    let notify = existing.notify.clone();
                    self.publish_snapshot_locked(&peer_id, existing, now);
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Spawned,
                        worker: Some(DplpmtudWorkerLease {
                            peer_id,
                            worker_owner_token,
                            identity,
                            cancel_rx,
                            notify,
                        }),
                    };
                }
                if existing.machine.state() == DplpmtudState::Unsupported
                    && !existing.worker_running
                    && existing.worker_owner_token.is_none()
                    && existing.cancel_tx.is_none()
                {
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Unsupported,
                        worker: None,
                    };
                }
                if let Some(cancel_tx) = existing.cancel_tx.take() {
                    let _ = cancel_tx.send(true);
                }
                existing.worker_owner_token = None;
                existing.worker_running = false;
                existing.send_in_progress = false;
                existing.machine =
                    DplpmtudStateMachine::for_path_with_reason(identity, false, unsupported_reason);
                self.publish_snapshot_locked(&peer_id, existing, now);
                return DplpmtudInstallResult {
                    decision: DplpmtudInstallDecision::Unsupported,
                    worker: None,
                };
            }
            if let Some(cancel_tx) = existing.cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
            existing.worker_owner_token = None;
            existing.worker_running = false;
            existing.send_in_progress = false;
        }

        let mut path_cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut path_cookie);
        let notify = Arc::new(Notify::new());
        if !supported {
            let machine =
                DplpmtudStateMachine::for_path_with_reason(identity, false, unsupported_reason);
            let entry = RuntimeEntry {
                budget_revision: self.allocate_budget_revision(),
                budget_revision_state: machine.budget_revision_state(),
                machine,
                path_cookie,
                worker_owner_token: None,
                cancel_tx: None,
                notify,
                worker_running: false,
                send_in_progress: false,
                business_enforced: false,
            };
            registry.entries.insert(peer_id.clone(), entry);
            let entry = registry
                .entries
                .get_mut(&peer_id)
                .expect("entry inserted above");
            self.publish_snapshot_locked(&peer_id, entry, now);
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::Unsupported,
                worker: None,
            };
        }

        let Some(worker_owner_token) = self.allocate_worker_owner_token() else {
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::OwnerTokenExhausted,
                worker: None,
            };
        };
        let (cancel_tx, cancel_rx) = watch::channel(false);
        let machine = DplpmtudStateMachine::for_path(identity.clone(), true, now);
        let entry = RuntimeEntry {
            budget_revision: self.allocate_budget_revision(),
            budget_revision_state: machine.budget_revision_state(),
            machine,
            path_cookie,
            worker_owner_token: Some(worker_owner_token),
            cancel_tx: Some(cancel_tx),
            notify: notify.clone(),
            worker_running: true,
            send_in_progress: false,
            business_enforced: true,
        };
        registry.entries.insert(peer_id.clone(), entry);
        let entry = registry
            .entries
            .get_mut(&peer_id)
            .expect("entry inserted above");
        self.publish_snapshot_locked(&peer_id, entry, now);
        DplpmtudInstallResult {
            decision: DplpmtudInstallDecision::Spawned,
            worker: Some(DplpmtudWorkerLease {
                peer_id,
                worker_owner_token,
                identity,
                cancel_rx,
                notify,
            }),
        }
    }

    pub(crate) fn retain_known_peers(&self, peers: &HashSet<String>, now: Instant) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let removed = registry
            .entries
            .keys()
            .filter(|peer_id| !peers.contains(*peer_id))
            .cloned()
            .collect::<Vec<_>>();
        for peer_id in removed {
            if let Some(mut entry) = registry.entries.remove(&peer_id) {
                if let Some(cancel_tx) = entry.cancel_tx.take() {
                    let _ = cancel_tx.send(true);
                }
                let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
                    reason: "peer_left".to_string(),
                    now,
                });
                self.refresh_budget_revision(&mut entry);
                self.publish_direct_business_budget_locked(&peer_id, &entry);
            }
            registry.supported_sessions.remove(&peer_id);
            registry.ack_response_times.remove(&peer_id);
            self.snapshots
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .remove(&peer_id);
        }
    }

    pub(crate) fn cancel_before_network_generation(
        &self,
        generation: u64,
        reason: &str,
        now: Instant,
    ) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let peer_ids = registry
            .entries
            .iter()
            .filter_map(|(peer_id, entry)| {
                entry
                    .machine
                    .identity()
                    .filter(|identity| identity.epoch.network_generation != generation)
                    .map(|_| peer_id.clone())
            })
            .collect::<Vec<_>>();
        for peer_id in peer_ids {
            let Some(entry) = registry.entries.get_mut(&peer_id) else {
                continue;
            };
            if let Some(cancel_tx) = entry.cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
            entry.worker_owner_token = None;
            entry.worker_running = false;
            entry.send_in_progress = false;
            let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
                reason: reason.to_string(),
                now,
            });
            entry.notify.notify_waiters();
            self.publish_snapshot_locked(&peer_id, entry, now);
        }
    }

    pub(crate) fn cancel_peer(&self, peer_id: &str, reason: &str, now: Instant) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(peer_id) else {
            return;
        };
        if let Some(cancel_tx) = entry.cancel_tx.take() {
            let _ = cancel_tx.send(true);
        }
        entry.worker_owner_token = None;
        entry.worker_running = false;
        entry.send_in_progress = false;
        let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
            reason: reason.to_string(),
            now,
        });
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(peer_id, entry, now);
    }

    pub(crate) fn close(&self, reason: &str, now: Instant) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        registry.closed = true;
        for (peer_id, entry) in &mut registry.entries {
            if let Some(cancel_tx) = entry.cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
            entry.worker_owner_token = None;
            entry.worker_running = false;
            entry.send_in_progress = false;
            let _ = entry.machine.apply(DplpmtudEvent::Cancelled {
                reason: reason.to_string(),
                now,
            });
            entry.notify.notify_waiters();
            self.publish_snapshot_locked(peer_id, entry, now);
        }
        registry.supported_sessions.clear();
        registry.ack_response_times.clear();
    }

    pub(crate) fn schedule_probe(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
        worker_owner_token: u64,
        now: Instant,
    ) -> Option<DplpmtudProbePlan> {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return None;
        }
        let entry = registry.entries.get_mut(peer_id)?;
        if !entry.worker_running
            || entry.worker_owner_token != Some(worker_owner_token)
            || entry.machine.identity() != Some(identity)
        {
            return None;
        }
        if entry.machine.state() == DplpmtudState::Base {
            let _ = entry.machine.apply(DplpmtudEvent::StartSearch { now });
        }
        if entry.machine.state() == DplpmtudState::SearchComplete {
            let _ = entry
                .machine
                .apply(DplpmtudEvent::CurrentPlpmtuConfirmationTimerExpired { now });
        }
        if matches!(
            entry.machine.state(),
            DplpmtudState::SearchComplete | DplpmtudState::Error
        ) && entry
            .machine
            .next_wakeup()
            .is_some_and(|deadline| now >= deadline)
        {
            let _ = entry
                .machine
                .apply(DplpmtudEvent::RaiseTimerExpired { now });
        }
        let (sequence, candidate, retry) = entry.machine.next_probe_components()?;
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let probe_identity = DplpmtudProbeIdentity {
            sequence,
            nonce,
            path_cookie: entry.path_cookie,
            candidate_udp_datagram_size: candidate,
        };
        let deadline = now + DPLPMTUD_PROBE_TIMEOUT;
        if entry.machine.apply(DplpmtudEvent::ProbeScheduled {
            probe: probe_identity,
            retry,
            now,
            deadline,
        }) != DplpmtudTransitionDecision::Applied
        {
            return None;
        }
        let wire_token = DplpmtudWireToken {
            sequence,
            nonce,
            path_cookie: entry.path_cookie,
            network_generation: identity.epoch.network_generation,
            peer_session_generation: identity.epoch.peer_session_generation.value(),
            remote_candidate_epoch: identity.epoch.remote_candidate_epoch,
            direct_validation_owner_token: identity.direct_validation_owner_token,
            direct_validation_request_id: identity.direct_validation_request_id,
            candidate_udp_datagram_size: candidate,
            outer_ip_family: identity.outer_ip_family,
        };
        self.publish_snapshot_locked(peer_id, entry, now);
        Some(DplpmtudProbePlan {
            peer_id: peer_id.to_string(),
            worker_owner_token,
            path_identity: identity.clone(),
            probe_identity,
            wire_token,
            deadline,
        })
    }

    /// Linearization point immediately before a worker attempts the kernel
    /// send. Marking the probe sent here, before socket I/O, prevents a fast
    /// authenticated ACK from racing ahead of the send bookkeeping.
    pub(crate) fn begin_probe_send(&self, plan: &DplpmtudProbePlan, now: Instant) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        let Some(entry) = registry.entries.get_mut(&plan.peer_id) else {
            return false;
        };
        if !entry.worker_running
            || entry.worker_owner_token != Some(plan.worker_owner_token)
            || entry.machine.identity() != Some(&plan.path_identity)
            || entry.machine.outstanding_identity() != Some(plan.probe_identity)
            || entry.send_in_progress
            || now >= plan.deadline
        {
            return false;
        }
        if entry.machine.apply(DplpmtudEvent::ProbeSent {
            probe: plan.probe_identity,
            now,
        }) != DplpmtudTransitionDecision::Applied
        {
            return false;
        }
        entry.send_in_progress = true;
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&plan.peer_id, entry, now);
        true
    }

    pub(crate) fn finish_probe_send(
        &self,
        plan: &DplpmtudProbePlan,
        result: Result<(), DplpmtudProbeSendFailure>,
        now: Instant,
    ) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(&plan.peer_id) else {
            return;
        };
        if entry.worker_owner_token != Some(plan.worker_owner_token)
            || entry.machine.identity() != Some(&plan.path_identity)
        {
            return;
        }
        entry.send_in_progress = false;
        match result {
            Ok(()) => {}
            Err(failure) => {
                let _ = entry.machine.apply(DplpmtudEvent::ProbeSendFailed {
                    probe: plan.probe_identity,
                    failure,
                    now,
                });
            }
        }
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&plan.peer_id, entry, now);
    }

    pub(crate) fn timeout_probe(
        &self,
        plan: &DplpmtudProbePlan,
        now: Instant,
    ) -> DplpmtudTransitionDecision {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(&plan.peer_id) else {
            return DplpmtudTransitionDecision::Noop;
        };
        if entry.worker_owner_token != Some(plan.worker_owner_token)
            || entry.machine.identity() != Some(&plan.path_identity)
        {
            return DplpmtudTransitionDecision::Noop;
        }
        let decision = entry.machine.apply(DplpmtudEvent::ProbeTimedOut {
            probe: plan.probe_identity,
            now,
        });
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&plan.peer_id, entry, now);
        decision
    }

    /// Consume an ACK while the caller holds the upper lifecycle/epoch fence.
    /// Contention fails closed instead of awaiting a lower registry lock.
    pub(crate) fn try_accept_ack(
        &self,
        peer_id: &str,
        current_path: &DplpmtudPathIdentity,
        token: DplpmtudWireToken,
        ingress: DplpmtudAckIngress,
        now: Instant,
    ) -> DplpmtudTransitionDecision {
        let Ok(mut registry) = self.registry.try_lock() else {
            return DplpmtudTransitionDecision::Busy;
        };
        if registry.closed {
            return DplpmtudTransitionDecision::Stale;
        }
        let Some(entry) = registry.entries.get_mut(peer_id) else {
            return DplpmtudTransitionDecision::Stale;
        };
        let exact_wire_identity = token.network_generation == current_path.epoch.network_generation
            && token.peer_session_generation == current_path.epoch.peer_session_generation.value()
            && token.remote_candidate_epoch == current_path.epoch.remote_candidate_epoch
            && token.direct_validation_owner_token == current_path.direct_validation_owner_token
            && token.direct_validation_request_id == current_path.direct_validation_request_id
            && token.outer_ip_family == current_path.outer_ip_family;
        let exact_ingress = ingress.remote_endpoint == current_path.authenticated_remote_endpoint
            && ingress.local_endpoint == current_path.local_endpoint
            && ingress.socket == current_path.socket;
        let worker_is_current = entry.worker_running && entry.worker_owner_token.is_some();
        let decision = if !worker_is_current
            || entry.machine.identity() != Some(current_path)
            || !exact_wire_identity
            || !exact_ingress
        {
            entry.machine.apply(DplpmtudEvent::StaleAck { now })
        } else {
            entry.machine.apply(DplpmtudEvent::ProbeAcked {
                probe: token.probe_identity(),
                now,
            })
        };
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(peer_id, entry, now);
        decision
    }

    pub(crate) fn outstanding_is_current(&self, plan: &DplpmtudProbePlan) -> bool {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(&plan.peer_id)
            .is_some_and(|entry| {
                entry.worker_running
                    && entry.worker_owner_token == Some(plan.worker_owner_token)
                    && entry.machine.identity() == Some(&plan.path_identity)
                    && entry.machine.outstanding_identity() == Some(plan.probe_identity)
            })
    }

    pub(crate) fn worker_state(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
        worker_owner_token: u64,
    ) -> Option<(
        DplpmtudState,
        Option<Instant>,
        Option<DplpmtudProbeIdentity>,
    )> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(peer_id)
            .filter(|entry| {
                entry.worker_owner_token == Some(worker_owner_token)
                    && entry.machine.identity() == Some(identity)
            })
            .map(|entry| {
                (
                    entry.machine.state(),
                    entry.machine.next_wakeup(),
                    entry.machine.outstanding_identity(),
                )
            })
    }

    pub(crate) fn finish_worker(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
        worker_owner_token: u64,
    ) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(peer_id) else {
            return;
        };
        if entry.worker_owner_token == Some(worker_owner_token)
            && entry.machine.identity() == Some(identity)
        {
            entry.worker_owner_token = None;
            entry.worker_running = false;
            entry.send_in_progress = false;
            entry.cancel_tx = None;
            self.publish_snapshot_locked(peer_id, entry, Instant::now());
        }
    }

    pub(crate) fn path_identity(&self, peer_id: &str) -> Option<DplpmtudPathIdentity> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .get(peer_id)
            .and_then(|entry| entry.machine.identity().cloned())
    }

    pub(crate) fn snapshots(&self) -> HashMap<String, DplpmtudSnapshot> {
        self.snapshots
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// Read one peer's diagnostics without cloning the all-peer table.
    pub(crate) fn snapshot_for_peer(&self, peer_id: &str) -> Option<DplpmtudSnapshot> {
        self.snapshots
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(peer_id)
            .cloned()
    }

    /// Read one exact path's diagnostics without cloning the all-peer table.
    /// This is for control/timeline reporting; business packetization uses
    /// the immutable publication mirror instead.
    pub(crate) fn snapshot_for_path(
        &self,
        identity: &DplpmtudPathIdentity,
    ) -> Option<DplpmtudSnapshot> {
        let expected = identity.summary();
        let snapshot = self.snapshot_for_peer(&identity.peer_id)?;
        (snapshot.path_identity.as_ref() == Some(&expected)).then_some(snapshot)
    }

    /// O(1) per-peer confirmed-budget read for the business consumer.  The
    /// exact identity check prevents a budget from a replaced endpoint,
    /// generation, candidate epoch, or socket publication from being reused.
    /// Business hot paths must use this accessor rather than `snapshots()`.
    #[allow(dead_code)]
    pub(crate) fn confirmed_budget_for_path(
        &self,
        identity: &DplpmtudPathIdentity,
    ) -> Option<DplpmtudConfirmedBudget> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return None;
        }
        let entry = registry.entries.get(&identity.peer_id)?;
        if entry.machine.identity() != Some(identity)
            || !entry.machine.supported
            || matches!(
                entry.machine.state(),
                DplpmtudState::Disabled | DplpmtudState::Unsupported
            )
            || !entry.machine.base_confirmed
        {
            return None;
        }
        let udp_datagram_size = entry.machine.business_confirmed_udp_datagram_size()?;
        let budget_revision = entry.budget_revision?;
        let outer_ip_packet_size = udp_datagram_size.outer_ip_packet_size(identity.outer_ip_family);
        let overlay_payload_budget = udp_datagram_size.overlay_payload_budget()?;
        Some(DplpmtudConfirmedBudget {
            budget_revision,
            udp_datagram_size,
            outer_ip_packet_size,
            overlay_payload_budget,
        })
    }

    /// Registry-free read used by the business data plane. Tokio watch owns
    /// one immutable, bounded map; cloning this entry never acquires the
    /// mutable DPLPMTUD registry mutex.
    pub(crate) fn direct_business_budget_entry(
        &self,
        peer_id: &str,
    ) -> Option<DirectBusinessBudgetMirrorEntry> {
        self.business_publications.borrow().get(peer_id).cloned()
    }

    /// Test seam for proving that the production post-encryption check uses
    /// the real WireGuard datagram length rather than the plaintext estimate.
    /// It intentionally makes one immutable publication conservative while
    /// leaving the reducer state untouched.
    #[cfg(test)]
    pub(crate) fn force_business_udp_budget_for_test(
        &self,
        peer_id: &str,
        udp_datagram_size: UdpDatagramSize,
    ) -> bool {
        self.with_business_publication_gate(|| {
            let current = self.business_publications.borrow().clone();
            let mut next = (*current).clone();
            let Some(entry) = next.get_mut(peer_id) else {
                return false;
            };
            let Some(publication) = entry.update.budget.as_mut() else {
                return false;
            };
            publication.udp_datagram_size = udp_datagram_size;
            self.business_publications.send_replace(Arc::new(next));
            if let Some(notifier) = self.business_change_notifier.as_ref() {
                notifier.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
            }
            true
        })
    }

    /// Serialize UDP publication-owner stores with the final business send.
    /// This gate is deliberately independent from `registry`; holding the
    /// registry in a test or worker cannot delay a confirmed business send.
    pub(crate) fn with_business_publication_gate<R>(&self, operation: impl FnOnce() -> R) -> R {
        let _guard = self
            .business_publication_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        operation()
    }

    /// Final budget linearization point. If this returns `Some`, the token was
    /// current for the entire synchronous operation (normally one
    /// `UdpSocket::try_send_to` syscall). A revocation that wins the gate makes
    /// this return `None`; a send that wins is ordered before the revocation.
    pub(crate) fn with_current_direct_business_token<R>(
        &self,
        token: &DirectBusinessSendToken,
        operation: impl FnOnce() -> R,
    ) -> Option<R> {
        self.with_business_publication_gate(|| {
            let publications = self.business_publications.borrow();
            let entry = publications.get(&token.path_identity.peer_id)?;
            if !entry.enforced
                || entry.update.path_identity != token.path_identity
                || entry.update.budget_revision != token.budget_revision
            {
                return None;
            }
            let publication = entry.update.budget.as_ref()?;
            if publication.path_identity != token.path_identity
                || publication.budget_revision != token.budget_revision
                || publication.udp_datagram_size != token.max_udp_datagram_size
                || publication.overlay_payload_budget != token.max_overlay_payload_size
            {
                return None;
            }
            Some(operation())
        })
    }

    /// Fail closed after a business EMSGSIZE (or an impossible actual-
    /// ciphertext overrun). Exact identity + revision make duplicate reports
    /// idempotent. No path-health or Relay state is touched here.
    pub(crate) fn invalidate_direct_business_budget(
        &self,
        token: &DirectBusinessSendToken,
        now: Instant,
    ) -> bool {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if registry.closed {
            return false;
        }
        let Some(entry) = registry.entries.get_mut(&token.path_identity.peer_id) else {
            return false;
        };
        if entry.machine.identity() != Some(&token.path_identity)
            || entry.budget_revision != Some(token.budget_revision)
            || entry
                .machine
                .business_confirmed_udp_datagram_size()
                .is_none()
        {
            return false;
        }
        if entry
            .machine
            .apply(DplpmtudEvent::BusinessPacketTooLarge { now })
            != DplpmtudTransitionDecision::Applied
        {
            return false;
        }
        entry.notify.notify_waiters();
        self.publish_snapshot_locked(&token.path_identity.peer_id, entry, now);
        true
    }

    #[cfg(test)]
    fn current_probe_token(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
    ) -> Option<DplpmtudWireToken> {
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = registry.entries.get(peer_id)?;
        if entry.machine.identity() != Some(identity) {
            return None;
        }
        let probe = entry.machine.outstanding.as_ref()?.identity;
        Some(DplpmtudWireToken {
            sequence: probe.sequence,
            nonce: probe.nonce,
            path_cookie: probe.path_cookie,
            network_generation: identity.epoch.network_generation,
            peer_session_generation: identity.epoch.peer_session_generation.value(),
            remote_candidate_epoch: identity.epoch.remote_candidate_epoch,
            direct_validation_owner_token: identity.direct_validation_owner_token,
            direct_validation_request_id: identity.direct_validation_request_id,
            candidate_udp_datagram_size: probe.candidate_udp_datagram_size,
            outer_ip_family: identity.outer_ip_family,
        })
    }

    #[cfg(test)]
    pub(crate) fn tracked_peer_count(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .len()
    }

    #[cfg(test)]
    pub(crate) fn active_worker_count(&self) -> usize {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entries
            .values()
            .filter(|entry| entry.worker_running && entry.worker_owner_token.is_some())
            .count()
    }

    fn publish_snapshot_locked(&self, peer_id: &str, entry: &mut RuntimeEntry, now: Instant) {
        self.refresh_budget_revision(entry);
        self.publish_direct_business_budget_locked(peer_id, entry);
        let mut snapshot = entry.machine.snapshot(now, entry.worker_running);
        snapshot.budget_revision = entry.budget_revision;
        self.snapshots
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(peer_id.to_string(), snapshot);
    }

    fn publish_direct_business_budget_locked(&self, peer_id: &str, entry: &RuntimeEntry) {
        let identity = entry.machine.identity().cloned();
        let revision = entry.budget_revision;
        self.with_business_publication_gate(|| {
            let current = self.business_publications.borrow().clone();
            let mut next = (*current).clone();
            let next_entry = identity
                .zip(revision)
                .map(|(path_identity, budget_revision)| {
                    let budget = entry
                        .machine
                        .business_confirmed_udp_datagram_size()
                        .and_then(|udp_datagram_size| {
                            udp_datagram_size.overlay_payload_budget().map(
                                |overlay_payload_budget| DirectBusinessBudgetPublication {
                                    path_identity: path_identity.clone(),
                                    budget_revision,
                                    udp_datagram_size,
                                    overlay_payload_budget,
                                },
                            )
                        });
                    DirectBusinessBudgetMirrorEntry {
                        enforced: entry.business_enforced,
                        update: DirectBusinessBudgetUpdate {
                            path_identity,
                            budget_revision,
                            budget,
                        },
                    }
                });

            let changed = match next_entry {
                Some(next_entry) => {
                    if !next.contains_key(peer_id) && next.len() >= MAX_TRACKED_DPLPMTUD_PEERS {
                        if let Some(tombstone) = next.iter().find_map(|(candidate, entry)| {
                            entry.update.budget.is_none().then(|| candidate.clone())
                        }) {
                            next.remove(&tombstone);
                        }
                    }
                    if (next.len() >= MAX_TRACKED_DPLPMTUD_PEERS && !next.contains_key(peer_id))
                        || next.get(peer_id) == Some(&next_entry)
                    {
                        false
                    } else {
                        next.insert(peer_id.to_string(), next_entry);
                        true
                    }
                }
                None => next.remove(peer_id).is_some(),
            };
            if changed {
                self.business_publications.send_replace(Arc::new(next));
                if let Some(notifier) = self.business_change_notifier.as_ref() {
                    notifier.send_modify(|sequence| *sequence = sequence.wrapping_add(1));
                }
            }
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudAckIngress {
    pub(crate) remote_endpoint: SocketAddr,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) socket: DplpmtudSocketIdentity,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::control::PeerInfo;
    use crate::dataplane::OutboundPacket;
    use crate::peer::{PeerManager, PeerSessionGeneration};
    use crate::transport::{DirectValidationKind, WireGuardTransport};
    use crate::udp::UdpTransport;
    use p2pnet_crypto::NodeIdentity;
    use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tokio::sync::{mpsc, watch};
    use tokio::time::timeout;

    fn test_identity(peer_id: &str) -> DplpmtudPathIdentity {
        test_identity_with(peer_id, 7, 11, 13, 17, 19, 23, 0)
    }

    #[allow(clippy::too_many_arguments)]
    fn test_identity_with(
        peer_id: &str,
        network_generation: u64,
        peer_session_generation: u64,
        remote_candidate_epoch: u64,
        validation_owner: u64,
        validation_request: u16,
        transport_instance_id: u64,
        socket_index: usize,
    ) -> DplpmtudPathIdentity {
        DplpmtudPathIdentity {
            peer_id: peer_id.to_string(),
            epoch: PathEpoch::new(
                network_generation,
                PeerSessionGeneration::for_test(peer_session_generation),
                remote_candidate_epoch,
            ),
            direct_validation_owner_token: validation_owner,
            direct_validation_request_id: validation_request,
            authenticated_remote_endpoint: "127.0.0.1:42002".parse().unwrap(),
            local_endpoint: "127.0.0.1:42001".parse().unwrap(),
            socket: DplpmtudSocketIdentity {
                transport_instance_id,
                socket_index,
            },
            outer_ip_family: OuterIpFamily::Ipv4,
        }
    }

    fn deterministic_probe(
        sequence: u64,
        candidate_udp_datagram_size: UdpDatagramSize,
    ) -> DplpmtudProbeIdentity {
        DplpmtudProbeIdentity {
            sequence,
            nonce: [sequence as u8; 16],
            path_cookie: [0x5a; 16],
            candidate_udp_datagram_size,
        }
    }

    fn schedule_and_mark_sent(
        machine: &mut DplpmtudStateMachine,
        now: Instant,
    ) -> (DplpmtudProbeIdentity, Instant) {
        if machine.state() == DplpmtudState::Base {
            assert_eq!(
                machine.apply(DplpmtudEvent::StartSearch { now }),
                DplpmtudTransitionDecision::Applied
            );
        }
        let (sequence, candidate, retry) = machine
            .next_probe_components()
            .expect("search must have a next candidate");
        let probe = deterministic_probe(sequence, candidate);
        let deadline = now + DPLPMTUD_PROBE_TIMEOUT;
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeScheduled {
                probe,
                retry,
                now,
                deadline,
            }),
            DplpmtudTransitionDecision::Applied
        );
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeSent {
                probe,
                now: now + Duration::from_millis(1),
            }),
            DplpmtudTransitionDecision::Applied
        );
        (probe, deadline)
    }

    fn positively_confirm_base(machine: &mut DplpmtudStateMachine, now: Instant) -> Instant {
        let (probe, _) = schedule_and_mark_sent(machine, now);
        assert_eq!(
            probe.candidate_udp_datagram_size.0,
            DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
        );
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeAcked {
                probe,
                now: now + Duration::from_millis(2),
            }),
            DplpmtudTransitionDecision::Applied
        );
        now + Duration::from_millis(3)
    }

    fn runtime_with_confirmed_base(
        identity: DplpmtudPathIdentity,
        now: Instant,
    ) -> (DplpmtudRuntime, DplpmtudWorkerLease) {
        let runtime = DplpmtudRuntime::new();
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .expect("supported path must own one worker");
        let plan = runtime
            .schedule_probe(&identity.peer_id, &identity, lease.worker_owner_token, now)
            .expect("BASE must be the first runtime probe");
        assert_eq!(
            plan.probe_identity.candidate_udp_datagram_size,
            UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
        );
        assert!(runtime.begin_probe_send(&plan, now));
        runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
        assert_eq!(
            runtime.try_accept_ack(
                &identity.peer_id,
                &identity,
                plan.wire_token,
                DplpmtudAckIngress {
                    remote_endpoint: identity.authenticated_remote_endpoint,
                    local_endpoint: identity.local_endpoint,
                    socket: identity.socket,
                },
                now + Duration::from_millis(2),
            ),
            DplpmtudTransitionDecision::Applied
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_some());
        (runtime, lease)
    }

    fn exact_ack_ingress(identity: &DplpmtudPathIdentity) -> DplpmtudAckIngress {
        DplpmtudAckIngress {
            remote_endpoint: identity.authenticated_remote_endpoint,
            local_endpoint: identity.local_endpoint,
            socket: identity.socket,
        }
    }

    fn business_token(
        entry: DirectBusinessBudgetMirrorEntry,
        publication_owner: u64,
    ) -> DirectBusinessSendToken {
        let publication = entry
            .update
            .budget
            .expect("test requires a confirmed business publication");
        DirectBusinessSendToken {
            path_identity: publication.path_identity,
            budget_revision: publication.budget_revision,
            max_udp_datagram_size: publication.udp_datagram_size,
            max_overlay_payload_size: publication.overlay_payload_budget,
            udp_publication_owner: publication_owner,
        }
    }

    fn schedule_and_mark_runtime_probe_sent(
        runtime: &DplpmtudRuntime,
        identity: &DplpmtudPathIdentity,
        lease: &DplpmtudWorkerLease,
        now: Instant,
    ) -> DplpmtudProbePlan {
        let plan = runtime
            .schedule_probe(&identity.peer_id, identity, lease.worker_owner_token, now)
            .expect("runtime search must have a next candidate");
        assert!(runtime.begin_probe_send(&plan, now));
        runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
        plan
    }

    fn ack_runtime_probe(
        runtime: &DplpmtudRuntime,
        identity: &DplpmtudPathIdentity,
        plan: &DplpmtudProbePlan,
        now: Instant,
    ) {
        assert_eq!(
            runtime.try_accept_ack(
                &identity.peer_id,
                identity,
                plan.wire_token,
                exact_ack_ingress(identity),
                now,
            ),
            DplpmtudTransitionDecision::Applied
        );
    }

    fn converge_runtime_to_threshold(
        runtime: &DplpmtudRuntime,
        identity: &DplpmtudPathIdentity,
        lease: &DplpmtudWorkerLease,
        mut now: Instant,
        threshold: u32,
    ) -> Instant {
        for _ in 0..96 {
            if runtime
                .snapshot_for_peer(&identity.peer_id)
                .is_some_and(|snapshot| snapshot.state == DplpmtudState::SearchComplete)
            {
                return now;
            }
            let plan = schedule_and_mark_runtime_probe_sent(runtime, identity, lease, now);
            if plan.probe_identity.candidate_udp_datagram_size.0 <= threshold {
                ack_runtime_probe(runtime, identity, &plan, now + Duration::from_millis(2));
                now += Duration::from_millis(3);
            } else {
                assert_eq!(
                    runtime.timeout_probe(&plan, plan.deadline),
                    DplpmtudTransitionDecision::Applied
                );
                now = plan.deadline + Duration::from_millis(1);
            }
        }
        panic!("bounded runtime DPLPMTUD search did not converge");
    }

    fn exhaust_runtime_current_confirmation(
        runtime: &DplpmtudRuntime,
        identity: &DplpmtudPathIdentity,
        lease: &DplpmtudWorkerLease,
        mut now: Instant,
        expected_candidate: UdpDatagramSize,
    ) -> Instant {
        let confirmation_at = runtime
            .worker_state(&identity.peer_id, identity, lease.worker_owner_token)
            .and_then(|(_, wakeup, _)| wakeup)
            .expect("SearchComplete must own a current-PLPMTU timer");
        now = now.max(confirmation_at);
        for _ in 0..=DPLPMTUD_MAX_RETRIES {
            let plan = schedule_and_mark_runtime_probe_sent(runtime, identity, lease, now);
            assert_eq!(
                plan.probe_identity.candidate_udp_datagram_size,
                expected_candidate
            );
            assert_eq!(
                runtime.timeout_probe(&plan, plan.deadline),
                DplpmtudTransitionDecision::Applied
            );
            now = plan.deadline + Duration::from_millis(1);
        }
        now
    }

    fn converge_machine_to_threshold(
        machine: &mut DplpmtudStateMachine,
        mut now: Instant,
        threshold: u32,
    ) -> Instant {
        for _ in 0..96 {
            if machine.state() == DplpmtudState::SearchComplete {
                return now;
            }
            let (probe, deadline) = schedule_and_mark_sent(machine, now);
            if probe.candidate_udp_datagram_size.0 <= threshold {
                assert_eq!(
                    machine.apply(DplpmtudEvent::ProbeAcked {
                        probe,
                        now: now + Duration::from_millis(2),
                    }),
                    DplpmtudTransitionDecision::Applied
                );
                now += Duration::from_millis(3);
            } else {
                assert_eq!(
                    machine.apply(DplpmtudEvent::ProbeTimedOut {
                        probe,
                        now: deadline,
                    }),
                    DplpmtudTransitionDecision::Applied
                );
                now = deadline + Duration::from_millis(1);
            }
        }
        panic!("bounded DPLPMTUD search did not converge");
    }

    #[test]
    fn unsupported_peer_stays_fail_closed_without_a_probe() {
        let now = Instant::now();
        let machine = DplpmtudStateMachine::for_path(test_identity("peer"), false, now);
        assert_eq!(machine.state(), DplpmtudState::Unsupported);
        assert!(machine.next_probe_components().is_none());
        let snapshot = machine.snapshot(now, false);
        assert!(!snapshot.supported);
        assert!(snapshot.outstanding_probe.is_none());
    }

    #[test]
    fn base_requires_a_positive_probe_before_any_confirmed_budget() {
        let mut now = Instant::now();
        let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
        let initial = machine.snapshot(now, false);
        assert_eq!(
            initial.assumed_base_udp_datagram_size,
            DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
        );
        assert!(!initial.base_confirmed);
        assert_eq!(initial.confirmed_udp_datagram_size, None);
        assert_eq!(initial.overlay_payload_budget, None);

        for _ in 0..=DPLPMTUD_MAX_RETRIES {
            let (probe, deadline) = schedule_and_mark_sent(&mut machine, now);
            assert_eq!(
                probe.candidate_udp_datagram_size.0,
                DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
            );
            assert_eq!(
                machine.apply(DplpmtudEvent::ProbeTimedOut {
                    probe,
                    now: deadline,
                }),
                DplpmtudTransitionDecision::Applied
            );
            now = deadline + Duration::from_millis(1);
        }
        assert_eq!(machine.state(), DplpmtudState::Error);
        let failed = machine.snapshot(now, false);
        assert!(!failed.base_confirmed);
        assert_eq!(failed.confirmed_udp_datagram_size, None);
        assert_eq!(failed.overlay_payload_budget, None);
        assert!(failed.outstanding_probe.is_none());

        let retry_at = machine.raise_at.expect("BASE Error owns a retry timer");
        assert_eq!(
            machine.apply(DplpmtudEvent::RaiseTimerExpired { now: retry_at }),
            DplpmtudTransitionDecision::Applied
        );
        assert_eq!(machine.state(), DplpmtudState::Base);
        assert_eq!(
            machine.next_probe_components().map(|(_, size, _)| size.0),
            Some(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
        );
        println!(
            "DPLPMTUD_BASE assumed={} positively_validated=false confirmed=none state={:?} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 old_ack_contamination=false task_leak=false",
            DPLPMTUD_BASE_UDP_DATAGRAM_SIZE,
            machine.state(),
        );
    }

    #[test]
    fn unsupported_same_identity_replay_is_idempotent() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        assert_eq!(
            runtime.install_path(identity.clone(), false, now).decision,
            DplpmtudInstallDecision::Unsupported
        );
        let first = runtime.snapshots().remove("peer").unwrap();

        assert_eq!(
            runtime
                .install_path(identity, false, now + Duration::from_secs(1))
                .decision,
            DplpmtudInstallDecision::Unsupported
        );
        let second = runtime.snapshots().remove("peer").unwrap();
        assert_eq!(second.state, DplpmtudState::Unsupported);
        assert!(!second.live_worker);
        assert_eq!(second.revision, first.revision);
        assert_eq!(second.reset_count, first.reset_count);
        assert_eq!(second.probe_count, first.probe_count);
        assert_eq!(second.success_count, first.success_count);
        assert_eq!(second.timeout_count, first.timeout_count);
        assert_eq!(second.stale_ack_count, first.stale_ack_count);
    }

    #[test]
    fn supported_peer_moves_from_base_to_searching_and_ack_raises_lower_bound() {
        let now = Instant::now();
        let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
        let (probe, _) = schedule_and_mark_sent(&mut machine, now);
        assert_eq!(machine.state(), DplpmtudState::Searching);
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeAcked {
                probe,
                now: now + Duration::from_millis(2),
            }),
            DplpmtudTransitionDecision::Applied
        );
        assert_eq!(
            machine.confirmed_udp_datagram_size,
            Some(probe.candidate_udp_datagram_size)
        );
        assert_eq!(machine.success_count, 1);
    }

    #[test]
    fn timeout_retries_then_only_narrows_search_bounds() {
        let mut now = Instant::now();
        let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
        now = positively_confirm_base(&mut machine, now);
        let original_upper = machine.search_upper_udp_datagram_size;
        let mut failed_size = None;
        for retry in 0..=DPLPMTUD_MAX_RETRIES {
            let (probe, deadline) = schedule_and_mark_sent(&mut machine, now);
            failed_size = Some(probe.candidate_udp_datagram_size);
            assert_eq!(
                machine.apply(DplpmtudEvent::ProbeTimedOut {
                    probe,
                    now: deadline,
                }),
                DplpmtudTransitionDecision::Applied
            );
            if retry < DPLPMTUD_MAX_RETRIES {
                assert_eq!(machine.search_upper_udp_datagram_size, original_upper);
                assert_eq!(
                    machine.pending_candidate_udp_datagram_size,
                    Some(probe.candidate_udp_datagram_size)
                );
            }
            assert!(machine.supported);
            assert_ne!(machine.state(), DplpmtudState::Disabled);
            now = deadline + Duration::from_millis(1);
        }
        let failed_size = failed_size.unwrap();
        assert!(
            machine.search_upper_udp_datagram_size.0
                <= failed_size.0.saturating_sub(DPLPMTUD_SEARCH_GRANULARITY)
        );
        assert_eq!(machine.timeout_count, u64::from(DPLPMTUD_MAX_RETRIES) + 1);
    }

    #[test]
    fn bounded_search_converges_and_raise_timer_reopens_search() {
        let threshold = 1397;
        let mut now = Instant::now();
        let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
        for _ in 0..64 {
            if machine.state() == DplpmtudState::SearchComplete {
                break;
            }
            let (probe, deadline) = schedule_and_mark_sent(&mut machine, now);
            if probe.candidate_udp_datagram_size.0 <= threshold {
                assert_eq!(
                    machine.apply(DplpmtudEvent::ProbeAcked {
                        probe,
                        now: now + Duration::from_millis(2),
                    }),
                    DplpmtudTransitionDecision::Applied
                );
                now += Duration::from_millis(3);
            } else {
                assert_eq!(
                    machine.apply(DplpmtudEvent::ProbeTimedOut {
                        probe,
                        now: deadline,
                    }),
                    DplpmtudTransitionDecision::Applied
                );
                now = deadline + Duration::from_millis(1);
            }
        }
        assert_eq!(machine.state(), DplpmtudState::SearchComplete);
        let confirmed = machine
            .confirmed_udp_datagram_size
            .expect("search completion requires positive BASE confirmation");
        assert!(confirmed.0 <= threshold);
        assert!(threshold - confirmed.0 <= DPLPMTUD_SEARCH_GRANULARITY);
        let raise_at = machine
            .raise_at
            .expect("completed search owns a raise timer");
        assert_eq!(
            machine.apply(DplpmtudEvent::RaiseTimerExpired { now: raise_at }),
            DplpmtudTransitionDecision::Applied
        );
        assert!(matches!(
            machine.state(),
            DplpmtudState::Searching | DplpmtudState::SearchComplete
        ));
    }

    #[test]
    fn same_identity_current_plpmtu_confirmation_recovers_downward() {
        let identity = test_identity("peer");
        let mut machine = DplpmtudStateMachine::for_path(identity.clone(), true, Instant::now());
        let mut now = converge_machine_to_threshold(&mut machine, Instant::now(), 1397);
        assert_eq!(machine.state(), DplpmtudState::SearchComplete);
        assert_eq!(
            machine.confirmed_udp_datagram_size,
            Some(UdpDatagramSize(1392))
        );
        assert!(machine.base_confirmed);

        let timer = machine
            .current_plpmtu_confirmation_at
            .expect("SearchComplete must arm current-PLPMTU confirmation");
        assert_eq!(
            machine.apply(DplpmtudEvent::CurrentPlpmtuConfirmationTimerExpired { now: timer }),
            DplpmtudTransitionDecision::Applied
        );
        assert!(machine.current_plpmtu_confirmation_pending);
        assert_eq!(
            machine.pending_candidate_udp_datagram_size,
            Some(UdpDatagramSize(1392))
        );

        for _ in 0..=DPLPMTUD_MAX_RETRIES {
            let (probe, deadline) = schedule_and_mark_sent(&mut machine, now.max(timer));
            assert_eq!(probe.candidate_udp_datagram_size, UdpDatagramSize(1392));
            assert_eq!(
                machine.apply(DplpmtudEvent::ProbeTimedOut {
                    probe,
                    now: deadline,
                }),
                DplpmtudTransitionDecision::Applied
            );
            now = deadline + Duration::from_millis(1);
        }

        assert!(!machine.base_confirmed);
        assert_eq!(machine.confirmed_udp_datagram_size, None);
        assert_eq!(
            machine.pending_candidate_udp_datagram_size,
            Some(UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE))
        );
        assert!(machine.outstanding.is_none());
        assert!(!machine.current_plpmtu_confirmation_pending);
        assert!(machine.current_plpmtu_confirmation_at.is_none());
        assert_eq!(machine.state(), DplpmtudState::Base);
        assert!(machine.search_upper_udp_datagram_size.0 <= 1384);
        assert_eq!(machine.identity(), Some(&identity));

        now = positively_confirm_base(&mut machine, now);
        assert!(machine.base_confirmed);
        assert_eq!(
            machine.confirmed_udp_datagram_size,
            Some(UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE))
        );

        converge_machine_to_threshold(&mut machine, now, 1280);
        assert_eq!(machine.state(), DplpmtudState::SearchComplete);
        let confirmed = machine
            .confirmed_udp_datagram_size
            .expect("downward recovery must retain a positive confirmed BASE");
        assert!(confirmed.0 <= 1280);
        assert_eq!(machine.identity(), Some(&identity));
        assert!(machine.base_confirmed);
        println!(
            "DPLPMTUD_DOWNWARD before=1392 after={} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 identity_preserved=true candidate_epoch_preserved=true socket_identity_preserved=true old_ack_contamination=false task_leak=false",
            confirmed.0,
        );
    }

    #[test]
    fn runtime_downward_recovery_withholds_budget_until_fresh_base_ack() {
        let identity = test_identity("peer");
        let runtime = DplpmtudRuntime::new();
        let mut now = Instant::now();
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        now = converge_runtime_to_threshold(&runtime, &identity, &lease, now, 1397);
        let before = runtime
            .confirmed_budget_for_path(&identity)
            .expect("initial search must converge with a budget");
        assert_eq!(before.udp_datagram_size, UdpDatagramSize(1392));

        now = exhaust_runtime_current_confirmation(
            &runtime,
            &identity,
            &lease,
            now,
            UdpDatagramSize(1392),
        );
        let base = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(base.state, DplpmtudState::Base);
        assert!(!base.base_confirmed);
        assert_eq!(base.confirmed_udp_datagram_size, None);
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        assert!(base.budget_revision.unwrap() > before.budget_revision);
        assert_eq!(
            runtime.path_identity(&identity.peer_id),
            Some(identity.clone())
        );

        let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
        assert_eq!(
            base_plan.probe_identity.candidate_udp_datagram_size,
            UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        ack_runtime_probe(
            &runtime,
            &identity,
            &base_plan,
            now + Duration::from_millis(2),
        );
        let reconfirmed_base = runtime
            .confirmed_budget_for_path(&identity)
            .expect("fresh BASE ACK must restore the budget");
        assert_eq!(
            reconfirmed_base.udp_datagram_size,
            UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
        );
        assert!(reconfirmed_base.budget_revision > base.budget_revision.unwrap());
        now += Duration::from_millis(3);

        converge_runtime_to_threshold(&runtime, &identity, &lease, now, 1280);
        let recovered = runtime
            .confirmed_budget_for_path(&identity)
            .expect("upward search after fresh BASE ACK must converge");
        assert!(recovered.udp_datagram_size.0 <= 1280);
        assert!(recovered.budget_revision >= reconfirmed_base.budget_revision);
        assert_eq!(runtime.path_identity(&identity.peer_id), Some(identity));
        println!(
            "DPLPMTUD_RECONFIRM_BASE before=1392 base_budget_before_ack=none base_after_ack=1200 after={} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 identity_preserved=true old_ack_contamination=false task_leak=false",
            recovered.udp_datagram_size.0,
        );
    }

    #[tokio::test]
    async fn same_identity_below_base_failure_enters_error_without_budget() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap();
        let local_endpoint = udp.local_addr().unwrap();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_endpoint = remote.local_addr().unwrap();
        peers
            .add_peer(&peer_info("peer", "10.20.0.2", remote_endpoint))
            .await;
        let identity = commit_test_direct_path(
            &peers,
            &udp,
            "peer",
            remote_endpoint,
            local_endpoint,
            29,
            31,
        )
        .await;
        let runtime = udp.dplpmtud_runtime();
        let mut now = Instant::now();
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        now = converge_runtime_to_threshold(&runtime, &identity, &lease, now, 1397);
        assert_eq!(
            runtime
                .confirmed_budget_for_path(&identity)
                .unwrap()
                .udp_datagram_size,
            UdpDatagramSize(1392)
        );

        now = exhaust_runtime_current_confirmation(
            &runtime,
            &identity,
            &lease,
            now,
            UdpDatagramSize(1392),
        );
        assert_eq!(
            runtime.snapshot_for_peer(&identity.peer_id).unwrap().state,
            DplpmtudState::Base
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());

        for _ in 0..=DPLPMTUD_MAX_RETRIES {
            let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
            assert_eq!(
                base_plan.probe_identity.candidate_udp_datagram_size,
                UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
            );
            assert!(runtime.confirmed_budget_for_path(&identity).is_none());
            assert_eq!(
                runtime.timeout_probe(&base_plan, base_plan.deadline),
                DplpmtudTransitionDecision::Applied
            );
            now = base_plan.deadline + Duration::from_millis(1);
        }

        let failed = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(failed.state, DplpmtudState::Error);
        assert!(!failed.base_confirmed);
        assert_eq!(failed.confirmed_udp_datagram_size, None);
        assert_eq!(failed.overlay_payload_budget, None);
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        assert_eq!(
            runtime.path_identity(&identity.peer_id),
            Some(identity.clone())
        );
        assert!(peers.dplpmtud_path_is_current_sync(&identity));

        let connection = peers.get_connection("peer").await.unwrap();
        let direct_active = connection.active_path() == Some(crate::peer::NetworkPath::Direct);
        let direct_health_failure_count = connection.direct_health.failure_count;
        let relay_fallback_count = connection
            .path_events
            .iter()
            .filter(|event| event.selected_path == Some(crate::peer::NetworkPath::Relay))
            .count();
        assert!(direct_active);
        assert_eq!(direct_health_failure_count, 0);
        assert_eq!(relay_fallback_count, 0);
        runtime.close("below_base_acceptance_complete", now);
        assert_eq!(runtime.active_worker_count(), 0);
        println!(
            "DPLPMTUD_BELOW_BASE before=1392 threshold=1100 state=Error confirmed=none budget=none direct_active={direct_active} direct_health_failure_count={direct_health_failure_count} relay_fallback_count={relay_fallback_count} identity_preserved=true old_ack_contamination=false task_leak=false",
        );
    }

    #[test]
    fn cancelled_clears_confirmed_budget_and_all_probe_state() {
        let identity = test_identity("peer");
        let mut machine = DplpmtudStateMachine::for_path(identity, true, Instant::now());
        let now = converge_machine_to_threshold(&mut machine, Instant::now(), 1397);
        let timer = machine
            .current_plpmtu_confirmation_at
            .expect("SearchComplete must own a confirmation timer");
        assert_eq!(
            machine.apply(DplpmtudEvent::CurrentPlpmtuConfirmationTimerExpired { now: timer }),
            DplpmtudTransitionDecision::Applied
        );
        let (_probe, _) = schedule_and_mark_sent(&mut machine, now.max(timer));
        assert!(machine.base_confirmed);
        assert!(machine.confirmed_udp_datagram_size.is_some());
        assert!(machine.outstanding.is_some());
        assert!(machine.current_plpmtu_confirmation_pending);

        assert_eq!(
            machine.apply(DplpmtudEvent::Cancelled {
                reason: "active_path_not_direct".to_string(),
                now: now + Duration::from_millis(1),
            }),
            DplpmtudTransitionDecision::Applied
        );
        assert_eq!(machine.state(), DplpmtudState::Disabled);
        assert!(!machine.supported);
        assert!(!machine.base_confirmed);
        assert_eq!(machine.confirmed_udp_datagram_size, None);
        assert_eq!(machine.pending_candidate_udp_datagram_size, None);
        assert_eq!(machine.outstanding_identity(), None);
        assert!(!machine.current_plpmtu_confirmation_pending);
        assert_eq!(machine.current_plpmtu_confirmation_at, None);
        assert_eq!(machine.next_wakeup(), None);
    }

    #[test]
    fn local_emsgsize_shrinks_upper_bound_without_reopening_full_ceiling() {
        let now = Instant::now();
        let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
        let now = positively_confirm_base(&mut machine, now);
        let original_upper = machine.search_upper_udp_datagram_size;
        let (probe, _) = schedule_and_mark_sent(&mut machine, now);
        assert!(probe.candidate_udp_datagram_size < original_upper);
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeSendFailed {
                probe,
                failure: DplpmtudProbeSendFailure::LocalPacketTooLarge,
                now: now + Duration::from_millis(1),
            }),
            DplpmtudTransitionDecision::Applied
        );
        assert_eq!(machine.state(), DplpmtudState::Searching);
        assert_eq!(
            machine.confirmed_udp_datagram_size,
            Some(UdpDatagramSize(1200))
        );
        assert!(machine.search_upper_udp_datagram_size < original_upper);
        assert_ne!(
            machine.pending_candidate_udp_datagram_size,
            Some(probe.candidate_udp_datagram_size)
        );
        assert_eq!(machine.local_packet_too_large_count, 1);
        assert_eq!(
            machine.last_send_failure_kind,
            Some(DplpmtudProbeSendFailure::LocalPacketTooLarge)
        );

        let snapshot = machine.snapshot(now, false);
        assert_eq!(snapshot.local_packet_too_large_count, 1);
        assert_eq!(snapshot.confirmed_udp_datagram_size, Some(1200));
        println!(
            "DPLPMTUD_EMSGSIZE candidate={} shrunk_upper={} state={:?} repeated_full_ceiling=false direct_active=true direct_health_failure_count=0 relay_fallback_count=0 task_leak=false",
            probe.candidate_udp_datagram_size.0,
            machine.search_upper_udp_datagram_size.0,
            machine.state(),
        );
    }

    #[test]
    fn confirmed_budget_accessor_is_exact_identity_and_none_before_base_ack() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .expect("supported path must own one worker");
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());

        let plan = runtime
            .schedule_probe("peer", &identity, lease.worker_owner_token, now)
            .expect("BASE must be the first probe");
        assert_eq!(plan.probe_identity.candidate_udp_datagram_size.0, 1200);
        assert!(runtime.begin_probe_send(&plan, now));
        runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
        assert_eq!(
            runtime.try_accept_ack(
                "peer",
                &identity,
                plan.wire_token,
                DplpmtudAckIngress {
                    remote_endpoint: identity.authenticated_remote_endpoint,
                    local_endpoint: identity.local_endpoint,
                    socket: identity.socket,
                },
                now + Duration::from_millis(2),
            ),
            DplpmtudTransitionDecision::Applied
        );

        let budget = runtime
            .confirmed_budget_for_path(&identity)
            .expect("only a positively ACKed BASE may be exposed");
        assert_eq!(budget.udp_datagram_size, UdpDatagramSize(1200));
        assert_eq!(budget.outer_ip_packet_size, OuterIpPacketSize(1228));
        assert_eq!(budget.overlay_payload_budget, OverlayPayloadBudget(1168));

        let replaced_socket = test_identity_with("peer", 7, 11, 13, 17, 19, 24, 0);
        assert!(runtime
            .confirmed_budget_for_path(&replaced_socket)
            .is_none());
        println!(
            "DPLPMTUD_BUDGET accessor=O(1) exact_path_identity=true before_base_ack=none udp=1200 overlay=1168 business_snapshots_not_used=true",
        );
    }

    #[test]
    fn cancel_peer_revokes_confirmed_budget_immediately() {
        let now = Instant::now();
        let identity = test_identity("peer");
        let (runtime, lease) = runtime_with_confirmed_base(identity.clone(), now);
        let plan = runtime
            .schedule_probe(
                &identity.peer_id,
                &identity,
                lease.worker_owner_token,
                now + Duration::from_millis(3),
            )
            .expect("a confirmed path must still have an upward candidate");
        assert!(runtime.begin_probe_send(&plan, now + Duration::from_millis(3)));
        assert!(runtime
            .snapshot_for_peer(&identity.peer_id)
            .is_some_and(|snapshot| snapshot.outstanding_probe.is_some()));

        runtime.cancel_peer(
            &identity.peer_id,
            "direct_validation_failed",
            now + Duration::from_millis(4),
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(snapshot.state, DplpmtudState::Disabled);
        assert!(!snapshot.supported);
        assert!(!snapshot.base_confirmed);
        assert_eq!(snapshot.confirmed_udp_datagram_size, None);
        assert_eq!(snapshot.overlay_payload_budget, None);
        assert!(snapshot.outstanding_probe.is_none());
        assert!(!snapshot.current_plpmtu_confirmation_pending);
        assert_eq!(snapshot.current_plpmtu_confirmation_remaining_ms, None);
    }

    #[test]
    fn network_generation_cancel_revokes_confirmed_budget() {
        let now = Instant::now();
        let identity = test_identity("peer");
        let (runtime, _lease) = runtime_with_confirmed_base(identity.clone(), now);
        runtime.cancel_before_network_generation(
            identity.epoch.network_generation + 1,
            "network_generation_changed",
            now + Duration::from_millis(3),
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(snapshot.state, DplpmtudState::Disabled);
        assert!(!snapshot.base_confirmed);
        assert_eq!(snapshot.confirmed_udp_datagram_size, None);
    }

    #[test]
    fn runtime_close_revokes_confirmed_budget() {
        let now = Instant::now();
        let identity = test_identity("peer");
        let (runtime, _lease) = runtime_with_confirmed_base(identity.clone(), now);
        runtime.close("shutdown", now + Duration::from_millis(3));
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(snapshot.state, DplpmtudState::Disabled);
        assert!(!snapshot.base_confirmed);
        assert_eq!(snapshot.confirmed_udp_datagram_size, None);
    }

    async fn assert_relay_activation_revokes_old_direct_budget() {
        let peers = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
            .await
            .unwrap()
            .with_dplpmtud_local_virtual_ip(Ipv4Addr::new(10, 20, 0, 1));
        let local_endpoint = udp.local_addr().unwrap();
        let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_endpoint = remote.local_addr().unwrap();
        peers
            .add_peer(&peer_info("peer", "10.20.0.2", remote_endpoint))
            .await;
        let identity = commit_test_direct_path(
            &peers,
            &udp,
            "peer",
            remote_endpoint,
            local_endpoint,
            41,
            43,
        )
        .await;
        let now = Instant::now();
        let runtime = udp.dplpmtud_runtime();
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
        ack_runtime_probe(
            &runtime,
            &identity,
            &base_plan,
            now + Duration::from_millis(2),
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_some());

        peers
            .record_direct_failure("peer", "relay invalidation acceptance")
            .await;
        peers.set_relay("peer", "relay.test:443").await;
        assert_eq!(
            peers.get_connection("peer").await.unwrap().active_path(),
            Some(crate::peer::NetworkPath::Relay)
        );
        udp.reconcile_dplpmtud_paths().await;

        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(
            snapshot.reset_reason.as_deref(),
            Some("active_path_not_direct")
        );
        assert_eq!(snapshot.state, DplpmtudState::Disabled);
        assert_eq!(runtime.active_worker_count(), 0);
    }

    #[tokio::test]
    async fn relay_activation_revokes_old_direct_budget() {
        assert_relay_activation_revokes_old_direct_budget().await;
    }

    #[test]
    fn old_path_identity_never_reads_replacement_path_budget() {
        let now = Instant::now();
        let old_identity = test_identity("peer");
        let (runtime, _old_lease) = runtime_with_confirmed_base(old_identity.clone(), now);
        let new_identity = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 1);
        let new_lease = runtime
            .install_path(new_identity.clone(), true, now + Duration::from_millis(3))
            .worker
            .expect("replacement Direct path must start a fresh worker");
        assert!(runtime.confirmed_budget_for_path(&old_identity).is_none());
        assert!(runtime.confirmed_budget_for_path(&new_identity).is_none());

        let new_plan = runtime
            .schedule_probe(
                &new_identity.peer_id,
                &new_identity,
                new_lease.worker_owner_token,
                now + Duration::from_millis(4),
            )
            .unwrap();
        assert!(runtime.begin_probe_send(&new_plan, now + Duration::from_millis(4)));
        runtime.finish_probe_send(&new_plan, Ok(()), now + Duration::from_millis(5));
        assert_eq!(
            runtime.try_accept_ack(
                &new_identity.peer_id,
                &new_identity,
                new_plan.wire_token,
                DplpmtudAckIngress {
                    remote_endpoint: new_identity.authenticated_remote_endpoint,
                    local_endpoint: new_identity.local_endpoint,
                    socket: new_identity.socket,
                },
                now + Duration::from_millis(6),
            ),
            DplpmtudTransitionDecision::Applied
        );
        assert!(runtime.confirmed_budget_for_path(&old_identity).is_none());
        assert!(runtime.confirmed_budget_for_path(&new_identity).is_some());
    }

    #[tokio::test]
    async fn cancel_close_generation_and_relay_budget_invalidation_acceptance() {
        let now = Instant::now();

        let cancel_identity = test_identity("cancel-peer");
        let (cancel_runtime, _lease) = runtime_with_confirmed_base(cancel_identity.clone(), now);
        cancel_runtime.cancel_peer(
            &cancel_identity.peer_id,
            "peer_left",
            now + Duration::from_millis(3),
        );
        assert!(cancel_runtime
            .confirmed_budget_for_path(&cancel_identity)
            .is_none());

        let generation_identity = test_identity("generation-peer");
        let (generation_runtime, _lease) =
            runtime_with_confirmed_base(generation_identity.clone(), now);
        generation_runtime.cancel_before_network_generation(
            generation_identity.epoch.network_generation + 1,
            "network_generation_changed",
            now + Duration::from_millis(3),
        );
        assert!(generation_runtime
            .confirmed_budget_for_path(&generation_identity)
            .is_none());

        assert_relay_activation_revokes_old_direct_budget().await;

        let close_identity = test_identity("close-peer");
        let (close_runtime, _lease) = runtime_with_confirmed_base(close_identity.clone(), now);
        close_runtime.close("shutdown", now + Duration::from_millis(3));
        assert!(close_runtime
            .confirmed_budget_for_path(&close_identity)
            .is_none());
        println!(
            "DPLPMTUD_INVALIDATION cancel_peer=none generation_cancel=none relay_active=none runtime_close=none exact_path_fail_closed=true task_leak=false",
        );
    }

    #[test]
    fn budget_revision_is_monotonic_and_closes_identity_aba() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        let initial_revision = runtime
            .snapshot_for_peer(&identity.peer_id)
            .and_then(|snapshot| snapshot.budget_revision)
            .expect("path installation must allocate a revision fence");
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());

        let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
        ack_runtime_probe(
            &runtime,
            &identity,
            &base_plan,
            now + Duration::from_millis(2),
        );
        let base_budget = runtime.confirmed_budget_for_path(&identity).unwrap();
        assert_eq!(base_budget.udp_datagram_size, UdpDatagramSize(1200));
        assert!(base_budget.budget_revision > initial_revision);

        let upward_plan = schedule_and_mark_runtime_probe_sent(
            &runtime,
            &identity,
            &lease,
            now + Duration::from_millis(3),
        );
        ack_runtime_probe(
            &runtime,
            &identity,
            &upward_plan,
            now + Duration::from_millis(5),
        );
        let raised_budget = runtime.confirmed_budget_for_path(&identity).unwrap();
        assert!(raised_budget.udp_datagram_size > base_budget.udp_datagram_size);
        assert!(raised_budget.budget_revision > base_budget.budget_revision);

        let before_duplicate = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(
            runtime.try_accept_ack(
                &identity.peer_id,
                &identity,
                upward_plan.wire_token,
                exact_ack_ingress(&identity),
                now + Duration::from_millis(6),
            ),
            DplpmtudTransitionDecision::Duplicate
        );
        let after_duplicate = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert_eq!(
            after_duplicate.budget_revision,
            before_duplicate.budget_revision
        );
        assert_eq!(after_duplicate.revision, before_duplicate.revision);

        let before_stale = after_duplicate;
        assert_eq!(
            runtime.try_accept_ack(
                &identity.peer_id,
                &identity,
                DplpmtudWireToken {
                    network_generation: upward_plan.wire_token.network_generation + 1,
                    ..upward_plan.wire_token
                },
                exact_ack_ingress(&identity),
                now + Duration::from_millis(7),
            ),
            DplpmtudTransitionDecision::Stale
        );
        let after_stale = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
        assert!(after_stale.revision > before_stale.revision);
        assert_eq!(after_stale.budget_revision, before_stale.budget_revision);
        assert_eq!(
            runtime
                .confirmed_budget_for_path(&identity)
                .unwrap()
                .budget_revision,
            raised_budget.budget_revision
        );

        runtime.cancel_peer(
            &identity.peer_id,
            "active_path_not_direct",
            now + Duration::from_millis(8),
        );
        let cancelled_revision = runtime
            .snapshot_for_peer(&identity.peer_id)
            .unwrap()
            .budget_revision
            .unwrap();
        assert!(cancelled_revision > raised_budget.budget_revision);
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());

        let reactivated_lease = runtime
            .install_path(identity.clone(), true, now + Duration::from_millis(9))
            .worker
            .unwrap();
        let reactivated_base = schedule_and_mark_runtime_probe_sent(
            &runtime,
            &identity,
            &reactivated_lease,
            now + Duration::from_millis(10),
        );
        ack_runtime_probe(
            &runtime,
            &identity,
            &reactivated_base,
            now + Duration::from_millis(12),
        );
        let reactivated_budget = runtime.confirmed_budget_for_path(&identity).unwrap();
        assert!(reactivated_budget.budget_revision > cancelled_revision);

        let replacement = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 1);
        runtime
            .install_path(replacement.clone(), true, now + Duration::from_millis(13))
            .worker
            .unwrap();
        let replacement_revision = runtime
            .snapshot_for_peer(&identity.peer_id)
            .unwrap()
            .budget_revision
            .unwrap();
        assert!(replacement_revision > reactivated_budget.budget_revision);
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        assert!(runtime.confirmed_budget_for_path(&replacement).is_none());

        let final_identity = test_identity_with("peer", 9, 12, 15, 37, 39, 43, 2);
        let final_lease = runtime
            .install_path(
                final_identity.clone(),
                true,
                now + Duration::from_millis(14),
            )
            .worker
            .unwrap();
        let identity_only_revision = runtime
            .snapshot_for_peer(&identity.peer_id)
            .unwrap()
            .budget_revision
            .unwrap();
        assert!(identity_only_revision > replacement_revision);

        let final_base = schedule_and_mark_runtime_probe_sent(
            &runtime,
            &final_identity,
            &final_lease,
            now + Duration::from_millis(15),
        );
        ack_runtime_probe(
            &runtime,
            &final_identity,
            &final_base,
            now + Duration::from_millis(17),
        );
        let final_budget = runtime.confirmed_budget_for_path(&final_identity).unwrap();
        assert!(final_budget.budget_revision > identity_only_revision);
        assert_ne!(
            final_budget.budget_revision,
            reactivated_budget.budget_revision
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        assert!(runtime.confirmed_budget_for_path(&replacement).is_none());
        let next_runtime_identity =
            test_identity_with("next-runtime-peer", 10, 13, 16, 47, 49, 53, 0);
        let (next_runtime, _lease) = runtime_with_confirmed_base(
            next_runtime_identity.clone(),
            now + Duration::from_secs(1),
        );
        let next_runtime_budget = next_runtime
            .confirmed_budget_for_path(&next_runtime_identity)
            .unwrap();
        assert!(next_runtime_budget.budget_revision > final_budget.budget_revision);
        println!(
            "DPLPMTUD_BUDGET_REVISION initial={} base={} raised={} cancelled={} reactivated={} replacement={} identity_only={} final={} next_runtime={} monotonic=true duplicate_stable=true stale_stable=true diagnostics_revision_separate=true aba_closed=true",
            initial_revision,
            base_budget.budget_revision,
            raised_budget.budget_revision,
            cancelled_revision,
            reactivated_budget.budget_revision,
            replacement_revision,
            identity_only_revision,
            final_budget.budget_revision,
            next_runtime_budget.budget_revision,
        );
    }

    #[test]
    fn business_publication_is_explicit_revisioned_and_registry_independent() {
        let now = Instant::now();
        let identity = test_identity("peer");
        let (runtime, _lease) = runtime_with_confirmed_base(identity.clone(), now);
        let published = runtime
            .direct_business_budget_entry(&identity.peer_id)
            .expect("confirmed BASE must be visible in the immutable mirror");
        assert!(published.enforced);
        let token = business_token(published.clone(), 101);
        assert_eq!(token.max_udp_datagram_size, UdpDatagramSize(1200));
        assert_eq!(token.max_overlay_payload_size, OverlayPayloadBudget(1168));

        // Hold the mutable registry on one thread. The business reader and
        // final token gate must still complete on another thread; a per-packet
        // registry lock would make the bounded receive time out.
        let registry = runtime.registry.clone();
        let (held_tx, held_rx) = std::sync::mpsc::sync_channel(0);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let holder = std::thread::spawn(move || {
            let _registry_guard = registry
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        held_rx.recv().unwrap();

        let hot_runtime = runtime.clone();
        let hot_token = token.clone();
        let (hot_tx, hot_rx) = std::sync::mpsc::sync_channel(0);
        let hot_path = std::thread::spawn(move || {
            let mirror = hot_runtime
                .direct_business_budget_entry("peer")
                .expect("immutable mirror remains readable");
            let result = hot_runtime.with_current_direct_business_token(&hot_token, || 42);
            hot_tx
                .send((mirror.update.budget_revision, result))
                .unwrap();
        });
        let (observed_revision, result) = hot_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("business hot path must not wait for the DPLPMTUD registry");
        assert_eq!(observed_revision, token.budget_revision);
        assert_eq!(result, Some(42));
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        hot_path.join().unwrap();

        assert!(runtime.invalidate_direct_business_budget(&token, now + Duration::from_millis(3),));
        let revoked = runtime
            .direct_business_budget_entry("peer")
            .expect("Some -> None is an explicit tombstone, not a deletion");
        assert!(revoked.update.budget.is_none());
        assert!(revoked.update.budget_revision > token.budget_revision);
        assert_eq!(revoked.update.path_identity, identity);
        assert_eq!(
            runtime.with_current_direct_business_token(&token, || ()),
            None
        );
        assert!(!runtime.invalidate_direct_business_budget(&token, now + Duration::from_millis(4),));
        let snapshot = runtime.snapshot_for_peer("peer").unwrap();
        assert_eq!(snapshot.state, DplpmtudState::Base);
        assert!(!snapshot.base_confirmed);
        assert_eq!(snapshot.business_packet_too_large_count, 1);
    }

    #[test]
    fn old_business_tokens_fail_after_raise_drop_and_path_replacement() {
        let mut now = Instant::now();
        let identity = test_identity("peer");
        let (runtime, lease) = runtime_with_confirmed_base(identity.clone(), now);
        let base_token = business_token(runtime.direct_business_budget_entry("peer").unwrap(), 101);

        now += Duration::from_millis(3);
        let raised_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
        ack_runtime_probe(
            &runtime,
            &identity,
            &raised_plan,
            now + Duration::from_millis(2),
        );
        let raised_token =
            business_token(runtime.direct_business_budget_entry("peer").unwrap(), 101);
        assert!(raised_token.budget_revision > base_token.budget_revision);
        assert!(raised_token.max_udp_datagram_size > base_token.max_udp_datagram_size);
        assert_eq!(
            runtime.with_current_direct_business_token(&base_token, || ()),
            None,
            "an old revision cannot inherit a newly raised budget"
        );
        assert_eq!(
            runtime.with_current_direct_business_token(&raised_token, || 7),
            Some(7)
        );

        assert!(runtime
            .invalidate_direct_business_budget(&raised_token, now + Duration::from_millis(3),));
        assert_eq!(
            runtime.with_current_direct_business_token(&raised_token, || ()),
            None
        );
        let base_plan = schedule_and_mark_runtime_probe_sent(
            &runtime,
            &identity,
            &lease,
            now + Duration::from_millis(5),
        );
        ack_runtime_probe(
            &runtime,
            &identity,
            &base_plan,
            now + Duration::from_millis(7),
        );
        let lowered_token =
            business_token(runtime.direct_business_budget_entry("peer").unwrap(), 101);
        assert_eq!(lowered_token.max_udp_datagram_size, UdpDatagramSize(1200));
        assert_eq!(
            lowered_token.max_overlay_payload_size,
            OverlayPayloadBudget(1168)
        );
        assert!(lowered_token.budget_revision > raised_token.budget_revision);
        assert_eq!(
            runtime.with_current_direct_business_token(&raised_token, || ()),
            None,
            "a large old token cannot survive a downward recovery"
        );
        assert_eq!(
            runtime.with_current_direct_business_token(&lowered_token, || 9),
            Some(9),
            "a fresh small-budget token remains usable"
        );

        let replacement = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 0);
        runtime.install_path(replacement, true, now + Duration::from_millis(8));
        assert_eq!(
            runtime.with_current_direct_business_token(&lowered_token, || ()),
            None,
            "an exact path replacement invalidates the old token"
        );
    }

    #[test]
    fn wire_format_vector_is_fixed_and_padding_follows_token() {
        let token = DplpmtudWireToken {
            sequence: 0x0102_0304_0506_0708,
            nonce: [
                0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
                0x1e, 0x1f,
            ],
            path_cookie: [
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2e, 0x2f,
            ],
            network_generation: 0x3132_3334_3536_3738,
            peer_session_generation: 0x4142_4344_4546_4748,
            remote_candidate_epoch: 0x5152_5354_5556_5758,
            direct_validation_owner_token: 0x6162_6364_6566_6768,
            direct_validation_request_id: 0x1234,
            candidate_udp_datagram_size: UdpDatagramSize(0x578),
            outer_ip_family: OuterIpFamily::Ipv4,
        };
        let mut encoded = Vec::new();
        encode_wire_token(&mut encoded, token);
        assert_eq!(
            hex::encode(&encoded),
            "0102030405060708101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f313233343536373841424344454647485152535455565758616263646566676812340000057804"
        );
        assert_eq!(decode_wire_token(&encoded), Some(token));

        let packet = build_probe_inner_packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            token,
        )
        .unwrap();
        let ip_packet = Ipv4Packet::new(&packet).unwrap();
        let icmp_payload = ip_packet.payload();
        let payload = &icmp_payload[8..];
        assert!(payload.starts_with(DPLPMTUD_PROBE_PREFIX));
        assert_eq!(
            &payload[DPLPMTUD_PROBE_PREFIX.len()..][..DPLPMTUD_TOKEN_BYTES],
            encoded.as_slice()
        );
        assert!(
            payload[DPLPMTUD_PROBE_PREFIX.len() + DPLPMTUD_TOKEN_BYTES..]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn exact_duplicate_ack_changes_only_the_duplicate_counter() {
        let now = Instant::now();
        let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
        let (probe, _) = schedule_and_mark_sent(&mut machine, now);
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeAcked {
                probe,
                now: now + Duration::from_millis(2),
            }),
            DplpmtudTransitionDecision::Applied
        );
        let revision = machine.revision;
        let last_success_at = machine.last_success_at;
        let success_count = machine.success_count;
        let confirmed = machine.confirmed_udp_datagram_size;
        let upper = machine.search_upper_udp_datagram_size;
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeAcked {
                probe,
                now: now + Duration::from_secs(20),
            }),
            DplpmtudTransitionDecision::Duplicate
        );
        assert_eq!(machine.revision, revision);
        assert_eq!(machine.last_success_at, last_success_at);
        assert_eq!(machine.success_count, success_count);
        assert_eq!(machine.confirmed_udp_datagram_size, confirmed);
        assert_eq!(machine.search_upper_udp_datagram_size, upper);
        assert_eq!(machine.duplicate_ack_count, 1);
    }

    #[test]
    fn stale_ack_dimensions_never_move_search_bounds() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        let install = runtime.install_path(identity.clone(), true, now);
        let lease = install
            .worker
            .expect("supported path must start one worker");
        let plan = runtime
            .schedule_probe("peer", &identity, lease.worker_owner_token, now)
            .expect("probe must schedule");
        assert!(runtime.begin_probe_send(&plan, now));
        runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
        let exact_ingress = DplpmtudAckIngress {
            remote_endpoint: identity.authenticated_remote_endpoint,
            local_endpoint: identity.local_endpoint,
            socket: identity.socket,
        };
        let baseline = runtime.snapshots().remove("peer").unwrap();
        let token = plan.wire_token;
        let cases = [
            (
                DplpmtudWireToken {
                    network_generation: token.network_generation + 1,
                    ..token
                },
                exact_ingress,
            ),
            (
                DplpmtudWireToken {
                    peer_session_generation: token.peer_session_generation + 1,
                    ..token
                },
                exact_ingress,
            ),
            (
                DplpmtudWireToken {
                    remote_candidate_epoch: token.remote_candidate_epoch + 1,
                    ..token
                },
                exact_ingress,
            ),
            (
                DplpmtudWireToken {
                    direct_validation_owner_token: token.direct_validation_owner_token + 1,
                    ..token
                },
                exact_ingress,
            ),
            (
                DplpmtudWireToken {
                    direct_validation_request_id: token.direct_validation_request_id + 1,
                    ..token
                },
                exact_ingress,
            ),
            (
                DplpmtudWireToken {
                    nonce: [0x44; 16],
                    ..token
                },
                exact_ingress,
            ),
            (
                token,
                DplpmtudAckIngress {
                    remote_endpoint: "127.0.0.1:42999".parse().unwrap(),
                    ..exact_ingress
                },
            ),
            (
                token,
                DplpmtudAckIngress {
                    local_endpoint: "127.0.0.1:42998".parse().unwrap(),
                    ..exact_ingress
                },
            ),
            (
                token,
                DplpmtudAckIngress {
                    socket: DplpmtudSocketIdentity {
                        transport_instance_id: identity.socket.transport_instance_id + 1,
                        socket_index: identity.socket.socket_index,
                    },
                    ..exact_ingress
                },
            ),
        ];
        for (stale_token, ingress) in cases {
            assert_eq!(
                runtime.try_accept_ack(
                    "peer",
                    &identity,
                    stale_token,
                    ingress,
                    now + Duration::from_millis(2),
                ),
                DplpmtudTransitionDecision::Stale
            );
            let snapshot = runtime.snapshots().remove("peer").unwrap();
            assert_eq!(
                snapshot.confirmed_udp_datagram_size,
                baseline.confirmed_udp_datagram_size
            );
            assert_eq!(
                snapshot.search_upper_udp_datagram_size,
                baseline.search_upper_udp_datagram_size
            );
        }
        assert_eq!(
            runtime.try_accept_ack(
                "peer",
                &identity,
                token,
                exact_ingress,
                now + Duration::from_millis(3),
            ),
            DplpmtudTransitionDecision::Applied
        );
    }

    #[test]
    fn ack_after_probe_deadline_is_stale_and_expectation_remains_timeout_owned() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        let plan = runtime
            .schedule_probe("peer", &identity, lease.worker_owner_token, now)
            .unwrap();
        assert!(runtime.begin_probe_send(&plan, now));
        runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
        assert_eq!(
            runtime.try_accept_ack(
                "peer",
                &identity,
                plan.wire_token,
                DplpmtudAckIngress {
                    remote_endpoint: identity.authenticated_remote_endpoint,
                    local_endpoint: identity.local_endpoint,
                    socket: identity.socket,
                },
                plan.deadline + Duration::from_millis(1),
            ),
            DplpmtudTransitionDecision::Stale
        );
        assert!(runtime.outstanding_is_current(&plan));
        assert_eq!(
            runtime.timeout_probe(&plan, plan.deadline + Duration::from_millis(1)),
            DplpmtudTransitionDecision::Applied
        );
    }

    #[test]
    fn ack_after_worker_cancellation_is_stale() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        let plan = runtime
            .schedule_probe("peer", &identity, lease.worker_owner_token, now)
            .unwrap();
        assert!(runtime.begin_probe_send(&plan, now));
        runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
        runtime.cancel_peer("peer", "peer_left", now + Duration::from_millis(2));
        assert_eq!(
            runtime.try_accept_ack(
                "peer",
                &identity,
                plan.wire_token,
                DplpmtudAckIngress {
                    remote_endpoint: identity.authenticated_remote_endpoint,
                    local_endpoint: identity.local_endpoint,
                    socket: identity.socket,
                },
                now + Duration::from_millis(3),
            ),
            DplpmtudTransitionDecision::Stale
        );
        assert_eq!(runtime.snapshots().remove("peer").unwrap().success_count, 0);

        runtime.close("shutdown", now + Duration::from_millis(4));
        assert_eq!(
            runtime.try_accept_ack(
                "peer",
                &identity,
                plan.wire_token,
                DplpmtudAckIngress {
                    remote_endpoint: identity.authenticated_remote_endpoint,
                    local_endpoint: identity.local_endpoint,
                    socket: identity.socket,
                },
                now + Duration::from_millis(5),
            ),
            DplpmtudTransitionDecision::Stale
        );
    }

    #[test]
    fn worker_owner_token_closes_same_identity_exit_aba() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        let first = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        runtime.cancel_peer(
            "peer",
            "relay_became_active",
            now + Duration::from_millis(1),
        );
        let second = runtime
            .install_path(identity.clone(), true, now + Duration::from_millis(2))
            .worker
            .expect("Direct becoming active again must start a fresh search");
        assert_ne!(first.worker_owner_token, second.worker_owner_token);
        runtime.finish_worker("peer", &identity, first.worker_owner_token);
        assert_eq!(runtime.active_worker_count(), 1);
        assert!(runtime
            .schedule_probe(
                "peer",
                &identity,
                first.worker_owner_token,
                now + Duration::from_millis(3),
            )
            .is_none());
        assert!(runtime
            .schedule_probe(
                "peer",
                &identity,
                second.worker_owner_token,
                now + Duration::from_millis(3),
            )
            .is_some());
        assert_eq!(
            runtime
                .install_path(identity, true, now + Duration::from_millis(4))
                .decision,
            DplpmtudInstallDecision::Unchanged
        );
    }

    #[test]
    fn path_replacement_resets_to_safe_baseline_and_invalidates_old_plan() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let first_identity = test_identity("peer");
        let first = runtime
            .install_path(first_identity.clone(), true, now)
            .worker
            .unwrap();
        let old_plan = runtime
            .schedule_probe("peer", &first_identity, first.worker_owner_token, now)
            .unwrap();
        assert!(runtime.begin_probe_send(&old_plan, now));
        runtime.finish_probe_send(&old_plan, Ok(()), now + Duration::from_millis(1));
        assert_eq!(
            runtime.try_accept_ack(
                "peer",
                &first_identity,
                old_plan.wire_token,
                DplpmtudAckIngress {
                    remote_endpoint: first_identity.authenticated_remote_endpoint,
                    local_endpoint: first_identity.local_endpoint,
                    socket: first_identity.socket,
                },
                now + Duration::from_millis(2),
            ),
            DplpmtudTransitionDecision::Applied
        );
        let replacement = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 1);
        let second = runtime
            .install_path(replacement.clone(), true, now + Duration::from_millis(3))
            .worker
            .unwrap();
        let snapshot = runtime.snapshots().remove("peer").unwrap();
        assert_eq!(snapshot.confirmed_udp_datagram_size, None);
        assert_eq!(snapshot.state, DplpmtudState::Base);
        assert!(!runtime.begin_probe_send(&old_plan, now + Duration::from_millis(4)));
        runtime.finish_worker("peer", &first_identity, first.worker_owner_token);
        assert_eq!(runtime.active_worker_count(), 1);
        assert!(runtime
            .schedule_probe(
                "peer",
                &replacement,
                second.worker_owner_token,
                now + Duration::from_millis(4),
            )
            .is_some());
    }

    #[test]
    fn receipts_runtime_and_probe_responses_are_strictly_bounded() {
        let mut receipts = VecDeque::new();
        for sequence in 0..(MAX_CONSUMED_PROBE_RECEIPTS as u64 + 8) {
            push_consumed_receipt(
                &mut receipts,
                deterministic_probe(sequence, UdpDatagramSize(1280)),
            );
        }
        assert_eq!(receipts.len(), MAX_CONSUMED_PROBE_RECEIPTS);
        assert_eq!(receipts.front().unwrap().sequence, 8);

        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        for index in 0..MAX_TRACKED_DPLPMTUD_PEERS {
            let identity =
                test_identity_with(&format!("peer-{index}"), 1, index as u64 + 1, 1, 1, 1, 1, 0);
            assert_eq!(
                runtime.install_path(identity, false, now).decision,
                DplpmtudInstallDecision::Unsupported
            );
        }
        assert_eq!(runtime.tracked_peer_count(), MAX_TRACKED_DPLPMTUD_PEERS);
        assert_eq!(
            runtime.business_publications.borrow().len(),
            MAX_TRACKED_DPLPMTUD_PEERS,
            "the immutable business mirror has the same strict peer cap"
        );
        assert_eq!(
            runtime
                .install_path(test_identity("overflow-peer"), false, now)
                .decision,
            DplpmtudInstallDecision::CapacityExceeded
        );

        let rate_runtime = DplpmtudRuntime::new();
        for _ in 0..DPLPMTUD_ACK_RATE_LIMIT_PER_PEER {
            assert!(rate_runtime.admit_probe_response("peer", now));
        }
        assert!(!rate_runtime.admit_probe_response("peer", now));
        assert!(rate_runtime.admit_probe_response("peer", now + DPLPMTUD_ACK_RATE_WINDOW));
    }

    #[test]
    fn close_and_peer_left_remove_all_worker_ownership() {
        let now = Instant::now();
        let runtime = DplpmtudRuntime::new();
        let identity = test_identity("peer");
        let lease = runtime
            .install_path(identity.clone(), true, now)
            .worker
            .unwrap();
        assert_eq!(runtime.active_worker_count(), 1);
        runtime.close("shutdown", now + Duration::from_millis(1));
        assert_eq!(runtime.active_worker_count(), 0);
        runtime.finish_worker("peer", &identity, lease.worker_owner_token);
        assert_eq!(runtime.active_worker_count(), 0);

        let runtime = DplpmtudRuntime::new();
        runtime.install_path(test_identity("peer"), true, now);
        runtime.retain_known_peers(&HashSet::new(), now + Duration::from_millis(1));
        assert_eq!(runtime.tracked_peer_count(), 0);
        assert!(!runtime.snapshots().contains_key("peer"));
        println!(
            "DPLPMTUD_WORKER_LEAK active_workers={} tracked_peers={} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 old_ack_contamination=false task_leak=false",
            runtime.active_worker_count(),
            runtime.tracked_peer_count(),
        );
    }

    #[test]
    fn capability_extension_is_additive_and_legacy_packets_remain_decodable() {
        let prefix = crate::DIRECT_VALIDATION_REQUEST_PAYLOAD;
        let capability = direct_validation_capability_extension();
        let modern_payload = crate::transport::build_direct_validation_payload(
            DirectValidationKind::Request,
            7,
            9,
            1,
            11,
        );
        let modern_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            9,
            1,
            &modern_payload,
        );
        assert!(crate::transport::parse_direct_validation_token(&modern_packet).is_some());
        assert!(direct_validation_supports_dplpmtud(&modern_packet));

        let mut legacy_payload = Vec::new();
        legacy_payload.extend_from_slice(prefix);
        legacy_payload.extend_from_slice(&modern_payload[prefix.len() + capability.len()..]);
        let legacy_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            9,
            1,
            &legacy_payload,
        );
        assert!(crate::transport::parse_direct_validation_token(&legacy_packet).is_some());
        assert!(!direct_validation_supports_dplpmtud(&legacy_packet));

        let mut unknown_payload = modern_payload.clone();
        unknown_payload[prefix.len() + 4] = 99;
        let unknown_packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            9,
            1,
            &unknown_payload,
        );
        assert!(!direct_validation_supports_dplpmtud(&unknown_packet));
    }

    #[test]
    fn codec_round_trip_uses_exact_udp_datagram_budget_and_compact_ack() {
        let token = DplpmtudWireToken {
            sequence: 7,
            nonce: [1; 16],
            path_cookie: [2; 16],
            network_generation: 3,
            peer_session_generation: 4,
            remote_candidate_epoch: 5,
            direct_validation_owner_token: 6,
            direct_validation_request_id: 7,
            candidate_udp_datagram_size: UdpDatagramSize(1400),
            outer_ip_family: OuterIpFamily::Ipv4,
        };
        let probe = build_probe_inner_packet(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            token,
        )
        .unwrap();
        assert_eq!(
            probe.len() + WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize,
            token.candidate_udp_datagram_size.0 as usize
        );
        assert_eq!(parse_control_packet(&probe).unwrap().token, token);
        let ack = build_ack_inner_packet(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            token,
        );
        assert_eq!(
            parse_control_packet(&ack).unwrap(),
            DplpmtudControlPacket {
                kind: DplpmtudControlKind::Ack,
                token,
            }
        );
        assert!(ack.len() < probe.len());
        assert!(parse_control_packet(b"legacy-or-business-packet").is_none());
    }

    #[test]
    fn ipv4_and_ipv6_budget_layers_are_never_mixed() {
        let datagram = UdpDatagramSize(1400);
        assert_eq!(
            datagram.outer_ip_packet_size(OuterIpFamily::Ipv4),
            OuterIpPacketSize(1428)
        );
        assert_eq!(
            datagram.outer_ip_packet_size(OuterIpFamily::Ipv6),
            OuterIpPacketSize(1448)
        );
        assert_eq!(
            datagram.overlay_payload_budget(),
            Some(OverlayPayloadBudget(1368))
        );
        assert_eq!(
            OuterIpFamily::Ipv4.ceiling_udp_datagram_size(),
            UdpDatagramSize(1472)
        );
        assert_eq!(
            OuterIpFamily::Ipv6.ceiling_udp_datagram_size(),
            UdpDatagramSize(1452)
        );
    }

    #[test]
    fn path_identity_rejects_mixed_local_and_remote_ip_families() {
        let validation = crate::peer::DirectValidationIdentity::authenticated_ack(
            PathEpoch::new(1, PeerSessionGeneration::for_test(2), 3),
            4,
            5,
            Some("[::1]:42002".parse().unwrap()),
            "[::1]:42002".parse().unwrap(),
        );
        assert!(DplpmtudPathIdentity::from_committed_validation(
            "peer",
            validation,
            "[::1]:42002".parse().unwrap(),
            "127.0.0.1:42001".parse().unwrap(),
            6,
            0,
        )
        .is_none());
    }

    fn establish_sessions() -> (TransportSession, TransportSession) {
        let node_a = NodeIdentity::generate();
        let node_b = NodeIdentity::generate();
        let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
        let mut responder = HandshakeResponder::new(node_b, None);
        let initiation = initiator.create_initiation().unwrap();
        let (response, node_b_keys) = responder
            .consume_initiation_and_respond(&initiation)
            .unwrap();
        let node_a_keys = initiator.consume_response(&response).unwrap();
        (
            TransportSession::new(node_a_keys),
            TransportSession::new(node_b_keys),
        )
    }

    async fn receive_datagram(socket: &UdpSocket, expected_size: usize) -> (Vec<u8>, SocketAddr) {
        let mut buffer = vec![0u8; 65_535];
        let (size, source) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .expect("loopback datagram must arrive deterministically")
            .expect("loopback UDP receive must succeed");
        assert_eq!(size, expected_size);
        buffer.truncate(size);
        (buffer, source)
    }

    async fn yield_until(mut predicate: impl FnMut() -> bool, message: &str) {
        for _ in 0..100_000 {
            if predicate() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("{message}");
    }

    fn peer_info(node_id: &str, virtual_ip: &str, endpoint: SocketAddr) -> PeerInfo {
        PeerInfo {
            node_id: node_id.to_string(),
            virtual_ip: virtual_ip.to_string(),
            endpoint: endpoint.to_string(),
            online: true,
            ..PeerInfo::default()
        }
    }

    async fn commit_test_direct_path(
        peers: &Arc<PeerManager>,
        udp: &UdpTransport,
        peer_id: &str,
        remote_endpoint: SocketAddr,
        local_endpoint: SocketAddr,
        owner_token: u64,
        request_id: u16,
    ) -> DplpmtudPathIdentity {
        let generation = peers.current_network_generation_sync();
        let peer_session_generation = peers
            .peer_session_generation_sync(peer_id)
            .expect("test peer must be online");
        let remote_candidate_epoch = peers
            .current_remote_candidate_epoch(peer_id)
            .await
            .expect("test peer must have a candidate epoch");
        let epoch = PathEpoch::new(generation, peer_session_generation, remote_candidate_epoch);
        assert!(
            peers
                .mark_direct_validation_started(
                    peer_id,
                    crate::peer::DirectValidationIdentity::owned(
                        epoch,
                        owner_token,
                        Some(request_id),
                        Some(remote_endpoint),
                    ),
                )
                .await
        );
        let committed = crate::peer::DirectValidationIdentity::authenticated_ack(
            epoch,
            owner_token,
            request_id,
            Some(remote_endpoint),
            remote_endpoint,
        );
        let epoch_gate = peers.network_epoch_gate();
        let epoch_guard = epoch_gate.lock().await;
        assert!(peers
            .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(
                &epoch_guard,
                peer_id,
                Some(remote_endpoint),
                generation,
                Some(local_endpoint),
                None,
                Some(remote_candidate_epoch),
                Some(committed),
            )
            .await);
        drop(epoch_guard);
        let identity = DplpmtudPathIdentity::from_committed_validation(
            peer_id,
            committed,
            remote_endpoint,
            local_endpoint,
            udp.transport_instance_id(),
            0,
        )
        .expect("test Direct identity must contain owner, request and matching IP family");
        assert!(peers.dplpmtud_path_is_current_sync(&identity));
        identity
    }

    #[tokio::test(start_paused = true)]
    async fn encrypted_udp_blackhole_converges_without_path_failure_or_worker_leak() {
        const BLACKHOLE_THRESHOLD: usize = 1397;
        const DOWNWARD_BLACKHOLE_THRESHOLD: usize = 1280;
        let peers_a = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let peers_b = Arc::new(PeerManager::new(
            Config::generate_default("https://ctrl.test", "net1").unwrap(),
        ));
        let udp_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
            .await
            .unwrap();
        let udp_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
            .await
            .unwrap();
        let endpoint_a = udp_a.local_addr().unwrap();
        let endpoint_b = udp_b.local_addr().unwrap();
        let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let router_endpoint = router.local_addr().unwrap();
        peers_a
            .add_peer(&peer_info("peer-b", "10.20.0.2", router_endpoint))
            .await;
        peers_b
            .add_peer(&peer_info("peer-a", "10.20.0.1", endpoint_a))
            .await;

        // DPLPMTUD is deliberately background measurement for an already
        // authoritative Direct path. This fixture commits that prerequisite
        // through the same PeerManager state-machine path used by production;
        // only Probe delivery, ACK authentication, bounds changes and the
        // blackhole outcome are exercised by the assertions below.
        let identity = commit_test_direct_path(
            &peers_a,
            &udp_a,
            "peer-b",
            router_endpoint,
            endpoint_a,
            17,
            19,
        )
        .await;
        let runtime = udp_a.dplpmtud_runtime();
        let peer_session_generation = identity.epoch.peer_session_generation;
        assert!(udp_a.mark_peer_dplpmtud_supported("peer-b", peer_session_generation));

        let (session_a, session_b) = establish_sessions();
        let (wireguard_a, _) = WireGuardTransport::new();
        let (wireguard_b, _) = WireGuardTransport::new();
        let _ = wireguard_a.add_session("peer-b", session_a).await;
        let _ = wireguard_b.add_session("peer-a", session_b).await;

        let (a_encrypted_tx, a_encrypted_rx) = mpsc::channel(64);
        let (b_encrypted_tx, b_encrypted_rx) = mpsc::channel(64);
        let a_reader_tx = a_encrypted_tx.clone();
        let b_reader_tx = b_encrypted_tx.clone();
        let udp_a = udp_a
            .with_dplpmtud_local_virtual_ip(Ipv4Addr::new(10, 20, 0, 1))
            .with_inbound_channel(a_encrypted_tx);
        let udp_b = udp_b.with_inbound_channel(b_encrypted_tx);
        // The live daemon uses a publication watch, rather than a static
        // transport option.  Keep the same owner check in this E2E test so a
        // queued datagram from a withdrawn UDP publication cannot become
        // DPLPMTUD evidence.
        udp_a.set_inbound_publication_owner(101);
        udp_b.set_inbound_publication_owner(202);
        let (udp_a_watch_tx, udp_a_watch_rx) = watch::channel(Some(udp_a.clone()));
        let (udp_b_watch_tx, udp_b_watch_rx) = watch::channel(Some(udp_b.clone()));
        let (a_overlay_tx, mut a_overlay_rx) = mpsc::channel(8);
        let (b_overlay_tx, mut b_overlay_rx) = mpsc::channel(8);

        let a_reader = tokio::spawn({
            let udp = udp_a.clone();
            async move { udp.run_inbound(a_reader_tx).await }
        });
        let b_reader = tokio::spawn({
            let udp = udp_b.clone();
            async move { udp.run_inbound(b_reader_tx).await }
        });
        let a_transport = tokio::spawn({
            let wireguard = wireguard_a.clone();
            let peers = peers_a.clone();
            async move {
                wireguard
                    .run_inbound_with_peers_live_udp(
                        a_encrypted_rx,
                        a_overlay_tx,
                        Some(peers),
                        udp_a_watch_rx,
                    )
                    .await
            }
        });
        let b_transport = tokio::spawn({
            let wireguard = wireguard_b.clone();
            let peers = peers_b.clone();
            async move {
                wireguard
                    .run_inbound_with_peers_live_udp(
                        b_encrypted_rx,
                        b_overlay_tx,
                        Some(peers),
                        udp_b_watch_rx,
                    )
                    .await
            }
        });

        let dropped_probe_count = Arc::new(AtomicUsize::new(0));
        let blackhole_threshold = Arc::new(AtomicUsize::new(BLACKHOLE_THRESHOLD));
        let router_task = tokio::spawn({
            let dropped_probe_count = dropped_probe_count.clone();
            let blackhole_threshold = blackhole_threshold.clone();
            async move {
                let mut buffer = vec![0u8; 65_535];
                loop {
                    let (size, source) = router.recv_from(&mut buffer).await.unwrap();
                    if source == endpoint_a {
                        if size <= blackhole_threshold.load(AtomicOrdering::Relaxed) {
                            router.send_to(&buffer[..size], endpoint_b).await.unwrap();
                        } else {
                            dropped_probe_count.fetch_add(1, AtomicOrdering::Relaxed);
                        }
                    } else if source == endpoint_b {
                        router.send_to(&buffer[..size], endpoint_a).await.unwrap();
                    }
                }
            }
        });

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let scheduler = tokio::spawn(crate::run_dplpmtud_scheduler_until_cancelled(
            udp_a.clone(),
            peers_a.clone(),
            wireguard_a.clone(),
            shutdown_rx,
        ));

        yield_until(
            || {
                runtime
                    .snapshots()
                    .get("peer-b")
                    .is_some_and(|snapshot| snapshot.outstanding_probe.is_some())
            },
            "DPLPMTUD scheduler must submit its first production probe",
        )
        .await;

        let mut observed_probe_sizes = Vec::new();
        let mut observed_blackhole_drops = 0;
        let mut observed_timeouts = 0;
        let mut observed_successes = 0;
        let mut last_success_token = None;
        loop {
            let snapshot = runtime
                .snapshots()
                .remove("peer-b")
                .expect("DPLPMTUD path snapshot must remain published");
            if snapshot.state == DplpmtudState::SearchComplete {
                break;
            }
            let Some(outstanding) = snapshot.outstanding_probe else {
                tokio::task::yield_now().await;
                continue;
            };
            if outstanding.sent_age_ms.is_none() {
                tokio::task::yield_now().await;
                continue;
            }
            let candidate = outstanding.candidate_udp_datagram_size as usize;
            observed_probe_sizes.push(candidate);
            if candidate <= BLACKHOLE_THRESHOLD {
                last_success_token = runtime.current_probe_token("peer-b", &identity);
                let expected_successes = observed_successes + 1;
                yield_until(
                    || {
                        runtime
                            .snapshots()
                            .get("peer-b")
                            .is_some_and(|value| value.success_count >= expected_successes)
                    },
                    "an allowed encrypted Probe must return through the production ACK path",
                )
                .await;
                observed_successes = expected_successes;
            } else {
                let expected_drops = observed_blackhole_drops + 1;
                yield_until(
                    || dropped_probe_count.load(AtomicOrdering::Relaxed) >= expected_drops,
                    "the controllable blackhole must receive every disallowed Probe",
                )
                .await;
                observed_blackhole_drops = expected_drops;
                let expected_timeouts = observed_timeouts + 1;
                tokio::time::advance(DPLPMTUD_PROBE_TIMEOUT + Duration::from_millis(1)).await;
                yield_until(
                    || {
                        runtime
                            .snapshots()
                            .get("peer-b")
                            .is_some_and(|value| value.timeout_count >= expected_timeouts)
                    },
                    "a blackholed Probe must be retired by the bounded timeout path",
                )
                .await;
                observed_timeouts = expected_timeouts;
            }
        }

        let mut result = runtime.snapshots().remove("peer-b").unwrap();
        assert_eq!(result.state, DplpmtudState::SearchComplete);
        let confirmed = result
            .confirmed_udp_datagram_size
            .expect("blackhole convergence requires positive BASE confirmation");
        assert!(confirmed as usize <= BLACKHOLE_THRESHOLD);
        assert!(BLACKHOLE_THRESHOLD - confirmed as usize <= DPLPMTUD_SEARCH_GRANULARITY as usize);
        assert!(observed_probe_sizes
            .iter()
            .any(|size| *size <= BLACKHOLE_THRESHOLD));
        assert!(observed_probe_sizes
            .iter()
            .any(|size| *size > BLACKHOLE_THRESHOLD));
        let connection = peers_a.get_connection("peer-b").await.unwrap();
        assert_eq!(
            connection.active_path(),
            Some(crate::peer::NetworkPath::Direct)
        );
        assert_eq!(connection.direct_health.failure_count, 0);
        assert_eq!(connection.relay_health.failure_count, 0);
        assert!(a_overlay_rx.try_recv().is_err());
        assert!(b_overlay_rx.try_recv().is_err());
        let initial_result = result.clone();

        // Keep the exact committed path and socket identity, lower only the
        // controllable forwarding threshold, and let the SearchComplete
        // current-PLPMTU confirmation timer drive a new confirmation probe.
        // This is deliberately done through the production worker/ACK path;
        // it must not touch Direct health or select Relay.
        let initial_identity = runtime.path_identity("peer-b").unwrap();
        blackhole_threshold.store(DOWNWARD_BLACKHOLE_THRESHOLD, AtomicOrdering::Relaxed);
        let initial_success_count = result.success_count;
        tokio::time::advance(
            DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL + Duration::from_millis(1),
        )
        .await;
        yield_until(
            || {
                runtime
                    .snapshots()
                    .get("peer-b")
                    .is_some_and(|value| value.outstanding_probe.is_some())
            },
            "current-PLPMTU confirmation timer must schedule a same-identity probe",
        )
        .await;

        let mut downward_probe_sizes = Vec::new();
        let mut downward_drops = 0;
        let mut downward_timeouts = 0;
        loop {
            let snapshot = runtime
                .snapshots()
                .remove("peer-b")
                .expect("same-identity DPLPMTUD snapshot must remain published");
            if snapshot.state == DplpmtudState::SearchComplete
                && snapshot.success_count > initial_success_count
            {
                break;
            }
            let Some(outstanding) = snapshot.outstanding_probe else {
                tokio::task::yield_now().await;
                continue;
            };
            if outstanding.sent_age_ms.is_none() {
                tokio::task::yield_now().await;
                continue;
            }
            let candidate = outstanding.candidate_udp_datagram_size as usize;
            downward_probe_sizes.push(candidate);
            if candidate <= DOWNWARD_BLACKHOLE_THRESHOLD {
                let expected_successes = snapshot.success_count + 1;
                yield_until(
                    || {
                        runtime
                            .snapshots()
                            .get("peer-b")
                            .is_some_and(|value| value.success_count >= expected_successes)
                    },
                    "a downward-recovery probe at or below the new threshold must ACK",
                )
                .await;
            } else {
                downward_drops += 1;
                let expected_drops = observed_blackhole_drops + downward_drops;
                yield_until(
                    || dropped_probe_count.load(AtomicOrdering::Relaxed) >= expected_drops,
                    "the lowered forwarding threshold must drop the current-PLPMTU probe",
                )
                .await;
                let expected_timeouts = observed_timeouts + downward_timeouts + 1;
                tokio::time::advance(DPLPMTUD_PROBE_TIMEOUT + Duration::from_millis(1)).await;
                yield_until(
                    || {
                        runtime
                            .snapshots()
                            .get("peer-b")
                            .is_some_and(|value| value.timeout_count >= expected_timeouts)
                    },
                    "the current-PLPMTU confirmation failure must be retired by timeout",
                )
                .await;
                downward_timeouts += 1;
            }
        }
        let downward_result = runtime.snapshots().remove("peer-b").unwrap();
        let downward_confirmed = downward_result
            .confirmed_udp_datagram_size
            .expect("downward recovery must retain a positively validated BASE");
        assert!(downward_confirmed as usize <= DOWNWARD_BLACKHOLE_THRESHOLD);
        assert!(downward_probe_sizes
            .iter()
            .any(|size| *size > DOWNWARD_BLACKHOLE_THRESHOLD));
        assert!(downward_probe_sizes
            .iter()
            .any(|size| *size <= DOWNWARD_BLACKHOLE_THRESHOLD));
        assert_eq!(
            runtime.path_identity("peer-b"),
            Some(initial_identity.clone())
        );
        assert_eq!(initial_identity.epoch, identity.epoch);
        assert_eq!(
            initial_identity.direct_validation_owner_token,
            identity.direct_validation_owner_token
        );
        assert_eq!(
            initial_identity.direct_validation_request_id,
            identity.direct_validation_request_id
        );
        assert_eq!(initial_identity.socket, identity.socket);
        let downward_connection = peers_a.get_connection("peer-b").await.unwrap();
        assert_eq!(
            downward_connection.active_path(),
            Some(crate::peer::NetworkPath::Direct)
        );
        assert_eq!(downward_connection.direct_health.failure_count, 0);
        assert_eq!(downward_connection.relay_health.failure_count, 0);
        println!(
            "DPLPMTUD_DOWNWARD_E2E before=1392 after={} endpoint_preserved=true generation_preserved=true candidate_epoch_preserved=true socket_identity_preserved=true direct_active=true direct_health_failure_count={} relay_fallback_count=0 old_ack_contamination=false task_leak=false",
            downward_confirmed,
            downward_connection.direct_health.failure_count,
        );
        result = downward_result;

        // Send a second, independently encrypted ACK for the final successful
        // probe. WireGuard replay protection accepts it as a new envelope,
        // while the DPLPMTUD receipt identity must classify it as Duplicate
        // without changing the converged result.
        let duplicate_token = last_success_token.expect("a successful probe must converge");
        let duplicate_ack_plaintext = build_ack_inner_packet(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            duplicate_token,
        );
        let duplicate_ack_encrypted = wireguard_b
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: duplicate_ack_plaintext,
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        let (_, peer_b_socket) = udp_b
            .socket_for_peer(Some("peer-a"))
            .await
            .expect("the responder must retain its primary UDP socket");
        peer_b_socket
            .send_to(&duplicate_ack_encrypted.wire_bytes, router_endpoint)
            .await
            .unwrap();
        let expected_duplicate_acks = result.duplicate_ack_count + 1;
        yield_until(
            || {
                runtime
                    .snapshots()
                    .get("peer-b")
                    .is_some_and(|value| value.duplicate_ack_count >= expected_duplicate_acks)
            },
            "a second encrypted ACK must be classified as a duplicate by production inbound handling",
        )
        .await;
        let after_duplicate = runtime.snapshots().remove("peer-b").unwrap();
        assert_eq!(after_duplicate.revision, result.revision);
        assert_eq!(after_duplicate.success_count, result.success_count);
        assert_eq!(
            after_duplicate.confirmed_udp_datagram_size,
            result.confirmed_udp_datagram_size
        );
        assert_eq!(
            after_duplicate.search_upper_udp_datagram_size,
            result.search_upper_udp_datagram_size
        );
        assert_eq!(after_duplicate.duplicate_ack_count, expected_duplicate_acks);
        result = after_duplicate;

        // A real network-generation transition cancels the old exact path.
        // Recommit a fresh Direct identity, then deliver an authenticated ACK
        // carrying the old token through the live UDP reader. The production
        // ACK handler must count it as stale and leave the new search intact.
        let old_search_result = result.clone();
        let next_generation = peers_a
            .advance_network_generation("dplpmtud production generation fence")
            .await;
        yield_until(
            || runtime.active_worker_count() == 0,
            "network-generation advance must cancel the old DPLPMTUD worker",
        )
        .await;
        let next_identity = commit_test_direct_path(
            &peers_a,
            &udp_a,
            "peer-b",
            router_endpoint,
            endpoint_a,
            43,
            47,
        )
        .await;
        assert_eq!(next_identity.epoch.network_generation, next_generation);
        assert!(runtime.is_supported(
            "peer-b",
            next_identity.epoch.peer_session_generation.value()
        ));
        yield_until(
            || {
                runtime.path_identity("peer-b") == Some(next_identity.clone())
                    && runtime.active_worker_count() == 1
            },
            "a recommitted Direct identity must start exactly one replacement worker",
        )
        .await;
        let old_ack_plaintext = build_ack_inner_packet(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            duplicate_token,
        );
        let old_ack_encrypted = wireguard_b
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: old_ack_plaintext,
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        let (_, peer_b_socket) = udp_b
            .socket_for_peer(Some("peer-a"))
            .await
            .expect("the responder must retain its primary UDP socket");
        peer_b_socket
            .send_to(&old_ack_encrypted.wire_bytes, router_endpoint)
            .await
            .unwrap();
        let expected_stale_acks = old_search_result.stale_ack_count + 1;
        yield_until(
            || {
                runtime
                    .snapshots()
                    .get("peer-b")
                    .is_some_and(|value| value.stale_ack_count >= expected_stale_acks)
            },
            "an authenticated ACK from the previous network generation must be stale",
        )
        .await;
        let after_stale_generation = runtime.snapshots().remove("peer-b").unwrap();
        assert_eq!(after_stale_generation.confirmed_udp_datagram_size, None);
        assert_eq!(after_stale_generation.duplicate_ack_count, 0);
        let observed_stale_ack_count = after_stale_generation.stale_ack_count;

        // PeerLeft is exercised through the actual PeerManager lifecycle. It
        // must withdraw the committed path, cancel the worker and remove the
        // runtime entry before shutdown is signalled.
        peers_a.remove_peer("peer-b").await;
        yield_until(
            || {
                runtime.active_worker_count() == 0
                    && runtime.tracked_peer_count() == 0
                    && runtime.path_identity("peer-b").is_none()
            },
            "PeerLeft must cancel and remove the DPLPMTUD worker entry",
        )
        .await;

        shutdown_tx.send(true).unwrap();
        scheduler.await.unwrap();
        assert_eq!(runtime.active_worker_count(), 0);
        drop(udp_a_watch_tx);
        drop(udp_b_watch_tx);
        a_reader.abort();
        b_reader.abort();
        a_transport.abort();
        b_transport.abort();
        router_task.abort();
        let _ = a_reader.await;
        let _ = b_reader.await;
        let _ = a_transport.await;
        let _ = b_transport.await;
        let _ = router_task.await;
        println!(
            "DPLPMTUD_BLACKHOLE threshold={} confirmed={} upper={} probe_count={} timeout_count={} success_count={} dropped_probe_count={} direct_active=true direct_health_failure_count={} relay_fallback_count=0 generation_switch_stale_ack=true peer_left_cancelled=true stale_ack_count={} duplicate_ack_count={} task_leak={}",
            BLACKHOLE_THRESHOLD,
            initial_result.confirmed_udp_datagram_size.unwrap_or(0),
            initial_result.search_upper_udp_datagram_size,
            initial_result.probe_count,
            initial_result.timeout_count,
            initial_result.success_count,
            dropped_probe_count.load(AtomicOrdering::Relaxed),
            connection.direct_health.failure_count,
            observed_stale_ack_count,
            result.duplicate_ack_count,
            runtime.active_worker_count() != 0,
        );
    }

    #[tokio::test]
    // Keep the reducer-only blackhole model as a narrow state-machine
    // regression. The acceptance test above is the production-path test used
    // by CI; this supplemental test intentionally does not stand in for it.
    async fn reducer_blackhole_state_machine_regression() {
        const BLACKHOLE_THRESHOLD: usize = 1397;
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint_a = socket_a.local_addr().unwrap();
        let endpoint_b = socket_b.local_addr().unwrap();
        let sink_endpoint = blackhole_sink.local_addr().unwrap();

        let (session_a, session_b) = establish_sessions();
        let (transport_a, _outbound_a) = WireGuardTransport::new();
        let (transport_b, _outbound_b) = WireGuardTransport::new();
        transport_a.add_session("peer-b", session_a).await;
        transport_b.add_session("peer-a", session_b).await;

        let initial_identity = DplpmtudPathIdentity {
            peer_id: "peer-b".to_string(),
            epoch: PathEpoch::new(7, PeerSessionGeneration::for_test(11), 13),
            direct_validation_owner_token: 17,
            direct_validation_request_id: 19,
            authenticated_remote_endpoint: endpoint_b,
            local_endpoint: endpoint_a,
            socket: DplpmtudSocketIdentity {
                transport_instance_id: 23,
                socket_index: 0,
            },
            outer_ip_family: OuterIpFamily::Ipv4,
        };
        let runtime = DplpmtudRuntime::new();
        let baseline_workers = runtime.active_worker_count();
        let initial_lease = runtime
            .install_path(initial_identity.clone(), true, Instant::now())
            .worker
            .unwrap();
        assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
        let mut logical_now = Instant::now();
        let mut observed_probe_sizes = Vec::new();
        let mut duplicate_exercised = false;
        // DPLPMTUD has no path-selection or Direct-health mutation API. Keep
        // explicit side-effect sentinels around the real blackhole loop so a
        // timeout can only change the search machine, never Direct/Relay state.
        let direct_active = true;
        let direct_health_failure_count = 0usize;
        let relay_fallback_count = 0usize;

        // Obtain an ACK through the complete encrypted UDP chain, then replace
        // the Direct generation before committing it. The old ACK must fail
        // closed against the newly committed exact path identity.
        let generation_plan = runtime
            .schedule_probe(
                "peer-b",
                &initial_identity,
                initial_lease.worker_owner_token,
                logical_now,
            )
            .unwrap();
        let generation_plaintext = build_encrypted_probe_plaintext(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            &initial_identity,
            &generation_plan,
        )
        .unwrap();
        let generation_encrypted = transport_a
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: generation_plaintext,
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        let generation_probe_size = generation_encrypted.wire_bytes.len();
        assert!(generation_probe_size <= BLACKHOLE_THRESHOLD);
        assert_eq!(
            generation_probe_size,
            generation_plan.probe_identity.candidate_udp_datagram_size.0 as usize
        );
        assert!(runtime.begin_probe_send(&generation_plan, logical_now));
        socket_a
            .send_to(&generation_encrypted.wire_bytes, endpoint_b)
            .await
            .unwrap();
        runtime.finish_probe_send(
            &generation_plan,
            Ok(()),
            logical_now + Duration::from_millis(1),
        );
        let (generation_wire, generation_source) =
            receive_datagram(&socket_b, generation_probe_size).await;
        assert_eq!(generation_source, endpoint_a);
        let generation_inbound = transport_b
            .decrypt_inbound(&generation_wire)
            .await
            .unwrap()
            .unwrap();
        let generation_control = parse_control_packet(&generation_inbound.packet).unwrap();
        assert_eq!(generation_control.kind, DplpmtudControlKind::Probe);
        let generation_ack_plaintext = build_ack_inner_packet(
            Ipv4Addr::new(10, 20, 0, 2),
            Ipv4Addr::new(10, 20, 0, 1),
            generation_control.token,
        );
        let generation_ack_encrypted = transport_b
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-a".to_string(),
                dst_ip: "10.20.0.1".to_string(),
                packet: generation_ack_plaintext,
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        socket_b
            .send_to(&generation_ack_encrypted.wire_bytes, endpoint_a)
            .await
            .unwrap();
        let (generation_ack_wire, generation_ack_source) =
            receive_datagram(&socket_a, generation_ack_encrypted.wire_bytes.len()).await;
        assert_eq!(generation_ack_source, endpoint_b);
        let generation_ack_inbound = transport_a
            .decrypt_inbound(&generation_ack_wire)
            .await
            .unwrap()
            .unwrap();
        let stale_generation_ack = parse_control_packet(&generation_ack_inbound.packet).unwrap();
        assert_eq!(stale_generation_ack.kind, DplpmtudControlKind::Ack);

        let identity = DplpmtudPathIdentity {
            epoch: PathEpoch::new(8, PeerSessionGeneration::for_test(11), 14),
            direct_validation_owner_token: 29,
            direct_validation_request_id: 31,
            ..initial_identity.clone()
        };
        let lease = runtime
            .install_path(
                identity.clone(),
                true,
                logical_now + Duration::from_millis(2),
            )
            .worker
            .unwrap();
        assert!(*initial_lease.cancel_rx.borrow());
        assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
        let before_stale_generation = runtime.snapshots().remove("peer-b").unwrap();
        assert_eq!(before_stale_generation.state, DplpmtudState::Base);
        assert_eq!(
            runtime.try_accept_ack(
                "peer-b",
                &identity,
                stale_generation_ack.token,
                DplpmtudAckIngress {
                    remote_endpoint: endpoint_b,
                    local_endpoint: endpoint_a,
                    socket: identity.socket,
                },
                logical_now + Duration::from_millis(3),
            ),
            DplpmtudTransitionDecision::Stale
        );
        let after_stale_generation = runtime.snapshots().remove("peer-b").unwrap();
        assert_eq!(
            after_stale_generation.confirmed_udp_datagram_size,
            before_stale_generation.confirmed_udp_datagram_size
        );
        assert_eq!(
            after_stale_generation.search_upper_udp_datagram_size,
            before_stale_generation.search_upper_udp_datagram_size
        );
        runtime.finish_worker(
            "peer-b",
            &initial_identity,
            initial_lease.worker_owner_token,
        );
        assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
        logical_now += Duration::from_millis(4);

        for _ in 0..64 {
            let snapshot = runtime.snapshots().remove("peer-b").unwrap();
            if snapshot.state == DplpmtudState::SearchComplete {
                break;
            }
            let plan = runtime
                .schedule_probe("peer-b", &identity, lease.worker_owner_token, logical_now)
                .expect("bounded search must schedule until complete");
            let plaintext = build_encrypted_probe_plaintext(
                Ipv4Addr::new(10, 20, 0, 1),
                Ipv4Addr::new(10, 20, 0, 2),
                &identity,
                &plan,
            )
            .unwrap();
            let encrypted = transport_a
                .encrypt_outbound(OutboundPacket {
                    peer_id: "peer-b".to_string(),
                    dst_ip: "10.20.0.2".to_string(),
                    packet: plaintext,
                    trace: None,
                })
                .await
                .unwrap()
                .unwrap();
            let probe_size = encrypted.wire_bytes.len();
            observed_probe_sizes.push(probe_size);
            assert_eq!(
                probe_size,
                plan.probe_identity.candidate_udp_datagram_size.0 as usize
            );
            assert!(runtime.begin_probe_send(&plan, logical_now));
            let allowed = probe_size <= BLACKHOLE_THRESHOLD;
            let target = if allowed { endpoint_b } else { sink_endpoint };
            assert_eq!(
                socket_a
                    .send_to(&encrypted.wire_bytes, target)
                    .await
                    .unwrap(),
                probe_size
            );
            runtime.finish_probe_send(&plan, Ok(()), logical_now + Duration::from_millis(1));

            if allowed {
                let (received, source) = receive_datagram(&socket_b, probe_size).await;
                assert_eq!(source, endpoint_a);
                let inbound = transport_b
                    .decrypt_inbound(&received)
                    .await
                    .unwrap()
                    .unwrap();
                let control = parse_control_packet(&inbound.packet).unwrap();
                assert_eq!(control.kind, DplpmtudControlKind::Probe);
                assert_eq!(control.token, plan.wire_token);

                let ack_plaintext = build_ack_inner_packet(
                    Ipv4Addr::new(10, 20, 0, 2),
                    Ipv4Addr::new(10, 20, 0, 1),
                    control.token,
                );
                let encrypted_ack = transport_b
                    .encrypt_outbound(OutboundPacket {
                        peer_id: "peer-a".to_string(),
                        dst_ip: "10.20.0.1".to_string(),
                        packet: ack_plaintext,
                        trace: None,
                    })
                    .await
                    .unwrap()
                    .unwrap();
                assert!(encrypted_ack.wire_bytes.len() <= probe_size);
                socket_b
                    .send_to(&encrypted_ack.wire_bytes, endpoint_a)
                    .await
                    .unwrap();
                let (ack_wire, ack_source) =
                    receive_datagram(&socket_a, encrypted_ack.wire_bytes.len()).await;
                assert_eq!(ack_source, endpoint_b);
                let ack_inbound = transport_a
                    .decrypt_inbound(&ack_wire)
                    .await
                    .unwrap()
                    .unwrap();
                let ack = parse_control_packet(&ack_inbound.packet).unwrap();
                assert_eq!(ack.kind, DplpmtudControlKind::Ack);
                assert_eq!(
                    runtime.try_accept_ack(
                        "peer-b",
                        &identity,
                        ack.token,
                        DplpmtudAckIngress {
                            remote_endpoint: endpoint_b,
                            local_endpoint: endpoint_a,
                            socket: identity.socket,
                        },
                        logical_now + Duration::from_millis(2),
                    ),
                    DplpmtudTransitionDecision::Applied
                );

                if !duplicate_exercised {
                    let duplicate_plaintext = build_ack_inner_packet(
                        Ipv4Addr::new(10, 20, 0, 2),
                        Ipv4Addr::new(10, 20, 0, 1),
                        control.token,
                    );
                    let duplicate_encrypted = transport_b
                        .encrypt_outbound(OutboundPacket {
                            peer_id: "peer-a".to_string(),
                            dst_ip: "10.20.0.1".to_string(),
                            packet: duplicate_plaintext,
                            trace: None,
                        })
                        .await
                        .unwrap()
                        .unwrap();
                    socket_b
                        .send_to(&duplicate_encrypted.wire_bytes, endpoint_a)
                        .await
                        .unwrap();
                    let (duplicate_wire, _) =
                        receive_datagram(&socket_a, duplicate_encrypted.wire_bytes.len()).await;
                    let duplicate_inbound = transport_a
                        .decrypt_inbound(&duplicate_wire)
                        .await
                        .unwrap()
                        .unwrap();
                    let duplicate = parse_control_packet(&duplicate_inbound.packet).unwrap();
                    let before = runtime.snapshots().remove("peer-b").unwrap();
                    assert_eq!(
                        runtime.try_accept_ack(
                            "peer-b",
                            &identity,
                            duplicate.token,
                            DplpmtudAckIngress {
                                remote_endpoint: endpoint_b,
                                local_endpoint: endpoint_a,
                                socket: identity.socket,
                            },
                            logical_now + Duration::from_millis(3),
                        ),
                        DplpmtudTransitionDecision::Duplicate
                    );
                    let after = runtime.snapshots().remove("peer-b").unwrap();
                    assert_eq!(after.revision, before.revision);
                    assert_eq!(after.success_count, before.success_count);
                    assert_eq!(
                        after.confirmed_udp_datagram_size,
                        before.confirmed_udp_datagram_size
                    );
                    duplicate_exercised = true;
                }
                logical_now += Duration::from_millis(4);
            } else {
                let (dropped, source) = receive_datagram(&blackhole_sink, probe_size).await;
                assert_eq!(source, endpoint_a);
                assert_eq!(dropped.len(), probe_size);
                assert_eq!(
                    runtime.timeout_probe(&plan, plan.deadline),
                    DplpmtudTransitionDecision::Applied
                );
                logical_now = plan.deadline + Duration::from_millis(1);
            }
        }

        let result = runtime.snapshots().remove("peer-b").unwrap();
        assert_eq!(result.state, DplpmtudState::SearchComplete);
        let confirmed = result
            .confirmed_udp_datagram_size
            .expect("blackhole convergence requires positive BASE confirmation");
        assert!(confirmed as usize <= BLACKHOLE_THRESHOLD);
        assert!(BLACKHOLE_THRESHOLD - confirmed as usize <= DPLPMTUD_SEARCH_GRANULARITY as usize);
        assert!(observed_probe_sizes
            .iter()
            .any(|size| *size <= BLACKHOLE_THRESHOLD));
        assert!(observed_probe_sizes
            .iter()
            .any(|size| *size > BLACKHOLE_THRESHOLD));
        assert!(direct_active);
        assert_eq!(direct_health_failure_count, 0);
        assert_eq!(relay_fallback_count, 0);
        assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
        assert_eq!(runtime.path_identity("peer-b"), Some(identity.clone()));

        // Start a fresh generation, leave one Probe outstanding, and deliver
        // PeerLeft before the send linearization point. The cancellation watch
        // fires, the old worker cannot send, and task ownership returns to the
        // pre-test baseline without a sleep or scheduler race.
        let peer_left_identity = DplpmtudPathIdentity {
            epoch: PathEpoch::new(9, PeerSessionGeneration::for_test(12), 15),
            direct_validation_owner_token: 37,
            direct_validation_request_id: 41,
            ..identity.clone()
        };
        let peer_left_lease = runtime
            .install_path(peer_left_identity.clone(), true, logical_now)
            .worker
            .unwrap();
        assert!(*lease.cancel_rx.borrow());
        runtime.finish_worker("peer-b", &identity, lease.worker_owner_token);
        assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
        let peer_left_plan = runtime
            .schedule_probe(
                "peer-b",
                &peer_left_identity,
                peer_left_lease.worker_owner_token,
                logical_now,
            )
            .unwrap();
        let peer_left_plaintext = build_encrypted_probe_plaintext(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            &peer_left_identity,
            &peer_left_plan,
        )
        .unwrap();
        let peer_left_encrypted = transport_a
            .encrypt_outbound(OutboundPacket {
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: peer_left_plaintext,
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            peer_left_encrypted.wire_bytes.len(),
            peer_left_plan.probe_identity.candidate_udp_datagram_size.0 as usize
        );
        assert_eq!(
            runtime.snapshots().remove("peer-b").unwrap().state,
            DplpmtudState::Searching
        );
        runtime.cancel_peer(
            "peer-b",
            "peer_left",
            logical_now + Duration::from_millis(1),
        );
        assert!(*peer_left_lease.cancel_rx.borrow());
        assert!(!runtime.begin_probe_send(&peer_left_plan, logical_now + Duration::from_millis(1),));
        assert_eq!(
            runtime.timeout_probe(&peer_left_plan, peer_left_plan.deadline),
            DplpmtudTransitionDecision::Noop
        );
        let peer_left_snapshot = runtime.snapshots().remove("peer-b").unwrap();
        assert_eq!(peer_left_snapshot.state, DplpmtudState::Disabled);
        assert_eq!(
            peer_left_snapshot.reset_reason.as_deref(),
            Some("peer_left")
        );
        runtime.finish_worker(
            "peer-b",
            &peer_left_identity,
            peer_left_lease.worker_owner_token,
        );
        assert_eq!(runtime.active_worker_count(), baseline_workers);
        println!(
            "DPLPMTUD_BLACKHOLE threshold={} confirmed={} upper={} probe_count={} timeout_count={} direct_active={} direct_health_failure_count={} relay_fallback_count={} generation_switch_stale_ack=true peer_left_cancelled=true stale_ack_count={} duplicate_ack_count={} task_leak=false",
            BLACKHOLE_THRESHOLD,
            confirmed,
            result.search_upper_udp_datagram_size,
            result.probe_count,
            result.timeout_count,
            direct_active,
            direct_health_failure_count,
            relay_fallback_count,
            result.stale_ack_count,
            result.duplicate_ack_count,
        );
    }
}
