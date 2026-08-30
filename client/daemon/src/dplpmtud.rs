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
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
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
pub(crate) const DPLPMTUD_ERROR_RETRY_INTERVAL: Duration = Duration::from_secs(5);
pub(crate) const DPLPMTUD_WORKER_MAX_LIFETIME: Duration = Duration::from_secs(60 * 60);
pub(crate) const MAX_TRACKED_DPLPMTUD_PEERS: usize = 256;
const MAX_CONSUMED_PROBE_RECEIPTS: usize = 32;

const DIRECT_VALIDATION_TOKEN_BYTES: usize = 8 + 2 + 1 + 8;
const DIRECT_VALIDATION_CAPABILITY_EXTENSION: [u8; 6] = [b'D', b'P', b'M', b'1', 1, 1];
const DPLPMTUD_PROBE_PREFIX: &[u8] = b"p2wlan-dplpmtud-probe-v1";
const DPLPMTUD_ACK_PREFIX: &[u8] = b"p2wlan-dplpmtud-ack-v1";
const DPLPMTUD_TOKEN_BYTES: usize = 8 + 16 + 16 + 8 + 8 + 8 + 8 + 2 + 4 + 1;
const INNER_IPV4_ICMP_OVERHEAD: usize = 20 + 8;

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
    base_udp_datagram_size: UdpDatagramSize,
    confirmed_udp_datagram_size: UdpDatagramSize,
    search_upper_udp_datagram_size: UdpDatagramSize,
    pending_candidate_udp_datagram_size: Option<UdpDatagramSize>,
    outstanding: Option<OutstandingProbe>,
    retry_count: u8,
    next_sequence: u64,
    revision: u64,
    probe_count: u64,
    success_count: u64,
    timeout_count: u64,
    send_failure_count: u64,
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
        let base = UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE);
        let upper = identity.outer_ip_family.ceiling_udp_datagram_size();
        let pending = supported
            .then(|| next_search_candidate(base, upper))
            .flatten();
        Self {
            identity: Some(identity),
            state: if supported {
                DplpmtudState::Base
            } else {
                DplpmtudState::Unsupported
            },
            supported,
            base_udp_datagram_size: base,
            confirmed_udp_datagram_size: base,
            search_upper_udp_datagram_size: upper,
            pending_candidate_udp_datagram_size: pending,
            outstanding: None,
            retry_count: 0,
            next_sequence: 1,
            revision: 1,
            probe_count: 0,
            success_count: 0,
            timeout_count: 0,
            send_failure_count: 0,
            stale_ack_count: 0,
            duplicate_ack_count: 0,
            last_success_at: None,
            last_timeout_at: None,
            last_failure_at: None,
            raise_at: None,
            last_reset_reason: Some(
                if supported {
                    "direct_committed"
                } else {
                    "dplpmtud_capability_not_negotiated"
                }
                .to_string(),
            ),
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

    pub(crate) fn outstanding_identity(&self) -> Option<DplpmtudProbeIdentity> {
        self.outstanding.map(|outstanding| outstanding.identity)
    }

    pub(crate) fn next_wakeup(&self) -> Option<Instant> {
        self.outstanding
            .map(|outstanding| outstanding.deadline)
            .or(self.raise_at)
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
                        next.confirmed_udp_datagram_size = next
                            .confirmed_udp_datagram_size
                            .max(probe.candidate_udp_datagram_size);
                        next.success_count = next.success_count.saturating_add(1);
                        next.last_success_at = Some(now);
                        push_consumed_receipt(&mut next.consumed_receipts, probe);
                        next.pending_candidate_udp_datagram_size = next_search_candidate(
                            next.confirmed_udp_datagram_size,
                            next.search_upper_udp_datagram_size,
                        );
                        if next.pending_candidate_udp_datagram_size.is_none() {
                            next.state = DplpmtudState::SearchComplete;
                            next.raise_at = Some(now + DPLPMTUD_RAISE_INTERVAL);
                        } else {
                            next.state = DplpmtudState::Searching;
                            next.raise_at = None;
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
                        let failed_upper = probe
                            .candidate_udp_datagram_size
                            .0
                            .saturating_sub(DPLPMTUD_SEARCH_GRANULARITY)
                            .max(next.confirmed_udp_datagram_size.0);
                        next.search_upper_udp_datagram_size = UdpDatagramSize(
                            next.search_upper_udp_datagram_size.0.min(failed_upper),
                        );
                        next.pending_candidate_udp_datagram_size = next_search_candidate(
                            next.confirmed_udp_datagram_size,
                            next.search_upper_udp_datagram_size,
                        );
                        if next.pending_candidate_udp_datagram_size.is_none() {
                            next.state = DplpmtudState::SearchComplete;
                            next.raise_at = Some(now + DPLPMTUD_RAISE_INTERVAL);
                        } else {
                            next.state = DplpmtudState::Searching;
                        }
                    }
                    DplpmtudTransitionDecision::Applied
                }
            }
            DplpmtudEvent::ProbeSendFailed { probe, now } => {
                if self.outstanding.map(|value| value.identity) != Some(probe) {
                    DplpmtudTransitionDecision::Noop
                } else {
                    next.outstanding = None;
                    next.send_failure_count = next.send_failure_count.saturating_add(1);
                    next.last_failure_at = Some(now);
                    next.state = DplpmtudState::Error;
                    next.raise_at = Some(now + DPLPMTUD_ERROR_RETRY_INTERVAL);
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
                    next.pending_candidate_udp_datagram_size = next_search_candidate(
                        next.confirmed_udp_datagram_size,
                        next.search_upper_udp_datagram_size,
                    );
                    next.retry_count = 0;
                    next.raise_at = None;
                    next.state = if next.pending_candidate_udp_datagram_size.is_some() {
                        DplpmtudState::Searching
                    } else {
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
                {
                    DplpmtudTransitionDecision::Noop
                } else {
                    next.state = DplpmtudState::Disabled;
                    next.supported = false;
                    next.outstanding = None;
                    next.pending_candidate_udp_datagram_size = None;
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
            base_udp_datagram_size: self.base_udp_datagram_size.0,
            confirmed_udp_datagram_size: self.confirmed_udp_datagram_size.0,
            search_upper_udp_datagram_size: self.search_upper_udp_datagram_size.0,
            confirmed_outer_ip_packet_size: family.map(|family| {
                self.confirmed_udp_datagram_size
                    .outer_ip_packet_size(family)
                    .0
            }),
            overlay_payload_budget: self
                .confirmed_udp_datagram_size
                .overlay_payload_budget()
                .map(|value| value.0),
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
            probe_count: self.probe_count,
            success_count: self.success_count,
            timeout_count: self.timeout_count,
            send_failure_count: self.send_failure_count,
            stale_ack_count: self.stale_ack_count,
            duplicate_ack_count: self.duplicate_ack_count,
            live_worker,
        }
    }
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
    if upper.0 <= confirmed.0.saturating_add(DPLPMTUD_SEARCH_GRANULARITY) {
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
    pub(crate) base_udp_datagram_size: u32,
    pub(crate) confirmed_udp_datagram_size: u32,
    pub(crate) search_upper_udp_datagram_size: u32,
    pub(crate) confirmed_outer_ip_packet_size: Option<u32>,
    pub(crate) overlay_payload_budget: Option<u32>,
    pub(crate) outstanding_probe: Option<DplpmtudOutstandingSnapshot>,
    pub(crate) last_success_age_ms: Option<u64>,
    pub(crate) last_timeout_age_ms: Option<u64>,
    pub(crate) last_failure_age_ms: Option<u64>,
    pub(crate) reset_reason: Option<String>,
    pub(crate) reset_count: u64,
    pub(crate) revision: u64,
    pub(crate) probe_count: u64,
    pub(crate) success_count: u64,
    pub(crate) timeout_count: u64,
    pub(crate) send_failure_count: u64,
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
    } else if let Some(bytes) = payload.strip_prefix(DPLPMTUD_ACK_PREFIX) {
        (DplpmtudControlKind::Ack, bytes)
    } else {
        return None;
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
    pub(crate) path_identity: DplpmtudPathIdentity,
    pub(crate) probe_identity: DplpmtudProbeIdentity,
    pub(crate) wire_token: DplpmtudWireToken,
    pub(crate) deadline: Instant,
}

#[derive(Debug)]
pub(crate) struct DplpmtudWorkerLease {
    pub(crate) peer_id: String,
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

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DplpmtudInstallDecision {
    Spawned,
    Unchanged,
    Unsupported,
    Closed,
    CapacityExceeded,
}

#[derive(Debug)]
pub(crate) struct DplpmtudInstallResult {
    pub(crate) decision: DplpmtudInstallDecision,
    pub(crate) worker: Option<DplpmtudWorkerLease>,
}

struct RuntimeEntry {
    machine: DplpmtudStateMachine,
    path_cookie: [u8; 16],
    cancel_tx: Option<watch::Sender<bool>>,
    notify: Arc<Notify>,
    worker_running: bool,
    send_in_progress: bool,
}

#[derive(Default)]
struct RuntimeRegistry {
    entries: HashMap<String, RuntimeEntry>,
    supported_sessions: HashMap<String, u64>,
    closed: bool,
}

/// Bounded, cloneable registry shared by one UDP publication, its scheduler,
/// receive path and diagnostics. No network I/O occurs while the mutex is held.
#[derive(Clone, Default)]
pub(crate) struct DplpmtudRuntime {
    registry: Arc<StdMutex<RuntimeRegistry>>,
    snapshots: Arc<StdRwLock<HashMap<String, DplpmtudSnapshot>>>,
}

impl DplpmtudRuntime {
    pub(crate) fn new() -> Self {
        Self::default()
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

    pub(crate) fn is_supported(&self, peer_id: &str, peer_session_generation: u64) -> bool {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .supported_sessions
            .get(peer_id)
            .is_some_and(|generation| *generation == peer_session_generation)
    }

    pub(crate) fn install_path(
        &self,
        identity: DplpmtudPathIdentity,
        supported: bool,
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
                if supported && existing.worker_running {
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Unchanged,
                        worker: None,
                    };
                }
                if supported {
                    let (cancel_tx, cancel_rx) = watch::channel(false);
                    existing.cancel_tx = Some(cancel_tx);
                    existing.worker_running = true;
                    existing.send_in_progress = false;
                    let notify = existing.notify.clone();
                    self.publish_snapshot_locked(&peer_id, existing, now);
                    return DplpmtudInstallResult {
                        decision: DplpmtudInstallDecision::Spawned,
                        worker: Some(DplpmtudWorkerLease {
                            peer_id,
                            identity,
                            cancel_rx,
                            notify,
                        }),
                    };
                }
                if let Some(cancel_tx) = existing.cancel_tx.take() {
                    let _ = cancel_tx.send(true);
                }
                existing.worker_running = false;
                existing.send_in_progress = false;
                existing.machine = DplpmtudStateMachine::for_path(identity, false, now);
                self.publish_snapshot_locked(&peer_id, existing, now);
                return DplpmtudInstallResult {
                    decision: DplpmtudInstallDecision::Unsupported,
                    worker: None,
                };
            } else if let Some(cancel_tx) = existing.cancel_tx.take() {
                let _ = cancel_tx.send(true);
            }
        }

        let mut path_cookie = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut path_cookie);
        let notify = Arc::new(Notify::new());
        if !supported {
            let entry = RuntimeEntry {
                machine: DplpmtudStateMachine::for_path(identity, false, now),
                path_cookie,
                cancel_tx: None,
                notify,
                worker_running: false,
                send_in_progress: false,
            };
            registry.entries.insert(peer_id.clone(), entry);
            let entry = registry
                .entries
                .get(&peer_id)
                .expect("entry inserted above");
            self.publish_snapshot_locked(&peer_id, entry, now);
            return DplpmtudInstallResult {
                decision: DplpmtudInstallDecision::Unsupported,
                worker: None,
            };
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let entry = RuntimeEntry {
            machine: DplpmtudStateMachine::for_path(identity.clone(), true, now),
            path_cookie,
            cancel_tx: Some(cancel_tx),
            notify: notify.clone(),
            worker_running: true,
            send_in_progress: false,
        };
        registry.entries.insert(peer_id.clone(), entry);
        let entry = registry
            .entries
            .get(&peer_id)
            .expect("entry inserted above");
        self.publish_snapshot_locked(&peer_id, entry, now);
        DplpmtudInstallResult {
            decision: DplpmtudInstallDecision::Spawned,
            worker: Some(DplpmtudWorkerLease {
                peer_id,
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
            }
            registry.supported_sessions.remove(&peer_id);
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
    }

    pub(crate) fn schedule_probe(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
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
        if !entry.worker_running || entry.machine.identity() != Some(identity) {
            return None;
        }
        if entry.machine.state() == DplpmtudState::Base {
            let _ = entry.machine.apply(DplpmtudEvent::StartSearch { now });
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
            path_identity: identity.clone(),
            probe_identity,
            wire_token,
            deadline,
        })
    }

    /// Linearization point immediately before a worker attempts the kernel
    /// send. Cancellation that wins first prevents the send.
    pub(crate) fn begin_probe_send(&self, plan: &DplpmtudProbePlan) -> bool {
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
            || entry.machine.identity() != Some(&plan.path_identity)
            || entry.machine.outstanding_identity() != Some(plan.probe_identity)
            || entry.send_in_progress
        {
            return false;
        }
        entry.send_in_progress = true;
        true
    }

    pub(crate) fn finish_probe_send(
        &self,
        plan: &DplpmtudProbePlan,
        result: Result<(), ()>,
        now: Instant,
    ) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(&plan.peer_id) else {
            return;
        };
        entry.send_in_progress = false;
        if entry.machine.identity() != Some(&plan.path_identity) {
            return;
        }
        match result {
            Ok(()) => {
                let _ = entry.machine.apply(DplpmtudEvent::ProbeSent {
                    probe: plan.probe_identity,
                    now,
                });
            }
            Err(()) => {
                let _ = entry.machine.apply(DplpmtudEvent::ProbeSendFailed {
                    probe: plan.probe_identity,
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
        if entry.machine.identity() != Some(&plan.path_identity) {
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
        let decision = if entry.machine.identity() != Some(current_path)
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
                    && entry.machine.identity() == Some(&plan.path_identity)
                    && entry.machine.outstanding_identity() == Some(plan.probe_identity)
            })
    }

    pub(crate) fn worker_state(
        &self,
        peer_id: &str,
        identity: &DplpmtudPathIdentity,
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
            .filter(|entry| entry.machine.identity() == Some(identity))
            .map(|entry| {
                (
                    entry.machine.state(),
                    entry.machine.next_wakeup(),
                    entry.machine.outstanding_identity(),
                )
            })
    }

    pub(crate) fn finish_worker(&self, peer_id: &str, identity: &DplpmtudPathIdentity) {
        let mut registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(entry) = registry.entries.get_mut(peer_id) else {
            return;
        };
        if entry.machine.identity() == Some(identity) {
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
            .filter(|entry| entry.worker_running)
            .count()
    }

    fn publish_snapshot_locked(&self, peer_id: &str, entry: &RuntimeEntry, now: Instant) {
        self.snapshots
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(
                peer_id.to_string(),
                entry.machine.snapshot(now, entry.worker_running),
            );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DplpmtudAckIngress {
    pub(crate) remote_endpoint: SocketAddr,
    pub(crate) local_endpoint: SocketAddr,
    pub(crate) socket: DplpmtudSocketIdentity,
}
