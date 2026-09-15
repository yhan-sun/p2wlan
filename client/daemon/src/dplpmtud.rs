//! Authenticated Direct UDP Datagram Packetization Layer Path MTU Discovery.
//!
//! This phase deliberately keeps three layers distinct:
//! - [`OuterIpPacketSize`]: complete outer IP packet (IP + UDP + datagram);
//! - [`UdpDatagramSize`]: bytes passed to `UdpSocket::send_to`;
//! - [`OverlayPayloadBudget`]: decrypted WireGuard plaintext budget.
//!
//! The reducer below never selects an active path and never mutates Direct
//! health. A probe timeout only narrows one exact Direct path's size search.

#[cfg(test)]
pub(crate) use runtime::DplpmtudWorkerLease;

use crate::peer::{ActiveBusinessPath, DirectValidationIdentity, PathEpoch, PeerPathLifecycle};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

mod state_machine;
pub(crate) use state_machine::{
    DplpmtudEvent, DplpmtudProbeIdentity, DplpmtudProbeSendFailure, DplpmtudSnapshot,
    DplpmtudState, DplpmtudStateMachine, DplpmtudTransitionDecision,
};
mod wire;
pub(crate) use wire::{
    build_ack_inner_packet, build_encrypted_probe_plaintext,
    direct_validation_capability_extension, direct_validation_supports_dplpmtud,
    parse_control_packet, DplpmtudControlKind, DplpmtudControlPacket, DplpmtudWireToken,
};
mod runtime;
pub(crate) use runtime::{
    DirectBusinessSendToken, DplpmtudAckIngress, DplpmtudInstallDecision, DplpmtudProbePlan,
    DplpmtudRuntime, DplpmtudWorkerIngress, DplpmtudWorkerStart,
};
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

#[cfg(test)]
mod tests;
