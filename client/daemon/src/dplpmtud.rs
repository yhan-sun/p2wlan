//! Authenticated Direct UDP Datagram Packetization Layer Path MTU Discovery.
//!
//! This phase deliberately keeps three layers distinct:
//! - [`sizes::OuterIpPacketSize`]: complete outer IP packet (IP + UDP + datagram);
//! - [`sizes::UdpDatagramSize`]: bytes passed to `UdpSocket::send_to`;
//! - [`sizes::OverlayPayloadBudget`]: decrypted WireGuard plaintext budget.
//!
//! The reducer below never selects an active path and never mutates Direct
//! health. A probe timeout only narrows one exact Direct path's size search.

mod identity;
mod runtime;
mod sizes;
mod state_machine;
mod wire;

pub(crate) use identity::{DplpmtudAckIngress, DplpmtudPathIdentity, DplpmtudSocketIdentity};
pub(crate) use runtime::{
    build_encrypted_probe_plaintext, DirectBusinessSendToken, DplpmtudInstallDecision,
    DplpmtudProbePlan, DplpmtudRuntime, DplpmtudWorkerIngress, DplpmtudWorkerStart,
    DPLPMTUD_WORKER_MAX_LIFETIME, MAX_TRACKED_DPLPMTUD_PEERS,
};
pub(crate) use sizes::{
    OuterIpFamily, DPLPMTUD_BASE_UDP_DATAGRAM_SIZE, WIREGUARD_UDP_DATAGRAM_OVERHEAD,
};
pub(crate) use state_machine::{
    DplpmtudProbeSendFailure, DplpmtudSnapshot, DplpmtudState, DplpmtudTransitionDecision,
    DPLPMTUD_PROBE_TIMEOUT,
};
pub(crate) use wire::{
    build_ack_inner_packet, direct_validation_capability_extension,
    direct_validation_supports_dplpmtud, parse_control_packet, DplpmtudControlKind,
    DplpmtudControlPacket, DplpmtudWireToken,
};

#[cfg(test)]
pub(crate) use runtime::DplpmtudWorkerLease;
#[cfg(test)]
pub(crate) use sizes::{
    UdpDatagramSize, DPLPMTUD_IPV4_UDP_DATAGRAM_CEILING, DPLPMTUD_IPV6_UDP_DATAGRAM_CEILING,
};
