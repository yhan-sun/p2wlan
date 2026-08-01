//! UDP Hole Punching — establish direct P2P connection through NAT.
//!
//! ## Protocol
//!
//! Both sides simultaneously send punch packets to each other's candidate
//! addresses. When one side receives a punch, it sends an ACK back. When
//! an ACK is received, the connection is established.
//!
//! ```text
//! Node A                    Node B
//!   │── PUNCH ─────────────→│
//!   │←───────────── PUNCH ──│
//!   │── ACK ───────────────→│
//!   │←─────────────── ACK ──│
//!   │                        │
//!   │<── Tunnel Established ─→
//! ```
//!
//! ## Packet Format
//!
//! Version 1 is the original unauthenticated 14-byte probe kept for
//! backwards compatibility:
//!
//! ```text
//! [0x50 0x4E 0x43 0x48]  Magic ("PNCH")
//! [0x01]                 Version (1)
//! [0x01 or 0x02]         Type (1=Punch, 2=ACK)
//! [8 bytes]              Nonce (random, for correlation)
//! ```
//!
//! Version 2 binds probes to the authenticated peer identities known from the
//! control plane and protects the frame with a truncated HMAC-BLAKE2s MAC.

use std::net::SocketAddr;
use std::time::Duration;

use p2pnet_crypto::hmac;
use tokio::net::UdpSocket;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

use crate::error::{NatError, Result};

/// Magic bytes for punch packets: "PNCH".
const PUNCH_MAGIC: [u8; 4] = [0x50, 0x4E, 0x43, 0x48];

/// Legacy unauthenticated protocol version.
const PUNCH_VERSION: u8 = 1;

/// Authenticated protocol version.
const AUTH_PUNCH_VERSION: u8 = 2;

/// Punch packet type.
const TYPE_PUNCH: u8 = 1;
/// ACK packet type.
const TYPE_ACK: u8 = 2;

/// Total legacy punch packet size.
const PUNCH_PACKET_SIZE: usize = 14;

/// Length of the truncated authentication tag on v2 probes.
const AUTH_PUNCH_MAC_SIZE: usize = 16;

/// ICE-style nomination bit for authenticated v2 connectivity checks.
const AUTH_PUNCH_FLAG_USE_CANDIDATE: u8 = 0x01;

/// Domain separator for authenticated UDP probe MACs.
const AUTH_PUNCH_MAC_DOMAIN: &[u8] = b"p2wlan-udp-probe-v2";

/// Symmetric MAC key for authenticated UDP probe packets.
pub type ProbeMacKey = [u8; 32];

/// Configuration for hole punching.
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// Maximum time to spend punching.
    pub timeout: Duration,
    /// Interval between punch packets.
    pub interval: Duration,
    /// Maximum number of punch attempts per candidate.
    pub max_attempts: u32,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            interval: Duration::from_millis(200),
            max_attempts: 50,
        }
    }
}

/// Result of a hole punching attempt.
#[derive(Debug, Clone)]
pub struct PunchResult {
    /// Whether the connection was successfully established.
    pub connected: bool,
    /// The peer address that responded (if connected).
    pub peer_addr: Option<SocketAddr>,
    /// Elapsed time.
    pub elapsed: Duration,
    /// Number of punch packets sent.
    pub packets_sent: u32,
}

/// Public punch datagram type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchPacketKind {
    /// Probe sent to open/refresh a NAT mapping.
    Punch,
    /// Acknowledgement for a received probe.
    Ack,
}

/// A decoded punch protocol datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPunchPacket {
    /// Packet kind.
    pub kind: PunchPacketKind,
    /// Correlation nonce.
    pub nonce: [u8; 8],
    /// Wire protocol version.
    pub version: u8,
    /// Source node ID for authenticated v2 probes.
    pub source_node_id: Option<String>,
    /// Target node ID for authenticated v2 probes.
    pub target_node_id: Option<String>,
    /// Sender-side local network generation for authenticated v2 probes.
    pub generation: Option<u64>,
    /// Whether this check nominates the candidate pair for direct data trials.
    pub use_candidate: bool,
    /// Whether the packet MAC was verified.
    pub authenticated: bool,
}

/// Identity fields that can be read before validating a v2 probe MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedPunchIdentity {
    /// Packet kind.
    pub kind: PunchPacketKind,
    /// Source node ID claimed by the sender.
    pub source_node_id: String,
    /// Target node ID claimed by the sender.
    pub target_node_id: String,
    /// Sender-side local network generation.
    pub generation: u64,
    /// Whether this check nominates the candidate pair for direct data trials.
    pub use_candidate: bool,
}

mod authenticated;
mod packet;
mod runtime;

pub use authenticated::{
    build_authenticated_punch_ack, build_authenticated_punch_packet,
    build_authenticated_punch_packet_with_nomination, build_authenticated_punch_packet_with_nonce,
    decode_authenticated_punch_packet, peek_authenticated_punch_identity,
};
pub use packet::{
    build_punch_ack, build_punch_packet, build_punch_packet_with_nonce, decode_punch_packet,
};
pub use runtime::{hole_punch, send_keepalive, send_punch};

#[cfg(test)]
mod tests;
