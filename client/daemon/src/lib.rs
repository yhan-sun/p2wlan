//! # p2wlan-daemon
//!
//! The main client daemon that runs the P2P virtual network.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────┐
//! │                     Daemon                          │
//! │  ┌─────────┐  ┌──────────┐  ┌──────────────────┐   │
//! │  │  Config  │  │ Control  │  │   PeerManager    │   │
//! │  └─────────┘  │  Client  │  │  (WireGuard/Relay)│   │
//! │               └──────────┘  └──────────────────┘   │
//! │  ┌─────────┐  ┌──────────┐  ┌──────────────────┐   │
//! │  │  DNS    │  │   ACL    │  │  PortMapping     │   │
//! │  └─────────┘  └──────────┘  └──────────────────┘   │
//! │                      ↕                              │
//! │               ┌───────────┐                         │
//! │               │ TUN NIC   │                         │
//! │               └───────────┘                         │
//! └─────────────────────────────────────────────────────┘
//! ```
//!
//! ## Phases Implemented
//!
//! - Phase 1: TUN virtual interface
//! - Phase 2: WireGuard encryption & handshake
//! - Phase 3: NAT traversal (STUN / ICE / UDP hole punching)
//! - Phase 4: Relay (DERP-like)
//! - Phase 5: Control plane client, peer management, ACL, DNS, port mapping

pub mod acl;
mod candidate_refresh;
pub mod config;
pub mod control;
pub mod dataplane;
pub mod diagnostics;
pub mod dns;
pub mod error;
pub mod gateway_mapping;
mod network_outbound;
pub mod peer;
pub mod port_mapping;
pub mod relay;
mod relay_runtime;
pub mod route;
pub mod tasks;
pub mod transport;
pub mod traversal_history;
pub mod udp;

// Re-export key types
pub use config::Config;
pub use error::{DaemonError, Result};

// ============================================================
// Daemon
// ============================================================

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use igd_next::{aio::tokio::search_gateway, PortMappingProtocol, SearchOptions};
use p2pnet_crypto::{DhKeyPair, NodeIdentity};
use p2pnet_nat::{CandidateGatherReport, CandidateSource, MappingBehavior, NatProfile};
use rand::RngCore;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn};

use acl::AclEngine;
use candidate_refresh::{
    add_peer_reflexive_candidate_to_set, advertised_udp_endpoint, candidate_endpoints_from_report,
    control_udp_endpoint_from_candidates, maybe_add_port_mapping_udp_candidate,
    publish_local_candidates_to_known_peers, run_udp_candidate_refresh,
    stable_network_candidate_signature, truncate_signal_candidates, UdpCandidateRefreshContext,
};
#[cfg(test)]
use candidate_refresh::{
    candidate_refresh_requires_network_generation_advance,
    compact_volatile_public_signal_candidates, ipv4_mapped_octets, parse_first_ipv4,
    parse_nat_pmp_mapping_response, parse_nat_pmp_public_address_response,
    parse_pcp_mapping_response, preserve_peer_reflexive_candidates,
    should_update_stable_control_endpoint,
};
#[cfg(test)]
use control::RelayCatalogEntry;
use control::{ControlClient, ControlEvent};
use dataplane::{DataPlane, InboundPacket, OutboundPacket};
use diagnostics::{run_diagnostics_server_with_retry, DiagnosticsContext};
use dns::DnsResolver;
use gateway_mapping::{record_method_result, GatewayMappingDiagnostics, GatewayMappingRuntime};
use network_outbound::run_network_outbound;
use p2pnet_tun::{InterfaceConfig, Ipv4Packet, TunDevice, VirtualInterface};
use p2pnet_wireguard::{
    HandshakeInitiator, HandshakeResponder, MessageInitiation, MessageResponse, TransportSession,
};
use peer::{
    ConnectionState, PeerManager, DIRECT_RETRY_BASE_INTERVAL, REASON_DIRECT_PROBE_FAILED,
    REASON_HANDSHAKE_TIMEOUT,
};
use port_mapping::PortMappingManager;
#[cfg(test)]
use relay::RelayCandidateConfig;
use relay::{RelaySelectionDiagnostics, RelayTicketCache, RelayTransport};
use relay_runtime::{
    effective_relay_allow_insecure_plaintext, infer_default_relay_servers,
    relay_candidates_from_sources, run_relay_peer_validation_loop, udp_observers_from_sources,
    RelaySupervisor,
};
#[cfg(test)]
use relay_runtime::{relay_spec_is_plaintext, send_relay_validation_packet, RelayValidationPacket};
use transport::{EncryptedPeerPacket, ReceivedEncryptedPacket, WireGuardTransport};
use udp::{PeerReflexiveObservation, UdpTransport};

include!("lib/pending_handshake.rs");
/// Maximum number of handshake re-initiation attempts before giving up.
const MAX_HANDSHAKE_ATTEMPTS: u32 = 5;
/// Handshake timeout before pending entry is cleared.
const HANDSHAKE_TIMEOUT_SECS: u64 = 90;
/// Grace period for UDP/STUN/port-mapping candidate gathering before signaling a WireGuard offer.
///
/// Real home gateways can take a little over 3s when STUN and short UPnP/PCP/NAT-PMP discovery
/// race at startup.  Sending an offer with zero candidates is especially harmful for symmetric-like
/// NATs because the peer starts its synchronized punch window without any usable destination for us.
const CANDIDATE_READY_TIMEOUT_MS: u64 = 8_000;
/// Public STUN fallbacks used when older configs do not specify STUN servers.
const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.miwifi.com:3478",
    "stun.l.google.com:19302",
];
/// Re-gather candidates often enough to notice Wi-Fi/hotspot changes.
const CANDIDATE_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// Server-side signaling currently rejects candidate lists above this size.
///
/// Keep this large enough for a linear symmetric NAT to publish its observed
/// STUN group plus the full predicted successor run. Air-like NATs can need
/// the high-teens successor ports before a peer-reflexive path appears.
const MAX_SIGNAL_CANDIDATES: usize = 96;
/// A bounded public candidate group preserves ICE-style linear NAT coverage.
///
/// Air-like linear symmetric NATs need the STUN group plus a predicted run
/// that reaches the high-teens port jumps seen in relay-first/direct-chase ICE.
/// The overall signaling cap still prevents broad scanning.
const MAX_SIGNAL_VOLATILE_PUBLIC_PER_PUBLIC_IP: usize = MAX_SIGNAL_CANDIDATES;
/// Keep UPnP discovery short so unsupported gateways never delay startup much.
const UPNP_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);
/// Short UPnP lease; refreshed by the regular candidate refresh loop.
const PORT_MAPPING_LEASE_SECS: u32 = 120;
/// NAT-PMP / PCP share UDP port 5351 and should fail fast when unsupported.
const NAT_MAPPING_DISCOVERY_TIMEOUT: Duration = Duration::from_millis(1_500);
const NAT_MAPPING_CONTROL_PORT: u16 = 5351;
/// Retry unavailable gateway discovery slowly; repeated 15s multicast probes
/// are noisy and rarely turn a disabled router into an IGD.
const PORT_MAPPING_FAILURE_RETRY: Duration = Duration::from_secs(60);
/// Active-path liveness must react much faster than a typical NAT mapping lease.
const DIRECT_LIVENESS_INTERVAL_MAX: Duration = Duration::from_secs(8);
/// Delay advertised in signaling so both peers can align a short UDP punching burst.
const RELAY_ASSISTED_PUNCH_DELAY: Duration = Duration::from_millis(1_500);
/// Start slightly before the advertised punch timestamp to absorb clock skew,
/// HTTP wake-up jitter, and scheduler latency while still keeping the packet
/// budget bounded by the existing probe schedule.
const RELAY_ASSISTED_PUNCH_LEAD: Duration = Duration::from_millis(250);
/// Ignore very stale relay-assisted windows and punch immediately instead.
const RELAY_ASSISTED_PUNCH_STALE_AFTER: Duration = Duration::from_secs(3);
/// Re-advertise peer-reflexive observations a few times during the most useful
/// NAT opening window. The UDP layer already rate-limits duplicate observations,
/// so this stays bounded while giving the remote side several chances to catch
/// the learned source port.
const PEER_REFLEXIVE_SIGNAL_DELAYS: [Duration; 4] = [
    Duration::ZERO,
    Duration::from_millis(80),
    Duration::from_millis(250),
    Duration::from_millis(700),
];
/// Send a few real encrypted packets over a freshly observed UDP path. The
/// packets are valid ICMP echo requests, so the remote TUN can answer and both
/// sides can confirm the WireGuard data path without waiting for user traffic.
const DIRECT_ENCRYPTED_VALIDATION_DELAYS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(80),
    Duration::from_millis(250),
];
/// A peer-reflexive ACK can arrive before the offer/answer handler installs the
/// WireGuard session. Keep the observed NAT mapping alive while waiting for the
/// handshake instead of permanently discarding the only useful endpoint.
const DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT: Duration = Duration::from_secs(8);
const DIRECT_ENCRYPTED_VALIDATION_SESSION_POLL: Duration = Duration::from_millis(50);
const DIRECT_ENCRYPTED_VALIDATION_PAYLOAD: &[u8] = b"p2wlan-direct-validation";
/// Avoid overlapping offer/answer, refresh, and retry bursts for one peer.
/// Competing bursts can create distinct NAT mappings and reduce, rather than
/// improve, the chance that both peers hit the same opening window.
const PUNCH_SESSION_DEDUP_WINDOW: Duration = Duration::from_secs(3);
const DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW: Duration = Duration::from_secs(1);
/// A traversal task must release its per-peer lease even if a transport call
/// stalls or an unexpectedly large candidate set reaches the scheduler.
const PUNCH_SESSION_HARD_DEADLINE: Duration = Duration::from_secs(8);

include!("lib/punch_dedup.rs");
include!("lib/daemon/core.rs");
include!("lib/daemon/udp_direct.rs");
include!("lib/daemon/handshake_maintenance.rs");
include!("lib/daemon/relay_spawn.rs");
include!("lib/daemon/dataplane_tasks.rs");
include!("lib/daemon/control_events.rs");
include!("lib/daemon/run.rs");
include!("lib/daemon/handshake.rs");
include!("lib/daemon/accessors.rs");
include!("lib/direct_runtime.rs");
include!("lib/stun.rs");
include!("lib/lifecycle.rs");
#[cfg(test)]
#[path = "lib/tests.rs"]
mod tests;
