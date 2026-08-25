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
pub mod build_info;
mod candidate_refresh;
pub mod config;
pub mod connection_timeline;
pub mod control;
pub mod dataplane;
pub mod diagnostics;
pub mod dns;
// The bounded MTU decision state is currently exercised as a pure module and
// is not wired into the live probe scheduler yet.
#[allow(dead_code)]
pub(crate) mod dplpmtud;
pub mod error;
pub mod gateway_mapping;
pub mod incarnation;
pub mod netenv;
mod network_outbound;
pub(crate) mod path_commit;
pub mod peer;
pub mod port_mapping;
pub mod relay;
pub(crate) mod relay_probe;
pub(crate) mod relay_runtime;
pub mod route;
pub mod tasks;
pub mod transport;
pub mod traversal_history;
pub mod udp;

// Re-export key types
pub use config::{Config, PathPolicy};
pub use error::{DaemonError, Result};

use crate::udp::estimate_remote_scatter_punch_deadline;

// ============================================================
// Daemon
// ============================================================

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use igd_next::{aio::tokio::search_gateway, PortMappingProtocol, SearchOptions};
use p2pnet_crypto::{DhKeyPair, NodeIdentity};
use p2pnet_nat::{CandidateGatherReport, CandidateSource, MappingBehavior, NatProfile};
use rand::RngCore;
use tokio::net::lookup_host;
#[cfg(test)]
#[allow(unused_imports)]
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch, Mutex, RwLock};
use tokio::time::{interval, sleep, timeout};
use tracing::{debug, error, info, warn};

use acl::AclEngine;
use candidate_refresh::{
    add_peer_reflexive_candidate_to_set, advertised_udp_endpoint, candidate_endpoints_from_report,
    candidate_refresh_requires_commit, candidate_set_change_reason, candidate_set_hash,
    control_udp_endpoint_from_candidates, maybe_add_port_mapping_udp_candidate,
    network_identity_changed, prepare_signal_candidates_and_network_identity,
    publish_local_candidates_to_known_peers, run_udp_candidate_refresh, UdpCandidateRefreshContext,
};
#[cfg(test)]
use candidate_refresh::{
    candidate_refresh_requires_network_generation_advance,
    compact_volatile_public_signal_candidates, ipv4_mapped_octets, parse_first_ipv4,
    parse_nat_pmp_mapping_response, parse_nat_pmp_public_address_response,
    parse_pcp_mapping_response, preserve_peer_reflexive_candidates,
    should_update_stable_control_endpoint, stable_network_candidate_signature,
    truncate_signal_candidates,
};
use connection_timeline::ConnectionTimeline;
#[cfg(test)]
use control::RelayCatalogEntry;
use control::{ControlClient, ControlEvent, PeerOfferSendFailure};
use dataplane::{DataPlane, InboundPacket, OutboundPacket};
use diagnostics::{
    run_diagnostics_server_with_retry_ready, run_speedtest_server_with_retry, DiagnosticsContext,
};
use dns::DnsResolver;
use gateway_mapping::{record_method_result, GatewayMappingDiagnostics, GatewayMappingRuntime};
use network_outbound::{run_network_outbound, RelayStartupWait};
#[cfg(target_os = "android")]
use p2pnet_tun::AndroidTunMode;
use p2pnet_tun::{InterfaceConfig, Ipv4Packet, TunDevice, VirtualInterface};
use p2pnet_wireguard::{
    HandshakeInitiator, HandshakeResponder, MessageInitiation, MessageResponse, TransportKeyPair,
    TransportSession,
};
use peer::{
    CandidateSetApplyResult, ConnectionState, DirectProbeTargetSet, HardHardSessionRecord,
    HardHardSessionState, PeerManager, PeerSessionGeneration, PendingRecoveryTarget,
    ProbeBindingStage, RecoveryAdmission, DIRECT_RETRY_BASE_INTERVAL, REASON_DIRECT_PROBE_FAILED,
    REASON_HANDSHAKE_TIMEOUT, RECOVERY_EPOCH_ACK_FEEDBACK_WINDOW,
};
use port_mapping::PortMappingManager;
#[cfg(test)]
use relay::RelayCandidateConfig;
use relay::{RelaySelectionDiagnostics, RelayTicketCache, RelayTransport};
use relay_runtime::{
    effective_relay_allow_insecure_plaintext, infer_default_relay_servers,
    relay_candidates_from_sources, run_relay_peer_probe_loop, run_relay_peer_validation_loop,
    udp_observers_from_sources, RelaySupervisor,
};
#[cfg(test)]
use relay_runtime::{relay_spec_is_plaintext, send_relay_validation_packet, RelayValidationPacket};
#[cfg(test)]
use transport::parse_direct_validation_token;
use transport::{
    build_direct_validation_payload, DirectValidationKind, InboundEvidenceFeed,
    ReceivedEncryptedPacket, ResponderSessionCommit, ResponderSessionStage, TransportSessionStatus,
    WireGuardTransport,
};
use udp::{
    FreshMappingOutcome, FreshMappingRejection, FreshMappingResult, PeerReflexiveIngress,
    PeerReflexiveObservation, PunchSendReport, UdpTransport,
};

include!("lib/pending_handshake.rs");
/// Maximum number of handshake re-initiation attempts before giving up.
const MAX_HANDSHAKE_ATTEMPTS: u32 = 5;
/// Initial signaling should retry quickly; the independent background punch
/// session can continue while a lost offer/answer is retried.
///
/// The timeout is a hard cleanup bound for the control-plane offer/answer
/// transaction and its session token.  Relay-first signaling no longer waits
/// for a STUN refresh: a cached candidate set, or an empty set while relay is
/// available, establishes the encrypted session; later candidates belong to
/// the background Direct upgrade.  A late answer still has to match its
/// pending session_id instead of being accepted as stale state.
const HANDSHAKE_TIMEOUT_SECS: u64 = 60;
/// Rekeys must retry several times before the old 180-second key lifetime ends.
const REKEY_HANDSHAKE_TIMEOUT_SECS: u64 = 45;
/// Retain the exact responder answer/key material long enough to replay a
/// duplicate offer idempotently instead of generating a second Noise session.
const RESPONDER_HANDSHAKE_CACHE_TTL: Duration = Duration::from_secs(120);
/// Short grace period for UDP/STUN/port-mapping candidates before WireGuard signaling.
///
/// Startup traffic must be able to fall back to relay quickly.  Candidate
/// refresh publishes/trickles UDP candidates later, so a slow STUN or gateway
/// probe must not hold the WireGuard session hostage for several seconds.
const CANDIDATE_READY_TIMEOUT_MS: u64 = 300;
/// Host candidates are published immediately after the UDP socket binds, but
/// the first full STUN/prediction snapshot is committed a moment later. Give
/// that startup gather a bounded opportunity to win the first offer so a
/// brand-new session does not advertise only the provisional host endpoint.
/// Relay availability still wins immediately, and the timeout preserves a
/// bounded fallback when STUN is unavailable.
const INITIAL_CANDIDATE_READY_TIMEOUT_MS: u64 = 750;
/// The first UDP candidate window is a latency-sensitive hint, not the final
/// NAT diagnosis.  Bound each observer wait so one silent STUN endpoint
/// cannot delay the first public candidate and the first Direct punch.  The
/// normal refresh immediately follows with the configured full timeout.
const DIRECT_STARTUP_STUN_TIMEOUT: Duration = Duration::from_millis(350);
/// Caller-side budget for the startup endpoint publish.  The publish travels
/// the handshake control lane; a pathological lane must never stall UDP
/// transport startup or the signal that follows a candidate refresh.
const STARTUP_ENDPOINT_PUBLISH_BUDGET_MS: u64 = 1500;
const PRE_SIGNAL_ENDPOINT_PUBLISH_BUDGET_MS: u64 = 1200;
/// Public STUN fallbacks used when older configs do not specify STUN servers.
const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.cloudflare.com:3478",
    "stun.miwifi.com:3478",
    "stun.l.google.com:19302",
];
/// Re-gather candidates often enough to notice Wi-Fi/hotspot changes.
const CANDIDATE_REFRESH_INTERVAL: Duration = Duration::from_secs(15);
/// Retry candidate discovery promptly when the bounded startup STUN probe
/// yielded only host/predicted candidates.  A normal snapshot keeps the
/// 15-second network-change refresh cadence; only the not-ready startup case
/// gets this extra attempt.
const CANDIDATE_REFRESH_INITIAL_RETRY_DELAY: Duration = Duration::from_millis(500);
/// Keep retrying a host-only startup snapshot while no locally observed
/// public mapping exists. A single retry followed by the normal 15-second
/// cadence left Air unable to publish a usable endpoint until ~16 seconds
/// after boot, which made Direct miss the desired sub-10-second window even
/// though relay-first was already available.
const CANDIDATE_REFRESH_NO_PUBLIC_RETRY_INTERVAL: Duration = Duration::from_secs(3);
/// Server-side signaling currently rejects candidate lists above this size.
///
/// Keep this large enough for a linear symmetric NAT to publish its observed
/// STUN group plus the full predicted successor run. Air-like NATs can need
/// the high-teens successor ports before a peer-reflexive path appears.
const MAX_SIGNAL_CANDIDATES: usize = 96;
/// Reserve a small part of the signaling budget for physical LAN host
/// candidates. A hard-NAT prediction window can otherwise consume all 96
/// entries and make same-LAN discovery impossible until a later refresh.
const MAX_SIGNAL_LAN_HOST_CANDIDATES: usize = 8;
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
///
/// Hard carrier / campus NATs can expose very short UDP mapping lifetimes
/// (the field logs show a 250ms lower bound).  We refresh candidates
/// immediately before signaling and start slightly before the rendezvous
/// timestamp, so the effective local wait should stay inside that lower bound.
const RELAY_ASSISTED_PUNCH_DELAY: Duration = Duration::from_millis(500);
/// Start slightly before the advertised punch timestamp to absorb clock skew,
/// HTTP wake-up jitter, and scheduler latency while still keeping the packet
/// budget bounded by the existing probe schedule.
const RELAY_ASSISTED_PUNCH_LEAD: Duration = Duration::from_millis(250);
/// Send a small immediate candidate window before the synchronized rendezvous
/// window. The synchronized window is still required for dependent NATs, but
/// waiting for it makes ordinary/public paths pay an avoidable 500ms tax.
/// Keeping this window small preserves the per-peer probe budget and leaves the
/// full candidate/scatter sweep as the lossless fallback.
const DIRECT_FAST_PROBE_MAX_CANDIDATES: usize = 8;
/// A fresh-prediction/peer-reflexive window is already authenticated control
/// evidence, but its useful port may sit behind the ordinary signaled prefix.
/// Give that bounded window a larger immediate opportunity without widening
/// the normal candidate prefix or bypassing the per-peer probe budget.
const DIRECT_FAST_PROBE_PREDICTED_MAX_CANDIDATES: usize = 32;
const DIRECT_FAST_PROBE_ATTEMPTS: u32 = 1;
const DIRECT_FAST_PROBE_ACK_WINDOW: Duration = Duration::from_millis(250);
/// Ignore very stale relay-assisted windows and punch immediately instead.
const RELAY_ASSISTED_PUNCH_STALE_AFTER: Duration = Duration::from_secs(3);
/// A peer-reflexive endpoint is relayed at most once per peer in this normal
/// cadence.  New observations are coalesced to the newest endpoint rather
/// than producing a fixed burst of HTTP POSTs for every NAT port change.
const PEER_REFLEXIVE_SIGNAL_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// HTTP 429 is a strong server-side back-pressure signal.  Retain only the
/// newest observation and retry it after this exponentially increasing delay.
const PEER_REFLEXIVE_SIGNAL_BACKOFF_INITIAL: Duration = Duration::from_secs(2);
const PEER_REFLEXIVE_SIGNAL_BACKOFF_MAX: Duration = Duration::from_secs(30);
/// When an authenticated Probe v2 source address is observed, send a tiny
/// endpoint-specific burst immediately.  This keeps the just-discovered NAT
/// mapping warm without waiting behind the peer-wide synchronized punch lease.
const PEER_REFLEXIVE_FAST_PUNCH_INTERVAL: Duration = Duration::from_millis(10);
const PEER_REFLEXIVE_FAST_PUNCH_ATTEMPTS: u32 = 2;
/// After a peer-reflexive observation has been relayed, both sides get one
/// small, shared-window retry.  This is intentionally separate from the
/// immediate two-packet mapping warmer above: it has a relay-advertised
/// `punch_at_ms`, one socket, at most two trusted endpoints and four logical
/// probes, so it cannot become a candidate/sockets scan storm.
const PEER_REFLEXIVE_MICRO_WINDOW_MAX_TARGETS: usize = 2;
const PEER_REFLEXIVE_MICRO_WINDOW_INTERVAL: Duration = Duration::from_millis(20);
const PEER_REFLEXIVE_MICRO_WINDOW_ATTEMPTS: u32 = 2;
const PEER_REFLEXIVE_MICRO_WINDOW_DEADLINE: Duration = Duration::from_secs(1);
/// During an asymmetric hard-NAT punch, the hard side keeps exactly one
/// destination-specific binding warm while the stable side sweeps predicted
/// public ports. This is a NAT-state maintainer, not a data-path keepalive.
const HARD_NAT_MAINTAINER_CONNECTING_INTERVAL: Duration = Duration::from_millis(150);
const HARD_NAT_MAINTAINER_CONNECTING_DURATION: Duration = Duration::from_secs(60);
/// Cadence of the relay-backed recovery heartbeat: one bounded beat over the
/// peer's trusted endpoints every few seconds, for as long as the relay
/// carries the data plane.
const RELAY_BACKOFF_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(3);
/// Send a few encrypted direct-validation requests over a freshly observed
/// UDP path and wait for the peer's daemon-internal ACK.
///
/// The request/ACK protocol is fully daemon-internal and authenticated by the
/// WireGuard session: neither side needs TUN, an OS ICMP echo reply, or user
/// traffic.  The responder validates the request and returns an idempotent
/// ACK; each side promotes to Direct only after its own request's exact ACK is
/// consumed.
const DIRECT_VALIDATION_REQUEST_DELAYS: [Duration; 3] = [
    Duration::ZERO,
    Duration::from_millis(80),
    Duration::from_millis(250),
];
/// How long the initiator waits for the validation ACK before retrying.
const DIRECT_VALIDATION_ACK_WAIT: Duration = Duration::from_millis(750);
/// A peer-reflexive ACK can arrive before the offer/answer handler installs the
/// WireGuard session. Keep the observed NAT mapping alive while waiting for the
/// handshake instead of permanently discarding the only useful endpoint.
///
/// The wait covers a normal control-plane handshake round trip, but is bounded
/// so an endpoint-specific validation lease cannot occupy the only validation
/// worker for tens of seconds. Relay remains the data-plane fallback while a
/// later authenticated observation can reopen validation.
const DIRECT_ENCRYPTED_VALIDATION_SESSION_WAIT: Duration = Duration::from_secs(10);
const DIRECT_ENCRYPTED_VALIDATION_SESSION_POLL: Duration = Duration::from_millis(50);
/// ICMP echo-request payload prefix marking a daemon-internal direct
/// validation REQUEST. The token contains network generation (8 bytes BE),
/// request id (2 bytes BE), attempt sequence (1 byte), and validation-session
/// owner token (8 bytes BE).
const DIRECT_VALIDATION_REQUEST_PAYLOAD: &[u8] = b"p2wlan-direct-validation-req";
/// ICMP echo-request payload prefix marking the daemon-internal direct
/// validation ACK.  Carries the mirrored token of the request it answers.
const DIRECT_VALIDATION_ACK_PAYLOAD: &[u8] = b"p2wlan-direct-validation-ack";
/// How long a validation ACK may lag behind its request before the token is
/// considered stale and must not confirm the path.
const DIRECT_VALIDATION_EXPECTATION_TTL: Duration = Duration::from_secs(8);
/// Explicitly prove answer adoption even when a healthy Direct path suppresses
/// the ordinary punch scheduler and no user traffic is flowing.
const REKEY_CONFIRMATION_DELAYS: [Duration; 9] = [
    Duration::ZERO,
    Duration::from_millis(100),
    Duration::from_millis(300),
    Duration::from_secs(1),
    Duration::from_secs(3),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(10),
    Duration::from_secs(15),
];
const REKEY_CONFIRMATION_PAYLOAD: &[u8] = b"p2wlan-rekey-confirmation";
/// Avoid overlapping offer/answer, refresh, and retry bursts for one peer.
/// Competing bursts can create distinct NAT mappings and reduce, rather than
/// improve, the chance that both peers hit the same opening window.
#[cfg(test)]
#[allow(dead_code)]
const PUNCH_SESSION_DEDUP_WINDOW: Duration = Duration::from_secs(3);
#[cfg(test)]
#[allow(dead_code)]
const DIRECT_RECLAIM_PUNCH_DEDUP_WINDOW: Duration = Duration::from_secs(1);
/// A traversal task must release its per-peer lease even if a transport call
/// stalls or an unexpectedly large candidate set reaches the scheduler.
///
/// The remote-scatter path is intentionally wider than ordinary punching:
/// 3,072 capped probes paced at 6ms take ~18.5s before round delays and the
/// final ACK grace window.  Keep the deadline above that budget so the wide
/// Hard-NAT sweep can finish and record coverage instead of being cancelled
/// mid-scan.
const PUNCH_SESSION_HARD_DEADLINE: Duration = Duration::from_secs(24);

/// Source label prefix that marks a genuinely fresh-mapping prediction signal.
///
/// The value carries the sender's persistent monotonic incarnation plus the
/// per-peer punch generation, e.g. `predicted_fresh:1742987654321:39`.  The
/// incarnation is a persisted counter (seeded from the wall clock only on the
/// very first boot) that strictly increases per daemon restart, so ordering
/// never depends on the wall clock: a clock rollback or a restart within the
/// same millisecond still yields a strictly newer incarnation, and a new
/// incarnation can replace an old one after a restart.  Ordinary ICE gathering
/// also emits `predicted` candidates, so only this distinct label may preempt
/// punch sessions; the embedded incarnation+generation lets the receiver
/// reject a stale prediction that a superseded task managed to send late.
pub(crate) const FRESH_PREDICTION_SOURCE_LABEL_PREFIX: &str = "predicted_fresh:";

/// Magic bytes of the independent overlay-validation business payload
/// (`P2WLOV`), used by the WireGuard inbound path as a cheap pre-filter before
/// forwarding a decrypted inbound packet to the overlay harness with its real
/// ingress metadata.
pub(crate) const OVERLAY_PAYLOAD_MAGIC: &[u8] = b"P2WLOV";

/// Reserved part of the 96-candidate signaling budget for the fresh-mapping
/// prediction window.  The prediction is time-sensitive: it must not be
/// crowded out by ordinary STUN/predicted candidates, and the sender order
/// (top-1 first, then the successor window) must survive truncation intact.
/// The reservation covers the widest window the model can produce, so every
/// publishable window port is preserved.
pub(crate) const MAX_SIGNAL_FRESH_WINDOW_CANDIDATES: usize =
    p2pnet_nat::mapping::MAX_MONOTONIC_WINDOW_PORTS;

/// Identity of one fresh-mapping prediction: the sender's daemon incarnation
/// (`boot_epoch`, a persistent strictly-monotonic counter seeded from the wall
/// clock only on the first boot) plus the per-peer punch generation inside
/// that incarnation.
///
/// Ordering is lexicographic: within one incarnation `generation` orders
/// predictions, while a newer incarnation always supersedes an older one (even
/// across a clock rollback or a same-millisecond restart), and once a new
/// incarnation has been accepted, late signals from the old incarnation can
/// never win again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FreshPredictionId {
    pub boot_epoch: u64,
    pub generation: u64,
}

/// Parse a candidate source label as a fresh-mapping prediction.
///
/// Malformed labels, a zero boot epoch and generation zero are all rejected
/// (the candidate then degrades to an ordinary `predicted` candidate and can
/// never claim fresh priority).  The strict two-part format prevents an old
/// single-number label from being confused with a valid incarnation.
pub(crate) fn parse_fresh_prediction_source_label(label: &str) -> Option<FreshPredictionId> {
    let rest = label.strip_prefix(FRESH_PREDICTION_SOURCE_LABEL_PREFIX)?;
    let (boot_epoch, generation) = rest.split_once(':')?;
    let boot_epoch = boot_epoch.parse::<u64>().ok()?;
    let generation = generation.parse::<u64>().ok()?;
    (boot_epoch != 0 && generation != 0).then_some(FreshPredictionId {
        boot_epoch,
        generation,
    })
}

/// Canonical wire label for one fresh-mapping prediction.
pub(crate) fn fresh_prediction_source_label(id: FreshPredictionId) -> String {
    format!(
        "{FRESH_PREDICTION_SOURCE_LABEL_PREFIX}{}:{}",
        id.boot_epoch, id.generation
    )
}

include!("lib/punch_dedup.rs");
include!("lib/daemon/udp_transport_slot.rs");
include!("lib/daemon/core.rs");
include!("lib/daemon/candidate_snapshot.rs");
include!("lib/daemon/udp_direct.rs");
include!("lib/daemon/handshake_maintenance.rs");
include!("lib/daemon/relay_spawn.rs");
include!("lib/daemon/dataplane_tasks.rs");
include!("lib/daemon/overlay_validate.rs");
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
