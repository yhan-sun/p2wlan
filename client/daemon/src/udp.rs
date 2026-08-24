//! UDP transport for encrypted peer packets.
//!
//! The WireGuard adapter produces serialized transport messages keyed by peer
//! ID. This module is the direct UDP sink: it resolves each peer endpoint from
//! `PeerManager` and sends the encrypted datagram to that socket address.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

use crate::error::{DaemonError, Result};
use crate::peer::{is_public_probe_endpoint, PeerManager, ProbeKeyRole, REASON_DIRECT_SEND_FAILED};
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
include!("udp/core.rs");
include!("udp/admission.rs");
include!("udp/gather.rs");
include!("udp/fast_gather.rs");
include!("udp/dynamic_punch.rs");
include!("udp/outbound.rs");
include!("udp/inbound.rs");
include!("udp/utils.rs");

#[cfg(test)]
#[path = "udp/tests.rs"]
mod tests;
