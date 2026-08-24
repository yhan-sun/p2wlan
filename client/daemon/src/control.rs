//! Control plane client — connects to the Go control server.
//!
//! Handles:
//! - WebSocket/gRPC connection to the control server
//! - Node registration and authentication
//! - Signaling (exchange of peer offers/answers)
//! - Endpoint updates after NAT detection
//! - Heartbeat / keep-alive
//!
//! ## Protocol
//!
//! The control plane uses a simple JSON-over-WebSocket protocol for signaling,
//! with protobuf available for higher performance in production.

use std::collections::HashMap;
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::connection_timeline::ConnectionTimeline;
use crate::error::{DaemonError, Result};
use crate::relay::RelaySelectionDiagnostics;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, RwLock, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{self, timeout};
use tracing::{debug, error, info, warn};

mod http;
mod websocket;

/// Single control-plane HTTP client builder shared by the ordinary loop and the
/// critical lane (see [`control::proxy`](crate::control::proxy)).
pub use http::control_http_client;
pub(crate) use http::incarnation_fits_candidate_generation_encoding;
#[cfg(test)]
pub(crate) use http::prepare_signal_payload as prepare_signal_payload_for_test;
/// Whether the configured proxy mode consults the process environment's proxy
/// variables for control-plane HTTP traffic (diagnostics only).
pub use http::proxy_consults_environment;
/// Short, non-sensitive HTTP proxy behavior label (diagnostics/structured
/// events).  See [`control::proxy`](crate::control::proxy) for the policy.
pub use http::proxy_http_behavior_label;
#[cfg(test)]
use http::register_device_payload;
pub(crate) use http::{
    candidate_generation_incarnation, candidate_generation_is_malformed_encoded,
    candidate_generation_predecessor_floor,
};
use http::{
    create_tunnel, fetch_relay_ticket_http, normalize_http_base_url, obtain_device_credential,
    poll_peers, poll_signals, prepare_signal_payload, register_device,
    route_aware_control_http_clients, send_prepared_signal, send_signal, update_endpoint,
    RouteAwareControlHttpClient, SignalDeliveryTracker, SignalSigningIdentity,
    SIGNAL_REST_PROTOCOL_VERSION,
};
use websocket::spawn_signal_websocket;
/// Stable WebSocket proxy policy label (`direct_only`).  Signaling never rides
/// an ambient proxy.
pub use websocket::websocket_proxy_policy_label;

#[cfg(test)]
use futures_util::SinkExt;
#[cfg(test)]
use http::{
    next_candidate_generation, next_candidate_generation_for_incarnation,
    normalize_signal_candidate_expiry, normalize_signal_punch_at, peer_metadata_changed,
    peer_reflexive_endpoint_from_signal, CandidateGenerationError,
    CANDIDATE_GENERATION_COUNTER_BITS, CANDIDATE_GENERATION_COUNTER_MASK,
    CANDIDATE_GENERATION_INCARNATION_BITS, CANDIDATE_GENERATION_INCARNATION_FLAG,
};
#[cfg(test)]
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, SEC_WEBSOCKET_PROTOCOL};
#[cfg(test)]
use tokio_tungstenite::tungstenite::http::HeaderValue;
#[cfg(test)]
use tokio_tungstenite::tungstenite::Message as WebSocketMessage;
#[cfg(test)]
use websocket::SIGNAL_WS_PROTOCOL;
#[cfg(test)]
use websocket::{run_signal_websocket, signal_websocket_url};

include!("control/types.rs");

include!("control/client.rs");
include!("control/client/test_handlers.rs");
include!("control/runtime.rs");

#[cfg(test)]
fn test_signal_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[path = "control/tests.rs"]
mod tests;
