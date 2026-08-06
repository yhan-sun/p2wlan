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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::{DaemonError, Result};
use crate::relay::RelaySelectionDiagnostics;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot, RwLock};
use tokio::time;
use tracing::{debug, error, info, warn};

mod http;
mod websocket;

#[cfg(test)]
use http::register_device_payload;
use http::{
    create_tunnel, fetch_relay_ticket_http, normalize_http_base_url, obtain_device_credential,
    poll_peers, poll_signals, register_device, send_signal, update_endpoint, SignalSigningIdentity,
    SIGNAL_REST_PROTOCOL_VERSION,
};
use websocket::spawn_signal_websocket;

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

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
#[path = "control/tests.rs"]
mod tests;
