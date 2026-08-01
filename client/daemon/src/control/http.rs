//! REST/HTTP client functions for the control plane.
//!
//! Device registration, challenge-response credential issuance, relay ticket
//! fetch, endpoint lease refresh, signal send/poll, peer polling and tunnel
//! creation. Split out of `control.rs`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use p2pnet_crypto::Ed25519KeyPair;
use serde::Deserialize;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use crate::config::Config;
use crate::error::{DaemonError, Result};

use super::{
    ClientState, ControlErrorResponse, ControlEvent, CreateTunnelResponse, EndpointUpdateResponse,
    FetchRelayTicketResponse, ListNodesResponse, ListSignalsResponse, PeerInfo,
    RegisterDeviceResponse, RelayCatalogEntry, SignalCreateResponse, SignalResponse,
};

/// Candidate-set revisions must be strictly increasing within a daemon.  Wall
/// clock milliseconds alone collide when an offer and a candidate refresh are
/// emitted in the same tick.
static LAST_CANDIDATE_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(super) const SIGNAL_REST_PROTOCOL_VERSION: u8 = 1;

include!("http/auth.rs");
include!("http/device.rs");
include!("http/signal.rs");
include!("http/peers.rs");
