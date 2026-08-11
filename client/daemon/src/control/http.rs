//! REST/HTTP client functions for the control plane.
//!
//! Device registration, challenge-response credential issuance, relay ticket
//! fetch, endpoint lease refresh, signal send/poll, peer polling and tunnel
//! creation. Split out of `control.rs`.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p2pnet_crypto::Ed25519KeyPair;
use serde::Deserialize;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use crate::config::{Config, ControlProxyMode};
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
/// A responder answer must not be held behind a wedged HTTP request for most
/// of its short receive-only key lifetime. Delivery remains ambiguous on
/// timeout, so the daemon retains staged state for authenticated confirmation.
const SIGNAL_SEND_TIMEOUT: Duration = Duration::from_secs(5);

include!("http/auth.rs");
include!("http/device.rs");
include!("http/signal.rs");
include!("http/peers.rs");
include!("proxy.rs");

#[cfg(test)]
mod signal_send_timeout_tests {
    use super::*;

    #[test]
    fn signal_send_timeout_is_bounded() {
        assert_eq!(SIGNAL_SEND_TIMEOUT, Duration::from_secs(5));
    }
}
