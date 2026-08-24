//! REST/HTTP client functions for the control plane.
//!
//! Device registration, challenge-response credential issuance, relay ticket
//! fetch, endpoint lease refresh, signal send/poll, peer polling and tunnel
//! creation. Split out of `control.rs`.

use std::collections::{HashMap, HashSet, VecDeque};
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
    RegisterDeviceResponse, RelayCatalogEntry, SignalApplyOutcome, SignalCreateResponse,
    SignalDeliveryReceipt, SignalDeliveryWaiter, SignalResponse,
};

/// Candidate-set revisions must be strictly increasing within a daemon.  Wall
/// clock milliseconds alone collide when an offer and a candidate refresh are
/// emitted in the same tick.
static LAST_CANDIDATE_GENERATION: AtomicU64 = AtomicU64::new(0);

pub(super) const SIGNAL_REST_PROTOCOL_VERSION: u8 = 1;
/// Bound ordinary control-plane requests so a route change or a dead socket
/// cannot stall the single control loop past the device lease TTL.  Signal
/// long-polling adds its server wait interval to this budget below.
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Presence release is a shutdown hint, never a reason to hold daemon
/// teardown. The server TTL remains the fallback for a lost process.
pub(super) const PRESENCE_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);
/// A responder answer must not be held behind a wedged HTTP request for most
/// of its short receive-only key lifetime. Delivery remains ambiguous on
/// timeout, so the daemon retains staged state for authenticated confirmation.
const SIGNAL_SEND_TIMEOUT: Duration = Duration::from_secs(5);

fn signal_poll_timeout(wait_ms: u64) -> Duration {
    CONTROL_REQUEST_TIMEOUT.saturating_add(Duration::from_millis(wait_ms))
}

include!("http/auth.rs");
include!("http/device.rs");
include!("http/signal.rs");
include!("http/peers.rs");
include!("proxy.rs");

#[cfg(test)]
mod signal_send_timeout_tests {
    use super::*;

    #[test]
    fn ordinary_control_requests_are_bounded() {
        assert_eq!(CONTROL_REQUEST_TIMEOUT, Duration::from_secs(10));
        assert_eq!(signal_poll_timeout(0), Duration::from_secs(10));
        assert_eq!(signal_poll_timeout(30_000), Duration::from_secs(40));
    }

    #[test]
    fn signal_send_timeout_is_bounded() {
        assert_eq!(SIGNAL_SEND_TIMEOUT, Duration::from_secs(5));
    }
}
