//! Async relay client — connects to a DERP-like relay server.
//!
//! ## Usage
//!
//! ```no_run
//! use p2pnet_relay::client::RelayClient;
//!
//! # async fn example() {
//! // Connect and register with the relay server
//! let (mut client, mut rx) = RelayClient::connect("127.0.0.1:8080", "my-node-id")
//!     .await
//!     .unwrap();
//!
//! // Send encrypted data to a peer via the relay
//! client.send_data("peer-node-id", &[0x01, 0x02, 0x03]).await.unwrap();
//!
//! // Receive data from peers
//! while let Some(msg) = rx.recv().await {
//!     if let p2pnet_relay::RelayMessage::Data { from_node, data } = msg {
//!         println!("From {}: {:?}", from_node, data);
//!     }
//! }
//! # }
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use crate::error::{RelayError, Result};
use crate::protocol::*;
use crate::RelayClientConfig;

#[allow(dead_code)]
const RELAY_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

/// Record the first close-reason attribution for a connection.
///
/// Both background tasks may observe the end of the connection (a write
/// failure races the read task's close observation); the first attribution
/// wins so a keepalive write failure is never mislabeled as a server close.
fn note_close_reason(
    reason: &Arc<std::sync::Mutex<RelayCloseReason>>,
    classification: RelayCloseReason,
) {
    let mut current = reason
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *current == RelayCloseReason::Unknown {
        *current = classification;
    }
}

/// Resolve the final close reason, defaulting an unclassified end to a local
/// shutdown (the read loop ended because the connection was closed locally).
fn resolve_close_reason(reason: &Arc<std::sync::Mutex<RelayCloseReason>>) -> RelayCloseReason {
    let current = reason
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *current == RelayCloseReason::Unknown {
        RelayCloseReason::LocalShutdown
    } else {
        *current
    }
}

/// A message received from the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessage {
    /// Data from a peer.
    Data { from_node: String, data: Vec<u8> },
    /// Pong response with timestamp.
    Pong { timestamp: u64 },
    /// Relay protocol or operational error.
    Error { code: u16, message: String },
    /// The relay connection ended, classified by the client's read/write
    /// tasks so the supervisor can distinguish server-side closes, TCP
    /// resets, idle timeouts and local write failures instead of collapsing
    /// every disconnect into one "connection closed".
    Closed { reason: RelayCloseReason },
}

/// Why a relay connection ended.  The read task attributes transport-level
/// failures; the write task attributes keepalive/data write failures.  The
/// first attribution wins, so a write failure that races the read task's
/// close observation is not mislabeled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayCloseReason {
    /// Classification was not recorded (local shutdown is the fallback).
    Unknown,
    /// The server sent a Close frame.
    ServerCloseFrame,
    /// The server closed the TCP connection with a clean FIN.
    ServerEof,
    /// The TCP connection was reset (RST).
    TcpReset,
    /// The client read loop hit its idle timeout (an Error frame with code
    /// 4009 was delivered before this).
    IdleTimeout,
    /// A keepalive or data write to the server failed.
    LocalWriteFailed,
    /// The connection was shut down locally.
    LocalShutdown,
    /// An unreclassified I/O error ended the read loop.
    IoError,
}

/// Commands sent from the client handle to the background write task.
#[derive(Debug)]
enum ClientCommand {
    /// Send a raw frame (currently unused by public API but available for extensions).
    #[allow(dead_code)]
    SendFrame(Frame),
    /// Send data to a peer.
    SendData { dst: String, data: Vec<u8> },
    /// Send a ping.
    Ping,
    /// Close the connection.
    Close,
}

/// A relay client connection.
///
/// The client maintains a background task that handles reading from and
/// writing to the relay server. Data received from peers is delivered via
/// the `mpsc::Receiver<RelayMessage>` returned by [`connect`].
#[derive(Debug)]
pub struct RelayClient {
    /// Command channel to the background task.
    cmd_tx: mpsc::Sender<ClientCommand>,
}

impl RelayClient {
    /// Test-only shell: a client handle backed by a closed command channel,
    /// for unit tests that only exercise transport metadata and lifecycle
    /// logic without a live relay connection.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn new_for_test() -> Self {
        let (tx, _rx) = mpsc::channel(1);
        Self { cmd_tx: tx }
    }
}

mod commands;
mod connect;
mod legacy_tcp;

#[cfg(test)]
mod tests;
