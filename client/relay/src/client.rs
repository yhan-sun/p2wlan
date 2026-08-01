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

/// A message received from the relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayMessage {
    /// Data from a peer.
    Data { from_node: String, data: Vec<u8> },
    /// Pong response with timestamp.
    Pong { timestamp: u64 },
    /// Relay protocol or operational error.
    Error { code: u16, message: String },
    /// Remote closed connection.
    Closed,
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

mod commands;
mod connect;
mod legacy_tcp;

#[cfg(test)]
mod tests;
