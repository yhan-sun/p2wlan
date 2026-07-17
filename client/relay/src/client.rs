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
//!     println!("From {}: {:?}", msg.from_node, msg.data);
//! }
//! # }
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::error::{RelayError, Result};
use crate::protocol::*;

/// A message received from the relay (data from a peer or a control message).
#[derive(Debug, Clone)]
pub struct RelayMessage {
    /// The source node ID (empty for control messages like pong/error).
    pub from_node: String,
    /// The data payload (for control messages, prefixed with "error:" or "pong:").
    pub data: Vec<u8>,
}

/// Commands sent from the client handle to the background write task.
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
pub struct RelayClient {
    /// Command channel to the background task.
    cmd_tx: mpsc::UnboundedSender<ClientCommand>,
}

impl RelayClient {
    /// Connect to a relay server and register with the given node ID.
    ///
    /// Returns the client handle and a receiver for incoming messages.
    pub async fn connect(
        addr: &str,
        node_id: &str,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayMessage>)> {
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| RelayError::ConnectFailed(format!("invalid address '{addr}': {e}")))?;

        Self::connect_to_addr(socket_addr, node_id).await
    }

    /// Connect, register, and wait for the server's confirmation.
    pub async fn connect_verified(
        addr: &str,
        node_id: &str,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayMessage>)> {
        let (client, mut rx) = Self::connect(addr, node_id).await?;

        // Wait for the Registered confirmation
        let timeout = Duration::from_secs(5);
        loop {
            match tokio::time::timeout(timeout, rx.recv()).await {
                Ok(Some(msg)) => {
                    if msg.from_node.is_empty() && msg.data.starts_with(b"registered:") {
                        return Ok((client, rx));
                    }
                    // Re-queue? For simplicity, just ignore and keep waiting.
                    // In practice the first message should be the confirmation.
                }
                Ok(None) => {
                    return Err(RelayError::Closed(
                        "connection closed during registration".into(),
                    ));
                }
                Err(_) => {
                    return Err(RelayError::Timeout("registration timed out".into()));
                }
            }
        }
    }

    async fn connect_to_addr(
        addr: SocketAddr,
        node_id: &str,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RelayMessage>)> {
        debug!("Connecting to relay server at {}", addr);

        let stream = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr))
            .await
            .map_err(|_| RelayError::Timeout("connect timed out".into()))?
            .map_err(|e| RelayError::ConnectFailed(e.to_string()))?;

        stream.set_nodelay(true).ok();
        let (mut reader, mut writer) = stream.into_split();

        // Send Register frame immediately
        let reg_frame = Frame::register(node_id);
        writer.write_all(&reg_frame.encode()).await?;

        info!(
            "Connected to relay server at {} (node_id={})",
            addr, node_id
        );

        // Channels
        let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<ClientCommand>();
        let (msg_tx, msg_rx) = mpsc::unbounded_channel::<RelayMessage>();
        let (reg_tx, reg_rx) = oneshot::channel::<Result<()>>();

        // Write task: processes commands and writes to the TCP stream
        let _write_task = tokio::spawn(async move {
            let mut writer = writer;
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    ClientCommand::SendFrame(frame) => {
                        if writer.write_all(&frame.encode()).await.is_err() {
                            break;
                        }
                    }
                    ClientCommand::SendData { dst, data } => match Frame::forward(&dst, &data) {
                        Ok(frame) => {
                            if writer.write_all(&frame.encode()).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("Failed to build forward frame: {}", e);
                        }
                    },
                    ClientCommand::Ping => {
                        let frame = Frame::ping();
                        if writer.write_all(&frame.encode()).await.is_err() {
                            break;
                        }
                    }
                    ClientCommand::Close => {
                        let frame = Frame::close(CLOSE_NORMAL);
                        let _ = writer.write_all(&frame.encode()).await;
                        break;
                    }
                }
            }
            debug!("Relay write task ended");
        });

        // Read task: reads frames and dispatches messages
        let msg_tx_clone = msg_tx.clone();
        let mut reg_tx = Some(reg_tx);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PAYLOAD + FRAME_HEADER_SIZE];

            loop {
                // Read header
                match reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]).await {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        debug!("Relay server disconnected");
                        break;
                    }
                    Err(e) => {
                        warn!("Relay read error: {}", e);
                        break;
                    }
                }

                // Parse header
                if buf[..4] != MAGIC {
                    warn!("Invalid magic from relay server");
                    break;
                }
                let msg_type = buf[5];
                let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

                // Read payload
                if payload_len > 0 {
                    if buf.len() < FRAME_HEADER_SIZE + payload_len {
                        buf.resize(FRAME_HEADER_SIZE + payload_len, 0);
                    }
                    if let Err(e) = reader
                        .read_exact(&mut buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len])
                        .await
                    {
                        warn!("Relay payload read error: {}", e);
                        break;
                    }
                }

                let payload = &buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len];

                match msg_type {
                    MSG_RECEIVED => {
                        // Data from a peer
                        let frame = Frame::new(MSG_RECEIVED, payload.to_vec());
                        match frame.parse_forward_payload() {
                            Ok((src, data)) => {
                                let _ = msg_tx_clone.send(RelayMessage {
                                    from_node: src.to_string(),
                                    data: data.to_vec(),
                                });
                            }
                            Err(e) => {
                                warn!("Failed to parse received frame: {}", e);
                            }
                        }
                    }

                    MSG_REGISTERED => {
                        // Server confirmed registration — signal via oneshot
                        debug!("Relay registration confirmed");
                        if let Some(tx) = reg_tx.take() {
                            let _ = tx.send(Ok(()));
                        }
                    }

                    MSG_PONG => {
                        let ts = if payload.len() >= 8 {
                            u64::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3], payload[4],
                                payload[5], payload[6], payload[7],
                            ])
                        } else {
                            0
                        };
                        let _ = msg_tx_clone.send(RelayMessage {
                            from_node: String::new(),
                            data: format!("pong:{}", ts).into_bytes(),
                        });
                    }

                    MSG_ERROR => {
                        let frame = Frame::new(MSG_ERROR, payload.to_vec());
                        let (code, message) = frame.parse_error().unwrap_or((0, "unknown".into()));
                        let _ = msg_tx_clone.send(RelayMessage {
                            from_node: String::new(),
                            data: format!("error:{}:{}", code, message).into_bytes(),
                        });
                    }

                    MSG_CLOSE => {
                        debug!("Relay server sent close");
                        break;
                    }

                    MSG_PING => {
                        // Server pinging us — shouldn't happen in normal protocol
                        debug!("Unexpected ping from relay server");
                    }

                    MSG_FORWARD => {
                        // We shouldn't receive forward frames (only the server does)
                        debug!("Unexpected forward frame from relay server");
                    }

                    MSG_REGISTER => {
                        debug!("Unexpected register frame from relay server");
                    }

                    _ => {
                        warn!("Unknown message type {:#04X} from relay server", msg_type);
                    }
                }
            }

            // Signal end of stream
            let _ = msg_tx_clone.send(RelayMessage {
                from_node: String::new(),
                data: b"closed".to_vec(),
            });
            debug!("Relay read task ended");
        });

        // Wait for registration confirmation before returning
        match tokio::time::timeout(Duration::from_secs(5), reg_rx).await {
            Ok(Ok(Ok(()))) => {
                debug!("Registration confirmed by relay server");
            }
            Ok(Ok(Err(e))) => return Err(e),
            Ok(Err(_)) => {
                return Err(RelayError::Closed("registration channel dropped".into()));
            }
            Err(_) => {
                return Err(RelayError::Timeout(
                    "registration confirmation timed out".into(),
                ));
            }
        }

        Ok((Self { cmd_tx }, msg_rx))
    }

    /// Send data to a peer via the relay.
    pub async fn send_data(&mut self, dst: &str, data: &[u8]) -> Result<()> {
        self.cmd_tx
            .send(ClientCommand::SendData {
                dst: dst.to_string(),
                data: data.to_vec(),
            })
            .map_err(|_| RelayError::Closed("relay write task stopped".into()))
    }

    /// Send a ping to the relay server (to measure latency / keep alive).
    pub async fn ping(&mut self) -> Result<()> {
        self.cmd_tx
            .send(ClientCommand::Ping)
            .map_err(|_| RelayError::Closed("relay write task stopped".into()))
    }

    /// Close the connection gracefully.
    pub async fn close(&mut self) -> Result<()> {
        let _ = self.cmd_tx.send(ClientCommand::Close);
        Ok(())
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        // Try to signal close (best-effort, ignore errors)
        let _ = self.cmd_tx.send(ClientCommand::Close);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::RelayServer;
    use std::time::Duration;

    #[tokio::test]
    async fn test_connect_and_registration_confirmed() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        // connect() should wait for registration confirmation internally
        let (_client, _rx) = RelayClient::connect(&addr.to_string(), "testnode")
            .await
            .unwrap();

        // If connect() returned successfully, registration was confirmed
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_send_data_between_clients() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut alice, mut rx_a) = RelayClient::connect(&addr.to_string(), "alice")
            .await
            .unwrap();
        let (mut bob, mut rx_b) = RelayClient::connect(&addr.to_string(), "bob")
            .await
            .unwrap();

        // connect() already waited for registration

        // Alice → Bob
        alice.send_data("bob", b"hello bob").await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(msg.from_node, "alice");
        assert_eq!(msg.data, b"hello bob");

        // Bob → Alice
        bob.send_data("alice", b"hi alice").await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(msg.from_node, "bob");
        assert_eq!(msg.data, b"hi alice");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_send_to_nonexistent_peer() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "sender")
            .await
            .unwrap();

        // connect() waited for registration, now send to nonexistent peer
        client.send_data("nonexistent", b"data").await.unwrap();

        // Should get an error response (code 404)
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(msg.data.starts_with(b"error:404"), "got: {:?}", msg.data);
    }

    #[tokio::test]
    async fn test_ping_pong() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "pinger")
            .await
            .unwrap();

        // connect() already waited for registration, so just ping
        client.ping().await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(msg.data.starts_with(b"pong:"));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_large_data() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut sender, _rx_s) = RelayClient::connect(&addr.to_string(), "sender")
            .await
            .unwrap();
        let (_receiver, mut rx_r) = RelayClient::connect(&addr.to_string(), "receiver")
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send 60KB (under the 65535 max payload)
        let data = vec![0xAB; 60_000];
        sender.send_data("receiver", &data).await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), rx_r.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(msg.from_node, "sender");
        assert_eq!(msg.data.len(), 60_000);
        assert!(msg.data.iter().all(|&b| b == 0xAB));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_connect_to_invalid_address() {
        // Port 1 is reserved and almost certainly not listening
        let result = RelayClient::connect("127.0.0.1:1", "test").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_close_connection() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, _rx) = RelayClient::connect(&addr.to_string(), "closer")
            .await
            .unwrap();

        client.close().await.unwrap();

        // Give it time for the close frame to be processed
        tokio::time::sleep(Duration::from_millis(200)).await;

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_bidirectional_stream() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut a, mut rxa) = RelayClient::connect(&addr.to_string(), "streamA")
            .await
            .unwrap();
        let (mut b, mut rxb) = RelayClient::connect(&addr.to_string(), "streamB")
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(150)).await;

        // Multiple messages both ways
        for i in 0..5 {
            let msg = format!("message-{}", i);
            a.send_data("streamB", msg.as_bytes()).await.unwrap();
            b.send_data("streamA", msg.as_bytes()).await.unwrap();
        }

        // Collect A → B messages
        let mut a_to_b = Vec::new();
        for _ in 0..5 {
            let msg = tokio::time::timeout(Duration::from_secs(2), rxb.recv())
                .await
                .unwrap()
                .unwrap();
            if !msg.from_node.is_empty() {
                a_to_b.push(msg);
            }
        }

        // Collect B → A messages
        let mut b_to_a = Vec::new();
        for _ in 0..5 {
            let msg = tokio::time::timeout(Duration::from_secs(2), rxa.recv())
                .await
                .unwrap()
                .unwrap();
            if !msg.from_node.is_empty() {
                b_to_a.push(msg);
            }
        }

        assert_eq!(a_to_b.len(), 5);
        assert_eq!(b_to_a.len(), 5);
        assert!(a_to_b.iter().all(|m| m.from_node == "streamA"));
        assert!(b_to_a.iter().all(|m| m.from_node == "streamB"));

        server.shutdown().await;
    }
}
