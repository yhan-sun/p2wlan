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

impl RelayClient {
    /// Connect to a relay server and register with the given node ID.
    ///
    /// Returns the client handle and a receiver for incoming messages.
    pub async fn connect(
        addr: &str,
        node_id: &str,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_with_config(addr, node_id, RelayClientConfig::default()).await
    }

    /// Connect with config.
    pub async fn connect_with_config(
        addr: &str,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        config.validate()?;
        let socket_addr: SocketAddr = addr
            .parse()
            .map_err(|e| RelayError::ConnectFailed(format!("invalid address '{addr}': {e}")))?;

        Self::connect_to_addr_with_config(socket_addr, node_id, config).await
    }

    /// Connect, register, and wait for the server's confirmation.
    pub async fn connect_verified(
        addr: &str,
        node_id: &str,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect(addr, node_id).await
    }

    /// Connect verified with config.
    pub async fn connect_verified_with_config(
        addr: &str,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_with_config(addr, node_id, config).await
    }

    #[allow(dead_code)]
    async fn connect_to_addr(
        addr: SocketAddr,
        node_id: &str,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        Self::connect_to_addr_with_keepalive(addr, node_id, RELAY_KEEPALIVE_INTERVAL).await
    }

    #[allow(dead_code)]
    async fn connect_to_addr_with_keepalive(
        addr: SocketAddr,
        node_id: &str,
        keepalive_interval: Duration,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        let config = RelayClientConfig {
            keepalive_interval,
            ..Default::default()
        };
        Self::connect_to_addr_with_config(addr, node_id, config).await
    }

    async fn connect_to_addr_with_config(
        addr: SocketAddr,
        node_id: &str,
        config: RelayClientConfig,
    ) -> Result<(Self, mpsc::Receiver<RelayMessage>)> {
        debug!("Connecting to relay server at {}", addr);

        let stream = tokio::time::timeout(config.register_timeout, TcpStream::connect(addr))
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
        let (cmd_tx, mut cmd_rx) = mpsc::channel::<ClientCommand>(config.cmd_queue_capacity);
        let (msg_tx, msg_rx) = mpsc::channel::<RelayMessage>(config.inbound_queue_capacity);
        let (reg_tx, reg_rx) = oneshot::channel::<Result<()>>();
        let (close_tx, close_rx) = watch::channel(false);

        // Write task: processes commands and writes to the TCP stream
        let write_close_tx = close_tx.clone();
        let mut write_close_rx = close_rx.clone();
        let max_payload = config.max_frame_payload;
        let _write_task = tokio::spawn(async move {
            let mut writer = writer;
            let mut keepalive = tokio::time::interval(config.keepalive_interval);
            keepalive.set_missed_tick_behavior(MissedTickBehavior::Skip);
            keepalive.tick().await;

            loop {
                tokio::select! {
                    command = cmd_rx.recv() => {
                        let Some(cmd) = command else {
                            break;
                        };
                        match cmd {
                            ClientCommand::SendFrame(frame) => {
                                if frame.payload.len() > max_payload {
                                    warn!("Frame payload exceeds max limit");
                                    continue;
                                }
                                if let Err(err) = writer.write_all(&frame.encode()).await {
                                    warn!("Relay write error: {}", err);
                                    break;
                                }
                            }
                            ClientCommand::SendData { dst, data } => match Frame::forward(&dst, &data) {
                                Ok(frame) => {
                                    if frame.payload.len() > max_payload {
                                        warn!("Frame payload exceeds max limit");
                                        continue;
                                    }
                                    if let Err(err) = writer.write_all(&frame.encode()).await {
                                        warn!("Relay write error: {}", err);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!("Failed to build forward frame: {}", e);
                                }
                            },
                            ClientCommand::Ping => {
                                let frame = Frame::ping();
                                if let Err(err) = writer.write_all(&frame.encode()).await {
                                    warn!("Relay ping write error: {}", err);
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
                    _ = keepalive.tick() => {
                        let frame = Frame::ping();
                        if let Err(err) = writer.write_all(&frame.encode()).await {
                            warn!("Relay keepalive write error: {}", err);
                            break;
                        }
                    }
                    changed = write_close_rx.changed() => {
                        if changed.is_ok() && *write_close_rx.borrow() {
                            break;
                        }
                    }
                }
            }
            let _ = write_close_tx.send(true);
            debug!("Relay write task ended");
        });

        // Read task: reads frames and dispatches messages
        let msg_tx_clone = msg_tx.clone();
        let mut reg_tx = Some(reg_tx);
        let read_close_tx = close_tx.clone();
        let mut read_close_rx = close_rx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; max_payload + FRAME_HEADER_SIZE];

            loop {
                // Read header
                match tokio::select! {
                    result = reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]) => result.map(|_| true),
                    changed = read_close_rx.changed() => {
                        let _ = changed;
                        Ok(false)
                    }
                } {
                    Ok(true) => {}
                    Ok(false) => break,
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
                let version = buf[4];
                if version != VERSION {
                    warn!("Unsupported version {} from relay server", version);
                    if let Some(tx) = reg_tx.take() {
                        let _ = tx.send(Err(RelayError::Protocol(format!(
                            "unsupported version: {}",
                            version
                        ))));
                    }
                    break;
                }
                let msg_type = buf[5];
                let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

                if payload_len > max_payload {
                    warn!(
                        "Payload length {} exceeds configured maximum {}",
                        payload_len, max_payload
                    );
                    if let Some(tx) = reg_tx.take() {
                        let _ = tx.send(Err(RelayError::FrameTooLarge(payload_len, max_payload)));
                    }
                    break;
                }

                // Read payload
                if payload_len > 0 {
                    if buf.len() < FRAME_HEADER_SIZE + payload_len {
                        buf.resize(FRAME_HEADER_SIZE + payload_len, 0);
                    }
                    match tokio::select! {
                        result = reader.read_exact(&mut buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len]) => result.map(|_| true),
                        changed = read_close_rx.changed() => {
                            let _ = changed;
                            Ok(false)
                        }
                    } {
                        Ok(true) => {}
                        Ok(false) => break,
                        Err(e) => {
                            warn!("Relay payload read error: {}", e);
                            break;
                        }
                    }
                }

                let payload = &buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len];

                match msg_type {
                    MSG_RECEIVED => {
                        // Data from a peer
                        let frame = Frame::new(MSG_RECEIVED, payload.to_vec());
                        match frame.parse_forward_payload() {
                            Ok((src, data)) => {
                                if msg_tx_clone
                                    .try_send(RelayMessage::Data {
                                        from_node: src.to_string(),
                                        data: data.to_vec(),
                                    })
                                    .is_err()
                                {
                                    warn!("msg_tx full or closed, closing connection");
                                    break;
                                }
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
                        if msg_tx_clone
                            .try_send(RelayMessage::Pong { timestamp: ts })
                            .is_err()
                        {
                            break;
                        }
                    }

                    MSG_ERROR => {
                        let frame = Frame::new(MSG_ERROR, payload.to_vec());
                        let (code, message) = frame.parse_error().unwrap_or((0, "unknown".into()));
                        if let Some(tx) = reg_tx.take() {
                            let _ = tx.send(Err(RelayError::ServerError(code, message.clone())));
                        }
                        if msg_tx_clone
                            .try_send(RelayMessage::Error { code, message })
                            .is_err()
                        {
                            break;
                        }
                    }

                    MSG_CLOSE => {
                        debug!("Relay server sent close");
                        break;
                    }

                    _ => {
                        warn!("Unexpected or unknown message type {:#04X}", msg_type);
                    }
                }
            }

            // Signal end of stream
            let _ = msg_tx_clone.try_send(RelayMessage::Closed);
            let _ = read_close_tx.send(true);
            debug!("Relay read task ended");
        });

        // Wait for registration confirmation before returning
        match tokio::time::timeout(config.register_timeout, reg_rx).await {
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
            .try_send(ClientCommand::SendData {
                dst: dst.to_string(),
                data: data.to_vec(),
            })
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    RelayError::Channel("command queue full".into())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    RelayError::Closed("relay write task stopped".into())
                }
            })
    }

    /// Send a ping to the relay server (to measure latency / keep alive).
    pub async fn ping(&mut self) -> Result<()> {
        self.cmd_tx
            .try_send(ClientCommand::Ping)
            .map_err(|e| match e {
                mpsc::error::TrySendError::Full(_) => {
                    RelayError::Channel("command queue full".into())
                }
                mpsc::error::TrySendError::Closed(_) => {
                    RelayError::Closed("relay write task stopped".into())
                }
            })
    }

    /// Close the connection gracefully.
    pub async fn close(&mut self) -> Result<()> {
        let _ = self.cmd_tx.try_send(ClientCommand::Close);
        Ok(())
    }
}

impl Drop for RelayClient {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(ClientCommand::Close);
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
    async fn idle_connection_sends_keepalive_ping() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;
        let (_client, mut rx) = RelayClient::connect_to_addr_with_keepalive(
            addr,
            "idle-node",
            Duration::from_millis(50),
        )
        .await
        .unwrap();

        let pong = tokio::time::timeout(Duration::from_millis(500), async {
            loop {
                let message = rx.recv().await.expect("relay stream closed");
                if let RelayMessage::Pong { .. } = message {
                    return message;
                }
            }
        })
        .await
        .expect("relay keepalive pong timed out");

        assert!(matches!(pong, RelayMessage::Pong { .. }));
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

        // Alice → Bob
        alice.send_data("bob", b"hello bob").await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            msg,
            RelayMessage::Data {
                from_node: "alice".to_string(),
                data: b"hello bob".to_vec()
            }
        );

        // Bob → Alice
        bob.send_data("alice", b"hi alice").await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            msg,
            RelayMessage::Data {
                from_node: "bob".to_string(),
                data: b"hi alice".to_vec()
            }
        );

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_send_to_nonexistent_peer() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "sender")
            .await
            .unwrap();

        // Send to nonexistent peer
        client.send_data("nonexistent", b"data").await.unwrap();

        // Should get an error response (code 404)
        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(
            matches!(msg, RelayMessage::Error { code: 404, .. }),
            "got: {:?}",
            msg
        );
    }

    #[tokio::test]
    async fn test_ping_pong() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "pinger")
            .await
            .unwrap();

        client.ping().await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(msg, RelayMessage::Pong { .. }));

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

        // Send 60KB
        let data = vec![0xAB; 60_000];
        sender.send_data("receiver", &data).await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(3), rx_r.recv())
            .await
            .unwrap()
            .unwrap();

        if let RelayMessage::Data { from_node, data } = msg {
            assert_eq!(from_node, "sender");
            assert_eq!(data.len(), 60_000);
            assert!(data.iter().all(|&b| b == 0xAB));
        } else {
            panic!("expected Data, got {:?}", msg);
        }

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_connect_to_invalid_address() {
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

        for i in 0..5 {
            let msg = format!("message-{}", i);
            a.send_data("streamB", msg.as_bytes()).await.unwrap();
            b.send_data("streamA", msg.as_bytes()).await.unwrap();
        }

        let mut a_to_b = Vec::new();
        for _ in 0..5 {
            let msg = tokio::time::timeout(Duration::from_secs(2), rxb.recv())
                .await
                .unwrap()
                .unwrap();
            if let RelayMessage::Data { ref from_node, .. } = msg {
                if !from_node.is_empty() {
                    a_to_b.push(msg);
                }
            }
        }

        let mut b_to_a = Vec::new();
        for _ in 0..5 {
            let msg = tokio::time::timeout(Duration::from_secs(2), rxa.recv())
                .await
                .unwrap()
                .unwrap();
            if let RelayMessage::Data { ref from_node, .. } = msg {
                if !from_node.is_empty() {
                    b_to_a.push(msg);
                }
            }
        }

        assert_eq!(a_to_b.len(), 5);
        assert_eq!(b_to_a.len(), 5);
        assert!(a_to_b
            .iter()
            .all(|m| matches!(m, RelayMessage::Data { from_node, .. } if from_node == "streamA")));
        assert!(b_to_a
            .iter()
            .all(|m| matches!(m, RelayMessage::Data { from_node, .. } if from_node == "streamB")));

        server.shutdown().await;
    }
}
