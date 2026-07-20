//! Async relay server for testing and development.
//!
//! The relay server listens on a TCP port, accepts connections from clients,
//! and forwards encrypted data between peers. The server cannot decrypt any
//! data — it only routes frames based on node IDs.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌───────────────────┐     ┌──────────────┐
//! │   Node A     │────▶│   Relay Server    │◀────│   Node B     │
//! │ (node-id-A)  │     │                   │     │ (node-id-B)  │
//! └──────────────┘     │  peer_table:      │     └──────────────┘
//!                      │  "A" → tx_a       │
//!                      │  "B" → tx_b       │
//!                      └───────────────────┘
//! ```
//!
//! Each client connection spawns two tasks:
//! 1. **Read task**: reads frames from the TCP stream, processes them
//! 2. **Write task**: receives data from an mpsc channel and writes to the TCP stream

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, Mutex};
use tracing::{debug, error, info, warn};

use crate::error::{RelayError, Result};
use crate::protocol::*;
use crate::RelayServerConfig;

/// A peer connection representation in the server.
#[derive(Clone)]
pub struct PeerConnection {
    tx: mpsc::Sender<Vec<u8>>,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
    conn_id: u64,
}

/// Shared state mapping node IDs to their write channels and connection metadata.
type PeerTable = Arc<Mutex<HashMap<String, PeerConnection>>>;

/// A running relay server instance.
pub struct RelayServer {
    /// The address the server is listening on.
    pub addr: SocketAddr,
    /// Handle to the server task.
    handle: tokio::task::JoinHandle<()>,
}

impl RelayServer {
    /// Start a relay server on the given address with default config.
    pub async fn start(addr: &str) -> Result<Self> {
        Self::start_with_config(addr, RelayServerConfig::default()).await
    }

    /// Start a relay server on the given address with custom config.
    pub async fn start_with_config(addr: &str, config: RelayServerConfig) -> Result<Self> {
        config.validate()?;
        let listener = TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;
        let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));
        let connection_count = Arc::new(AtomicUsize::new(0));

        info!(
            "Relay server listening on {} with config: {:?}",
            actual_addr, config
        );

        let c_config = config.clone();
        let handle = tokio::spawn(async move {
            let mut next_conn_id = 0u64;
            loop {
                match listener.accept().await {
                    Ok((stream, client_addr)) => {
                        debug!("New connection from {}", client_addr);
                        let table = peer_table.clone();
                        let conn_count = connection_count.clone();
                        let client_cfg = c_config.clone();
                        next_conn_id += 1;
                        let conn_id = next_conn_id;
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_client(stream, table, conn_count, conn_id, client_cfg).await
                            {
                                warn!("Client connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Accept error: {}", e);
                        break;
                    }
                }
            }
        });

        Ok(Self {
            addr: actual_addr,
            handle,
        })
    }

    /// Start a relay server on a random port (for testing).
    pub async fn start_random() -> Result<Self> {
        Self::start("127.0.0.1:0").await
    }

    /// Shut down the relay server.
    pub async fn shutdown(self) {
        self.handle.abort();
        info!("Relay server shut down");
    }
}

/// Handle a single client connection.
async fn handle_client(
    stream: TcpStream,
    peer_table: PeerTable,
    connection_count: Arc<AtomicUsize>,
    conn_id: u64,
    config: RelayServerConfig,
) -> Result<()> {
    let client_addr = stream.peer_addr().ok();

    // Check connection limit
    let current_connections = connection_count.fetch_add(1, Ordering::SeqCst);
    struct ConnectionGuard {
        count: Arc<AtomicUsize>,
    }
    impl Drop for ConnectionGuard {
        fn drop(&mut self) {
            self.count.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _guard = ConnectionGuard {
        count: connection_count.clone(),
    };

    if current_connections >= config.max_connections {
        let mut writer = stream.into_split().1;
        let _ = writer
            .write_all(&Frame::error(ERR_CONNECTION_LIMIT, "connection limit exceeded").encode())
            .await;
        return Err(RelayError::Protocol("connection limit exceeded".into()));
    }

    let (mut reader, mut writer) = stream.into_split();

    // Channel for sending data to this client (from other peers)
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(config.outbound_queue_capacity);
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();

    // Write task: forward queued frames to the TCP stream
    let write_task = tokio::spawn(async move {
        while let Some(frame_bytes) = rx.recv().await {
            if writer.write_all(&frame_bytes).await.is_err() {
                break;
            }
        }
    });

    // Step 1: Wait for Register frame within register_timeout
    let first_frame_fut = async {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        reader.read_exact(&mut header).await?;
        if header[..4] != MAGIC {
            return Err(RelayError::Protocol("invalid magic".into()));
        }
        let version = header[4];
        if version != VERSION {
            return Err(RelayError::Protocol("unsupported version".into()));
        }
        let msg_type = header[5];
        let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;
        if payload_len > config.max_frame_payload {
            return Err(RelayError::FrameTooLarge(
                payload_len,
                config.max_frame_payload,
            ));
        }
        let mut payload = vec![0u8; payload_len];
        if payload_len > 0 {
            reader.read_exact(&mut payload).await?;
        }
        Ok(Frame::new(msg_type, payload))
    };

    let first_frame = match tokio::select! {
        _ = &mut shutdown_rx => {
            return Err(RelayError::Closed("connection shutdown before registration".into()));
        }
        res = tokio::time::timeout(config.register_timeout, first_frame_fut) => match res {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(RelayError::Timeout("registration timed out".into())),
        }
    } {
        Ok(frame) => frame,
        Err(e) => {
            let err_code = match &e {
                RelayError::FrameTooLarge(_, _) => ERR_FRAME_TOO_LARGE,
                RelayError::Timeout(_) => ERR_REGISTRATION_TIMEOUT,
                RelayError::Protocol(s) if s.contains("unsupported version") => {
                    ERR_UNSUPPORTED_VERSION
                }
                RelayError::Protocol(s) if s.contains("invalid magic") => ERR_INVALID_FRAME,
                _ => ERR_INVALID_FRAME,
            };
            let _ = tx.try_send(Frame::error(err_code, &e.to_string()).encode());
            tokio::time::sleep(Duration::from_millis(50)).await;
            return Err(e);
        }
    };

    if first_frame.msg_type != MSG_REGISTER {
        let _ =
            tx.try_send(Frame::error(ERR_REGISTRATION_REQUIRED, "registration required").encode());
        tokio::time::sleep(Duration::from_millis(50)).await;
        return Err(RelayError::Protocol("first frame must be register".into()));
    }

    let node_id = match std::str::from_utf8(&first_frame.payload) {
        Ok(s) => s.to_string(),
        Err(_) => {
            let _ = tx.try_send(Frame::error(ERR_INVALID_FRAME, "invalid node ID UTF-8").encode());
            tokio::time::sleep(Duration::from_millis(50)).await;
            return Err(RelayError::Protocol("invalid node ID UTF-8".into()));
        }
    };

    if node_id.is_empty() || node_id.len() > MAX_NODE_ID_LEN {
        let _ = tx.try_send(Frame::error(ERR_INVALID_FRAME, "invalid node ID length").encode());
        tokio::time::sleep(Duration::from_millis(50)).await;
        return Err(RelayError::Protocol("invalid node ID length".into()));
    }

    debug!("Client {:?} registering as '{}'", client_addr, node_id);
    let registered_id = Some(node_id.clone());

    // Register in peer table, close duplicate connection if exists
    let my_connection = PeerConnection {
        tx: tx.clone(),
        shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
        conn_id,
    };

    {
        let mut table = peer_table.lock().await;
        if let Some(old_conn) = table.get(&node_id) {
            // Unregister/shutdown the old connection
            if let Some(s_tx) = old_conn.shutdown_tx.lock().await.take() {
                let _ = s_tx.send(());
            }
        }
        table.insert(node_id.clone(), my_connection);
    }

    // Send confirmation
    if tx.send(Frame::registered(&node_id).encode()).await.is_err() {
        return Err(RelayError::Closed(
            "client closed connection immediately".into(),
        ));
    }

    // Read loop with idle_timeout
    let mut buf = vec![0u8; config.max_frame_payload + FRAME_HEADER_SIZE];

    loop {
        // Read header with idle timeout
        let read_header_fut = reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]);
        let read_res = tokio::select! {
            _ = &mut shutdown_rx => {
                debug!("Client '{}' connection closed by shutdown signal", node_id);
                break;
            }
            res = tokio::time::timeout(config.idle_timeout, read_header_fut) => match res {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    debug!("Client '{}' disconnected", node_id);
                    break;
                }
                Ok(Err(e)) => Err(RelayError::Io(e)),
                Err(_) => {
                    debug!("Client '{}' idle timeout", node_id);
                    let _ = tx.try_send(Frame::error(ERR_IDLE_TIMEOUT, "idle timeout").encode());
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    break;
                }
            }
        };

        if let Err(e) = read_res {
            warn!("Read error from '{}': {}", node_id, e);
            break;
        }

        // Parse header
        if buf[..4] != MAGIC {
            warn!("Invalid magic from '{}'", node_id);
            let _ = tx.try_send(Frame::error(ERR_INVALID_FRAME, "invalid magic").encode());
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }
        let version = buf[4];
        if version != VERSION {
            warn!("Unsupported version {} from '{}'", version, node_id);
            let _ =
                tx.try_send(Frame::error(ERR_UNSUPPORTED_VERSION, "unsupported version").encode());
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }
        let msg_type = buf[5];
        let payload_len = u16::from_be_bytes([buf[6], buf[7]]) as usize;

        if payload_len > config.max_frame_payload {
            warn!(
                "Payload length {} exceeds limit {}",
                payload_len, config.max_frame_payload
            );
            let _ = tx.try_send(Frame::error(ERR_FRAME_TOO_LARGE, "frame too large").encode());
            tokio::time::sleep(Duration::from_millis(50)).await;
            break;
        }

        // Read payload
        if payload_len > 0 {
            if buf.len() < FRAME_HEADER_SIZE + payload_len {
                buf.resize(FRAME_HEADER_SIZE + payload_len, 0);
            }
            let read_payload_fut =
                reader.read_exact(&mut buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len]);
            let read_payload_res = tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                res = read_payload_fut => res,
            };
            if let Err(e) = read_payload_res {
                warn!("Payload read error from '{}': {}", node_id, e);
                break;
            }
        }

        let payload = &buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len];

        match msg_type {
            MSG_REGISTER => {
                let new_id = match std::str::from_utf8(payload) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        let _ = tx
                            .try_send(Frame::error(ERR_INVALID_FRAME, "invalid node ID").encode());
                        continue;
                    }
                };
                if Some(&new_id) != registered_id.as_ref() {
                    let _ = tx.try_send(
                        Frame::error(
                            ERR_DUPLICATE_REGISTRATION,
                            "already registered with a different node ID",
                        )
                        .encode(),
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    break;
                } else {
                    let _ = tx.try_send(Frame::registered(&new_id).encode());
                }
            }

            MSG_FORWARD => {
                if payload.is_empty() {
                    let _ = tx.try_send(
                        Frame::error(ERR_INVALID_FRAME, "empty forward payload").encode(),
                    );
                    continue;
                }

                let dst_len = payload[0] as usize;
                if payload.len() < 1 + dst_len {
                    let _ =
                        tx.try_send(Frame::error(ERR_INVALID_FRAME, "malformed forward").encode());
                    continue;
                }

                let dst_id = match std::str::from_utf8(&payload[1..1 + dst_len]) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ =
                            tx.try_send(Frame::error(ERR_INVALID_FRAME, "invalid dst ID").encode());
                        continue;
                    }
                };

                let data = &payload[1 + dst_len..];

                // Check if outbound frame payload exceeds the configured maximum frame payload
                let total_received_len = 1 + node_id.len() + data.len();
                if total_received_len > config.max_frame_payload {
                    let _ = tx.try_send(
                        Frame::error(ERR_FRAME_TOO_LARGE, "forward payload too large").encode(),
                    );
                    continue;
                }

                // Look up destination peer
                let dst_conn = {
                    let table = peer_table.lock().await;
                    table.get(dst_id).cloned()
                };

                match dst_conn {
                    Some(dst) => {
                        // Build a Received frame and forward it
                        match Frame::received(&node_id, data) {
                            Ok(frame) => match dst.tx.try_send(frame.encode()) {
                                Ok(_) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    warn!("Target '{}' is slow consumer, closing it", dst_id);
                                    if let Some(s_tx) = dst.shutdown_tx.lock().await.take() {
                                        let _ = s_tx.send(());
                                    }
                                    let _ = tx.try_send(
                                        Frame::error(
                                            ERR_PEER_BACKPRESSURE,
                                            "target peer outbound queue full",
                                        )
                                        .encode(),
                                    );
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    let _ = tx.try_send(
                                        Frame::error(
                                            ERR_PEER_NOT_FOUND,
                                            "target peer write channel closed",
                                        )
                                        .encode(),
                                    );
                                }
                            },
                            Err(e) => {
                                let _ = tx.try_send(
                                    Frame::error(ERR_INVALID_FRAME, &e.to_string()).encode(),
                                );
                            }
                        }
                    }
                    None => {
                        let _ = tx.try_send(
                            Frame::error(ERR_PEER_NOT_FOUND, &format!("peer not found: {dst_id}"))
                                .encode(),
                        );
                    }
                }
            }

            MSG_PING => {
                let timestamp = if payload.len() >= 8 {
                    u64::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                        payload[6], payload[7],
                    ])
                } else {
                    0
                };
                let _ = tx.try_send(Frame::pong(timestamp).encode());
            }

            MSG_CLOSE => {
                debug!("Client '{}' sent close", node_id);
                break;
            }

            _ => {
                warn!(
                    "Unexpected message type {:#04X} from client '{}'",
                    msg_type, node_id
                );
                let _ = tx
                    .try_send(Frame::error(ERR_INVALID_FRAME, "unexpected message type").encode());
            }
        }
    }

    // Clean up: remove from peer table if it's still ours
    if let Some(id) = &registered_id {
        let mut table = peer_table.lock().await;
        if let Some(conn) = table.get(id) {
            if conn.conn_id == conn_id {
                table.remove(id);
                debug!("Removed '{}' (conn_id={}) from peer table", id, conn_id);
            }
        }
    }

    write_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RelayClient;
    use crate::{RelayClientConfig, RelayErrorCode};
    use std::time::Duration;

    #[tokio::test]
    async fn test_server_start_and_shutdown() {
        let server = RelayServer::start_random().await.unwrap();
        assert!(server.addr.port() > 0);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_client_register_and_forward() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        // Client A registers
        let (mut client_a, mut rx_a) = RelayClient::connect(&addr.to_string(), "nodeA")
            .await
            .unwrap();

        // Client B registers
        let (mut client_b, mut rx_b) = RelayClient::connect(&addr.to_string(), "nodeB")
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // A sends data to B
        client_a.send_data("nodeB", b"hello from A").await.unwrap();

        // B should receive it
        let received = tokio::time::timeout(Duration::from_secs(2), rx_b.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(received.from_node, "nodeA");
        assert_eq!(received.data, b"hello from A");

        // B sends data back to A
        client_b.send_data("nodeA", b"hi from B").await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(2), rx_a.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert_eq!(received.from_node, "nodeB");
        assert_eq!(received.data, b"hi from B");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_forward_to_nonexistent_peer() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "lonely")
            .await
            .unwrap();

        // connect() waited for registration

        // Send to a peer that doesn't exist
        client.send_data("ghost", b"data").await.unwrap();

        // Should receive an error
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        assert!(received.from_node.is_empty()); // Error messages have empty from_node
        assert!(received.data.starts_with(b"error:"));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_ping_pong() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client, mut rx) = RelayClient::connect(&addr.to_string(), "pinger")
            .await
            .unwrap();

        // connect() waited for registration

        client.ping().await.unwrap();

        // Should receive a pong
        let received = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout")
            .expect("channel closed");

        // Pong comes as a special message
        assert!(received.from_node.is_empty());

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_multiple_peers() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        // Register 3 clients
        let (_c1, mut rx1) = RelayClient::connect(&addr.to_string(), "p1").await.unwrap();
        let (_c2, mut rx2) = RelayClient::connect(&addr.to_string(), "p2").await.unwrap();
        let (mut c3, _rx3) = RelayClient::connect(&addr.to_string(), "p3").await.unwrap();

        tokio::time::sleep(Duration::from_millis(50)).await;

        // p3 sends to p1 and p2
        c3.send_data("p1", b"to p1").await.unwrap();
        c3.send_data("p2", b"to p2").await.unwrap();

        let r1 = tokio::time::timeout(Duration::from_secs(2), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r1.from_node, "p3");
        assert_eq!(r1.data, b"to p1");

        let r2 = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(r2.from_node, "p3");
        assert_eq!(r2.data, b"to p2");

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_large_data_transfer() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (mut client_a, _rxa) = RelayClient::connect(&addr.to_string(), "bigA")
            .await
            .unwrap();
        let (_client_b, mut rxb) = RelayClient::connect(&addr.to_string(), "bigB")
            .await
            .unwrap();

        // connect() waited for registration

        // Send 60KB of data
        let big_data = vec![0x42u8; 60000];
        client_a.send_data("bigB", &big_data).await.unwrap();

        let received = tokio::time::timeout(Duration::from_secs(3), rxb.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(received.from_node, "bigA");
        assert_eq!(received.data.len(), 60000);
        assert!(received.data.iter().all(|&b| b == 0x42));

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_invalid_limits() {
        let config = RelayServerConfig {
            max_connections: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
        assert!(RelayServer::start_with_config("127.0.0.1:0", config)
            .await
            .is_err());

        let client_cfg = RelayClientConfig {
            cmd_queue_capacity: 0,
            ..Default::default()
        };
        assert!(client_cfg.validate().is_err());
    }

    #[tokio::test]
    async fn test_client_command_and_inbound_queue_bounded() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let config = RelayClientConfig {
            cmd_queue_capacity: 1,
            inbound_queue_capacity: 1,
            ..Default::default()
        };

        let (_client, _rx) =
            RelayClient::connect_verified_with_config(&addr.to_string(), "client-bounded", config)
                .await
                .unwrap();
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_server_outbound_queue_full_policy() {
        let server_config = RelayServerConfig {
            outbound_queue_capacity: 1,
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let mut bob_stream = TcpStream::connect(addr).await.unwrap();
        let reg = Frame::register("bob").encode();
        bob_stream.write_all(&reg).await.unwrap();

        let mut buf = [0u8; 100];
        let n = bob_stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        let (mut alice, mut rx_a) = RelayClient::connect_verified(&addr.to_string(), "alice")
            .await
            .unwrap();

        let mut got_backpressure = false;
        let data = vec![0u8; 10000];
        for _ in 0..100 {
            let _ = alice.send_data("bob", &data).await;
            tokio::time::sleep(Duration::from_millis(2)).await;
            if let Ok(Some(msg)) = tokio::time::timeout(Duration::from_millis(5), rx_a.recv()).await
            {
                if msg.from_node.is_empty() && msg.data.starts_with(b"error:4008") {
                    got_backpressure = true;
                    break;
                }
            }
        }
        assert!(got_backpressure, "Should have received backpressure error");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_register_timeout() {
        let server_config = RelayServerConfig {
            register_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let frame = Frame::decode(&buf[..n]);
        if let Ok((f, _)) = frame {
            assert_eq!(f.msg_type, MSG_ERROR);
            let (code, _) = f.parse_error().unwrap();
            assert_eq!(code, ERR_REGISTRATION_TIMEOUT);
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_idle_timeout() {
        let server_config = RelayServerConfig {
            idle_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let (_client, mut rx) = RelayClient::connect_verified(&addr.to_string(), "client-idle")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let msg = tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(msg.from_node.is_empty());
        assert!(msg.data.starts_with(b"error:4009")); // ERR_IDLE_TIMEOUT
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_max_connections() {
        let server_config = RelayServerConfig {
            max_connections: 1,
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let (_client1, _rx1) = RelayClient::connect_verified(&addr.to_string(), "c1")
            .await
            .unwrap();
        let res = RelayClient::connect_verified(&addr.to_string(), "c2").await;
        assert!(res.is_err());
        let err = res.unwrap_err();
        if let RelayError::ServerError(code, _) = err {
            assert_eq!(code, ERR_CONNECTION_LIMIT);
        } else {
            panic!("Expected server error, got: {:?}", err);
        }
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_oversized_frame_rejected_before_payload() {
        let server_config = RelayServerConfig {
            max_frame_payload: 10,
            ..Default::default()
        };
        let server = RelayServer::start_with_config("127.0.0.1:0", server_config)
            .await
            .unwrap();
        let addr = server.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let reg = Frame::register("c1").encode();
        stream.write_all(&reg).await.unwrap();
        let mut buf = [0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        let mut header = Vec::new();
        header.extend_from_slice(&MAGIC);
        header.push(VERSION);
        header.push(MSG_FORWARD);
        header.extend_from_slice(&1000u16.to_be_bytes());
        stream.write_all(&header).await.unwrap();

        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_ERROR);
        let (code, _) = f.parse_error().unwrap();
        assert_eq!(code, ERR_FRAME_TOO_LARGE);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_duplicate_registration_race_and_ownership() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let (client1, mut rx1) = RelayClient::connect_verified(&addr.to_string(), "dup")
            .await
            .unwrap();
        let (_client2, mut rx2) = RelayClient::connect_verified(&addr.to_string(), "dup")
            .await
            .unwrap();

        let msg = tokio::time::timeout(Duration::from_millis(500), rx1.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(msg.from_node.is_empty());
        assert_eq!(msg.data, b"closed");

        drop(client1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (mut client3, _rx3) = RelayClient::connect_verified(&addr.to_string(), "sender3")
            .await
            .unwrap();
        client3.send_data("dup", b"still here").await.unwrap();

        let msg = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(msg.from_node, "sender3");
        assert_eq!(msg.data, b"still here");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_duplicate_registration_same_connection() {
        let server = RelayServer::start_random().await.unwrap();
        let addr = server.addr;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let reg1 = Frame::register("node-a").encode();
        stream.write_all(&reg1).await.unwrap();
        let mut buf = [0u8; 100];
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        stream.write_all(&reg1).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_REGISTERED);

        let reg2 = Frame::register("node-b").encode();
        stream.write_all(&reg2).await.unwrap();
        let n = stream.read(&mut buf).await.unwrap();
        assert!(n > 0);
        let (f, _) = Frame::decode(&buf[..n]).unwrap();
        assert_eq!(f.msg_type, MSG_ERROR);
        let (code, _) = f.parse_error().unwrap();
        assert_eq!(code, ERR_DUPLICATE_REGISTRATION);
        server.shutdown().await;
    }

    #[test]
    fn test_unknown_wire_error_code() {
        let frame = Frame::error(9999, "unknown issue");
        let (code, msg) = frame.parse_error().unwrap();
        assert_eq!(code, 9999);
        assert_eq!(msg, "unknown issue");

        let ec = RelayErrorCode::from_u16(9999);
        assert!(ec.is_none());
    }
}
