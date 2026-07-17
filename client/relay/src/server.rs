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
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};

use crate::error::Result;
use crate::protocol::*;

/// Shared state mapping node IDs to their write channels.
type PeerTable = Arc<Mutex<HashMap<String, mpsc::UnboundedSender<Vec<u8>>>>>;

/// A running relay server instance.
pub struct RelayServer {
    /// The address the server is listening on.
    pub addr: SocketAddr,
    /// Handle to the server task.
    handle: tokio::task::JoinHandle<()>,
}

impl RelayServer {
    /// Start a relay server on the given address.
    ///
    /// Returns once the server is listening.
    pub async fn start(addr: &str) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let actual_addr = listener.local_addr()?;
        let peer_table: PeerTable = Arc::new(Mutex::new(HashMap::new()));

        info!("Relay server listening on {}", actual_addr);

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, client_addr)) => {
                        debug!("New connection from {}", client_addr);
                        let table = peer_table.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_client(stream, table).await {
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
async fn handle_client(stream: TcpStream, peer_table: PeerTable) -> Result<()> {
    let client_addr = stream.peer_addr().ok();
    let (mut reader, mut writer) = stream.into_split();

    // Channel for sending data to this client (from other peers)
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Write task: forward queued frames to the TCP stream
    let write_task = tokio::spawn(async move {
        while let Some(frame_bytes) = rx.recv().await {
            if writer.write_all(&frame_bytes).await.is_err() {
                break;
            }
        }
    });

    // Read loop
    let mut registered_id: Option<String> = None;
    let mut buf = vec![0u8; MAX_PAYLOAD + FRAME_HEADER_SIZE];

    loop {
        // Read frame header
        match reader.read_exact(&mut buf[..FRAME_HEADER_SIZE]).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!("Client {:?} disconnected", client_addr);
                break;
            }
            Err(e) => {
                warn!("Read error from {:?}: {}", client_addr, e);
                break;
            }
        }

        // Parse header
        if buf[..4] != MAGIC {
            warn!("Invalid magic from {:?}", client_addr);
            break;
        }
        let version = buf[4];
        if version != VERSION {
            warn!("Unsupported version {} from {:?}", version, client_addr);
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
                warn!("Payload read error from {:?}: {}", client_addr, e);
                break;
            }
        }

        let payload = &buf[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len];

        match msg_type {
            MSG_REGISTER => {
                let node_id = match std::str::from_utf8(payload) {
                    Ok(s) => s.to_string(),
                    Err(_) => {
                        let _ = tx.send(Frame::error(400, "invalid node ID").encode());
                        continue;
                    }
                };

                debug!("Client {:?} registering as '{}'", client_addr, node_id);

                // Register in peer table
                {
                    let mut table = peer_table.lock().await;
                    table.insert(node_id.clone(), tx.clone());
                }
                registered_id = Some(node_id.clone());

                // Send confirmation
                let _ = tx.send(Frame::registered(&node_id).encode());
            }

            MSG_FORWARD => {
                if payload.is_empty() {
                    let _ = tx.send(Frame::error(400, "empty forward payload").encode());
                    continue;
                }

                let dst_len = payload[0] as usize;
                if payload.len() < 1 + dst_len {
                    let _ = tx.send(Frame::error(400, "malformed forward").encode());
                    continue;
                }

                let dst_id = match std::str::from_utf8(&payload[1..1 + dst_len]) {
                    Ok(s) => s,
                    Err(_) => {
                        let _ = tx.send(Frame::error(400, "invalid dst ID").encode());
                        continue;
                    }
                };

                let data = &payload[1 + dst_len..];

                // Look up destination peer
                let src_id = match &registered_id {
                    Some(id) => id.clone(),
                    None => {
                        let _ = tx.send(Frame::error(401, "not registered").encode());
                        continue;
                    }
                };

                let dst_tx = {
                    let table = peer_table.lock().await;
                    table.get(dst_id).cloned()
                };

                match dst_tx {
                    Some(dst) => {
                        // Build a Received frame and forward it
                        match Frame::received(&src_id, data) {
                            Ok(frame) => {
                                if dst.send(frame.encode()).is_err() {
                                    let _ =
                                        tx.send(Frame::error(503, "peer write failed").encode());
                                }
                            }
                            Err(e) => {
                                let _ = tx.send(Frame::error(500, &e.to_string()).encode());
                            }
                        }
                    }
                    None => {
                        let _ = tx
                            .send(Frame::error(404, &format!("peer not found: {dst_id}")).encode());
                    }
                }
            }

            MSG_PING => {
                // Echo pong with the same timestamp
                let timestamp = if payload.len() >= 8 {
                    u64::from_be_bytes([
                        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5],
                        payload[6], payload[7],
                    ])
                } else {
                    0
                };
                let _ = tx.send(Frame::pong(timestamp).encode());
            }

            MSG_CLOSE => {
                debug!("Client {:?} sent close", client_addr);
                break;
            }

            MSG_PONG => {
                // Ignore — client shouldn't send pong to server, but tolerate it
                debug!("Unexpected pong from {:?}", client_addr);
            }

            MSG_REGISTERED | MSG_RECEIVED | MSG_ERROR => {
                warn!(
                    "Unexpected message type {:#04X} from client {:?}",
                    msg_type, client_addr
                );
            }

            _ => {
                warn!(
                    "Unknown message type {:#04X} from {:?}",
                    msg_type, client_addr
                );
            }
        }
    }

    // Clean up: remove from peer table
    if let Some(id) = &registered_id {
        let mut table = peer_table.lock().await;
        table.remove(id);
        debug!("Removed '{}' from peer table", id);
    }

    write_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::RelayClient;
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
}
