//! Async STUN client for sending Binding Requests and parsing responses.
//!
//! ## Key Design
//!
//! - Uses an existing `UdpSocket` (NOT a new one) so NAT mappings are shared
//!   with the WireGuard tunnel
//! - Supports both standard Binding Requests and CHANGE-REQUEST (for NAT type detection)
//! - Timeout-based receives to avoid hanging

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::error::{NatError, Result};
use crate::stun::*;

/// Default STUN timeout (3 seconds).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(3);

/// Default maximum response size (1500 bytes, typical MTU).
const RECV_BUF_SIZE: usize = 2048;

/// Response from a STUN Binding Request.
#[derive(Debug, Clone)]
pub struct BindingResponse {
    /// The reflexive address (public IP + port as seen by the STUN server).
    pub reflexive_address: Option<SocketAddr>,
    /// The address the response came from (may differ from server if CHANGE-REQUEST was used).
    pub from_addr: SocketAddr,
    /// The full parsed STUN message.
    pub message: StunMessage,
}

/// Async STUN client.
pub struct StunClient {
    /// Timeout for receiving responses.
    timeout: Duration,
}

impl Default for StunClient {
    fn default() -> Self {
        Self::new()
    }
}

impl StunClient {
    /// Create a new STUN client with default timeout (3s).
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Create a new STUN client with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Send a Binding Request to `server_addr` and wait for the response.
    ///
    /// Uses the provided `socket` — this MUST be the same socket used for
    /// the WireGuard tunnel so NAT mappings are consistent.
    pub async fn binding_request(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
    ) -> Result<BindingResponse> {
        self.binding_request_with_change(socket, server_addr, false, false)
            .await
    }

    /// Send a Binding Request with optional CHANGE-REQUEST attribute.
    ///
    /// When `change_ip` or `change_port` is true, the STUN server sends its
    /// response from a different IP/port. This is used for NAT type detection.
    pub async fn binding_request_with_change(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
        change_ip: bool,
        change_port: bool,
    ) -> Result<BindingResponse> {
        // Build the Binding Request
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("P2PNet/0.1".to_string()));
        if change_ip || change_port {
            msg.add_attribute(StunAttribute::ChangeRequest {
                change_ip,
                change_port,
            });
        }

        let encoded = msg.encode();
        let transaction_id = msg.transaction_id;

        debug!(
            "Sending STUN Binding Request to {} (txn_id={:02x?}, change_ip={}, change_port={})",
            server_addr,
            &transaction_id[..4],
            change_ip,
            change_port
        );

        // Send
        socket
            .send_to(&encoded, server_addr)
            .await
            .map_err(|e| NatError::Network(format!("send_to failed: {e}")))?;

        // Receive with one total timeout. A live UDP socket can also carry
        // responses for an earlier STUN transaction (or unrelated tunnel
        // traffic), so a single `recv_from` followed by an immediate error is
        // unsafe: it turns harmless reordering into a failed gather. Keep
        // reading until the response for this transaction arrives or the
        // request's timeout expires.
        let recv_result = timeout(self.timeout, async {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            loop {
                let (len, from_addr) = socket
                    .recv_from(&mut buf)
                    .await
                    .map_err(|e| NatError::Network(format!("recv_from failed: {e}")))?;
                let data = &buf[..len];
                let message = match StunMessage::decode(data) {
                    Ok(message) => message,
                    Err(error) => {
                        debug!(
                            "Ignoring non-STUN UDP packet from {} while waiting for transaction {:02x?}: {}",
                            from_addr,
                            &transaction_id[..4],
                            error
                        );
                        continue;
                    }
                };

                // A delayed response for another request is expected when a
                // socket is shared by candidate gathering and liveness. It is
                // not a protocol failure for the request currently in flight.
                if message.transaction_id != transaction_id {
                    debug!(
                        "Ignoring STUN transaction mismatch from {}: sent {:02x?}, got {:02x?}",
                        from_addr,
                        &transaction_id[..4],
                        &message.transaction_id[..4]
                    );
                    continue;
                }

                // Check for error response
                if message.is_error_response() {
                    if let Some((code, reason)) = message.get_error_code() {
                        return Err(NatError::Stun(format!(
                            "STUN error response: {} {}",
                            code, reason
                        )));
                    }
                    return Err(NatError::Stun("STUN error response without code".into()));
                }

                // Check it's a binding response
                if !message.is_binding_response() {
                    return Err(NatError::Stun(format!(
                        "unexpected message type: 0x{:04X}",
                        message.msg_type
                    )));
                }

                let reflexive_address = message.get_reflexive_address();

                debug!(
                    "STUN response from {}: reflexive = {:?}",
                    from_addr, reflexive_address
                );

                return Ok(BindingResponse {
                    reflexive_address,
                    from_addr,
                    message,
                });
            }
        })
        .await;

        match recv_result {
            Ok(result) => result,
            Err(_) => {
                warn!(
                    "STUN request to {} timed out after {:?}",
                    server_addr, self.timeout
                );
                Err(NatError::Timeout(format!(
                    "no response from {} after {:?}",
                    server_addr, self.timeout
                )))
            }
        }
    }

    /// Send a Binding Request and return just the reflexive address.
    pub async fn get_reflexive_address(
        &self,
        socket: &UdpSocket,
        server_addr: SocketAddr,
    ) -> Result<SocketAddr> {
        let resp = self.binding_request(socket, server_addr).await?;
        resp.reflexive_address.ok_or_else(|| {
            NatError::Stun("no XOR-MAPPED-ADDRESS or MAPPED-ADDRESS in response".into())
        })
    }
}

/// Public test helpers (only available during testing).
#[cfg(test)]
pub mod test_helpers {
    use super::*;

    /// Spawn a mock STUN server that responds with XOR-MAPPED-ADDRESS.
    pub async fn spawn_mock_stun_server() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            while let Ok((len, client_addr)) = socket.recv_from(&mut buf).await {
                let data = &buf[..len];
                if let Ok(req) = StunMessage::decode(data) {
                    if req.msg_type == BINDING_REQUEST {
                        let mut resp =
                            StunMessage::with_transaction_id(BINDING_RESPONSE, req.transaction_id);
                        resp.add_attribute(StunAttribute::XorMappedAddress(client_addr));
                        resp.add_attribute(StunAttribute::Software("MockSTUN/1.0".to_string()));
                        let encoded = resp.encode();
                        let _ = socket.send_to(&encoded, client_addr).await;
                    }
                }
            }
        });

        (addr, handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::test_helpers::spawn_mock_stun_server;

    #[tokio::test]
    async fn test_binding_request_reflexive_address() {
        let (server_addr, _handle) = spawn_mock_stun_server().await;

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_local = client_socket.local_addr().unwrap();

        let stun = StunClient::with_timeout(Duration::from_secs(2));
        let result = stun
            .binding_request(&client_socket, server_addr)
            .await
            .unwrap();

        assert_eq!(result.reflexive_address, Some(client_local));
        assert_eq!(result.from_addr, server_addr);
        assert!(result.message.is_binding_response());
    }

    #[tokio::test]
    async fn test_get_reflexive_address() {
        let (server_addr, _handle) = spawn_mock_stun_server().await;

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_local = client_socket.local_addr().unwrap();

        let stun = StunClient::with_timeout(Duration::from_secs(2));
        let reflexive = stun
            .get_reflexive_address(&client_socket, server_addr)
            .await
            .unwrap();

        assert_eq!(reflexive, client_local);
    }

    #[tokio::test]
    async fn test_timeout_on_no_response() {
        let dead_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_socket.local_addr().unwrap();
        drop(dead_socket);

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun = StunClient::with_timeout(Duration::from_millis(200));

        let result = stun.binding_request(&client_socket, dead_addr).await;
        assert!(result.is_err());
        match result {
            Err(NatError::Timeout(_)) => {}
            Err(NatError::Network(_)) => {}
            _ => panic!("expected timeout or network error"),
        }
    }

    #[tokio::test]
    async fn test_transaction_id_mismatch() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            let (len, client_addr) = socket.recv_from(&mut buf).await.unwrap();
            let _req = StunMessage::decode(&buf[..len]).unwrap();

            let bad_txn_id = [0xFF; 12];
            let mut resp = StunMessage::with_transaction_id(BINDING_RESPONSE, bad_txn_id);
            resp.add_attribute(StunAttribute::XorMappedAddress(client_addr));
            let encoded = resp.encode();
            let _ = socket.send_to(&encoded, client_addr).await;
        });

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun = StunClient::with_timeout(Duration::from_millis(50));

        let result = stun.binding_request(&client_socket, addr).await;
        assert!(matches!(result, Err(NatError::Timeout(_))));
    }

    #[tokio::test]
    async fn test_ignores_stale_transaction_until_matching_response() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let _handle = tokio::spawn(async move {
            let mut buf = vec![0u8; RECV_BUF_SIZE];
            let (len, client_addr) = socket.recv_from(&mut buf).await.unwrap();
            let req = StunMessage::decode(&buf[..len]).unwrap();

            let mut stale = StunMessage::with_transaction_id(BINDING_RESPONSE, [0xEE; 12]);
            stale.add_attribute(StunAttribute::XorMappedAddress(client_addr));
            socket.send_to(&stale.encode(), client_addr).await.unwrap();

            let mut response =
                StunMessage::with_transaction_id(BINDING_RESPONSE, req.transaction_id);
            response.add_attribute(StunAttribute::XorMappedAddress(client_addr));
            socket
                .send_to(&response.encode(), client_addr)
                .await
                .unwrap();
        });

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun = StunClient::with_timeout(Duration::from_secs(1));
        let response = stun.binding_request(&client_socket, addr).await.unwrap();
        assert_eq!(
            response.reflexive_address,
            Some(client_socket.local_addr().unwrap())
        );
    }

    #[tokio::test]
    async fn test_binding_request_with_software_attr() {
        let (server_addr, _handle) = spawn_mock_stun_server().await;

        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stun = StunClient::with_timeout(Duration::from_secs(2));
        let resp = stun
            .binding_request(&client_socket, server_addr)
            .await
            .unwrap();

        let has_software = resp
            .message
            .attributes
            .iter()
            .any(|a| matches!(a, StunAttribute::Software(_)));
        assert!(has_software);
    }
}
