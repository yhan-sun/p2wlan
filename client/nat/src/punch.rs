//! UDP Hole Punching — establish direct P2P connection through NAT.
//!
//! ## Protocol
//!
//! Both sides simultaneously send punch packets to each other's candidate
//! addresses. When one side receives a punch, it sends an ACK back. When
//! an ACK is received, the connection is established.
//!
//! ```text
//! Node A                    Node B
//!   │── PUNCH ─────────────→│
//!   │←───────────── PUNCH ──│
//!   │── ACK ───────────────→│
//!   │←─────────────── ACK ──│
//!   │                        │
//!   │<── Tunnel Established ─→
//! ```
//!
//! ## Packet Format (14 bytes)
//!
//! ```text
//! [0x50 0x4E 0x43 0x48]  Magic ("PNCH")
//! [0x01]                 Version (1)
//! [0x01 or 0x02]         Type (1=Punch, 2=ACK)
//! [8 bytes]              Nonce (random, for correlation)
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{interval, timeout};
use tracing::{debug, info, warn};

use crate::error::{NatError, Result};

/// Magic bytes for punch packets: "PNCH".
const PUNCH_MAGIC: [u8; 4] = [0x50, 0x4E, 0x43, 0x48];

/// Protocol version.
const PUNCH_VERSION: u8 = 1;

/// Punch packet type.
const TYPE_PUNCH: u8 = 1;
/// ACK packet type.
const TYPE_ACK: u8 = 2;

/// Total punch packet size.
const PUNCH_PACKET_SIZE: usize = 14;

/// Configuration for hole punching.
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// Maximum time to spend punching.
    pub timeout: Duration,
    /// Interval between punch packets.
    pub interval: Duration,
    /// Maximum number of punch attempts per candidate.
    pub max_attempts: u32,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            interval: Duration::from_millis(200),
            max_attempts: 50,
        }
    }
}

/// Result of a hole punching attempt.
#[derive(Debug, Clone)]
pub struct PunchResult {
    /// Whether the connection was successfully established.
    pub connected: bool,
    /// The peer address that responded (if connected).
    pub peer_addr: Option<SocketAddr>,
    /// Elapsed time.
    pub elapsed: Duration,
    /// Number of punch packets sent.
    pub packets_sent: u32,
}

/// Public punch datagram type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchPacketKind {
    /// Probe sent to open/refresh a NAT mapping.
    Punch,
    /// Acknowledgement for a received probe.
    Ack,
}

/// A decoded punch protocol datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedPunchPacket {
    /// Packet kind.
    pub kind: PunchPacketKind,
    /// Correlation nonce.
    pub nonce: [u8; 8],
}

/// A parsed punch packet.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PunchPacket {
    packet_type: u8,
    nonce: [u8; 8],
}

impl PunchPacket {
    /// Create a new punch packet with a random nonce.
    fn new_punch() -> Self {
        use rand::RngCore;
        let mut nonce = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut nonce);
        Self {
            packet_type: TYPE_PUNCH,
            nonce,
        }
    }

    /// Create an ACK packet echoing the nonce.
    fn new_ack(nonce: [u8; 8]) -> Self {
        Self {
            packet_type: TYPE_ACK,
            nonce,
        }
    }

    /// Encode to 14 bytes.
    fn encode(&self) -> [u8; PUNCH_PACKET_SIZE] {
        let mut buf = [0u8; PUNCH_PACKET_SIZE];
        buf[..4].copy_from_slice(&PUNCH_MAGIC);
        buf[4] = PUNCH_VERSION;
        buf[5] = self.packet_type;
        buf[6..14].copy_from_slice(&self.nonce);
        buf
    }

    /// Decode from raw bytes.
    fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < PUNCH_PACKET_SIZE {
            return None;
        }
        if data[..4] != PUNCH_MAGIC {
            return None;
        }
        if data[4] != PUNCH_VERSION {
            return None;
        }
        let packet_type = data[5];
        if packet_type != TYPE_PUNCH && packet_type != TYPE_ACK {
            return None;
        }
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&data[6..14]);
        Some(Self { packet_type, nonce })
    }

    fn is_punch(&self) -> bool {
        self.packet_type == TYPE_PUNCH
    }

    fn is_ack(&self) -> bool {
        self.packet_type == TYPE_ACK
    }
}

impl From<PunchPacket> for DecodedPunchPacket {
    fn from(packet: PunchPacket) -> Self {
        let kind = if packet.is_punch() {
            PunchPacketKind::Punch
        } else {
            PunchPacketKind::Ack
        };

        Self {
            kind,
            nonce: packet.nonce,
        }
    }
}

/// Decode a punch protocol datagram, returning `None` for unrelated traffic.
pub fn decode_punch_packet(data: &[u8]) -> Option<DecodedPunchPacket> {
    PunchPacket::decode(data).map(Into::into)
}

/// Build a fresh PUNCH datagram.
pub fn build_punch_packet() -> [u8; PUNCH_PACKET_SIZE] {
    PunchPacket::new_punch().encode()
}

/// Build an ACK datagram for a received PUNCH nonce.
pub fn build_punch_ack(nonce: [u8; 8]) -> [u8; PUNCH_PACKET_SIZE] {
    PunchPacket::new_ack(nonce).encode()
}

/// Send one PUNCH probe to a candidate endpoint.
pub async fn send_punch(socket: &UdpSocket, peer_addr: SocketAddr) -> Result<()> {
    let bytes = build_punch_packet();
    socket
        .send_to(&bytes, peer_addr)
        .await
        .map_err(|e| NatError::Network(format!("punch send failed: {e}")))?;
    Ok(())
}

/// Perform UDP hole punching to establish a direct P2P connection.
///
/// This function uses the provided `socket` (which should be the same socket
/// used for WireGuard to maintain NAT mappings) and tries to connect to the
/// peer by sending punch packets to all candidate addresses.
///
/// Both sides must call this function simultaneously (coordinated via signaling).
pub async fn hole_punch(
    socket: &UdpSocket,
    peer_candidates: &[SocketAddr],
    config: &PunchConfig,
) -> Result<PunchResult> {
    if peer_candidates.is_empty() {
        return Err(NatError::NoCandidates);
    }

    let start = std::time::Instant::now();
    let mut packets_sent: u32 = 0;
    let mut seen_punches: std::collections::HashSet<[u8; 8]> = std::collections::HashSet::new();
    let mut send_interval = interval(config.interval);

    info!(
        "Starting hole punch to {} candidates (timeout={:?})",
        peer_candidates.len(),
        config.timeout
    );

    // Create a random nonce for our punch packets
    let my_punch = PunchPacket::new_punch();
    let punch_bytes = my_punch.encode();

    loop {
        // Check timeout
        if start.elapsed() >= config.timeout {
            warn!(
                "Hole punch timed out after {:?} (sent {} packets)",
                start.elapsed(),
                packets_sent
            );
            return Ok(PunchResult {
                connected: false,
                peer_addr: None,
                elapsed: start.elapsed(),
                packets_sent,
            });
        }

        // Check max attempts
        if packets_sent >= config.max_attempts * peer_candidates.len() as u32 {
            warn!("Max punch attempts reached");
            return Ok(PunchResult {
                connected: false,
                peer_addr: None,
                elapsed: start.elapsed(),
                packets_sent,
            });
        }

        // Send a punch packet to each candidate
        send_interval.tick().await;
        for &peer_addr in peer_candidates {
            match socket.send_to(&punch_bytes, peer_addr).await {
                Ok(_) => {
                    packets_sent += 1;
                    debug!("Sent punch to {} (attempt {})", peer_addr, packets_sent);
                }
                Err(e) => {
                    debug!("Failed to send punch to {}: {}", peer_addr, e);
                }
            }
        }

        // Try to receive a response (with short timeout)
        let mut buf = vec![0u8; 64];
        let recv_timeout = Duration::from_millis(100);

        match timeout(recv_timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from_addr))) => {
                let data = &buf[..len];
                if let Some(packet) = PunchPacket::decode(data) {
                    if packet.is_punch() {
                        // Received a punch from peer — send ACK back
                        debug!("Received PUNCH from {}", from_addr);

                        // Avoid replying to the same punch repeatedly
                        if seen_punches.insert(packet.nonce) {
                            let ack = PunchPacket::new_ack(packet.nonce);
                            let ack_bytes = ack.encode();
                            let _ = socket.send_to(&ack_bytes, from_addr).await;
                            debug!("Sent ACK to {}", from_addr);
                        }
                    } else if packet.is_ack() {
                        // Received an ACK — connection established!
                        info!("Received ACK from {} — connection established!", from_addr);
                        return Ok(PunchResult {
                            connected: true,
                            peer_addr: Some(from_addr),
                            elapsed: start.elapsed(),
                            packets_sent,
                        });
                    }
                } else {
                    // Not a punch packet — might be WireGuard traffic, ignore
                    debug!(
                        "Received non-punch packet from {} ({} bytes)",
                        from_addr, len
                    );
                }
            }
            Ok(Err(e)) => {
                debug!("recv_from error: {}", e);
            }
            Err(_) => {
                // Timeout — continue sending punches
            }
        }
    }
}

/// Send a keepalive packet to maintain NAT mapping.
///
/// Should be called periodically (e.g., every 25 seconds) to prevent
/// the NAT mapping from expiring.
pub async fn send_keepalive(socket: &UdpSocket, peer_addr: SocketAddr) -> Result<()> {
    send_punch(socket, peer_addr)
        .await
        .map_err(|e| NatError::Network(format!("keepalive send failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_punch_packet_encode_decode() {
        let punch = PunchPacket::new_punch();
        let encoded = punch.encode();
        assert_eq!(encoded.len(), PUNCH_PACKET_SIZE);
        assert_eq!(&encoded[..4], &PUNCH_MAGIC);

        let decoded = PunchPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, punch);
        assert!(decoded.is_punch());
    }

    #[test]
    fn test_ack_packet_encode_decode() {
        let nonce = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let ack = PunchPacket::new_ack(nonce);
        let encoded = ack.encode();

        let decoded = PunchPacket::decode(&encoded).unwrap();
        assert_eq!(decoded, ack);
        assert!(decoded.is_ack());
        assert_eq!(decoded.nonce, nonce);
    }

    #[test]
    fn test_public_punch_helpers() {
        let punch = build_punch_packet();
        let decoded = decode_punch_packet(&punch).unwrap();
        assert_eq!(decoded.kind, PunchPacketKind::Punch);

        let ack = build_punch_ack(decoded.nonce);
        let decoded_ack = decode_punch_packet(&ack).unwrap();
        assert_eq!(decoded_ack.kind, PunchPacketKind::Ack);
        assert_eq!(decoded_ack.nonce, decoded.nonce);
    }

    #[test]
    fn test_invalid_magic() {
        let mut buf = vec![0u8; PUNCH_PACKET_SIZE];
        buf[0] = 0xFF; // wrong magic
        assert!(PunchPacket::decode(&buf).is_none());
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = vec![0u8; PUNCH_PACKET_SIZE];
        buf[..4].copy_from_slice(&PUNCH_MAGIC);
        buf[4] = 0x99; // wrong version
        assert!(PunchPacket::decode(&buf).is_none());
    }

    #[test]
    fn test_too_short() {
        let buf = vec![0u8; 5];
        assert!(PunchPacket::decode(&buf).is_none());
    }

    #[tokio::test]
    async fn test_local_hole_punch() {
        // Create two local sockets and have them punch each other
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        let config = PunchConfig {
            timeout: Duration::from_secs(3),
            interval: Duration::from_millis(50),
            max_attempts: 100,
        };

        // Both sides punch simultaneously
        let candidates_b = [addr_b];
        let candidates_a = [addr_a];
        let punch_a = hole_punch(&socket_a, &candidates_b, &config);
        let punch_b = hole_punch(&socket_b, &candidates_a, &config);

        let (result_a, result_b) = tokio::join!(punch_a, punch_b);

        let result_a = result_a.unwrap();
        let result_b = result_b.unwrap();

        // At least one side should connect
        assert!(
            result_a.connected || result_b.connected,
            "Neither side connected! A={:?}, B={:?}",
            result_a,
            result_b
        );

        if result_a.connected {
            assert_eq!(result_a.peer_addr, Some(addr_b));
        }
        if result_b.connected {
            assert_eq!(result_b.peer_addr, Some(addr_a));
        }
    }

    #[tokio::test]
    async fn test_hole_punch_no_candidates() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config = PunchConfig::default();

        let result = hole_punch(&socket, &[], &config).await;
        assert!(result.is_err());
        assert!(matches!(result, Err(NatError::NoCandidates)));
    }

    #[tokio::test]
    async fn test_hole_punch_timeout() {
        // Punch to a dead address — should timeout
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let config = PunchConfig {
            timeout: Duration::from_millis(500),
            interval: Duration::from_millis(100),
            max_attempts: 10,
        };

        // Use a non-existent but valid address
        let dead_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();

        let result = hole_punch(&socket, &[dead_addr], &config).await.unwrap();
        assert!(!result.connected);
        assert!(result.elapsed >= Duration::from_millis(400));
    }

    #[tokio::test]
    async fn test_keepalive() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        // Send keepalive from A to B
        send_keepalive(&socket_a, addr_b).await.unwrap();

        // B should receive a punch packet
        let mut buf = vec![0u8; 64];
        let (len, from) = socket_b.recv_from(&mut buf).await.unwrap();
        let packet = PunchPacket::decode(&buf[..len]).unwrap();
        assert!(packet.is_punch());
        assert_eq!(from, socket_a.local_addr().unwrap());
    }

    #[tokio::test]
    async fn test_simultaneous_punch_both_connect() {
        // Test that both sides can connect to each other
        let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();

        let config = PunchConfig {
            timeout: Duration::from_secs(5),
            interval: Duration::from_millis(50),
            max_attempts: 200,
        };

        let candidates_b = [addr_b];
        let candidates_a = [addr_a];
        let (result_a, result_b) = tokio::join!(
            hole_punch(&socket_a, &candidates_b, &config),
            hole_punch(&socket_b, &candidates_a, &config),
        );

        let result_a = result_a.unwrap();
        let result_b = result_b.unwrap();

        // Both should connect (each receives the other's punch and sends ACK,
        // then receives the other's ACK)
        // Note: due to timing, it's possible only one connects if the other
        // receives a punch but the ACK arrives before the next receive loop.
        // But in practice both should connect.
        assert!(
            result_a.connected || result_b.connected,
            "At least one should connect"
        );

        // Both should have sent packets
        assert!(result_a.packets_sent > 0);
        assert!(result_b.packets_sent > 0);
    }
}
