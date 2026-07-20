//! DERP-like relay wire protocol.
//!
//! ## Frame Format
//!
//! Every message on the wire is a frame:
//!
//! ```text
//! +------+------+------+------+------+------+------+------+
//! | 0x44 | 0x45 | 0x52 | 0x50 | ver  | type | len (2B, BE) | payload ... |
//! +------+------+------+------+------+------+------+------+
//!  \___________________________/  \____/  \____/  \__________/  \________/
//!          magic "DERP"           version  type   length (BE)    payload
//! ```
//!
//! - **Magic**: `b"DERP"` (4 bytes)
//! - **Version**: protocol version (currently 1)
//! - **Type**: message type byte
//! - **Length**: payload length in bytes (big-endian u16, max 65535)
//! - **Payload**: type-specific data
//!
//! ## Message Types
//!
//! | Type | Name       | Payload                                              |
//! |------|------------|------------------------------------------------------|
//! | 0x01 | Register   | `[node_id UTF-8]`                                    |
//! | 0x02 | Registered | `[node_id UTF-8]` (server confirms registration)     |
//! | 0x03 | Forward    | `[1B dst_len][dst_id][data...]` (send to peer)       |
//! | 0x04 | Received   | `[1B src_len][src_id][data...]` (data from peer)     |
//! | 0x05 | Ping       | `[8B timestamp BE]`                                  |
//! | 0x06 | Pong       | `[8B timestamp BE]`                                  |
//! | 0x07 | Error      | `[2B code BE][message UTF-8]`                        |
//! | 0x08 | Close      | `[1B reason_code]`                                    |

use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{RelayError, Result};

// ============================================================
// Constants
// ============================================================

/// Magic bytes identifying a DERP frame.
pub const MAGIC: [u8; 4] = *b"DERP";

/// Current protocol version.
pub const VERSION: u8 = 1;

/// Maximum payload size (u16 max).
pub const MAX_PAYLOAD: usize = 65535;

/// Frame header size: 4 (magic) + 1 (version) + 1 (type) + 2 (length).
pub const FRAME_HEADER_SIZE: usize = 8;

/// Maximum node ID length.
pub const MAX_NODE_ID_LEN: usize = 255;

// Message types
pub const MSG_REGISTER: u8 = 0x01;
pub const MSG_REGISTERED: u8 = 0x02;
pub const MSG_FORWARD: u8 = 0x03;
pub const MSG_RECEIVED: u8 = 0x04;
pub const MSG_PING: u8 = 0x05;
pub const MSG_PONG: u8 = 0x06;
pub const MSG_ERROR: u8 = 0x07;
pub const MSG_CLOSE: u8 = 0x08;
pub const MSG_AUTH_REGISTER: u8 = 0x09;

// Close reason codes
pub const CLOSE_NORMAL: u8 = 0x00;
pub const CLOSE_ERROR: u8 = 0x01;
pub const CLOSE_TIMEOUT: u8 = 0x02;

// Error codes (stable wire codes)
pub const ERR_INVALID_FRAME: u16 = 4000;
pub const ERR_UNSUPPORTED_VERSION: u16 = 4001;
pub const ERR_REGISTRATION_REQUIRED: u16 = 4002;
pub const ERR_REGISTRATION_TIMEOUT: u16 = 4003;
pub const ERR_DUPLICATE_REGISTRATION: u16 = 4004;
pub const ERR_CONNECTION_LIMIT: u16 = 4005;
pub const ERR_FRAME_TOO_LARGE: u16 = 4006;
pub const ERR_PEER_NOT_FOUND: u16 = 404;
pub const ERR_PEER_BACKPRESSURE: u16 = 4008;
pub const ERR_IDLE_TIMEOUT: u16 = 4009;
pub const ERR_TRANSPORT_CLOSED: u16 = 4010;

// ============================================================
// Frame
// ============================================================

/// A single protocol frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Message type byte.
    pub msg_type: u8,
    /// Frame payload.
    pub payload: Vec<u8>,
}

impl Frame {
    /// Create a new frame.
    pub fn new(msg_type: u8, payload: Vec<u8>) -> Self {
        Self { msg_type, payload }
    }

    /// Encode this frame to wire format.
    pub fn encode(&self) -> Vec<u8> {
        let len = self.payload.len() as u16;
        let mut buf = Vec::with_capacity(FRAME_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.push(self.msg_type);
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Decode a frame from a complete buffer.
    ///
    /// Returns `(frame, bytes_consumed)`.
    pub fn decode(data: &[u8]) -> Result<(Frame, usize)> {
        if data.len() < FRAME_HEADER_SIZE {
            return Err(RelayError::Protocol(format!(
                "frame too short: {} bytes (need at least {})",
                data.len(),
                FRAME_HEADER_SIZE
            )));
        }

        if data[..4] != MAGIC {
            return Err(RelayError::Protocol(format!(
                "invalid magic: {:02X?} (expected {:02X?})",
                &data[..4],
                MAGIC
            )));
        }

        let version = data[4];
        if version != VERSION {
            return Err(RelayError::Protocol(format!(
                "unsupported version: {} (expected {})",
                version, VERSION
            )));
        }

        let msg_type = data[5];
        let payload_len = u16::from_be_bytes([data[6], data[7]]) as usize;

        if data.len() < FRAME_HEADER_SIZE + payload_len {
            return Err(RelayError::Protocol(format!(
                "frame truncated: have {} bytes, header says {}",
                data.len(),
                FRAME_HEADER_SIZE + payload_len
            )));
        }

        let payload = data[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_len].to_vec();
        let consumed = FRAME_HEADER_SIZE + payload_len;

        Ok((Frame { msg_type, payload }, consumed))
    }

    /// Create a Register frame.
    pub fn register(node_id: &str) -> Self {
        Self::new(MSG_REGISTER, node_id.as_bytes().to_vec())
    }

    /// Create a Registered frame.
    pub fn registered(node_id: &str) -> Self {
        Self::new(MSG_REGISTERED, node_id.as_bytes().to_vec())
    }

    /// Create a Forward frame (send data to a peer).
    pub fn forward(dst_id: &str, data: &[u8]) -> Result<Self> {
        let dst_bytes = dst_id.as_bytes();
        if dst_bytes.len() > MAX_NODE_ID_LEN {
            return Err(RelayError::Protocol(format!(
                "destination node ID too long: {} bytes (max {})",
                dst_bytes.len(),
                MAX_NODE_ID_LEN
            )));
        }
        let payload_len = 1 + dst_bytes.len() + data.len();
        if payload_len > MAX_PAYLOAD {
            return Err(RelayError::FrameTooLarge(payload_len, MAX_PAYLOAD));
        }
        let mut payload = Vec::with_capacity(payload_len);
        payload.push(dst_bytes.len() as u8);
        payload.extend_from_slice(dst_bytes);
        payload.extend_from_slice(data);
        Ok(Self::new(MSG_FORWARD, payload))
    }

    /// Create a Received frame (data received from a peer).
    pub fn received(src_id: &str, data: &[u8]) -> Result<Self> {
        let src_bytes = src_id.as_bytes();
        if src_bytes.len() > MAX_NODE_ID_LEN {
            return Err(RelayError::Protocol(format!(
                "source node ID too long: {} bytes (max {})",
                src_bytes.len(),
                MAX_NODE_ID_LEN
            )));
        }
        let payload_len = 1 + src_bytes.len() + data.len();
        if payload_len > MAX_PAYLOAD {
            return Err(RelayError::FrameTooLarge(payload_len, MAX_PAYLOAD));
        }
        let mut payload = Vec::with_capacity(payload_len);
        payload.push(src_bytes.len() as u8);
        payload.extend_from_slice(src_bytes);
        payload.extend_from_slice(data);
        Ok(Self::new(MSG_RECEIVED, payload))
    }

    /// Create a Ping frame with the current timestamp.
    pub fn ping() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self::new(MSG_PING, now.to_be_bytes().to_vec())
    }

    /// Create a Pong frame echoing a Ping timestamp.
    pub fn pong(ping_timestamp: u64) -> Self {
        Self::new(MSG_PONG, ping_timestamp.to_be_bytes().to_vec())
    }

    /// Create an Error frame.
    pub fn error(code: u16, message: &str) -> Self {
        let mut payload = Vec::with_capacity(2 + message.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(message.as_bytes());
        Self::new(MSG_ERROR, payload)
    }

    /// Create a Close frame.
    pub fn close(reason: u8) -> Self {
        Self::new(MSG_CLOSE, vec![reason])
    }

    // ---- Payload parsing helpers ----

    /// Parse a Forward/Received payload into (peer_id, data).
    pub fn parse_forward_payload(&self) -> Result<(&str, &[u8])> {
        if self.payload.is_empty() {
            return Err(RelayError::Protocol("forward payload empty".into()));
        }
        let id_len = self.payload[0] as usize;
        if self.payload.len() < 1 + id_len {
            return Err(RelayError::Protocol("forward payload truncated".into()));
        }
        let id_bytes = &self.payload[1..1 + id_len];
        let id = std::str::from_utf8(id_bytes)
            .map_err(|e| RelayError::Protocol(format!("invalid UTF-8 in node ID: {e}")))?;
        let data = &self.payload[1 + id_len..];
        Ok((id, data))
    }

    /// Parse a Ping/Pong payload as a timestamp.
    pub fn parse_timestamp(&self) -> Result<u64> {
        if self.payload.len() < 8 {
            return Err(RelayError::Protocol("timestamp payload too short".into()));
        }
        Ok(u64::from_be_bytes([
            self.payload[0],
            self.payload[1],
            self.payload[2],
            self.payload[3],
            self.payload[4],
            self.payload[5],
            self.payload[6],
            self.payload[7],
        ]))
    }

    /// Parse an Error payload into (code, message).
    pub fn parse_error(&self) -> Result<(u16, String)> {
        if self.payload.len() < 2 {
            return Err(RelayError::Protocol("error payload too short".into()));
        }
        let code = u16::from_be_bytes([self.payload[0], self.payload[1]]);
        let message = String::from_utf8_lossy(&self.payload[2..]).to_string();
        Ok((code, message))
    }

    /// Parse a Close payload into a reason code.
    pub fn parse_close_reason(&self) -> Result<u8> {
        if self.payload.is_empty() {
            return Ok(CLOSE_NORMAL);
        }
        Ok(self.payload[0])
    }

    /// Parse a Register/Registered payload as a node ID string.
    pub fn parse_node_id(&self) -> Result<String> {
        String::from_utf8(self.payload.clone())
            .map_err(|e| RelayError::Protocol(format!("invalid UTF-8 in node ID: {e}")))
    }
}

// ============================================================
// FrameCodec — async read/write helper
// ============================================================

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Asynchronously read a complete frame from a reader.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    // Read header
    let mut header = [0u8; FRAME_HEADER_SIZE];
    reader.read_exact(&mut header).await?;

    if header[..4] != MAGIC {
        return Err(RelayError::Protocol(format!(
            "invalid magic: {:02X?}",
            &header[..4]
        )));
    }

    let version = header[4];
    if version != VERSION {
        return Err(RelayError::Protocol(format!(
            "unsupported version: {version}"
        )));
    }

    let msg_type = header[5];
    let payload_len = u16::from_be_bytes([header[6], header[7]]) as usize;

    if payload_len > MAX_PAYLOAD {
        return Err(RelayError::FrameTooLarge(payload_len, MAX_PAYLOAD));
    }

    // Read payload
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader.read_exact(&mut payload).await?;
    }

    Ok(Frame { msg_type, payload })
}

/// Asynchronously write a frame to a writer.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    let encoded = frame.encode();
    writer.write_all(&encoded).await?;
    Ok(())
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode_roundtrip() {
        let frame = Frame::new(MSG_PING, vec![0x01, 0x02, 0x03]);
        let encoded = frame.encode();
        assert!(encoded.starts_with(&MAGIC));
        assert_eq!(encoded[4], VERSION);
        assert_eq!(encoded[5], MSG_PING);

        let (decoded, consumed) = Frame::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_register_frame() {
        let frame = Frame::register("node-abc123");
        assert_eq!(frame.msg_type, MSG_REGISTER);
        assert_eq!(frame.parse_node_id().unwrap(), "node-abc123");
    }

    #[test]
    fn test_forward_frame_roundtrip() {
        let data = b"hello relay world";
        let frame = Frame::forward("peer456", data).unwrap();
        assert_eq!(frame.msg_type, MSG_FORWARD);

        let (dst, payload) = frame.parse_forward_payload().unwrap();
        assert_eq!(dst, "peer456");
        assert_eq!(payload, data);
    }

    #[test]
    fn test_received_frame_roundtrip() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = Frame::received("src789", &data).unwrap();
        assert_eq!(frame.msg_type, MSG_RECEIVED);

        let (src, payload) = frame.parse_forward_payload().unwrap();
        assert_eq!(src, "src789");
        assert_eq!(payload, &data[..]);
    }

    #[test]
    fn test_ping_pong_timestamp() {
        let ping = Frame::ping();
        assert_eq!(ping.msg_type, MSG_PING);
        let ts = ping.parse_timestamp().unwrap();
        assert!(ts > 0);

        let pong = Frame::pong(ts);
        assert_eq!(pong.msg_type, MSG_PONG);
        assert_eq!(pong.parse_timestamp().unwrap(), ts);
    }

    #[test]
    fn test_error_frame() {
        let frame = Frame::error(404, "peer not found");
        assert_eq!(frame.msg_type, MSG_ERROR);
        let (code, msg) = frame.parse_error().unwrap();
        assert_eq!(code, 404);
        assert_eq!(msg, "peer not found");
    }

    #[test]
    fn test_close_frame() {
        let frame = Frame::close(CLOSE_ERROR);
        assert_eq!(frame.msg_type, MSG_CLOSE);
        assert_eq!(frame.parse_close_reason().unwrap(), CLOSE_ERROR);
    }

    #[test]
    fn test_close_frame_empty() {
        // Close with no payload should default to CLOSE_NORMAL
        let frame = Frame::new(MSG_CLOSE, vec![]);
        assert_eq!(frame.parse_close_reason().unwrap(), CLOSE_NORMAL);
    }

    #[test]
    fn test_invalid_magic() {
        let buf = vec![0x00, 0x01, 0x02, 0x03, VERSION, MSG_PING, 0x00, 0x00];
        let result = Frame::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_version() {
        let mut buf = MAGIC.to_vec();
        buf.push(0xFF); // wrong version
        buf.push(MSG_PING);
        buf.extend_from_slice(&0u16.to_be_bytes());
        let result = Frame::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_frame_too_short() {
        let buf = vec![0x00, 0x01];
        let result = Frame::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_truncated_payload() {
        let mut buf = MAGIC.to_vec();
        buf.push(VERSION);
        buf.push(MSG_FORWARD);
        buf.extend_from_slice(&100u16.to_be_bytes()); // claims 100 bytes
        buf.extend_from_slice(&[0x01]); // only 1 byte
        let result = Frame::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_forward_empty_data() {
        let frame = Frame::forward("peer", &[]).unwrap();
        let (dst, data) = frame.parse_forward_payload().unwrap();
        assert_eq!(dst, "peer");
        assert!(data.is_empty());
    }

    #[test]
    fn test_forward_large_data() {
        let data = vec![0xAB; 10000];
        let frame = Frame::forward("peer", &data).unwrap();
        let (dst, payload) = frame.parse_forward_payload().unwrap();
        assert_eq!(dst, "peer");
        assert_eq!(payload.len(), 10000);
    }

    #[test]
    fn test_node_id_too_long() {
        let long_id = "x".repeat(256);
        let result = Frame::forward(&long_id, b"data");
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_frames_in_buffer() {
        let f1 = Frame::ping();
        let f2 = Frame::register("node1");
        let f3 = Frame::close(CLOSE_NORMAL);

        let mut buf = Vec::new();
        buf.extend(f1.encode());
        buf.extend(f2.encode());
        buf.extend(f3.encode());

        let (d1, c1) = Frame::decode(&buf).unwrap();
        let (d2, c2) = Frame::decode(&buf[c1..]).unwrap();
        let (d3, _) = Frame::decode(&buf[c1 + c2..]).unwrap();

        assert_eq!(d1.msg_type, MSG_PING);
        assert_eq!(d2.msg_type, MSG_REGISTER);
        assert_eq!(d3.msg_type, MSG_CLOSE);
    }
}
