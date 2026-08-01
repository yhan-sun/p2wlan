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
