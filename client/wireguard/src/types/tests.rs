#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initiation_roundtrip() {
        let msg = MessageInitiation {
            sender_index: 0x12345678,
            ephemeral: [0xAB; 32],
            encrypted_static: [0xCD; 48],
            encrypted_timestamp: [0xEF; 28],
            mac1: [0x11; 16],
            mac2: [0x22; 16],
        };

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), INITIALIZATION_MSG_SIZE);

        let decoded = MessageInitiation::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender_index, 0x12345678);
        assert_eq!(decoded.ephemeral, [0xAB; 32]);
        assert_eq!(decoded.mac1, [0x11; 16]);
        assert_eq!(decoded.mac2, [0x22; 16]);
    }

    #[test]
    fn test_session_keys_debug_redacts_keys() {
        let keys = SessionKeys::new([0xAB; 32], [0xCD; 32]);

        let debug = format!("{keys:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains(&hex::encode(keys.send_key)));
        assert!(!debug.contains(&hex::encode(keys.recv_key)));
        assert!(debug.contains("send_counter"));
        assert!(debug.contains("recv_counter"));
    }

    #[test]
    fn test_response_roundtrip() {
        let msg = MessageResponse {
            sender_index: 0xAAAAAAAA,
            receiver_index: 0xBBBBBBBB,
            ephemeral: [0x42; 32],
            encrypted_empty: [0x99; 16],
            mac1: [0x33; 16],
            mac2: [0x44; 16],
        };

        let bytes = msg.to_bytes();
        assert_eq!(bytes.len(), RESPONSE_MSG_SIZE);

        let decoded = MessageResponse::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.sender_index, 0xAAAAAAAA);
        assert_eq!(decoded.receiver_index, 0xBBBBBBBB);
        assert_eq!(decoded.ephemeral, [0x42; 32]);
    }

    #[test]
    fn test_fixed_handshake_messages_reject_trailing_bytes() {
        let init = MessageInitiation {
            sender_index: 0x12345678,
            ephemeral: [0xAB; 32],
            encrypted_static: [0xCD; 48],
            encrypted_timestamp: [0xEF; 28],
            mac1: [0x11; 16],
            mac2: [0x22; 16],
        };
        let mut init_bytes = init.to_bytes();
        init_bytes.push(0xFF);
        assert!(matches!(
            MessageInitiation::from_bytes(&init_bytes),
            Err(WireGuardError::InvalidPacket(_))
        ));

        let response = MessageResponse {
            sender_index: 0xAAAAAAAA,
            receiver_index: 0xBBBBBBBB,
            ephemeral: [0x42; 32],
            encrypted_empty: [0x99; 16],
            mac1: [0x33; 16],
            mac2: [0x44; 16],
        };
        let mut response_bytes = response.to_bytes();
        response_bytes.push(0xFF);
        assert!(matches!(
            MessageResponse::from_bytes(&response_bytes),
            Err(WireGuardError::InvalidPacket(_))
        ));
    }

    #[test]
    fn test_fixed_handshake_messages_reject_truncated_bytes() {
        let init_bytes = vec![TYPE_INITIALIZATION; INITIALIZATION_MSG_SIZE - 1];
        assert!(matches!(
            MessageInitiation::from_bytes(&init_bytes),
            Err(WireGuardError::InvalidPacket(_))
        ));

        let response_bytes = vec![TYPE_RESPONSE; RESPONSE_MSG_SIZE - 1];
        assert!(matches!(
            MessageResponse::from_bytes(&response_bytes),
            Err(WireGuardError::InvalidPacket(_))
        ));
    }

    #[test]
    fn test_handshake_messages_reject_wrong_type() {
        let init = MessageInitiation {
            sender_index: 0x12345678,
            ephemeral: [0xAB; 32],
            encrypted_static: [0xCD; 48],
            encrypted_timestamp: [0xEF; 28],
            mac1: [0x11; 16],
            mac2: [0x22; 16],
        };
        let mut init_bytes = init.to_bytes();
        init_bytes[0] = TYPE_RESPONSE;
        assert!(matches!(
            MessageInitiation::from_bytes(&init_bytes),
            Err(WireGuardError::InvalidMessageType(TYPE_RESPONSE))
        ));

        let response = MessageResponse {
            sender_index: 0xAAAAAAAA,
            receiver_index: 0xBBBBBBBB,
            ephemeral: [0x42; 32],
            encrypted_empty: [0x99; 16],
            mac1: [0x33; 16],
            mac2: [0x44; 16],
        };
        let mut response_bytes = response.to_bytes();
        response_bytes[0] = TYPE_INITIALIZATION;
        assert!(matches!(
            MessageResponse::from_bytes(&response_bytes),
            Err(WireGuardError::InvalidMessageType(TYPE_INITIALIZATION))
        ));
    }

    #[test]
    fn handshake_messages_reject_reserved_bytes_and_zero_indices() {
        let initiation = MessageInitiation {
            sender_index: 7,
            ephemeral: [1; 32],
            encrypted_static: [2; 48],
            encrypted_timestamp: [3; 28],
            mac1: [4; 16],
            mac2: [0; 16],
        };
        let mut reserved = initiation.to_bytes();
        reserved[2] = 1;
        assert!(matches!(
            MessageInitiation::from_bytes(&reserved),
            Err(WireGuardError::InvalidPacket(_))
        ));
        let mut zero_index = initiation.to_bytes();
        zero_index[4..8].fill(0);
        assert!(matches!(
            MessageInitiation::from_bytes(&zero_index),
            Err(WireGuardError::InvalidPacket(_))
        ));

        let response = MessageResponse {
            sender_index: 8,
            receiver_index: 7,
            ephemeral: [5; 32],
            encrypted_empty: [6; 16],
            mac1: [7; 16],
            mac2: [0; 16],
        };
        let mut reserved = response.to_bytes();
        reserved[1] = 1;
        assert!(matches!(
            MessageResponse::from_bytes(&reserved),
            Err(WireGuardError::InvalidPacket(_))
        ));
        let mut zero_index = response.to_bytes();
        zero_index[8..12].fill(0);
        assert!(matches!(
            MessageResponse::from_bytes(&zero_index),
            Err(WireGuardError::InvalidPacket(_))
        ));
    }

    #[test]
    fn test_transport_roundtrip() {
        let payload = vec![
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE,
            0xBA, 0xBE,
        ];
        let msg = MessageTransport {
            receiver_index: 0xCAFEBABE,
            counter: 42,
            encrypted_payload: payload.clone(),
        };

        let bytes = msg.to_bytes();
        let decoded = MessageTransport::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.receiver_index, 0xCAFEBABE);
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.encrypted_payload, payload);
    }

    #[test]
    fn test_message_type_detection() {
        let init = MessageInitiation {
            sender_index: 0,
            ephemeral: [0; 32],
            encrypted_static: [0; 48],
            encrypted_timestamp: [0; 28],
            mac1: [0; 16],
            mac2: [0; 16],
        };
        assert_eq!(message_type(&init.to_bytes()), Some(TYPE_INITIALIZATION));

        let resp = MessageResponse {
            sender_index: 0,
            receiver_index: 0,
            ephemeral: [0; 32],
            encrypted_empty: [0; 16],
            mac1: [0; 16],
            mac2: [0; 16],
        };
        assert_eq!(message_type(&resp.to_bytes()), Some(TYPE_RESPONSE));
    }
}
