use super::*;

    #[test]
    fn test_crc32_known_vector() {
        // Standard CRC-32 test vector
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_crc32_empty() {
        assert_eq!(crc32(b""), 0x00000000);
    }

    #[test]
    fn test_fingerprint_xor() {
        // FINGERPRINT = CRC-32 XOR 0x5354554E
        let data = b"test message";
        let expected = crc32(data) ^ 0x5354554E;
        assert_eq!(compute_fingerprint(data), expected);
    }

    #[test]
    fn test_xor_mapped_address_ipv4_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 5678);
        let txn_id = [0xAA; 12];

        let encoded = encode_xor_mapped_address(addr, &txn_id);
        let decoded = decode_xor_mapped_address(&encoded, &txn_id).unwrap();

        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_xor_mapped_address_ipv6_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 9999);
        let txn_id = [0xBB; 12];

        let encoded = encode_xor_mapped_address(addr, &txn_id);
        let decoded = decode_xor_mapped_address(&encoded, &txn_id).unwrap();

        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_mapped_address_ipv4_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 3478);
        let encoded = encode_mapped_address(addr);
        let decoded = decode_mapped_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_mapped_address_ipv6_roundtrip() {
        let addr = SocketAddr::new(IpAddr::V6("fe80::1".parse().unwrap()), 12345);
        let encoded = encode_mapped_address(addr);
        let decoded = decode_mapped_address(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_change_request_attribute() {
        let attr = StunAttribute::ChangeRequest {
            change_ip: true,
            change_port: true,
        };
        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        assert_eq!(attr_type, ATTR_CHANGE_REQUEST);
        assert_eq!(value, vec![0x00, 0x00, 0x00, 0x06]); // 0x04 | 0x02

        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();
        if let StunAttribute::ChangeRequest {
            change_ip,
            change_port,
        } = decoded
        {
            assert!(change_ip);
            assert!(change_port);
        } else {
            panic!("expected ChangeRequest");
        }
    }

    #[test]
    fn test_error_code_attribute() {
        let attr = StunAttribute::ErrorCode {
            code: 401,
            reason: "Unauthorized".to_string(),
        };
        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        assert_eq!(attr_type, ATTR_ERROR_CODE);
        assert_eq!(value[3], 4); // class
        assert_eq!(value[4], 1); // number

        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();
        if let StunAttribute::ErrorCode { code, reason } = decoded {
            assert_eq!(code, 401);
            assert_eq!(reason, "Unauthorized");
        } else {
            panic!("expected ErrorCode");
        }
    }

    #[test]
    fn test_software_attribute() {
        let attr = StunAttribute::Software("P2PNet STUN 1.0".to_string());
        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        assert_eq!(attr_type, ATTR_SOFTWARE);

        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();
        if let StunAttribute::Software(s) = decoded {
            assert_eq!(s, "P2PNet STUN 1.0");
        } else {
            panic!("expected Software");
        }
    }

    #[test]
    fn test_message_encode_decode_roundtrip() {
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("TestClient/1.0".to_string()));
        msg.add_attribute(StunAttribute::ChangeRequest {
            change_ip: false,
            change_port: true,
        });

        let encoded = msg.encode();
        assert_eq!(encoded.len() % 4, 0); // STUN messages are 4-byte aligned

        let decoded = StunMessage::decode(&encoded).unwrap();
        assert_eq!(decoded.msg_type, BINDING_REQUEST);
        assert_eq!(decoded.transaction_id, msg.transaction_id);
        assert_eq!(decoded.attributes.len(), 2);

        // Check attribute order
        assert!(matches!(decoded.attributes[0], StunAttribute::Software(_)));
        assert!(matches!(
            decoded.attributes[1],
            StunAttribute::ChangeRequest { .. }
        ));
    }

    #[test]
    fn test_message_with_xor_mapped_address() {
        let mut msg = StunMessage::with_transaction_id(BINDING_RESPONSE, [0x42; 12]);
        let reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), 43210);
        msg.add_attribute(StunAttribute::XorMappedAddress(reflexive));

        let encoded = msg.encode();
        let decoded = StunMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.get_reflexive_address(), Some(reflexive));
        assert!(decoded.is_binding_response());
    }

    #[test]
    fn test_message_with_fingerprint() {
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("FingerprintTest".to_string()));

        let encoded = msg.encode_with_fingerprint();

        // The encoded message should have FINGERPRINT as the last attribute
        let last_attr_type =
            u16::from_be_bytes([encoded[encoded.len() - 8], encoded[encoded.len() - 7]]);
        assert_eq!(last_attr_type, ATTR_FINGERPRINT);

        // Decode and verify fingerprint
        let decoded = StunMessage::decode(&encoded).unwrap();
        assert!(decoded.verify_fingerprint());
    }

    #[test]
    fn test_message_with_tampered_fingerprint() {
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("TamperTest".to_string()));

        let mut encoded = msg.encode_with_fingerprint();

        // Tamper with a byte in the middle
        encoded[25] ^= 0xFF;

        let decoded = StunMessage::decode(&encoded).unwrap();
        assert!(!decoded.verify_fingerprint());
    }

    #[test]
    fn test_invalid_magic_cookie() {
        let mut buf = vec![0x00, 0x01, 0x00, 0x00]; // type + length
        buf.extend_from_slice(&0xDEADBEEFu32.to_be_bytes()); // wrong cookie
        buf.extend_from_slice(&[0u8; 12]); // transaction ID

        let result = StunMessage::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_too_short() {
        let buf = vec![0x00, 0x01, 0x00];
        let result = StunMessage::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_reflexive_address_fallback() {
        // Test that MAPPED-ADDRESS is used when XOR-MAPPED-ADDRESS is absent
        let mut msg = StunMessage::new(BINDING_RESPONSE);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 1111);
        msg.add_attribute(StunAttribute::MappedAddress(addr));

        assert_eq!(msg.get_reflexive_address(), Some(addr));
        assert_eq!(msg.get_xor_mapped_address(), None);
    }

    #[test]
    fn test_get_error_code() {
        let mut msg = StunMessage::new(BINDING_ERROR_RESPONSE);
        msg.add_attribute(StunAttribute::ErrorCode {
            code: 300,
            reason: "Try Alternate".to_string(),
        });

        let (code, reason) = msg.get_error_code().unwrap();
        assert_eq!(code, 300);
        assert_eq!(reason, "Try Alternate");
        assert!(msg.is_error_response());
    }

    #[test]
    fn test_attribute_padding() {
        // Attribute with value length not multiple of 4
        let mut msg = StunMessage::binding_request();
        msg.add_attribute(StunAttribute::Software("abc".to_string())); // 3 bytes, needs 1 byte padding

        let encoded = msg.encode();
        let decoded = StunMessage::decode(&encoded).unwrap();

        assert_eq!(decoded.attributes.len(), 1);
        if let StunAttribute::Software(s) = &decoded.attributes[0] {
            assert_eq!(s, "abc");
        } else {
            panic!("expected Software attribute");
        }
    }

    #[test]
    fn test_other_attribute_roundtrip() {
        let raw_value = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x01];
        let attr = StunAttribute::Other {
            attr_type: 0x8000,
            value: raw_value.clone(),
        };

        let txn_id = [0; 12];
        let (attr_type, value) = attr.encode(&txn_id);
        let decoded = StunAttribute::decode(attr_type, &value, &txn_id).unwrap();

        if let StunAttribute::Other { attr_type, value } = decoded {
            assert_eq!(attr_type, 0x8000);
            assert_eq!(value, raw_value);
        } else {
            panic!("expected Other attribute");
        }
    }
