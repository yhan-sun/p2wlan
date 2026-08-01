/// Compute standard CRC-32 (same polynomial as Ethernet/PNG/zlib).
///
/// Test vector: `crc32(b"123456789") == 0xCBF43926`
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Compute the STUN FINGERPRINT value for the given message bytes.
///
/// FINGERPRINT = CRC-32(message) XOR 0x5354554E
pub fn compute_fingerprint(data: &[u8]) -> u32 {
    crc32(data) ^ FINGERPRINT_XOR
}

// ============================================================
// Attribute Encoding/Decoding Helpers
// ============================================================

/// Encode a SocketAddr as XOR-MAPPED-ADDRESS attribute value.
pub fn encode_xor_mapped_address(addr: SocketAddr, transaction_id: &[u8; 12]) -> Vec<u8> {
    let port = addr.port();
    let x_port = port ^ ((MAGIC_COOKIE >> 16) as u16);

    let mut buf = Vec::new();
    buf.push(0x00); // Reserved

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            buf.push(FAMILY_IPV4);
            buf.extend_from_slice(&x_port.to_be_bytes());
            let octets = ipv4.octets();
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                buf.push(octets[i] ^ cookie[i]);
            }
        }
        IpAddr::V6(ipv6) => {
            buf.push(FAMILY_IPV6);
            buf.extend_from_slice(&x_port.to_be_bytes());
            let octets = ipv6.octets();
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE_BYTES);
            key[4..].copy_from_slice(transaction_id);
            for i in 0..16 {
                buf.push(octets[i] ^ key[i]);
            }
        }
    }
    buf
}

/// Decode an XOR-MAPPED-ADDRESS attribute value.
pub fn decode_xor_mapped_address(data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(NatError::InvalidAttribute(format!(
            "XOR-MAPPED-ADDRESS too short: {} bytes",
            data.len()
        )));
    }

    let family = data[1];
    let x_port = u16::from_be_bytes([data[2], data[3]]);
    let port = x_port ^ ((MAGIC_COOKIE >> 16) as u16);

    match family {
        FAMILY_IPV4 => {
            if data.len() < 8 {
                return Err(NatError::InvalidAttribute(
                    "XOR-MAPPED-ADDRESS IPv4 too short".into(),
                ));
            }
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let octets = [
                data[4] ^ cookie[0],
                data[5] ^ cookie[1],
                data[6] ^ cookie[2],
                data[7] ^ cookie[3],
            ];
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            if data.len() < 20 {
                return Err(NatError::InvalidAttribute(
                    "XOR-MAPPED-ADDRESS IPv6 too short".into(),
                ));
            }
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE_BYTES);
            key[4..].copy_from_slice(transaction_id);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = data[4 + i] ^ key[i];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(NatError::InvalidAttribute(format!(
            "unknown family: {family}"
        ))),
    }
}

/// Encode a SocketAddr as MAPPED-ADDRESS attribute value.
pub fn encode_mapped_address(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x00); // Reserved

    match addr.ip() {
        IpAddr::V4(ipv4) => {
            buf.push(FAMILY_IPV4);
            buf.extend_from_slice(&addr.port().to_be_bytes());
            buf.extend_from_slice(&ipv4.octets());
        }
        IpAddr::V6(ipv6) => {
            buf.push(FAMILY_IPV6);
            buf.extend_from_slice(&addr.port().to_be_bytes());
            buf.extend_from_slice(&ipv6.octets());
        }
    }
    buf
}

/// Decode a MAPPED-ADDRESS attribute value.
pub fn decode_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(NatError::InvalidAttribute(format!(
            "MAPPED-ADDRESS too short: {} bytes",
            data.len()
        )));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        FAMILY_IPV4 => {
            if data.len() < 8 {
                return Err(NatError::InvalidAttribute(
                    "MAPPED-ADDRESS IPv4 too short".into(),
                ));
            }
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        FAMILY_IPV6 => {
            if data.len() < 20 {
                return Err(NatError::InvalidAttribute(
                    "MAPPED-ADDRESS IPv6 too short".into(),
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&data[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(NatError::InvalidAttribute(format!(
            "unknown family: {family}"
        ))),
    }
}

// ============================================================
// StunAttribute
// ============================================================
