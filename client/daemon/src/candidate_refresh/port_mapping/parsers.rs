pub(super) fn parse_nat_pmp_public_address_response(response: &[u8]) -> Option<Ipv4Addr> {
    if response.len() < 12 || response[0] != 0 || response[1] != 128 {
        return None;
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        debug!("NAT-PMP public address request failed with result code {result}");
        return None;
    }
    Some(Ipv4Addr::new(
        response[8],
        response[9],
        response[10],
        response[11],
    ))
}

pub(super) fn parse_nat_pmp_mapping_response(
    response: &[u8],
    expected_internal_port: u16,
) -> Option<u16> {
    if response.len() < 16 || response[0] != 0 || response[1] != 129 {
        return None;
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        debug!("NAT-PMP UDP mapping failed with result code {result}");
        return None;
    }
    let internal_port = u16::from_be_bytes([response[8], response[9]]);
    if internal_port != expected_internal_port {
        return None;
    }
    let external_port = u16::from_be_bytes([response[10], response[11]]);
    (external_port > 0).then_some(external_port)
}

pub(super) fn parse_pcp_mapping_response(
    response: &[u8],
    expected_internal_port: u16,
) -> Option<SocketAddr> {
    if response.len() < 60 || response[0] != 2 || response[1] != 0x81 {
        return None;
    }
    let result = response[3];
    if result != 0 {
        debug!("PCP UDP mapping failed with result code {result}");
        return None;
    }
    if response[36] != 17 {
        return None;
    }
    let internal_port = u16::from_be_bytes([response[40], response[41]]);
    if internal_port != expected_internal_port {
        return None;
    }
    let external_port = u16::from_be_bytes([response[42], response[43]]);
    if external_port == 0 {
        return None;
    }
    let external_ip = parse_pcp_ip_address(&response[44..60])?;
    Some(SocketAddr::new(external_ip, external_port))
}

fn parse_pcp_ip_address(bytes: &[u8]) -> Option<IpAddr> {
    let bytes: [u8; 16] = bytes.try_into().ok()?;
    if bytes[..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
        return Some(IpAddr::V4(Ipv4Addr::new(
            bytes[12], bytes[13], bytes[14], bytes[15],
        )));
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

pub(super) fn ipv4_mapped_octets(ip: Ipv4Addr) -> [u8; 16] {
    let mut octets = [0u8; 16];
    octets[10] = 0xff;
    octets[11] = 0xff;
    octets[12..16].copy_from_slice(&ip.octets());
    octets
}
