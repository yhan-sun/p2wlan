fn socket_pool_is_eligible(report: &CandidateGatherReport) -> bool {
    report.nat_profile.mapping_behavior == MappingBehavior::AddressOrPortDependent
        && !report.nat_profile.udp_blocked
}

fn pool_stun_servers(
    stun_servers: &[SocketAddr],
    local_addr: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let Some(local_addr) = local_addr else {
        return Vec::new();
    };
    stun_servers
        .iter()
        .copied()
        .filter(|server| server.is_ipv4() == local_addr.is_ipv4())
        .take(SOCKET_POOL_STUN_OBSERVERS_PER_SOCKET)
        .collect()
}

fn is_ignorable_udp_receive_error(error: &std::io::Error) -> bool {
    #[cfg(target_os = "windows")]
    {
        error.raw_os_error() == Some(10054) || error.kind() == std::io::ErrorKind::ConnectionReset
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = error;
        false
    }
}

fn is_authenticated_punch_candidate(data: &[u8]) -> bool {
    data.len() >= 5 && data.starts_with(&[0x50, 0x4e, 0x43, 0x48]) && data[4] == 2
}

fn stun_transaction_id(data: &[u8]) -> Option<StunTransactionId> {
    if data.len() < 20 || data[0] & 0xc0 != 0 {
        return None;
    }
    if u32::from_be_bytes(data[4..8].try_into().ok()?) != MAGIC_COOKIE {
        return None;
    }
    let declared_len = u16::from_be_bytes(data[2..4].try_into().ok()?) as usize;
    if data.len() < 20 + declared_len {
        return None;
    }
    data[8..20].try_into().ok()
}
