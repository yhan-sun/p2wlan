fn peer_diagnostic_endpoints(peer: &Value) -> Vec<SocketAddr> {
    let mut endpoints = Vec::new();
    if let Some(endpoint) = peer.get("endpoint").and_then(Value::as_str) {
        push_socket_addr(&mut endpoints, endpoint);
    }
    for candidate in peer_candidate_strings(peer) {
        push_socket_addr(&mut endpoints, &candidate);
    }
    endpoints
}
pub(crate) fn peer_candidate_strings(peer: &Value) -> Vec<String> {
    peer.get("candidates")
        .and_then(Value::as_array)
        .map(|candidates| {
            candidates
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}
fn push_socket_addr(endpoints: &mut Vec<SocketAddr>, value: &str) {
    if let Ok(endpoint) = value.parse::<SocketAddr>() {
        if !endpoints.contains(&endpoint) {
            endpoints.push(endpoint);
        }
    }
}
pub(crate) fn is_public_udp_endpoint(endpoint: &SocketAddr) -> bool {
    endpoint.port() != 0 && !is_private_or_local_ip(endpoint.ip())
}
fn is_private_or_local_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_unspecified()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            ip.is_loopback()
                || ip.is_unspecified()
                || (segments[0] & 0xfe00) == 0xfc00
                || (segments[0] & 0xffc0) == 0xfe80
        }
    }
}
fn peer_display_name(peer: &Value) -> String {
    let node_id = peer
        .get("node_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let name = peer
        .get("device_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(node_id);
    let virtual_ip = peer
        .get("virtual_ip")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    format!("{}({})", short_text(name, 18), virtual_ip)
}
pub(crate) fn endpoint_preview(endpoints: &[String], max_items: usize) -> String {
    if endpoints.is_empty() {
        return String::new();
    }
    let preview = endpoints
        .iter()
        .take(max_items)
        .map(|endpoint| short_text(endpoint, 32))
        .collect::<Vec<_>>()
        .join(",");
    if endpoints.len() > max_items {
        format!(" [{}…]", preview)
    } else {
        format!(" [{preview}]")
    }
}
fn short_text(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!("{}...", value.chars().take(max_len).collect::<String>())
    }
}
