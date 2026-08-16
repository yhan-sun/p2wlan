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
/// Render the peer's `nat_type` fingerprint hint for the doctor output.
///
/// The `p2:` / `p2v2:` label carries the remote's structured NAT behavior
/// (mapping / allocation / filtering / hairpin).  We surface it as space-
/// separated `key=value` tokens so `f=address_or_port_dependent` and
/// `h=unsupported` are readable at a glance, plus the same scatter verdict the
/// daemon acts on (`scatter==yes/no`) — that verdict comes from
/// `p2pnet_daemon::peer::scatter_decision`, the single source of truth, so the
/// display never drifts from the actual port-scatter behavior.  Legacy labels
/// (`p2:`, no `f=`/`h=`) simply show fewer columns.
pub(crate) fn peer_nat_hint_summary(peer: &Value) -> Option<String> {
    let raw = peer.get("nat_type").and_then(Value::as_str)?;
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let body = raw
        .strip_prefix("p2v2:")
        .or_else(|| raw.strip_prefix("p2:"))
        .unwrap_or(raw)
        .replace(';', " ");
    let scatter = if p2pnet_daemon::peer::scatter_decision(raw) {
        "yes"
    } else {
        "no"
    };
    Some(format!("nat={body} scatter={scatter}"))
}
fn short_text(value: &str, max_len: usize) -> String {
    if value.chars().count() <= max_len {
        value.to_string()
    } else {
        format!("{}...", value.chars().take(max_len).collect::<String>())
    }
}
