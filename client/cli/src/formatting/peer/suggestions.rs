pub(crate) fn peer_direct_suggestions(snapshot: &Value) -> Vec<String> {
    let Some(peers) = snapshot.get("peers").and_then(Value::as_array) else {
        return Vec::new();
    };

    let mut private_only_peers = Vec::new();
    let mut generation_changed_peers = Vec::new();
    let mut handshake_timeout_peers = Vec::new();
    let mut direct_send_failed_peers = Vec::new();
    let mut public_without_open_ingress_peers = Vec::new();
    let mut generic_direct_failures = 0_u64;
    for peer in peers {
        let direct_error_code = direct_error_code(peer);
        let has_direct_error = direct_failure_stage(peer).is_some();
        if has_direct_error && matches!(direct_error_code, Some("direct_probe_failed") | None) {
            generic_direct_failures += 1;
        }
        match direct_error_code {
            Some("network_generation_changed") => {
                generation_changed_peers.push(peer_display_name(peer))
            }
            Some("handshake_timeout") => handshake_timeout_peers.push(peer_display_name(peer)),
            Some("direct_send_failed") => direct_send_failed_peers.push(peer_display_name(peer)),
            _ => {}
        }

        let endpoints = peer_diagnostic_endpoints(peer);
        if endpoints.is_empty() {
            continue;
        }
        let has_public_endpoint = endpoints.iter().any(is_public_udp_endpoint);
        let has_private_or_local_endpoint = endpoints
            .iter()
            .any(|endpoint| is_private_or_local_ip(endpoint.ip()));
        if has_direct_error && !has_public_endpoint && has_private_or_local_endpoint {
            private_only_peers.push(peer_display_name(peer));
        } else if has_direct_error
            && has_public_endpoint
            && peer_has_only_stun_like_public_candidates(peer)
        {
            public_without_open_ingress_peers.push(peer_display_name(peer));
        }
    }

    let mut suggestions = Vec::new();
    if !generation_changed_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 的 Direct 状态来自旧网络代际，已切回 Relay；等待新的 UDP candidate/ACK 后会自动重新选择直连。",
            generation_changed_peers.join("、")
        ));
    }
    if !handshake_timeout_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} UDP 探测后 WireGuard 握手超时；通常是单向 UDP、防火墙状态表或对端会话未及时刷新。",
            handshake_timeout_peers.join("、")
        ));
    }
    if !direct_send_failed_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 的 Direct 发送失败，daemon 已降级 Relay；请重点查看网络切换、防火墙和 UDP endpoint 是否漂移。",
            direct_send_failed_peers.join("、")
        ));
    }
    if !private_only_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 只上报了私网/回环 UDP 候选；请在对应设备配置 udp-advertise <公网IP>:<端口>，并放行同一个 UDP 入站端口。",
            private_only_peers.join("、")
        ));
    } else if !public_without_open_ingress_peers.is_empty() {
        suggestions.push(format!(
            "对端 {} 有公网候选但 Direct 仍失败；公网 STUN 映射稳定不代表 NAT 过滤开放。请优先在较友好的一侧启用 UPnP/PCP/NAT-PMP 或手动 UDP 端口转发，让困难 NAT 设备能把第一包打进去。",
            public_without_open_ingress_peers.join("、")
        ));
    } else if generic_direct_failures > 0 {
        suggestions.push(
            "检测到 Direct UDP 探测失败；请确认两端 udp-bind/udp-advertise、云安全组和系统防火墙使用同一个 UDP 端口。"
                .to_string(),
        );
    }
    suggestions
}
fn peer_has_only_stun_like_public_candidates(peer: &Value) -> bool {
    let Some(pairs) = peer.get("candidate_pairs").and_then(Value::as_array) else {
        return false;
    };
    let mut saw_public = false;
    for pair in pairs {
        let Some(endpoint) = pair
            .get("remote_endpoint")
            .and_then(Value::as_str)
            .and_then(|endpoint| endpoint.parse::<SocketAddr>().ok())
        else {
            continue;
        };
        if !is_public_udp_endpoint(&endpoint) {
            continue;
        }
        saw_public = true;
        let source = pair
            .get("remote_candidate_type")
            .or_else(|| pair.get("remote_source"))
            .or_else(|| pair.get("source"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if matches!(
            source,
            "upnp" | "pcp" | "nat_pmp" | "nat-pmp" | "port_mapping" | "peer_reflexive" | "learned"
        ) {
            return false;
        }
    }
    saw_public
}
