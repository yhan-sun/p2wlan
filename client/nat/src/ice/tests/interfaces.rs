#[test]
fn test_priority_ordering() {
    let host_pri = compute_priority(CandidateType::Host);
    let srflx_pri = compute_priority(CandidateType::ServerReflexive);
    let prflx_pri = compute_priority(CandidateType::PeerReflexive);
    let relay_pri = compute_priority(CandidateType::Relay);

    assert!(host_pri > prflx_pri);
    assert!(prflx_pri > srflx_pri);
    assert!(srflx_pri > relay_pri);

    // Check exact values (RFC 8445 §6.1.2.3: the last term is 256 - component_id,
    // not component_id).
    assert_eq!(
        host_pri,
        (1 << 24) * PREF_HOST + (1 << 8) * LOCAL_PREF + (256 - COMPONENT_ID)
    );
    assert_eq!(
        srflx_pri,
        (1 << 24) * PREF_SERVER_REFLEXIVE + (1 << 8) * LOCAL_PREF + (256 - COMPONENT_ID)
    );
}

#[test]
fn priority_uses_rfc_component_term_not_bare_component_id() {
    // The RFC 8445 priority formula's final term is (256 - component_id).  The
    // historical code used component_id directly, which inverted the term.  With
    // component_id = 1 the correct term is 255, so every priority is offset by
    // (255 - 1) = 254 above the bare-component-id value — a fixed offset that
    // preserves relative ordering (higher component_id must still rank LOWER).
    let host = compute_priority(CandidateType::Host);
    assert_eq!(
        host,
        (1u32 << 24) * PREF_HOST + (1u32 << 8) * LOCAL_PREF + (256 - COMPONENT_ID),
        "component term must be (256 - COMPONENT_ID), got {host}"
    );
    assert_eq!(
        (host - (1u32 << 24) * PREF_HOST - (1u32 << 8) * LOCAL_PREF),
        256 - COMPONENT_ID,
        "the low-order component term must be 255 (256 - 1)"
    );
}

#[test]
fn test_gather_local_addresses() {
    let addrs = gather_local_addresses();
    assert!(!addrs.iter().any(IpAddr::is_loopback));

    let unique: std::collections::HashSet<_> = addrs.iter().copied().collect();
    assert_eq!(unique.len(), addrs.len());
}

#[test]
fn local_network_matches_only_same_prefix_and_address_family() {
    let network = LocalNetwork::new("192.168.31.10".parse().unwrap(), 24);
    assert!(network.contains("192.168.31.20".parse().unwrap()));
    assert!(!network.contains("192.168.32.20".parse().unwrap()));
    assert!(!network.contains("fd00::20".parse().unwrap()));
}

#[test]
fn local_network_does_not_treat_overlay_ranges_as_on_link_without_a_matching_interface() {
    let physical = LocalNetwork::new("192.168.31.10".parse().unwrap(), 24);
    assert!(!physical.contains("10.20.0.13".parse().unwrap()));
    assert!(!physical.contains("100.64.0.13".parse().unwrap()));
    assert!(!physical.contains("fd12:3456::13".parse().unwrap()));
}

#[test]
fn route_probe_cannot_reintroduce_filtered_vpn_address() {
    let physical = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4));
    let vpn = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2));
    let selected = select_local_addresses(
        &[("en0".to_string(), physical), ("utun6".to_string(), vpn)],
        &[vpn, physical],
    );
    assert_eq!(selected, vec![physical]);
}

#[test]
fn route_probe_is_used_only_when_interface_enumeration_failed() {
    let fallback = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4));
    assert_eq!(select_local_addresses(&[], &[fallback]), vec![fallback]);

    let vpn = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2));
    assert!(select_local_addresses(&[("utun6".to_string(), vpn)], &[vpn]).is_empty());
}

#[test]
fn overlay_utun_addresses_are_filtered_from_host_candidates() {
    let tailscale_v4 = IpAddr::V4(Ipv4Addr::new(100, 84, 190, 40));
    let tailscale_v6 = IpAddr::V6("fd7a:115c:a1e0::e136:be29".parse().unwrap());
    let p2wlan_overlay = IpAddr::V4(Ipv4Addr::new(10, 20, 0, 13));
    let generic_vpn = IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2));

    let selected = select_local_addresses(
        &[
            ("utun4".to_string(), tailscale_v4),
            ("utun4".to_string(), tailscale_v6),
            ("utun5".to_string(), p2wlan_overlay),
            ("utun6".to_string(), generic_vpn),
        ],
        &[],
    );

    assert!(!selected.contains(&tailscale_v4));
    assert!(!selected.contains(&tailscale_v6));
    assert!(!selected.contains(&p2wlan_overlay));
    assert!(!selected.contains(&generic_vpn));
}

#[test]
fn test_candidate_host_ip_filter() {
    assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
    assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
        127, 0, 0, 1
    ))));
    assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
        169, 254, 1, 2
    ))));
    assert!(!is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
        224, 0, 0, 1
    ))));
    assert!(!is_candidate_host_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    assert!(!is_candidate_host_ip(IpAddr::V6(
        "fe80::1".parse().unwrap()
    )));
    assert!(is_candidate_host_ip(IpAddr::V4(Ipv4Addr::new(
        192, 168, 2, 4
    ))));
}

#[test]
fn test_candidate_interface_name_filter() {
    assert!(is_candidate_interface_name("en0"));
    assert!(is_candidate_interface_name("Ethernet"));
    assert!(is_candidate_interface_name("Wi-Fi"));

    for name in [
        "lo0", "utun6", "tun0", "tap0", "wg0", "p2pnet0", "p2wlan", "wintun", "docker0", "br-123",
        "vethabc", "llw0", "awdl0",
    ] {
        assert!(!is_candidate_interface_name(name), "{name}");
    }
}

#[test]
fn test_push_unique_keeps_first_address() {
    let mut addrs = Vec::new();
    push_unique(&mut addrs, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4)));
    push_unique(&mut addrs, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4)));
    push_unique(&mut addrs, IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)));
    assert_eq!(
        addrs,
        vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 4)),
            IpAddr::V4(Ipv4Addr::new(172, 18, 0, 1)),
        ]
    );
}
