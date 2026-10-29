use super::*;

fn adapter(name: &str, luid: u64, address: &str) -> WindowsAdapter {
    WindowsAdapter {
        name: name.into(),
        luid,
        up: true,
        tunnel: false,
        network_id: "network-a".into(),
        ipv4_metric: 20,
        ipv6_metric: 30,
        addresses: vec![(address.parse().unwrap(), 24)],
    }
}

fn route(luid: u64, index: u32, gateway: &str) -> WindowsDefaultRoute {
    WindowsDefaultRoute {
        luid,
        index,
        next_hop: gateway.parse().unwrap(),
        scope: 0,
        metric: 10,
    }
}

#[test]
fn windows_signature_is_stable_across_adapter_route_and_address_order() {
    let mut adapters = vec![
        adapter("Ethernet", 1, "192.0.2.2"),
        adapter("Wi-Fi", 2, "198.51.100.2"),
    ];
    adapters[0]
        .addresses
        .push(("2001:db8::2".parse().unwrap(), 64));
    let mut routes = vec![
        route(1, 4, "192.0.2.1"),
        route(1, 4, "fe80::1"),
        route(2, 5, "198.51.100.1"),
    ];
    let original = windows_signature(&adapters, &routes, &[]);
    assert!(
        !original.is_empty(),
        "Windows must provide a handover baseline"
    );
    adapters[0].addresses.reverse();
    adapters.reverse();
    routes.reverse();
    routes.push(routes[0].clone());
    assert_eq!(windows_signature(&adapters, &routes, &[]), original);
}

#[test]
fn windows_signature_tracks_default_selection_between_existing_up_adapters() {
    let adapters = vec![
        adapter("Ethernet", 1, "192.0.2.2"),
        adapter("Wi-Fi", 2, "198.51.100.2"),
    ];
    let before = vec![route(1, 4, "192.0.2.1"), route(2, 5, "198.51.100.1")];
    let baseline = windows_signature(&adapters, &before, &[]);
    let mut routes = before.clone();
    routes[1].metric = 1;
    assert_ne!(windows_signature(&adapters, &routes, &[]), baseline);
    let mut changed = adapters.clone();
    changed[1].ipv4_metric = 1;
    assert_ne!(windows_signature(&changed, &before, &[]), baseline);
    assert_ne!(windows_signature(&adapters, &before[1..], &[]), baseline);
}

#[test]
fn windows_signature_tracks_source_prefix_gateway_and_network_changes() {
    let adapters = vec![adapter("Wi-Fi", 1, "192.0.2.2")];
    let routes = vec![route(1, 4, "192.0.2.1")];
    let baseline = windows_signature(&adapters, &routes, &[]);
    let mut changed = adapters.clone();
    changed[0].addresses[0].0 = "192.0.2.3".parse().unwrap();
    assert_ne!(windows_signature(&changed, &routes, &[]), baseline);
    let mut changed = adapters.clone();
    changed[0].addresses[0].1 = 25;
    assert_ne!(windows_signature(&changed, &routes, &[]), baseline);
    let mut changed = adapters.clone();
    changed[0].network_id = "network-b".into();
    assert_ne!(windows_signature(&changed, &routes, &[]), baseline);
    let mut changed = routes.clone();
    changed[0].next_hop = "192.0.2.254".parse().unwrap();
    assert_ne!(windows_signature(&adapters, &changed, &[]), baseline);
}

#[test]
fn windows_ipv6_only_route_tracks_scope_and_interface_metric() {
    let mut adapters = vec![adapter("Wi-Fi", 1, "2001:db8::2")];
    adapters[0].addresses[0].1 = 64;
    let mut routes = vec![route(1, 4, "fe80::1")];
    routes[0].scope = 4;
    let baseline = windows_signature(&adapters, &routes, &[]);
    assert!(!baseline.is_empty());
    adapters[0].ipv6_metric += 10;
    assert_ne!(windows_signature(&adapters, &routes, &[]), baseline);
    adapters[0].ipv6_metric -= 10;
    routes[0].scope = 5;
    assert_ne!(windows_signature(&adapters, &routes, &[]), baseline);
}

#[test]
fn windows_tunnel_overlay_down_and_unrouted_adapters_do_not_change_signature() {
    let mut adapters = vec![adapter("Ethernet", 1, "192.0.2.2")];
    let mut routes = vec![route(1, 4, "192.0.2.1")];
    let baseline = windows_signature(&adapters, &routes, &[]);
    adapters.push(adapter("P2WLAN-room", 2, "10.0.0.2"));
    adapters.push(adapter("Tunnel with custom alias", 3, "10.1.0.2"));
    adapters[2].tunnel = true;
    adapters.push(adapter("Unused Ethernet", 4, "198.51.100.2"));
    adapters.push(adapter("Disconnected Ethernet", 5, "203.0.113.2"));
    adapters[4].up = false;
    adapters.push(adapter("Owned overlay with custom alias", 6, "10.2.0.2"));
    for luid in [2, 3, 5, 6] {
        routes.push(route(luid, luid as u32, "10.0.0.1"));
    }
    assert_eq!(
        windows_signature(
            &adapters,
            &routes,
            &["Owned overlay with custom alias".into()]
        ),
        baseline,
    );
}

#[test]
fn unix_address_change_on_same_interface_and_gateway_changes_signature() {
    let sample = |address: &str, prefix| {
        let mut signature = vec!["physical:en0:192.0.2.1".into()];
        append_relevant_address(
            &mut signature,
            &["en0"],
            &[],
            "en0",
            address.parse().unwrap(),
            prefix,
        );
        signature
    };
    assert_ne!(sample("192.0.2.2", 24), sample("192.0.2.3", 24));
    assert_ne!(sample("192.0.2.2", 24), sample("192.0.2.2", 25));
    assert_ne!(sample("2001:db8::2", 64), sample("2001:db8::3", 64));
}

#[test]
fn unix_ignores_unrelated_and_virtual_interface_addresses() {
    let mut signature = Vec::new();
    let relevant = ["en0", "utun1", "p2wlan0", "tap0", "veth0", "custom-overlay"];
    for name in ["en1", "utun1", "p2wlan0", "tap0", "veth0", "custom-overlay"] {
        append_relevant_address(
            &mut signature,
            &relevant,
            &["custom-overlay".into()],
            name,
            "192.0.2.2".parse().unwrap(),
            24,
        );
    }
    assert!(signature.is_empty());
    append_relevant_address(
        &mut signature,
        &relevant,
        &[],
        "en0",
        "192.0.2.2".parse().unwrap(),
        24,
    );
    assert_eq!(signature, ["address:en0:192.0.2.2/24"]);
}

#[test]
fn invalid_addresses_are_not_physical_identity() {
    for (address, prefix) in [
        ("0.0.0.0", 0),
        ("127.0.0.1", 8),
        ("224.0.0.1", 4),
        ("::", 0),
        ("::1", 128),
        ("ff02::1", 16),
        ("192.0.2.2", 33),
        ("2001:db8::2", 129),
    ] {
        assert!(address_entry("interface", address.parse().unwrap(), prefix).is_none());
    }
}

#[test]
fn ipv6_only_observation_provides_baseline_and_tracks_its_addresses() {
    let mut signature = Vec::new();
    let interface = append_ipv6_default(
        &mut signature,
        Some(("en0".into(), Some("fe80::1%en0".into()))),
        &[],
    )
    .unwrap();
    append_relevant_address(
        &mut signature,
        &[&interface],
        &[],
        &interface,
        "2001:db8::2".parse().unwrap(),
        64,
    );
    assert_eq!(
        signature,
        ["default6:en0:fe80::1%en0", "address:en0:2001:db8::2/64"]
    );
    assert_eq!(
        append_ipv6_default(
            &mut signature,
            Some(("utun9".into(), Some("fe80::1%utun9".into()))),
            &[]
        ),
        None
    );
    assert_eq!(signature.len(), 2);
}

#[test]
fn ppp_upstreams_are_observed_without_changing_socket_binding_policy() {
    assert!(physical_interface("ppp0", &[]));
    assert!(super::super::is_virtual_interface_name("ppp0"));
    let adapters = vec![adapter("ppp0", 1, "192.0.2.2")];
    assert!(!windows_signature(&adapters, &[route(1, 4, "192.0.2.1")], &[]).is_empty());
    let mut signature = Vec::new();
    append_relevant_address(
        &mut signature,
        &["ppp0"],
        &[],
        "ppp0",
        "192.0.2.2".parse().unwrap(),
        32,
    );
    assert_eq!(signature, ["address:ppp0:192.0.2.2/32"]);
}
