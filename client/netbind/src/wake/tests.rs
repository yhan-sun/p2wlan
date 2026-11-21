use super::*;

const MAC: &str = "02:11:22:33:44:50";

#[test]
fn magic_packet_has_the_sync_header_and_sixteen_copies_of_the_mac() {
    let address = MAC.parse().unwrap();
    let packet = magic_packet(address);
    assert_eq!(&packet[..6], &[0xff; 6]);
    let (addresses, _) = packet[6..].as_chunks::<6>();
    for copy in addresses {
        assert_eq!(copy, &[0x02, 0x11, 0x22, 0x33, 0x44, 0x50]);
    }
}

#[test]
fn normalizes_unicast_and_rejects_invalid_mac_addresses() {
    for valid in ["02:11:22:33:44:50", "02-11-22-33-44-50", "021122334450"] {
        let address = valid.parse::<MacAddress>().unwrap();
        assert_eq!(address.to_string(), MAC);
        assert!(!format!("{address:?}").contains(MAC));
    }
    assert_eq!(
        "AA:BB:CC:DD:EE:FE"
            .parse::<MacAddress>()
            .unwrap()
            .to_string(),
        "aa:bb:cc:dd:ee:fe"
    );
    for invalid in [
        "",
        "00:00:00:00:00:00",
        "ff:ff:ff:ff:ff:ff",
        "01:00:5e:00:00:01",
        "02-11:22-33-44-50",
        "02:11:22:33:44:GG",
        "02:11:22:33:44",
        "⓪②①①②②③③④④⑤⓪",
    ] {
        assert_eq!(invalid.parse::<MacAddress>(), Err(InvalidMacAddress));
    }
}

#[test]
fn computes_a_directed_broadcast_and_rejects_nonbroadcast_links() {
    let ip = Ipv4Addr::new(192, 0, 2, 65);
    assert_eq!(
        directed_broadcast(ip, Ipv4Addr::new(255, 255, 255, 192)),
        Some(Ipv4Addr::new(192, 0, 2, 127))
    );
    for mask in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(255, 255, 255, 254),
        Ipv4Addr::new(255, 255, 0, 255),
    ] {
        assert_eq!(directed_broadcast(ip, mask), None);
    }
    assert_eq!(
        directed_broadcast(Ipv4Addr::LOCALHOST, Ipv4Addr::new(255, 0, 0, 0)),
        None
    );
    assert_eq!(directed_broadcast(ip, Ipv4Addr::new(128, 0, 0, 0)), None);
}

#[test]
fn identifies_loopback_and_virtual_link_names_without_rejecting_openwrt_lan() {
    for name in [
        "lo",
        "lo0",
        "utun1",
        "tun123",
        "tap0",
        "docker0",
        "br-8e8f12a455ab",
        "veth789",
        "p2wlan0",
        "p2r123abcd",
        "Wintun",
    ] {
        assert!(excluded_interface(name));
    }
    for name in ["br-lan", "eth0", "Ethernet"] {
        assert!(!excluded_interface(name));
    }
}

#[test]
fn selects_one_source_per_interface_and_broadcast() {
    let first = LanInterface {
        name: "br-lan".to_string(),
        ipv4: Ipv4Addr::new(192, 0, 2, 1),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        broadcast: Ipv4Addr::new(192, 0, 2, 255),
        mac: MAC.parse().unwrap(),
        wired: true,
    };
    let mut alias = first.clone();
    alias.ipv4 = Ipv4Addr::new(192, 0, 2, 2);
    let mut overlay = first.clone();
    overlay.name = "custom-overlay".to_string();
    let interfaces = [first, alias, overlay];
    assert_eq!(distinct_broadcasts(&interfaces, None, "").count(), 2);
    assert_eq!(
        distinct_broadcasts(&interfaces, None, "custom-overlay").count(),
        1
    );
    assert_eq!(
        distinct_broadcasts(&interfaces, Some("br-lan"), "").count(),
        1
    );
    assert_eq!(distinct_broadcasts(&interfaces, Some(""), "").count(), 0);
}

#[tokio::test]
async fn empty_lan_selection_returns_a_typed_error() {
    assert_eq!(
        send_to_lans(MAC.parse().unwrap(), std::iter::empty()).await,
        Err(WakeSendError::NoLanInterface)
    );
}

#[cfg(all(target_os = "linux", not(target_env = "ohos")))]
#[tokio::test]
async fn wake_rejects_loopback_but_can_pin_a_new_udp_socket() {
    // This covers the socket operation separately from LAN eligibility and
    // uses loopback without transmitting any packets.
    let source = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0);
    assert!(crate::bind_udp(source.into(), Some("lo")).await.is_ok());
    assert_eq!(
        send_magic_packet(MAC.parse().unwrap(), Some("lo")).await,
        Err(WakeSendError::NoLanInterface),
    );
}
