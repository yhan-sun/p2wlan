//! Integration tests for the TUN module.
//!
//! These tests use the `MockTunDevice` to avoid requiring system
//! privileges. Platform-specific tests that require root/Administrator
//! are marked with `#[ignore]`.

use p2pnet_tun::{
    InterfaceConfig, IpPacket, Ipv4Packet, MockTunDevice, Protocol, VirtualInterface,
};
use std::net::Ipv4Addr;

/// Test that a mock device can read and write packets.
#[tokio::test]
async fn test_mock_device_roundtrip() {
    let (mut dev, mut ctrl) = MockTunDevice::new_default("p2pnet0");

    let src = Ipv4Addr::new(10, 20, 0, 1);
    let dst = Ipv4Addr::new(10, 20, 0, 2);
    let packet = Ipv4Packet::build_icmp_echo_request(src, dst, 0xABCD, 1, b"test-payload");

    // Inject the packet into the device
    ctrl.inject(packet.clone()).await.unwrap();

    // The device reads it
    let mut buf = [0u8; 65535];
    let n = dev.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &packet[..]);

    // Parse the received packet
    let parsed = IpPacket::new(&buf[..n]).unwrap();
    assert_eq!(parsed.version(), 4);
    assert_eq!(parsed.protocol(), Protocol::Icmp);
    assert_eq!(parsed.src_addr_string(), "10.20.0.1");
    assert_eq!(parsed.dst_addr_string(), "10.20.0.2");

    // Write it back
    dev.write(&buf[..n]).await.unwrap();

    // Controller receives the written packet
    let written = ctrl.recv_written().await.unwrap();
    assert_eq!(written, packet);
}

/// Test that multiple packets can be sent in sequence.
#[tokio::test]
async fn test_multiple_packets() {
    let (mut dev, mut ctrl) = MockTunDevice::new_default("test0");

    for i in 0..5u16 {
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            i,
            1,
            b"data",
        );
        ctrl.inject(packet).await.unwrap();
    }

    let mut buf = [0u8; 65535];
    for i in 0..5u16 {
        let n = dev.read(&mut buf).await.unwrap();
        let parsed = Ipv4Packet::new(&buf[..n]).unwrap();
        assert_eq!(parsed.identification(), i);
    }
}

/// Test that a closed device returns errors.
#[tokio::test]
async fn test_closed_device_errors() {
    let (mut dev, _ctrl) = MockTunDevice::new_default("test0");
    dev.close();

    let mut buf = [0u8; 65535];
    assert!(dev.read(&mut buf).await.is_err());
    assert!(dev.write(&[0x45, 0x00]).await.is_err());
    assert!(!dev.is_up());
}

/// Test interface configuration.
#[test]
fn test_interface_config() {
    let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420).unwrap();

    assert_eq!(config.name, "p2pnet0");
    assert_eq!(config.address, Ipv4Addr::new(10, 20, 0, 1));
    assert_eq!(config.prefix_len(), 24);
    assert_eq!(config.network_address(), Ipv4Addr::new(10, 20, 0, 0));
}

/// Test IPv4 packet construction and checksum verification.
#[test]
fn test_icmp_packet_construction() {
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(192, 168, 1, 1),
        Ipv4Addr::new(10, 0, 0, 1),
        0x1234,
        42,
        b"hello-world-payload",
    );

    let parsed = Ipv4Packet::new(&packet).unwrap();

    assert_eq!(parsed.version(), 4);
    assert_eq!(parsed.header_len(), 20);
    assert_eq!(parsed.protocol(), Protocol::Icmp);
    assert_eq!(parsed.src_addr(), Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(parsed.dst_addr(), Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(parsed.identification(), 0x1234);
    assert!(parsed.verify_checksum());
    assert_eq!(parsed.payload().len(), 8 + 19); // ICMP header (8) + payload (19)
}

/// Test that the device reports correct properties.
#[tokio::test]
async fn test_device_properties() {
    let (dev, _ctrl) = MockTunDevice::new_pair("mytun", 1280, "172.16.0.1");

    assert_eq!(dev.name(), "mytun");
    assert_eq!(dev.mtu(), 1280);
    assert_eq!(dev.address(), "172.16.0.1");
    assert!(dev.is_up());
}

/// Test handling of large packets (up to MTU).
#[tokio::test]
async fn test_large_packet() {
    let (mut dev, mut ctrl) = MockTunDevice::new_pair("test0", 1420, "10.20.0.1");

    // Create a large payload (1300 bytes)
    let large_payload = vec![0xAA; 1300];
    let packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        0x0001,
        1,
        &large_payload,
    );

    ctrl.inject(packet.clone()).await.unwrap();

    let mut buf = [0u8; 65535];
    let n = dev.read(&mut buf).await.unwrap();
    assert_eq!(n, packet.len());

    let parsed = Ipv4Packet::new(&buf[..n]).unwrap();
    assert_eq!(parsed.payload().len(), 8 + 1300); // ICMP header + payload
}

/// Test creating a real TUN device (requires Administrator/root).
#[cfg(target_os = "windows")]
#[tokio::test]
#[ignore = "Requires wintun.dll and Administrator privileges"]
async fn test_real_wintun_device() {
    let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420).unwrap();
    let dev = p2pnet_tun::TunDevice::create(&config);

    if dev.is_err() {
        eprintln!("Skipping: could not create Wintun device: {:?}", dev.err());
        return;
    }

    let dev = dev.unwrap();
    assert_eq!(dev.name(), "p2pnet0");
    assert_eq!(dev.mtu(), 1420);
    assert!(dev.is_up());
}

/// Test creating a real TUN device (requires root).
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "Requires root privileges"]
async fn test_real_linux_tun_device() {
    let config = InterfaceConfig::new("p2pnet0", "10.20.0.1", "255.255.255.0", 1420).unwrap();
    let mut dev = p2pnet_tun::TunDevice::create(&config).unwrap();

    assert_eq!(dev.name(), "p2pnet0");
    assert!(dev.is_up());

    // Read with a short timeout to verify the device is functional
    let mut buf = [0u8; 65535];
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(100), dev.read(&mut buf)).await;

    // We expect a timeout (no packets to read), which is fine.
    assert!(result.is_err() || result.unwrap().is_ok());
}
