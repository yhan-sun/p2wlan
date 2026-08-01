#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_packet_parsing() {
        // Build a test packet
        let src = Ipv4Addr::new(10, 20, 0, 1);
        let dst = Ipv4Addr::new(10, 20, 0, 2);
        let packet_data = Ipv4Packet::build_icmp_echo_request(src, dst, 0x1234, 1, b"hello");

        // Parse it back
        let parsed = Ipv4Packet::new(&packet_data).unwrap();

        assert_eq!(parsed.version(), 4);
        assert_eq!(parsed.header_len(), 20);
        assert_eq!(parsed.total_len(), packet_data.len() as u16);
        assert_eq!(parsed.protocol(), Protocol::Icmp);
        assert_eq!(parsed.src_addr(), src);
        assert_eq!(parsed.dst_addr(), dst);
        assert_eq!(parsed.ttl(), 64);
        assert!(parsed.verify_checksum());
    }

    #[test]
    fn test_ip_packet_dispatch() {
        let src = Ipv4Addr::new(10, 20, 0, 1);
        let dst = Ipv4Addr::new(10, 20, 0, 2);
        let packet_data = Ipv4Packet::build_icmp_echo_request(src, dst, 0x1234, 1, b"test");

        let packet = IpPacket::new(&packet_data).unwrap();

        assert_eq!(packet.version(), 4);
        assert_eq!(packet.protocol(), Protocol::Icmp);
        assert_eq!(packet.src_addr_string(), "10.20.0.1");
        assert_eq!(packet.dst_addr_string(), "10.20.0.2");
    }

    #[test]
    fn test_protocol_from_u8() {
        assert_eq!(Protocol::from(1), Protocol::Icmp);
        assert_eq!(Protocol::from(6), Protocol::Tcp);
        assert_eq!(Protocol::from(17), Protocol::Udp);
        assert_eq!(Protocol::from(99), Protocol::Unknown);
    }

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Icmp.to_string(), "ICMP");
    }

    #[test]
    fn test_packet_too_short() {
        let short_buf = [0x45, 0x00, 0x00];
        assert!(Ipv4Packet::new(&short_buf).is_err());
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = vec![0xFF; 20];
        buf[0] = 0x70; // version 7
        assert!(IpPacket::new(&buf).is_err());
    }

    #[test]
    fn test_empty_buffer() {
        assert!(IpPacket::new(&[]).is_err());
    }

    #[test]
    fn test_checksum_verification() {
        let packet = Ipv4Packet::build_icmp_echo_request(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            0x1234,
            1,
            b"data",
        );
        let parsed = Ipv4Packet::new(&packet).unwrap();
        assert!(parsed.verify_checksum());

        // Corrupt a byte and check that checksum fails
        let mut corrupted = packet.clone();
        corrupted[10] ^= 0xFF;
        let parsed_corrupt = Ipv4Packet::new(&corrupted).unwrap();
        assert!(!parsed_corrupt.verify_checksum());
    }

    #[test]
    fn test_ipv6_packet_parsing() {
        // Build a minimal IPv6 packet
        let mut buf = vec![0u8; 48];

        // version=6, traffic_class=0, flow_label=0
        buf[0] = 0x60;
        // payload length = 8
        buf[4] = 0x00;
        buf[5] = 0x08;
        // next header = UDP (17)
        buf[6] = 17;
        // hop limit = 64
        buf[7] = 64;

        // src addr: fd00::1 (16 bytes at offset 8-23)
        buf[8] = 0xfd;
        buf[9] = 0x00;
        buf[23] = 0x01; // last byte of src addr

        // dst addr: fd00::2 (16 bytes at offset 24-39)
        buf[24] = 0xfd;
        buf[25] = 0x00;
        buf[39] = 0x02; // last byte of dst addr

        // 8 bytes of payload
        buf[40..48].fill(0xAA);

        let parsed = Ipv6Packet::new(&buf).unwrap();
        assert_eq!(parsed.version(), 6);
        assert_eq!(parsed.header_len(), 40);
        assert_eq!(parsed.payload_len(), 8);
        assert_eq!(parsed.total_len(), 48);
        assert_eq!(parsed.next_header(), 17);
        assert_eq!(parsed.hop_limit(), 64);
        assert_eq!(parsed.protocol(), Protocol::Udp);
        assert_eq!(
            parsed.src_addr(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
        );
        assert_eq!(
            parsed.dst_addr(),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)
        );
        assert_eq!(parsed.payload().len(), 8);
    }

    #[test]
    fn test_fragment_detection() {
        let src = Ipv4Addr::new(10, 20, 0, 1);
        let dst = Ipv4Addr::new(10, 20, 0, 2);
        let packet_data = Ipv4Packet::build_icmp_echo_request(src, dst, 0x1234, 1, b"hello");

        let parsed = Ipv4Packet::new(&packet_data).unwrap();
        // DF flag is set by our builder
        assert!(parsed.dont_fragment());
        assert!(!parsed.is_fragment());
    }
}
