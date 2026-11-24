use super::*;

fn tcp_checksum(packet: &[u8], tcp_start: usize) -> u16 {
    let tcp = &packet[tcp_start..];
    let mut pseudo = Vec::new();
    if packet[0] >> 4 == 4 {
        pseudo.extend_from_slice(&packet[12..20]);
        pseudo.extend_from_slice(&[0, 6]);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    } else {
        pseudo.extend_from_slice(&packet[8..40]);
        pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 6]);
    }
    pseudo.extend_from_slice(tcp);
    let checksum = pseudo.len() - tcp.len() + 16;
    pseudo[checksum..checksum + 2].fill(0);
    super::super::compute_checksum(&pseudo)
}

fn syn(tcp_start: usize, flags: u8, options: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; tcp_start + 20 + options.len()];
    let len = packet.len();
    if tcp_start < 40 {
        packet[0] = 0x40 | (tcp_start / 4) as u8;
        packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..20].copy_from_slice(&[10, 1, 0, 1, 10, 1, 0, 2]);
    } else {
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
        packet[6] = if tcp_start == 40 { 6 } else { 60 };
        packet[7] = 64;
        packet[8] = 0xfd;
        packet[23] = 1;
        packet[24] = 0xfd;
        packet[39] = 2;
        if tcp_start != 40 {
            packet[40] = 6;
        }
    }
    let tcp = &mut packet[tcp_start..];
    tcp[..4].copy_from_slice(&[4, 0, 1, 0xbb]);
    tcp[12] = (((options.len() + 20) / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
    tcp[20..].copy_from_slice(options);
    let checksum = tcp_checksum(&packet, tcp_start);
    packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&checksum.to_be_bytes());
    packet
}

#[test]
fn clamping_matches_independent_checksum_for_both_families_and_alignments() {
    for start in [20, 24, 40, 48] {
        for flags in [0x02, 0x12] {
            for odd in [false, true] {
                let options = if odd {
                    [1, 2, 4, 0x05, 0xb4, 3, 3, 7]
                } else {
                    [2, 4, 0x05, 0xb4, 3, 3, 7, 0]
                };
                // Vary an independent header word to exercise end-around carry.
                for window in [0, 1, 255, 32768, 65534, 65535] {
                    let mut packet = syn(start, flags, &options);
                    packet[start + 14..start + 16].copy_from_slice(&u16::to_be_bytes(window));
                    let original = tcp_checksum(&packet, start);
                    packet[start + 16..start + 18].copy_from_slice(&original.to_be_bytes());
                    assert_eq!(traffic_class(&packet), TrafficClass::Control);
                    assert!(clamp_tcp_mss(&mut packet, 1340));
                    let mss = start + 22 + usize::from(odd);
                    let expected = (1340 - start - 28) as u16;
                    assert_eq!(&packet[mss..mss + 2], &expected.to_be_bytes());
                    let independent = tcp_checksum(&packet, start);
                    assert_eq!(&packet[start + 16..start + 18], &independent.to_be_bytes());
                    let unchanged = packet.clone();
                    assert!(!clamp_tcp_mss(&mut packet, 1340));
                    assert_eq!(packet, unchanged);
                }
            }
        }
    }
}

#[test]
fn clamp_leaves_ineligible_or_malformed_packets_untouched() {
    for mut packet in [
        syn(20, 0x10, &[2, 4, 0x05, 0xb4]),
        syn(40, 0x02, &[2, 3, 0x05, 0xb4]),
        syn(20, 0x02, &[2, 4, 0x05, 0xb4, 2, 4, 0x05, 0xb4]),
        syn(20, 0x02, &[2, 4, 0x03, 0x20]),
    ] {
        let before = packet.clone();
        assert!(!clamp_tcp_mss(&mut packet, 1340));
        assert_eq!(before, packet);
    }
    let mut fragment = syn(20, 0x02, &[2, 4, 0x05, 0xb4]);
    fragment[6] |= 0x20;
    assert!(!clamp_tcp_mss(&mut fragment, 1340));
}
