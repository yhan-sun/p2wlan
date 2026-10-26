//! Production admission with a real held mutex; no fabricated KernelRead.
use super::super::control_lock::ControlState;
use super::*;
use std::cell::Cell;

fn bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|p| u32::from(p[0]) * 256 + u32::from(p.get(1).copied().unwrap_or(0)))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[test]
fn nonbusiness_and_unparseable_packets_do_not_enter_held_original_registry() {
    let state = ControlState::new(());
    let held = state.try_lock().unwrap();
    let enters = Cell::new(0);
    let mut nonbusiness = crate::build_udp_overlay_packet(
        "10.21.1.2",
        "10.21.1.3",
        32123,
        43210,
        b"ordinary application data",
    )
    .unwrap();
    let sum = checksum(&nonbusiness[..20]);
    nonbusiness[10..12].copy_from_slice(&sum.to_be_bytes());
    // An IPv4 port-unreachable packet quotes the original IP/UDP headers.
    // Both complete checksums are valid; the capture protocols still reject it.
    let mut icmp = vec![0u8; 56];
    icmp[0] = 0x45;
    icmp[2..4].copy_from_slice(&56u16.to_be_bytes());
    icmp[8] = 64;
    icmp[9] = 1;
    icmp[12..16].copy_from_slice(&[10, 21, 1, 2]);
    icmp[16..20].copy_from_slice(&[10, 21, 1, 3]);
    icmp[20] = 3;
    icmp[21] = 3;
    icmp[28..].copy_from_slice(&nonbusiness[..28]);
    let sum = checksum(&icmp[20..]);
    icmp[22..24].copy_from_slice(&sum.to_be_bytes());
    let sum = checksum(&icmp[..20]);
    icmp[10..12].copy_from_slice(&sum.to_be_bytes());
    assert_eq!(checksum(&icmp[..20]), 0);
    assert_eq!(checksum(&icmp[20..]), 0);
    for packet in [icmp.as_slice(), nonbusiness.as_slice(), &[], &[0x45, 0]] {
        let result: Result<Option<()>, CaptureFailure> = capture(packet, |_, _| {
            enters.set(enters.get() + 1);
            let _actual = state
                .try_original_read_lock(16)
                .map_err(|_| CaptureFailure::Contended)?;
            Err(CaptureFailure::InvalidPlan)
        });
        assert!(matches!(result, Ok(None)));
    }
    assert_eq!(enters.get(), 0);
    assert!(state.original_read_refusal_snapshot().is_none());
    drop(held);
    assert!(state.try_lock().is_ok());
}

#[test]
fn original_tcp_vectors_still_enter_real_busy_registry_once_each() {
    let document: serde_json::Value = serde_json::from_str(include_str!(
        "../../../business_evidence/tcp_frame/tool_vectors.json"
    ))
    .unwrap();
    let rows = document["vectors"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    let state = ControlState::new(());
    let held = state.try_lock().unwrap();
    let enters = Cell::new(0);
    for row in rows {
        let packet = bytes(row["ipv4_packet"].as_str().unwrap());
        let result: Result<Option<()>, CaptureFailure> = capture(&packet, |udp, tcp| {
            assert!(udp.is_none());
            assert!(tcp.is_some());
            enters.set(enters.get() + 1);
            let _actual = state
                .try_original_read_lock(1)
                .map_err(|_| CaptureFailure::Contended)?;
            Ok(Some(()))
        });
        assert!(matches!(result, Err(CaptureFailure::Contended)));
    }
    assert_eq!(enters.get(), 4);
    assert!(state.original_read_refusal_snapshot().is_some());
    drop(held);
}

#[test]
fn registered_udp_keeps_the_actual_single_try_and_original_refusal() {
    let mut body = vec![0xa5; 63 + 128];
    body[..8].copy_from_slice(b"P2WUDE1\0");
    body[8] = 0;
    body[9..25].fill(0x33);
    body[25..41].fill(0x44);
    body[41..45].copy_from_slice(&0u32.to_be_bytes());
    body[45..61].fill(0x55);
    body[61..63].copy_from_slice(&128u16.to_be_bytes());
    let mut packet =
        crate::build_udp_overlay_packet("10.21.1.2", "10.21.1.3", 32123, 43210, &body).unwrap();
    let sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    assert!(parse_os_udp(&packet).is_ok());
    let state = ControlState::new(());
    let held = state.try_lock().unwrap();
    let enters = Cell::new(0);
    let result: Result<Option<()>, CaptureFailure> = capture(&packet, |udp, tcp| {
        assert_eq!(udp.unwrap().key.request_nonce, [0x55; 16]);
        assert!(tcp.is_none());
        enters.set(enters.get() + 1);
        let _actual = state
            .try_original_read_lock(1)
            .map_err(|_| CaptureFailure::Contended)?;
        Ok(Some(()))
    });
    assert!(matches!(result, Err(CaptureFailure::Contended)));
    assert_eq!(enters.get(), 1);
    assert!(state.original_read_refusal_snapshot().is_some());
    drop(held);
}
