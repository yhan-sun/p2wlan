use p2pnet_nat::engine::{
    check_udp_reachability, select_best_candidate_group_pair, CompactFrame, CompactSession,
    FrameKind, Lane, NatKind, PunchMetrics, PunchPacer, PunchProfile, PunchSettings, PunchTarget,
    UdpReachability, FRAME_SIZE,
};
use p2pnet_nat::{
    candidate_report_from_observations, candidate_report_from_unordered_observations,
    StunAttribute, StunMessage, StunObservation, BINDING_RESPONSE,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{net::UdpSocket, time::Instant};

fn addr(port: u16) -> SocketAddr {
    ([127, 0, 0, 1], port).into()
}

fn observed(ports: &[u16]) -> Vec<StunObservation> {
    ports
        .iter()
        .enumerate()
        .map(|(i, &port)| {
            StunObservation::reply(
                ([192, 0, 2, 1 + i as u8], 3478).into(),
                Some(([198, 51, 100, 10], port).into()),
                Duration::from_millis(5),
            )
        })
        .collect()
}

fn classified(ports: &[u16]) -> PunchProfile {
    PunchProfile::from_primary(
        &candidate_report_from_observations(addr(5000), false, observed(ports)).nat_profile,
    )
    .unwrap()
}

#[test]
fn ordered_primary_observations_and_last_valid_port() {
    assert_eq!(classified(&[1001, 1001]).nat_type, NatKind::Cone);
    let open = candidate_report_from_observations(
        ([198, 51, 100, 10], 1234).into(),
        false,
        observed(&[1234, 1234]),
    );
    assert_eq!(
        PunchProfile::from_primary(&open.nat_profile)
            .unwrap()
            .nat_type,
        NatKind::None
    );
    for (ports, step) in [
        (&[4000, 4003, 4006][..], 3),
        (&[4006, 4003, 4000], -3),
        (&[65533, 65535, 1], 2),
    ] {
        let profile = classified(ports);
        assert_eq!(profile.nat_type, NatKind::LinearSymmetric);
        assert_eq!(profile.port_step, step);
        assert_eq!(profile.port_hint, *ports.last().unwrap());
        assert!(profile.valid());
    }
    for ports in [
        &[9000][..],
        &[3200, 3199],
        &[5000, 5001, 5003],
        &[3000, 9000, 2000, 8000],
    ] {
        let profile = classified(ports);
        assert_eq!(profile.nat_type, NatKind::RandomSymmetric);
        assert_eq!(profile.port_step, 0);
        assert_eq!(profile.port_hint, *ports.last().unwrap());
    }
    let mut obs = observed(&[5000, 5003, 5006, 41000, 99]);
    obs[3].server = obs[0].server.clone();
    obs[4].error = Some("timeout".into());
    let sample = candidate_report_from_observations(addr(1000), false, obs);
    let profile = PunchProfile::from_primary(&sample.nat_profile).unwrap();
    assert_eq!(profile.nat_type, NatKind::RandomSymmetric);
    assert_eq!(profile.port_hint, 41000);
    let unordered = candidate_report_from_unordered_observations(
        addr(5000),
        false,
        observed(&[3000, 3004, 3008]),
    );
    assert_eq!(
        PunchProfile::from_primary(&unordered.nat_profile)
            .unwrap()
            .nat_type,
        NatKind::RandomSymmetric
    );
    assert!(PunchProfile::from_primary(
        &candidate_report_from_observations(addr(5000), false, vec![]).nat_profile
    )
    .is_none());
}

#[test]
fn directional_matrix_and_role_order_are_symmetric() {
    use NatKind::*;
    let groups = [None, Cone, LinearSymmetric, RandomSymmetric].map(|kind| PunchProfile {
        nat_type: kind,
        port_hint: 4000,
        port_step: if kind == LinearSymmetric { 1 } else { 0 },
        ..Default::default()
    });
    let expected = [[0, 0, 0, 0], [0, 1, 2, 4], [0, 3, 6, 7], [0, 5, 8, 9]];
    for (i, a) in groups.iter().enumerate() {
        for (j, b) in groups.iter().enumerate() {
            let from_a = select_best_candidate_group_pair(
                "alpha",
                std::slice::from_ref(a),
                "beta",
                std::slice::from_ref(b),
            )
            .unwrap();
            let from_b = select_best_candidate_group_pair(
                "beta",
                std::slice::from_ref(b),
                "alpha",
                std::slice::from_ref(a),
            )
            .unwrap();
            assert_eq!((from_a.mode, from_a.role), (expected[i][j], 0));
            assert_eq!((from_b.mode, from_b.role), (expected[j][i], 1));
        }
    }
    let a = [groups[2].clone(), groups[1].clone()];
    let b = [groups[3].clone(), groups[2].clone()];
    let ab = select_best_candidate_group_pair("a", &a, "b", &b).unwrap();
    let ba = select_best_candidate_group_pair("b", &b, "a", &a).unwrap();
    assert_eq!((ab.local_group, ab.remote_group), (1, 1));
    assert_eq!(
        (ab.local_group, ab.remote_group),
        (ba.remote_group, ba.local_group)
    );
    assert!(select_best_candidate_group_pair("b", &a, "b", &b).is_none());
    assert!(select_best_candidate_group_pair("a", &[], "b", &b).is_none());
    let mut mapped = groups[3].clone();
    mapped.upnp_mapped_addr = Some(addr(4000));
    assert_eq!(mapped.effective_kind(), Cone);
}

#[test]
fn compact_frame_peer_session_direction_and_wire_integrity() {
    let a = CompactSession::new(&[7; 32], "room:abcd", "a", "b").unwrap();
    let b = CompactSession::new(&[7; 32], "room:abcd", "b", "a").unwrap();
    let frame = CompactFrame {
        kind: FrameKind::Request,
        nominate: true,
        epoch: 0x12345678,
        nonce: 0x01020304,
    };
    let packet = a.encode(frame);
    assert_eq!(a.id, b.id);
    assert_eq!(packet.len(), FRAME_SIZE);
    assert_eq!(FRAME_SIZE, 36);
    assert_eq!(CompactFrame::session_hint(&packet), Some(b.id));
    assert_eq!(b.decode(&packet), Some(frame));
    assert_eq!(a.decode(&packet), None);
    assert_eq!(frame.correlation(), [0x12, 0x34, 0x56, 0x78, 1, 2, 3, 4]);
    assert!(CompactSession::new(&[7; 32], "", "a", "b").is_none());
    assert!(CompactSession::new(&[7; 32], "room", "a", "a").is_none());
    for other in [
        CompactSession::new(&[8; 32], "room:abcd", "b", "a"),
        CompactSession::new(&[7; 32], "room:abce", "b", "a"),
        CompactSession::new(&[7; 32], "room:abcd", "c", "a"),
    ] {
        assert!(other.unwrap().decode(&packet).is_none());
    }
    for i in 0..FRAME_SIZE {
        let mut forged = packet;
        forged[i] ^= 1;
        assert!(b.decode(&forged).is_none(), "modified byte {i}");
        assert!(b.decode(&packet[..i]).is_none(), "length {i}");
    }
    let reply = CompactFrame {
        kind: FrameKind::Response,
        nominate: false,
        ..frame
    };
    assert_eq!(a.decode(&b.encode(reply)), Some(reply));
    assert!(b
        .decode(&a.encode(CompactFrame {
            nominate: true,
            ..reply
        }))
        .is_none());
    assert!(a.decode(&[0; 37]).is_none());
    assert_eq!(
        packet.map(|byte| format!("{byte:02x}")).concat(),
        "50330101000192c46c6a91b61234567801020304ebbdfffb3b979f970b7b6c3e2e7428fb"
    );
}

#[tokio::test(start_paused = true)]
async fn pacer_limits_actual_udp_datagrams_in_a_sliding_second() {
    let receiver = UdpSocket::bind(addr(0)).await.unwrap();
    let sender = UdpSocket::bind(addr(0)).await.unwrap();
    sender
        .connect(receiver.local_addr().unwrap())
        .await
        .unwrap();
    sender.writable().await.unwrap();
    for budget in [0u16, 1, 7, 80, 200, 999] {
        let pacer = PunchPacer::new(17, budget);
        for port in 1..=600 {
            let lane = if port % 2 == 0 {
                Lane::Regular
            } else {
                Lane::Predicted
            };
            let target = PunchTarget {
                address: addr(port),
                socket: 0,
            };
            let admitted = pacer.enqueue(17, lane, target);
            assert_eq!(admitted, port <= 512 && budget != 0);
            assert!(!pacer.enqueue(17, lane, target));
        }
        let before = pacer.metrics(0);
        assert_eq!(
            before.queue_a_len + before.queue_b_len,
            if budget == 0 { 0 } else { 512 }
        );
        let mut peak = 0;
        let mut physical = 0;
        let mut lane_counts = [0, 0];
        for _ in 0..100 {
            for (lane, target) in pacer.tick(17, Instant::now()).into_iter().enumerate() {
                if target.is_some() {
                    pacer.try_send(17, || sender.try_send(&[42])).unwrap();
                    let mut buf = [0; 1];
                    assert_eq!(receiver.recv(&mut buf).await.unwrap(), 1);
                    assert_eq!(buf, [42]);
                    physical += 1;
                    lane_counts[lane] += 1;
                }
            }
            peak = peak.max(pacer.metrics(0).actual_pps);
            tokio::time::advance(pacer.interval()).await;
        }
        eprintln!("UDP pacer budget={budget} peak={peak} packets={physical}");
        assert!(peak <= usize::from(budget.min(200)));
        if budget != 0 {
            assert!(lane_counts.iter().all(|n| *n > 0));
            assert!(peak > 0);
        }
        if budget >= 200 {
            assert_eq!(peak, 200);
        }
        assert_eq!(pacer.clear_punch_state(), Some(18));
        assert_eq!(pacer.tick(17, Instant::now()), [None, None]);
        assert_eq!(
            pacer.try_send(17, || Ok(1)).unwrap_err().kind(),
            std::io::ErrorKind::Interrupted
        );
        assert_eq!(pacer.metrics(0).queue_a_len, 0);
        assert_eq!(pacer.metrics(0).queue_b_len, 0);
        assert!(!pacer.enqueue(
            17,
            Lane::Regular,
            PunchTarget {
                address: addr(1),
                socket: 0
            }
        ));
    }
}

#[tokio::test]
async fn connected_firewall_probe_checks_stun_transaction() {
    let live = UdpSocket::bind(addr(0)).await.unwrap();
    let live_addr = live.local_addr().unwrap();
    let silent = UdpSocket::bind(addr(0)).await.unwrap();
    let silent_addr = silent.local_addr().unwrap();
    let service = tokio::spawn(async move {
        let mut buf = [0; 1024];
        let (size, client) = live.recv_from(&mut buf).await.unwrap();
        let req = StunMessage::decode(&buf[..size]).unwrap();
        let mut response = StunMessage::with_transaction_id(BINDING_RESPONSE, req.transaction_id);
        response.add_attribute(StunAttribute::XorMappedAddress(client));
        live.send_to(&response.encode(), client).await.unwrap();
    });
    let window = Duration::from_millis(100);
    assert_eq!(
        check_udp_reachability(&[], None, window).await,
        UdpReachability::Unknown
    );
    assert_eq!(
        check_udp_reachability(&[silent_addr, live_addr], None, window).await,
        UdpReachability::Available
    );
    service.await.unwrap();
    assert_eq!(
        check_udp_reachability(&[silent_addr], None, window).await,
        UdpReachability::Blocked
    );
}

#[test]
fn json_contract_shared_with_go_and_legacy_defaults() {
    let signal: serde_json::Value = serde_json::from_str(include_str!(
        "../../../contracts/fixtures/negotiated_signal.json"
    ))
    .unwrap();
    let profile: PunchProfile = serde_json::from_value(signal["nat_profile"].clone()).unwrap();
    assert!(profile.valid());
    assert_eq!(profile.port_step, -4);
    assert_eq!(profile.tcp_candidates.len(), 2);
    assert_eq!(
        serde_json::to_value(profile).unwrap(),
        signal["nat_profile"]
    );
    let legacy: PunchProfile = serde_json::from_str("{}").unwrap();
    assert_eq!(legacy, PunchProfile::default());
    let old_metrics: PunchMetrics = serde_json::from_str("{}").unwrap();
    assert_eq!(old_metrics.punch_epoch, 0);
    let partial_metrics: PunchMetrics = serde_json::from_str(r#"{"actual_pps":7}"#).unwrap();
    assert_eq!(partial_metrics.actual_pps, 7);
    assert_eq!(partial_metrics.active_punch_sockets, 0);
    let settings: PunchSettings = serde_json::from_str("{}").unwrap();
    assert_eq!(settings.max_punch_pps, 200);
    assert_eq!(settings.max_punch_sockets, 24);
    assert_eq!(settings.linear_scan_count, 50);
    assert!(!settings.disable_sym_hole_punching);
    assert!(!settings.lazy_p2p);
    assert!(settings.firewall_probe_addresses.is_empty());
}
