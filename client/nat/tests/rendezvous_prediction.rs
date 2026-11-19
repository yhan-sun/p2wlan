use p2pnet_nat::mapping::rendezvous::{
    bounded_prediction_window, fixed_step_rendezvous_order, fixed_step_rendezvous_targets,
    predict_for_rendezvous, RendezvousPredictionTiming,
};
use p2pnet_nat::mapping::{build_model, predict_ports, ModelRejection};
use std::net::SocketAddr;
use std::time::Duration;

fn timing(delay_ms: u64) -> RendezvousPredictionTiming {
    RendezvousPredictionTiming {
        measurement_span_ms: 100,
        last_measurement_send_at_ms: 200,
        now_ms: 210,
        send_delay_ms: delay_ms,
        max_send_delay_ms: 3_500,
        max_model_age: Duration::from_millis(2_500),
    }
}

#[test]
fn scheduled_gap_covers_busy_allocator_drift_without_changing_top_one() {
    let model = build_model(&[1000, 1001, 1002, 1006], None, 100);
    let immediate = predict_for_rendezvous(&model, 1006, timing(0), None, false).unwrap();
    let scheduled = predict_for_rendezvous(&model, 1006, timing(600), None, false).unwrap();
    assert_eq!(scheduled[0], immediate[0]);
    assert_eq!(scheduled.len(), 24);
    assert!(scheduled.len() > immediate.len());
    assert!(scheduled.iter().any(|candidate| candidate.port == 1030));
    assert!(!immediate.iter().any(|candidate| candidate.port == 1030));
}

#[test]
fn forecast_horizon_and_current_sample_freshness_are_separate() {
    let model = build_model(&[1000, 1001, 1002], None, 100);
    assert!(predict_for_rendezvous(&model, 1002, timing(3_500), None, false).is_ok());
    assert_eq!(
        predict_for_rendezvous(&model, 1002, timing(3_501), None, false),
        Err(ModelRejection::BatchStale)
    );
    let mut stale = timing(0);
    stale.now_ms = 2_601;
    assert_eq!(
        predict_for_rendezvous(&model, 1002, stale, None, false),
        Err(ModelRejection::BatchStale)
    );
    let mut invalid_clock = timing(0);
    invalid_clock.last_measurement_send_at_ms = invalid_clock.now_ms + 1;
    assert_eq!(
        predict_for_rendezvous(&model, 1002, invalid_clock, None, false),
        Err(ModelRejection::BatchStale)
    );
}

#[test]
fn immediate_clean_forecast_keeps_exact_existing_ranked_window() {
    for sequence in [[1000, 1001, 1002], [6000, 5998, 5996], [65530, 65533, 0]] {
        let model = build_model(&sequence, None, 100);
        assert_eq!(
            predict_for_rendezvous(&model, sequence[2], timing(0), None, false).unwrap(),
            predict_ports(&model, sequence[2])
        );
    }
}

#[test]
fn scheduled_clean_batch_keeps_ranked_prefix_and_covers_unobserved_drift() {
    for sequence in [
        [1000, 1001, 1002],
        [6000, 5998, 5996],
        [65525, 65528, 65531],
    ] {
        let model = build_model(&sequence, None, 100);
        let immediate = predict_ports(&model, sequence[2]);
        let scheduled =
            predict_for_rendezvous(&model, sequence[2], timing(3_500), None, false).unwrap();
        assert_eq!(&scheduled[..immediate.len()], immediate.as_slice());
        assert_eq!(scheduled.len(), p2pnet_nat::mapping::MAX_PREDICTED_PORTS);
        assert!(scheduled.iter().all(|candidate| candidate.port != 0));
        let unique = scheduled
            .iter()
            .map(|candidate| candidate.port)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), scheduled.len());
    }
    let model = build_model(&[1000, 1001, 1002], None, 100);
    let count = predict_for_rendezvous(&model, 1002, timing(3_500), None, false)
        .unwrap()
        .len();
    let a = fixed_step_rendezvous_order(count, false, false);
    let b = fixed_step_rendezvous_order(count, true, true);
    assert!(reciprocal_pair(&a, &b, 2, 3));
    assert!(!reciprocal_pair(
        &a[..6],
        &fixed_step_rendezvous_order(6, true, true),
        2,
        3
    ));
}

#[test]
fn scheduled_expansion_does_not_override_confidence_or_wrap_safety() {
    let mut model = build_model(&[1000, 1001, 1002], None, 100);
    model.confidence = 59;
    assert!(
        predict_for_rendezvous(&model, 1002, timing(3_500), None, false)
            .unwrap()
            .is_empty()
    );
    let model = build_model(&[65531, 65532, 65533], None, 100);
    let scheduled = predict_for_rendezvous(&model, 65533, timing(3_500), None, false).unwrap();
    assert!(scheduled.len() <= p2pnet_nat::mapping::MAX_PREDICTED_PORTS);
    assert_eq!(scheduled[0].port, 65534);
    assert!(scheduled.iter().all(|candidate| candidate.port != 0));
    let unique = scheduled
        .iter()
        .map(|candidate| candidate.port)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), scheduled.len());
}

#[test]
fn bounded_window_preserves_prefix_and_reaches_far_drift_inside_same_cap() {
    let ports = (10_001..=10_096).collect::<Vec<_>>();
    let window = bounded_prediction_window(&ports, 32);
    assert_eq!(window.len(), 32);
    assert_eq!(&window[..8], &ports[..8]);
    assert_eq!(window.last(), ports.last());
    assert!(window.contains(&10_096));
    assert!(!ports[..32].contains(&10_096));
    assert!(window.windows(2).all(|pair| pair[1] > pair[0]));
    for cap in 0..=96 {
        let window = bounded_prediction_window(&ports, cap);
        assert!(window.len() <= cap);
        assert!(window.iter().all(|port| ports.contains(port)));
        if cap > 0 {
            assert_eq!(window[0], ports[0]);
        }
    }
    assert_eq!(
        bounded_prediction_window(&[0, 1000, 1000, 1001], 32),
        vec![1000, 1001]
    );
}

// Strict APDM/APDF toy model: contacting the i-th distinct destination
// allocates source rank d+i; the mapping only admits that exact destination.
fn reciprocal_pair(a: &[usize], b: &[usize], drift_a: usize, drift_b: usize) -> bool {
    a.iter().enumerate().any(|(i, target_b)| {
        b.iter()
            .enumerate()
            .any(|(l, target_a)| *target_b == drift_b + l && *target_a == drift_a + i)
    })
}

#[test]
fn two_fresh_generation_phases_cover_bounded_positive_drift_in_strict_toy_model() {
    for count in 3..=32 {
        let initiator = fixed_step_rendezvous_order(count, false, false);
        let phase_a = fixed_step_rendezvous_order(count, true, false);
        let phase_b = fixed_step_rendezvous_order(count, true, true);
        assert_eq!(phase_a[0], 0);
        assert_eq!(phase_b[0], 0);
        assert!(reciprocal_pair(&initiator, &phase_a, 0, 0));
        assert!(reciprocal_pair(&initiator, &phase_b, 0, 0));
        for drift_a in 0..count {
            for drift_b in 0..count {
                let sum = drift_a + drift_b;
                if (1..=count - 3).contains(&sum) {
                    assert!(!reciprocal_pair(&initiator, &initiator, drift_a, drift_b));
                    assert!(
                        reciprocal_pair(&initiator, &phase_a, drift_a, drift_b)
                            || reciprocal_pair(&initiator, &phase_b, drift_a, drift_b),
                        "count={count} drift_a={drift_a} drift_b={drift_b}"
                    );
                }
            }
        }
    }
}

fn endpoints(ip: &str, ports: &[u16]) -> Vec<SocketAddr> {
    ports
        .iter()
        .map(|port| format!("{ip}:{port}").parse().unwrap())
        .collect()
}

#[test]
fn role_order_requires_complete_fixed_step_windows() {
    let local = endpoints("192.0.2.1", &[65532, 65534, 0, 2]);
    let remote = endpoints("198.51.100.2", &[4004, 4003, 4002, 4001]);
    assert!(fixed_step_rendezvous_targets(&local, &remote, true, false).is_none());
    let local = endpoints("192.0.2.1", &[65533, 65535, 1, 3]);
    let reordered = fixed_step_rendezvous_targets(&local, &remote, true, false).unwrap();
    assert_eq!(reordered, vec![remote[0], remote[3], remote[2], remote[1]]);
    assert_eq!(
        fixed_step_rendezvous_targets(&local[..3], &remote, true, false).unwrap(),
        vec![remote[0], remote[2], remote[1], remote[3]]
    );
    let sparse = endpoints("198.51.100.2", &[4004, 4003, 4001, 4000]);
    assert!(fixed_step_rendezvous_targets(&local, &sparse, true, false).is_none());
    let mut mixed_ip = remote.clone();
    mixed_ip[1] = "198.51.100.3:4003".parse().unwrap();
    assert!(fixed_step_rendezvous_targets(&local, &mixed_ip, true, false).is_none());
    let duplicate = endpoints("198.51.100.2", &[4004, 4003, 4003, 4002]);
    assert!(fixed_step_rendezvous_targets(&local, &duplicate, true, false).is_none());
}

#[test]
fn unequal_windows_preserve_the_proved_common_prefix_and_all_remaining_targets() {
    // Each phase keeps exactly the old equal-width proof; neither single phase
    // is claimed to cover both parities. This also covers negative-step NATs.
    for (local_width, remote_width) in [(15, 24), (24, 15), (4, 9), (9, 4)] {
        for step in [-2i32, 1] {
            let window = |ip, base, count| {
                endpoints(
                    ip,
                    &(0..count)
                        .map(|rank| (base + step * rank as i32) as u16)
                        .collect::<Vec<_>>(),
                )
            };
            let local = window("192.0.2.1", 30000, local_width);
            let remote = window("198.51.100.2", 40000, remote_width);
            let common_width = local_width.min(remote_width);
            let initiator = (0..local_width).collect::<Vec<_>>();
            for phase in [false, true] {
                let reordered =
                    fixed_step_rendezvous_targets(&local, &remote, true, phase).unwrap();
                let ranks = reordered
                    .iter()
                    .map(|target| {
                        remote
                            .iter()
                            .position(|candidate| candidate == target)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                let proved_order = fixed_step_rendezvous_order(common_width, true, phase);
                assert_eq!(ranks.len(), remote_width);
                assert_eq!(ranks[0], 0);
                assert_eq!(ranks[..common_width], proved_order);
                assert_eq!(
                    ranks[common_width..],
                    (common_width..remote_width).collect::<Vec<_>>()
                );
                assert!(reciprocal_pair(&initiator, &ranks, 0, 0));
                for drift_a in 0..common_width {
                    for drift_b in 0..common_width {
                        if reciprocal_pair(
                            &(0..common_width).collect::<Vec<_>>(),
                            &proved_order,
                            drift_a,
                            drift_b,
                        ) {
                            assert!(reciprocal_pair(&initiator, &ranks, drift_a, drift_b));
                        }
                    }
                }
                assert_eq!(
                    fixed_step_rendezvous_targets(&local, &remote, false, phase).unwrap(),
                    remote,
                    "initiator order must remain compatible with existing hh2"
                );
            }
            let mut sparse_suffix = remote.clone();
            let last = sparse_suffix.last_mut().unwrap();
            // Skip one rank in the original direction. The final delta is
            // 2*step while every earlier delta is step: both have the same
            // sign, so this cannot accidentally become a valid wrap.
            last.set_port((i32::from(last.port()) + step) as u16);
            for phase in [false, true] {
                assert!(
                    fixed_step_rendezvous_targets(&local, &sparse_suffix, true, phase).is_none(),
                    "local_width={local_width} remote_width={remote_width} step={step} phase={phase}"
                );
                assert!(
                    fixed_step_rendezvous_targets(&sparse_suffix, &local, true, phase).is_none(),
                    "a gap anywhere in either advertised window must reject reordering"
                );
            }
        }
    }
}

#[test]
fn circular_rank_shape_does_not_establish_allocation_domain_evidence() {
    use p2pnet_nat::{infer_port_domain, PortDomainEvidence};

    let local = endpoints("192.0.2.1", &(5000..5009).collect::<Vec<_>>());
    // Adding seven to the last element of [40000, 39998, 39996, 39994]
    // is not a reliable sparse counterexample: [-2, -2, +5] describes a
    // complete rank sequence modulo seven. Its reversal is equally regular.
    for (ports, step) in [
        ([40000, 39998, 39996, 40001], -2),
        ([40001, 39996, 39998, 40000], 2),
    ] {
        let witness = PortDomainEvidence::ObservedRange {
            first: 39995,
            last: 40001,
        };
        assert!(ports
            .windows(2)
            .all(|pair| witness.advance(pair[0], step) == Some(pair[1])));
        assert!(
            infer_port_domain(&ports).is_err(),
            "a mathematical rank witness must not manufacture measured NAT evidence"
        );
        let remote = endpoints("198.51.100.2", &ports);
        for phase in [false, true] {
            let expected = fixed_step_rendezvous_order(remote.len(), true, phase)
                .into_iter()
                .map(|rank| remote[rank])
                .collect::<Vec<_>>();
            assert_eq!(
                fixed_step_rendezvous_targets(&local, &remote, true, phase),
                Some(expected)
            );
            assert_eq!(
                fixed_step_rendezvous_targets(&local, &remote, false, phase),
                Some(remote.clone())
            );
        }
    }
}

#[test]
fn boundary_truncated_windows_recover_the_existing_phase_coverage() {
    let a = endpoints("192.0.2.1", &(65521..=65535).collect::<Vec<_>>());
    let b = endpoints("198.51.100.2", &(40001..=40024).collect::<Vec<_>>());
    let initiator = (0..b.len()).collect::<Vec<_>>();
    let same_order = (0..a.len()).collect::<Vec<_>>();
    assert!(!reciprocal_pair(&initiator, &same_order, 1, 1));
    let ranks = |phase| {
        fixed_step_rendezvous_targets(&b, &a, true, phase)
            .unwrap()
            .iter()
            .map(|target| a.iter().position(|candidate| candidate == target).unwrap())
            .collect::<Vec<_>>()
    };
    assert!(!reciprocal_pair(&initiator, &ranks(false), 1, 1));
    assert!(reciprocal_pair(&initiator, &ranks(true), 1, 1));
}

#[test]
fn observed_port_domain_predictions_keep_the_same_common_prefix_rank_proof() {
    use p2pnet_nat::{infer_port_domain, PortDomainEvidence};

    // These complete ordered measurement sequences uniquely establish the
    // same 4097-port domain in either direction. Candidate validation must
    // preserve that predictor's ranks instead of assuming a 65536-port ring.
    for (sequence, expected_step) in [
        ([49152, 51200, 53248, 51199, 53247, 51198], 2048),
        ([53248, 51200, 49152, 51201, 49153, 51202], -2048),
    ] {
        let (step, domain) = infer_port_domain(&sequence).unwrap();
        assert_eq!(step, expected_step);
        assert_eq!(
            domain,
            PortDomainEvidence::ObservedRange {
                first: 49152,
                last: 53248
            }
        );
        let ports = (1..=24)
            .map(|rank| domain.advance(sequence[5], i64::from(step) * rank).unwrap())
            .collect::<Vec<_>>();
        for (local_width, remote_width) in [(15, 24), (24, 15), (24, 24)] {
            let local = endpoints("192.0.2.1", &ports[..local_width]);
            let remote = endpoints("198.51.100.2", &ports[..remote_width]);
            let common_width = local_width.min(remote_width);
            let initiator = (0..local_width).collect::<Vec<_>>();
            for phase in [false, true] {
                let reordered =
                    fixed_step_rendezvous_targets(&local, &remote, true, phase).unwrap();
                let ranks = reordered
                    .iter()
                    .map(|target| {
                        remote
                            .iter()
                            .position(|candidate| candidate == target)
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(ranks.len(), remote_width);
                assert_eq!(
                    ranks[..common_width],
                    fixed_step_rendezvous_order(common_width, true, phase)
                );
                assert_eq!(
                    ranks[common_width..],
                    (common_width..remote_width).collect::<Vec<_>>()
                );
                assert!(reciprocal_pair(&initiator, &ranks, 0, 0));
                for drift_a in 0..common_width {
                    for drift_b in 0..common_width {
                        let sum = drift_a + drift_b;
                        if (1..=common_width - 3).contains(&sum)
                            && (common_width - usize::from(phase) - sum) % 2 == 0
                        {
                            assert!(reciprocal_pair(&initiator, &ranks, drift_a, drift_b));
                        }
                    }
                }
                assert_eq!(
                    fixed_step_rendezvous_targets(&local, &remote, false, phase).unwrap(),
                    remote
                );
            }
        }
    }
}

#[test]
fn circular_rank_validation_rejects_sparse_spanning_and_ambiguous_lists() {
    let local = endpoints("192.0.2.1", &[5000, 5001, 5002, 5003]);
    for ports in [
        vec![53246, 51197, 53245, 51195], // Three distinct raw deltas.
        vec![1000, 4000, 3000, 6000],     // Port span exceeds the proposed ring.
        vec![6000, 3000, 4000, 1000],     // Same invalid span, negative direction.
        vec![1000, 3000, 1000, 3000],     // Half-cycle repeats the same pair.
        vec![1, 60000, 2, 60001],         // Proposed modulus exceeds the UDP domain.
        vec![4000, 4001, 4003, 4004],     // Same-sign sparse sequence.
    ] {
        let remote = endpoints("198.51.100.2", &ports);
        assert!(fixed_step_rendezvous_targets(&local, &remote, true, false).is_none());
        assert!(fixed_step_rendezvous_targets(&remote, &local, true, false).is_none());
    }
}

#[test]
fn filtering_evidence_requires_an_uncontacted_source_ip() {
    use p2pnet_nat::ice::classify_filtering_probe_response;
    use p2pnet_nat::FilteringBehavior;
    let server = "192.0.2.1:3478".parse().unwrap();
    let alternate = "192.0.2.2:3479".parse().unwrap();
    assert_eq!(
        classify_filtering_probe_response(server, alternate, &[server]),
        Some(FilteringBehavior::EndpointIndependent)
    );
    assert_eq!(
        classify_filtering_probe_response(server, alternate, &[server, alternate]),
        None
    );
    assert_eq!(
        classify_filtering_probe_response(server, "192.0.2.1:3479".parse().unwrap(), &[server]),
        None
    );
}

#[test]
fn concurrent_discovery_is_a_low_confidence_hint_until_fresh_measurement() {
    use p2pnet_nat::{
        candidate_report_from_observations, candidate_report_from_unordered_observations,
        FilteringBehavior, NatCapabilities, StunObservation,
    };
    let observations = (0..4)
        .map(|index| StunObservation {
            failure_kind: None,
            server: format!("192.0.2.{}:3478", index + 1),
            mapped_address: Some(format!("198.51.100.1:{}", 4000 + index)),
            rtt_ms: Some(5),
            error: None,
        })
        .collect::<Vec<_>>();
    let local = "0.0.0.0:40000".parse().unwrap();
    let ordered = candidate_report_from_observations(local, false, observations.clone());
    let unordered = candidate_report_from_unordered_observations(local, false, observations);
    assert_eq!(ordered.nat_profile.confidence, 90);
    assert_eq!(unordered.nat_profile.confidence, 60);
    assert_eq!(
        unordered.nat_profile.filtering_behavior,
        FilteringBehavior::Unknown
    );
    assert!(NatCapabilities::from_profile(&unordered.nat_profile).hard_allocation_is_predictable());
    // Admission remains possible; neither the profile score nor candidate
    // list substitutes for the dedicated socket's ordered allocation model.
    let endpoints = |report: &p2pnet_nat::CandidateGatherReport| {
        report
            .candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.endpoint.to_string(),
                    candidate.source,
                    candidate.priority,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(endpoints(&unordered), endpoints(&ordered));
}
