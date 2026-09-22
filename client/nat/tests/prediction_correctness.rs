use p2pnet_nat::adaptive::StepLearner;
use p2pnet_nat::mapping::{
    build_model, build_model_for_batch, infer_allocation_model, predict_ports,
    predict_ports_with_learning, AllocationModelKind, MappingBatch, MappingObservation,
    ModelRejection, PortModelKind,
};
use std::collections::HashSet;
use std::time::Duration;

#[test]
fn wide_signed_products_preserve_distinct_candidates() {
    for step in [-2048i16, 2048] {
        let sequence = if step < 0 {
            [56144, 54096, 52048]
        } else {
            [43856, 45904, 47952]
        };
        let model = build_model(&sequence, None, 1);
        let result = predict_ports_with_learning(&model, 50000, 0, 0, None, true);
        assert_eq!(result.len(), 24);
        assert_eq!(
            result.iter().map(|c| c.port).collect::<HashSet<_>>().len(),
            24
        );
        for (index, candidate) in result.iter().enumerate() {
            let expected = (50000i64 + i64::from(step) * (index + 1) as i64).rem_euclid(65536);
            assert_eq!(i64::from(candidate.port), expected);
            assert_eq!(usize::from(candidate.rank), index);
        }
    }
}

#[test]
fn extreme_delta_span_and_half_ring_do_not_panic() {
    for ports in [[1000, 30000, 1000], [0, 32768, 0], [1, 32769, 1]] {
        let model = build_model(&ports, None, 1);
        let result = predict_ports(&model, ports[2]);
        assert!(result.iter().all(|c| c.port != 0));
    }
}

#[test]
fn malformed_empty_periodic_model_has_no_candidates() {
    let mut model = build_model(&[1000, 1001, 1002], None, 1);
    model.kind = PortModelKind::Periodic { steps: vec![] };
    assert!(predict_ports(&model, 1002).is_empty());
}

#[test]
fn signed_advertisement_preserves_reverse_allocator() {
    let mut learner = StepLearner::new();
    learner.observe_advertised(-2048);
    assert_eq!(learner.estimate(), Some(-2048));
    learner.observe_advertised(0);
    assert_eq!(learner.estimate(), Some(-2048));
}

#[test]
fn confidence_can_fall_when_recent_evidence_is_noisy() {
    let mut learner = StepLearner::new();
    for _ in 0..8 {
        learner.observe_diff(1);
    }
    assert_eq!(learner.confidence(), 1.0);
    for step in 2..=9 {
        learner.observe_diff(step);
    }
    assert_eq!(learner.confidence(), 0.125);
    learner.reset();
    assert_eq!(learner.confidence(), 0.0);
}

fn observation(sequence: u16, port: u16) -> MappingObservation {
    MappingObservation {
        sequence,
        observer: format!("192.0.2.1:{}", 3478 + sequence).parse().unwrap(),
        observed: format!("198.51.100.1:{port}").parse().unwrap(),
        sent_at_ms: 100 + u64::from(sequence),
        responded_at_ms: 110 + u64::from(sequence),
        local_endpoint: "127.0.0.1:40000".parse().unwrap(),
    }
}

#[test]
fn reordered_responses_do_not_change_send_order_model() {
    let mut observations = vec![
        observation(0, 1000),
        observation(1, 1001),
        observation(2, 1002),
    ];
    observations[0].responded_at_ms = 120;
    assert_eq!(
        infer_allocation_model(&observations).kind,
        AllocationModelKind::FixedStep { step: 1 }
    );
}

#[test]
fn gaps_cannot_manufacture_exact_step_in_profile_entrypoint() {
    let observations = vec![
        observation(0, 1000),
        observation(2, 1002),
        observation(4, 1004),
    ];
    assert_eq!(
        infer_allocation_model(&observations).kind,
        AllocationModelKind::Unknown
    );
}

#[test]
fn mixed_public_ips_are_rejected_before_prediction() {
    let mut observations = vec![
        observation(0, 1000),
        observation(1, 1001),
        observation(2, 1002),
    ];
    observations[1].observed = "198.51.100.2:1001".parse().unwrap();
    let batch = MappingBatch {
        generation: 1,
        network_generation: 1,
        socket_identity: observations[0].local_endpoint,
        observations,
        started_at_ms: 100,
        finished_at_ms: 120,
    };
    assert_eq!(
        build_model_for_batch(&batch, Duration::from_secs(1), 150),
        Err(ModelRejection::PublicIpChanged)
    );
}

#[test]
fn learning_never_discards_fresh_top_candidate_or_increases_total_budget() {
    use p2pnet_nat::mapping::{build_model, predict_ports_with_learning, PredictionReason};
    for (samples, estimate) in [([40000, 40002, 40004], 7), ([40000, 39998, 39996], -7)] {
        let model = build_model(&samples, Some("198.51.100.1".parse().unwrap()), 1);
        let plain = predict_ports_with_learning(&model, samples[2], 0, 0, None, false);
        let learned = predict_ports_with_learning(&model, samples[2], 0, 0, Some(estimate), false);
        assert_eq!(learned.len(), plain.len());
        assert_eq!(learned[0], plain[0]);
        assert!(learned
            .iter()
            .any(|c| matches!(c.reason, PredictionReason::LearnedSuccessor { .. })));
        let unique: std::collections::HashSet<_> = learned.iter().map(|c| c.port).collect();
        assert_eq!(unique.len(), learned.len());
        assert!(learned
            .iter()
            .enumerate()
            .all(|(rank, c)| c.rank as usize == rank && c.port != 0));
    }
}
