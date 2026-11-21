use super::*;

fn identity() -> OrdinaryProbeIdentity {
    OrdinaryProbeIdentity {
        transport_instance: 2,
        session_id: 3,
        network_generation: 4,
        peer_session_generation: PeerSessionGeneration::for_test(5),
        recovery_epoch: 6,
    }
}

fn socket(index: usize) -> OrdinaryProbeSocket {
    OrdinaryProbeSocket {
        index,
        socket_ptr: index,
        local_endpoint: Some("127.0.0.1:1234".parse().unwrap()),
        target: "127.0.0.1:4321".parse().unwrap(),
        network_generation: 4,
    }
}

#[test]
fn n01_fixed_reducer_uses_actual_returned_bytes_and_commits_once() {
    let owner = OrdinaryProbeCost::new(identity());
    let mut call = owner.begin_call();
    call.classify_domain(true);
    let mut operation = call.begin_operation(OrdinaryProbeKind::Primary, 99, socket(7));
    // A pure reducer input, deliberately shorter than the requested length;
    // actual native acceptance is proved by the separate UDP controls.
    operation.complete(Some(7), 9);
    operation.complete(Some(99), 10);
    drop(operation);
    drop(call);
    let actual = owner.snapshot();
    assert_eq!(actual.primary.accepted_datagrams, 1);
    assert_eq!(actual.primary.accepted_bytes, 7);
    assert_eq!(actual.primary.first_result_at_ms, Some(9));
    assert_eq!(actual.primary.last_result_at_ms, Some(9));
    assert_eq!(actual.primary.missing_completions, 0);
    assert_eq!(actual.primary.active_operations, 0);
    assert_eq!(actual.dropped_calls, 1);
}

#[test]
fn n01_fixed_reducer_preserves_original_identity_missing_and_excluded_domains() {
    let owner = OrdinaryProbeCost::new(identity());
    {
        let mut call = owner.begin_call();
        call.classify_domain(true);
        let _operation = call.begin_operation(OrdinaryProbeKind::Compatibility, 12, socket(7));
    }
    {
        let mut call = owner.begin_call();
        call.classify_domain(false);
        call.returned(&Err(ProbeSendFailure::new(
            ProbeSendFailureKind::SocketRevoked,
            crate::error::DaemonError::Network("pure HH2 exclusion".into()),
        )));
    }
    let actual = owner.snapshot();
    assert_eq!(actual.identity, identity());
    assert_eq!(actual.compatibility.missing_completions, 1);
    assert_eq!(actual.compatibility.missing_completion_requested_bytes, 12);
    assert_eq!(actual.compatibility.accepted_datagrams, 0);
    assert_eq!(actual.compatibility.returned_errors, 0);
    assert_eq!(actual.compatibility.first_result_at_ms, None);
    assert_eq!(actual.proven_pre_handoff_rejections, 0);
    assert_eq!(actual.excluded_hh2_calls, 1);
    assert_eq!(actual.active_calls, 0);
    assert_eq!(
        actual.producer_settlement,
        OrdinaryProducerSettlement::NotStarted
    );
}

#[test]
fn n01_fixed_reducer_saturation_and_context_mixing_remain_explicit() {
    assert!(std::mem::size_of::<OrdinaryProbeCostState>() <= 1024);
    let owner = OrdinaryProbeCost::new(identity());
    owner.observe_generation(4, 8);
    owner.observe_generation(4, 9);
    owner.update(|s| s.primary.accepted_bytes = u64::MAX);
    for (index, at) in [(7, 9), (8, 3)] {
        let mut call = owner.begin_call();
        call.classify_domain(true);
        let mut operation = call.begin_operation(OrdinaryProbeKind::Primary, 1, socket(index));
        operation.complete(Some(1), at);
    }
    let actual = owner.snapshot();
    assert_eq!(actual.identity, identity());
    assert_eq!(actual.first_punch_generation, Some((4, 8)));
    assert!(actual.multiple_punch_generations);
    assert_eq!(actual.primary.first_socket, Some(socket(7)));
    assert!(actual.primary.multiple_socket_contexts);
    assert_eq!(actual.primary.accepted_bytes, u64::MAX);
    assert!(actual.counters_saturated);
    assert_eq!(actual.primary.first_result_at_ms, Some(3));
    assert_eq!(actual.primary.last_result_at_ms, Some(9));
}
