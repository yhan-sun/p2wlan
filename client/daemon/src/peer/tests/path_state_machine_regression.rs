#[test]
fn lost_direct_request_restarts_after_candidate_churn_while_peer_is_direct() {
    let initial = epoch(0, 1, 0);
    let first_refresh = epoch(0, 1, 1);
    let second_refresh = epoch(0, 1, 2);
    let mut local = online_machine(initial);
    let mut remote = online_machine(initial);
    assert!(commit(
        &mut local,
        PathEvent::RelayPeerConfirmed {
            relay: relay(initial, "relay.test:443", 1),
        },
    )
    .accepted());

    let lost_request = DirectValidationIdentity::owned(
        initial,
        11,
        Some(38051),
        Some("127.0.0.1:26007".parse().unwrap()),
    );
    assert!(commit(
        &mut local,
        PathEvent::DirectValidationStarted {
            validation: lost_request,
        },
    )
    .accepted());
    // The first outbound request receives no ACK. The peer's separate
    // authenticated request/ACK succeeds, leaving only this side on Relay.
    let remote_request = validation(initial, 12, 38053);
    assert!(commit_direct(&mut remote, remote_request).accepted());
    assert_eq!(local.active_path(), Some(NetworkPath::Relay));
    assert_eq!(remote.active_path(), Some(NetworkPath::Direct));

    for refreshed in [first_refresh, second_refresh] {
        let advanced = commit(
            &mut local,
            PathEvent::RemoteCandidateEpochAdvanced {
                epoch: refreshed,
                direct: DirectCandidateContinuity::Invalidate,
            },
        );
        assert!(
            advanced.accepted(),
            "candidate handover must retire the lost owner: {:?}",
            advanced.decision
        );
        assert_eq!(advanced.snapshot.state.epoch, Some(refreshed));
        assert!(matches!(
            advanced.snapshot.state.direct,
            DirectPathState::Idle
        ));
        assert_eq!(local.active_path(), Some(NetworkPath::Relay));
    }

    let new_request = DirectValidationIdentity::owned(
        second_refresh,
        14,
        Some(48547),
        Some("127.0.0.1:26009".parse().unwrap()),
    );
    assert!(commit(
        &mut local,
        PathEvent::DirectValidationStarted {
            validation: new_request,
        },
    )
    .accepted());
    assert_eq!(local.active_path(), Some(NetworkPath::Relay));

    for (stale, expected) in [
        (
            matching_ack(lost_request),
            PathTransitionDecision::RejectedRemoteCandidateEpoch,
        ),
        (
            matching_ack(validation(epoch(1, 1, 2), 14, 48547)),
            PathTransitionDecision::RejectedNetworkGeneration,
        ),
        (
            matching_ack(validation(epoch(0, 2, 2), 14, 48547)),
            PathTransitionDecision::RejectedPeerSessionGeneration,
        ),
    ] {
        assert_eq!(
            commit(&mut local, PathEvent::DirectCommitted { validation: stale }).decision,
            expected
        );
    }
    let wrong_request_endpoint = DirectValidationIdentity::authenticated_ack(
        second_refresh,
        14,
        48547,
        Some("127.0.0.1:26008".parse().unwrap()),
        "127.0.0.1:26010".parse().unwrap(),
    );
    assert_eq!(
        commit(
            &mut local,
            PathEvent::DirectCommitted {
                validation: wrong_request_endpoint,
            },
        )
        .decision,
        PathTransitionDecision::RejectedDirectValidationIdentity
    );
    assert_eq!(local.active_path(), Some(NetworkPath::Relay));

    // The authenticated ACK may arrive from a new peer-reflexive source,
    // but must still match the new owner's request target and identity.
    let ack = authenticated_ack(new_request, "127.0.0.1:26010".parse().unwrap());
    let promoted = commit(&mut local, PathEvent::DirectCommitted { validation: ack });
    assert!(promoted.accepted());
    assert_eq!(local.active_path(), Some(NetworkPath::Direct));
    assert!(matches!(
        promoted.snapshot.state.active,
        ActiveBusinessPath::Direct(identity)
            if identity.request_endpoint() == new_request.request_endpoint()
                && identity.commit_endpoint() == ack.commit_endpoint()
    ));
}
