use super::*;
use crate::dplpmtud::*;
use crate::peer::PathEpoch;
use crate::peer::PeerSessionGeneration;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::time::Instant;

fn test_identity(peer_id: &str) -> DplpmtudPathIdentity {
    test_identity_with(peer_id, 7, 11, 13, 17, 19, 23, 0)
}

#[allow(clippy::too_many_arguments)]
fn test_identity_with(
    peer_id: &str,
    network_generation: u64,
    peer_session_generation: u64,
    remote_candidate_epoch: u64,
    validation_owner: u64,
    validation_request: u16,
    transport_instance_id: u64,
    socket_index: usize,
) -> DplpmtudPathIdentity {
    DplpmtudPathIdentity {
        peer_id: peer_id.to_string(),
        epoch: PathEpoch::new(
            network_generation,
            PeerSessionGeneration::for_test(peer_session_generation),
            remote_candidate_epoch,
        ),
        direct_validation_owner_token: validation_owner,
        direct_validation_request_id: validation_request,
        authenticated_remote_endpoint: "127.0.0.1:42002".parse().unwrap(),
        local_endpoint: "127.0.0.1:42001".parse().unwrap(),
        socket: DplpmtudSocketIdentity {
            transport_instance_id,
            socket_index,
        },
        outer_ip_family: OuterIpFamily::Ipv4,
    }
}

fn deterministic_probe(
    sequence: u64,
    candidate_udp_datagram_size: UdpDatagramSize,
) -> DplpmtudProbeIdentity {
    DplpmtudProbeIdentity {
        sequence,
        nonce: [sequence as u8; 16],
        path_cookie: [0x5a; 16],
        candidate_udp_datagram_size,
    }
}

fn schedule_and_mark_sent(
    machine: &mut DplpmtudStateMachine,
    now: Instant,
) -> (DplpmtudProbeIdentity, Instant) {
    if machine.state() == DplpmtudState::Base {
        assert_eq!(
            machine.apply(DplpmtudEvent::StartSearch { now }),
            DplpmtudTransitionDecision::Applied
        );
    }
    let (sequence, candidate, retry) = machine
        .next_probe_components()
        .expect("search must have a next candidate");
    let probe = deterministic_probe(sequence, candidate);
    let deadline = now + DPLPMTUD_PROBE_TIMEOUT;
    assert_eq!(
        machine.apply(DplpmtudEvent::ProbeScheduled {
            probe,
            retry,
            now,
            deadline,
        }),
        DplpmtudTransitionDecision::Applied
    );
    assert_eq!(
        machine.apply(DplpmtudEvent::ProbeSent {
            probe,
            now: now + Duration::from_millis(1),
        }),
        DplpmtudTransitionDecision::Applied
    );
    (probe, deadline)
}

fn positively_confirm_base(machine: &mut DplpmtudStateMachine, now: Instant) -> Instant {
    let (probe, _) = schedule_and_mark_sent(machine, now);
    assert_eq!(
        probe.candidate_udp_datagram_size.0,
        DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
    );
    assert_eq!(
        machine.apply(DplpmtudEvent::ProbeAcked {
            probe,
            now: now + Duration::from_millis(2),
        }),
        DplpmtudTransitionDecision::Applied
    );
    now + Duration::from_millis(3)
}

fn converge_machine_to_threshold(
    machine: &mut DplpmtudStateMachine,
    mut now: Instant,
    threshold: u32,
) -> Instant {
    for _ in 0..96 {
        if machine.state() == DplpmtudState::SearchComplete {
            return now;
        }
        let (probe, deadline) = schedule_and_mark_sent(machine, now);
        if probe.candidate_udp_datagram_size.0 <= threshold {
            assert_eq!(
                machine.apply(DplpmtudEvent::ProbeAcked {
                    probe,
                    now: now + Duration::from_millis(2),
                }),
                DplpmtudTransitionDecision::Applied
            );
            now += Duration::from_millis(3);
        } else {
            assert_eq!(
                machine.apply(DplpmtudEvent::ProbeTimedOut {
                    probe,
                    now: deadline,
                }),
                DplpmtudTransitionDecision::Applied
            );
            now = deadline + Duration::from_millis(1);
        }
    }
    panic!("bounded DPLPMTUD search did not converge");
}

#[test]
fn unsupported_peer_stays_fail_closed_without_a_probe() {
    let now = Instant::now();
    let machine = DplpmtudStateMachine::for_path(test_identity("peer"), false, now);
    assert_eq!(machine.state(), DplpmtudState::Unsupported);
    assert!(machine.next_probe_components().is_none());
    let snapshot = machine.snapshot(now, false);
    assert!(!snapshot.supported);
    assert!(snapshot.outstanding_probe.is_none());
}

#[test]
fn base_requires_a_positive_probe_before_any_confirmed_budget() {
    let mut now = Instant::now();
    let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
    let initial = machine.snapshot(now, false);
    assert_eq!(
        initial.assumed_base_udp_datagram_size,
        DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
    );
    assert!(!initial.base_confirmed);
    assert_eq!(initial.confirmed_udp_datagram_size, None);
    assert_eq!(initial.overlay_payload_budget, None);

    for _ in 0..=DPLPMTUD_MAX_RETRIES {
        let (probe, deadline) = schedule_and_mark_sent(&mut machine, now);
        assert_eq!(
            probe.candidate_udp_datagram_size.0,
            DPLPMTUD_BASE_UDP_DATAGRAM_SIZE
        );
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeTimedOut {
                probe,
                now: deadline,
            }),
            DplpmtudTransitionDecision::Applied
        );
        now = deadline + Duration::from_millis(1);
    }
    assert_eq!(machine.state(), DplpmtudState::Error);
    let failed = machine.snapshot(now, false);
    assert!(!failed.base_confirmed);
    assert_eq!(failed.confirmed_udp_datagram_size, None);
    assert_eq!(failed.overlay_payload_budget, None);
    assert!(failed.outstanding_probe.is_none());

    let retry_at = machine.raise_at.expect("BASE Error owns a retry timer");
    assert_eq!(
        machine.apply(DplpmtudEvent::RaiseTimerExpired { now: retry_at }),
        DplpmtudTransitionDecision::Applied
    );
    assert_eq!(machine.state(), DplpmtudState::Base);
    assert_eq!(
        machine.next_probe_components().map(|(_, size, _)| size.0),
        Some(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
    );
    println!(
            "DPLPMTUD_BASE assumed={} positively_validated=false confirmed=none state={:?} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 old_ack_contamination=false task_leak=false",
            DPLPMTUD_BASE_UDP_DATAGRAM_SIZE,
            machine.state(),
        );
}

#[test]
fn supported_peer_moves_from_base_to_searching_and_ack_raises_lower_bound() {
    let now = Instant::now();
    let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
    let (probe, _) = schedule_and_mark_sent(&mut machine, now);
    assert_eq!(machine.state(), DplpmtudState::Searching);
    assert_eq!(
        machine.apply(DplpmtudEvent::ProbeAcked {
            probe,
            now: now + Duration::from_millis(2),
        }),
        DplpmtudTransitionDecision::Applied
    );
    assert_eq!(
        machine.confirmed_udp_datagram_size,
        Some(probe.candidate_udp_datagram_size)
    );
    assert_eq!(machine.success_count, 1);
}

#[test]
fn timeout_retries_then_only_narrows_search_bounds() {
    let mut now = Instant::now();
    let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
    now = positively_confirm_base(&mut machine, now);
    let original_upper = machine.search_upper_udp_datagram_size;
    let mut failed_size = None;
    for retry in 0..=DPLPMTUD_MAX_RETRIES {
        let (probe, deadline) = schedule_and_mark_sent(&mut machine, now);
        failed_size = Some(probe.candidate_udp_datagram_size);
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeTimedOut {
                probe,
                now: deadline,
            }),
            DplpmtudTransitionDecision::Applied
        );
        if retry < DPLPMTUD_MAX_RETRIES {
            assert_eq!(machine.search_upper_udp_datagram_size, original_upper);
            assert_eq!(
                machine.pending_candidate_udp_datagram_size,
                Some(probe.candidate_udp_datagram_size)
            );
        }
        assert!(machine.supported);
        assert_ne!(machine.state(), DplpmtudState::Disabled);
        now = deadline + Duration::from_millis(1);
    }
    let failed_size = failed_size.unwrap();
    assert!(
        machine.search_upper_udp_datagram_size.0
            <= failed_size.0.saturating_sub(DPLPMTUD_SEARCH_GRANULARITY)
    );
    assert_eq!(machine.timeout_count, u64::from(DPLPMTUD_MAX_RETRIES) + 1);
}

#[test]
fn bounded_search_converges_and_raise_timer_reopens_search() {
    let threshold = 1397;
    let mut now = Instant::now();
    let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
    for _ in 0..64 {
        if machine.state() == DplpmtudState::SearchComplete {
            break;
        }
        let (probe, deadline) = schedule_and_mark_sent(&mut machine, now);
        if probe.candidate_udp_datagram_size.0 <= threshold {
            assert_eq!(
                machine.apply(DplpmtudEvent::ProbeAcked {
                    probe,
                    now: now + Duration::from_millis(2),
                }),
                DplpmtudTransitionDecision::Applied
            );
            now += Duration::from_millis(3);
        } else {
            assert_eq!(
                machine.apply(DplpmtudEvent::ProbeTimedOut {
                    probe,
                    now: deadline,
                }),
                DplpmtudTransitionDecision::Applied
            );
            now = deadline + Duration::from_millis(1);
        }
    }
    assert_eq!(machine.state(), DplpmtudState::SearchComplete);
    let confirmed = machine
        .confirmed_udp_datagram_size
        .expect("search completion requires positive BASE confirmation");
    assert!(confirmed.0 <= threshold);
    assert!(threshold - confirmed.0 <= DPLPMTUD_SEARCH_GRANULARITY);
    let raise_at = machine
        .raise_at
        .expect("completed search owns a raise timer");
    assert_eq!(
        machine.apply(DplpmtudEvent::RaiseTimerExpired { now: raise_at }),
        DplpmtudTransitionDecision::Applied
    );
    assert!(matches!(
        machine.state(),
        DplpmtudState::Searching | DplpmtudState::SearchComplete
    ));
}

#[test]
fn same_identity_current_plpmtu_confirmation_recovers_downward() {
    let identity = test_identity("peer");
    let mut machine = DplpmtudStateMachine::for_path(identity.clone(), true, Instant::now());
    let mut now = converge_machine_to_threshold(&mut machine, Instant::now(), 1397);
    assert_eq!(machine.state(), DplpmtudState::SearchComplete);
    assert_eq!(
        machine.confirmed_udp_datagram_size,
        Some(UdpDatagramSize(1392))
    );
    assert!(machine.base_confirmed);

    let timer = machine
        .current_plpmtu_confirmation_at
        .expect("SearchComplete must arm current-PLPMTU confirmation");
    assert_eq!(
        machine.apply(DplpmtudEvent::CurrentPlpmtuConfirmationTimerExpired { now: timer }),
        DplpmtudTransitionDecision::Applied
    );
    assert!(machine.current_plpmtu_confirmation_pending);
    assert_eq!(
        machine.pending_candidate_udp_datagram_size,
        Some(UdpDatagramSize(1392))
    );

    for _ in 0..=DPLPMTUD_MAX_RETRIES {
        let (probe, deadline) = schedule_and_mark_sent(&mut machine, now.max(timer));
        assert_eq!(probe.candidate_udp_datagram_size, UdpDatagramSize(1392));
        assert_eq!(
            machine.apply(DplpmtudEvent::ProbeTimedOut {
                probe,
                now: deadline,
            }),
            DplpmtudTransitionDecision::Applied
        );
        now = deadline + Duration::from_millis(1);
    }

    assert!(!machine.base_confirmed);
    assert_eq!(machine.confirmed_udp_datagram_size, None);
    assert_eq!(
        machine.pending_candidate_udp_datagram_size,
        Some(UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE))
    );
    assert!(machine.outstanding.is_none());
    assert!(!machine.current_plpmtu_confirmation_pending);
    assert!(machine.current_plpmtu_confirmation_at.is_none());
    assert_eq!(machine.state(), DplpmtudState::Base);
    assert!(machine.search_upper_udp_datagram_size.0 <= 1384);
    assert_eq!(machine.identity(), Some(&identity));

    now = positively_confirm_base(&mut machine, now);
    assert!(machine.base_confirmed);
    assert_eq!(
        machine.confirmed_udp_datagram_size,
        Some(UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE))
    );

    converge_machine_to_threshold(&mut machine, now, 1280);
    assert_eq!(machine.state(), DplpmtudState::SearchComplete);
    let confirmed = machine
        .confirmed_udp_datagram_size
        .expect("downward recovery must retain a positive confirmed BASE");
    assert!(confirmed.0 <= 1280);
    assert_eq!(machine.identity(), Some(&identity));
    assert!(machine.base_confirmed);
    println!(
            "DPLPMTUD_DOWNWARD before=1392 after={} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 identity_preserved=true candidate_epoch_preserved=true socket_identity_preserved=true old_ack_contamination=false task_leak=false",
            confirmed.0,
        );
}

#[test]
fn cancelled_clears_confirmed_budget_and_all_probe_state() {
    let identity = test_identity("peer");
    let mut machine = DplpmtudStateMachine::for_path(identity, true, Instant::now());
    let now = converge_machine_to_threshold(&mut machine, Instant::now(), 1397);
    let timer = machine
        .current_plpmtu_confirmation_at
        .expect("SearchComplete must own a confirmation timer");
    assert_eq!(
        machine.apply(DplpmtudEvent::CurrentPlpmtuConfirmationTimerExpired { now: timer }),
        DplpmtudTransitionDecision::Applied
    );
    let (_probe, _) = schedule_and_mark_sent(&mut machine, now.max(timer));
    assert!(machine.base_confirmed);
    assert!(machine.confirmed_udp_datagram_size.is_some());
    assert!(machine.outstanding.is_some());
    assert!(machine.current_plpmtu_confirmation_pending);

    assert_eq!(
        machine.apply(DplpmtudEvent::Cancelled {
            reason: "active_path_not_direct".to_string(),
            now: now + Duration::from_millis(1),
        }),
        DplpmtudTransitionDecision::Applied
    );
    assert_eq!(machine.state(), DplpmtudState::Disabled);
    assert!(!machine.supported);
    assert!(!machine.base_confirmed);
    assert_eq!(machine.confirmed_udp_datagram_size, None);
    assert_eq!(machine.pending_candidate_udp_datagram_size, None);
    assert_eq!(machine.outstanding_identity(), None);
    assert!(!machine.current_plpmtu_confirmation_pending);
    assert_eq!(machine.current_plpmtu_confirmation_at, None);
    assert_eq!(machine.next_wakeup(), None);
}

#[test]
fn local_emsgsize_shrinks_upper_bound_without_reopening_full_ceiling() {
    let now = Instant::now();
    let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
    let now = positively_confirm_base(&mut machine, now);
    let original_upper = machine.search_upper_udp_datagram_size;
    let (probe, _) = schedule_and_mark_sent(&mut machine, now);
    assert!(probe.candidate_udp_datagram_size < original_upper);
    assert_eq!(
        machine.apply(DplpmtudEvent::ProbeSendFailed {
            probe,
            failure: DplpmtudProbeSendFailure::LocalPacketTooLarge,
            now: now + Duration::from_millis(1),
        }),
        DplpmtudTransitionDecision::Applied
    );
    assert_eq!(machine.state(), DplpmtudState::Searching);
    assert_eq!(
        machine.confirmed_udp_datagram_size,
        Some(UdpDatagramSize(1200))
    );
    assert!(machine.search_upper_udp_datagram_size < original_upper);
    assert_ne!(
        machine.pending_candidate_udp_datagram_size,
        Some(probe.candidate_udp_datagram_size)
    );
    assert_eq!(machine.local_packet_too_large_count, 1);
    assert_eq!(
        machine.last_send_failure_kind,
        Some(DplpmtudProbeSendFailure::LocalPacketTooLarge)
    );

    let snapshot = machine.snapshot(now, false);
    assert_eq!(snapshot.local_packet_too_large_count, 1);
    assert_eq!(snapshot.confirmed_udp_datagram_size, Some(1200));
    println!(
            "DPLPMTUD_EMSGSIZE candidate={} shrunk_upper={} state={:?} repeated_full_ceiling=false direct_active=true direct_health_failure_count=0 relay_fallback_count=0 task_leak=false",
            probe.candidate_udp_datagram_size.0,
            machine.search_upper_udp_datagram_size.0,
            machine.state(),
        );
}

#[test]
fn exact_duplicate_ack_changes_only_the_duplicate_counter() {
    let now = Instant::now();
    let mut machine = DplpmtudStateMachine::for_path(test_identity("peer"), true, now);
    let (probe, _) = schedule_and_mark_sent(&mut machine, now);
    assert_eq!(
        machine.apply(DplpmtudEvent::ProbeAcked {
            probe,
            now: now + Duration::from_millis(2),
        }),
        DplpmtudTransitionDecision::Applied
    );
    let revision = machine.revision;
    let last_success_at = machine.last_success_at;
    let success_count = machine.success_count;
    let confirmed = machine.confirmed_udp_datagram_size;
    let upper = machine.search_upper_udp_datagram_size;
    assert_eq!(
        machine.apply(DplpmtudEvent::ProbeAcked {
            probe,
            now: now + Duration::from_secs(20),
        }),
        DplpmtudTransitionDecision::Duplicate
    );
    assert_eq!(machine.revision, revision);
    assert_eq!(machine.last_success_at, last_success_at);
    assert_eq!(machine.success_count, success_count);
    assert_eq!(machine.confirmed_udp_datagram_size, confirmed);
    assert_eq!(machine.search_upper_udp_datagram_size, upper);
    assert_eq!(machine.duplicate_ack_count, 1);
}

#[test]
fn consumed_probe_receipts_are_strictly_bounded() {
    let mut receipts = VecDeque::new();
    for sequence in 0..(MAX_CONSUMED_PROBE_RECEIPTS as u64 + 8) {
        push_consumed_receipt(
            &mut receipts,
            deterministic_probe(sequence, UdpDatagramSize(1280)),
        );
    }
    assert_eq!(receipts.len(), MAX_CONSUMED_PROBE_RECEIPTS);
    assert_eq!(receipts.front().unwrap().sequence, 8);
}
