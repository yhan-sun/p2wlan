use super::{
    hard_hard_birthday_candidates, hard_hard_birthday_capacity_plan,
    hard_hard_birthday_packets_planned, hard_hard_birthday_socket_plan,
    hard_hard_birthday_wave_assignments, hard_hard_birthday_wave_count,
    record_birthday_worker_result, BirthdaySweepFailureKind, HardHardSocketSnapshot,
    ProbeSendFailureKind, PunchSendReport,
};

use crate::error::DaemonError;

use p2pnet_nat::mapping::AllocationModelKind;

use std::collections::{HashMap, HashSet};

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[test]
fn birthday_levels_are_exact_and_never_scan_the_full_port_ring() {
    let public_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    for (level, token) in [(64, "android"), (128, "android-2"), (256, "desktop")] {
        let candidates = hard_hard_birthday_candidates(
            public_ip,
            &[40_000, 40_001, 40_002, 40_003],
            level,
            token,
        );
        assert_eq!(candidates.len(), level);
        assert!(candidates
            .iter()
            .all(|candidate| { candidate.ip() == public_ip && candidate.port() != 0 }));
        let unique = candidates
            .iter()
            .map(SocketAddr::port)
            .collect::<HashSet<_>>();
        assert_eq!(unique.len(), level);
        assert!(level < usize::from(u16::MAX));
    }
}

#[test]
fn birthday_diagnostics_keep_unknown_distinct_from_high_entropy() {
    assert_eq!(AllocationModelKind::Unknown.label(), "unknown");
    assert_eq!(AllocationModelKind::HighEntropy.label(), "high_entropy");
    assert_ne!(
        AllocationModelKind::Unknown.label(),
        AllocationModelKind::HighEntropy.label()
    );
}

#[test]
fn probe_failure_kinds_keep_precise_terminal_stop_reasons() {
    let cases = [
        (ProbeSendFailureKind::PhysicalSend, "send_error"),
        (
            ProbeSendFailureKind::NetworkGenerationChanged,
            "network_generation_changed",
        ),
        (
            ProbeSendFailureKind::CandidateEpochChanged,
            "candidate_epoch_changed",
        ),
        (
            ProbeSendFailureKind::LocalProfileGenerationChanged,
            "profile_generation_changed",
        ),
        (
            ProbeSendFailureKind::RemoteProfileGenerationChanged,
            "profile_generation_changed",
        ),
        (
            ProbeSendFailureKind::PeerSessionChanged,
            "peer_session_changed",
        ),
        (ProbeSendFailureKind::SessionRetired, "session_retired"),
        (
            ProbeSendFailureKind::SocketUnavailable,
            "socket_unavailable",
        ),
        (ProbeSendFailureKind::SocketRevoked, "socket_revoked"),
        (
            ProbeSendFailureKind::ProbeRegistrationFailed,
            "probe_registration_failed",
        ),
        (
            ProbeSendFailureKind::ProbeEncodingFailed,
            "probe_encoding_failed",
        ),
    ];
    for (probe_failure, stop_reason) in cases {
        let failure = BirthdaySweepFailureKind::from_probe_failure(probe_failure);
        assert_eq!(failure.stop_reason(), stop_reason);
        assert_eq!(
            BirthdaySweepFailureKind::from_stop_reason(stop_reason),
            Some(failure)
        );
    }
}

#[test]
fn birthday_two_waves_rotate_targets_without_socket_cartesian_product() {
    for (socket_count, level) in [(2, 64), (4, 128), (8, 256)] {
        let targets = (1..=level)
            .map(|port| SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port as u16))
            .collect::<Vec<_>>();
        assert_eq!(hard_hard_birthday_wave_count(socket_count), 2);
        let first = hard_hard_birthday_wave_assignments(socket_count, targets.clone(), 0);
        let second = hard_hard_birthday_wave_assignments(socket_count, targets.clone(), 1);
        assert_eq!(first.len(), socket_count);
        assert_eq!(second.len(), socket_count);
        for assignments in [&first, &second] {
            let flattened = assignments.iter().flatten().copied().collect::<Vec<_>>();
            assert_eq!(flattened.len(), level);
            assert_eq!(flattened.iter().collect::<HashSet<_>>().len(), level);
            assert!(flattened.iter().all(|target| targets.contains(target)));
        }
        let first_socket = first
            .iter()
            .enumerate()
            .flat_map(|(socket, assigned)| assigned.iter().map(move |target| (*target, socket)))
            .collect::<HashMap<_, _>>();
        let second_socket = second
            .iter()
            .enumerate()
            .flat_map(|(socket, assigned)| assigned.iter().map(move |target| (*target, socket)))
            .collect::<HashMap<_, _>>();
        assert!(targets
            .iter()
            .all(|target| first_socket[target] != second_socket[target]));
    }
    assert_eq!(hard_hard_birthday_wave_count(1), 1);
    assert_eq!(hard_hard_birthday_wave_count(0), 0);
    assert_eq!(hard_hard_birthday_packets_planned(2, 64), 128);
    assert_eq!(hard_hard_birthday_packets_planned(4, 96), 192);
    assert_eq!(hard_hard_birthday_packets_planned(1, 96), 96);
}

#[test]
fn birthday_capacity_plan_preserves_cap_and_exposes_downgrade() {
    assert_eq!(hard_hard_birthday_capacity_plan(64, 2), Some((64, 2)));
    assert_eq!(hard_hard_birthday_capacity_plan(128, 3), Some((64, 2)));
    assert_eq!(hard_hard_birthday_capacity_plan(256, 7), Some((128, 4)));
    assert_eq!(hard_hard_birthday_capacity_plan(256, 8), Some((256, 8)));
    assert_eq!(hard_hard_birthday_capacity_plan(256, 1), None);
}

#[test]
fn birthday_socket_plan_is_exact_and_fails_closed() {
    let partial = hard_hard_birthday_socket_plan(
        64,
        vec![
            HardHardSocketSnapshot {
                socket_index: 41,
                attached: true,
                usable: true,
            },
            HardHardSocketSnapshot {
                socket_index: 42,
                attached: true,
                usable: false,
            },
        ],
    );
    assert_eq!(partial.requested_socket_count, 2);
    assert_eq!(partial.attached_socket_count, 2);
    assert_eq!(partial.usable_socket_count, 1);
    assert_eq!(partial.unavailable_socket_count, 1);
    assert_eq!(partial.usable_socket_indices, vec![41]);
    assert_eq!(
        hard_hard_birthday_wave_count(partial.usable_socket_count),
        1
    );

    let detached = hard_hard_birthday_socket_plan(
        64,
        vec![
            HardHardSocketSnapshot {
                socket_index: 41,
                attached: false,
                usable: false,
            },
            HardHardSocketSnapshot {
                socket_index: 42,
                attached: false,
                usable: false,
            },
        ],
    );
    assert_eq!(detached.attached_socket_count, 0);
    assert_eq!(detached.usable_socket_count, 0);
    assert_eq!(detached.unavailable_socket_count, 2);
    assert!(detached.usable_socket_indices.is_empty());
    assert_eq!(
        hard_hard_birthday_wave_count(detached.usable_socket_count),
        0
    );

    let full = hard_hard_birthday_socket_plan(
        128,
        (0..4)
            .map(|offset| HardHardSocketSnapshot {
                socket_index: 100 + offset,
                attached: true,
                usable: true,
            })
            .collect(),
    );
    assert_eq!(full.requested_socket_count, 4);
    assert_eq!(full.attached_socket_count, 4);
    assert_eq!(full.usable_socket_count, 4);
    assert_eq!(full.unavailable_socket_count, 0);
    assert_eq!(hard_hard_birthday_wave_count(full.usable_socket_count), 2);

    let capped = hard_hard_birthday_socket_plan(
        256,
        (0..4)
            .map(|offset| HardHardSocketSnapshot {
                socket_index: 200 + offset,
                attached: true,
                usable: true,
            })
            .collect(),
    );
    assert_eq!(capped.requested_socket_count, 8);
    assert_eq!(capped.usable_socket_count, 4);
    assert_eq!(capped.unavailable_socket_count, 4);
    assert_eq!(capped.usable_socket_indices, vec![200, 201, 202, 203]);
}

#[tokio::test]
async fn birthday_worker_collection_preserves_partial_stats_and_join_errors() {
    let mut wave_report = PunchSendReport::default();
    let mut wave_fully_completed = true;
    let mut failure_kind = None;
    record_birthday_worker_result(
        &mut wave_report,
        &mut wave_fully_completed,
        &mut failure_kind,
        Ok((
            2,
            Ok(PunchSendReport {
                packets_sent: 1,
                per_socket_sent: vec![(41, 2)],
                targets_assigned: 2,
                targets_attempted: 2,
                target_processing_completed: true,
                ..PunchSendReport::default()
            }),
        )),
    );
    assert_eq!(wave_report.packets_sent, 1);
    assert_eq!(wave_report.per_socket_sent, vec![(41, 2)]);
    assert!(wave_fully_completed);
    assert_eq!(failure_kind, None);

    record_birthday_worker_result(
        &mut wave_report,
        &mut wave_fully_completed,
        &mut failure_kind,
        Ok((
            3,
            Err(DaemonError::Network("injected worker error".to_string())),
        )),
    );
    assert_eq!(wave_report.packets_sent, 1);
    assert_eq!(wave_report.per_socket_sent, vec![(41, 2)]);
    assert_eq!(wave_report.targets_cancelled, 3);
    assert_eq!(wave_report.probe_path_errors, 1);
    assert!(!wave_fully_completed);
    assert_eq!(
        failure_kind,
        Some(BirthdaySweepFailureKind::ProbeRegistrationFailed)
    );

    let handle = tokio::spawn(async { std::future::pending::<()>().await });
    handle.abort();
    let join_error = handle
        .await
        .expect_err("aborted worker must yield JoinError");
    record_birthday_worker_result(
        &mut wave_report,
        &mut wave_fully_completed,
        &mut failure_kind,
        Err(join_error),
    );
    assert!(!wave_fully_completed);
    assert_eq!(failure_kind, Some(BirthdaySweepFailureKind::WorkerJoin));
    assert_eq!(wave_report.packets_sent, 1);
    assert_eq!(wave_report.per_socket_sent, vec![(41, 2)]);
}
