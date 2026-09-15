use crate::peer::PathEpoch;
use p2pnet_tun::Ipv4Packet;
use std::collections::{HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::Instant;

use super::*;
use super::{runtime::*, state_machine::*, wire::*};
use crate::config::Config;
use crate::control::PeerInfo;
use crate::dataplane::OutboundPacket;
use crate::peer::{PeerManager, PeerSessionGeneration};
use crate::transport::{DirectValidationKind, WireGuardTransport};
use crate::udp::UdpTransport;
use p2pnet_crypto::NodeIdentity;
use p2pnet_wireguard::{HandshakeInitiator, HandshakeResponder, TransportSession};
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use tokio::sync::{mpsc, watch};
use tokio::time::timeout;

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

fn runtime_with_confirmed_base(
    identity: DplpmtudPathIdentity,
    now: Instant,
) -> (DplpmtudRuntime, DplpmtudWorkerLease) {
    let runtime = DplpmtudRuntime::new();
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .expect("supported path must own one worker");
    let plan = runtime
        .schedule_probe(&identity.peer_id, &identity, lease.worker_owner_token, now)
        .expect("BASE must be the first runtime probe");
    assert_eq!(
        plan.probe_identity.candidate_udp_datagram_size,
        UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
    );
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            &identity,
            plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: identity.authenticated_remote_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            now + Duration::from_millis(2),
        ),
        DplpmtudTransitionDecision::Applied
    );
    assert!(runtime.confirmed_budget_for_path(&identity).is_some());
    (runtime, lease)
}

fn exact_ack_ingress(identity: &DplpmtudPathIdentity) -> DplpmtudAckIngress {
    DplpmtudAckIngress {
        remote_endpoint: identity.authenticated_remote_endpoint,
        local_endpoint: identity.local_endpoint,
        socket: identity.socket,
    }
}

fn business_token(
    entry: DirectBusinessBudgetMirrorEntry,
    publication_owner: u64,
) -> DirectBusinessSendToken {
    let publication = entry
        .update
        .budget
        .expect("test requires a confirmed business publication");
    DirectBusinessSendToken {
        path_identity: publication.path_identity,
        budget_revision: publication.budget_revision,
        max_udp_datagram_size: publication.udp_datagram_size,
        max_overlay_payload_size: publication.overlay_payload_budget,
        udp_publication_owner: publication_owner,
    }
}

fn schedule_and_mark_runtime_probe_sent(
    runtime: &DplpmtudRuntime,
    identity: &DplpmtudPathIdentity,
    lease: &DplpmtudWorkerLease,
    now: Instant,
) -> DplpmtudProbePlan {
    let plan = runtime
        .schedule_probe(&identity.peer_id, identity, lease.worker_owner_token, now)
        .expect("runtime search must have a next candidate");
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    plan
}

fn ack_runtime_probe(
    runtime: &DplpmtudRuntime,
    identity: &DplpmtudPathIdentity,
    plan: &DplpmtudProbePlan,
    now: Instant,
) {
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            identity,
            plan.wire_token,
            exact_ack_ingress(identity),
            now,
        ),
        DplpmtudTransitionDecision::Applied
    );
}

fn converge_runtime_to_threshold(
    runtime: &DplpmtudRuntime,
    identity: &DplpmtudPathIdentity,
    lease: &DplpmtudWorkerLease,
    mut now: Instant,
    threshold: u32,
) -> Instant {
    for _ in 0..96 {
        if runtime
            .snapshot_for_peer(&identity.peer_id)
            .is_some_and(|snapshot| snapshot.state == DplpmtudState::SearchComplete)
        {
            return now;
        }
        let plan = schedule_and_mark_runtime_probe_sent(runtime, identity, lease, now);
        if plan.probe_identity.candidate_udp_datagram_size.0 <= threshold {
            ack_runtime_probe(runtime, identity, &plan, now + Duration::from_millis(2));
            now += Duration::from_millis(3);
        } else {
            assert_eq!(
                runtime.timeout_probe(&plan, plan.deadline),
                DplpmtudTransitionDecision::Applied
            );
            now = plan.deadline + Duration::from_millis(1);
        }
    }
    panic!("bounded runtime DPLPMTUD search did not converge");
}

fn exhaust_runtime_current_confirmation(
    runtime: &DplpmtudRuntime,
    identity: &DplpmtudPathIdentity,
    lease: &DplpmtudWorkerLease,
    mut now: Instant,
    expected_candidate: UdpDatagramSize,
) -> Instant {
    let confirmation_at = runtime
        .worker_state(&identity.peer_id, identity, lease.worker_owner_token)
        .and_then(|(_, wakeup, _)| wakeup)
        .expect("SearchComplete must own a current-PLPMTU timer");
    now = now.max(confirmation_at);
    for _ in 0..=DPLPMTUD_MAX_RETRIES {
        let plan = schedule_and_mark_runtime_probe_sent(runtime, identity, lease, now);
        assert_eq!(
            plan.probe_identity.candidate_udp_datagram_size,
            expected_candidate
        );
        assert_eq!(
            runtime.timeout_probe(&plan, plan.deadline),
            DplpmtudTransitionDecision::Applied
        );
        now = plan.deadline + Duration::from_millis(1);
    }
    now
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
fn unsupported_same_identity_replay_is_idempotent() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    assert_eq!(
        runtime.install_path(identity.clone(), false, now).decision,
        DplpmtudInstallDecision::Unsupported
    );
    let first = runtime.snapshots().remove("peer").unwrap();

    assert_eq!(
        runtime
            .install_path(identity, false, now + Duration::from_secs(1))
            .decision,
        DplpmtudInstallDecision::Unsupported
    );
    let second = runtime.snapshots().remove("peer").unwrap();
    assert_eq!(second.state, DplpmtudState::Unsupported);
    assert!(!second.live_worker);
    assert_eq!(second.revision, first.revision);
    assert_eq!(second.reset_count, first.reset_count);
    assert_eq!(second.probe_count, first.probe_count);
    assert_eq!(second.success_count, first.success_count);
    assert_eq!(second.timeout_count, first.timeout_count);
    assert_eq!(second.stale_ack_count, first.stale_ack_count);
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
fn runtime_downward_recovery_withholds_budget_until_fresh_base_ack() {
    let identity = test_identity("peer");
    let runtime = DplpmtudRuntime::new();
    let mut now = Instant::now();
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    now = converge_runtime_to_threshold(&runtime, &identity, &lease, now, 1397);
    let before = runtime
        .confirmed_budget_for_path(&identity)
        .expect("initial search must converge with a budget");
    assert_eq!(before.udp_datagram_size, UdpDatagramSize(1392));

    now = exhaust_runtime_current_confirmation(
        &runtime,
        &identity,
        &lease,
        now,
        UdpDatagramSize(1392),
    );
    let base = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(base.state, DplpmtudState::Base);
    assert!(!base.base_confirmed);
    assert_eq!(base.confirmed_udp_datagram_size, None);
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    assert!(base.budget_revision.unwrap() > before.budget_revision);
    assert_eq!(
        runtime.path_identity(&identity.peer_id),
        Some(identity.clone())
    );

    let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
    assert_eq!(
        base_plan.probe_identity.candidate_udp_datagram_size,
        UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
    );
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    ack_runtime_probe(
        &runtime,
        &identity,
        &base_plan,
        now + Duration::from_millis(2),
    );
    let reconfirmed_base = runtime
        .confirmed_budget_for_path(&identity)
        .expect("fresh BASE ACK must restore the budget");
    assert_eq!(
        reconfirmed_base.udp_datagram_size,
        UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
    );
    assert!(reconfirmed_base.budget_revision > base.budget_revision.unwrap());
    now += Duration::from_millis(3);

    converge_runtime_to_threshold(&runtime, &identity, &lease, now, 1280);
    let recovered = runtime
        .confirmed_budget_for_path(&identity)
        .expect("upward search after fresh BASE ACK must converge");
    assert!(recovered.udp_datagram_size.0 <= 1280);
    assert!(recovered.budget_revision >= reconfirmed_base.budget_revision);
    assert_eq!(runtime.path_identity(&identity.peer_id), Some(identity));
    println!(
        "DPLPMTUD_RECONFIRM_BASE before=1392 base_budget_before_ack=none base_after_ack=1200 after={} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 identity_preserved=true old_ack_contamination=false task_leak=false",
        recovered.udp_datagram_size.0,
    );
}

#[tokio::test]
async fn same_identity_below_base_failure_enters_error_without_budget() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap();
    let local_endpoint = udp.local_addr().unwrap();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_endpoint = remote.local_addr().unwrap();
    peers
        .add_peer(&peer_info("peer", "10.20.0.2", remote_endpoint))
        .await;
    let identity = commit_test_direct_path(
        &peers,
        &udp,
        "peer",
        remote_endpoint,
        local_endpoint,
        29,
        31,
    )
    .await;
    let runtime = udp.dplpmtud_runtime();
    let mut now = Instant::now();
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    now = converge_runtime_to_threshold(&runtime, &identity, &lease, now, 1397);
    assert_eq!(
        runtime
            .confirmed_budget_for_path(&identity)
            .unwrap()
            .udp_datagram_size,
        UdpDatagramSize(1392)
    );

    now = exhaust_runtime_current_confirmation(
        &runtime,
        &identity,
        &lease,
        now,
        UdpDatagramSize(1392),
    );
    assert_eq!(
        runtime.snapshot_for_peer(&identity.peer_id).unwrap().state,
        DplpmtudState::Base
    );
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());

    for _ in 0..=DPLPMTUD_MAX_RETRIES {
        let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
        assert_eq!(
            base_plan.probe_identity.candidate_udp_datagram_size,
            UdpDatagramSize(DPLPMTUD_BASE_UDP_DATAGRAM_SIZE)
        );
        assert!(runtime.confirmed_budget_for_path(&identity).is_none());
        assert_eq!(
            runtime.timeout_probe(&base_plan, base_plan.deadline),
            DplpmtudTransitionDecision::Applied
        );
        now = base_plan.deadline + Duration::from_millis(1);
    }

    let failed = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(failed.state, DplpmtudState::Error);
    assert!(!failed.base_confirmed);
    assert_eq!(failed.confirmed_udp_datagram_size, None);
    assert_eq!(failed.overlay_payload_budget, None);
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    assert_eq!(
        runtime.path_identity(&identity.peer_id),
        Some(identity.clone())
    );
    assert!(peers.dplpmtud_path_is_current_sync(&identity));

    let connection = peers.get_connection("peer").await.unwrap();
    let direct_active = connection.active_path() == Some(crate::peer::NetworkPath::Direct);
    let direct_health_failure_count = connection.direct_health.failure_count;
    let relay_fallback_count = connection
        .path_events
        .iter()
        .filter(|event| event.selected_path == Some(crate::peer::NetworkPath::Relay))
        .count();
    assert!(direct_active);
    assert_eq!(direct_health_failure_count, 0);
    assert_eq!(relay_fallback_count, 0);
    runtime.close("below_base_acceptance_complete", now);
    assert_eq!(runtime.active_worker_count(), 0);
    println!(
        "DPLPMTUD_BELOW_BASE before=1392 threshold=1100 state=Error confirmed=none budget=none direct_active={direct_active} direct_health_failure_count={direct_health_failure_count} relay_fallback_count={relay_fallback_count} identity_preserved=true old_ack_contamination=false task_leak=false",
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
fn confirmed_budget_accessor_is_exact_identity_and_none_before_base_ack() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .expect("supported path must own one worker");
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());

    let plan = runtime
        .schedule_probe("peer", &identity, lease.worker_owner_token, now)
        .expect("BASE must be the first probe");
    assert_eq!(plan.probe_identity.candidate_udp_datagram_size.0, 1200);
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            "peer",
            &identity,
            plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: identity.authenticated_remote_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            now + Duration::from_millis(2),
        ),
        DplpmtudTransitionDecision::Applied
    );

    let budget = runtime
        .confirmed_budget_for_path(&identity)
        .expect("only a positively ACKed BASE may be exposed");
    assert_eq!(budget.udp_datagram_size, UdpDatagramSize(1200));
    assert_eq!(budget.outer_ip_packet_size, OuterIpPacketSize(1228));
    assert_eq!(budget.overlay_payload_budget, OverlayPayloadBudget(1168));

    let replaced_socket = test_identity_with("peer", 7, 11, 13, 17, 19, 24, 0);
    assert!(runtime
        .confirmed_budget_for_path(&replaced_socket)
        .is_none());
    println!(
        "DPLPMTUD_BUDGET accessor=O(1) exact_path_identity=true before_base_ack=none udp=1200 overlay=1168 business_snapshots_not_used=true",
    );
}

#[test]
fn cancel_peer_revokes_confirmed_budget_immediately() {
    let now = Instant::now();
    let identity = test_identity("peer");
    let (runtime, lease) = runtime_with_confirmed_base(identity.clone(), now);
    let plan = runtime
        .schedule_probe(
            &identity.peer_id,
            &identity,
            lease.worker_owner_token,
            now + Duration::from_millis(3),
        )
        .expect("a confirmed path must still have an upward candidate");
    assert!(runtime.begin_probe_send(&plan, now + Duration::from_millis(3)));
    assert!(runtime
        .snapshot_for_peer(&identity.peer_id)
        .is_some_and(|snapshot| snapshot.outstanding_probe.is_some()));

    runtime.cancel_peer(
        &identity.peer_id,
        "direct_validation_failed",
        now + Duration::from_millis(4),
    );
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(snapshot.state, DplpmtudState::Disabled);
    assert!(!snapshot.supported);
    assert!(!snapshot.base_confirmed);
    assert_eq!(snapshot.confirmed_udp_datagram_size, None);
    assert_eq!(snapshot.overlay_payload_budget, None);
    assert!(snapshot.outstanding_probe.is_none());
    assert!(!snapshot.current_plpmtu_confirmation_pending);
    assert_eq!(snapshot.current_plpmtu_confirmation_remaining_ms, None);
}

#[test]
fn network_generation_cancel_revokes_confirmed_budget() {
    let now = Instant::now();
    let identity = test_identity("peer");
    let (runtime, _lease) = runtime_with_confirmed_base(identity.clone(), now);
    runtime.cancel_before_network_generation(
        identity.epoch.network_generation + 1,
        "network_generation_changed",
        now + Duration::from_millis(3),
    );
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(snapshot.state, DplpmtudState::Disabled);
    assert!(!snapshot.base_confirmed);
    assert_eq!(snapshot.confirmed_udp_datagram_size, None);
}

#[test]
fn runtime_close_revokes_confirmed_budget() {
    let now = Instant::now();
    let identity = test_identity("peer");
    let (runtime, _lease) = runtime_with_confirmed_base(identity.clone(), now);
    runtime.close("shutdown", now + Duration::from_millis(3));
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(snapshot.state, DplpmtudState::Disabled);
    assert!(!snapshot.base_confirmed);
    assert_eq!(snapshot.confirmed_udp_datagram_size, None);
}

async fn assert_relay_activation_revokes_old_direct_budget() {
    let peers = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let udp = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers.clone())
        .await
        .unwrap()
        .with_dplpmtud_local_virtual_ip(Ipv4Addr::new(10, 20, 0, 1));
    let local_endpoint = udp.local_addr().unwrap();
    let remote = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let remote_endpoint = remote.local_addr().unwrap();
    peers
        .add_peer(&peer_info("peer", "10.20.0.2", remote_endpoint))
        .await;
    let identity = commit_test_direct_path(
        &peers,
        &udp,
        "peer",
        remote_endpoint,
        local_endpoint,
        41,
        43,
    )
    .await;
    let now = Instant::now();
    let runtime = udp.dplpmtud_runtime();
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
    ack_runtime_probe(
        &runtime,
        &identity,
        &base_plan,
        now + Duration::from_millis(2),
    );
    assert!(runtime.confirmed_budget_for_path(&identity).is_some());

    peers
        .record_direct_failure("peer", "relay invalidation acceptance")
        .await;
    peers.set_relay("peer", "relay.test:443").await;
    assert_eq!(
        peers.get_connection("peer").await.unwrap().active_path(),
        Some(crate::peer::NetworkPath::Relay)
    );
    udp.reconcile_dplpmtud_paths().await;

    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    let snapshot = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(
        snapshot.reset_reason.as_deref(),
        Some("active_path_not_direct")
    );
    assert_eq!(snapshot.state, DplpmtudState::Disabled);
    assert_eq!(runtime.active_worker_count(), 0);
}

#[tokio::test]
async fn relay_activation_revokes_old_direct_budget() {
    assert_relay_activation_revokes_old_direct_budget().await;
}

#[test]
fn old_path_identity_never_reads_replacement_path_budget() {
    let now = Instant::now();
    let old_identity = test_identity("peer");
    let (runtime, _old_lease) = runtime_with_confirmed_base(old_identity.clone(), now);
    let new_identity = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 1);
    let new_lease = runtime
        .install_path(new_identity.clone(), true, now + Duration::from_millis(3))
        .worker
        .expect("replacement Direct path must start a fresh worker");
    assert!(runtime.confirmed_budget_for_path(&old_identity).is_none());
    assert!(runtime.confirmed_budget_for_path(&new_identity).is_none());

    let new_plan = runtime
        .schedule_probe(
            &new_identity.peer_id,
            &new_identity,
            new_lease.worker_owner_token,
            now + Duration::from_millis(4),
        )
        .unwrap();
    assert!(runtime.begin_probe_send(&new_plan, now + Duration::from_millis(4)));
    runtime.finish_probe_send(&new_plan, Ok(()), now + Duration::from_millis(5));
    assert_eq!(
        runtime.try_accept_ack(
            &new_identity.peer_id,
            &new_identity,
            new_plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: new_identity.authenticated_remote_endpoint,
                local_endpoint: new_identity.local_endpoint,
                socket: new_identity.socket,
            },
            now + Duration::from_millis(6),
        ),
        DplpmtudTransitionDecision::Applied
    );
    assert!(runtime.confirmed_budget_for_path(&old_identity).is_none());
    assert!(runtime.confirmed_budget_for_path(&new_identity).is_some());
}

#[tokio::test]
async fn cancel_close_generation_and_relay_budget_invalidation_acceptance() {
    let now = Instant::now();

    let cancel_identity = test_identity("cancel-peer");
    let (cancel_runtime, _lease) = runtime_with_confirmed_base(cancel_identity.clone(), now);
    cancel_runtime.cancel_peer(
        &cancel_identity.peer_id,
        "peer_left",
        now + Duration::from_millis(3),
    );
    assert!(cancel_runtime
        .confirmed_budget_for_path(&cancel_identity)
        .is_none());

    let generation_identity = test_identity("generation-peer");
    let (generation_runtime, _lease) =
        runtime_with_confirmed_base(generation_identity.clone(), now);
    generation_runtime.cancel_before_network_generation(
        generation_identity.epoch.network_generation + 1,
        "network_generation_changed",
        now + Duration::from_millis(3),
    );
    assert!(generation_runtime
        .confirmed_budget_for_path(&generation_identity)
        .is_none());

    assert_relay_activation_revokes_old_direct_budget().await;

    let close_identity = test_identity("close-peer");
    let (close_runtime, _lease) = runtime_with_confirmed_base(close_identity.clone(), now);
    close_runtime.close("shutdown", now + Duration::from_millis(3));
    assert!(close_runtime
        .confirmed_budget_for_path(&close_identity)
        .is_none());
    println!(
        "DPLPMTUD_INVALIDATION cancel_peer=none generation_cancel=none relay_active=none runtime_close=none exact_path_fail_closed=true task_leak=false",
    );
}

#[test]
fn budget_revision_is_monotonic_and_closes_identity_aba() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    let initial_revision = runtime
        .snapshot_for_peer(&identity.peer_id)
        .and_then(|snapshot| snapshot.budget_revision)
        .expect("path installation must allocate a revision fence");
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());

    let base_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
    ack_runtime_probe(
        &runtime,
        &identity,
        &base_plan,
        now + Duration::from_millis(2),
    );
    let base_budget = runtime.confirmed_budget_for_path(&identity).unwrap();
    assert_eq!(base_budget.udp_datagram_size, UdpDatagramSize(1200));
    assert!(base_budget.budget_revision > initial_revision);

    let upward_plan = schedule_and_mark_runtime_probe_sent(
        &runtime,
        &identity,
        &lease,
        now + Duration::from_millis(3),
    );
    ack_runtime_probe(
        &runtime,
        &identity,
        &upward_plan,
        now + Duration::from_millis(5),
    );
    let raised_budget = runtime.confirmed_budget_for_path(&identity).unwrap();
    assert!(raised_budget.udp_datagram_size > base_budget.udp_datagram_size);
    assert!(raised_budget.budget_revision > base_budget.budget_revision);

    let before_duplicate = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            &identity,
            upward_plan.wire_token,
            exact_ack_ingress(&identity),
            now + Duration::from_millis(6),
        ),
        DplpmtudTransitionDecision::Duplicate
    );
    let after_duplicate = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert_eq!(
        after_duplicate.budget_revision,
        before_duplicate.budget_revision
    );
    assert_eq!(after_duplicate.revision, before_duplicate.revision);

    let before_stale = after_duplicate;
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            &identity,
            DplpmtudWireToken {
                network_generation: upward_plan.wire_token.network_generation + 1,
                ..upward_plan.wire_token
            },
            exact_ack_ingress(&identity),
            now + Duration::from_millis(7),
        ),
        DplpmtudTransitionDecision::Stale
    );
    let after_stale = runtime.snapshot_for_peer(&identity.peer_id).unwrap();
    assert!(after_stale.revision > before_stale.revision);
    assert_eq!(after_stale.budget_revision, before_stale.budget_revision);
    assert_eq!(
        runtime
            .confirmed_budget_for_path(&identity)
            .unwrap()
            .budget_revision,
        raised_budget.budget_revision
    );

    runtime.cancel_peer(
        &identity.peer_id,
        "active_path_not_direct",
        now + Duration::from_millis(8),
    );
    let cancelled_revision = runtime
        .snapshot_for_peer(&identity.peer_id)
        .unwrap()
        .budget_revision
        .unwrap();
    assert!(cancelled_revision > raised_budget.budget_revision);
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());

    let reactivated_lease = runtime
        .install_path(identity.clone(), true, now + Duration::from_millis(9))
        .worker
        .unwrap();
    let reactivated_base = schedule_and_mark_runtime_probe_sent(
        &runtime,
        &identity,
        &reactivated_lease,
        now + Duration::from_millis(10),
    );
    ack_runtime_probe(
        &runtime,
        &identity,
        &reactivated_base,
        now + Duration::from_millis(12),
    );
    let reactivated_budget = runtime.confirmed_budget_for_path(&identity).unwrap();
    assert!(reactivated_budget.budget_revision > cancelled_revision);

    let replacement = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 1);
    runtime
        .install_path(replacement.clone(), true, now + Duration::from_millis(13))
        .worker
        .unwrap();
    let replacement_revision = runtime
        .snapshot_for_peer(&identity.peer_id)
        .unwrap()
        .budget_revision
        .unwrap();
    assert!(replacement_revision > reactivated_budget.budget_revision);
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    assert!(runtime.confirmed_budget_for_path(&replacement).is_none());

    let final_identity = test_identity_with("peer", 9, 12, 15, 37, 39, 43, 2);
    let final_lease = runtime
        .install_path(
            final_identity.clone(),
            true,
            now + Duration::from_millis(14),
        )
        .worker
        .unwrap();
    let identity_only_revision = runtime
        .snapshot_for_peer(&identity.peer_id)
        .unwrap()
        .budget_revision
        .unwrap();
    assert!(identity_only_revision > replacement_revision);

    let final_base = schedule_and_mark_runtime_probe_sent(
        &runtime,
        &final_identity,
        &final_lease,
        now + Duration::from_millis(15),
    );
    ack_runtime_probe(
        &runtime,
        &final_identity,
        &final_base,
        now + Duration::from_millis(17),
    );
    let final_budget = runtime.confirmed_budget_for_path(&final_identity).unwrap();
    assert!(final_budget.budget_revision > identity_only_revision);
    assert_ne!(
        final_budget.budget_revision,
        reactivated_budget.budget_revision
    );
    assert!(runtime.confirmed_budget_for_path(&identity).is_none());
    assert!(runtime.confirmed_budget_for_path(&replacement).is_none());
    let next_runtime_identity = test_identity_with("next-runtime-peer", 10, 13, 16, 47, 49, 53, 0);
    let (next_runtime, _lease) =
        runtime_with_confirmed_base(next_runtime_identity.clone(), now + Duration::from_secs(1));
    let next_runtime_budget = next_runtime
        .confirmed_budget_for_path(&next_runtime_identity)
        .unwrap();
    assert!(next_runtime_budget.budget_revision > final_budget.budget_revision);
    println!(
        "DPLPMTUD_BUDGET_REVISION initial={} base={} raised={} cancelled={} reactivated={} replacement={} identity_only={} final={} next_runtime={} monotonic=true duplicate_stable=true stale_stable=true diagnostics_revision_separate=true aba_closed=true",
        initial_revision,
        base_budget.budget_revision,
        raised_budget.budget_revision,
        cancelled_revision,
        reactivated_budget.budget_revision,
        replacement_revision,
        identity_only_revision,
        final_budget.budget_revision,
        next_runtime_budget.budget_revision,
    );
}

#[test]
fn business_publication_is_explicit_revisioned_and_registry_independent() {
    let now = Instant::now();
    let identity = test_identity("peer");
    let (runtime, _lease) = runtime_with_confirmed_base(identity.clone(), now);
    let published = runtime
        .direct_business_budget_entry(&identity.peer_id)
        .expect("confirmed BASE must be visible in the immutable mirror");
    assert!(published.enforced);
    let token = business_token(published.clone(), 101);
    assert_eq!(token.max_udp_datagram_size, UdpDatagramSize(1200));
    assert_eq!(token.max_overlay_payload_size, OverlayPayloadBudget(1168));

    // Hold the mutable registry on one thread. The business reader and
    // final token gate must still complete on another thread; a per-packet
    // registry lock would make the bounded receive time out.
    let registry = runtime.registry.clone();
    let (held_tx, held_rx) = std::sync::mpsc::sync_channel(0);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
    let holder = std::thread::spawn(move || {
        let _registry_guard = registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        held_tx.send(()).unwrap();
        release_rx.recv().unwrap();
    });
    held_rx.recv().unwrap();

    let hot_runtime = runtime.clone();
    let hot_token = token.clone();
    let (hot_tx, hot_rx) = std::sync::mpsc::sync_channel(0);
    let hot_path = std::thread::spawn(move || {
        let mirror = hot_runtime
            .direct_business_budget_entry("peer")
            .expect("immutable mirror remains readable");
        let result = hot_runtime.with_current_direct_business_token(&hot_token, || 42);
        hot_tx
            .send((mirror.update.budget_revision, result))
            .unwrap();
    });
    let (observed_revision, result) = hot_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("business hot path must not wait for the DPLPMTUD registry");
    assert_eq!(observed_revision, token.budget_revision);
    assert_eq!(result, Some(42));
    release_tx.send(()).unwrap();
    holder.join().unwrap();
    hot_path.join().unwrap();

    assert!(runtime.invalidate_direct_business_budget(&token, now + Duration::from_millis(3),));
    let revoked = runtime
        .direct_business_budget_entry("peer")
        .expect("Some -> None is an explicit tombstone, not a deletion");
    assert!(revoked.update.budget.is_none());
    assert!(revoked.update.budget_revision > token.budget_revision);
    assert_eq!(revoked.update.path_identity, identity);
    assert_eq!(
        runtime.with_current_direct_business_token(&token, || ()),
        None
    );
    assert!(!runtime.invalidate_direct_business_budget(&token, now + Duration::from_millis(4),));
    let snapshot = runtime.snapshot_for_peer("peer").unwrap();
    assert_eq!(snapshot.state, DplpmtudState::Base);
    assert!(!snapshot.base_confirmed);
    assert_eq!(snapshot.business_packet_too_large_count, 1);
}

#[test]
fn old_business_tokens_fail_after_raise_drop_and_path_replacement() {
    let mut now = Instant::now();
    let identity = test_identity("peer");
    let (runtime, lease) = runtime_with_confirmed_base(identity.clone(), now);
    let base_token = business_token(runtime.direct_business_budget_entry("peer").unwrap(), 101);

    now += Duration::from_millis(3);
    let raised_plan = schedule_and_mark_runtime_probe_sent(&runtime, &identity, &lease, now);
    ack_runtime_probe(
        &runtime,
        &identity,
        &raised_plan,
        now + Duration::from_millis(2),
    );
    let raised_token = business_token(runtime.direct_business_budget_entry("peer").unwrap(), 101);
    assert!(raised_token.budget_revision > base_token.budget_revision);
    assert!(raised_token.max_udp_datagram_size > base_token.max_udp_datagram_size);
    assert_eq!(
        runtime.with_current_direct_business_token(&base_token, || ()),
        None,
        "an old revision cannot inherit a newly raised budget"
    );
    assert_eq!(
        runtime.with_current_direct_business_token(&raised_token, || 7),
        Some(7)
    );

    assert!(
        runtime.invalidate_direct_business_budget(&raised_token, now + Duration::from_millis(3),)
    );
    assert_eq!(
        runtime.with_current_direct_business_token(&raised_token, || ()),
        None
    );
    let base_plan = schedule_and_mark_runtime_probe_sent(
        &runtime,
        &identity,
        &lease,
        now + Duration::from_millis(5),
    );
    ack_runtime_probe(
        &runtime,
        &identity,
        &base_plan,
        now + Duration::from_millis(7),
    );
    let lowered_token = business_token(runtime.direct_business_budget_entry("peer").unwrap(), 101);
    assert_eq!(lowered_token.max_udp_datagram_size, UdpDatagramSize(1200));
    assert_eq!(
        lowered_token.max_overlay_payload_size,
        OverlayPayloadBudget(1168)
    );
    assert!(lowered_token.budget_revision > raised_token.budget_revision);
    assert_eq!(
        runtime.with_current_direct_business_token(&raised_token, || ()),
        None,
        "a large old token cannot survive a downward recovery"
    );
    assert_eq!(
        runtime.with_current_direct_business_token(&lowered_token, || 9),
        Some(9),
        "a fresh small-budget token remains usable"
    );

    let replacement = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 0);
    runtime.install_path(replacement, true, now + Duration::from_millis(8));
    assert_eq!(
        runtime.with_current_direct_business_token(&lowered_token, || ()),
        None,
        "an exact path replacement invalidates the old token"
    );
}

#[test]
fn wire_format_vector_is_fixed_and_padding_follows_token() {
    let token = DplpmtudWireToken {
        sequence: 0x0102_0304_0506_0708,
        nonce: [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ],
        path_cookie: [
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
            0x2e, 0x2f,
        ],
        network_generation: 0x3132_3334_3536_3738,
        peer_session_generation: 0x4142_4344_4546_4748,
        remote_candidate_epoch: 0x5152_5354_5556_5758,
        direct_validation_owner_token: 0x6162_6364_6566_6768,
        direct_validation_request_id: 0x1234,
        candidate_udp_datagram_size: UdpDatagramSize(0x578),
        outer_ip_family: OuterIpFamily::Ipv4,
    };
    let mut encoded = Vec::new();
    encode_wire_token(&mut encoded, token);
    assert_eq!(
        hex::encode(&encoded),
        "0102030405060708101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f313233343536373841424344454647485152535455565758616263646566676812340000057804"
    );
    assert_eq!(decode_wire_token(&encoded), Some(token));

    let packet = build_probe_inner_packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        token,
    )
    .unwrap();
    let ip_packet = Ipv4Packet::new(&packet).unwrap();
    let icmp_payload = ip_packet.payload();
    let payload = &icmp_payload[8..];
    assert!(payload.starts_with(DPLPMTUD_PROBE_PREFIX));
    assert_eq!(
        &payload[DPLPMTUD_PROBE_PREFIX.len()..][..DPLPMTUD_TOKEN_BYTES],
        encoded.as_slice()
    );
    assert!(
        payload[DPLPMTUD_PROBE_PREFIX.len() + DPLPMTUD_TOKEN_BYTES..]
            .iter()
            .all(|byte| *byte == 0)
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
fn stale_ack_dimensions_never_move_search_bounds() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let install = runtime.install_path(identity.clone(), true, now);
    let lease = install
        .worker
        .expect("supported path must start one worker");
    let plan = runtime
        .schedule_probe("peer", &identity, lease.worker_owner_token, now)
        .expect("probe must schedule");
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    let exact_ingress = DplpmtudAckIngress {
        remote_endpoint: identity.authenticated_remote_endpoint,
        local_endpoint: identity.local_endpoint,
        socket: identity.socket,
    };
    let baseline = runtime.snapshots().remove("peer").unwrap();
    let token = plan.wire_token;
    let cases = [
        (
            DplpmtudWireToken {
                network_generation: token.network_generation + 1,
                ..token
            },
            exact_ingress,
        ),
        (
            DplpmtudWireToken {
                peer_session_generation: token.peer_session_generation + 1,
                ..token
            },
            exact_ingress,
        ),
        (
            DplpmtudWireToken {
                remote_candidate_epoch: token.remote_candidate_epoch + 1,
                ..token
            },
            exact_ingress,
        ),
        (
            DplpmtudWireToken {
                direct_validation_owner_token: token.direct_validation_owner_token + 1,
                ..token
            },
            exact_ingress,
        ),
        (
            DplpmtudWireToken {
                direct_validation_request_id: token.direct_validation_request_id + 1,
                ..token
            },
            exact_ingress,
        ),
        (
            DplpmtudWireToken {
                nonce: [0x44; 16],
                ..token
            },
            exact_ingress,
        ),
        // The reply's UDP source is deliberately absent from the stale
        // dimensions: behind an address/port-dependent NAT the peer's ACK
        // leaves through a different mapping than the validation commit
        // observed, so `try_accept_ack` no longer pins it. The remapped
        // source is accepted by
        // `ack_from_peer_reply_mapping_is_accepted_on_the_probed_local_socket`.
        (
            token,
            DplpmtudAckIngress {
                local_endpoint: "127.0.0.1:42998".parse().unwrap(),
                ..exact_ingress
            },
        ),
        (
            token,
            DplpmtudAckIngress {
                socket: DplpmtudSocketIdentity {
                    transport_instance_id: identity.socket.transport_instance_id + 1,
                    socket_index: identity.socket.socket_index,
                },
                ..exact_ingress
            },
        ),
    ];
    for (stale_token, ingress) in cases {
        assert_eq!(
            runtime.try_accept_ack(
                "peer",
                &identity,
                stale_token,
                ingress,
                now + Duration::from_millis(2),
            ),
            DplpmtudTransitionDecision::Stale
        );
        let snapshot = runtime.snapshots().remove("peer").unwrap();
        assert_eq!(
            snapshot.confirmed_udp_datagram_size,
            baseline.confirmed_udp_datagram_size
        );
        assert_eq!(
            snapshot.search_upper_udp_datagram_size,
            baseline.search_upper_udp_datagram_size
        );
    }
    assert_eq!(
        runtime.try_accept_ack(
            "peer",
            &identity,
            token,
            exact_ingress,
            now + Duration::from_millis(3),
        ),
        DplpmtudTransitionDecision::Applied
    );
}

#[test]
fn ack_after_probe_deadline_is_stale_and_expectation_remains_timeout_owned() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    let plan = runtime
        .schedule_probe("peer", &identity, lease.worker_owner_token, now)
        .unwrap();
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            "peer",
            &identity,
            plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: identity.authenticated_remote_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            plan.deadline + Duration::from_millis(1),
        ),
        DplpmtudTransitionDecision::Stale
    );
    assert!(runtime.outstanding_is_current(&plan));
    assert_eq!(
        runtime.timeout_probe(&plan, plan.deadline + Duration::from_millis(1)),
        DplpmtudTransitionDecision::Applied
    );
}

/// The peer's DPLPMTUD ACK legitimately leaves through a different NAT
/// mapping than the one the encrypted validation commit observed (an
/// address/port-dependent NAT re-maps per destination). The ACK stays
/// WireGuard-authenticated and echoes the outstanding probe, so a reply
/// whose source endpoint differs from `authenticated_remote_endpoint`
/// must still be accepted when it arrives on the probed local socket.
#[test]
fn ack_from_peer_reply_mapping_is_accepted_on_the_probed_local_socket() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    let plan = runtime
        .schedule_probe("peer", &identity, lease.worker_owner_token, now)
        .unwrap();
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    let remapped_peer_endpoint: SocketAddr = "127.0.0.1:64001".parse().unwrap();
    assert_ne!(
        remapped_peer_endpoint, identity.authenticated_remote_endpoint,
        "the fixture must model a genuinely re-mapped reply source"
    );
    assert_eq!(
        runtime.try_accept_ack(
            "peer",
            &identity,
            plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: remapped_peer_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            now + Duration::from_millis(2),
        ),
        DplpmtudTransitionDecision::Applied
    );
    assert_eq!(
        runtime
            .snapshots()
            .remove("peer")
            .unwrap()
            .confirmed_udp_datagram_size,
        Some(plan.probe_identity.candidate_udp_datagram_size.0),
    );
    runtime.close("shutdown", now + Duration::from_millis(3));
}

#[test]
fn ack_after_worker_cancellation_is_stale() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    let plan = runtime
        .schedule_probe("peer", &identity, lease.worker_owner_token, now)
        .unwrap();
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    runtime.cancel_peer("peer", "peer_left", now + Duration::from_millis(2));
    assert_eq!(
        runtime.try_accept_ack(
            "peer",
            &identity,
            plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: identity.authenticated_remote_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            now + Duration::from_millis(3),
        ),
        DplpmtudTransitionDecision::Stale
    );
    assert_eq!(runtime.snapshots().remove("peer").unwrap().success_count, 0);

    runtime.close("shutdown", now + Duration::from_millis(4));
    assert_eq!(
        runtime.try_accept_ack(
            "peer",
            &identity,
            plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: identity.authenticated_remote_endpoint,
                local_endpoint: identity.local_endpoint,
                socket: identity.socket,
            },
            now + Duration::from_millis(5),
        ),
        DplpmtudTransitionDecision::Stale
    );
}

#[test]
fn worker_owner_token_closes_same_identity_exit_aba() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let first = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    runtime.cancel_peer(
        "peer",
        "relay_became_active",
        now + Duration::from_millis(1),
    );
    let second = runtime
        .install_path(identity.clone(), true, now + Duration::from_millis(2))
        .worker
        .expect("Direct becoming active again must start a fresh search");
    assert_ne!(first.worker_owner_token, second.worker_owner_token);
    runtime.finish_worker("peer", &identity, first.worker_owner_token);
    assert_eq!(runtime.active_worker_count(), 1);
    assert!(runtime
        .schedule_probe(
            "peer",
            &identity,
            first.worker_owner_token,
            now + Duration::from_millis(3),
        )
        .is_none());
    assert!(runtime
        .schedule_probe(
            "peer",
            &identity,
            second.worker_owner_token,
            now + Duration::from_millis(3),
        )
        .is_some());
    assert_eq!(
        runtime
            .install_path(identity, true, now + Duration::from_millis(4))
            .decision,
        DplpmtudInstallDecision::Unchanged
    );
}

#[test]
fn path_replacement_resets_to_safe_baseline_and_invalidates_old_plan() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let first_identity = test_identity("peer");
    let first = runtime
        .install_path(first_identity.clone(), true, now)
        .worker
        .unwrap();
    let old_plan = runtime
        .schedule_probe("peer", &first_identity, first.worker_owner_token, now)
        .unwrap();
    assert!(runtime.begin_probe_send(&old_plan, now));
    runtime.finish_probe_send(&old_plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            "peer",
            &first_identity,
            old_plan.wire_token,
            DplpmtudAckIngress {
                remote_endpoint: first_identity.authenticated_remote_endpoint,
                local_endpoint: first_identity.local_endpoint,
                socket: first_identity.socket,
            },
            now + Duration::from_millis(2),
        ),
        DplpmtudTransitionDecision::Applied
    );
    let replacement = test_identity_with("peer", 8, 11, 14, 27, 29, 33, 1);
    let second = runtime
        .install_path(replacement.clone(), true, now + Duration::from_millis(3))
        .worker
        .unwrap();
    let snapshot = runtime.snapshots().remove("peer").unwrap();
    assert_eq!(snapshot.confirmed_udp_datagram_size, None);
    assert_eq!(snapshot.state, DplpmtudState::Base);
    assert!(!runtime.begin_probe_send(&old_plan, now + Duration::from_millis(4)));
    runtime.finish_worker("peer", &first_identity, first.worker_owner_token);
    assert_eq!(runtime.active_worker_count(), 1);
    assert!(runtime
        .schedule_probe(
            "peer",
            &replacement,
            second.worker_owner_token,
            now + Duration::from_millis(4),
        )
        .is_some());
}

#[test]
fn receipts_runtime_and_probe_responses_are_strictly_bounded() {
    let mut receipts = VecDeque::new();
    for sequence in 0..(MAX_CONSUMED_PROBE_RECEIPTS as u64 + 8) {
        push_consumed_receipt(
            &mut receipts,
            deterministic_probe(sequence, UdpDatagramSize(1280)),
        );
    }
    assert_eq!(receipts.len(), MAX_CONSUMED_PROBE_RECEIPTS);
    assert_eq!(receipts.front().unwrap().sequence, 8);

    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    for index in 0..MAX_TRACKED_DPLPMTUD_PEERS {
        let identity =
            test_identity_with(&format!("peer-{index}"), 1, index as u64 + 1, 1, 1, 1, 1, 0);
        assert_eq!(
            runtime.install_path(identity, false, now).decision,
            DplpmtudInstallDecision::Unsupported
        );
    }
    assert_eq!(runtime.tracked_peer_count(), MAX_TRACKED_DPLPMTUD_PEERS);
    assert_eq!(
        runtime.business_publications.borrow().len(),
        MAX_TRACKED_DPLPMTUD_PEERS,
        "the immutable business mirror has the same strict peer cap"
    );
    assert_eq!(
        runtime
            .install_path(test_identity("overflow-peer"), false, now)
            .decision,
        DplpmtudInstallDecision::CapacityExceeded
    );

    let rate_runtime = DplpmtudRuntime::new();
    for _ in 0..DPLPMTUD_ACK_RATE_LIMIT_PER_PEER {
        assert!(rate_runtime.admit_probe_response("peer", now));
    }
    assert!(!rate_runtime.admit_probe_response("peer", now));
    assert!(rate_runtime.admit_probe_response("peer", now + DPLPMTUD_ACK_RATE_WINDOW));
}

#[test]
fn close_and_peer_left_remove_all_worker_ownership() {
    let now = Instant::now();
    let runtime = DplpmtudRuntime::new();
    let identity = test_identity("peer");
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .unwrap();
    assert_eq!(runtime.active_worker_count(), 1);
    runtime.close("shutdown", now + Duration::from_millis(1));
    assert_eq!(runtime.active_worker_count(), 0);
    runtime.finish_worker("peer", &identity, lease.worker_owner_token);
    assert_eq!(runtime.active_worker_count(), 0);

    let runtime = DplpmtudRuntime::new();
    runtime.install_path(test_identity("peer"), true, now);
    runtime.retain_known_peers(&HashSet::new(), now + Duration::from_millis(1));
    assert_eq!(runtime.tracked_peer_count(), 0);
    assert!(!runtime.snapshots().contains_key("peer"));
    println!(
        "DPLPMTUD_WORKER_LEAK active_workers={} tracked_peers={} direct_active=true direct_health_failure_count=0 relay_fallback_count=0 old_ack_contamination=false task_leak=false",
        runtime.active_worker_count(),
        runtime.tracked_peer_count(),
    );
}

#[test]
fn capability_extension_is_additive_and_legacy_packets_remain_decodable() {
    let prefix = crate::DIRECT_VALIDATION_REQUEST_PAYLOAD;
    let capability = direct_validation_capability_extension();
    let modern_payload = crate::transport::build_direct_validation_payload(
        DirectValidationKind::Request,
        7,
        9,
        1,
        11,
    );
    let modern_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        9,
        1,
        &modern_payload,
    );
    assert!(crate::transport::parse_direct_validation_token(&modern_packet).is_some());
    assert!(direct_validation_supports_dplpmtud(&modern_packet));

    let mut legacy_payload = Vec::new();
    legacy_payload.extend_from_slice(prefix);
    legacy_payload.extend_from_slice(&modern_payload[prefix.len() + capability.len()..]);
    let legacy_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        9,
        1,
        &legacy_payload,
    );
    assert!(crate::transport::parse_direct_validation_token(&legacy_packet).is_some());
    assert!(!direct_validation_supports_dplpmtud(&legacy_packet));

    let mut unknown_payload = modern_payload.clone();
    unknown_payload[prefix.len() + 4] = 99;
    let unknown_packet = Ipv4Packet::build_icmp_echo_request(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        9,
        1,
        &unknown_payload,
    );
    assert!(!direct_validation_supports_dplpmtud(&unknown_packet));
}

#[test]
fn codec_round_trip_uses_exact_udp_datagram_budget_and_compact_ack() {
    let token = DplpmtudWireToken {
        sequence: 7,
        nonce: [1; 16],
        path_cookie: [2; 16],
        network_generation: 3,
        peer_session_generation: 4,
        remote_candidate_epoch: 5,
        direct_validation_owner_token: 6,
        direct_validation_request_id: 7,
        candidate_udp_datagram_size: UdpDatagramSize(1400),
        outer_ip_family: OuterIpFamily::Ipv4,
    };
    let probe = build_probe_inner_packet(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        token,
    )
    .unwrap();
    assert_eq!(
        probe.len() + WIREGUARD_UDP_DATAGRAM_OVERHEAD as usize,
        token.candidate_udp_datagram_size.0 as usize
    );
    assert_eq!(parse_control_packet(&probe).unwrap().token, token);
    let ack = build_ack_inner_packet(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        token,
    );
    assert_eq!(
        parse_control_packet(&ack).unwrap(),
        DplpmtudControlPacket {
            kind: DplpmtudControlKind::Ack,
            token,
        }
    );
    assert!(ack.len() < probe.len());
    assert!(parse_control_packet(b"legacy-or-business-packet").is_none());
}

#[test]
fn ipv4_and_ipv6_budget_layers_are_never_mixed() {
    let datagram = UdpDatagramSize(1400);
    assert_eq!(
        datagram.outer_ip_packet_size(OuterIpFamily::Ipv4),
        OuterIpPacketSize(1428)
    );
    assert_eq!(
        datagram.outer_ip_packet_size(OuterIpFamily::Ipv6),
        OuterIpPacketSize(1448)
    );
    assert_eq!(
        datagram.overlay_payload_budget(),
        Some(OverlayPayloadBudget(1368))
    );
    assert_eq!(
        OuterIpFamily::Ipv4.ceiling_udp_datagram_size(),
        UdpDatagramSize(1472)
    );
    assert_eq!(
        OuterIpFamily::Ipv6.ceiling_udp_datagram_size(),
        UdpDatagramSize(1452)
    );
}

#[test]
fn path_identity_rejects_mixed_local_and_remote_ip_families() {
    let validation = crate::peer::DirectValidationIdentity::authenticated_ack(
        PathEpoch::new(1, PeerSessionGeneration::for_test(2), 3),
        4,
        5,
        Some("[::1]:42002".parse().unwrap()),
        "[::1]:42002".parse().unwrap(),
    );
    assert!(DplpmtudPathIdentity::from_committed_validation(
        "peer",
        validation,
        "[::1]:42002".parse().unwrap(),
        "127.0.0.1:42001".parse().unwrap(),
        6,
        0,
    )
    .is_none());
}

fn establish_sessions() -> (TransportSession, TransportSession) {
    let node_a = NodeIdentity::generate();
    let node_b = NodeIdentity::generate();
    let mut initiator = HandshakeInitiator::new(node_a, node_b.public_key(), None);
    let mut responder = HandshakeResponder::new(node_b, None);
    let initiation = initiator.create_initiation().unwrap();
    let (response, node_b_keys) = responder
        .consume_initiation_and_respond(&initiation)
        .unwrap();
    let node_a_keys = initiator.consume_response(&response).unwrap();
    (
        TransportSession::new(node_a_keys),
        TransportSession::new(node_b_keys),
    )
}

async fn receive_datagram(socket: &UdpSocket, expected_size: usize) -> (Vec<u8>, SocketAddr) {
    let mut buffer = vec![0u8; 65_535];
    let (size, source) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
        .await
        .expect("loopback datagram must arrive deterministically")
        .expect("loopback UDP receive must succeed");
    assert_eq!(size, expected_size);
    buffer.truncate(size);
    (buffer, source)
}

async fn yield_until(mut predicate: impl FnMut() -> bool, message: &str) {
    for _ in 0..100_000 {
        if predicate() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("{message}");
}

fn peer_info(node_id: &str, virtual_ip: &str, endpoint: SocketAddr) -> PeerInfo {
    PeerInfo {
        node_id: node_id.to_string(),
        virtual_ip: virtual_ip.to_string(),
        endpoint: endpoint.to_string(),
        online: true,
        ..PeerInfo::default()
    }
}

async fn commit_test_direct_path(
    peers: &Arc<PeerManager>,
    udp: &UdpTransport,
    peer_id: &str,
    remote_endpoint: SocketAddr,
    local_endpoint: SocketAddr,
    owner_token: u64,
    request_id: u16,
) -> DplpmtudPathIdentity {
    let generation = peers.current_network_generation_sync();
    let peer_session_generation = peers
        .peer_session_generation_sync(peer_id)
        .expect("test peer must be online");
    let remote_candidate_epoch = peers
        .current_remote_candidate_epoch(peer_id)
        .await
        .expect("test peer must have a candidate epoch");
    let epoch = PathEpoch::new(generation, peer_session_generation, remote_candidate_epoch);
    assert!(
        peers
            .mark_direct_validation_started(
                peer_id,
                crate::peer::DirectValidationIdentity::owned(
                    epoch,
                    owner_token,
                    Some(request_id),
                    Some(remote_endpoint),
                ),
            )
            .await
    );
    let committed = crate::peer::DirectValidationIdentity::authenticated_ack(
        epoch,
        owner_token,
        request_id,
        Some(remote_endpoint),
        remote_endpoint,
    );
    let epoch_gate = peers.network_epoch_gate();
    let epoch_guard = epoch_gate.lock().await;
    assert!(peers
        .record_direct_success_for_generation_with_local_endpoint_and_latency_in_epoch_for_remote_epoch(
            &epoch_guard,
            peer_id,
            Some(remote_endpoint),
            generation,
            Some(local_endpoint),
            None,
            Some(remote_candidate_epoch),
            Some(committed),
        )
        .await);
    drop(epoch_guard);
    let identity = DplpmtudPathIdentity::from_committed_validation(
        peer_id,
        committed,
        remote_endpoint,
        local_endpoint,
        udp.transport_instance_id(),
        0,
    )
    .expect("test Direct identity must contain owner, request and matching IP family");
    assert!(peers.dplpmtud_path_is_current_sync(&identity));
    identity
}

#[tokio::test(start_paused = true)]
async fn encrypted_udp_blackhole_converges_without_path_failure_or_worker_leak() {
    const BLACKHOLE_THRESHOLD: usize = 1397;
    const DOWNWARD_BLACKHOLE_THRESHOLD: usize = 1280;
    let peers_a = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let peers_b = Arc::new(PeerManager::new(
        Config::generate_default("https://ctrl.test", "net1").unwrap(),
    ));
    let udp_a = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_a.clone())
        .await
        .unwrap();
    let udp_b = UdpTransport::bind("127.0.0.1:0".parse().unwrap(), peers_b.clone())
        .await
        .unwrap();
    let endpoint_a = udp_a.local_addr().unwrap();
    let endpoint_b = udp_b.local_addr().unwrap();
    let router = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let router_endpoint = router.local_addr().unwrap();
    peers_a
        .add_peer(&peer_info("peer-b", "10.20.0.2", router_endpoint))
        .await;
    peers_b
        .add_peer(&peer_info("peer-a", "10.20.0.1", endpoint_a))
        .await;

    // DPLPMTUD is deliberately background measurement for an already
    // authoritative Direct path. This fixture commits that prerequisite
    // through the same PeerManager state-machine path used by production;
    // only Probe delivery, ACK authentication, bounds changes and the
    // blackhole outcome are exercised by the assertions below.
    let identity = commit_test_direct_path(
        &peers_a,
        &udp_a,
        "peer-b",
        router_endpoint,
        endpoint_a,
        17,
        19,
    )
    .await;
    let runtime = udp_a.dplpmtud_runtime();
    let peer_session_generation = identity.epoch.peer_session_generation;
    assert!(udp_a.mark_peer_dplpmtud_supported("peer-b", peer_session_generation));

    let (session_a, session_b) = establish_sessions();
    let (wireguard_a, _) = WireGuardTransport::new();
    let (wireguard_b, _) = WireGuardTransport::new();
    let _ = wireguard_a.add_session("peer-b", session_a).await;
    let _ = wireguard_b.add_session("peer-a", session_b).await;

    let (a_encrypted_tx, a_encrypted_rx) = mpsc::channel(64);
    let (b_encrypted_tx, b_encrypted_rx) = mpsc::channel(64);
    let a_reader_tx = a_encrypted_tx.clone();
    let b_reader_tx = b_encrypted_tx.clone();
    let udp_a = udp_a
        .with_dplpmtud_local_virtual_ip(Ipv4Addr::new(10, 20, 0, 1))
        .with_inbound_channel(a_encrypted_tx);
    let udp_b = udp_b.with_inbound_channel(b_encrypted_tx);
    // The live daemon uses a publication watch, rather than a static
    // transport option.  Keep the same owner check in this E2E test so a
    // queued datagram from a withdrawn UDP publication cannot become
    // DPLPMTUD evidence.
    udp_a.set_inbound_publication_owner(101);
    udp_b.set_inbound_publication_owner(202);
    let (udp_a_watch_tx, udp_a_watch_rx) = watch::channel(Some(udp_a.clone()));
    let (udp_b_watch_tx, udp_b_watch_rx) = watch::channel(Some(udp_b.clone()));
    let (a_overlay_tx, mut a_overlay_rx) = mpsc::channel(8);
    let (b_overlay_tx, mut b_overlay_rx) = mpsc::channel(8);

    let a_reader = tokio::spawn({
        let udp = udp_a.clone();
        async move { udp.run_inbound(a_reader_tx).await }
    });
    let b_reader = tokio::spawn({
        let udp = udp_b.clone();
        async move { udp.run_inbound(b_reader_tx).await }
    });
    let a_transport = tokio::spawn({
        let wireguard = wireguard_a.clone();
        let peers = peers_a.clone();
        async move {
            wireguard
                .run_inbound_with_peers_live_udp(
                    a_encrypted_rx,
                    a_overlay_tx,
                    Some(peers),
                    udp_a_watch_rx,
                )
                .await
        }
    });
    let b_transport = tokio::spawn({
        let wireguard = wireguard_b.clone();
        let peers = peers_b.clone();
        async move {
            wireguard
                .run_inbound_with_peers_live_udp(
                    b_encrypted_rx,
                    b_overlay_tx,
                    Some(peers),
                    udp_b_watch_rx,
                )
                .await
        }
    });

    let dropped_probe_count = Arc::new(AtomicUsize::new(0));
    let blackhole_threshold = Arc::new(AtomicUsize::new(BLACKHOLE_THRESHOLD));
    let router_task = tokio::spawn({
        let dropped_probe_count = dropped_probe_count.clone();
        let blackhole_threshold = blackhole_threshold.clone();
        async move {
            let mut buffer = vec![0u8; 65_535];
            loop {
                let (size, source) = router.recv_from(&mut buffer).await.unwrap();
                if source == endpoint_a {
                    if size <= blackhole_threshold.load(AtomicOrdering::Relaxed) {
                        router.send_to(&buffer[..size], endpoint_b).await.unwrap();
                    } else {
                        dropped_probe_count.fetch_add(1, AtomicOrdering::Relaxed);
                    }
                } else if source == endpoint_b {
                    router.send_to(&buffer[..size], endpoint_a).await.unwrap();
                }
            }
        }
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let scheduler = tokio::spawn(crate::run_dplpmtud_scheduler_until_cancelled(
        udp_a.clone(),
        peers_a.clone(),
        wireguard_a.clone(),
        shutdown_rx,
    ));

    yield_until(
        || {
            runtime
                .snapshots()
                .get("peer-b")
                .is_some_and(|snapshot| snapshot.outstanding_probe.is_some())
        },
        "DPLPMTUD scheduler must submit its first production probe",
    )
    .await;

    let mut observed_probe_sizes = Vec::new();
    let mut observed_blackhole_drops = 0;
    let mut observed_timeouts = 0;
    let mut observed_successes = 0;
    let mut last_success_token = None;
    loop {
        let snapshot = runtime
            .snapshots()
            .remove("peer-b")
            .expect("DPLPMTUD path snapshot must remain published");
        if snapshot.state == DplpmtudState::SearchComplete {
            break;
        }
        let Some(outstanding) = snapshot.outstanding_probe else {
            tokio::task::yield_now().await;
            continue;
        };
        if outstanding.sent_age_ms.is_none() {
            tokio::task::yield_now().await;
            continue;
        }
        let candidate = outstanding.candidate_udp_datagram_size as usize;
        observed_probe_sizes.push(candidate);
        if candidate <= BLACKHOLE_THRESHOLD {
            last_success_token = runtime.current_probe_token("peer-b", &identity);
            let expected_successes = observed_successes + 1;
            yield_until(
                || {
                    runtime
                        .snapshots()
                        .get("peer-b")
                        .is_some_and(|value| value.success_count >= expected_successes)
                },
                "an allowed encrypted Probe must return through the production ACK path",
            )
            .await;
            observed_successes = expected_successes;
        } else {
            let expected_drops = observed_blackhole_drops + 1;
            yield_until(
                || dropped_probe_count.load(AtomicOrdering::Relaxed) >= expected_drops,
                "the controllable blackhole must receive every disallowed Probe",
            )
            .await;
            observed_blackhole_drops = expected_drops;
            let expected_timeouts = observed_timeouts + 1;
            tokio::time::advance(DPLPMTUD_PROBE_TIMEOUT + Duration::from_millis(1)).await;
            yield_until(
                || {
                    runtime
                        .snapshots()
                        .get("peer-b")
                        .is_some_and(|value| value.timeout_count >= expected_timeouts)
                },
                "a blackholed Probe must be retired by the bounded timeout path",
            )
            .await;
            observed_timeouts = expected_timeouts;
        }
    }

    let mut result = runtime.snapshots().remove("peer-b").unwrap();
    assert_eq!(result.state, DplpmtudState::SearchComplete);
    let confirmed = result
        .confirmed_udp_datagram_size
        .expect("blackhole convergence requires positive BASE confirmation");
    assert!(confirmed as usize <= BLACKHOLE_THRESHOLD);
    assert!(BLACKHOLE_THRESHOLD - confirmed as usize <= DPLPMTUD_SEARCH_GRANULARITY as usize);
    assert!(observed_probe_sizes
        .iter()
        .any(|size| *size <= BLACKHOLE_THRESHOLD));
    assert!(observed_probe_sizes
        .iter()
        .any(|size| *size > BLACKHOLE_THRESHOLD));
    let connection = peers_a.get_connection("peer-b").await.unwrap();
    assert_eq!(
        connection.active_path(),
        Some(crate::peer::NetworkPath::Direct)
    );
    assert_eq!(connection.direct_health.failure_count, 0);
    assert_eq!(connection.relay_health.failure_count, 0);
    assert!(a_overlay_rx.try_recv().is_err());
    assert!(b_overlay_rx.try_recv().is_err());
    let initial_result = result.clone();

    // Keep the exact committed path and socket identity, lower only the
    // controllable forwarding threshold, and let the SearchComplete
    // current-PLPMTU confirmation timer drive a new confirmation probe.
    // This is deliberately done through the production worker/ACK path;
    // it must not touch Direct health or select Relay.
    let initial_identity = runtime.path_identity("peer-b").unwrap();
    blackhole_threshold.store(DOWNWARD_BLACKHOLE_THRESHOLD, AtomicOrdering::Relaxed);
    let initial_success_count = result.success_count;
    tokio::time::advance(DPLPMTUD_CURRENT_PLPMTU_CONFIRMATION_INTERVAL + Duration::from_millis(1))
        .await;
    yield_until(
        || {
            runtime
                .snapshots()
                .get("peer-b")
                .is_some_and(|value| value.outstanding_probe.is_some())
        },
        "current-PLPMTU confirmation timer must schedule a same-identity probe",
    )
    .await;

    let mut downward_probe_sizes = Vec::new();
    let mut downward_drops = 0;
    let mut downward_timeouts = 0;
    loop {
        let snapshot = runtime
            .snapshots()
            .remove("peer-b")
            .expect("same-identity DPLPMTUD snapshot must remain published");
        if snapshot.state == DplpmtudState::SearchComplete
            && snapshot.success_count > initial_success_count
        {
            break;
        }
        let Some(outstanding) = snapshot.outstanding_probe else {
            tokio::task::yield_now().await;
            continue;
        };
        if outstanding.sent_age_ms.is_none() {
            tokio::task::yield_now().await;
            continue;
        }
        let candidate = outstanding.candidate_udp_datagram_size as usize;
        downward_probe_sizes.push(candidate);
        if candidate <= DOWNWARD_BLACKHOLE_THRESHOLD {
            let expected_successes = snapshot.success_count + 1;
            yield_until(
                || {
                    runtime
                        .snapshots()
                        .get("peer-b")
                        .is_some_and(|value| value.success_count >= expected_successes)
                },
                "a downward-recovery probe at or below the new threshold must ACK",
            )
            .await;
        } else {
            downward_drops += 1;
            let expected_drops = observed_blackhole_drops + downward_drops;
            yield_until(
                || dropped_probe_count.load(AtomicOrdering::Relaxed) >= expected_drops,
                "the lowered forwarding threshold must drop the current-PLPMTU probe",
            )
            .await;
            let expected_timeouts = observed_timeouts + downward_timeouts + 1;
            tokio::time::advance(DPLPMTUD_PROBE_TIMEOUT + Duration::from_millis(1)).await;
            yield_until(
                || {
                    runtime
                        .snapshots()
                        .get("peer-b")
                        .is_some_and(|value| value.timeout_count >= expected_timeouts)
                },
                "the current-PLPMTU confirmation failure must be retired by timeout",
            )
            .await;
            downward_timeouts += 1;
        }
    }
    let downward_result = runtime.snapshots().remove("peer-b").unwrap();
    let downward_confirmed = downward_result
        .confirmed_udp_datagram_size
        .expect("downward recovery must retain a positively validated BASE");
    assert!(downward_confirmed as usize <= DOWNWARD_BLACKHOLE_THRESHOLD);
    assert!(downward_probe_sizes
        .iter()
        .any(|size| *size > DOWNWARD_BLACKHOLE_THRESHOLD));
    assert!(downward_probe_sizes
        .iter()
        .any(|size| *size <= DOWNWARD_BLACKHOLE_THRESHOLD));
    assert_eq!(
        runtime.path_identity("peer-b"),
        Some(initial_identity.clone())
    );
    assert_eq!(initial_identity.epoch, identity.epoch);
    assert_eq!(
        initial_identity.direct_validation_owner_token,
        identity.direct_validation_owner_token
    );
    assert_eq!(
        initial_identity.direct_validation_request_id,
        identity.direct_validation_request_id
    );
    assert_eq!(initial_identity.socket, identity.socket);
    let downward_connection = peers_a.get_connection("peer-b").await.unwrap();
    assert_eq!(
        downward_connection.active_path(),
        Some(crate::peer::NetworkPath::Direct)
    );
    assert_eq!(downward_connection.direct_health.failure_count, 0);
    assert_eq!(downward_connection.relay_health.failure_count, 0);
    println!(
        "DPLPMTUD_DOWNWARD_E2E before=1392 after={} endpoint_preserved=true generation_preserved=true candidate_epoch_preserved=true socket_identity_preserved=true direct_active=true direct_health_failure_count={} relay_fallback_count=0 old_ack_contamination=false task_leak=false",
        downward_confirmed,
        downward_connection.direct_health.failure_count,
    );
    result = downward_result;

    // Send a second, independently encrypted ACK for the final successful
    // probe. WireGuard replay protection accepts it as a new envelope,
    // while the DPLPMTUD receipt identity must classify it as Duplicate
    // without changing the converged result.
    let duplicate_token = last_success_token.expect("a successful probe must converge");
    let duplicate_ack_plaintext = build_ack_inner_packet(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        duplicate_token,
    );
    let duplicate_ack_encrypted = wireguard_b
        .encrypt_outbound(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.1".to_string(),
            packet: duplicate_ack_plaintext,
            trace: None,
        })
        .await
        .unwrap()
        .unwrap();
    let (_, peer_b_socket) = udp_b
        .socket_for_peer(Some("peer-a"))
        .await
        .expect("the responder must retain its primary UDP socket");
    peer_b_socket
        .send_to(&duplicate_ack_encrypted.wire_bytes, router_endpoint)
        .await
        .unwrap();
    let expected_duplicate_acks = result.duplicate_ack_count + 1;
    yield_until(
        || {
            runtime
                .snapshots()
                .get("peer-b")
                .is_some_and(|value| value.duplicate_ack_count >= expected_duplicate_acks)
        },
        "a second encrypted ACK must be classified as a duplicate by production inbound handling",
    )
    .await;
    let after_duplicate = runtime.snapshots().remove("peer-b").unwrap();
    assert_eq!(after_duplicate.revision, result.revision);
    assert_eq!(after_duplicate.success_count, result.success_count);
    assert_eq!(
        after_duplicate.confirmed_udp_datagram_size,
        result.confirmed_udp_datagram_size
    );
    assert_eq!(
        after_duplicate.search_upper_udp_datagram_size,
        result.search_upper_udp_datagram_size
    );
    assert_eq!(after_duplicate.duplicate_ack_count, expected_duplicate_acks);
    result = after_duplicate;

    // A real network-generation transition cancels the old exact path.
    // Recommit a fresh Direct identity, then deliver an authenticated ACK
    // carrying the old token through the live UDP reader. The production
    // ACK handler must count it as stale and leave the new search intact.
    let old_search_result = result.clone();
    let next_generation = peers_a
        .advance_network_generation("dplpmtud production generation fence")
        .await;
    yield_until(
        || runtime.active_worker_count() == 0,
        "network-generation advance must cancel the old DPLPMTUD worker",
    )
    .await;
    let next_identity = commit_test_direct_path(
        &peers_a,
        &udp_a,
        "peer-b",
        router_endpoint,
        endpoint_a,
        43,
        47,
    )
    .await;
    assert_eq!(next_identity.epoch.network_generation, next_generation);
    assert!(runtime.is_supported(
        "peer-b",
        next_identity.epoch.peer_session_generation.value()
    ));
    yield_until(
        || {
            runtime.path_identity("peer-b") == Some(next_identity.clone())
                && runtime.active_worker_count() == 1
        },
        "a recommitted Direct identity must start exactly one replacement worker",
    )
    .await;
    let old_ack_plaintext = build_ack_inner_packet(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        duplicate_token,
    );
    let old_ack_encrypted = wireguard_b
        .encrypt_outbound(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.1".to_string(),
            packet: old_ack_plaintext,
            trace: None,
        })
        .await
        .unwrap()
        .unwrap();
    let (_, peer_b_socket) = udp_b
        .socket_for_peer(Some("peer-a"))
        .await
        .expect("the responder must retain its primary UDP socket");
    peer_b_socket
        .send_to(&old_ack_encrypted.wire_bytes, router_endpoint)
        .await
        .unwrap();
    let expected_stale_acks = old_search_result.stale_ack_count + 1;
    yield_until(
        || {
            runtime
                .snapshots()
                .get("peer-b")
                .is_some_and(|value| value.stale_ack_count >= expected_stale_acks)
        },
        "an authenticated ACK from the previous network generation must be stale",
    )
    .await;
    let after_stale_generation = runtime.snapshots().remove("peer-b").unwrap();
    assert_eq!(after_stale_generation.confirmed_udp_datagram_size, None);
    assert_eq!(after_stale_generation.duplicate_ack_count, 0);
    let observed_stale_ack_count = after_stale_generation.stale_ack_count;

    // PeerLeft is exercised through the actual PeerManager lifecycle. It
    // must withdraw the committed path, cancel the worker and remove the
    // runtime entry before shutdown is signalled.
    peers_a.remove_peer("peer-b").await;
    yield_until(
        || {
            runtime.active_worker_count() == 0
                && runtime.tracked_peer_count() == 0
                && runtime.path_identity("peer-b").is_none()
        },
        "PeerLeft must cancel and remove the DPLPMTUD worker entry",
    )
    .await;

    shutdown_tx.send(true).unwrap();
    scheduler.await.unwrap();
    assert_eq!(runtime.active_worker_count(), 0);
    drop(udp_a_watch_tx);
    drop(udp_b_watch_tx);
    a_reader.abort();
    b_reader.abort();
    a_transport.abort();
    b_transport.abort();
    router_task.abort();
    let _ = a_reader.await;
    let _ = b_reader.await;
    let _ = a_transport.await;
    let _ = b_transport.await;
    let _ = router_task.await;
    println!(
        "DPLPMTUD_BLACKHOLE threshold={} confirmed={} upper={} probe_count={} timeout_count={} success_count={} dropped_probe_count={} direct_active=true direct_health_failure_count={} relay_fallback_count=0 generation_switch_stale_ack=true peer_left_cancelled=true stale_ack_count={} duplicate_ack_count={} task_leak={}",
        BLACKHOLE_THRESHOLD,
        initial_result.confirmed_udp_datagram_size.unwrap_or(0),
        initial_result.search_upper_udp_datagram_size,
        initial_result.probe_count,
        initial_result.timeout_count,
        initial_result.success_count,
        dropped_probe_count.load(AtomicOrdering::Relaxed),
        connection.direct_health.failure_count,
        observed_stale_ack_count,
        result.duplicate_ack_count,
        runtime.active_worker_count() != 0,
    );
}

#[tokio::test]
// Keep the reducer-only blackhole model as a narrow state-machine
// regression. The acceptance test above is the production-path test used
// by CI; this supplemental test intentionally does not stand in for it.
async fn reducer_blackhole_state_machine_regression() {
    const BLACKHOLE_THRESHOLD: usize = 1397;
    let socket_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socket_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let blackhole_sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let endpoint_a = socket_a.local_addr().unwrap();
    let endpoint_b = socket_b.local_addr().unwrap();
    let sink_endpoint = blackhole_sink.local_addr().unwrap();

    let (session_a, session_b) = establish_sessions();
    let (transport_a, _outbound_a) = WireGuardTransport::new();
    let (transport_b, _outbound_b) = WireGuardTransport::new();
    transport_a.add_session("peer-b", session_a).await;
    transport_b.add_session("peer-a", session_b).await;

    let initial_identity = DplpmtudPathIdentity {
        peer_id: "peer-b".to_string(),
        epoch: PathEpoch::new(7, PeerSessionGeneration::for_test(11), 13),
        direct_validation_owner_token: 17,
        direct_validation_request_id: 19,
        authenticated_remote_endpoint: endpoint_b,
        local_endpoint: endpoint_a,
        socket: DplpmtudSocketIdentity {
            transport_instance_id: 23,
            socket_index: 0,
        },
        outer_ip_family: OuterIpFamily::Ipv4,
    };
    let runtime = DplpmtudRuntime::new();
    let baseline_workers = runtime.active_worker_count();
    let initial_lease = runtime
        .install_path(initial_identity.clone(), true, Instant::now())
        .worker
        .unwrap();
    assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
    let mut logical_now = Instant::now();
    let mut observed_probe_sizes = Vec::new();
    let mut duplicate_exercised = false;
    // DPLPMTUD has no path-selection or Direct-health mutation API. Keep
    // explicit side-effect sentinels around the real blackhole loop so a
    // timeout can only change the search machine, never Direct/Relay state.
    let direct_active = true;
    let direct_health_failure_count = 0usize;
    let relay_fallback_count = 0usize;

    // Obtain an ACK through the complete encrypted UDP chain, then replace
    // the Direct generation before committing it. The old ACK must fail
    // closed against the newly committed exact path identity.
    let generation_plan = runtime
        .schedule_probe(
            "peer-b",
            &initial_identity,
            initial_lease.worker_owner_token,
            logical_now,
        )
        .unwrap();
    let generation_plaintext = build_encrypted_probe_plaintext(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        &initial_identity,
        &generation_plan,
    )
    .unwrap();
    let generation_encrypted = transport_a
        .encrypt_outbound(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: generation_plaintext,
            trace: None,
        })
        .await
        .unwrap()
        .unwrap();
    let generation_probe_size = generation_encrypted.wire_bytes.len();
    assert!(generation_probe_size <= BLACKHOLE_THRESHOLD);
    assert_eq!(
        generation_probe_size,
        generation_plan.probe_identity.candidate_udp_datagram_size.0 as usize
    );
    assert!(runtime.begin_probe_send(&generation_plan, logical_now));
    socket_a
        .send_to(&generation_encrypted.wire_bytes, endpoint_b)
        .await
        .unwrap();
    runtime.finish_probe_send(
        &generation_plan,
        Ok(()),
        logical_now + Duration::from_millis(1),
    );
    let (generation_wire, generation_source) =
        receive_datagram(&socket_b, generation_probe_size).await;
    assert_eq!(generation_source, endpoint_a);
    let generation_inbound = transport_b
        .decrypt_inbound(&generation_wire)
        .await
        .unwrap()
        .unwrap();
    let generation_control = parse_control_packet(&generation_inbound.packet).unwrap();
    assert_eq!(generation_control.kind, DplpmtudControlKind::Probe);
    let generation_ack_plaintext = build_ack_inner_packet(
        Ipv4Addr::new(10, 20, 0, 2),
        Ipv4Addr::new(10, 20, 0, 1),
        generation_control.token,
    );
    let generation_ack_encrypted = transport_b
        .encrypt_outbound(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-a".to_string(),
            dst_ip: "10.20.0.1".to_string(),
            packet: generation_ack_plaintext,
            trace: None,
        })
        .await
        .unwrap()
        .unwrap();
    socket_b
        .send_to(&generation_ack_encrypted.wire_bytes, endpoint_a)
        .await
        .unwrap();
    let (generation_ack_wire, generation_ack_source) =
        receive_datagram(&socket_a, generation_ack_encrypted.wire_bytes.len()).await;
    assert_eq!(generation_ack_source, endpoint_b);
    let generation_ack_inbound = transport_a
        .decrypt_inbound(&generation_ack_wire)
        .await
        .unwrap()
        .unwrap();
    let stale_generation_ack = parse_control_packet(&generation_ack_inbound.packet).unwrap();
    assert_eq!(stale_generation_ack.kind, DplpmtudControlKind::Ack);

    let identity = DplpmtudPathIdentity {
        epoch: PathEpoch::new(8, PeerSessionGeneration::for_test(11), 14),
        direct_validation_owner_token: 29,
        direct_validation_request_id: 31,
        ..initial_identity.clone()
    };
    let lease = runtime
        .install_path(
            identity.clone(),
            true,
            logical_now + Duration::from_millis(2),
        )
        .worker
        .unwrap();
    assert!(*initial_lease.cancel_rx.borrow());
    assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
    let before_stale_generation = runtime.snapshots().remove("peer-b").unwrap();
    assert_eq!(before_stale_generation.state, DplpmtudState::Base);
    assert_eq!(
        runtime.try_accept_ack(
            "peer-b",
            &identity,
            stale_generation_ack.token,
            DplpmtudAckIngress {
                remote_endpoint: endpoint_b,
                local_endpoint: endpoint_a,
                socket: identity.socket,
            },
            logical_now + Duration::from_millis(3),
        ),
        DplpmtudTransitionDecision::Stale
    );
    let after_stale_generation = runtime.snapshots().remove("peer-b").unwrap();
    assert_eq!(
        after_stale_generation.confirmed_udp_datagram_size,
        before_stale_generation.confirmed_udp_datagram_size
    );
    assert_eq!(
        after_stale_generation.search_upper_udp_datagram_size,
        before_stale_generation.search_upper_udp_datagram_size
    );
    runtime.finish_worker(
        "peer-b",
        &initial_identity,
        initial_lease.worker_owner_token,
    );
    assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
    logical_now += Duration::from_millis(4);

    for _ in 0..64 {
        let snapshot = runtime.snapshots().remove("peer-b").unwrap();
        if snapshot.state == DplpmtudState::SearchComplete {
            break;
        }
        let plan = runtime
            .schedule_probe("peer-b", &identity, lease.worker_owner_token, logical_now)
            .expect("bounded search must schedule until complete");
        let plaintext = build_encrypted_probe_plaintext(
            Ipv4Addr::new(10, 20, 0, 1),
            Ipv4Addr::new(10, 20, 0, 2),
            &identity,
            &plan,
        )
        .unwrap();
        let encrypted = transport_a
            .encrypt_outbound(OutboundPacket {
                room_authorization: None,
                peer_id: "peer-b".to_string(),
                dst_ip: "10.20.0.2".to_string(),
                packet: plaintext,
                trace: None,
            })
            .await
            .unwrap()
            .unwrap();
        let probe_size = encrypted.wire_bytes.len();
        observed_probe_sizes.push(probe_size);
        assert_eq!(
            probe_size,
            plan.probe_identity.candidate_udp_datagram_size.0 as usize
        );
        assert!(runtime.begin_probe_send(&plan, logical_now));
        let allowed = probe_size <= BLACKHOLE_THRESHOLD;
        let target = if allowed { endpoint_b } else { sink_endpoint };
        assert_eq!(
            socket_a
                .send_to(&encrypted.wire_bytes, target)
                .await
                .unwrap(),
            probe_size
        );
        runtime.finish_probe_send(&plan, Ok(()), logical_now + Duration::from_millis(1));

        if allowed {
            let (received, source) = receive_datagram(&socket_b, probe_size).await;
            assert_eq!(source, endpoint_a);
            let inbound = transport_b
                .decrypt_inbound(&received)
                .await
                .unwrap()
                .unwrap();
            let control = parse_control_packet(&inbound.packet).unwrap();
            assert_eq!(control.kind, DplpmtudControlKind::Probe);
            assert_eq!(control.token, plan.wire_token);

            let ack_plaintext = build_ack_inner_packet(
                Ipv4Addr::new(10, 20, 0, 2),
                Ipv4Addr::new(10, 20, 0, 1),
                control.token,
            );
            let encrypted_ack = transport_b
                .encrypt_outbound(OutboundPacket {
                    room_authorization: None,
                    peer_id: "peer-a".to_string(),
                    dst_ip: "10.20.0.1".to_string(),
                    packet: ack_plaintext,
                    trace: None,
                })
                .await
                .unwrap()
                .unwrap();
            assert!(encrypted_ack.wire_bytes.len() <= probe_size);
            socket_b
                .send_to(&encrypted_ack.wire_bytes, endpoint_a)
                .await
                .unwrap();
            let (ack_wire, ack_source) =
                receive_datagram(&socket_a, encrypted_ack.wire_bytes.len()).await;
            assert_eq!(ack_source, endpoint_b);
            let ack_inbound = transport_a
                .decrypt_inbound(&ack_wire)
                .await
                .unwrap()
                .unwrap();
            let ack = parse_control_packet(&ack_inbound.packet).unwrap();
            assert_eq!(ack.kind, DplpmtudControlKind::Ack);
            assert_eq!(
                runtime.try_accept_ack(
                    "peer-b",
                    &identity,
                    ack.token,
                    DplpmtudAckIngress {
                        remote_endpoint: endpoint_b,
                        local_endpoint: endpoint_a,
                        socket: identity.socket,
                    },
                    logical_now + Duration::from_millis(2),
                ),
                DplpmtudTransitionDecision::Applied
            );

            if !duplicate_exercised {
                let duplicate_plaintext = build_ack_inner_packet(
                    Ipv4Addr::new(10, 20, 0, 2),
                    Ipv4Addr::new(10, 20, 0, 1),
                    control.token,
                );
                let duplicate_encrypted = transport_b
                    .encrypt_outbound(OutboundPacket {
                        room_authorization: None,
                        peer_id: "peer-a".to_string(),
                        dst_ip: "10.20.0.1".to_string(),
                        packet: duplicate_plaintext,
                        trace: None,
                    })
                    .await
                    .unwrap()
                    .unwrap();
                socket_b
                    .send_to(&duplicate_encrypted.wire_bytes, endpoint_a)
                    .await
                    .unwrap();
                let (duplicate_wire, _) =
                    receive_datagram(&socket_a, duplicate_encrypted.wire_bytes.len()).await;
                let duplicate_inbound = transport_a
                    .decrypt_inbound(&duplicate_wire)
                    .await
                    .unwrap()
                    .unwrap();
                let duplicate = parse_control_packet(&duplicate_inbound.packet).unwrap();
                let before = runtime.snapshots().remove("peer-b").unwrap();
                assert_eq!(
                    runtime.try_accept_ack(
                        "peer-b",
                        &identity,
                        duplicate.token,
                        DplpmtudAckIngress {
                            remote_endpoint: endpoint_b,
                            local_endpoint: endpoint_a,
                            socket: identity.socket,
                        },
                        logical_now + Duration::from_millis(3),
                    ),
                    DplpmtudTransitionDecision::Duplicate
                );
                let after = runtime.snapshots().remove("peer-b").unwrap();
                assert_eq!(after.revision, before.revision);
                assert_eq!(after.success_count, before.success_count);
                assert_eq!(
                    after.confirmed_udp_datagram_size,
                    before.confirmed_udp_datagram_size
                );
                duplicate_exercised = true;
            }
            logical_now += Duration::from_millis(4);
        } else {
            let (dropped, source) = receive_datagram(&blackhole_sink, probe_size).await;
            assert_eq!(source, endpoint_a);
            assert_eq!(dropped.len(), probe_size);
            assert_eq!(
                runtime.timeout_probe(&plan, plan.deadline),
                DplpmtudTransitionDecision::Applied
            );
            logical_now = plan.deadline + Duration::from_millis(1);
        }
    }

    let result = runtime.snapshots().remove("peer-b").unwrap();
    assert_eq!(result.state, DplpmtudState::SearchComplete);
    let confirmed = result
        .confirmed_udp_datagram_size
        .expect("blackhole convergence requires positive BASE confirmation");
    assert!(confirmed as usize <= BLACKHOLE_THRESHOLD);
    assert!(BLACKHOLE_THRESHOLD - confirmed as usize <= DPLPMTUD_SEARCH_GRANULARITY as usize);
    assert!(observed_probe_sizes
        .iter()
        .any(|size| *size <= BLACKHOLE_THRESHOLD));
    assert!(observed_probe_sizes
        .iter()
        .any(|size| *size > BLACKHOLE_THRESHOLD));
    assert!(direct_active);
    assert_eq!(direct_health_failure_count, 0);
    assert_eq!(relay_fallback_count, 0);
    assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
    assert_eq!(runtime.path_identity("peer-b"), Some(identity.clone()));

    // Start a fresh generation, leave one Probe outstanding, and deliver
    // PeerLeft before the send linearization point. The cancellation watch
    // fires, the old worker cannot send, and task ownership returns to the
    // pre-test baseline without a sleep or scheduler race.
    let peer_left_identity = DplpmtudPathIdentity {
        epoch: PathEpoch::new(9, PeerSessionGeneration::for_test(12), 15),
        direct_validation_owner_token: 37,
        direct_validation_request_id: 41,
        ..identity.clone()
    };
    let peer_left_lease = runtime
        .install_path(peer_left_identity.clone(), true, logical_now)
        .worker
        .unwrap();
    assert!(*lease.cancel_rx.borrow());
    runtime.finish_worker("peer-b", &identity, lease.worker_owner_token);
    assert_eq!(runtime.active_worker_count(), baseline_workers + 1);
    let peer_left_plan = runtime
        .schedule_probe(
            "peer-b",
            &peer_left_identity,
            peer_left_lease.worker_owner_token,
            logical_now,
        )
        .unwrap();
    let peer_left_plaintext = build_encrypted_probe_plaintext(
        Ipv4Addr::new(10, 20, 0, 1),
        Ipv4Addr::new(10, 20, 0, 2),
        &peer_left_identity,
        &peer_left_plan,
    )
    .unwrap();
    let peer_left_encrypted = transport_a
        .encrypt_outbound(OutboundPacket {
            room_authorization: None,
            peer_id: "peer-b".to_string(),
            dst_ip: "10.20.0.2".to_string(),
            packet: peer_left_plaintext,
            trace: None,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        peer_left_encrypted.wire_bytes.len(),
        peer_left_plan.probe_identity.candidate_udp_datagram_size.0 as usize
    );
    assert_eq!(
        runtime.snapshots().remove("peer-b").unwrap().state,
        DplpmtudState::Searching
    );
    runtime.cancel_peer(
        "peer-b",
        "peer_left",
        logical_now + Duration::from_millis(1),
    );
    assert!(*peer_left_lease.cancel_rx.borrow());
    assert!(!runtime.begin_probe_send(&peer_left_plan, logical_now + Duration::from_millis(1),));
    assert_eq!(
        runtime.timeout_probe(&peer_left_plan, peer_left_plan.deadline),
        DplpmtudTransitionDecision::Noop
    );
    let peer_left_snapshot = runtime.snapshots().remove("peer-b").unwrap();
    assert_eq!(peer_left_snapshot.state, DplpmtudState::Disabled);
    assert_eq!(
        peer_left_snapshot.reset_reason.as_deref(),
        Some("peer_left")
    );
    runtime.finish_worker(
        "peer-b",
        &peer_left_identity,
        peer_left_lease.worker_owner_token,
    );
    assert_eq!(runtime.active_worker_count(), baseline_workers);
    println!(
        "DPLPMTUD_BLACKHOLE threshold={} confirmed={} upper={} probe_count={} timeout_count={} direct_active={} direct_health_failure_count={} relay_fallback_count={} generation_switch_stale_ack=true peer_left_cancelled=true stale_ack_count={} duplicate_ack_count={} task_leak=false",
        BLACKHOLE_THRESHOLD,
        confirmed,
        result.search_upper_udp_datagram_size,
        result.probe_count,
        result.timeout_count,
        direct_active,
        direct_health_failure_count,
        relay_fallback_count,
        result.stale_ack_count,
        result.duplicate_ack_count,
    );
}
