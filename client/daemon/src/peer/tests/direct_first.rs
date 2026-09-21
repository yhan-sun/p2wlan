use super::*;
use crate::peer::path_state_machine::{ActiveBusinessPath, PathTransitionDecision};

fn epoch() -> PathEpoch {
    PathEpoch::new(1, PeerSessionGeneration::for_test(1), 1)
}
fn commit(machine: &mut PathStateMachine, event: PathEvent) -> PathTransitionOutcome {
    machine.commit(machine.reduce(event))
}
fn started(now: Instant) -> PathStateMachine {
    let mut machine = PathStateMachine::new(ConnectionState::Idle);
    assert!(commit(&mut machine, PathEvent::PeerOnline { epoch: epoch() }).accepted());
    assert!(commit(
        &mut machine,
        PathEvent::DirectFirstStarted {
            epoch: epoch(),
            now
        }
    )
    .accepted());
    machine
}
fn confirm_relay(machine: &mut PathStateMachine) {
    let relay = RelayConnectionIdentity::new(epoch(), "relay.test:443", Some(1));
    assert!(commit(
        machine,
        PathEvent::RelayTransportReady {
            relay: relay.clone()
        }
    )
    .accepted());
    assert!(commit(machine, PathEvent::RelayPeerConfirmed { relay }).accepted());
}

#[test]
fn direct_first_confirmed_relay_is_standby_until_exact_deadline() {
    let now = Instant::now();
    let mut machine = started(now);
    confirm_relay(&mut machine);
    assert_eq!(machine.active_path(), None);
    assert!(commit(
        &mut machine,
        PathEvent::DirectFirstDeadline {
            epoch: epoch(),
            now: now + Duration::from_millis(4999)
        }
    )
    .accepted());
    assert_eq!(machine.active_path(), None);
    assert!(commit(
        &mut machine,
        PathEvent::DirectFirstDeadline {
            epoch: epoch(),
            now: now + Duration::from_secs(5)
        }
    )
    .accepted());
    assert_eq!(machine.active_path(), Some(NetworkPath::Relay));
}

#[test]
fn direct_first_repeated_start_cannot_extend_the_window() {
    let now = Instant::now();
    let mut machine = started(now);
    confirm_relay(&mut machine);
    for offset in 1..=4 {
        assert!(commit(
            &mut machine,
            PathEvent::DirectFirstStarted {
                epoch: epoch(),
                now: now + Duration::from_secs(offset)
            }
        )
        .accepted());
    }
    commit(
        &mut machine,
        PathEvent::DirectFirstDeadline {
            epoch: epoch(),
            now: now + Duration::from_secs(5),
        },
    );
    assert_eq!(machine.active_path(), Some(NetworkPath::Relay));
    commit(
        &mut machine,
        PathEvent::DirectFirstStarted {
            epoch: epoch(),
            now: now + Duration::from_secs(6),
        },
    );
    assert!(!machine.direct_first_pending());
}

#[test]
fn direct_first_candidate_refresh_preserves_deadline_and_rejects_old_tick() {
    let now = Instant::now();
    let mut machine = started(now);
    confirm_relay(&mut machine);
    let refreshed = PathEpoch {
        remote_candidate_epoch: 2,
        ..epoch()
    };
    assert!(commit(
        &mut machine,
        PathEvent::RemoteCandidateEpochAdvanced {
            epoch: refreshed,
            direct: DirectCandidateContinuity::Invalidate
        }
    )
    .accepted());
    let stale = commit(
        &mut machine,
        PathEvent::DirectFirstDeadline {
            epoch: epoch(),
            now: now + Duration::from_secs(5),
        },
    );
    assert_eq!(
        stale.decision,
        PathTransitionDecision::RejectedRemoteCandidateEpoch
    );
    assert_eq!(machine.active_path(), None);
    assert!(commit(
        &mut machine,
        PathEvent::DirectFirstDeadline {
            epoch: refreshed,
            now: now + Duration::from_secs(5)
        }
    )
    .accepted());
    assert_eq!(machine.active_path(), Some(NetworkPath::Relay));
}

#[test]
fn direct_first_stale_network_or_session_cannot_release_current_window() {
    let now = Instant::now();
    let mut machine = started(now);
    confirm_relay(&mut machine);
    for stale in [
        PathEpoch {
            network_generation: 0,
            ..epoch()
        },
        PathEpoch::new(1, PeerSessionGeneration::for_test(0), 1),
    ] {
        assert!(!commit(
            &mut machine,
            PathEvent::DirectFirstDeadline {
                epoch: stale,
                now: now + Duration::from_secs(6)
            }
        )
        .accepted());
        assert!(machine.direct_first_pending());
    }
}

#[test]
fn direct_first_direct_commit_wins_before_timeout_and_does_not_flap_at_expiry() {
    let now = Instant::now();
    let mut machine = started(now);
    confirm_relay(&mut machine);
    let endpoint = "198.51.100.1:40000".parse().unwrap();
    let validation = DirectValidationIdentity::compatibility(epoch(), Some(endpoint));
    assert!(commit(&mut machine, PathEvent::DirectCommitted { validation }).accepted());
    assert_eq!(machine.active_path(), Some(NetworkPath::Direct));
    commit(
        &mut machine,
        PathEvent::DirectFirstDeadline {
            epoch: epoch(),
            now: now + Duration::from_secs(5),
        },
    );
    assert_eq!(machine.active_path(), Some(NetworkPath::Direct));
}

#[test]
fn direct_first_failed_established_path_falls_back_without_cold_wait() {
    let now = Instant::now();
    let mut machine = started(now);
    confirm_relay(&mut machine);
    let validation = DirectValidationIdentity::compatibility(
        epoch(),
        Some("198.51.100.1:40000".parse().unwrap()),
    );
    commit(&mut machine, PathEvent::DirectCommitted { validation });
    assert!(commit(&mut machine, PathEvent::DirectPathFailed { epoch: epoch() }).accepted());
    assert_eq!(machine.active_path(), Some(NetworkPath::Relay));
    assert!(!machine.direct_first_pending());
}

#[test]
fn direct_first_probe_failure_is_not_a_connection_deadline() {
    let mut machine = started(Instant::now());
    confirm_relay(&mut machine);
    assert!(commit(
        &mut machine,
        PathEvent::DirectProbeFailed { epoch: epoch() }
    )
    .accepted());
    assert!(machine.direct_first_pending());
    assert!(matches!(
        machine.snapshot().state.active,
        ActiveBusinessPath::Unavailable
    ));
}

#[test]
fn direct_first_departure_cannot_be_revived_by_a_late_deadline() {
    let now = Instant::now();
    let mut machine = started(now);
    confirm_relay(&mut machine);
    assert!(commit(&mut machine, PathEvent::PeerLeft { epoch: epoch() }).accepted());
    assert!(!commit(
        &mut machine,
        PathEvent::DirectFirstDeadline {
            epoch: epoch(),
            now: now + Duration::from_secs(6)
        }
    )
    .accepted());
    assert_eq!(machine.active_path(), None);
}

#[test]
fn direct_first_queue_timeout_does_not_invent_a_relay() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    assert_eq!(
        config.relay.path_policy,
        crate::config::PathPolicy::DirectFirst
    );
    assert_eq!(
        config.relay.startup_wait_timeout(false),
        Some(Duration::from_secs(5))
    );
    assert_eq!(
        config.relay.startup_wait_timeout(true),
        Some(Duration::from_secs(8))
    );
    let mut legacy = config;
    legacy.relay.path_policy = crate::config::PathPolicy::Auto;
    assert_eq!(legacy.relay.startup_wait_timeout(false), None);
    assert_eq!(
        legacy.relay.startup_wait_timeout(true),
        Some(Duration::from_secs(3))
    );
}

#[tokio::test]
async fn direct_first_manager_blocks_relay_but_admits_one_way_confirmed_direct() {
    let config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    let manager = PeerManager::new(config);
    let endpoint = "198.51.100.9:41000".parse().unwrap();
    manager
        .add_peer(&test_peer("peer-direct-first", endpoint))
        .await;
    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .confirm_relay_peer("peer-direct-first", "relay.test:443", generation)
            .await
    );
    assert!(
        !manager
            .is_data_path_admitted_for_generation("peer-direct-first", generation, true)
            .await
    );
    assert!(
        !manager
            .is_relay_business_admitted_for_generation("peer-direct-first", generation)
            .await
    );
    let selection = manager
        .select_path_for_data("peer-direct-first", true, true)
        .await;
    assert_eq!(selection.path, None);
    assert_eq!(selection.reason_code, REASON_PATH_DIRECT_FIRST_WAIT);
    manager
        .record_direct_probe_success_with_latency(
            "peer-direct-first",
            endpoint,
            Some(Duration::from_millis(600)),
        )
        .await;
    assert!(
        !manager
            .is_data_path_admitted_for_generation("peer-direct-first", generation, true)
            .await
    );
    manager
        .record_direct_success("peer-direct-first", Some(endpoint))
        .await;
    assert!(
        manager
            .is_data_path_admitted_for_generation("peer-direct-first", generation, true)
            .await
    );
    assert_eq!(
        manager
            .select_path_for_data("peer-direct-first", true, true)
            .await
            .path,
        Some(NetworkPath::Direct)
    );
    // No Relay business exchange and no natural reverse application packet were needed.
}

#[tokio::test]
async fn direct_first_explicit_relay_only_remains_explicit() {
    let mut config = Config::generate_default("https://ctrl.test", "net1").unwrap();
    config.relay.path_policy = crate::config::PathPolicy::RelayOnly;
    let manager = PeerManager::new(config);
    manager
        .add_peer(&test_peer(
            "peer-relay-only",
            "198.51.100.9:41000".parse().unwrap(),
        ))
        .await;
    let generation = manager.current_network_generation().await;
    assert!(
        manager
            .confirm_relay_peer("peer-relay-only", "relay.test:443", generation)
            .await
    );
    assert!(
        manager
            .is_data_path_admitted_for_generation("peer-relay-only", generation, true)
            .await
    );
    assert_eq!(
        manager
            .select_path_for_data("peer-relay-only", true, true)
            .await
            .path,
        Some(NetworkPath::Relay)
    );
}

#[test]
fn direct_first_business_readiness_requires_the_exact_committed_validation() {
    let mut machine = started(Instant::now());
    confirm_relay(&mut machine);
    let validation = DirectValidationIdentity::compatibility(
        epoch(),
        Some("198.51.100.1:40000".parse().unwrap()),
    );
    assert!(!commit(&mut machine, PathEvent::DirectFirstSatisfied { validation }).accepted());
    commit(&mut machine, PathEvent::DirectCommitted { validation });
    assert!(
        machine.direct_first_pending(),
        "ACK alone cannot bypass a pending managed MTU budget"
    );
    let wrong = DirectValidationIdentity::compatibility(
        epoch(),
        Some("198.51.100.1:40001".parse().unwrap()),
    );
    assert!(!commit(
        &mut machine,
        PathEvent::DirectFirstSatisfied { validation: wrong }
    )
    .accepted());
    assert!(commit(&mut machine, PathEvent::DirectFirstSatisfied { validation }).accepted());
    assert!(!machine.direct_first_pending());
    assert_eq!(machine.active_path(), Some(NetworkPath::Direct));
}
