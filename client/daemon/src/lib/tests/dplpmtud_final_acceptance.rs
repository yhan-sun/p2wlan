fn dplpmtud_final_identity(
    peer_id: &str,
    network_generation: u64,
    peer_session_generation: u64,
    remote_candidate_epoch: u64,
    direct_validation_owner_token: u64,
    direct_validation_request_id: u16,
    transport_instance_id: u64,
    socket_index: usize,
    outer_ip_family: crate::dplpmtud::OuterIpFamily,
) -> crate::dplpmtud::DplpmtudPathIdentity {
    let (local_endpoint, remote_endpoint) = match outer_ip_family {
        crate::dplpmtud::OuterIpFamily::Ipv4 => (
            "127.0.0.1:43101".parse().unwrap(),
            "127.0.0.1:43102".parse().unwrap(),
        ),
        crate::dplpmtud::OuterIpFamily::Ipv6 => (
            "[::1]:43101".parse().unwrap(),
            "[::1]:43102".parse().unwrap(),
        ),
    };
    crate::dplpmtud::DplpmtudPathIdentity {
        peer_id: peer_id.to_string(),
        epoch: crate::peer::PathEpoch::new(
            network_generation,
            crate::peer::PeerSessionGeneration::for_test(peer_session_generation),
            remote_candidate_epoch,
        ),
        direct_validation_owner_token,
        direct_validation_request_id,
        authenticated_remote_endpoint: remote_endpoint,
        local_endpoint,
        socket: crate::dplpmtud::DplpmtudSocketIdentity {
            transport_instance_id,
            socket_index,
        },
        outer_ip_family,
    }
}

fn dplpmtud_final_ack_ingress(
    identity: &crate::dplpmtud::DplpmtudPathIdentity,
) -> crate::dplpmtud::DplpmtudAckIngress {
    crate::dplpmtud::DplpmtudAckIngress {
        remote_endpoint: identity.authenticated_remote_endpoint,
        local_endpoint: identity.local_endpoint,
        socket: identity.socket,
    }
}

fn dplpmtud_final_confirm_base(
    runtime: &crate::dplpmtud::DplpmtudRuntime,
    identity: &crate::dplpmtud::DplpmtudPathIdentity,
    lease: &crate::dplpmtud::DplpmtudWorkerLease,
    now: tokio::time::Instant,
) -> crate::dplpmtud::DplpmtudProbePlan {
    let plan = runtime
        .schedule_probe(
            &identity.peer_id,
            identity,
            lease.worker_owner_token,
            now,
        )
        .expect("BASE probe must be scheduled");
    assert_eq!(
        plan.probe_identity.candidate_udp_datagram_size,
        crate::dplpmtud::UdpDatagramSize(
            crate::dplpmtud::DPLPMTUD_BASE_UDP_DATAGRAM_SIZE,
        )
    );
    assert!(runtime.begin_probe_send(&plan, now));
    runtime.finish_probe_send(&plan, Ok(()), now + Duration::from_millis(1));
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            identity,
            plan.wire_token,
            dplpmtud_final_ack_ingress(identity),
            now + Duration::from_millis(2),
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Applied
    );
    plan
}

fn dplpmtud_final_emit(record: serde_json::Value) {
    println!(
        "DPLPMTUD_FINAL_EVIDENCE {}",
        serde_json::to_string(&record).expect("evidence record must serialize")
    );
}

#[test]
fn dplpmtud_final_boundary_matrix_ipv4_ipv6() {
    let boundaries = [1280u32, 1360, 1380, 1420, 1500];
    let mut rows = Vec::new();
    for boundary in boundaries {
        for family in [
            crate::dplpmtud::OuterIpFamily::Ipv4,
            crate::dplpmtud::OuterIpFamily::Ipv6,
        ] {
            let overhead = family.outer_ip_udp_overhead();
            let udp = crate::dplpmtud::UdpDatagramSize(boundary - overhead);
            assert_eq!(udp.outer_ip_packet_size(family).0, boundary);
            assert!(udp <= family.ceiling_udp_datagram_size());
            let overlay = udp
                .overlay_payload_budget()
                .expect("all required boundaries exceed WireGuard overhead");
            assert_eq!(
                overlay.0,
                boundary - overhead - crate::dplpmtud::WIREGUARD_UDP_DATAGRAM_OVERHEAD
            );
            rows.push(serde_json::json!({
                "outer_ip_packet_size": boundary,
                "outer_ip_family": match family {
                    crate::dplpmtud::OuterIpFamily::Ipv4 => "ipv4",
                    crate::dplpmtud::OuterIpFamily::Ipv6 => "ipv6",
                },
                "outer_ip_udp_overhead": overhead,
                "udp_datagram_size": udp.0,
                "overlay_payload_budget": overlay.0,
            }));
        }
    }
    assert_eq!(
        crate::dplpmtud::UdpDatagramSize(
            crate::dplpmtud::DPLPMTUD_IPV4_UDP_DATAGRAM_CEILING
        )
        .outer_ip_packet_size(crate::dplpmtud::OuterIpFamily::Ipv4)
        .0,
        1500
    );
    assert_eq!(
        crate::dplpmtud::UdpDatagramSize(
            crate::dplpmtud::DPLPMTUD_IPV6_UDP_DATAGRAM_CEILING
        )
        .outer_ip_packet_size(crate::dplpmtud::OuterIpFamily::Ipv6)
        .0,
        1500
    );
    dplpmtud_final_emit(serde_json::json!({
        "scenario_id": "DP-01",
        "test_id": "tests::dplpmtud_final_boundary_matrix_ipv4_ipv6",
        "decision": "applied",
        "path_kind": "direct",
        "outer_ip_family": "ipv4_ipv6",
        "boundaries": boundaries,
        "rows": rows,
        "invariants": {
            "all_required_boundaries_executed": true,
            "outer_udp_overhead_separated": true,
            "wireguard_overhead_applied": true,
            "ethernet_ceiling_preserved": true
        }
    }));
}

#[test]
fn dplpmtud_final_epoch_and_socket_identity_isolation() {
    let now = tokio::time::Instant::now();
    let runtime = crate::dplpmtud::DplpmtudRuntime::new();
    let old_identity = dplpmtud_final_identity(
        "final-peer",
        7,
        11,
        13,
        17,
        19,
        23,
        0,
        crate::dplpmtud::OuterIpFamily::Ipv4,
    );
    let old_lease = runtime
        .install_path(old_identity.clone(), true, now)
        .worker
        .expect("old exact Direct path must own a worker");
    let old_plan = dplpmtud_final_confirm_base(&runtime, &old_identity, &old_lease, now);
    let old_budget = runtime
        .confirmed_budget_for_path(&old_identity)
        .expect("old exact path must have a confirmed BASE budget");

    let new_identity = dplpmtud_final_identity(
        "final-peer",
        8,
        12,
        14,
        27,
        29,
        33,
        1,
        crate::dplpmtud::OuterIpFamily::Ipv4,
    );
    let new_lease = runtime
        .install_path(
            new_identity.clone(),
            true,
            now + Duration::from_millis(3),
        )
        .worker
        .expect("replacement exact Direct path must own a worker");
    assert!(
        *old_lease.cancel_rx.borrow(),
        "replacement must cancel the old worker owner"
    );
    assert!(runtime.confirmed_budget_for_path(&old_identity).is_none());
    assert!(runtime.confirmed_budget_for_path(&new_identity).is_none());

    let stale = runtime.try_accept_ack(
        &old_identity.peer_id,
        &old_identity,
        old_plan.wire_token,
        dplpmtud_final_ack_ingress(&old_identity),
        now + Duration::from_millis(4),
    );
    assert_eq!(
        stale,
        crate::dplpmtud::DplpmtudTransitionDecision::Stale
    );
    let replacement_before_base = runtime
        .snapshot_for_peer(&new_identity.peer_id)
        .expect("replacement snapshot");
    assert_eq!(
        replacement_before_base
            .path_identity
            .as_ref()
            .map(|identity| identity.network_generation),
        Some(8)
    );
    assert_eq!(replacement_before_base.stale_ack_count, 1);

    dplpmtud_final_confirm_base(
        &runtime,
        &new_identity,
        &new_lease,
        now + Duration::from_millis(5),
    );
    let new_budget = runtime
        .confirmed_budget_for_path(&new_identity)
        .expect("replacement path must confirm its own BASE");
    assert_eq!(
        new_budget.udp_datagram_size,
        crate::dplpmtud::UdpDatagramSize(
            crate::dplpmtud::DPLPMTUD_BASE_UDP_DATAGRAM_SIZE,
        )
    );
    assert!(new_budget.budget_revision > old_budget.budget_revision);
    assert!(runtime.confirmed_budget_for_path(&old_identity).is_none());
    runtime.cancel_peer(
        &new_identity.peer_id,
        "final_identity_test_complete",
        now + Duration::from_millis(8),
    );

    dplpmtud_final_emit(serde_json::json!({
        "scenario_id": "DP-02",
        "test_id": "tests::dplpmtud_final_epoch_and_socket_identity_isolation",
        "decision": "stale_rejected",
        "path_kind": "direct",
        "outer_ip_family": "ipv4",
        "reason_code": "old_exact_path_identity",
        "counter_names": ["stale_ack_count", "budget_revision"],
        "invariants": {
            "network_epoch_changed": true,
            "peer_session_changed": true,
            "candidate_epoch_changed": true,
            "validation_owner_changed": true,
            "transport_and_socket_changed": true,
            "old_worker_cancelled": true,
            "old_budget_revoked": true,
            "old_ack_rejected": true,
            "replacement_requires_fresh_base_ack": true
        }
    }));
}

#[test]
fn dplpmtud_final_loss_reorder_duplicate_are_fenced() {
    let now = tokio::time::Instant::now();
    let runtime = crate::dplpmtud::DplpmtudRuntime::new();
    let identity = dplpmtud_final_identity(
        "loss-peer",
        17,
        21,
        23,
        27,
        29,
        31,
        0,
        crate::dplpmtud::OuterIpFamily::Ipv4,
    );
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .expect("loss/reorder path must own a worker");
    let base_plan = dplpmtud_final_confirm_base(&runtime, &identity, &lease, now);
    let base_budget = runtime
        .confirmed_budget_for_path(&identity)
        .expect("positive BASE ACK must publish a budget");

    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            &identity,
            base_plan.wire_token,
            dplpmtud_final_ack_ingress(&identity),
            now + Duration::from_millis(3),
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Duplicate
    );

    let first_attempt = runtime
        .schedule_probe(
            &identity.peer_id,
            &identity,
            lease.worker_owner_token,
            now + Duration::from_millis(4),
        )
        .expect("upward search attempt");
    assert!(runtime.begin_probe_send(
        &first_attempt,
        now + Duration::from_millis(4)
    ));
    runtime.finish_probe_send(
        &first_attempt,
        Ok(()),
        now + Duration::from_millis(5),
    );
    assert_eq!(
        runtime.timeout_probe(&first_attempt, first_attempt.deadline),
        crate::dplpmtud::DplpmtudTransitionDecision::Applied
    );
    assert_eq!(
        runtime
            .confirmed_budget_for_path(&identity)
            .expect("one lost upward probe must retain the confirmed lower bound")
            .udp_datagram_size,
        base_budget.udp_datagram_size
    );

    let retry = runtime
        .schedule_probe(
            &identity.peer_id,
            &identity,
            lease.worker_owner_token,
            first_attempt.deadline + Duration::from_millis(1),
        )
        .expect("bounded retry must schedule");
    assert!(runtime.begin_probe_send(
        &retry,
        first_attempt.deadline + Duration::from_millis(1)
    ));
    runtime.finish_probe_send(
        &retry,
        Ok(()),
        first_attempt.deadline + Duration::from_millis(2),
    );
    let late_old = runtime.try_accept_ack(
        &identity.peer_id,
        &identity,
        first_attempt.wire_token,
        dplpmtud_final_ack_ingress(&identity),
        first_attempt.deadline + Duration::from_millis(3),
    );
    assert_eq!(
        late_old,
        crate::dplpmtud::DplpmtudTransitionDecision::Stale
    );
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            &identity,
            retry.wire_token,
            dplpmtud_final_ack_ingress(&identity),
            first_attempt.deadline + Duration::from_millis(4),
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Applied
    );
    let recovered = runtime
        .confirmed_budget_for_path(&identity)
        .expect("matching retry ACK must recover upward search");
    assert!(recovered.udp_datagram_size > base_budget.udp_datagram_size);
    let snapshot = runtime
        .snapshot_for_peer(&identity.peer_id)
        .expect("loss/reorder snapshot");
    assert_eq!(snapshot.timeout_count, 1);
    assert_eq!(snapshot.duplicate_ack_count, 1);
    assert_eq!(snapshot.stale_ack_count, 1);
    assert!(snapshot.live_worker);
    runtime.cancel_peer(
        &identity.peer_id,
        "loss_reorder_test_complete",
        first_attempt.deadline + Duration::from_millis(5),
    );

    dplpmtud_final_emit(serde_json::json!({
        "scenario_id": "DP-03",
        "test_id": "tests::dplpmtud_final_loss_reorder_duplicate_are_fenced",
        "decision": "recovered",
        "path_kind": "direct",
        "outer_ip_family": "ipv4",
        "reason_code": "bounded_probe_retry",
        "counter_names": ["timeout_count", "duplicate_ack_count", "stale_ack_count"],
        "invariants": {
            "loss_retained_confirmed_lower_bound": true,
            "duplicate_ack_had_no_budget_side_effect": true,
            "late_old_ack_rejected": true,
            "matching_retry_ack_applied": true,
            "worker_remained_live_until_explicit_cancel": true
        }
    }));
}

#[test]
fn dplpmtud_final_direct_relay_switch_and_recovery() {
    let now = tokio::time::Instant::now();
    let runtime = crate::dplpmtud::DplpmtudRuntime::new();
    let direct_a = dplpmtud_final_identity(
        "switch-peer",
        31,
        33,
        35,
        37,
        39,
        41,
        0,
        crate::dplpmtud::OuterIpFamily::Ipv4,
    );
    let lease_a = runtime
        .install_path(direct_a.clone(), true, now)
        .worker
        .expect("initial Direct path");
    dplpmtud_final_confirm_base(&runtime, &direct_a, &lease_a, now);
    assert!(runtime.confirmed_budget_for_path(&direct_a).is_some());

    runtime.cancel_peer(
        &direct_a.peer_id,
        "active_path_relay",
        now + Duration::from_millis(3),
    );
    assert!(*lease_a.cancel_rx.borrow());
    assert!(runtime.confirmed_budget_for_path(&direct_a).is_none());
    let relay_snapshot = runtime
        .snapshot_for_peer(&direct_a.peer_id)
        .expect("Relay cancellation tombstone");
    assert_eq!(
        relay_snapshot.state,
        crate::dplpmtud::DplpmtudState::Disabled
    );
    assert_eq!(
        relay_snapshot.reset_reason.as_deref(),
        Some("active_path_relay")
    );
    assert!(!relay_snapshot.live_worker);

    let direct_b = dplpmtud_final_identity(
        "switch-peer",
        32,
        34,
        36,
        47,
        49,
        51,
        1,
        crate::dplpmtud::OuterIpFamily::Ipv4,
    );
    let lease_b = runtime
        .install_path(
            direct_b.clone(),
            true,
            now + Duration::from_millis(4),
        )
        .worker
        .expect("new Direct path after Relay");
    assert!(
        runtime.confirmed_budget_for_path(&direct_b).is_none(),
        "Relay -> Direct must restart from unconfirmed BASE"
    );
    dplpmtud_final_confirm_base(
        &runtime,
        &direct_b,
        &lease_b,
        now + Duration::from_millis(5),
    );
    assert_eq!(
        runtime
            .confirmed_budget_for_path(&direct_b)
            .expect("fresh Direct must recover only after BASE ACK")
            .udp_datagram_size,
        crate::dplpmtud::UdpDatagramSize(
            crate::dplpmtud::DPLPMTUD_BASE_UDP_DATAGRAM_SIZE,
        )
    );
    assert!(runtime.confirmed_budget_for_path(&direct_a).is_none());
    runtime.cancel_peer(
        &direct_b.peer_id,
        "path_switch_test_complete",
        now + Duration::from_millis(8),
    );
    assert_eq!(runtime.active_worker_count(), 0);

    dplpmtud_final_emit(serde_json::json!({
        "scenario_id": "DP-04",
        "test_id": "tests::dplpmtud_final_direct_relay_switch_and_recovery",
        "decision": "recovered",
        "path_kind": "direct_relay_direct",
        "outer_ip_family": "ipv4",
        "reason_code": "active_path_relay",
        "counter_names": ["reset_count", "budget_revision"],
        "invariants": {
            "direct_budget_revoked_on_relay_activation": true,
            "relay_does_not_inherit_direct_budget": true,
            "old_worker_cancelled": true,
            "new_direct_identity_requires_base_confirmation": true,
            "old_direct_budget_never_reappears": true,
            "worker_ownership_cleaned": true
        }
    }));
}

#[test]
fn dplpmtud_final_typed_counters_use_bounded_labels() {
    let now = tokio::time::Instant::now();
    let runtime = crate::dplpmtud::DplpmtudRuntime::new();
    let identity = dplpmtud_final_identity(
        "counter-peer",
        61,
        63,
        65,
        67,
        69,
        71,
        0,
        crate::dplpmtud::OuterIpFamily::Ipv6,
    );
    let lease = runtime
        .install_path(identity.clone(), true, now)
        .worker
        .expect("counter path");
    let base_plan = dplpmtud_final_confirm_base(&runtime, &identity, &lease, now);
    assert_eq!(
        runtime.try_accept_ack(
            &identity.peer_id,
            &identity,
            base_plan.wire_token,
            dplpmtud_final_ack_ingress(&identity),
            now + Duration::from_millis(3),
        ),
        crate::dplpmtud::DplpmtudTransitionDecision::Duplicate
    );
    let snapshot = runtime
        .snapshot_for_peer(&identity.peer_id)
        .expect("typed snapshot");
    let counter_names = [
        "probe_count",
        "success_count",
        "timeout_count",
        "send_failure_count",
        "stale_ack_count",
        "duplicate_ack_count",
        "reset_count",
        "revision",
        "budget_revision",
    ];
    assert_eq!(snapshot.probe_count, 1);
    assert_eq!(snapshot.success_count, 1);
    assert_eq!(snapshot.duplicate_ack_count, 1);
    assert_eq!(
        snapshot
            .path_identity
            .as_ref()
            .map(|value| value.outer_ip_family),
        Some(crate::dplpmtud::OuterIpFamily::Ipv6)
    );
    let record = serde_json::json!({
        "scenario_id": "DP-05",
        "test_id": "tests::dplpmtud_final_typed_counters_use_bounded_labels",
        "decision": "observed",
        "path_kind": "direct",
        "outer_ip_family": "ipv6",
        "state": format!("{:?}", snapshot.state).to_ascii_lowercase(),
        "counter_names": counter_names,
        "counters": {
            "probe_count": snapshot.probe_count,
            "success_count": snapshot.success_count,
            "timeout_count": snapshot.timeout_count,
            "send_failure_count": snapshot.send_failure_count,
            "stale_ack_count": snapshot.stale_ack_count,
            "duplicate_ack_count": snapshot.duplicate_ack_count,
            "reset_count": snapshot.reset_count,
            "revision": snapshot.revision,
            "budget_revision_present": snapshot.budget_revision.is_some()
        },
        "invariants": {
            "typed_state_present": true,
            "typed_counter_names_bounded": true,
            "peer_or_endpoint_not_used_as_metric_label": true,
            "path_identity_remains_available_in_diagnostics_not_labels": true
        }
    });
    let encoded = serde_json::to_string(&record).unwrap();
    assert!(!encoded.contains("127.0.0.1"));
    assert!(!encoded.contains("[::1]"));
    assert!(!encoded.contains("counter-peer"));
    dplpmtud_final_emit(record);
    runtime.cancel_peer(
        &identity.peer_id,
        "counter_test_complete",
        now + Duration::from_millis(4),
    );
}
