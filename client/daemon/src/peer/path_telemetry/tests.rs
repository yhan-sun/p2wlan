use std::sync::Arc;

use super::super::path_observability::{PathEpochDiagnostics, PathObservabilitySnapshot};
use super::super::types::NetworkPath;
use super::super::PeerConnection;
use super::hub::{PathTelemetryHub, MAX_DIRTY_PEERS};
use super::wire::observation_from_snapshot;

fn dummy_snapshot(
    current_path: Option<NetworkPath>,
    gen: u64,
    revision: u64,
) -> PathObservabilitySnapshot {
    PathObservabilitySnapshot {
        current_path,
        path_state_revision: revision,
        network_epoch: Some(PathEpochDiagnostics {
            network_generation: gen,
            peer_session_generation: 1,
            remote_candidate_epoch: 2,
        }),
        transition_reason: "direct_validation_succeeded".to_string(),
        ..Default::default()
    }
}

#[test]
fn test_scenario_01_committed_state_only() {
    let hub = Arc::new(PathTelemetryHub::new("device-1".into(), "net-1".into()));
    let mut conn = PeerConnection::new("peer-alpha", "10.20.0.2");
    conn.attach_telemetry_hub(hub.clone());

    // Initially, attaching syncs the initial snapshot
    let initial_dirty = hub.drain_dirty(10);
    assert_eq!(initial_dirty.len(), 1);
    assert_eq!(initial_dirty[0].current_path, "none");

    // Commit an accepted path transition: PeerOnline
    let epoch = crate::peer::path_state_machine::PathEpoch::unbound(1, 0);
    let outcome = conn.commit_path_transition(
        crate::peer::path_state_machine::PathEvent::PeerOnline { epoch },
        |_| {},
    );
    assert!(outcome.accepted());

    // Dirty queue must contain peer-alpha with online/none or initial state
    assert!(hub.has_dirty());
    let drained = hub.drain_dirty(10);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].remote_device_id, "peer-alpha");

    // A rejected or duplicate transition that applies no side effects
    let dup_outcome = conn.commit_path_transition(
        crate::peer::path_state_machine::PathEvent::PeerOnline { epoch },
        |_| {},
    );
    // Duplicate event should not have applied side effects
    assert!(!dup_outcome.applies_side_effects());
}

#[test]
fn test_scenario_02_dirty_queue_bounding() {
    let hub = PathTelemetryHub::new("dev-bound".into(), "net-bound".into());
    let snap = dummy_snapshot(Some(NetworkPath::Direct), 1, 1);

    // Enqueue MAX_DIRTY_PEERS + 20 distinct peers
    for i in 0..(MAX_DIRTY_PEERS + 20) {
        let peer_id = format!("peer-{i:04}");
        hub.enqueue(&peer_id, &snap);
    }

    let metrics = hub.metrics();
    assert_eq!(metrics.enqueued_events, (MAX_DIRTY_PEERS + 20) as u64);
    assert_eq!(metrics.dropped_events, 20);

    // Draining all should return exactly MAX_DIRTY_PEERS items
    let drained = hub.drain_dirty(MAX_DIRTY_PEERS * 2);
    assert_eq!(drained.len(), MAX_DIRTY_PEERS);
    assert!(!hub.has_dirty());
}

#[test]
fn test_scenario_03_coalescing() {
    let hub = PathTelemetryHub::new("dev-coalesce".into(), "net-coalesce".into());

    let snap1 = dummy_snapshot(Some(NetworkPath::Relay), 1, 1);
    hub.enqueue("peer-fast", &snap1);

    let snap2 = dummy_snapshot(Some(NetworkPath::Direct), 1, 2);
    hub.enqueue("peer-fast", &snap2);

    let snap3 = dummy_snapshot(Some(NetworkPath::Direct), 1, 3);
    hub.enqueue("peer-fast", &snap3);

    let metrics = hub.metrics();
    assert_eq!(metrics.enqueued_events, 1);
    assert_eq!(metrics.coalesced_events, 2);

    // Drain should return only the latest snapshot
    let drained = hub.drain_dirty(10);
    assert_eq!(drained.len(), 1);
    assert_eq!(drained[0].observation_revision, 3);
    assert_eq!(drained[0].current_path, "direct");
}

#[test]
fn test_scenario_04_privacy_no_leaks() {
    let mut snap = dummy_snapshot(Some(NetworkPath::Direct), 1, 10);
    snap.direct_health.latency_ms = Some(24);

    let obs = observation_from_snapshot("peer-sensitive-uuid", "net-secure-uuid", &snap);
    let serialized = serde_json::to_string(&obs).expect("serialization failed");

    // Strict privacy checks: no IP, port, socket endpoint, key, or packet payload
    assert!(!serialized.contains("10.20."));
    assert!(!serialized.contains("192.168."));
    assert!(!serialized.contains("127.0.0.1"));
    assert!(!serialized.contains("endpoint"));
    assert!(!serialized.contains("socket"));
    assert!(!serialized.contains("public_key"));
    assert!(!serialized.contains("private_key"));
    assert!(!serialized.contains("payload"));
    assert!(!serialized.contains(":51820"));
}

#[test]
fn test_scenario_05_reconnect_resync() {
    let hub = PathTelemetryHub::new("dev-resync".into(), "net-resync".into());

    hub.enqueue("peer-1", &dummy_snapshot(Some(NetworkPath::Direct), 1, 1));
    hub.enqueue("peer-2", &dummy_snapshot(Some(NetworkPath::Relay), 1, 2));

    // Drain everything
    let drained = hub.drain_dirty(10);
    assert_eq!(drained.len(), 2);
    assert!(!hub.has_dirty());

    // Mark all dirty (simulating reconnect with "path_telemetry_v1" support)
    hub.mark_all_dirty();
    assert!(hub.has_dirty());

    let resynced = hub.drain_dirty(10);
    assert_eq!(resynced.len(), 2);
    let ids: Vec<&str> = resynced
        .iter()
        .map(|o| o.remote_device_id.as_str())
        .collect();
    assert!(ids.contains(&"peer-1"));
    assert!(ids.contains(&"peer-2"));
}

#[test]
fn test_scenario_06_network_generation_reset() {
    let hub = PathTelemetryHub::new("dev-gen".into(), "net-gen".into());

    // Gen 1
    hub.enqueue("peer-1", &dummy_snapshot(Some(NetworkPath::Direct), 1, 5));
    let obs1 = hub.drain_dirty(1)[0].clone();
    assert_eq!(obs1.network_generation, 1);

    // Gen advances to 2
    hub.enqueue("peer-1", &dummy_snapshot(Some(NetworkPath::Relay), 2, 6));
    let obs2 = hub.drain_dirty(1)[0].clone();
    assert_eq!(obs2.network_generation, 2);
    assert_eq!(obs2.current_path, "relay");
}

#[test]
fn test_scenario_07_drain_dirty_batching() {
    let hub = PathTelemetryHub::new("dev-batch".into(), "net-batch".into());

    for i in 0..10 {
        let id = format!("peer-{i}");
        hub.enqueue(&id, &dummy_snapshot(Some(NetworkPath::Direct), 1, 1));
    }

    // Drain in batches of 4
    let batch1 = hub.drain_dirty(4);
    assert_eq!(batch1.len(), 4);

    let batch2 = hub.drain_dirty(4);
    assert_eq!(batch2.len(), 4);

    let batch3 = hub.drain_dirty(4);
    assert_eq!(batch3.len(), 2);

    let batch4 = hub.drain_dirty(4);
    assert_eq!(batch4.len(), 0);
}

#[test]
fn test_scenario_08_metrics_tracking() {
    let hub = PathTelemetryHub::new("dev-metrics".into(), "net-metrics".into());

    hub.enqueue("p1", &dummy_snapshot(Some(NetworkPath::Direct), 1, 1));
    hub.enqueue("p1", &dummy_snapshot(Some(NetworkPath::Direct), 1, 2)); // coalesced

    hub.record_sent_batch(1);
    hub.record_ack(1234567890);
    hub.record_send_failure();

    let m = hub.metrics();
    assert_eq!(m.enqueued_events, 1);
    assert_eq!(m.coalesced_events, 1);
    assert_eq!(m.sent_batches, 1);
    assert_eq!(m.sent_observations, 1);
    assert_eq!(m.ack_received, 1);
    assert_eq!(m.send_failures, 1);
}

#[test]
fn test_scenario_09_payload_and_frame_serialization() {
    let hub = PathTelemetryHub::new("local-dev".into(), "net-123".into());
    hub.set_registration_seq(42);

    let snap = dummy_snapshot(Some(NetworkPath::Direct), 2, 8);
    hub.enqueue("remote-dev", &snap);

    let dirty = hub.drain_dirty(10);
    let frame = hub.build_frame(dirty);

    assert_eq!(frame.frame_type, "path_telemetry");
    assert_eq!(frame.payload.device_id, "local-dev");
    assert_eq!(frame.payload.network_id, "net-123");
    assert_eq!(frame.payload.observations.len(), 1);
    assert_eq!(frame.payload.observations[0].current_path, "direct");

    let json = serde_json::to_string(&frame).expect("valid frame JSON");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid parse");
    assert_eq!(parsed["type"], "path_telemetry");
    assert_eq!(parsed["payload"]["device_id"], "local-dev");
    assert_eq!(parsed["payload"]["network_id"], "net-123");
}

#[test]
fn test_scenario_10_empty_hub() {
    let hub = PathTelemetryHub::new("dev-empty".into(), "net-empty".into());
    assert!(!hub.has_dirty());
    assert!(hub.drain_dirty(10).is_empty());
    assert!(hub.snapshot_all().is_empty());

    let payload = hub.build_payload(Vec::new());
    assert!(payload.observations.is_empty());
}

#[test]
fn rust_wire_matches_shared_go_ingestion_fixture() {
    use super::wire::PathTelemetryFrame;
    let mut snapshot = dummy_snapshot(Some(NetworkPath::Direct), 2, 8);
    snapshot.lifecycle = "online".into();
    snapshot.previous_path = Some(NetworkPath::Relay);
    snapshot.transition_reason = "direct_committed".into();
    snapshot.direct_state = "ready".into();
    snapshot.relay_state = "none".into();
    snapshot.path_age_ms = 125;
    snapshot.direct_health.latency_ms = Some(24);
    snapshot.relay_health.latency_ms = Some(40);
    snapshot.selected_path_mtu = Some(1420);
    let mut observation = observation_from_snapshot("rust-remote", "fixture-network", &snapshot);
    assert!(observation.observed_at > 0);
    observation.observed_at = 1700000000;
    let hub = PathTelemetryHub::new("rust-reporter".into(), "fixture-network".into());
    let mut frame = hub.build_frame(vec![observation]);
    frame.payload.sent_at = 1700000000123;
    let expected: PathTelemetryFrame = serde_json::from_str(include_str!(
        "../../../../../server/api/testdata/path_telemetry_rust_v1.json"
    ))
    .expect("shared Rust/Go fixture");
    assert_eq!(
        serde_json::to_value(frame).unwrap(),
        serde_json::to_value(expected).unwrap()
    );
}

#[test]
fn lifecycle_comes_from_committed_peer_snapshot() {
    let mut snapshot = dummy_snapshot(None, 1, 1);
    for lifecycle in ["online", "offline", "unbound"] {
        snapshot.lifecycle = lifecycle.into();
        let observation = observation_from_snapshot("peer", "network", &snapshot);
        assert_eq!(observation.lifecycle, lifecycle);
        assert!(observation.observed_at > 0);
    }
}

#[test]
fn maximum_history_batches_fit_the_control_message_budget_without_losing_peers() {
    use super::wire::{PathTransitionTeleItem, MAX_PATH_TELEMETRY_FRAME_BYTES};
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    let mut observation = observation_from_snapshot(
        "peer",
        "network",
        &dummy_snapshot(Some(NetworkPath::Direct), 1, 1),
    );
    observation.transitions = (0..32)
        .map(|revision| PathTransitionTeleItem {
            revision,
            event_kind: "DirectValidationSucceeded".into(),
            decision: "committed".into(),
            reason_code: "direct_committed".into(),
            previous_path: Some("relay".into()),
            current_path: Some("direct".into()),
            age_ms: 1000,
        })
        .collect();
    // Use the same normal enqueue path with the recorder's full history ring.
    let mut snapshot = dummy_snapshot(Some(NetworkPath::Direct), 1, 1);
    snapshot.transitions = observation
        .transitions
        .iter()
        .map(
            |item| super::super::path_observability::PathTransitionDiagnostics {
                revision: item.revision,
                event_kind: item.event_kind.clone(),
                decision: item.decision.clone(),
                reason_code: item.reason_code.clone(),
                previous_path: Some(NetworkPath::Relay),
                current_path: Some(NetworkPath::Direct),
                age_ms: item.age_ms,
                epoch: None,
            },
        )
        .collect();
    for index in 0..32 {
        hub.enqueue(&format!("peer-{index:04}"), &snapshot);
    }
    let full = hub.build_frame(hub.snapshot_all());
    assert!(serde_json::to_vec(&full).unwrap().len() > MAX_PATH_TELEMETRY_FRAME_BYTES);
    let mut received = std::collections::HashSet::new();
    let mut frames = 0;
    while hub.has_dirty() {
        let frame = hub.drain_bounded_frame(32).expect("nonempty batch");
        assert!(serde_json::to_vec(&frame).unwrap().len() <= MAX_PATH_TELEMETRY_FRAME_BYTES);
        for observation in frame.payload.observations {
            assert_eq!(observation.transitions.len(), 32);
            assert!(received.insert(observation.remote_device_id));
        }
        frames += 1;
        assert!(frames <= 32);
    }
    assert!(frames > 1);
    assert_eq!(received.len(), 32);
    assert_eq!(hub.metrics().dropped_events, 0);
}

#[test]
fn oversized_single_observation_is_counted_and_does_not_block_healthy_peers() {
    use super::wire::MAX_PATH_TELEMETRY_FRAME_BYTES;
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    let mut snapshot = dummy_snapshot(Some(NetworkPath::Direct), 1, 1);
    snapshot.transition_reason = "x".repeat(MAX_PATH_TELEMETRY_FRAME_BYTES);
    hub.enqueue("oversized", &snapshot);
    hub.enqueue("healthy", &dummy_snapshot(Some(NetworkPath::Direct), 1, 1));
    let frame = hub.drain_bounded_frame(32).expect("healthy peer retained");
    assert_eq!(frame.payload.observations.len(), 1);
    assert_eq!(frame.payload.observations[0].remote_device_id, "healthy");
    assert_eq!(hub.metrics().oversized_observations, 1);
    assert_eq!(hub.metrics().dropped_events, 1);
    assert!(!hub.has_dirty());
}

#[test]
fn oversized_history_trims_oldest_optional_event_and_preserves_snapshot() {
    use super::super::path_observability::PathTransitionDiagnostics;
    use super::wire::MAX_PATH_TELEMETRY_FRAME_BYTES;
    let hub = PathTelemetryHub::new("reporter".into(), "network".into());
    let mut snapshot = dummy_snapshot(Some(NetworkPath::Direct), 1, 2);
    snapshot.transitions = vec![
        PathTransitionDiagnostics {
            age_ms: 100,
            revision: 1,
            event_kind: "x".repeat(MAX_PATH_TELEMETRY_FRAME_BYTES),
            decision: "committed".into(),
            reason_code: "initial".into(),
            epoch: None,
            previous_path: None,
            current_path: Some(NetworkPath::Relay),
        },
        PathTransitionDiagnostics {
            age_ms: 1,
            revision: 2,
            event_kind: "DirectValidationSucceeded".into(),
            decision: "committed".into(),
            reason_code: "direct_committed".into(),
            epoch: None,
            previous_path: Some(NetworkPath::Relay),
            current_path: Some(NetworkPath::Direct),
        },
    ];
    hub.enqueue("peer", &snapshot);
    let frame = hub
        .drain_bounded_frame(32)
        .expect("authoritative snapshot retained");
    assert!(serde_json::to_vec(&frame).unwrap().len() <= MAX_PATH_TELEMETRY_FRAME_BYTES);
    let observation = &frame.payload.observations[0];
    assert_eq!(observation.current_path, "direct");
    assert_eq!(observation.observation_revision, 2);
    assert_eq!(observation.transitions.len(), 1);
    assert_eq!(observation.transitions[0].revision, 2);
    assert_eq!(hub.metrics().trimmed_transition_items, 1);
    assert_eq!(hub.metrics().dropped_events, 0);
}

#[test]
fn rust_and_go_share_the_same_telemetry_resource_contract() {
    let limits: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../server/api/testdata/path_telemetry_limits.json"
    ))
    .expect("shared protocol limits");
    assert_eq!(
        limits["max_frame_bytes"],
        super::wire::MAX_PATH_TELEMETRY_FRAME_BYTES
    );
    assert_eq!(
        limits["max_observations"],
        super::hub::DEFAULT_BATCH_OBSERVATIONS
    );
    assert_eq!(
        limits["max_history_items"],
        super::super::path_observability::PATH_TRANSITION_EVENT_LIMIT
    );
}
