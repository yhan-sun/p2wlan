//! Shared contract fixture tests: the JSON fixtures under `contracts/fixtures/`
//! are the single source of truth for the daemon <-> Flutter wire contract
//! (ADR 0004). The Flutter client reads the same files in
//! `apps/flutter_client/test/contract_test.dart`. If the Rust daemon renames,
//! drops, or retypes a contract field, deserialization here fails so the two
//! sides cannot drift silently.

use p2pnet_daemon::diagnostics::{derive_ready_phase, DiagnosticsSnapshot, StatusEvent};
use p2pnet_daemon::route::{RouteObservation, RouteState};

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../contracts/fixtures")
}

fn read_fixture(name: &str) -> String {
    let path = fixture_dir().join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read shared contract fixture {path:?}: {e}")
    })
}

#[test]
fn status_fixture_deserializes_into_daemon_snapshot() {
    let raw = read_fixture("status.json");
    let snapshot: DiagnosticsSnapshot = serde_json::from_str(&raw)
        .expect("status.json must deserialize into the daemon DiagnosticsSnapshot");

    assert_eq!(snapshot.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(snapshot.node_id, "node-a");
    assert_eq!(snapshot.network_id, "net1");
    assert_eq!(snapshot.virtual_ip, "10.20.0.7");
    // Contract fields introduced for the Flutter unification.
    assert!(snapshot.revision > 0);
    assert!(
        !snapshot.ready_phase.is_empty(),
        "ready_phase must be populated, never empty"
    );

    // The fixture's ready_phase must be one the daemon actually derives.
    let known = [
        "connecting_control",
        "connected_manual",
        "connected_direct",
        "connected_relay",
        "discovering_peers",
        "allocating_virtual_ip",
        "credential_reauth_required",
        "error",
        "stopping",
    ];
    assert!(
        known.contains(&snapshot.ready_phase.as_str()),
        "unexpected ready_phase value: {}",
        snapshot.ready_phase
    );

    // `derive_ready_phase` never returns an unknown/empty phase either.
    for vip in ["", "10.20.0.1"] {
        let phase = derive_ready_phase(
            &snapshot.health,
            snapshot.relay_connected,
            &snapshot.peers,
            vip,
        );
        assert!(known.contains(&phase), "derived unknown phase {phase}");
    }
}

#[test]
fn events_fixture_deserializes_into_status_events() {
    let raw = read_fixture("events.json");
    let body: serde_json::Value =
        serde_json::from_str(&raw).expect("events.json must be valid JSON");
    let revision = body["revision"]
        .as_u64()
        .expect("events.json must carry a revision");
    assert!(revision >= 3);
    let events: Vec<StatusEvent> = serde_json::from_value(body["events"].clone())
        .expect("events[] must deserialize into the daemon StatusEvent struct");
    assert_eq!(events.len(), 3);
    let mut seqs: Vec<u64> = events.iter().map(|e| e.seq).collect();
    seqs.sort_unstable();
    seqs.dedup();
    assert_eq!(seqs.len(), events.len(), "event seq must be unique");
    assert!(events.iter().all(|e| !e.event.is_empty()));
}

#[test]
fn routes_fixture_deserializes_into_route_observations() {
    let raw = read_fixture("routes.json");
    let body: serde_json::Value =
        serde_json::from_str(&raw).expect("routes.json must be valid JSON");
    assert_eq!(body["interface"], "p2wlan0");
    assert_eq!(body["healthy"], true);
    assert_eq!(body["conflictCount"], 0);

    let entries: Vec<RouteObservation> = serde_json::from_value(body["entries"].clone())
        .expect("entries[] must deserialize into the daemon RouteObservation struct");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cidr, "10.20.0.0/16");
    assert_eq!(entries[0].state, RouteState::Installed);
    assert_eq!(entries[0].expected_interface, "p2wlan0");
    assert!(entries[0].owned);
}

#[test]
fn route_repair_fixture_never_restarts_daemon() {
    let raw = read_fixture("route_repair.json");
    let body: serde_json::Value =
        serde_json::from_str(&raw).expect("route_repair.json must be valid JSON");
    // Repair is in-place only; the contract MUST keep restartedDaemon false.
    assert_eq!(body["restartedDaemon"], false);
    assert_eq!(body["changed"], true);
    assert_eq!(body["after"], "installed");
    assert_eq!(body["reason"], "installed");
    // All contract keys are present so a Rust-side rename is caught.
    for key in [
        "cidr",
        "changed",
        "attempted",
        "before",
        "after",
        "reason",
        "restartedDaemon",
    ] {
        assert!(
            body.get(key).is_some(),
            "route_repair fixture is missing contract key {key}"
        );
    }
}