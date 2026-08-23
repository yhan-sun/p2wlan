//! Shared contract fixture tests: the JSON fixtures under `contracts/fixtures/`
//! are the single source of truth for the daemon <-> Flutter wire contract
//! (ADR 0004). The Flutter client reads the same files in
//! `apps/flutter_client/test/contract_test.dart`. If the Rust daemon renames,
//! drops, or retypes a contract field, deserialization here fails so the two
//! sides cannot drift silently.

use p2pnet_daemon::diagnostics::{
    derive_ready_phase, EventsResponse, PeersPageResponse, PermissionPreflightResponse,
    RouteRepairResponse, RoutesResponse, StatusResponse,
};
use p2pnet_daemon::route::RouteState;

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts/fixtures")
}

fn read_fixture(name: &str) -> String {
    let path = fixture_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read shared contract fixture {path:?}: {e}"))
}

#[test]
fn status_fixture_deserializes_into_daemon_snapshot() {
    let raw = read_fixture("status.json");
    let response: StatusResponse = serde_json::from_str(&raw)
        .expect("status.json must deserialize into the production StatusResponse");
    assert_eq!(response.contract_version, 1);
    let snapshot = response.snapshot;
    let expected: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let actual = serde_json::to_value(StatusResponse::from_snapshot(snapshot.clone())).unwrap();
    assert_eq!(
        actual, expected,
        "status serializer must match the shared fixture"
    );

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
            snapshot.ready_phase == "connected_manual",
        );
        assert!(known.contains(&phase), "derived unknown phase {phase}");
    }
}

#[test]
fn events_fixture_deserializes_into_status_events() {
    let raw = read_fixture("events.json");
    let response: EventsResponse =
        serde_json::from_str(&raw).expect("events.json must deserialize into EventsResponse");
    assert_eq!(response.contract_version, 1);
    let expected: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let actual = serde_json::to_value(response.clone()).unwrap();
    assert_eq!(
        actual, expected,
        "events serializer must match the shared fixture"
    );
    assert!(response.revision >= 3);
    let events = response.events;
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
    let response: RoutesResponse =
        serde_json::from_str(&raw).expect("routes.json must deserialize into RoutesResponse");
    assert_eq!(response.contract_version, 1);
    let expected: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let actual = serde_json::to_value(response.clone()).unwrap();
    assert_eq!(
        actual, expected,
        "routes serializer must match the shared fixture"
    );
    assert_eq!(response.interface, "p2wlan0");
    assert!(response.healthy);
    assert_eq!(response.conflict_count, 0);
    assert_eq!(response.entries.len(), 1);
    assert_eq!(response.entries[0].cidr, "10.20.0.0/16");
    assert_eq!(response.entries[0].state, RouteState::Installed);
    assert_eq!(response.entries[0].expected_interface, "p2wlan0");
    assert!(response.entries[0].owned);
}

#[test]
fn route_repair_fixture_never_restarts_daemon() {
    let raw = read_fixture("route_repair.json");
    let response: RouteRepairResponse = serde_json::from_str(&raw)
        .expect("route_repair.json must deserialize into RouteRepairResponse");
    let expected: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let actual = serde_json::to_value(response.clone()).unwrap();
    assert_eq!(
        actual, expected,
        "route repair serializer must match the shared fixture"
    );
    // Repair is in-place only; the contract MUST keep restartedDaemon false.
    assert!(!response.restarted_daemon);
    assert!(response.changed);
    assert_eq!(response.after, "installed");
    assert_eq!(response.reason, "installed");
}

#[test]
fn peers_page_fixture_deserializes_into_production_response() {
    let raw = read_fixture("peers_page.json");
    let response: PeersPageResponse =
        serde_json::from_str(&raw).expect("peers_page.json must use PeersPageResponse");
    assert_eq!(response.contract_version, 1);
    assert_eq!(response.total, response.peers.len());
    assert!(response.peers.is_empty());
}

#[test]
fn permission_preflight_fixture_deserializes_into_production_response() {
    let raw = read_fixture("permission_preflight.json");
    let response: PermissionPreflightResponse = serde_json::from_str(&raw)
        .expect("permission_preflight.json must use PermissionPreflightResponse");
    assert_eq!(response.contract_version, 1);
    assert_eq!(response.state, "runtimeVerificationRequired");
    assert_eq!(response.can_create_tun, None);
    assert_eq!(response.can_modify_routes, Some(true));
}
