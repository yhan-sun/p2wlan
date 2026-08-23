use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_config() -> Config {
    Config::generate_default("https://ctrl.test", "net1").unwrap()
}

#[test]
fn managed_register_payload_omits_stale_virtual_ip() {
    let mut config = test_config();
    config.network.manual = false;
    config.network.virtual_ip = "10.20.0.1".to_string();

    let payload = register_device_payload(&config);

    assert!(payload.get("virtual_ip").is_none());
    assert_eq!(payload["network_id"], "net1");
    assert_eq!(payload["app_version"], env!("CARGO_PKG_VERSION"));
}

#[test]
fn manual_register_payload_keeps_requested_virtual_ip() {
    let mut config = test_config();
    config.network.manual = true;
    config.network.virtual_ip = "10.20.0.44".to_string();

    let payload = register_device_payload(&config);

    assert_eq!(payload["virtual_ip"], "10.20.0.44");
}

#[test]
fn ordinary_endpoint_update_uses_the_device_lease_health_lane() {
    // `commands.rs` is include!-spliced inside the runtime select branch, so a
    // source-level contract assertion is the narrowest regression test for
    // this call-site wiring; HealthState's behavior is exercised separately.
    let source = include_str!("runtime/commands.rs");
    let update_endpoint = source
        .split("ControlCommand::UpdateEndpoint")
        .nth(1)
        .and_then(|tail| tail.split("ControlCommand::SendPeerReflexive").next())
        .expect("UpdateEndpoint command branch");

    assert!(update_endpoint.contains("mark_device_lease_success().await"));
    assert!(update_endpoint.contains("set_device_lease_healthy(false)"));
    assert!(!update_endpoint.contains("mark_control_success().await"));
}

include!("tests/websocket.rs");
include!("tests/peers.rs");
include!("tests/messages.rs");
include!("tests/client.rs");
