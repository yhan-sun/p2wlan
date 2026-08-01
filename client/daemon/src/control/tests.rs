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

include!("tests/websocket.rs");
include!("tests/peers.rs");
include!("tests/messages.rs");
include!("tests/client.rs");
