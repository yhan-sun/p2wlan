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
fn registration_payload_uses_persisted_incarnation_without_a_wall_clock_fallback() {
    let config = test_config();

    let fenced = register_device_payload_with_incarnation(&config, 42);
    assert_eq!(fenced["registration_incarnation"], 42);

    let unavailable = register_device_payload_with_incarnation(&config, 0);
    assert!(unavailable.get("registration_incarnation").is_none());
}

#[tokio::test]
async fn registration_rejects_partial_lifecycle_response() {
    async fn registration_result(body: &'static str) -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        let config = test_config();
        let result = register_device(
            &test_no_proxy_client(),
            &format!("http://{address}"),
            "test-token",
            &config,
        )
        .await
        .map(|_| ());
        server.await.unwrap();
        result
    }

    let missing_incarnation = registration_result(
        r#"{"success":true,"node_id":"node-a","virtual_ip":"10.20.0.2","cidr":"10.20.0.0/16","registration_seq":7}"#,
    )
    .await
    .expect_err("a sequence without its incarnation must not enable session fencing");
    assert!(missing_incarnation
        .to_string()
        .contains("omitted registration_incarnation"));

    let missing_sequence = registration_result(
        r#"{"success":true,"node_id":"node-a","virtual_ip":"10.20.0.2","cidr":"10.20.0.0/16","registration_incarnation":7}"#,
    )
    .await
    .expect_err("an incarnation without its sequence must not enable session fencing");
    assert!(missing_sequence
        .to_string()
        .contains("omitted a valid registration_seq"));
}

#[test]
fn endpoint_control_label_replaces_untrusted_lifecycle_and_stays_bounded() {
    let base = "p2v2:m=endpoint_independent;a=stable;d=0;c=100;f=endpoint_independent;h=supported;g=18446744073709551615;o=18446744073709551615;l=1";
    let label = control_label_with_registration_seq(base, Some(2));

    assert!(
        label.len() <= 128,
        "label exceeds server field cap: {label}"
    );
    assert_eq!(extract_nat_lifecycle(&label), Some(2));
    assert!(!label.contains("l=1"));
    assert_eq!(
        control_label_with_registration_seq("unknown", Some(9)),
        "p2v2:l=9"
    );
    assert_eq!(
        control_label_with_registration_seq("p2v2:m=endpoint_independent;l=1", None),
        "p2v2:m=endpoint_independent;l=1"
    );
}

#[test]
fn registration_conflicts_are_never_treated_as_transient_auth_or_network_errors() {
    assert!(is_registration_conflict_error(
        "registration conflict (registration_conflict) current_registration_seq=3: registration sequence conflict"
    ));
    assert!(is_registration_conflict_error(
        "registration conflict (registration_protocol_upgrade_required) current_registration_seq=3: registration requires a sequence-aware client"
    ));
    assert!(!is_registration_conflict_error(
        "register request returned HTTP 503"
    ));
}

#[test]
fn advertised_endpoint_snapshot_keeps_newer_observation_and_registration_fences() {
    let mut snapshot = AdvertisedEndpointSnapshot::default();
    let base = "p2v2:m=address_or_port_dependent;a=linear;d=4;c=90;f=address_dependent;h=unknown";
    let endpoint = "203.0.113.7:41000".to_string();

    snapshot.update(endpoint.clone(), format!("{base};g=7;o=2;l=5"));
    assert_eq!(snapshot.endpoint, endpoint);
    assert_eq!(snapshot.generation, Some(7));
    assert_eq!(snapshot.observation, Some(2));
    assert_eq!(snapshot.lifecycle, Some(5));

    // A delayed ordinary lane request cannot replace a newer critical-lane
    // observation, remove its o fence, or regress the registration lifecycle.
    snapshot.update(
        "203.0.113.99:41000".to_string(),
        format!("{base};g=7;o=1;l=5"),
    );
    snapshot.update("203.0.113.98:41000".to_string(), format!("{base};g=7;l=5"));
    snapshot.update(
        "203.0.113.97:41000".to_string(),
        format!("{base};g=99;o=99;l=4"),
    );
    assert_eq!(snapshot.endpoint, endpoint);
    assert_eq!(snapshot.observation, Some(2));
    assert_eq!(snapshot.lifecycle, Some(5));

    // A real same-capability observation advances o. A newer server lifecycle
    // may intentionally reset the daemon's local g/o counters.
    snapshot.update(
        "203.0.113.8:41000".to_string(),
        format!("{base};g=7;o=3;l=5"),
    );
    assert_eq!(snapshot.observation, Some(3));
    snapshot.update(
        "203.0.113.9:41000".to_string(),
        format!("{base};g=1;o=1;l=6"),
    );
    assert_eq!(snapshot.endpoint, "203.0.113.9:41000");
    assert_eq!(snapshot.generation, Some(1));
    assert_eq!(snapshot.observation, Some(1));
    assert_eq!(snapshot.lifecycle, Some(6));
}

include!("tests/websocket.rs");
include!("tests/peers.rs");
include!("tests/messages.rs");
include!("tests/client.rs");
include!("tests/commands.rs");
