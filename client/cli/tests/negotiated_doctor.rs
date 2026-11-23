use p2pnet_daemon::Config;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn doctor_prints_negotiated_fields_from_authenticated_status() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let dir = std::env::temp_dir().join(format!(
        "p2wlan-doctor-{}-{}",
        std::process::id(),
        addr.port()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("config.json");
    let mut config = Config::generate_default("http://127.0.0.1", "matrix-room").unwrap();
    config.diagnostics.bind = addr.to_string();
    config.save_to_file(&path).unwrap();
    std::fs::write(dir.join("p2wlan-daemon.diag-auth"), "loopback-fixture").unwrap();
    let profile = serde_json::json!({"nat_type":"RandomSymmetric","port_hint":49000,"port_step":0});
    let body=serde_json::json!({"upnp_status":"unavailable","local_nat_profile":profile,
        "peers":[{"node_id":"peer-b","remote_nat_profile":profile,"punch_epoch":41,"punch_mode":9,
        "udp_firewall_status":"blocked","queue_a_len":0,"queue_b_len":0,"actual_pps":3,"active_punch_sockets":0,
        "active_path":"Relay","active_path_type":"tls_relay","path_cost":10,"reason_code":"UDP_BLOCKED"},
        {"node_id":"peer-c","punch_epoch":42,"active_path_type":"tcp_direct","tcp_open_method":"simultaneous","path_cost":4}]}).to_string();
    let status = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|v| v == b"\r\n\r\n") {
            let mut buf = [0; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0);
            request.extend_from_slice(&buf[..n]);
        }
        let headers = String::from_utf8(request).unwrap().to_ascii_lowercase();
        assert!(headers.starts_with("get /status "));
        assert!(headers.contains("authorization: bearer loopback-fixture"));
        let response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_p2wlan"))
        .env("P2WLAN_CONFIG", &path)
        .env("P2WLAN_HOME", &dir)
        .env("P2WLAN_STATE_DIR", &dir)
        .arg("doctor")
        .output()
        .await
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), status)
        .await
        .unwrap()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    for marker in [
        "local_nat_profile=",
        "remote_nat_profile=",
        "nat_type",
        "port_step",
        "port_hint",
        "punch_mode=9",
        "punch_epoch=41",
        "queue_a_len=0",
        "queue_b_len=0",
        "actual_pps=3",
        "active_punch_sockets=0",
        "udp_firewall_status=",
        "upnp_status=",
        "active_path=",
        "active_path_type=",
        "path_cost=10",
        "tcp_open_method=\"simultaneous\"",
        "UDP_BLOCKED",
    ] {
        assert!(stdout.contains(marker), "doctor missing {marker}: {stdout}");
    }
}
