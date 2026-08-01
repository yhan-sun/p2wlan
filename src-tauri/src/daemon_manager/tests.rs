use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_options(diagnostics_url: String) -> DaemonStartOptions {
    DaemonStartOptions {
        diagnostics_url: Some(diagnostics_url),
        control_server: Some("http://127.0.0.1:18080".to_string()),
        auth_token: Some("test-token".to_string()),
        network_id: Some("test-network".to_string()),
        device_name: Some("test-device".to_string()),
        tun_interface: Some("p2wlan-test".to_string()),
        udp_bind: Some("0.0.0.0:60207".to_string()),
        udp_advertise: Some("203.0.113.10:60207".to_string()),
        socket_pool: Some("3".to_string()),
        mtu: Some(1420),
    }
}

async fn status_server_once(body: &'static str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let mut request = [0_u8; 1024];
            let n = stream.read(&mut request).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&request[..n]);
            if request.starts_with("GET /health ") {
                let response =
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
                stream.write_all(response.as_bytes()).await.unwrap();
            } else {
                let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        }
    });
    format!("http://{address}/status")
}

async fn health_ok_status_hangs_server() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 1024];
                let n = stream.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]);
                if request.starts_with("GET /health ") {
                    let response =
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n";
                    stream.write_all(response.as_bytes()).await.unwrap();
                } else {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            });
        }
    });
    format!("http://{address}/status")
}

fn unused_local_status_url() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{address}/status")
}

fn spawn_sleep_child() -> Child {
    #[cfg(windows)]
    {
        Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
            .spawn()
            .unwrap()
    }

    #[cfg(not(windows))]
    {
        Command::new("sleep").arg("30").spawn().unwrap()
    }
}

#[cfg(unix)]
fn spawn_daemon_named_child(bind_addr: &str) -> (tempfile::TempDir, Child) {
    use std::os::unix::fs::PermissionsExt;

    let temp_dir = tempfile::tempdir().unwrap();
    let script = temp_dir.path().join("p2wlan-daemon-test");
    std::fs::write(
            &script,
            "#!/bin/sh\ntrap 'kill \"$child\" 2>/dev/null' TERM EXIT\nsleep 30 &\nchild=$!\nwait \"$child\"\n",
        )
        .unwrap();
    let mut permissions = std::fs::metadata(&script).unwrap().permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&script, permissions).unwrap();

    let child = Command::new(&script)
        .args(["--diagnostics-bind", bind_addr])
        .spawn()
        .unwrap();
    (temp_dir, child)
}

include!("tests/phase.rs");
include!("tests/status.rs");
include!("tests/paths.rs");
include!("tests/serialization.rs");
