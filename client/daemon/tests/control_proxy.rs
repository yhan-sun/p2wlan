//! Control-plane proxy policy integration tests.
//!
//! These live in an integration-test crate so they run in their OWN process:
//! `std::env` manipulation here cannot pollute the daemon unit-test process
//! (where many other tests build `reqwest::Client`).  The two tests share a
//! mutex so they do not clobber each other's environment within this process.
//!
//! The daemon's control plane must be explicit about proxy behavior:
//! - `Direct` (default): HTTP control traffic does NOT read environment
//!   proxies, even when `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are set.
//! - `Environment`: the request is routed through the configured proxy.

use std::env;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use p2pnet_daemon::config::ControlProxyMode;
use p2pnet_daemon::control::control_http_client;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Serializes the two env-mutating tests inside this process.  A tokio mutex so
/// the guard is held across `await` points without a `std` sync-lock deadlock
/// warning.
static PROXY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Minimal HTTP responder that flips a flag when it receives a request.
async fn start_http_flag_server(flag: Arc<AtomicBool>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let flag = flag.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let mut total = 0usize;
                // Read until the request headers end.
                let window = loop {
                    let Ok(n) = stream.read(&mut buf[total..]).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    total += n;
                    if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
                        break total;
                    }
                    if total == buf.len() {
                        break total;
                    }
                };
                flag.store(true, Ordering::SeqCst);
                let _ = &buf[..window];
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn direct_mode_ignores_environment_proxy() {
    let _guard = PROXY_TEST_LOCK.lock().await;

    let proxy_hit = Arc::new(AtomicBool::new(false));
    let server_hit = Arc::new(AtomicBool::new(false));
    let proxy_addr = start_http_flag_server(proxy_hit.clone()).await;
    let server_addr = start_http_flag_server(server_hit.clone()).await;

    env::set_var("HTTP_PROXY", format!("http://{proxy_addr}"));
    env::set_var("HTTPS_PROXY", format!("http://{proxy_addr}"));
    env::set_var("ALL_PROXY", format!("http://{proxy_addr}"));
    // Make sure the target is ONLY reachable directly (not through the proxy).
    let client = control_http_client(ControlProxyMode::Direct).unwrap();
    let resp = client
        .get(format!("http://{server_addr}/health"))
        .send()
        .await
        .unwrap();
    env::remove_var("HTTP_PROXY");
    env::remove_var("HTTPS_PROXY");
    env::remove_var("ALL_PROXY");

    assert_eq!(resp.status(), 200);
    assert!(
        server_hit.load(Ordering::SeqCst),
        "direct-mode control HTTP must reach the server directly"
    );
    assert!(
        !proxy_hit.load(Ordering::SeqCst),
        "direct-mode control HTTP must NOT route through an ambient proxy"
    );
}

#[tokio::test]
async fn environment_mode_routes_through_configured_proxy() {
    let _guard = PROXY_TEST_LOCK.lock().await;

    let proxy_hit = Arc::new(AtomicBool::new(false));
    let _unused_server = Arc::new(AtomicBool::new(false));
    let proxy_addr = start_http_flag_server(proxy_hit.clone()).await;

    env::set_var("HTTP_PROXY", format!("http://{proxy_addr}"));
    // The target host does not resolve / is unreachable directly; only the
    // proxy can answer.  Environment mode must send the request to the proxy.
    let client = control_http_client(ControlProxyMode::Environment).unwrap();
    let resp = client
        .get("http://control.invalid:18080/api/v1/health")
        .send()
        .await
        .unwrap();
    env::remove_var("HTTP_PROXY");

    assert_eq!(resp.status(), 200);
    assert!(
        proxy_hit.load(Ordering::SeqCst),
        "environment-mode control HTTP must route through the configured proxy"
    );
}
