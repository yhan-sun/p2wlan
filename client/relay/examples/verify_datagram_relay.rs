use p2pnet_relay::{RelayClient, RelayClientConfig, RelayMessage};
use std::{env, io::Write, time::Duration};
use tokio::sync::mpsc;

async fn next_data(rx: &mut mpsc::Receiver<RelayMessage>, peer: &str, bytes: &[u8]) {
    let limit = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(limit, rx.recv()).await.unwrap() {
            Some(RelayMessage::Data { from_node, data }) => {
                assert_eq!(from_node, peer);
                assert_eq!(data, bytes);
                return;
            }
            Some(RelayMessage::Pong { .. }) => {}
            other => panic!("expected forwarding for {peer}, received {other:?}"),
        }
    }
}

async fn wait_closed(rx: &mut mpsc::Receiver<RelayMessage>) {
    let wait = async {
        while let Some(message) = rx.recv().await {
            if matches!(message, RelayMessage::Closed { .. }) {
                break;
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(9), wait)
        .await
        .unwrap();
}

async fn connect(addr: &str, id: &str, key: &str) -> (RelayClient, mpsc::Receiver<RelayMessage>) {
    let config = RelayClientConfig {
        relay_ticket: Some(env::var(key).unwrap()),
        tls_server_name: Some("localhost".into()),
        tls_ca_cert_path: Some(env::var_os("P2WLAN_VERIFY_RELAY_CA").unwrap().into()),
        prefer_datagrams: true,
        connect_timeout: Duration::from_secs(2),
        register_timeout: Duration::from_secs(2),
        idle_timeout: Duration::from_millis(700),
        keepalive_interval: Duration::from_millis(150),
        ..RelayClientConfig::default()
    };
    RelayClient::connect_with_endpoint(addr, id, config)
        .await
        .unwrap()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let addr = env::var("P2WLAN_VERIFY_RELAY_ENDPOINT").unwrap();
    for udp in [true, false] {
        let started = std::time::Instant::now();
        let (a, mut receive_a) =
            connect(&addr, "relay-probe-a", "P2WLAN_VERIFY_RELAY_TICKET_A").await;
        let (b, mut receive_b) =
            connect(&addr, "relay-probe-b", "P2WLAN_VERIFY_RELAY_TICKET_B").await;
        assert_eq!(a.is_udp(), udp);
        assert_eq!(b.is_udp(), udp);
        // A sub-MTU datagram and frames split across several datagrams exercise
        // both directions of the real Go ↔ Rust framing protocol.
        for size in [96, 1240, 4096] {
            let bytes: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
            a.send_data("relay-probe-b", &bytes).await.unwrap();
            next_data(&mut receive_b, "relay-probe-a", &bytes).await;
            b.send_data("relay-probe-a", &bytes).await.unwrap();
            next_data(&mut receive_a, "relay-probe-b", &bytes).await;
        }
        if udp {
            println!("UDP bidirectional verified");
            std::io::stdout().flush().unwrap();
            tokio::join!(wait_closed(&mut receive_a), wait_closed(&mut receive_b));
        } else {
            println!(
                "TLS bidirectional verified, reconnect and exchange took {:?}",
                started.elapsed()
            );
            a.close().await.unwrap();
            b.close().await.unwrap();
        }
    }
}
